"""Jira REST access and report-data derivation for the SOC platform.

This module owns two concerns that Refactor 3 gave an explicit seam between:

1. **REST primitives** — thin ``httpx.get`` wrappers that talk to the Jira
   Cloud API (search, single-issue fetch, project issue-type discovery, and
   per-month incident counting). These resolve per-customer auth via
   :func:`_resolve_jira_auth` (Key Vault-backed through ``tools.secrets``),
   never reading credentials straight from ``os.environ``.

2. **Report derivation** — turning raw Jira issues into the stats/derived
   structures the report templates and LLM prompt consume
   (:func:`_compute_stats`, :func:`_compute_incident_derived_stats`), plus the
   multi-project fan-out/merge orchestration.

Two collaborator objects express that seam so the report side becomes testable
without mocking HTTP:

- :class:`JiraRestClient` — a stateless, per-call handle over the REST
  primitives. ``project_spec`` is locked at construction so a client instance
  is bound to one Jira instance/customer; concurrency (see
  :func:`fetch_all_projects`) uses one client per thread. Its methods delegate
  to the module-level primitive functions *by name at call time*, so tests that
  rebind e.g. ``jira_client.jira_search`` still intercept the call.

- :class:`JiraReportPipeline` — depends on a ``JiraRestClient`` (or a stub with
  the same surface) and reaches HTTP only through ``self._client``. It owns the
  incident/SR/CR fetches, the 12-month trend, and the multi-project merge.

The historical **module-level function API is preserved as a facade** over a
shared ``_PIPELINE`` instance: all ~20 public names keep their exact current
signatures so the 11 external callers work with zero import changes, and the
existing tests keep their monkeypatch points (name rebinding at module scope).
``_compute_stats`` and ``_compute_incident_derived_stats`` stay pure
module-level functions — imported directly by ``tools/test_pending_by_entity``.
"""

import os
import csv
import json
import re
import base64
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from collections import Counter

import httpx

logger = logging.getLogger(__name__)

JIRA_URL = os.environ.get("JIRA_URL", "").rstrip("/")
USE_SAMPLE_DATA = os.environ.get("USE_SAMPLE_DATA", "false").lower() == "true"


def _jira_headers() -> dict:
    """Build the Jira REST auth header at call time, using the global env
    fallback creds (JIRA_EMAIL + JIRA_API_TOKEN). Used by code paths that
    are not customer-scoped (e.g. the L1 Triage webhook in routes/webhook.py).
    Customer-scoped report fetches go through :func:`_resolve_jira_auth`
    instead, which honours per-project ``base_url`` / ``email`` /
    ``api_token_kv_name`` overrides for multi-instance customers.

    Resolves email + token via tools.secrets.get_secret so KV-backed
    deployments work without the credentials being smuggled into the image
    via .env. Falls back to os.environ for dev/CI where load_dotenv() has
    populated the process env."""
    from tools.secrets import get_secret
    email = get_secret("JIRA_EMAIL") or os.environ.get("JIRA_EMAIL", "")
    token = get_secret("JIRA_API_TOKEN") or os.environ.get("JIRA_API_TOKEN", "")
    creds = base64.b64encode(f"{email}:{token}".encode()).decode()
    return {"Authorization": f"Basic {creds}", "Accept": "application/json"}


def _resolve_jira_auth(project_spec: dict | None = None) -> tuple[str, dict]:
    """Resolve (base_url, auth_headers) for a Jira project fetch.

    When ``project_spec`` is None, returns the global env-var creds
    (current production path: one Jira instance shared across all customers).
    When ``project_spec`` is provided, each of ``base_url`` / ``email`` /
    ``api_token_kv_name`` independently falls back to env when blank — so a
    customer can override just the base_url while reusing the shared token,
    or override creds while sharing the URL. The api token is resolved via
    ``tools.secrets.get_secret`` so it lives in Key Vault, not the customer
    record on disk."""
    from tools.secrets import get_secret

    spec = project_spec or {}
    base_url = (spec.get("base_url") or "").strip() or JIRA_URL
    email = (spec.get("email") or "").strip() or (
        get_secret("JIRA_EMAIL") or os.environ.get("JIRA_EMAIL", "")
    )
    kv_name = (spec.get("api_token_kv_name") or "").strip()
    token = ""
    if kv_name:
        token = get_secret(kv_name) or ""
    if not token:
        token = get_secret("JIRA_API_TOKEN") or os.environ.get("JIRA_API_TOKEN", "")
    creds = base64.b64encode(f"{email}:{token}".encode()).decode()
    headers = {"Authorization": f"Basic {creds}", "Accept": "application/json"}
    return base_url.rstrip("/"), headers


_FIELDS = (
    "summary,status,priority,labels,created,updated,resolved,assignee,"
    "resolution,description,"
    "customfield_10038,"   # Severity
    "customfield_10488,"   # Incident Type
    "customfield_10057,"   # Close Justification
    "customfield_10127,"   # Resolution Summary
    "customfield_10072"    # Tactics List
)


def fetch_issue_by_key(issue_key: str, fields: str = "*all") -> dict | None:
    """Fetch a single Jira issue by key. Returns the parsed JSON (with `fields`
    populated) or None on any error. Used by the L1 Triage webhook handler to
    re-read an issue after a short delay, since Service Desk request forms can
    populate custom fields after the initial issue_created webhook fires."""
    if not JIRA_URL:
        logger.error("fetch_issue_by_key: JIRA_URL not configured")
        return None
    try:
        r = httpx.get(
            f"{JIRA_URL}/rest/api/3/issue/{issue_key}",
            headers=_jira_headers(),
            params={"fields": fields},
            timeout=30,
        )
        if r.status_code >= 400:
            logger.error("fetch_issue_by_key %s HTTP %s: %s",
                         issue_key, r.status_code, r.text[:300])
            return None
        return r.json()
    except Exception as e:
        logger.error("fetch_issue_by_key %s exception: %s", issue_key, e)
        return None


def jira_search(jql: str, max_results: int = 100, next_page_token: str | None = None,
                project_spec: dict | None = None) -> dict:
    params = {
        "jql": jql,
        "maxResults": max_results,
        "fields": _FIELDS,
    }
    if next_page_token:
        params["nextPageToken"] = next_page_token

    base_url, headers = _resolve_jira_auth(project_spec)
    r = httpx.get(
        f"{base_url}/rest/api/3/search/jql",
        headers=headers,
        params=params,
        timeout=30,
    )
    if r.status_code >= 400:
        logger.error(f"jira_search HTTP {r.status_code}: {r.text[:500]}")
        return {"error": f"HTTP {r.status_code}", "detail": r.text[:500]}
    return r.json()


# Centralised filter used by every code path that counts incidents. Keeping it
# in one place guarantees the verifier in tools/jira_verifier.py applies the
# exact same project + issue-type predicate as the primary fetch — otherwise
# they could disagree purely from drift in two copies of the same string.
DEFAULT_INCIDENT_ISSUE_TYPE = "[System] Incident"


def _incident_jql_filter(project_key: str, issue_type: str) -> str:
    return f'project = "{project_key}" AND issuetype = "{issue_type or DEFAULT_INCIDENT_ISSUE_TYPE}"'


def _parse_jira_date(date_str: str) -> datetime | None:
    if not date_str:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    return None


def _extract_adf_text(field_value) -> str:
    """Extract plain text from an Atlassian Document Format (ADF) rich text field."""
    if not field_value:
        return ""
    if isinstance(field_value, str):
        return field_value
    if not isinstance(field_value, dict):
        return str(field_value)

    parts = []

    def _walk(node):
        if isinstance(node, dict):
            if node.get("type") == "text":
                parts.append(node.get("text", ""))
            for child in node.get("content", []):
                _walk(child)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(field_value)
    return " ".join(parts).strip()


# Jira's default lowest priority is literally "Lowest", which surprises clients
# reading the report — they expect SOC-standard severity tier names. Map
# "Lowest" to "Informational" at the data layer so every downstream consumer
# (chart, prompt, summary table, appendix) agrees on the label. Add more
# remappings here if/when other non-standard tier names appear.
_SEVERITY_NORMALIZATION = {
    "lowest": "Informational",
}


def _normalize_severity(severity: str) -> str:
    if not severity:
        return ""
    return _SEVERITY_NORMALIZATION.get(severity.strip().lower(), severity)


# Phase 1 (L1 Triage redesign): map SIEM severity (customfield_10038) to Jira
# priority so newly-created tickets get a priority that matches their severity
# instead of inheriting the project default (typically "Medium"). Handles both
# standard tier names AND the SCDM "Sev-X" convention seen in production. The
# LLM Triage call in routes/webhook.py may override this baseline if its
# confidence threshold is met. Returns None for unknown inputs so the caller
# can skip the priority update rather than guess.
# Canonical severity->priority map lives in tools/jira_schema.py (single source
# of truth, also used by per-customer schema resolution). Imported here so
# jira_client.severity_to_priority stays available for non-webhook callers
# without a second copy that can drift.
from tools.jira_schema import _DEFAULT_SEVERITY_MAP as _SEVERITY_TO_PRIORITY


def severity_to_priority(severity: str) -> str | None:
    if not severity:
        return None
    return _SEVERITY_TO_PRIORITY.get(severity.strip().lower())


def _normalize_issue(issue: dict) -> dict:
    fields = issue.get("fields", {})
    status = fields.get("status", {})
    priority = fields.get("priority", {})
    assignee = fields.get("assignee", {})

    # Extract tactics text and take the first tactic as category
    tactics_raw = _extract_adf_text(fields.get("customfield_10072"))
    category = tactics_raw.split()[0].strip() if tactics_raw else ""

    raw_severity = (fields.get("customfield_10038") or {}).get("value", "") or (priority.get("name", "") if priority else "")

    return {
        "key": issue.get("key", ""),
        "summary": fields.get("summary", ""),
        "status": status.get("name", "") if status else "",
        "priority": priority.get("name", "") if priority else "",
        "severity": _normalize_severity(raw_severity),
        "incident_type": category,
        "labels": fields.get("labels", []),
        "created": fields.get("created", ""),
        "updated": fields.get("updated", ""),
        "resolved": fields.get("resolved", ""),
        "assignee": (assignee.get("displayName", "") if assignee else ""),
        "close_justification": (fields.get("customfield_10057") or {}).get("value", ""),
        "resolution_summary": _extract_adf_text(fields.get("customfield_10127")),
        "tactics_list": tactics_raw,
    }


def _fetch_all_pages(jql: str, project_spec: dict | None = None,
                     client: "JiraRestClient | None" = None) -> list:
    """Fetch all pages for a JQL query using cursor pagination.

    REST goes through a :class:`JiraRestClient` (``client.search``), never a
    direct ``httpx.get``. When no client is supplied, one bound to
    ``project_spec`` is constructed — that keeps the module-level facade path
    working. The pipeline passes its own ``self._client`` so a stub injected
    into :class:`JiraReportPipeline` intercepts here with zero HTTP.
    """
    client = client or JiraRestClient(project_spec)
    all_issues = []
    next_token = None
    while len(all_issues) < 5000:
        result = client.search(jql, max_results=100, next_page_token=next_token)
        if "error" in result:
            logger.error(f"Jira fetch error: {result}")
            break
        issues = result.get("issues", [])
        all_issues.extend(issues)
        next_token = result.get("nextPageToken")
        if not issues or not next_token or result.get("isLast") is True:
            break
    return all_issues


def _date_chunks(start_date: str, end_date: str):
    """Yield (chunk_start, chunk_end_exclusive) tuples for each day in the range.
    Uses next-day exclusive end to avoid Jira's zero-width window when >= and <= share the same date."""
    start = datetime.strptime(start_date, "%Y-%m-%d")
    end = datetime.strptime(end_date, "%Y-%m-%d")
    current = start
    while current <= end:
        next_day = current + timedelta(days=1)
        yield current.strftime("%Y-%m-%d"), next_day.strftime("%Y-%m-%d")
        current = next_day


def fetch_incidents_for_report(project_key: str, start_date: str, end_date: str,
                               incident_issue_type: str = DEFAULT_INCIDENT_ISSUE_TYPE,
                               project_spec: dict | None = None) -> dict:
    """Facade — delegates to the shared pipeline (see :class:`JiraReportPipeline`)."""
    return _PIPELINE.fetch_incidents_for_report(
        project_key, start_date, end_date,
        incident_issue_type=incident_issue_type, project_spec=project_spec,
    )


def _compute_stats(incidents: list[dict]) -> dict:
    total = len(incidents)
    by_severity = dict(Counter(i["severity"] or "Unspecified" for i in incidents))
    by_status = dict(Counter(i["status"] for i in incidents))
    by_priority = dict(Counter(i["priority"] or "Unspecified" for i in incidents))
    by_close_justification = dict(Counter(
        i["close_justification"] or "Unspecified" for i in incidents if i["close_justification"]
    ))

    label_counts = Counter()
    for i in incidents:
        for label in i["labels"]:
            label_counts[label] += 1
    top_alerts = dict(label_counts.most_common(10))

    monthly_trend = Counter()
    for i in incidents:
        created = i["created"]
        if created:
            try:
                dt = _parse_jira_date(created) or _parse_csv_date(created)
                if dt:
                    monthly_trend[dt.strftime("%Y-%m")] += 1
            except Exception:
                pass
    monthly_trend = dict(sorted(monthly_trend.items()))

    assignee_counts = dict(Counter(i["assignee"] or "Unassigned" for i in incidents))

    return {
        "total": total,
        "by_severity": by_severity,
        "by_status": by_status,
        "by_priority": by_priority,
        "by_close_justification": by_close_justification,
        "top_alerts": top_alerts,
        "monthly_trend": monthly_trend,
        "assignee_distribution": assignee_counts,
    }


# Closed-state vocabulary mirrors `_closed_statuses` in routes/reports.py. Kept
# here so derived metrics that classify "pending" can be computed at the data
# layer without importing from the routes module.
_CLOSED_STATUSES = {"closed", "resolved", "done", "complete", "completed"}

# Logicalis enriches each incident summary with a regional-entity prefix in the
# form "<CODE> | LOGICALIS-<n> | <SEVERITY> | <description>". The entity code is
# the operating entity the ticket belongs to (LSG, LMY, LHK, LTW, PSI, LAU, LCN,
# LVN, IZENO). It lives ONLY in the summary — no component/label/custom field
# carries it — and the enrichment lags ticket creation, so freshly-created
# tickets may not be prefixed yet. Requiring the "| LOGICALIS-" structure keeps
# an ordinary summary (e.g. "File shared with ...") from false-matching.
_ENTITY_PREFIX_RE = re.compile(r"^\s*([A-Za-z]{2,6})\s*\|\s*LOGICALIS-", re.IGNORECASE)
_ENTITY_ALIASES = {"IZ": "IZENO"}


def _entity_of(summary: str) -> str:
    """Regional entity code parsed from a Logicalis incident summary.

    Returns the normalised code (IZ -> IZENO) or ``"Unknown"`` when the summary
    carries no valid entity prefix, so an entity breakdown always reconciles to
    the full pending total instead of dropping unenriched tickets.
    """
    m = _ENTITY_PREFIX_RE.match(summary or "")
    if not m:
        return "Unknown"
    code = m.group(1).upper()
    return _ENTITY_ALIASES.get(code, code)

# Severity ranking used to surface "top critical" incidents and to bucket MTTR.
# Higher number = more severe. Unknown / blank severities sort last (0).
_SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
    "info": 1,
}


def _parse_any_date(value: str) -> datetime | None:
    """Parse either Jira ISO or CSV date strings. Returns timezone-naive datetime
    (Jira ISO is converted by stripping tzinfo) — caller only needs ordering
    and day-diff arithmetic, not exact UTC alignment."""
    if not value:
        return None
    dt = _parse_jira_date(value) or _parse_csv_date(value)
    if dt is None:
        return None
    if dt.tzinfo is not None:
        dt = dt.replace(tzinfo=None)
    return dt


def _compute_incident_derived_stats(incidents: list[dict], end_date: str) -> dict:
    """Compute derived/grounded statistics for AI consumption.

    Returned under `stats["derived"]` so the system prompt can reference a
    stable contract (e.g. `derived.mom_delta.delta_pct`). Every numeric field
    AI is allowed to cite must come from here — never from inline computation.

    Edge cases:
    - <2 months of history → mom_delta.insufficient_data = True
    - No resolved tickets → mttr.insufficient_data = True
    - No pending tickets → pending_aging all zero, oldest_pending empty list
    """
    end_dt = _parse_any_date(end_date) or datetime.now()

    # --- Month-over-month deltas for incident volume ---
    monthly_trend = Counter()
    for i in incidents:
        dt = _parse_any_date(i.get("created", ""))
        if dt:
            monthly_trend[dt.strftime("%Y-%m")] += 1
    monthly_trend = dict(sorted(monthly_trend.items()))

    months_sorted = list(monthly_trend.keys())
    if len(months_sorted) >= 2:
        cur_month, prev_month = months_sorted[-1], months_sorted[-2]
        cur_count = monthly_trend[cur_month]
        prev_count = monthly_trend[prev_month]
        delta_abs = cur_count - prev_count
        delta_pct = (delta_abs / prev_count * 100.0) if prev_count else None
        recent_three = months_sorted[-3:] if len(months_sorted) >= 3 else months_sorted
        three_month_avg = sum(monthly_trend[m] for m in recent_three) / len(recent_three)
        vs_avg_pct = ((cur_count - three_month_avg) / three_month_avg * 100.0) if three_month_avg else None
        mom_delta = {
            "current_month": cur_month,
            "current_count": cur_count,
            "previous_month": prev_month,
            "previous_count": prev_count,
            "delta_abs": delta_abs,
            "delta_pct": round(delta_pct, 1) if delta_pct is not None else None,
            "three_month_avg": round(three_month_avg, 1),
            "vs_avg_pct": round(vs_avg_pct, 1) if vs_avg_pct is not None else None,
            "insufficient_data": False,
        }
    else:
        mom_delta = {
            "current_month": months_sorted[-1] if months_sorted else None,
            "current_count": monthly_trend.get(months_sorted[-1], 0) if months_sorted else 0,
            "previous_month": None,
            "previous_count": None,
            "delta_abs": None,
            "delta_pct": None,
            "three_month_avg": None,
            "vs_avg_pct": None,
            "insufficient_data": True,
        }

    # --- MTTR (Mean Time To Resolution) ---
    # Some Jira workflows don't populate the system `resolved` field — they
    # close incidents via status transition only. When `resolved` is empty
    # but the status indicates the ticket is closed, fall back to the
    # `updated` timestamp as a proxy for resolution time. This is imprecise
    # (a late-updated comment will inflate MTTR) but is dramatically more
    # accurate than reporting `resolved_count: 0` for a customer with 880+
    # closed incidents.
    resolution_hours: list[float] = []
    resolution_hours_by_severity: dict[str, list[float]] = {}
    mttr_by_month: dict[str, list[float]] = {}
    for i in incidents:
        created_dt = _parse_any_date(i.get("created", ""))
        resolved_dt = _parse_any_date(i.get("resolved", ""))
        if not resolved_dt:
            status_lc = (i.get("status") or "").strip().lower()
            if status_lc in _CLOSED_STATUSES:
                resolved_dt = _parse_any_date(i.get("updated", ""))
        if not created_dt or not resolved_dt or resolved_dt < created_dt:
            continue
        hours = (resolved_dt - created_dt).total_seconds() / 3600.0
        resolution_hours.append(hours)
        sev = (i.get("severity") or "Unspecified").strip() or "Unspecified"
        resolution_hours_by_severity.setdefault(sev, []).append(hours)
        mttr_by_month.setdefault(resolved_dt.strftime("%Y-%m"), []).append(hours)

    if resolution_hours:
        mean_hours = sum(resolution_hours) / len(resolution_hours)
        by_sev_mean = {
            sev: round(sum(vals) / len(vals), 1)
            for sev, vals in resolution_hours_by_severity.items()
        }
        # MoM MTTR delta — anchor to the report's end_date month rather than
        # "whichever YYYY-MM key happened to sort last", which can be a
        # spillover month (e.g. 2 stragglers resolved after the report period
        # closed) and produces statistically meaningless deltas. Require ≥3
        # samples in each side of the comparison; otherwise mark None.
        _MTTR_MIN_SAMPLES = 3
        cur_key = end_dt.strftime("%Y-%m")
        prev_dt = (end_dt.replace(day=1) - timedelta(days=1))
        prev_key = prev_dt.strftime("%Y-%m")
        cur_samples = mttr_by_month.get(cur_key, [])
        prev_samples = mttr_by_month.get(prev_key, [])
        if len(cur_samples) >= _MTTR_MIN_SAMPLES and len(prev_samples) >= _MTTR_MIN_SAMPLES:
            cur_mttr = sum(cur_samples) / len(cur_samples)
            prev_mttr = sum(prev_samples) / len(prev_samples)
            mttr_delta_pct = ((cur_mttr - prev_mttr) / prev_mttr * 100.0) if prev_mttr else None
        else:
            mttr_delta_pct = None
        mttr = {
            "mean_hours": round(mean_hours, 1),
            "mean_hours_by_severity": by_sev_mean,
            "resolved_count": len(resolution_hours),
            "mom_delta_pct": round(mttr_delta_pct, 1) if mttr_delta_pct is not None else None,
            "insufficient_data": False,
        }
    else:
        mttr = {
            "mean_hours": None,
            "mean_hours_by_severity": {},
            "resolved_count": 0,
            "mom_delta_pct": None,
            "insufficient_data": True,
        }

    # --- Pending ticket aging ---
    pending = [
        i for i in incidents
        if (i.get("status") or "").strip().lower() not in _CLOSED_STATUSES
    ]
    aging_buckets = {"lt_7d": 0, "7_to_14d": 0, "14_to_30d": 0, "gt_30d": 0}
    # Per-entity aging breakdown (feedback #1). Counts EVERY pending ticket so
    # the grand total reconciles to len(pending): an undated ticket still adds
    # to its entity's `total`, just not to an aging sub-bucket. 'Unknown' holds
    # tickets whose summary carries no entity prefix.
    by_entity: dict[str, dict] = {}
    def _entity_row(name: str) -> dict:
        return by_entity.setdefault(
            name,
            {"entity": name, "total": 0,
             "lt_7d": 0, "7_to_14d": 0, "14_to_30d": 0, "gt_30d": 0},
        )
    pending_with_age: list[tuple[int, dict]] = []
    for p in pending:
        row = _entity_row(_entity_of(p.get("summary", "")))
        row["total"] += 1
        created_dt = _parse_any_date(p.get("created", ""))
        if not created_dt:
            continue
        age_days = max(0, (end_dt - created_dt).days)
        if age_days < 7:
            bucket = "lt_7d"
        elif age_days < 14:
            bucket = "7_to_14d"
        elif age_days < 30:
            bucket = "14_to_30d"
        else:
            bucket = "gt_30d"
        aging_buckets[bucket] += 1
        row[bucket] += 1
        pending_with_age.append((age_days, p))

    # Rank entities by pending volume; keep 'Unknown' last so it reads as a
    # residual rather than a ranked entity.
    entity_breakdown = sorted(
        by_entity.values(),
        key=lambda r: (r["entity"] == "Unknown", -r["total"], r["entity"]),
    )

    pending_with_age.sort(key=lambda pair: pair[0], reverse=True)
    oldest_pending = [
        {
            "key": rec.get("key", ""),
            "summary": rec.get("summary", ""),
            "severity": rec.get("severity", ""),
            "status": rec.get("status", ""),
            "created": rec.get("created", ""),
            "age_days": age_days,
        }
        for age_days, rec in pending_with_age[:5]
    ]
    pending_aging = {
        **aging_buckets,
        "total": len(pending),
        "oldest_age_days": pending_with_age[0][0] if pending_with_age else 0,
        "by_entity": entity_breakdown,
    }

    # --- Top 5 critical incidents (by severity rank, then created date desc) ---
    def _sev_sort_key(rec: dict) -> tuple[int, datetime]:
        sev = (rec.get("severity") or "").strip().lower()
        rank = _SEVERITY_RANK.get(sev, 0)
        created_dt = _parse_any_date(rec.get("created", "")) or datetime.min
        return (rank, created_dt)

    incidents_ranked = sorted(incidents, key=_sev_sort_key, reverse=True)
    top_critical_incidents = [
        {
            "key": rec.get("key", ""),
            "summary": rec.get("summary", ""),
            "severity": rec.get("severity", ""),
            "status": rec.get("status", ""),
            "created": rec.get("created", ""),
        }
        for rec in incidents_ranked[:5]
    ]

    return {
        "mom_delta": mom_delta,
        "mttr": mttr,
        "pending_aging": pending_aging,
        "top_critical_incidents": top_critical_incidents,
        "oldest_pending": oldest_pending,
    }


def _parse_csv_date(date_str: str) -> datetime | None:
    if not date_str:
        return None
    for fmt in ("%d/%m/%Y %H:%M", "%d/%m/%Y", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(date_str.strip(), fmt)
        except ValueError:
            continue
    return None


def fetch_incidents_from_csv(project_key: str, start_date: str, end_date: str,
                             csv_path: str | None = None) -> dict:
    if not csv_path:
        csv_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "samples", "sample-CAM Jira Dump.csv"
        )
    if not os.path.exists(csv_path):
        logger.error(f"Sample CSV not found at {csv_path}")
        return {"incidents": [], "stats": {}, "error": "Sample CSV not found"}

    try:
        start_dt = _parse_csv_date(start_date) or datetime(2000, 1, 1)
        end_dt = _parse_csv_date(end_date) or datetime(2099, 12, 31)
    except Exception:
        start_dt = datetime(2000, 1, 1)
        end_dt = datetime(2099, 12, 31)

    incidents = []
    with open(csv_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("Project key", "") != project_key and project_key:
                continue

            created_dt = _parse_csv_date(row.get("Created", ""))
            if created_dt and not (start_dt <= created_dt <= end_dt):
                continue

            # Use Tactics List as primary category (matches sample report's Category column)
            tactics = row.get("Custom field (Tactics List)", "").strip()
            # Clean up multi-tactic entries: take the first one
            category = tactics.split("  ")[0].strip() if tactics else ""

            incidents.append({
                "key": row.get("Issue key", ""),
                "summary": row.get("Summary", ""),
                "status": row.get("Status", ""),
                "priority": row.get("Priority", ""),
                "severity": _normalize_severity(
                    row.get("Custom field (Severity)", "").strip() or row.get("Priority", "").strip()
                ),
                "incident_type": category,
                "labels": [l.strip() for l in row.get("Labels", "").split(",") if l.strip()],
                "created": row.get("Created", ""),
                "updated": row.get("Updated", ""),
                "resolved": row.get("Resolved", ""),
                "assignee": row.get("Assignee", ""),
                "close_justification": row.get("Custom field (Close Justification)", ""),
                "resolution_summary": row.get("Custom field (Resolution Summary)", ""),
                "tactics_list": tactics,
            })

    stats = _compute_stats(incidents)
    stats["derived"] = _compute_incident_derived_stats(incidents, end_date)
    return {"incidents": incidents, "stats": stats}


def _fetch_jira_by_type(issue_type: str, project_key: str,
                        start_date: str, end_date: str,
                        project_spec: dict | None = None,
                        client: "JiraRestClient | None" = None) -> dict:
    """Generic Jira fetch by issue type. Returns {items, stats, unavailable}.

    REST goes through ``client.search`` (a :class:`JiraRestClient`), never a
    direct ``httpx.get``. Kept module-level (and directly callable) because
    ``test_issue_type_resolution`` invokes it with ``jira_search`` rebound — the
    client late-binds ``jira_search`` so that monkeypatch still intercepts.
    """
    client = client or JiraRestClient(project_spec)
    seen_keys = set()
    all_issues = []

    for chunk_start, chunk_end in _date_chunks(start_date, end_date):
        jql = (
            f'project = "{project_key}" '
            f'AND issuetype = "{issue_type}" '
            f'AND created >= "{chunk_start}" '
            f'AND created < "{chunk_end}" '
            f'ORDER BY created DESC'
        )
        next_token = None
        while len(all_issues) < 5000:
            result = client.search(jql, max_results=100, next_page_token=next_token)
            if "error" in result:
                if "HTTP 400" in result.get("error", "") or "HTTP 404" in result.get("error", ""):
                    logger.warning(f"Issue type '{issue_type}' not found in project {project_key}")
                    return {"items": [], "stats": {}, "unavailable": True}
                logger.error(f"Jira fetch failed for {issue_type}: {result}")
                return {"items": [], "stats": {}, "error": result["error"], "unavailable": False}

            issues = result.get("issues", [])
            for issue in issues:
                key = issue.get("key")
                if key and key not in seen_keys:
                    seen_keys.add(key)
                    all_issues.append(issue)

            next_token = result.get("nextPageToken")
            if not issues or not next_token or result.get("isLast") is True:
                break

    logger.info("_fetch_jira_by_type(%s/%s): total=%d", project_key, issue_type, len(all_issues))
    items = [_normalize_issue(i) for i in all_issues]
    stats = _compute_stats(items)
    return {"items": items, "stats": stats, "unavailable": False}


# Aliases tried (in order) when the configured issue type name does not exist
# in the target project. JSM cloud sites name the system types
# "[System] Change" / "[System] Service request", while the admin-UI default
# says "Change" / "Service Request" — names that are often valid site-wide, so
# the JQL returned 0 rows with no error and the report printed a false zero
# (NTCJ, July 2026). Resolution happens against the project's real type list;
# the "[System] " prefix is ignored when comparing, so most JSM projects match
# without needing an alias at all.
_CHANGE_REQUEST_ALIASES = ["Change", "Change Request", "RFC", "Change Management"]
_SERVICE_REQUEST_ALIASES = ["Service Request", "Service Desk Request"]

# Cache of {(base_url, project_key): [type names]}. Project type sets change
# rarely and one report run needs the list twice per project (SR + CR).
# Failed lookups are not cached so a transient error self-heals.
_project_issue_types_cache: dict = {}


def _get_project_issue_type_names(project_key: str,
                                  project_spec: dict | None = None) -> list[str] | None:
    """Names of the issue types available in a project, or None when the
    createmeta endpoint cannot be reached (permissions, network, old server)."""
    base_url, headers = _resolve_jira_auth(project_spec)
    cache_key = (base_url, project_key)
    if cache_key in _project_issue_types_cache:
        return _project_issue_types_cache[cache_key]
    try:
        r = httpx.get(
            f"{base_url}/rest/api/3/issue/createmeta/{project_key}/issuetypes",
            headers=headers, params={"maxResults": 200}, timeout=30,
        )
        if r.status_code >= 400:
            logger.warning("createmeta issuetypes HTTP %s for %s: %s",
                           r.status_code, project_key, r.text[:300])
            return None
        data = r.json()
        raw = data.get("issueTypes") or data.get("values") or []
        names = [t.get("name", "") for t in raw if t.get("name")]
    except Exception as e:
        logger.warning("createmeta issuetypes failed for %s: %s", project_key, e)
        return None
    _project_issue_types_cache[cache_key] = names
    return names


def _normalize_type_name(name: str) -> str:
    n = name.strip().lower()
    if n.startswith("[system]"):
        n = n[len("[system]"):].strip()
    return n


def _resolve_issue_type_for_project(configured: str, aliases: list[str],
                                    project_key: str,
                                    project_spec: dict | None = None,
                                    client: "JiraRestClient | None" = None) -> str | None:
    """Map a configured issue type name onto the name the project actually uses.

    Returns the project's canonical name (exact-casing) on a match, the
    configured name unchanged when the project's type list cannot be fetched
    (so behaviour degrades to the pre-validation JQL), or None when the type
    genuinely does not exist in the project — the caller marks the section
    unavailable so the report shows the "not configured" placeholder instead
    of a false zero.

    The project's type list is fetched through ``client.fetch_project_issue_types``
    (a :class:`JiraRestClient`), which late-binds
    ``_get_project_issue_type_names`` — so ``test_issue_type_resolution``'s
    rebind of that module-level name still intercepts."""
    client = client or JiraRestClient(project_spec)
    names = client.fetch_project_issue_types(project_key)
    if names is None:
        return configured
    lookup: dict[str, str] = {}
    for n in names:
        lookup.setdefault(n.strip().lower(), n)
        lookup.setdefault(_normalize_type_name(n), n)
    for candidate in [configured, *aliases]:
        hit = lookup.get(candidate.strip().lower()) or lookup.get(_normalize_type_name(candidate))
        if hit:
            if hit != configured:
                logger.info("Issue type '%s' resolved to '%s' for project %s",
                            configured, hit, project_key)
            return hit
    logger.warning("Issue type '%s' (aliases %s) not found in project %s — available types: %s",
                   configured, aliases, project_key, names)
    return None


def fetch_service_requests(project_key: str, start_date: str, end_date: str,
                           issue_type: str = "Service Request",
                           project_spec: dict | None = None) -> dict:
    """Fetch Service Request tickets from Jira for the given project and date range.

    The issue_type defaults to the canonical Atlassian/JSM name "Service Request",
    but customers whose Jira project uses a different label (e.g.
    "Service Desk Request") can override this per customer in the admin UI.
    The configured name is validated against the project's real issue types
    (with "[System] "-prefix-insensitive matching and alias fallback) so a
    name mismatch yields unavailable=True rather than a silent zero.

    Facade — delegates to the shared pipeline."""
    return _PIPELINE.fetch_service_requests(
        project_key, start_date, end_date,
        issue_type=issue_type, project_spec=project_spec,
    )


def fetch_change_requests(project_key: str, start_date: str, end_date: str,
                          issue_type: str = "Change",
                          project_spec: dict | None = None) -> dict:
    """Fetch Change Request tickets from Jira for the given project and date range.

    The issue_type defaults to "Change" (the JSM canonical name); per-customer
    overrides are supported for projects using alternatives like "RFC" or
    "Change Management". The configured name is validated against the
    project's real issue types (with "[System] "-prefix-insensitive matching
    and alias fallback) so a name mismatch yields unavailable=True rather
    than a silent zero.

    Facade — delegates to the shared pipeline."""
    return _PIPELINE.fetch_change_requests(
        project_key, start_date, end_date,
        issue_type=issue_type, project_spec=project_spec,
    )


# Sanity bound on the per-month pagination loop. Far above any plausible
# incident volume — its only job is to prevent a runaway loop if Jira ever
# misbehaves. NOT a truncation cap on real data.
_MONTHLY_FETCH_SAFETY_BOUND = 200_000


def _fetch_month_count(project_key: str, month_start: str, month_end: str,
                       issue_type: str = DEFAULT_INCIDENT_ISSUE_TYPE,
                       project_spec: dict | None = None) -> int:
    """Return the count of incidents for a single month window using cursor pagination.

    Uses full pagination — the loop terminates naturally on `isLast` /
    missing nextPageToken / empty page. The safety bound only protects
    against an upstream API bug that would otherwise spin forever; if it is
    ever hit on real data, that is a data-integrity incident, not a normal
    truncation, and is logged at WARNING.
    """
    jql = (
        f'{_incident_jql_filter(project_key, issue_type)} '
        f'AND created >= "{month_start}" '
        f'AND created < "{month_end}" '
        f'ORDER BY created ASC'
    )
    logger.info("_fetch_month_count JQL: %s", jql)
    base_url, headers = _resolve_jira_auth(project_spec)
    count = 0
    next_token = None
    while count < _MONTHLY_FETCH_SAFETY_BOUND:
        params: dict = {"jql": jql, "maxResults": 100, "fields": "created"}
        if next_token:
            params["nextPageToken"] = next_token
        r = httpx.get(
            f"{base_url}/rest/api/3/search/jql",
            headers=headers,
            params=params,
            timeout=30,
        )
        if r.status_code >= 400:
            logger.warning("_fetch_month_count HTTP %s for %s — JQL: %s — response: %s",
                           r.status_code, month_start, jql, r.text[:500])
            break
        data = r.json()
        issues = data.get("issues", [])
        count += len(issues)
        next_token = data.get("nextPageToken")
        if not issues or not next_token or data.get("isLast") is True:
            break
    if count >= _MONTHLY_FETCH_SAFETY_BOUND:
        logger.warning(
            "_fetch_month_count hit safety bound %d for %s — month count may be truncated. "
            "This is unexpected; investigate JIRA volume or pagination behaviour.",
            _MONTHLY_FETCH_SAFETY_BOUND, month_start,
        )
    logger.info("_fetch_month_count %s: %d issues", month_start, count)
    return count


def fetch_monthly_counts_12m(project_key: str, end_date: str,
                             incident_issue_type: str = DEFAULT_INCIDENT_ISSUE_TYPE,
                             project_spec: dict | None = None) -> dict:
    """Fetch incident counts per month for the 12 months ending at end_date.

    Queries one month at a time so that months with large issue counts (e.g. 700+)
    cannot cause the cursor to exhaust the page budget and starve earlier months.
    Each month is an independent paginated query — the same JQL filter used by
    fetch_incidents_for_report ensures consistency with the report data.

    Facade — delegates to the shared pipeline.
    """
    return _PIPELINE.fetch_monthly_counts_12m(
        project_key, end_date,
        incident_issue_type=incident_issue_type, project_spec=project_spec,
    )


# ── Multi-project orchestrator ───────────────────────────────────────────────
#
# A customer record can carry a ``jira_projects`` list (see
# tools/customers.py:_normalize_customer). When it has >1 entry, all the Jira
# fetches for a single report fan out across the projects in parallel and
# their results are merged into a single dict shaped exactly like a
# single-project response — so the downstream chart / template / LLM-prompt
# code is unchanged.
#
# Per-project auth: each project_spec can override base_url / email /
# api_token_kv_name independently. Blank fields fall back to env vars, so
# single-instance multi-project customers (the common case) need only set
# project_key + name.

def _sum_count_dicts(dicts: list[dict]) -> dict:
    """Sum a list of {key: int} dicts into one. Used to merge by-severity /
    by-status / etc. across multiple projects without losing per-key
    granularity. Non-numeric values are coerced via int() or skipped on
    TypeError so a malformed entry doesn't poison the rollup."""
    out: dict = {}
    for d in dicts:
        if not isinstance(d, dict):
            continue
        for k, v in d.items():
            try:
                out[k] = out.get(k, 0) + int(v)
            except (TypeError, ValueError):
                continue
    return out


def _merge_project_results(results: list[dict]) -> dict:
    """Combine N per-project fetches into a single dict shaped like a
    single-project response. See the table in
    /Users/.../plans/i-want-to-go-swirling-scroll.md for the merge rules.

    Each input dict has the shape returned by :func:`_fetch_project_data`:
        {
          "incidents": [...], "stats": {...},
          "service_requests": {"items": [...], "stats": {...},
                                "unavailable": bool} | None,
          "change_requests":  {...} | None,
          "monthly_trend_12m": {YYYY-MM: int} | None,
          "project_name": str, "project_key": str,
        }
    """
    if len(results) == 1:
        return results[0]

    # --- incidents: concat, then tag each with source_project ----------------
    merged_incidents: list = []
    incident_stats_dicts: dict[str, list[dict]] = {
        "by_severity": [], "by_status": [], "by_priority": [],
        "by_close_justification": [], "top_alerts": [],
        "monthly_trend": [], "assignee_distribution": [],
    }
    total_incidents = 0
    for r in results:
        proj_name = r.get("project_name", "")
        for inc in r.get("incidents", []):
            inc_copy = dict(inc)
            inc_copy.setdefault("source_project", proj_name)
            merged_incidents.append(inc_copy)
        s = r.get("stats") or {}
        total_incidents += int(s.get("total") or 0)
        for key in incident_stats_dicts:
            incident_stats_dicts[key].append(s.get(key) or {})

    merged_stats: dict = {"total": total_incidents}
    for key, ds in incident_stats_dicts.items():
        merged = _sum_count_dicts(ds)
        if key == "top_alerts":
            # Re-cap to top 10 after summing so the chart isn't dominated by long-tail.
            merged = dict(sorted(merged.items(), key=lambda kv: kv[1], reverse=True)[:10])
        elif key == "monthly_trend":
            merged = dict(sorted(merged.items()))
        merged_stats[key] = merged

    # --- service requests / change requests ----------------------------------
    def _merge_ticket_bucket(bucket_key: str) -> dict | None:
        buckets = [r.get(bucket_key) for r in results if r.get(bucket_key) is not None]
        if not buckets:
            return None
        items: list = []
        for b in buckets:
            items.extend(b.get("items") or [])
        stats = _compute_stats(items) if items else {}
        # unavailable is True only if EVERY project reported it unavailable.
        # If even one project returned data, surface that data and mark
        # available; the per-project unavailable flag for the others is lost
        # but the merged section is still useful.
        unavailable = all(bool(b.get("unavailable")) for b in buckets)
        return {"items": items, "stats": stats, "unavailable": unavailable}

    merged_service_requests = _merge_ticket_bucket("service_requests")
    merged_change_requests = _merge_ticket_bucket("change_requests")

    # --- 12-month trend: sum per YYYY-MM key --------------------------------
    trend_dicts = [r.get("monthly_trend_12m") for r in results
                   if isinstance(r.get("monthly_trend_12m"), dict)]
    merged_monthly_trend_12m: dict | None = None
    if trend_dicts:
        merged_monthly_trend_12m = dict(sorted(_sum_count_dicts(trend_dicts).items()))

    out: dict = {
        "incidents": merged_incidents,
        "stats": merged_stats,
        "project_breakdown": [
            {"name": r.get("project_name", ""),
             "project_key": r.get("project_key", ""),
             "total_incidents": int((r.get("stats") or {}).get("total") or 0)}
            for r in results
        ],
    }
    if merged_service_requests is not None:
        out["service_requests"] = merged_service_requests
    if merged_change_requests is not None:
        out["change_requests"] = merged_change_requests
    if merged_monthly_trend_12m is not None:
        out["monthly_trend_12m"] = merged_monthly_trend_12m
    return out


def _fetch_project_data(project_spec: dict, customer_record: dict,
                        start_date: str, end_date: str,
                        sections: list[str],
                        csv_path: str | None = None,
                        skip_monthly_trend: bool = False) -> dict:
    """Fetch all Jira data for one project. Single-project-shaped result
    that :func:`_merge_project_results` will combine if there are multiples.

    ``skip_monthly_trend`` short-circuits the 12-month trend fetch on the
    CSV path (where it has never been wired) and on callers that don't
    need it. Service / change requests are only fetched when the
    corresponding section was opted in.

    Facade — delegates to the shared pipeline, which builds one
    :class:`JiraRestClient` bound to ``project_spec`` for this project/thread.
    """
    return _PIPELINE._fetch_project_data(
        project_spec, customer_record, start_date, end_date, sections,
        csv_path=csv_path, skip_monthly_trend=skip_monthly_trend,
    )


def fetch_all_projects(customer_record: dict, start_date: str, end_date: str,
                       sections: list[str],
                       csv_path: str | None = None,
                       project_filter: str | None = None) -> dict:
    """Orchestrate Jira fetches across all of a customer's Jira projects.

    Returns a single dict with the same keys as a single-project response so
    downstream code (charts, templates, LLM prompt) does not need to know
    whether one or many projects were involved. The aggregated dict carries
    an extra ``project_breakdown`` list (one entry per project, with name +
    project_key + total_incidents) for any optional per-project sub-table.

    Parallelisation: projects are fetched concurrently via
    ThreadPoolExecutor, capped at 4 workers to avoid hammering small Jira
    Cloud instances with parallel cursor-paginated queries. Per-project
    fetches are serial inside each thread (incidents → SR → CR → 12-month).

    ``project_filter``: when set, only the project whose ``name`` matches is
    fetched. Used by the per-project fanout path in routes/reports.py.

    Facade — delegates to the shared pipeline.
    """
    return _PIPELINE.fetch_all_projects(
        customer_record, start_date, end_date, sections,
        csv_path=csv_path, project_filter=project_filter,
    )


# ── Seam objects (Refactor 3) ────────────────────────────────────────────────
#
# JiraRestClient and JiraReportPipeline give the REST layer and the report
# layer an explicit boundary so report derivation is stub-testable. They are a
# thin object layer OVER the module-level functions above, not a reimplementation
# of them: every method delegates to the module-global function BY NAME at call
# time (looked up via globals()[...] / the bare name), never by capturing a
# bound reference at construction. That is load-bearing — the existing tests
# rebind module-level names such as ``jira_client.jira_search`` and
# ``jira_client._get_project_issue_type_names`` and then invoke the report
# functions, so the interception only works if resolution is late. The
# module-level functions remain the real implementations and the primary,
# monkeypatchable API; these classes and the ``_PIPELINE`` facade below sit on
# top without changing any signature or import surface.


class JiraRestClient:
    """Stateless handle over the Jira REST primitives for one Jira instance.

    ``project_spec`` is locked at construction (per-call in the sense that a
    single client is bound to one customer/instance and passed the same spec on
    every REST call) — resolution of ``base_url`` / auth still happens inside
    the module-level primitives via :func:`_resolve_jira_auth`, honouring the
    Key Vault credential boundary. Concurrency (:func:`fetch_all_projects`
    fan-out) constructs one client per project/thread rather than sharing a
    single instance; the ``_project_issue_types_cache`` it reads stays
    MODULE-LEVEL so the type-name cache is shared across those per-thread
    clients for the process lifetime.

    Every method resolves its target module-level function by name at call time
    (``globals()[...]``) so test monkeypatches that rebind those names are
    honoured.
    """

    def __init__(self, project_spec: dict | None = None):
        self._project_spec = project_spec

    def search(self, jql: str, max_results: int = 100,
               next_page_token: str | None = None) -> dict:
        return globals()["jira_search"](
            jql, max_results=max_results, next_page_token=next_page_token,
            project_spec=self._project_spec,
        )

    def fetch_issue(self, key: str, fields: str = "*all") -> dict | None:
        return globals()["fetch_issue_by_key"](key, fields=fields)

    def fetch_project_issue_types(self, project_key: str) -> list[str] | None:
        return globals()["_get_project_issue_type_names"](
            project_key, project_spec=self._project_spec,
        )

    def fetch_month_count(self, project_key: str, month_start: str,
                          month_end: str,
                          issue_type: str = DEFAULT_INCIDENT_ISSUE_TYPE) -> int:
        return globals()["_fetch_month_count"](
            project_key, month_start, month_end,
            issue_type=issue_type, project_spec=self._project_spec,
        )


class JiraReportPipeline:
    """Report-data derivation that depends on a :class:`JiraRestClient` (or a
    stub exposing ``.search`` / ``.fetch_issue`` / ``.fetch_project_issue_types``
    / ``.fetch_month_count``).

    Reaches HTTP ONLY through a client — every REST call goes via
    ``self._client_for(project_spec).search(...)`` (or ``.fetch_month_count`` /
    ``.fetch_project_issue_types``); this class never calls ``httpx.get``, and
    never calls the module-level ``jira_search`` / ``_fetch_month_count`` /
    ``_get_project_issue_type_names`` directly. That is what makes report
    derivation stub-testable: injecting a stub client into ``__init__`` diverts
    all fetching to the stub with zero HTTP and zero monkeypatching.

    Client selection (:meth:`_client_for`):

    - If a client was *explicitly* injected at construction (the stub-test
      path, ``JiraReportPipeline(client=stub)``), that one client is used for
      every call regardless of the ``project_spec`` argument — the test drives
      the whole pipeline through its single stub.
    - Otherwise (the production ``_PIPELINE`` facade path, constructed with no
      client) each call builds a fresh :class:`JiraRestClient` bound to the
      call's ``project_spec`` — so multi-instance customers still get
      per-project auth, and the :func:`fetch_all_projects` fan-out constructs
      one client per project/thread.

    The pure derivation functions ``_compute_stats`` /
    ``_compute_incident_derived_stats`` and the merge/date helpers stay
    module-level and are called directly (no I/O).
    """

    def __init__(self, client: JiraRestClient | None = None):
        # Remember whether a client was *explicitly* injected — that decides
        # _client_for's behaviour (fixed stub vs. per-spec construction).
        self._injected_client = client
        self._client = client or JiraRestClient()

    def _client_for(self, project_spec: dict | None) -> JiraRestClient:
        """Client to use for a call. A stub injected at construction wins for
        every call (test path); otherwise build one bound to ``project_spec``."""
        if self._injected_client is not None:
            return self._injected_client
        return JiraRestClient(project_spec)

    # -- incidents ------------------------------------------------------------
    def fetch_incidents_for_report(self, project_key: str, start_date: str,
                                   end_date: str,
                                   incident_issue_type: str = DEFAULT_INCIDENT_ISSUE_TYPE,
                                   project_spec: dict | None = None) -> dict:
        if USE_SAMPLE_DATA:
            return self.fetch_incidents_from_csv(project_key, start_date, end_date)

        client = self._client_for(project_spec)
        seen_keys = set()
        all_issues = []

        for chunk_start, chunk_end in _date_chunks(start_date, end_date):
            jql = (
                f'{_incident_jql_filter(project_key, incident_issue_type)} '
                f'AND created >= "{chunk_start}" '
                f'AND created < "{chunk_end}" '
                f'ORDER BY created DESC'
            )
            issues = _fetch_all_pages(jql, client=client)
            for issue in issues:
                key = issue.get("key")
                if key and key not in seen_keys:
                    seen_keys.add(key)
                    all_issues.append(issue)

        logger.info("fetch_incidents_for_report(%s): total=%d",
                    project_key, len(all_issues))
        incidents = [_normalize_issue(i) for i in all_issues]
        stats = _compute_stats(incidents)
        stats["derived"] = _compute_incident_derived_stats(incidents, end_date)
        return {"incidents": incidents, "stats": stats}

    def fetch_incidents_from_csv(self, project_key: str, start_date: str,
                                 end_date: str,
                                 csv_path: str | None = None) -> dict:
        # CSV path does no REST — reads a local sample dump — so it stays a
        # direct call to the module-level function; no client involved.
        return fetch_incidents_from_csv(
            project_key, start_date, end_date, csv_path=csv_path,
        )

    # -- service / change requests -------------------------------------------
    def fetch_service_requests(self, project_key: str, start_date: str,
                               end_date: str,
                               issue_type: str = "Service Request",
                               project_spec: dict | None = None) -> dict:
        client = self._client_for(project_spec)
        try:
            resolved = _resolve_issue_type_for_project(
                issue_type or "Service Request", _SERVICE_REQUEST_ALIASES,
                project_key, client=client)
            if resolved is None:
                return {"items": [], "stats": {}, "unavailable": True}
            return _fetch_jira_by_type(resolved, project_key,
                                       start_date, end_date, client=client)
        except Exception as e:
            logger.warning(f"fetch_service_requests exception: {e}")
            return {"items": [], "stats": {}, "unavailable": True}

    def fetch_change_requests(self, project_key: str, start_date: str,
                              end_date: str, issue_type: str = "Change",
                              project_spec: dict | None = None) -> dict:
        client = self._client_for(project_spec)
        try:
            resolved = _resolve_issue_type_for_project(
                issue_type or "Change", _CHANGE_REQUEST_ALIASES,
                project_key, client=client)
            if resolved is None:
                return {"items": [], "stats": {}, "unavailable": True}
            return _fetch_jira_by_type(resolved, project_key,
                                       start_date, end_date, client=client)
        except Exception as e:
            logger.warning(f"fetch_change_requests exception: {e}")
            return {"items": [], "stats": {}, "unavailable": True}

    # -- 12-month trend -------------------------------------------------------
    def fetch_monthly_counts_12m(self, project_key: str, end_date: str,
                                 incident_issue_type: str = DEFAULT_INCIDENT_ISSUE_TYPE,
                                 project_spec: dict | None = None) -> dict:
        from dateutil.relativedelta import relativedelta

        try:
            end_dt = datetime.strptime(end_date, "%Y-%m-%d")
        except ValueError:
            logger.warning("fetch_monthly_counts_12m: invalid end_date %s", end_date)
            return {}

        client = self._client_for(project_spec)
        end_month = end_dt.replace(day=1)

        monthly_counts: dict[str, int] = {}
        for i in range(11, -1, -1):
            m = end_month - relativedelta(months=i)
            month_key = m.strftime("%Y-%m")
            month_start = m.strftime("%Y-%m-%d")
            month_end = (m + relativedelta(months=1)).strftime("%Y-%m-%d")
            count = client.fetch_month_count(
                project_key, month_start, month_end,
                issue_type=incident_issue_type)
            monthly_counts[month_key] = count
            logger.info("fetch_monthly_counts_12m(%s): %s = %d",
                        project_key, month_key, count)

        return monthly_counts

    # -- multi-project orchestration -----------------------------------------
    def _fetch_project_data(self, project_spec: dict, customer_record: dict,
                            start_date: str, end_date: str,
                            sections: list[str],
                            csv_path: str | None = None,
                            skip_monthly_trend: bool = False) -> dict:
        """Fetch all Jira data for one project via a client bound to
        ``project_spec`` (one client per project/thread in the fan-out)."""
        proj_key = (project_spec.get("project_key") or "").strip()
        proj_name = (project_spec.get("name") or proj_key or "Primary").strip()

        incident_issue_type = (customer_record.get("jira_incident_issuetype") or "").strip() \
            or DEFAULT_INCIDENT_ISSUE_TYPE
        sr_issue_type = (customer_record.get("jira_service_request_issuetype") or "").strip() \
            or "Service Request"
        cr_issue_type = (customer_record.get("jira_change_request_issuetype") or "").strip() \
            or "Change"

        if csv_path:
            result = self.fetch_incidents_from_csv(proj_key, start_date, end_date,
                                                   csv_path=csv_path)
        else:
            result = self.fetch_incidents_for_report(
                proj_key, start_date, end_date,
                incident_issue_type=incident_issue_type, project_spec=project_spec)

        out: dict = {
            "incidents": result.get("incidents") or [],
            "stats": result.get("stats") or {},
            "project_name": proj_name,
            "project_key": proj_key,
        }
        if result.get("error"):
            out["error"] = result["error"]

        if "service_requests" in sections and proj_key:
            out["service_requests"] = self.fetch_service_requests(
                proj_key, start_date, end_date,
                issue_type=sr_issue_type, project_spec=project_spec,
            )
        if "change_requests" in sections and proj_key:
            out["change_requests"] = self.fetch_change_requests(
                proj_key, start_date, end_date,
                issue_type=cr_issue_type, project_spec=project_spec,
            )
        if not csv_path and proj_key and not skip_monthly_trend:
            out["monthly_trend_12m"] = self.fetch_monthly_counts_12m(
                proj_key, end_date,
                incident_issue_type=incident_issue_type,
                project_spec=project_spec,
            )

        return out

    def fetch_all_projects(self, customer_record: dict, start_date: str,
                           end_date: str, sections: list[str],
                           csv_path: str | None = None,
                           project_filter: str | None = None) -> dict:
        projects = customer_record.get("jira_projects") or []
        if not projects:
            # No Jira projects configured — return an empty shell so the caller
            # can proceed with non-Jira sections. The downstream report flow
            # already tolerates zero incidents.
            return {"incidents": [], "stats": _compute_stats([])}

        if project_filter:
            projects = [p for p in projects if (p.get("name") or "") == project_filter]
            if not projects:
                logger.warning(
                    "fetch_all_projects: project_filter=%r matched no project in customer record",
                    project_filter,
                )
                return {"incidents": [], "stats": _compute_stats([])}

        # Single-project shortcut keeps the legacy 1-project install path
        # unchanged — no extra thread, no merge.
        if len(projects) == 1:
            return self._fetch_project_data(
                projects[0], customer_record, start_date, end_date, sections,
                csv_path=csv_path,
            )

        logger.info(
            "fetch_all_projects: fanning out across %d Jira projects for customer=%s",
            len(projects), customer_record.get("id", "?"),
        )
        results: list[dict] = []
        max_workers = min(4, len(projects))
        # Each thread runs _fetch_project_data, which builds its own client per
        # project via _client_for (no shared client across threads on the
        # production path). _project_issue_types_cache stays module-level so the
        # type-name cache is shared across those per-thread clients.
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                pool.submit(
                    self._fetch_project_data, p, customer_record, start_date,
                    end_date, sections, csv_path,
                ): p
                for p in projects
            }
            for fut in as_completed(futures):
                proj = futures[fut]
                try:
                    results.append(fut.result())
                except Exception as exc:
                    logger.error(
                        "fetch_all_projects: project=%s raised %s; skipping",
                        proj.get("name", "?"), exc,
                    )
                    # Carry an empty per-project result so the merge accounting
                    # is still correct (one entry per project, just empty).
                    results.append({
                        "incidents": [],
                        "stats": _compute_stats([]),
                        "project_name": proj.get("name", ""),
                        "project_key": proj.get("project_key", ""),
                        "error": str(exc),
                    })

        return self._merge_project_results(results)

    def _merge_project_results(self, results: list[dict]) -> dict:
        # Pure merge (no I/O) — delegates to the module-level helper.
        return _merge_project_results(results)


# Shared module-level pipeline instance backing the facade. Constructed with NO
# explicit client, so _client_for builds a fresh per-``project_spec`` client on
# every call (production path). Callers keep using the module-level functions
# (unchanged); this instance is what those facades delegate to.
_PIPELINE = JiraReportPipeline()
