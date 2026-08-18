"""Standalone tests for the Refactor 3 seam: JiraReportPipeline driven by a
stub JiraRestClient, with ZERO httpx mocking.

Run: python tools/test_jira_report_pipeline.py

The whole point of the split is that report derivation
(`_compute_stats` / `_compute_incident_derived_stats`) and the report fetches
(`fetch_incidents_for_report` / `fetch_monthly_counts_12m`) can be exercised
against a stub client that returns canned Jira-shaped payloads — no network,
no `httpx` monkeypatch. We drive the stub two ways:

  1. Directly against the pure functions, feeding normalized incident dicts.
  2. Through the module-level facade functions, whose REST reach we redirect to
     the stub by rebinding the module-level seam names (`jira_search`,
     `_fetch_month_count`) — the same late-binding monkeypatch style the other
     jira_client tests already rely on. This proves the pipeline talks to the
     seam, not to httpx.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tools.jira_client as jc
from tools.jira_client import (
    JiraRestClient,
    JiraReportPipeline,
    _compute_stats,
    _compute_incident_derived_stats,
)

fails = 0


def check(name, cond):
    global fails
    print(("  PASS " if cond else "  FAIL ") + name)
    if not cond:
        fails += 1


# ── Stub REST client ─────────────────────────────────────────────────────────
class StubJiraRestClient:
    """Canned stand-in for JiraRestClient. Records calls; returns fixtures.

    `search`  -> pages of raw Jira issues keyed by next_page_token.
    `fetch_issue` -> a single raw issue dict.
    `fetch_month_count` -> an int per (project, month_start).
    """

    def __init__(self, search_pages=None, issue=None, month_counts=None):
        self._search_pages = search_pages or {None: {"issues": [], "isLast": True}}
        self._issue = issue
        self._month_counts = month_counts or {}
        self.search_calls = []
        self.issue_calls = []
        self.month_calls = []

    def search(self, jql, max_results=100, next_page_token=None):
        self.search_calls.append((jql, max_results, next_page_token))
        return self._search_pages.get(next_page_token, {"issues": [], "isLast": True})

    def fetch_issue(self, key, fields="*all"):
        self.issue_calls.append((key, fields))
        return self._issue

    def fetch_project_issue_types(self, project_key):
        return None

    def fetch_month_count(self, project_key, month_start, month_end,
                          issue_type=jc.DEFAULT_INCIDENT_ISSUE_TYPE):
        self.month_calls.append((project_key, month_start, month_end, issue_type))
        return self._month_counts.get((project_key, month_start), 0)


def _raw_issue(key, created, severity=None, status="Open", labels=None,
               summary="", resolved="", updated="", assignee=None):
    """Build a raw Jira issue dict shaped like the /search response `issues`."""
    fields = {
        "summary": summary,
        "status": {"name": status},
        "priority": {"name": "Medium"},
        "labels": labels or [],
        "created": created,
        "updated": updated,
        "resolved": resolved,
    }
    if severity is not None:
        fields["customfield_10038"] = {"value": severity}
    if assignee is not None:
        fields["assignee"] = {"displayName": assignee}
    return {"key": key, "fields": fields}


# ── 1. Pure derivation via stub client output ────────────────────────────────
print("== _compute_stats / _compute_incident_derived_stats (pure) ==")

# Feed normalized incident dicts (the shape _normalize_issue produces) straight
# into the pure functions — this is what the pipeline hands them post-fetch.
incidents = [
    {"key": "A-1", "summary": "LSG | LOGICALIS-1 | HIGH | x", "status": "Open",
     "priority": "High", "severity": "High", "incident_type": "", "labels": ["brute-force"],
     "created": "2026-05-10T09:00:00.000+0800", "updated": "", "resolved": "",
     "assignee": "Alice", "close_justification": "", "resolution_summary": "", "tactics_list": ""},
    {"key": "A-2", "summary": "LSG | LOGICALIS-2 | LOW | y", "status": "Closed",
     "priority": "Low", "severity": "Low", "incident_type": "", "labels": ["brute-force"],
     "created": "2026-06-05T09:00:00.000+0800", "updated": "2026-06-06T09:00:00.000+0800",
     "resolved": "2026-06-06T09:00:00.000+0800",
     "assignee": "Bob", "close_justification": "Benign", "resolution_summary": "", "tactics_list": ""},
    {"key": "A-3", "summary": "Plain summary no entity", "status": "Open",
     "priority": "Medium", "severity": "Medium", "incident_type": "", "labels": [],
     "created": "2026-06-20T09:00:00.000+0800", "updated": "", "resolved": "",
     "assignee": "", "close_justification": "", "resolution_summary": "", "tactics_list": ""},
]

stats = _compute_stats(incidents)
check("total counted", stats["total"] == 3)
check("by_severity aggregated", stats["by_severity"] == {"High": 1, "Low": 1, "Medium": 1})
check("by_status aggregated", stats["by_status"] == {"Open": 2, "Closed": 1})
check("top_alerts label counted", stats["top_alerts"].get("brute-force") == 2)
check("assignee distribution incl. Unassigned",
      stats["assignee_distribution"].get("Unassigned") == 1)

derived = _compute_incident_derived_stats(incidents, "2026-06-30")
check("mom_delta present (>=2 months)", derived["mom_delta"]["insufficient_data"] is False)
check("mttr computed from one resolved (fallback via Closed status)",
      derived["mttr"]["resolved_count"] == 1)
check("pending aging total = 2 open", derived["pending_aging"]["total"] == 2)
ent = {r["entity"]: r for r in derived["pending_aging"]["by_entity"]}
check("entity breakdown reconciles to pending total",
      sum(r["total"] for r in derived["pending_aging"]["by_entity"]) == 2)
check("LSG entity parsed", "LSG" in ent)
check("unprefixed pending -> Unknown", "Unknown" in ent)


# ── 2. fetch_incidents_for_report through the stub (no httpx) ─────────────────
print("== fetch_incidents_for_report via stub client ==")

# The stub is wired in by redirecting the module-level seam (`jira_search`) to
# it. Zero httpx involved — jira_client.jira_search is never reached.
end_date = "2026-06-30"
stub = StubJiraRestClient(search_pages={
    None: {
        "issues": [
            _raw_issue("R-1", "2026-06-28T10:00:00.000+0800", severity="High",
                       status="Open", summary="LSG | LOGICALIS-1 | HIGH | a",
                       labels=["phish"]),
            _raw_issue("R-2", "2026-06-10T10:00:00.000+0800", severity="Low",
                       status="Closed", resolved="2026-06-11T10:00:00.000+0800",
                       summary="LSG | LOGICALIS-2 | LOW | b"),
        ],
        "isLast": True,
    },
})

_orig_jira_search = jc.jira_search
# Redirect the module-level primitive to the stub. The pipeline / facade calls
# jira_search(...) by module-global name; this intercepts at the seam, not HTTP.
jc.jira_search = lambda jql, max_results=100, next_page_token=None, project_spec=None: \
    stub.search(jql, max_results=max_results, next_page_token=next_page_token)

try:
    pipeline = JiraReportPipeline(JiraRestClient())
    result = pipeline.fetch_incidents_for_report("LSG", "2026-06-01", end_date)
    check("returns incidents + stats", set(result) >= {"incidents", "stats"})
    check("both incidents normalized", len(result["incidents"]) == 2)
    check("stats.total via pipeline", result["stats"]["total"] == 2)
    check("severity normalized in pipeline output",
          {i["severity"] for i in result["incidents"]} == {"High", "Low"})
    check("derived stats attached under stats.derived",
          "derived" in result["stats"] and "pending_aging" in result["stats"]["derived"])
    check("one pending (R-1 open), one closed excluded",
          result["stats"]["derived"]["pending_aging"]["total"] == 1)
    check("stub actually queried (proves no httpx path)", len(stub.search_calls) >= 1)

    # Same call via the bare module-level facade function must behave identically.
    facade_result = jc.fetch_incidents_for_report("LSG", "2026-06-01", end_date)
    check("facade fn matches pipeline method",
          facade_result["stats"]["total"] == result["stats"]["total"])
finally:
    jc.jira_search = _orig_jira_search


# ── 3. fetch_monthly_counts_12m through the stub (no httpx) ───────────────────
print("== fetch_monthly_counts_12m via stub client ==")

month_stub = StubJiraRestClient(month_counts={
    ("LSG", "2026-06-01"): 42,
    ("LSG", "2026-05-01"): 17,
})

_orig_month_count = jc._fetch_month_count
# Redirect the module-level month-count primitive to the stub client. Again the
# pipeline reaches this by module-global name — no httpx.get is exercised.
jc._fetch_month_count = lambda project_key, month_start, month_end, \
    issue_type=jc.DEFAULT_INCIDENT_ISSUE_TYPE, project_spec=None: \
    month_stub.fetch_month_count(project_key, month_start, month_end, issue_type=issue_type)

try:
    pipeline = JiraReportPipeline(JiraRestClient())
    counts = pipeline.fetch_monthly_counts_12m("LSG", "2026-06-30")
    check("12 month keys returned", len(counts) == 12)
    check("June count from stub", counts.get("2026-06") == 42)
    check("May count from stub", counts.get("2026-05") == 17)
    check("unstubbed month defaults to 0", counts.get("2026-01") == 0)
    check("stub month_count actually called 12x", len(month_stub.month_calls) == 12)
finally:
    jc._fetch_month_count = _orig_month_count


# ── 4. JiraRestClient is late-binding (monkeypatch-safe) ─────────────────────
print("== JiraRestClient late-binding delegation ==")

_orig = jc.jira_search
_seen = {}
jc.jira_search = lambda jql, max_results=100, next_page_token=None, project_spec=None: \
    _seen.setdefault("spec", project_spec) or {"issues": [], "isLast": True}
try:
    client = JiraRestClient(project_spec={"project_key": "LSG", "base_url": "x"})
    client.search("project = LSG")
    check("client.search resolves rebound jira_search at call time",
          "spec" in _seen)
    check("client forwards its locked project_spec",
          _seen["spec"] == {"project_key": "LSG", "base_url": "x"})
finally:
    jc.jira_search = _orig


print()
if fails:
    print(f"{fails} FAILED")
    sys.exit(1)
print("ALL PASS")
