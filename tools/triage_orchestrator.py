"""
Triage/enrichment orchestration for both entry points (Jira webhook auto-trigger
and the manual analyst-initiated "run triage" endpoint).

This module owns the background-worker pipeline that fetches a Jira issue, waits
for its Sentinel-style entity custom fields to populate, runs the Phase 1 triage
foundation (severity sync, GSOC assignment, LLM priority override) and dedup,
then hands off to `enrich_ticket()` to produce the enrichment comment. It was
extracted out of `routes/webhook.py` so both blueprints (`routes/webhook.py` and
`routes/triage.py`) depend on `tools/` rather than importing each other — one
feature = one blueprint + supporting logic in `tools/`.

The job-state registry (`_jobs` in `routes/webhook.py`, `_manual_jobs` in
`routes/triage.py`) stays owned by the routes; this module never owns that
process-local state and always requires the caller to pass its own `jobs=` dict.
"""
import logging
import os
import time

from tools.jira_schema import resolve_jira_schema, default_schema
from tools.dedup_jira import (
    append_occurrence,
    find_strict_duplicate,
    mark_as_duplicate,
    write_dedup_key,
)
from tools.customers import find_customer_by_jira_project
from tools.enrichment import enrich_ticket, has_entity_data, set_priority, assign_jira_ticket
from tools.gateway.dedup import derive_key_from_ticket
from tools.historical_alerts import query_similar_alerts
from tools.jira_client import fetch_issue_by_key
from tools.rag_retrieval import retrieve_customer_context
from tools.secrets import get_secret
from tools.triage import TRIAGE_CONFIDENCE_THRESHOLD, triage_priority

logger = logging.getLogger(__name__)


def _await_ticket_ready(job_id: str, ticket_key: str, schema, *,
                        manual: bool, jobs: dict) -> dict | None:
    """Fetch the Jira issue, returning the issue dict to enrich (or None).

    Webhook path (manual=False): the ticket was just created and its entity
    custom-fields (IP/host/hash/…) may still be populating, so poll every
    WEBHOOK_FETCH_DELAY_SECONDS until they appear (then wait
    WEBHOOK_FETCH_STABILIZATION_SECONDS for later waves and re-fetch), or until
    WEBHOOK_FETCH_MAX_WAIT_SECONDS elapses.

    Manual path (manual=True): an analyst is running triage on an EXISTING
    ticket. Its entity fields either exist now or never will — polling only
    stalls the run (up to the full max-wait when they are empty, the SCDM-745
    "stuck for 4 minutes" bug). So fetch ONCE and proceed with whatever is on
    the ticket.
    """
    jobs[job_id]["stage"] = "Fetching ticket from Jira"

    if manual:
        issue = fetch_issue_by_key(ticket_key)
        logger.info(
            "Enrichment %s: manual run — single fetch, no entity-field wait for %s",
            job_id, ticket_key,
        )
        return issue if (issue and "fields" in issue) else None

    poll_interval = int(os.environ.get("WEBHOOK_FETCH_DELAY_SECONDS", "5"))
    max_wait = int(os.environ.get("WEBHOOK_FETCH_MAX_WAIT_SECONDS", "60"))
    stabilization = int(os.environ.get("WEBHOOK_FETCH_STABILIZATION_SECONDS", "30"))
    elapsed = 0
    last_issue = None

    while elapsed < max_wait:
        time.sleep(poll_interval)
        elapsed += poll_interval

        issue = fetch_issue_by_key(ticket_key)
        if not issue or "fields" not in issue:
            logger.warning(
                "Enrichment %s: poll %ds — fetch failed for %s, will retry",
                job_id, elapsed, ticket_key,
            )
            continue

        last_issue = issue
        if has_entity_data(issue["fields"], schema):
            logger.info(
                "Enrichment %s: entity fields detected after %ds — sleeping %ds for stabilization",
                job_id, elapsed, stabilization,
            )
            if stabilization > 0:
                time.sleep(stabilization)
            final = fetch_issue_by_key(ticket_key)
            if final and "fields" in final:
                last_issue = final
                logger.info(
                    "Enrichment %s: post-stabilization fetch complete — proceeding",
                    job_id,
                )
            else:
                logger.warning(
                    "Enrichment %s: post-stabilization fetch failed — using pre-stabilization snapshot",
                    job_id,
                )
            break
        logger.info(
            "Enrichment %s: poll %ds — entity fields still empty for %s",
            job_id, elapsed, ticket_key,
        )
    else:
        logger.warning(
            "Enrichment %s: timeout after %ds — proceeding with whatever data is available for %s",
            job_id, max_wait, ticket_key,
        )
    return last_issue


def run_enrichment(job_id: str, ticket_key: str, *,
                   jobs: dict,
                   manual: bool = False) -> None:
    """Background worker. Polls the Jira API until entity fields are populated
    (or the max wait expires), then runs the enrichment pipeline once.

    jobs   — job-state dict to write status into. Required: the webhook route
             passes its own `_jobs`, the manual /triage runner passes its own
             `_manual_jobs` so manual results stay behind an authenticated
             endpoint.
    manual — analyst-initiated run on an EXISTING ticket: fetch the ticket ONCE
             and proceed (no entity-field polling — see _await_ticket_ready),
             and dedup is skipped entirely so the pasted ticket can never be
             auto-closed as a duplicate.
    """
    try:
        # Resolve the customer + per-customer Jira schema ONCE, up front. Entity
        # field IDs and severity mapping vary per customer; a project with no
        # customer record (or no schema override) resolves to the global defaults
        # (SCDM behaviour). project_key needs no Jira fetch.
        project_key = ticket_key.split("-")[0]
        try:
            customer = find_customer_by_jira_project(project_key)
        except Exception as _cust_err:
            logger.warning("Enrichment %s: customer lookup raised (%s); using default schema: %s",
                           job_id, type(_cust_err).__name__, _cust_err)
            customer = None
        schema = resolve_jira_schema(customer, project_key)

        last_issue = _await_ticket_ready(
            job_id, ticket_key, schema, manual=manual, jobs=jobs)

        if last_issue is None or "fields" not in last_issue:
            msg = f"failed to fetch issue {ticket_key} from Jira API after {elapsed}s"
            logger.error("Enrichment %s: %s", job_id, msg)
            jobs[job_id].update({"status": "error", "error": msg})
            return

        # Dedup MUST run on polled (fully populated) data, not the webhook payload.
        # The Sentinel Logic App writes Incident ID / entity fields asynchronously,
        # so the webhook payload often arrives before the description is populated —
        # which would cause derive_key_from_ticket() to fall through to the Tier-3
        # fuzzy fallback and produce a key that bears no relation to the actual
        # incident. Running here, after polling, guarantees Tier 1/2 see real data.
        dedup_result = None
        if not manual and os.environ.get("DEDUP_WEBHOOK_ENABLED", "true").lower() == "true":
            try:
                dedup_result = _apply_dedup_if_strict_match(ticket_key, last_issue["fields"])
            except Exception as e:
                logger.exception("Dedup check failed for %s; falling through to triage: %s",
                                 ticket_key, e)

        if dedup_result and dedup_result.get("action") == "closed":
            # Ticket was just closed as a duplicate — skip L1 Triage. Enriching a
            # closed ticket adds noise the analyst will never review.
            logger.info("Enrichment %s: skipping L1 Triage for %s (closed as duplicate of %s)",
                        job_id, ticket_key, dedup_result["original"])
            jobs[job_id].update({"status": "done", "result": dedup_result})
            return

        # ── Phase 3: Historical Alert Correlation ───────────────────────────
        # Looks up similar alerts in the past 24h (same Jira project + matching
        # summary prefix). Failure-safe — returns None on any error. The result
        # feeds both the Phase 1 LLM Triage call (de-escalation evidence) and
        # the enrichment comment (Similar Alerts section).
        historical = None
        jobs[job_id]["stage"] = "Historical alert correlation (24h)"
        try:
            project_key = ticket_key.split("-")[0]
            summary = (last_issue["fields"].get("summary") or "")
            historical = query_similar_alerts(ticket_key, summary, project_key)
        except Exception as e:
            logger.warning("Enrichment %s: historical lookup raised (%s); continuing without it: %s",
                           job_id, type(e).__name__, e)

        # ── Alert Pattern Analysis (30d) ─────────────────────────────────────
        # Extends Phase 3 to a 30-day view: frequency, first-ever occurrence,
        # business-hours timing pattern, per-entity prior-incident correlation
        # and a deterministic tuning recommendation. Killswitch defaults OFF
        # (ALERT_PATTERN_ANALYSIS_ENABLED). Module never raises and self-caps
        # at ALERT_PATTERN_TIMEOUT_S; this try/except is belt-and-suspenders.
        # Comment rendering uses `pattern`; the LLM Triage prompt only sees it
        # behind the separate ALERT_PATTERN_TO_LLM_PROMPT_ENABLED gate below.
        pattern = None
        jobs[job_id]["stage"] = "Alert pattern analysis (30d)"
        try:
            from tools.alert_pattern_analysis import analyze_alert_patterns
            project_key = ticket_key.split("-")[0]
            pattern = analyze_alert_patterns(ticket_key, last_issue["fields"], project_key, schema)
        except Exception as e:
            logger.warning("Enrichment %s: alert pattern analysis raised (%s); continuing without it: %s",
                           job_id, type(e).__name__, e)

        # ── Phase 4: RAG Customer Context retrieval ─────────────────────────
        # Vector search over indexed knowledge documents (HRT/HVT lists,
        # Escalation Matrix, Whitelists, Asset Inventory, etc.) for snippets
        # relevant to this ticket's summary + IOCs. Killswitch defaults OFF
        # (RAG_LOOKUP_ENABLED=false). Hard 5s timeout. Returns None on ANY
        # failure mode (disabled, timeout, embed error, store error, no
        # chunks above threshold) — pipeline always continues.
        #
        # Phase 4 MVP: RAG context is surfaced to the analyst in the
        # enrichment comment only, NOT fed into the LLM Triage prompt.
        # Mitigates the prior failure mode where bad retrievals confused
        # the LLM and degraded priority decisions. LLM integration is a
        # future opt-in (Phase 4c) contingent on retrieval quality.
        #
        # Phase 4b-rev (2026-06-15): retrieval is strictly customer-scoped.
        # Resolve the customer from the ticket's project key BEFORE the call;
        # tickets whose project key matches no customer get no Customer
        # Context section (silent skip).
        # rag_info: shape {pages_searched: int, status: "matched"|"no_matches",
        #                  chunks: list[dict]} OR None to suppress the section.
        # We only build rag_info when the customer was resolved AND has at
        # least one Confluence page registered AND retrieval actually ran
        # (statuses "matched" / "no_matches"). Every other status — disabled,
        # error, no_customer, no_query — is silent in the comment.
        rag_info = None
        jobs[job_id]["stage"] = "Customer context (RAG)"
        try:
            summary_text = (last_issue["fields"].get("summary") or "")
            query = summary_text[:500]
            project_key = ticket_key.split("-")[0]
            customer = find_customer_by_jira_project(project_key)
            customer_id = (customer or {}).get("id") or ""
            pages_count = len((customer or {}).get("confluence_pages") or [])
            if not customer_id:
                logger.info("Enrichment %s: no customer matched project_key=%s — "
                            "skipping RAG retrieval", job_id, project_key)
            elif pages_count == 0:
                logger.info("Enrichment %s: customer %s has no Confluence pages — "
                            "skipping RAG retrieval", job_id, customer_id)
            else:
                retrieval = retrieve_customer_context(query, customer_id=customer_id)
                status = (retrieval or {}).get("status") or "error"
                if status in ("matched", "no_matches"):
                    rag_info = {
                        "pages_searched": pages_count,
                        "status": status,
                        "chunks": list((retrieval or {}).get("chunks") or []),
                    }
        except Exception as e:
            logger.warning("Enrichment %s: RAG retrieval orchestrator raised (%s); continuing without it: %s",
                           job_id, type(e).__name__, e)

        # ── Phase 1: Triage Foundation ───────────────────────────────────────
        # Runs before enrichment so the priority/assignee are correct by the
        # time the IOC pipeline kicks in. Each step is independently failure-
        # tolerant — a hiccup here must not block enrichment.
        #
        # Phase 4c (2026-06-15): customer-scoped RAG context can now reach the
        # LLM Triage prompt, gated by:
        #   - RAG_TO_LLM_PROMPT_ENABLED (default false — code ships dark)
        #   - RAG_PROMPT_MIN_SCORE (default 0.7 — stricter than the comment's
        #     RAG_MIN_SCORE so noise that's safe to show analysts doesn't reach
        #     the model's priority reasoning).
        # We filter the SAME chunks already retrieved (no second retrieval).
        chunks_for_prompt: list[dict] = []
        try:
            if rag_info and os.environ.get("RAG_TO_LLM_PROMPT_ENABLED", "false").strip().lower() == "true":
                try:
                    prompt_threshold = float(os.environ.get("RAG_PROMPT_MIN_SCORE", "0.7"))
                except (TypeError, ValueError):
                    prompt_threshold = 0.7
                chunks_for_prompt = [
                    c for c in (rag_info.get("chunks") or [])
                    if float(c.get("score") or 0.0) >= prompt_threshold
                ]
                if chunks_for_prompt:
                    logger.info("Enrichment %s: passing %d RAG chunk(s) to LLM Triage prompt (>= %.2f)",
                                job_id, len(chunks_for_prompt), prompt_threshold)
        except Exception as e:
            logger.warning("Enrichment %s: RAG-to-prompt gate raised (%s); continuing without prompt chunks: %s",
                           job_id, type(e).__name__, e)
            chunks_for_prompt = []

        # Alert Pattern → LLM prompt gate (same conservative ladder as RAG 4c):
        # the comment always renders `pattern` when analysis ran; the LLM only
        # sees it once the team has validated section quality and flipped
        # ALERT_PATTERN_TO_LLM_PROMPT_ENABLED (default false — ships dark).
        pattern_for_prompt = None
        if pattern and os.environ.get("ALERT_PATTERN_TO_LLM_PROMPT_ENABLED", "false").strip().lower() == "true":
            pattern_for_prompt = pattern
            logger.info("Enrichment %s: passing alert pattern context to LLM Triage prompt", job_id)

        jobs[job_id]["stage"] = "L1 triage — severity sync, assignment, LLM priority"
        _run_triage_foundation(job_id, ticket_key, last_issue["fields"], historical, chunks_for_prompt, schema,
                               pattern_for_prompt)

        # ── Phase 5: AI-driven KQL expansion ─────────────────────────────────
        # Runs AFTER Phase 1 (so the triage call doesn't pay for KQL latency,
        # which can be up to 60s) and BEFORE enrich_ticket so the rendered
        # comment includes the Sentinel Evidence block. Killswitch defaults
        # OFF — code ships dark. Hot path: bounded by KQL_EXPANSION_TIMEOUT_S
        # and KQL_EXPANSION_MAX_ITERATIONS; failure-isolated (never raises;
        # None return = skip the section).
        kql_evidence = None
        jobs[job_id]["stage"] = "KQL evidence expansion"
        try:
            from tools.kql_expansion import expand_with_kql
            summary_text = (last_issue["fields"].get("summary") or "")
            description_text = ""
            try:
                from tools.jira_client import _extract_adf_text
                description_text = _extract_adf_text(last_issue["fields"].get("description")) or ""
            except Exception:
                description_text = ""
            # Reuse the IOCs the enrichment pipeline will extract anyway —
            # better than duplicating regex/entity extraction here.
            iocs_for_kql: list[dict] = []
            try:
                from tools.enrichment import extract_iocs_from_entity_fields
                iocs_for_kql = list(extract_iocs_from_entity_fields(last_issue["fields"], schema) or [])
            except Exception as _ioc_err:
                logger.warning("Enrichment %s: IOC extraction for KQL failed (%s); continuing with empty IOC list",
                               job_id, _ioc_err)
            kql_evidence = expand_with_kql(
                customer=customer if 'customer' in locals() else None,
                ticket_key=ticket_key,
                ticket_summary=summary_text,
                ticket_description=description_text,
                iocs=iocs_for_kql,
            )
        except Exception as e:
            logger.warning("Enrichment %s: KQL expansion orchestrator raised (%s); continuing without it: %s",
                           job_id, type(e).__name__, e)
            kql_evidence = None

        jobs[job_id]["stage"] = "IOC enrichment & comment"
        result = enrich_ticket(ticket_key, last_issue["fields"], historical, rag_info, kql_evidence, schema,
                               pattern=pattern)
        jobs[job_id].update({"status": "done", "result": result})
        logger.info("Enrichment %s complete: ticket=%s verdict=%s",
                    job_id, ticket_key, result.get("verdict"))
    except Exception as e:
        logger.exception("Enrichment %s failed for %s: %s", job_id, ticket_key, e)
        jobs[job_id].update({"status": "error", "error": str(e)})


def _run_triage_foundation(job_id: str, ticket_key: str, fields: dict,
                           historical: dict | None = None,
                           rag_chunks_for_prompt: list[dict] | None = None,
                           schema=None,
                           pattern_for_prompt: dict | None = None) -> None:
    """Phase 1 pre-enrichment steps. Each step logs and continues on failure
    so the downstream enrichment pipeline always runs.

      1. Severity sync — read the SIEM severity custom field (default
         customfield_10038) and set the Jira priority to match.
      2. GSOC auto-assign — assign the ticket to JIRA_GSOC_ACCOUNT_ID if set.
      3. LLM Triage — ask the model whether the actual impact warrants a
         different priority than the severity-mapped baseline; override only
         if confidence ≥ TRIAGE_CONFIDENCE_THRESHOLD AND recommendation
         differs from baseline.

    Phase 3 (2026-06-13): optional `historical` arg (precomputed by the
    caller) is passed through to triage_priority() so the LLM sees the
    same-rule FP/TP distribution as de-escalation evidence.

    Phase 4c (2026-06-15): optional `rag_chunks_for_prompt` arg — list of
    chunks already filtered against `RAG_PROMPT_MIN_SCORE` and gated by
    `RAG_TO_LLM_PROMPT_ENABLED` by the caller. Passed through to
    triage_priority() so customer-specific HVT/whitelist/asset-inventory
    context can influence the priority recommendation. Empty list or None
    suppresses the block entirely (no behavioural change from Phase 4b).
    """
    # ── 1. Severity sync ────────────────────────────────────────────────
    sch = schema or default_schema()
    severity_field_id = sch.severity_field
    raw = fields.get(severity_field_id) or {}
    severity = (raw.get("value", "") if isinstance(raw, dict) else str(raw or "")).strip()
    baseline_priority = sch.severity_to_priority(severity)
    if baseline_priority:
        set_priority(ticket_key, baseline_priority)
        logger.info("Triage %s: severity sync — '%s' → priority '%s' for %s",
                    job_id, severity, baseline_priority, ticket_key)
    else:
        logger.info("Triage %s: priority sync skipped for %s — unknown severity %r",
                    job_id, ticket_key, severity)

    # ── 2. GSOC auto-assign ─────────────────────────────────────────────
    gsoc_id = get_secret("JIRA_GSOC_ACCOUNT_ID")
    if gsoc_id:
        assign_jira_ticket(ticket_key, gsoc_id)
        logger.info("Triage %s: assigned %s to GSOC (%s)", job_id, ticket_key, gsoc_id)
    else:
        logger.info("Triage %s: GSOC assign skipped for %s — JIRA_GSOC_ACCOUNT_ID not set",
                    job_id, ticket_key)

    # ── 3. LLM Triage priority override ─────────────────────────────────
    rec = triage_priority(ticket_key, fields, severity, baseline_priority,
                          historical, rag_chunks_for_prompt, pattern_for_prompt)
    if not rec:
        logger.info("Triage %s: LLM rec unavailable for %s — keeping baseline",
                    job_id, ticket_key)
        return

    if rec["confidence"] < TRIAGE_CONFIDENCE_THRESHOLD:
        logger.info("Triage %s: override rejected for %s — confidence %.2f < %.2f",
                    job_id, ticket_key, rec["confidence"], TRIAGE_CONFIDENCE_THRESHOLD)
        return

    if rec["recommended_priority"] == baseline_priority:
        logger.info("Triage %s: LLM agrees with baseline (%s) for %s",
                    job_id, baseline_priority, ticket_key)
        return

    if set_priority(ticket_key, rec["recommended_priority"]):
        logger.info("Triage %s: override accepted for %s — %s → %s (confidence %.2f). Rationale: %s",
                    job_id, ticket_key, baseline_priority or "(none)",
                    rec["recommended_priority"], rec["confidence"], rec["rationale"][:200])


def _apply_dedup_if_strict_match(ticket_key: str, fields: dict) -> dict | None:
    """Post-creation dedup side effects.

    1. Determine the dedup key — read from cf_10125 if already populated
       (gateway path), or derive from ticket fields (Sentinel Logic App path).
    2. Write the derived key to cf_10125 so future searches can find this ticket.
    3. Search for an OLDER open ticket within 24h that strictly matches
       (same summary + same five typed entity fields).
    4. If strict match → mark this ticket as duplicate (prefix summary,
       comment-link, close with resolution=Duplicate) and bump occurrence
       count + last seen on the original.

    Returns a dict with action="closed" on dedup hit so the caller can skip
    L1 Triage (no point enriching a ticket we just closed). Returns None when
    no dedup action was taken — caller proceeds with normal triage.
    """
    dedup_field = os.environ.get("JIRA_FIELD_SOURCE_ALERT_ID", "customfield_10125")
    existing_key_value = fields.get(dedup_field)

    if existing_key_value:
        dedup_key = str(existing_key_value)
        logger.info("Webhook dedup: %s already carries key %s (gateway-created)",
                    ticket_key, dedup_key)
    else:
        dedup_key = derive_key_from_ticket(fields)
        if not dedup_key:
            logger.info("Webhook dedup: no signal in %s — skipping dedup", ticket_key)
            return None
        logger.info("Webhook dedup: derived key %s for %s", dedup_key, ticket_key)
        write_dedup_key(ticket_key, dedup_key)

    match = find_strict_duplicate(dedup_key, current_key=ticket_key, current_fields=fields)
    if not match:
        logger.info("Webhook dedup: no strict duplicate within 24h for %s (key=%s) — "
                    "proceeding to triage as standalone ticket",
                    ticket_key, dedup_key)
        return None

    original_key = match["key"]
    current_count = match["occurrence_count"]
    original_labels = match.get("labels") or []
    last_seen = fields.get("created", "")

    new_count = append_occurrence(original_key, current_count, ticket_key, last_seen)
    closed_ok = mark_as_duplicate(ticket_key, original_key, original_labels)

    logger.info("Webhook dedup STRICT MATCH: %s closed as duplicate of %s; "
                "original count=%s; close_ok=%s",
                ticket_key, original_key, new_count, closed_ok)
    return {
        "action": "closed",
        "original": original_key,
        "dedup_key": dedup_key,
        "occurrence_count": new_count,
    }
