"""
Jira webhook receiver for automated IOC enrichment.

Jira calls POST /webhook/jira?secret=<JIRA_WEBHOOK_SECRET> when a new issue
is created. We respond 200 immediately and process enrichment in a background
thread (same pattern as report generation).

The thread polls the Jira REST API every WEBHOOK_FETCH_DELAY_SECONDS (default 5)
until any Sentinel-style entity custom field becomes populated, or until
WEBHOOK_FETCH_MAX_WAIT_SECONDS (default 60) total elapses. This adaptive wait
handles the gap between issue_created firing and Service Desk request-form
field merging, which has been observed to take 30+ seconds in the SCDM
project. Tickets created programmatically (e.g. by soc-ticket-gateway) where
fields are populated atomically will trigger after the first poll.

Once entity fields are detected, the thread sleeps an additional
WEBHOOK_FETCH_STABILIZATION_SECONDS (default 30) and re-fetches the issue.
Service Desk merges entity fields in waves — the IP may appear first, then
Host/DNS/Hash arrive 20-30s later. The stabilization sleep lets later waves
land before we run the pipeline, so the comment captures all IOCs.

After the wait (or timeout), the latest fields are passed to enrich_ticket()
which produces the comment. Even on timeout we still run the pipeline — that
posts a "No IOCs found" comment, which is a useful signal.

Configure in Jira → System → Webhooks:
  URL:    https://<soc-platform-url>/webhook/jira?secret=<JIRA_WEBHOOK_SECRET>
  Events: Issue Created
  Filter: project = <JIRA_ENRICHMENT_PROJECT> (optional)
"""
import logging
import os
import threading
import uuid

from flask import Blueprint, jsonify, request

from tools.triage_orchestrator import run_enrichment

webhook_bp = Blueprint("webhook", __name__)
logger = logging.getLogger(__name__)

_jobs: dict[str, dict] = {}


def _handle_issue_updated(payload: dict):
    """Phase 7 (2026-06-16) — capture L2 decisions from label changes.

    When the analyst adds a 'True-Positive' / 'Benign-Positive' / 'Unknown'
    label to a ticket, we log an immutable decision row to data/
    triage_decisions.jsonl. Used by future few-shot triage prompts and
    auto-close FP (sub-features 2 + 3, deferred). Failure-isolated:
    bad payloads / disabled killswitch → 200 ignored, never raises.
    """
    if os.environ.get("DECISION_CAPTURE_ENABLED", "false").lower() != "true":
        return jsonify({"status": "ignored", "reason": "decision capture disabled"}), 200

    issue = payload.get("issue", {}) or {}
    ticket_key = issue.get("key", "")
    if not ticket_key:
        return jsonify({"status": "ignored", "reason": "no issue key"}), 200

    changelog = payload.get("changelog", {}) or {}
    items = changelog.get("items", []) or []
    label_changes = [i for i in items if (i.get("field") or "").lower() == "labels"]
    if not label_changes:
        return jsonify({"status": "ignored", "reason": "no label change"}), 200

    # Determine which triage label was newly added.
    _ML  = os.environ.get("JIRA_TRIAGE_MALICIOUS_LABEL", "True-Positive")
    _CL  = os.environ.get("JIRA_TRIAGE_CLEAN_LABEL",     "Benign-Positive")
    _UL  = os.environ.get("JIRA_TRIAGE_UNKNOWN_LABEL",   "Unknown")
    triage_labels = {_ML, _CL, _UL}

    added_triage_label = None
    platform_verdict = "unknown"
    for chg in label_changes:
        # Jira sends `toString` and `fromString` as space-separated label lists.
        before = set((chg.get("fromString") or "").split())
        after  = set((chg.get("toString")   or "").split())
        new_labels = after - before
        for lbl in new_labels:
            if lbl in triage_labels:
                added_triage_label = lbl
                break
        # Detect what the platform had labelled before (so we know what the
        # platform's original verdict was for the few-shot loop).
        for lbl in before & triage_labels:
            if   lbl == _ML: platform_verdict = "malicious"
            elif lbl == _CL: platform_verdict = "benign"
            elif lbl == _UL: platform_verdict = "unknown"
        if added_triage_label:
            break

    if not added_triage_label:
        return jsonify({"status": "ignored", "reason": "no triage-label addition"}), 200

    # The L2 decision is the newly-added triage label.
    fields = issue.get("fields", {}) or {}
    summary = fields.get("summary") or ""
    # Re-use Phase 3's rule-prefix derivation so this decision is keyed
    # the same way historical_alerts groups similar tickets.
    rule_prefix = summary[: int(os.environ.get("HISTORICAL_LOOKUP_SUMMARY_PREFIX_LEN", "60"))]

    project_key = (issue.get("fields", {}).get("project", {}) or {}).get("key", "") \
                  or ticket_key.split("-")[0]

    # Customer resolution (best-effort, never blocks the record write).
    customer_id = ""
    try:
        from tools.customers import find_customer_by_jira_project
        cust = find_customer_by_jira_project(project_key)
        customer_id = (cust or {}).get("id", "")
    except Exception:
        pass

    try:
        from tools.decisions import record_decision
        record_decision(
            ticket_key=ticket_key,
            project_key=project_key,
            customer_id=customer_id,
            rule_prefix=rule_prefix,
            l2_label=added_triage_label,
            platform_verdict=platform_verdict,
        )
    except Exception:
        logger.exception("Phase 7 record_decision dispatch failed for %s", ticket_key)
        return jsonify({"status": "error", "reason": "record_decision failed"}), 200

    return jsonify({
        "status": "recorded",
        "ticket": ticket_key,
        "l2_label": added_triage_label,
        "platform_verdict": platform_verdict,
    }), 200


@webhook_bp.route("/jira", methods=["POST"])
def jira_webhook():
    """Receive a Jira issue_created webhook and queue IOC enrichment.

    Phase 7 (2026-06-16) — also accepts issue_updated events and dispatches
    them to _handle_issue_updated() for decision capture. Same URL keeps
    Jira webhook config simple.
    """
    webhook_secret = os.environ.get("JIRA_WEBHOOK_SECRET", "")
    if webhook_secret:
        provided = request.args.get("secret", "")
        if provided != webhook_secret:
            logger.warning("Jira webhook: invalid secret from %s", request.remote_addr)
            return jsonify({"error": "Unauthorized"}), 401

    payload = request.get_json(silent=True) or {}
    event = payload.get("webhookEvent", "")

    # Phase 7 (2026-06-16) — handle issue_updated events for L2 decision
    # capture. Same endpoint as issue_created to keep the Jira webhook config
    # simple (one URL handles everything).
    if event == "jira:issue_updated":
        return _handle_issue_updated(payload)

    if event and event != "jira:issue_created":
        return jsonify({"status": "ignored", "reason": f"event '{event}' not processed"}), 200

    issue = payload.get("issue", {})
    ticket_key = issue.get("key", "")

    if not ticket_key:
        logger.warning("Jira webhook: missing issue key in payload")
        return jsonify({"status": "ignored", "reason": "no issue key"}), 200

    # Fail-closed allowlist: only projects explicitly listed in
    # JIRA_ENRICHMENT_PROJECT are enriched. An empty/unset allowlist denies ALL
    # tickets (rather than the old fail-open behaviour of processing everything),
    # so a blank or dropped env var can never silently open enrichment to every
    # customer project.
    allowed = {p.strip().upper()
               for p in os.environ.get("JIRA_ENRICHMENT_PROJECT", "").split(",")
               if p.strip()}
    project_key = ticket_key.split("-")[0].upper()
    if not allowed:
        logger.warning(
            "JIRA_ENRICHMENT_PROJECT is empty — denying enrichment for %s "
            "(fail-closed). Set the allowlist to enable processing.", ticket_key)
        return jsonify({"status": "ignored", "reason": "no project allowlist configured"}), 200
    if project_key not in allowed:
        return jsonify({"status": "ignored", "reason": "project not monitored"}), 200

    # Note: dedup runs INSIDE run_enrichment after polling completes, not here.
    # Running synchronously off the webhook payload was racy because the Sentinel
    # Logic App writes the Incident ID and entity fields asynchronously, often
    # arriving 20-30s after issue_created fires. Webhook-time derivation would
    # see an empty description, fall through to the Tier-3 fuzzy fallback, and
    # produce a key unrelated to the real incident. Kill switch
    # DEDUP_WEBHOOK_ENABLED is checked inside run_enrichment now.

    job_id = str(uuid.uuid4())
    _jobs[job_id] = {
        "status": "queued",
        "ticket": ticket_key,
        "result": None,
        "error": None,
    }

    threading.Thread(
        target=run_enrichment,
        args=(job_id, ticket_key),
        kwargs={"jobs": _jobs},
        daemon=True,
    ).start()

    logger.info("Jira webhook: queued enrichment job %s for ticket %s", job_id, ticket_key)
    return jsonify({"status": "queued", "job_id": job_id, "ticket": ticket_key}), 200


@webhook_bp.route("/jira/jobs/<job_id>", methods=["GET"])
def enrichment_job_status(job_id: str):
    """Poll enrichment job status. Returns job dict or 404."""
    job = _jobs.get(job_id)
    if not job:
        return jsonify({"error": "job not found"}), 404
    return jsonify(job), 200
