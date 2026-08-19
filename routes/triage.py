"""Manual L1 Triage runner — an analyst pastes a Jira ticket key and the full
enrichment pipeline runs on it on demand.

Design notes:
- Deliberately BYPASSES the JIRA_ENRICHMENT_PROJECT allowlist: the analyst is
  Entra-authenticated and acting intentionally. A non-allowlisted project or a
  project with no customer record produces a warning, not a block.
- Reuses tools.triage_orchestrator.run_enrichment with manual=True: the pasted ticket is
  NEVER dedup-closed, and the fetch does a SINGLE read with no entity-field
  polling — an existing ticket's fields either exist now or never will, so
  waiting only stalls the run (was the ~4-minute "stuck" bug on bare tickets).
- Jobs live in this module's own _manual_jobs dict, NOT webhook._jobs: the
  webhook job endpoint is login-exempt (/webhook/ prefix), so manual results
  must be polled through the authenticated endpoint below instead.
- Killswitch: MANUAL_TRIAGE_ENABLED (default false — code ships dark).
"""
import logging
import os
import re
import threading
import uuid

from flask import Blueprint, jsonify, render_template, request, session

from routes.auth import require_login
from tools.triage_orchestrator import run_enrichment
from tools.customers import find_customer_by_jira_project
from tools.jira_client import JIRA_URL, fetch_issue_by_key

triage_bp = Blueprint("triage", __name__)
logger = logging.getLogger(__name__)

_manual_jobs: dict[str, dict] = {}

_TICKET_RE = re.compile(r"^[A-Z][A-Z0-9_]*-\d+$")


def _enabled() -> bool:
    return os.environ.get("MANUAL_TRIAGE_ENABLED", "false").lower() == "true"


def _gate():
    """Return a 404 response when the feature is switched off, else None."""
    if not _enabled():
        return "Not found", 404
    return None


def _ticket_key_from_request() -> str:
    """Ticket key from ?ticket= or JSON {"ticket": ...}, normalised upper-case."""
    key = request.args.get("ticket") or ""
    if not key:
        payload = request.get_json(silent=True) or {}
        key = payload.get("ticket") or ""
    return key.strip().upper()


def _active_job_for(ticket_key: str) -> str | None:
    """Return the job_id of an in-flight run for this ticket, if any.

    Checks both the manual jobs and the webhook's own jobs so a manual run
    can't stack on top of a still-running webhook enrichment.
    """
    from routes import webhook as _webhook
    for job_id, job in _manual_jobs.items():
        if job.get("ticket") == ticket_key and job.get("status") == "queued":
            return job_id
    for job_id, job in _webhook._jobs.items():
        if job.get("ticket") == ticket_key and job.get("status") == "queued":
            return job_id
    return None


@triage_bp.route("/", methods=["GET"])
@require_login
def triage_page():
    gate = _gate()
    if gate:
        return gate
    return render_template(
        "triage.html",
        user=session.get("user", {}),
        active_mode="triage",
        jira_url=JIRA_URL,
    )


@triage_bp.route("/api/run", methods=["POST"])
@require_login
def api_run_triage():
    gate = _gate()
    if gate:
        return gate

    ticket_key = _ticket_key_from_request()
    if not ticket_key or not _TICKET_RE.match(ticket_key):
        return jsonify({"error": "Invalid ticket key format — expected e.g. SCDM-727"}), 400

    existing = _active_job_for(ticket_key)
    if existing:
        return jsonify({
            "error": f"A triage run is already in flight for {ticket_key}",
            "job_id": existing if existing in _manual_jobs else None,
        }), 409

    issue = fetch_issue_by_key(ticket_key, fields="summary,status,project,created")
    if not issue or "fields" not in issue:
        return jsonify({"error": f"Ticket {ticket_key} not found (or Jira unreachable)"}), 404
    fields = issue["fields"]
    summary = fields.get("summary") or ""
    status_name = ((fields.get("status") or {}).get("name")) or ""

    # Non-blocking warnings — manual runs proceed on any project.
    warnings: list[str] = []
    project_key = ticket_key.split("-")[0]
    allowed = {p.strip().upper()
               for p in os.environ.get("JIRA_ENRICHMENT_PROJECT", "").split(",")
               if p.strip()}
    if project_key not in allowed:
        warnings.append(
            f"Project {project_key} is not on the enrichment allowlist — manual run proceeds anyway.")
    try:
        customer = find_customer_by_jira_project(project_key)
    except Exception:
        customer = None
    if not customer:
        warnings.append(
            f"No customer record for project {project_key} — the default (SCDM) field schema will be used.")

    job_id = str(uuid.uuid4())
    _manual_jobs[job_id] = {
        "status": "queued",
        "ticket": ticket_key,
        "result": None,
        "error": None,
        "stage": "Queued",
        "submitted_by": (session.get("user") or {}).get("email", ""),
    }
    thread = threading.Thread(
        target=run_enrichment,
        args=(job_id, ticket_key),
        kwargs={"jobs": _manual_jobs, "manual": True},
        daemon=True,
    )
    thread.start()
    logger.info("Manual triage %s started for %s by %s",
                job_id, ticket_key, _manual_jobs[job_id]["submitted_by"])

    return jsonify({
        "job_id": job_id,
        "ticket": ticket_key,
        "summary": summary,
        "status_name": status_name,
        "warnings": warnings,
    }), 200


@triage_bp.route("/api/jobs/<job_id>", methods=["GET"])
@require_login
def api_triage_job_status(job_id: str):
    gate = _gate()
    if gate:
        return gate
    job = _manual_jobs.get(job_id)
    if not job:
        return jsonify({"error": "job not found"}), 404
    return jsonify(job), 200
