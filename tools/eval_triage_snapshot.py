"""One-off CLI: pulls verdict-labeled Jira tickets into a frozen golden-set
fixture for the offline triage evaluation harness (see
docs/SPEC-triage-eval-harness.md).

Not part of the running app — invoked manually:
    python tools/eval_triage_snapshot.py --project SCDM --per-label-count 15

Pulls up to --per-label-count tickets per verdict label (True-Positive,
Benign-Positive, Unknown by default, overridable via the same
JIRA_TRIAGE_*_LABEL env vars tools.historical_alerts._label_names() reads)
and writes data/eval/triage_golden_set.json. That file is git-ignored (it
contains real customer ticket text) — see tools/eval_triage_run.py for the
script that replays this fixture through the live LLM.
"""
import argparse
import json
import logging
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import truststore
truststore.inject_into_ssl()  # trust the OS cert store, not just certifi's bundle

from dotenv import load_dotenv
load_dotenv()

from tools.jira_client import JiraRestClient
from tools.jira_schema import default_schema

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)

_GOLDEN_SET_PATH = os.path.join("data", "eval", "triage_golden_set.json")


def _label_names_raw() -> dict[str, str]:
    """Verdict label names as literally stored on Jira tickets (no
    lower-casing) — needed for JQL string-equality, unlike
    tools.historical_alerts._label_names()'s lower-cased variant which is
    for case-insensitive Python-side comparison."""
    return {
        "True-Positive": (os.environ.get("JIRA_TRIAGE_MALICIOUS_LABEL", "True-Positive") or "").strip(),
        "Benign-Positive": (os.environ.get("JIRA_TRIAGE_CLEAN_LABEL", "Benign-Positive") or "").strip(),
        "Unknown": (os.environ.get("JIRA_TRIAGE_UNKNOWN_LABEL", "Unknown") or "").strip(),
    }


def _current_commit() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, check=True, timeout=10,
        )
        return result.stdout.strip()
    except Exception as e:
        logger.warning("could not resolve git commit hash (%s); using 'unknown'", e)
        return "unknown"


def _derive_severity_and_baseline(fields: dict) -> tuple[str, str | None]:
    """Same derivation _run_triage_foundation uses (triage_orchestrator.py)."""
    sch = default_schema()
    raw = fields.get(sch.severity_field) or {}
    severity = (raw.get("value", "") if isinstance(raw, dict) else str(raw or "")).strip()
    baseline_priority = sch.severity_to_priority(severity)
    return severity, baseline_priority


def _pull_label(client: JiraRestClient, project: str, verdict_label: str,
                jira_label: str, per_label_count: int) -> list[dict]:
    if not jira_label:
        logger.warning("no label name resolved for verdict %r — skipping", verdict_label)
        return []

    jql = f'project = "{project}" AND labels = "{jira_label}" ORDER BY created DESC'
    response = client.search(jql, max_results=per_label_count)

    if "error" in response:
        logger.warning("Jira search failed for label %r (%s) — skipping this label",
                       jira_label, response.get("error"))
        return []

    issues = response.get("issues") or []
    if len(issues) < per_label_count:
        logger.warning("only found %d/%d tickets for label %r",
                       len(issues), per_label_count, jira_label)

    tickets = []
    for issue in issues:
        ticket_key = issue.get("key")
        fields = issue.get("fields") or {}
        severity, baseline_priority = _derive_severity_and_baseline(fields)
        tickets.append({
            "ticket_key": ticket_key,
            "verdict_label": verdict_label,
            "fields": fields,
            "severity": severity,
            "baseline_priority": baseline_priority,
        })
    return tickets


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True, help="Jira project key, e.g. SCDM")
    parser.add_argument("--per-label-count", type=int, default=15,
                        help="Tickets to pull per verdict label (default 15)")
    args = parser.parse_args()

    client = JiraRestClient()
    labels = _label_names_raw()

    all_tickets = []
    for verdict_label, jira_label in labels.items():
        tickets = _pull_label(client, args.project, verdict_label, jira_label, args.per_label_count)
        logger.info("pulled %d tickets for verdict %r (label %r)",
                    len(tickets), verdict_label, jira_label)
        all_tickets.extend(tickets)

    fixture = {
        "pulled_at_commit": _current_commit(),
        "jira_project": args.project,
        "per_label_count": args.per_label_count,
        "tickets": all_tickets,
    }

    os.makedirs(os.path.dirname(_GOLDEN_SET_PATH), exist_ok=True)
    with open(_GOLDEN_SET_PATH, "w", encoding="utf-8") as f:
        json.dump(fixture, f, indent=2)

    logger.info("wrote %d tickets total to %s", len(all_tickets), _GOLDEN_SET_PATH)


if __name__ == "__main__":
    main()
