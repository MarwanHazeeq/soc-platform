"""Replays the frozen golden-set fixture (tools/eval_triage_snapshot.py)
through the real (unmocked) tools.triage.triage_priority() LLM call,
scores the effective post-threshold decision, appends a run entry to
data/eval/triage_run_log.jsonl, and diffs against the previous run.

Not part of the running app — invoked manually, before touching
tools/triage.py or its prompt (see docs/SPEC-triage-eval-harness.md):

    python tools/eval_triage_run.py
    python tools/eval_triage_run.py --verbose

Never calls set_priority()/assign_jira_ticket() or any other function that
mutates a real Jira ticket — only triage_priority() (read + LLM call) and
the pure decide_effective_priority() are exercised.
"""
import argparse
import hashlib
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

from tools.triage import TRIAGE_CONFIDENCE_THRESHOLD, _SYSTEM_PROMPT, decide_effective_priority, triage_priority

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)

_GOLDEN_SET_PATH = os.path.join("data", "eval", "triage_golden_set.json")
_RUN_LOG_PATH = os.path.join("data", "eval", "triage_run_log.jsonl")

_PRIORITY_ORDER = ["Lowest", "Low", "Medium", "High", "Highest"]


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


def _load_golden_set() -> dict:
    if not os.path.exists(_GOLDEN_SET_PATH):
        logger.error("%s not found — run tools/eval_triage_snapshot.py first", _GOLDEN_SET_PATH)
        sys.exit(1)
    with open(_GOLDEN_SET_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _load_previous_run() -> list[dict] | None:
    """Return the `results` list of the most recent line in the run-log, or
    None if the run-log doesn't exist yet (first-ever run)."""
    if not os.path.exists(_RUN_LOG_PATH):
        return None
    last_line = None
    with open(_RUN_LOG_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                last_line = line
    if not last_line:
        return None
    return json.loads(last_line)["results"]


def diff_runs(prev_results: list[dict] | None, curr_results: list[dict]) -> list[dict]:
    """Pure diff of a run's results against the previous run's results,
    matched by ticket_key. Standalone so it's unit-testable without running
    the full script (see tools/test_triage_eval_scoring.py)."""
    prev_by_key = {r["ticket_key"]: r for r in (prev_results or [])}

    diffs = []
    for curr in curr_results:
        prev = prev_by_key.get(curr["ticket_key"])
        is_new = prev is None
        changed = (not is_new) and (
            prev["effective_priority"] != curr["effective_priority"]
            or prev["accepted_override"] != curr["accepted_override"]
        )
        diffs.append({
            "ticket_key": curr["ticket_key"],
            "prev_effective_priority": prev["effective_priority"] if prev else None,
            "curr_effective_priority": curr["effective_priority"],
            "prev_accepted_override": prev["accepted_override"] if prev else None,
            "curr_accepted_override": curr["accepted_override"],
            "changed": changed,
            "is_new": is_new,
        })
    return diffs


def _directional_flag(verdict_label: str, baseline_priority: str | None,
                      effective_priority: str | None) -> str | None:
    """True-Positive tickets shouldn't be de-escalated below baseline;
    Benign-Positive tickets shouldn't be escalated above baseline. Unknown
    tickets have no clear expected direction — never flagged."""
    if baseline_priority not in _PRIORITY_ORDER or effective_priority not in _PRIORITY_ORDER:
        return None
    base_idx = _PRIORITY_ORDER.index(baseline_priority)
    eff_idx = _PRIORITY_ORDER.index(effective_priority)
    if verdict_label == "True-Positive" and eff_idx < base_idx:
        return "DE-ESCALATED a True-Positive"
    if verdict_label == "Benign-Positive" and eff_idx > base_idx:
        return "ESCALATED a Benign-Positive"
    return None


def _run_ticket(ticket: dict) -> dict:
    rec = triage_priority(
        ticket["ticket_key"], ticket["fields"], ticket["severity"],
        ticket["baseline_priority"], temperature=0,
    )
    decision = decide_effective_priority(rec, ticket["baseline_priority"])
    return {
        "ticket_key": ticket["ticket_key"],
        "verdict_label": ticket["verdict_label"],
        "baseline_priority": ticket["baseline_priority"],
        "raw_recommendation": rec,
        "effective_priority": decision["effective_priority"],
        "accepted_override": decision["accepted_override"],
        "reason": decision["reason"],
    }


def _print_report(results: list[dict], diffs: list[dict], verbose: bool) -> None:
    diffs_by_key = {d["ticket_key"]: d for d in diffs}

    header = f"{'TICKET':<14}{'VERDICT':<18}{'BASELINE':<10}{'EFFECTIVE':<10}{'OVERRIDE':<10}{'STATUS'}"
    print(header)
    print("-" * len(header))

    changed_count = 0
    for r in results:
        d = diffs_by_key.get(r["ticket_key"], {})
        status_bits = []
        if d.get("is_new"):
            status_bits.append("NEW")
        elif d.get("changed"):
            status_bits.append("CHANGED")
            changed_count += 1

        flag = _directional_flag(r["verdict_label"], r["baseline_priority"], r["effective_priority"])
        if flag:
            status_bits.append(flag)

        print(f"{r['ticket_key']:<14}{r['verdict_label']:<18}{r['baseline_priority'] or '-':<10}"
              f"{r['effective_priority'] or '-':<10}{str(r['accepted_override']):<10}{' '.join(status_bits)}")

        if verbose:
            rec = r["raw_recommendation"]
            if rec:
                print(f"    confidence={rec['confidence']:.2f} rationale={rec['rationale']}")
            else:
                print(f"    (no recommendation — reason={r['reason']})")

    print()
    print(f"{changed_count} ticket(s) changed since last run")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verbose", action="store_true", help="show full rationale/confidence per ticket")
    args = parser.parse_args()

    golden_set = _load_golden_set()
    tickets = golden_set.get("tickets", [])
    logger.info("replaying %d tickets from %s", len(tickets), _GOLDEN_SET_PATH)

    results = [_run_ticket(t) for t in tickets]

    prev_results = _load_previous_run()
    if prev_results is None:
        logger.info("no previous run found — this is the first run, nothing to diff against")
        diffs = diff_runs(None, results)
    else:
        diffs = diff_runs(prev_results, results)

    entry = {
        "run_at_commit": _current_commit(),
        "prompt_hash": hashlib.sha256(_SYSTEM_PROMPT.encode()).hexdigest(),
        "threshold": TRIAGE_CONFIDENCE_THRESHOLD,
        "results": results,
    }

    os.makedirs(os.path.dirname(_RUN_LOG_PATH), exist_ok=True)
    with open(_RUN_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    _print_report(results, diffs, args.verbose)


if __name__ == "__main__":
    main()
