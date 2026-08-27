"""Standalone tests for the offline triage evaluation harness's pure scoring
logic: tools.triage.decide_effective_priority() and
tools.eval_triage_run.diff_runs().

Run:  python tools/test_triage_eval_scoring.py

No network, no LLM, no Jira — entirely synthetic in-memory data. See
docs/SPEC-triage-eval-harness.md.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.triage import decide_effective_priority
from tools.eval_triage_run import diff_runs


def _run():
    fails = 0

    def check(name, cond):
        nonlocal fails
        print(("  PASS" if cond else "  FAIL") + f"  {name}")
        if not cond:
            fails += 1

    # ── decide_effective_priority() — four branches ─────────────────────

    d = decide_effective_priority(None, "High")
    check("decide: no recommendation -> keeps baseline", d["effective_priority"] == "High")
    check("decide: no recommendation -> not accepted", d["accepted_override"] is False)
    check("decide: no recommendation -> reason", d["reason"] == "no_recommendation")

    rec_low_conf = {"recommended_priority": "Highest", "confidence": 0.5, "rationale": "meh"}
    d = decide_effective_priority(rec_low_conf, "High")
    check("decide: below threshold -> keeps baseline", d["effective_priority"] == "High")
    check("decide: below threshold -> not accepted", d["accepted_override"] is False)
    check("decide: below threshold -> reason", d["reason"] == "below_threshold")

    rec_agrees = {"recommended_priority": "High", "confidence": 0.9, "rationale": "matches"}
    d = decide_effective_priority(rec_agrees, "High")
    check("decide: agrees with baseline -> keeps baseline", d["effective_priority"] == "High")
    check("decide: agrees with baseline -> not accepted", d["accepted_override"] is False)
    check("decide: agrees with baseline -> reason", d["reason"] == "agrees_with_baseline")

    rec_override = {"recommended_priority": "Highest", "confidence": 0.9, "rationale": "escalate"}
    d = decide_effective_priority(rec_override, "High")
    check("decide: override accepted -> uses recommendation", d["effective_priority"] == "Highest")
    check("decide: override accepted -> accepted", d["accepted_override"] is True)
    check("decide: override accepted -> reason", d["reason"] == "override_accepted")

    # ── diff_runs() ──────────────────────────────────────────────────────

    prev = [
        {"ticket_key": "SCDM-1", "effective_priority": "High", "accepted_override": False},
        {"ticket_key": "SCDM-2", "effective_priority": "Medium", "accepted_override": False},
        {"ticket_key": "SCDM-3", "effective_priority": "Medium", "accepted_override": False},
    ]
    curr = [
        {"ticket_key": "SCDM-1", "effective_priority": "Highest", "accepted_override": True},  # changed
        {"ticket_key": "SCDM-2", "effective_priority": "Medium", "accepted_override": False},   # unchanged
        {"ticket_key": "SCDM-4", "effective_priority": "Low", "accepted_override": False},      # new
    ]
    diffs = diff_runs(prev, curr)
    by_key = {d["ticket_key"]: d for d in diffs}

    check("diff: changed ticket flagged changed", by_key["SCDM-1"]["changed"] is True)
    check("diff: changed ticket not flagged new", by_key["SCDM-1"]["is_new"] is False)
    check("diff: unchanged ticket not flagged changed", by_key["SCDM-2"]["changed"] is False)
    check("diff: new ticket flagged is_new", by_key["SCDM-4"]["is_new"] is True)
    check("diff: new ticket not flagged changed", by_key["SCDM-4"]["changed"] is False)
    check("diff: new ticket has no prev values", by_key["SCDM-4"]["prev_effective_priority"] is None)
    check("diff: ticket absent from current run is simply not in the diff",
         "SCDM-3" not in by_key)

    # accepted_override flips while effective_priority coincidentally matches baseline text
    prev2 = [{"ticket_key": "SCDM-9", "effective_priority": "High", "accepted_override": False}]
    curr2 = [{"ticket_key": "SCDM-9", "effective_priority": "High", "accepted_override": True}]
    diffs2 = diff_runs(prev2, curr2)
    check("diff: accepted_override-only flip is still 'changed'", diffs2[0]["changed"] is True)

    # first-ever run: no previous results at all
    diffs3 = diff_runs(None, curr)
    check("diff: first run treats every ticket as new",
         all(d["is_new"] for d in diffs3))
    check("diff: first run never flags changed",
         all(not d["changed"] for d in diffs3))

    print(f"\n{'ALL PASS' if fails == 0 else str(fails) + ' FAILED'}")
    return fails


if __name__ == "__main__":
    sys.exit(1 if _run() else 0)
