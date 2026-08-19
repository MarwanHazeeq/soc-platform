"""Standalone tests for tools/triage_orchestrator.py::_await_ticket_ready — the
Jira-fetch wait that run_enrichment uses.

Run:  python tools/test_manual_triage_wait.py

Regression guard for the manual-triage "stuck for ~4 minutes" bug: a manual run
on an EXISTING ticket must fetch ONCE and proceed, never polling for entity
fields to appear — even when those fields are empty (a ticket whose SIEM never
populated them, e.g. SCDM-745). The webhook path must keep its adaptive poll:
break early when entity data lands, and fall through to a timeout otherwise.

No network, no real sleeps: fetch_issue_by_key / has_entity_data / time.sleep
are all monkeypatched on the orchestrator module.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tools.triage_orchestrator as w

_ISSUE = {"fields": {"summary": "post-deploy EICAR probe"}}


def _install(fetch_returns, entity_returns):
    """Patch the module: fetch_issue_by_key yields from fetch_returns (or repeats
    the last), has_entity_data yields from entity_returns (or repeats the last).
    Returns a dict of call counters. No real sleeping."""
    calls = {"fetch": 0, "entity": 0, "slept": []}

    def fake_fetch(ticket_key, fields="*all"):
        i = min(calls["fetch"], len(fetch_returns) - 1)
        calls["fetch"] += 1
        return fetch_returns[i]

    def fake_entity(fields, schema):
        i = min(calls["entity"], len(entity_returns) - 1)
        calls["entity"] += 1
        return entity_returns[i]

    def fake_sleep(seconds):
        calls["slept"].append(seconds)

    w.fetch_issue_by_key = fake_fetch
    w.has_entity_data = fake_entity
    w.time.sleep = fake_sleep
    return calls


def _run():
    import time as _real_time
    _orig_fetch, _orig_entity, _orig_sleep = (
        w.fetch_issue_by_key, w.has_entity_data, w.time.sleep)
    fails = 0

    def check(name, cond):
        nonlocal fails
        print(("  PASS" if cond else "  FAIL") + f"  {name}")
        if not cond:
            fails += 1

    try:
        # 1. MANUAL, entity fields EMPTY → exactly one fetch, no waiting, returns issue.
        os.environ["WEBHOOK_FETCH_MAX_WAIT_SECONDS"] = "240"
        os.environ["WEBHOOK_FETCH_DELAY_SECONDS"] = "5"
        calls = _install([_ISSUE], [False])
        jobs = {"j": {}}
        out = w._await_ticket_ready("j", "SCDM-745", {}, manual=True, jobs=jobs)
        check("manual/empty: fetched exactly once (no poll loop)", calls["fetch"] == 1)
        check("manual/empty: returned the issue", out is _ISSUE)
        check("manual/empty: never slept the poll/max_wait", calls["slept"] == [])
        check("manual/empty: stage set", jobs["j"].get("stage") == "Fetching ticket from Jira")

        # 2. MANUAL, fetch returns junk (no fields) → returns None (caller errors out).
        calls = _install([{"nope": 1}], [False])
        out = w._await_ticket_ready("j", "SCDM-1", {}, manual=True, jobs={"j": {}})
        check("manual/no-fields: returns None", out is None)
        check("manual/no-fields: still one fetch", calls["fetch"] == 1)

        # 3. WEBHOOK, entity fields NEVER populate → polls to max_wait, returns last issue.
        os.environ["WEBHOOK_FETCH_MAX_WAIT_SECONDS"] = "3"
        os.environ["WEBHOOK_FETCH_DELAY_SECONDS"] = "1"
        os.environ["WEBHOOK_FETCH_STABILIZATION_SECONDS"] = "0"
        calls = _install([_ISSUE], [False])
        out = w._await_ticket_ready("j", "SCDM-2", {}, manual=False, jobs={"j": {}})
        check("webhook/empty: polled max_wait/delay = 3 times", calls["fetch"] == 3)
        check("webhook/empty: returns last issue (timeout path)", out is _ISSUE)

        # 4. WEBHOOK, entity data lands on the 2nd poll → breaks early + re-fetches.
        os.environ["WEBHOOK_FETCH_MAX_WAIT_SECONDS"] = "60"
        os.environ["WEBHOOK_FETCH_DELAY_SECONDS"] = "1"
        os.environ["WEBHOOK_FETCH_STABILIZATION_SECONDS"] = "0"
        final = {"fields": {"summary": "now with entities"}}
        # polls: #1 issue (no entity), #2 issue (entity!) → post-stabilization fetch #3 = final
        calls = _install([_ISSUE, _ISSUE, final], [False, True])
        out = w._await_ticket_ready("j", "SCDM-3", {}, manual=False, jobs={"j": {}})
        check("webhook/detect: broke early (3 fetches: 2 polls + re-fetch)", calls["fetch"] == 3)
        check("webhook/detect: returned post-stabilization issue", out is final)
    finally:
        w.fetch_issue_by_key, w.has_entity_data = _orig_fetch, _orig_entity
        w.time.sleep = _orig_sleep

    print(f"\n{'ALL PASS' if fails == 0 else str(fails) + ' FAILED'}")
    return fails


if __name__ == "__main__":
    sys.exit(1 if _run() else 0)
