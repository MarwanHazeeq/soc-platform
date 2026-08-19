"""Standalone tests for tools/triage_orchestrator.py::run_enrichment — the
extracted background-worker pipeline shared by the Jira webhook auto-trigger and
the manual analyst-initiated triage runner.

Run:  python tools/test_triage_orchestrator.py

These lock in the Refactor-2 move (webhook.py → tools/triage_orchestrator.py):
  (a) manual entry (jobs explicit, manual=True) writes its job dict and reaches
      enrich_ticket();
  (b) webhook-auto entry (jobs explicit, manual=False) does the same;
  (c) run_enrichment now REQUIRES jobs= (the old module-global _jobs fallback is
      gone — see REFACTOR-2 Decision 1) — calling without it raises TypeError.

No Flask, no network, no real sleeps. We stub the orchestrator's collaborators by
monkeypatching them on the module: _await_ticket_ready (so no polling/fetch),
_apply_dedup_if_strict_match and _run_triage_foundation (side-effect steps), the
correlation/RAG lookups, and enrich_ticket itself. The dynamic-import stages
(alert pattern, KQL) are fail-open (try/except) so they harmlessly no-op here.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tools.triage_orchestrator as orch

_ISSUE = {"fields": {"summary": "EICAR test detection", "created": ""}}


def _install(calls):
    """Patch the orchestrator's collaborators so run_enrichment runs offline.

    Records into `calls`: which stages fired, and the enrich_ticket args.
    _await_ticket_ready returns a ready issue immediately (no polling).
    """
    def fake_await(job_id, ticket_key, schema, *, manual, jobs):
        calls["await_manual"] = manual
        jobs[job_id]["stage"] = "Fetching ticket from Jira"
        return _ISSUE

    def fake_dedup(ticket_key, fields):
        calls["dedup"] = True
        return None  # no strict match → pipeline continues to triage

    def fake_triage_foundation(*args, **kwargs):
        calls["triage_foundation"] = True

    def fake_enrich(ticket_key, fields, historical, rag_info, kql_evidence, schema, *, pattern=None):
        calls["enrich"] = True
        calls["enrich_ticket_key"] = ticket_key
        return {"verdict": "clean"}

    orch._await_ticket_ready = fake_await
    orch._apply_dedup_if_strict_match = fake_dedup
    orch._run_triage_foundation = fake_triage_foundation
    orch.enrich_ticket = fake_enrich
    # Stub the schema/customer/correlation calls so nothing touches Jira/DB.
    orch.find_customer_by_jira_project = lambda pk: None
    orch.resolve_jira_schema = lambda customer, pk: object()
    orch.query_similar_alerts = lambda *a, **k: None
    orch.retrieve_customer_context = lambda *a, **k: None


def _run():
    _orig = {
        "await": orch._await_ticket_ready,
        "dedup": orch._apply_dedup_if_strict_match,
        "tf": orch._run_triage_foundation,
        "enrich": orch.enrich_ticket,
        "cust": orch.find_customer_by_jira_project,
        "schema": orch.resolve_jira_schema,
        "hist": orch.query_similar_alerts,
        "rag": orch.retrieve_customer_context,
    }
    fails = 0

    def check(name, cond):
        nonlocal fails
        print(("  PASS" if cond else "  FAIL") + f"  {name}")
        if not cond:
            fails += 1

    try:
        # (a) MANUAL entry: jobs passed explicitly, manual=True.
        calls = {}
        _install(calls)
        jobs = {"j1": {"status": "queued", "ticket": "SCDM-100"}}
        orch.run_enrichment("j1", "SCDM-100", jobs=jobs, manual=True)
        check("manual: job marked done", jobs["j1"].get("status") == "done")
        check("manual: result written from enrich_ticket", jobs["j1"].get("result") == {"verdict": "clean"})
        check("manual: enrich_ticket reached", calls.get("enrich") is True)
        check("manual: enrich_ticket got the right ticket", calls.get("enrich_ticket_key") == "SCDM-100")
        check("manual: _await called with manual=True", calls.get("await_manual") is True)
        check("manual: dedup SKIPPED on manual path", "dedup" not in calls)
        check("manual: triage foundation ran", calls.get("triage_foundation") is True)

        # (b) WEBHOOK-AUTO entry: jobs passed explicitly, manual=False.
        os.environ["DEDUP_WEBHOOK_ENABLED"] = "false"  # keep dedup a pure no-op path
        calls = {}
        _install(calls)
        jobs = {"j2": {"status": "queued", "ticket": "SCDM-200"}}
        orch.run_enrichment("j2", "SCDM-200", jobs=jobs, manual=False)
        check("webhook: job marked done", jobs["j2"].get("status") == "done")
        check("webhook: result written from enrich_ticket", jobs["j2"].get("result") == {"verdict": "clean"})
        check("webhook: enrich_ticket reached", calls.get("enrich") is True)
        check("webhook: _await called with manual=False", calls.get("await_manual") is False)

        # (c) run_enrichment now REQUIRES jobs= (old _jobs global fallback removed).
        raised = False
        try:
            orch.run_enrichment("j3", "SCDM-300")  # no jobs= kwarg
        except TypeError:
            raised = True
        check("jobs= is required (TypeError without it)", raised)
    finally:
        orch._await_ticket_ready = _orig["await"]
        orch._apply_dedup_if_strict_match = _orig["dedup"]
        orch._run_triage_foundation = _orig["tf"]
        orch.enrich_ticket = _orig["enrich"]
        orch.find_customer_by_jira_project = _orig["cust"]
        orch.resolve_jira_schema = _orig["schema"]
        orch.query_similar_alerts = _orig["hist"]
        orch.retrieve_customer_context = _orig["rag"]

    print(f"\n{'ALL PASS' if fails == 0 else str(fails) + ' FAILED'}")
    return fails


if __name__ == "__main__":
    sys.exit(1 if _run() else 0)
