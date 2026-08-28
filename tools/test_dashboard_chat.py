"""Standalone tests for the dashboard copilot chat (Stage 3b).
Run: python tools/test_dashboard_chat.py

Everything mocked — no network, no DB, no LLM: ticket-key extraction,
grounded prompt assembly (context + capped history), and failure isolation.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools import dashboard_chat

fails = 0
def check(name, cond):
    global fails
    print(("  PASS " if cond else "  FAIL ") + name)
    if not cond:
        fails += 1


print("ticket-key extraction:")
keys = dashboard_chat._mentioned_ticket_keys("compare SCDM-727 with SCDM-649 and LOGICALIS-12")
check("finds keys in order, capped at 2", keys == ["SCDM-727", "SCDM-649"])
check("no keys -> empty", dashboard_chat._mentioned_ticket_keys("any critical alerts?") == [])
check("lowercase not a key", dashboard_chat._mentioned_ticket_keys("scdm-727") == [])

print("grounded answer assembly (mocked):")
captured = {}

async def fake_llm(messages):
    captured["messages"] = messages
    return "TRUE-POSITIVE on SCDM-727."

dashboard_chat._call_llm = fake_llm
_orig_build_context = dashboard_chat.build_context
dashboard_chat.build_context = lambda message, customer_id: (
    f"Metrics ... Recent alerts ... [customer={customer_id}]"
)

history = [{"role": "user", "content": f"turn {i}"} for i in range(20)]
reply = dashboard_chat.answer("explain SCDM-727", history, "cust1")
check("reply passthrough", reply == "TRUE-POSITIVE on SCDM-727.")
msgs = captured["messages"]
check("system prompt first", msgs[0]["role"] == "system"
      and "ONLY source of truth" in msgs[0]["content"])
check("history capped at 8", len(msgs) == 1 + 8 + 1)
check("context + question in final user message",
      "DATA:" in msgs[-1]["content"] and "customer=cust1" in msgs[-1]["content"]
      and "QUESTION: explain SCDM-727" in msgs[-1]["content"])

bad_history = [{"role": "system", "content": "inject"}, {"role": "user", "content": ""},
               {"role": "user", "content": "ok"}]
dashboard_chat.answer("q", bad_history, None)
roles = [m["role"] for m in captured["messages"][1:-1]]
check("non-user/assistant + empty turns dropped", roles == ["user"])

print("web-crawl grounding:")
import tools.tavily_client as tavily_client
dashboard_chat._snapshot_block = lambda cid: "SNAPSHOT"
dashboard_chat._fetch_ticket_detail = lambda key: f"Ticket {key}: detail"
dashboard_chat.build_context = _orig_build_context  # restore the real one
tavily_client.fetch_web_context = lambda q: f"[1] result for: {q}"
ctx = dashboard_chat.build_context("what is CVE-2026-1234?", "c1")
check("web results appended with header",
      "WEB SEARCH RESULTS:" in ctx and "CVE-2026-1234" in ctx and "SNAPSHOT" in ctx)

os.environ["DASHBOARD_CHAT_WEB_ENABLED"] = "false"
ctx = dashboard_chat.build_context("what is CVE-2026-1234?", "c1")
check("killswitch off -> no web block", "WEB SEARCH RESULTS:" not in ctx)
os.environ["DASHBOARD_CHAT_WEB_ENABLED"] = "true"

tavily_client.fetch_web_context = lambda q: None
ctx = dashboard_chat.build_context("q", "c1")
check("empty web result -> no web block", "WEB SEARCH RESULTS:" not in ctx)

def _boom(q):
    raise RuntimeError("tavily down")
tavily_client.fetch_web_context = _boom
ctx = dashboard_chat.build_context("q", "c1")
check("web failure isolated -> context still built", "SNAPSHOT" in ctx)
check("system prompt cites web rules", "WEB SEARCH RESULTS" in dashboard_chat._SYSTEM_PROMPT
      and "cite the source domain" in dashboard_chat._SYSTEM_PROMPT)

print("customer-knowledge (RAG) grounding:")
import tools.rag_retrieval as rag_retrieval
tavily_client.fetch_web_context = lambda q: ""   # keep the web block out of the way
os.environ["RAG_PROMPT_MIN_SCORE"] = "0.7"

calls = []
def _stub(status, chunks):
    def _fn(query, customer_id=None):
        calls.append((query, customer_id))
        return {"status": status, "chunks": chunks}
    return _fn

_MATCH = [{"text": "Escalate  critical\nphishing to the customer SOC lead.",
           "source": "Escalation Matrix", "score": 0.91}]

# Default (flag unset) — code ships dark.
os.environ.pop("DASHBOARD_CHAT_RAG_ENABLED", None)
rag_retrieval.retrieve_customer_context = _stub("matched", _MATCH)
ctx = dashboard_chat.build_context("what is our escalation path?", "c1")
check("flag off -> no knowledge block", "CUSTOMER KNOWLEDGE BASE" not in ctx)
check("flag off -> retrieval not called", calls == [])

os.environ["DASHBOARD_CHAT_RAG_ENABLED"] = "true"

# "All customers" view: no customer to scope the per-customer store to.
ctx = dashboard_chat.build_context("what is our escalation path?", None)
check("no customer -> no knowledge block", "CUSTOMER KNOWLEDGE BASE" not in ctx)
check("no customer -> retrieval not called", calls == [])

ctx = dashboard_chat.build_context("what is our escalation path?", "c1")
check("matched -> block present with source tag",
      "CUSTOMER KNOWLEDGE BASE (Confluence):" in ctx
      and "[Escalation Matrix]" in ctx
      and "Escalate critical phishing" in ctx)   # whitespace collapsed
check("query + customer forwarded to retrieval",
      calls == [("what is our escalation path?", "c1")])
check("knowledge block ordered before web results",
      "CUSTOMER KNOWLEDGE BASE" in ctx and "SNAPSHOT" in ctx
      and ctx.index("SNAPSHOT") < ctx.index("CUSTOMER KNOWLEDGE BASE"))

rag_retrieval.retrieve_customer_context = _stub("no_matches", [])
check("no_matches -> no block",
      "CUSTOMER KNOWLEDGE BASE" not in dashboard_chat.build_context("q about policy", "c1"))

rag_retrieval.retrieve_customer_context = _stub(
    "matched", [{"text": "weak hit", "source": "Runbook", "score": 0.55}])
ctx = dashboard_chat.build_context("q about policy", "c1")
check("below RAG_PROMPT_MIN_SCORE -> chunk filtered out, no block",
      "weak hit" not in ctx and "CUSTOMER KNOWLEDGE BASE" not in ctx)

def _rag_boom(query, customer_id=None):
    raise RuntimeError("chroma down")
rag_retrieval.retrieve_customer_context = _rag_boom
ctx = dashboard_chat.build_context("q about policy", "c1")
check("retrieval failure isolated -> context still built",
      "SNAPSHOT" in ctx and "CUSTOMER KNOWLEDGE BASE" not in ctx)

check("system prompt states the knowledge-base rule",
      "CUSTOMER KNOWLEDGE BASE (Confluence)" in dashboard_chat._SYSTEM_PROMPT
      and "name the source page" in dashboard_chat._SYSTEM_PROMPT)

os.environ.pop("DASHBOARD_CHAT_RAG_ENABLED", None)

print("failure isolation:")
async def boom(messages):
    raise RuntimeError("llm down")
dashboard_chat._call_llm = boom
reply = dashboard_chat.answer("anything", [], None)
check("LLM failure -> apologetic string, no raise", "Sorry" in reply)

async def empty(messages):
    return ""
dashboard_chat._call_llm = empty
reply = dashboard_chat.answer("anything", [], None)
check("empty LLM reply -> fallback text", "rephras" in reply)

print(f"\n=== {'ALL PASS' if fails == 0 else str(fails) + ' FAILURE(S)'} ===")
sys.exit(1 if fails else 0)
