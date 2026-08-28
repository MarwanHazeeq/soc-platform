"""
Dashboard copilot chat — grounded Q&A over the analyst's own alert data.

Replaces the retired SOCRadar Investigate copilot in the dashboard chat
panel. No per-user OAuth: uses the same Azure OpenAI client as the L1
pipeline (tools/llm_client.make_chat_client), available to every analyst
immediately after SSO login.

Grounding is DETERMINISTIC, not agentic — each question is answered with
context the server injects up front:
  1. Ticket keys mentioned in the message (e.g. SCDM-727) are fetched live
     from Jira (summary/status/priority + the L1 enrichment comment).
  2. A snapshot of recent tickets for the selected customer from the
     dashboard_tickets read-model (key, severity, verdict, status, summary).
  3. The current metric values.
  4. Web search results (Tavily — same engine as ioc_insights) so the
     copilot can reach out for external knowledge: CVEs, threat actors,
     tools, IP/domain reputation context. Killswitch
     DASHBOARD_CHAT_WEB_ENABLED (default on); fail-silent.
  5. Customer-scoped Confluence knowledge (the same Phase 4 RAG store the
     automated L1 triage comment draws on — runbooks, escalation matrices,
     whitelists, asset inventories) so the copilot can answer "what does
     OUR procedure say" rather than only "what happened". Requires a
     customer to be selected; the "All customers" view skips it.
     Killswitch DASHBOARD_CHAT_RAG_ENABLED (default off); fail-silent.
The model is instructed to treat the alert data as the ONLY source of truth
about tickets, treat the knowledge base as customer policy, use web results
only for external knowledge (citing source domains), and say so when none of
them contains the answer.

Failure isolation: answer() never raises — it returns an apologetic string
on any error, and the L1 pipeline is never touched.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re

logger = logging.getLogger(__name__)

TIMEOUT_S = int(os.environ.get("DASHBOARD_CHAT_TIMEOUT_S", "60"))
_MAX_HISTORY = 8            # prior turns forwarded to the model
_MAX_TICKET_FETCHES = 2     # live Jira lookups per question
_SNAPSHOT_ROWS = 50         # read-model rows in the context
_MAX_COMMENT_CHARS = 1800   # cap per fetched enrichment comment
_MAX_RAG_CHUNK_CHARS = 700  # cap per retrieved Confluence chunk

_TICKET_KEY_RE = re.compile(r"\b[A-Z][A-Z0-9]{1,9}-\d{1,6}\b")

_SYSTEM_PROMPT = (
    "You are the SOC dashboard copilot for Logicalis SOC analysts. The user "
    "message contains a DATA section (recent-alert snapshot, metrics, fetched "
    "ticket details) and may contain a CUSTOMER KNOWLEDGE BASE (Confluence) "
    "section and a WEB SEARCH RESULTS section. Rules: "
    "(1) The DATA section is the ONLY source of truth about the customer's "
    "tickets, verdicts, IOCs, and timestamps — never invent or infer ticket "
    "facts beyond it. "
    "(2) The CUSTOMER KNOWLEDGE BASE (Confluence) section, when present, is "
    "the customer's own documented procedure — runbooks, escalation matrices, "
    "whitelists, asset inventories. Prefer it over general knowledge for "
    "'what should we do' questions, and name the source page in parentheses "
    "for any claim drawn from it. It describes policy, not live ticket facts. "
    "(3) Use WEB SEARCH RESULTS for external knowledge — CVEs, threat actors, "
    "malware, tools, IP/domain reputation, event-ID meanings — and cite the "
    "source domain in parentheses for any web-derived claim. "
    "(4) If none of them contains the answer, say so plainly and suggest what "
    "the analyst could check. "
    "Always reference tickets by their key (e.g. SCDM-727). Be concise: a "
    "few sentences, or a short list when comparing several items. Plain "
    "text only — no markdown formatting."
)


def _mentioned_ticket_keys(message: str) -> list[str]:
    seen: list[str] = []
    for key in _TICKET_KEY_RE.findall(message or ""):
        if key not in seen:
            seen.append(key)
    return seen[:_MAX_TICKET_FETCHES]


def _fetch_ticket_detail(key: str) -> str:
    """Compact live-Jira summary of one ticket incl. the latest L1 enrichment
    comment. Returns '' when the ticket can't be fetched."""
    from tools.jira_client import fetch_issue_by_key, _extract_adf_text

    issue = fetch_issue_by_key(
        key,
        fields="summary,status,priority,labels,created,assignee,resolution,"
               "comment,customfield_10038,customfield_10488",
    )
    if not issue:
        return ""
    f = issue.get("fields", {}) or {}
    sev = (f.get("customfield_10038") or {}).get("value", "")
    lines = [
        f"Ticket {key}:",
        f"  summary: {f.get('summary', '')}",
        f"  status: {(f.get('status') or {}).get('name', '')} | "
        f"priority: {(f.get('priority') or {}).get('name', '')} | severity: {sev}",
        f"  assignee: {(f.get('assignee') or {}).get('displayName', '') or 'unassigned'}"
        f" | labels: {', '.join(f.get('labels') or []) or 'none'}",
        f"  created: {f.get('created', '')}",
    ]
    # Latest L1 enrichment comment (the bot's full analysis).
    comments = ((f.get("comment") or {}).get("comments")) or []
    for c in reversed(comments):
        text = _extract_adf_text(c.get("body"))
        if "L1 Triage Report (Automated)" in text or "VERDICT:" in text:
            lines.append("  latest L1 enrichment comment: "
                         + text[:_MAX_COMMENT_CHARS])
            break
    return "\n".join(lines)


def _snapshot_block(customer_id: str | None) -> str:
    """Recent tickets + metrics from the read-model, compactly."""
    from tools import db
    parts: list[str] = []
    try:
        m = db.load_dashboard_metrics(customer_id, window_days=7)
        parts.append(
            "Metrics (last 7 days): "
            f"active={m['active']}, critical_or_high={m['critical']}, "
            f"avg_response_seconds={m['avg_response_seconds']}, "
            f"auto_resolved_pct={m['auto_resolved_pct']}"
        )
    except Exception:
        logger.exception("dashboard_chat: metrics context failed")
    try:
        rows = db.load_dashboard_feed(customer_id, limit=_SNAPSHOT_ROWS)
        if rows:
            parts.append("Recent alerts (newest first):")
            for r in rows:
                created = r.get("created_at")
                created = created.isoformat() if hasattr(created, "isoformat") \
                    else (created or "")
                parts.append(
                    f"- {r['ticket_key']} | {r.get('severity') or '?'} | "
                    f"{r.get('verdict_label') or '?'} | {r.get('raw_status') or '?'} | "
                    f"{created} | {(r.get('summary') or '')[:140]}"
                )
        else:
            parts.append("Recent alerts: none in the sync window.")
    except Exception:
        logger.exception("dashboard_chat: feed context failed")
    return "\n".join(parts)


def _web_context(message: str) -> str:
    """Tavily web search on the analyst's question — the copilot's reach
    beyond internal data. Fail-silent: '' when disabled, unconfigured, or
    the search errors/returns nothing."""
    if os.environ.get("DASHBOARD_CHAT_WEB_ENABLED", "true").lower() != "true":
        return ""
    try:
        from tools.tavily_client import fetch_web_context
        return fetch_web_context((message or "").strip()[:200]) or ""
    except Exception:
        logger.exception("dashboard_chat: web search failed")
        return ""


def _rag_context(message: str, customer_id: str | None) -> str:
    """Customer-scoped Confluence knowledge for the copilot prompt.

    Reuses the triage-side retrieval primitive (tools.rag_retrieval) unchanged
    — that function already enforces RAG_LOOKUP_ENABLED, the hard timeout,
    RAG_TOP_K/RAG_MIN_SCORE, and never raises. Fail-silent: '' when disabled,
    when no customer is selected (the "All customers" view), when nothing
    scores above threshold, or on any error."""
    if os.environ.get("DASHBOARD_CHAT_RAG_ENABLED", "false").strip().lower() != "true":
        return ""
    if not (customer_id or "").strip():
        # Per-customer store: an unscoped question has no store to search.
        return ""
    try:
        from tools.rag_retrieval import retrieve_customer_context
        result = retrieve_customer_context((message or "").strip(),
                                           customer_id=customer_id)
        if (result or {}).get("status") != "matched":
            return ""
        # Stricter cut-off than the analyst-facing comment threshold, same
        # rationale as RAG_PROMPT_MIN_SCORE on the triage path: noise that's
        # safe to show an analyst isn't safe to feed the model's reasoning.
        try:
            floor = float(os.environ.get("RAG_PROMPT_MIN_SCORE", "0.7"))
        except (TypeError, ValueError):
            floor = 0.7
        lines: list[str] = []
        for c in (result.get("chunks") or []):
            text = " ".join((c.get("text") or "").split())
            if not text or float(c.get("score") or 0.0) < floor:
                continue
            lines.append(f"- [{c.get('source') or 'doc'}] "
                         f"{text[:_MAX_RAG_CHUNK_CHARS]}")
        return "\n".join(lines)
    except Exception:
        logger.exception("dashboard_chat: RAG retrieval failed")
        return ""


def build_context(message: str, customer_id: str | None) -> str:
    blocks = [_snapshot_block(customer_id)]
    for key in _mentioned_ticket_keys(message):
        try:
            detail = _fetch_ticket_detail(key)
        except Exception:
            logger.exception("dashboard_chat: ticket fetch failed for %s", key)
            detail = ""
        blocks.append(detail or f"Ticket {key}: could not be fetched from Jira.")
    # Internal customer knowledge before external web results — mirrors the
    # trust hierarchy the system prompt states.
    rag = _rag_context(message, customer_id)
    if rag:
        blocks.append("CUSTOMER KNOWLEDGE BASE (Confluence):\n" + rag)
    web = _web_context(message)
    if web:
        blocks.append("WEB SEARCH RESULTS:\n" + web)
    return "\n\n".join(b for b in blocks if b)


async def _call_llm(messages: list[dict]) -> str:
    from tools.llm_client import make_chat_client
    client, model = make_chat_client()
    response = await client.chat.completions.create(
        model=model,
        messages=messages,
        # Reasoning models burn tokens before visible text — keep headroom
        # (see tools/recommendation.py); brevity is enforced by the prompt.
        max_completion_tokens=1500,
    )
    return (response.choices[0].message.content or "").strip()


def answer(message: str, history: list[dict] | None,
           customer_id: str | None) -> str:
    """Answer one chat message. Never raises."""
    try:
        context = build_context(message, customer_id)
        messages: list[dict] = [{"role": "system", "content": _SYSTEM_PROMPT}]
        for turn in (history or [])[-_MAX_HISTORY:]:
            role = turn.get("role")
            content = str(turn.get("content") or "")[:4000]
            if role in ("user", "assistant") and content:
                messages.append({"role": role, "content": content})
        messages.append({
            "role": "user",
            "content": f"DATA:\n{context}\n\nQUESTION: {message}",
        })

        async def _runner():
            return await asyncio.wait_for(_call_llm(messages), timeout=TIMEOUT_S)

        text = asyncio.run(_runner())
        return text or "I could not generate an answer — please try rephrasing."
    except Exception:
        logger.exception("dashboard_chat: answer failed")
        return ("Sorry, I hit an error answering that. The alert feed and "
                "metrics above are unaffected — please try again.")
