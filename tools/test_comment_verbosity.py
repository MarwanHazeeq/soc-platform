"""Standalone tests for COMMENT_VERBOSITY (2026-08-05).
Run: python tools/test_comment_verbosity.py

Renders a worst-case ticket — every optional section populated — through both
the plain-text and ADF comment builders in full and compact mode. No network.

The load-bearing assertions are the ones that protect the rollback story:
compact must not DROP information (only demote it), and full must stay exactly
as it was so COMMENT_VERBOSITY=full is a true revert without a redeploy."""
import importlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# The known-activity advisory is one of the never-collapse blocks, so it has to
# be live for this suite to exercise that guarantee.
os.environ["KNOWN_ACTIVITY_ADVISORY_ENABLED"] = "true"
os.environ["KNOWN_ACTIVITY_ADVISORY_MIN_SCORE"] = "0.75"

from tools import enrichment

fails = 0


def check(name, cond):
    global fails
    print(("  PASS " if cond else "  FAIL ") + name)
    if not cond:
        fails += 1


def fixture():
    """6 observables: 2 malicious, 1 suspicious, 3 clean. Every optional
    section populated with realistic shapes."""
    def obs(value, typ, verdict, mal=0, tot=0):
        return {
            "ioc": {"value": value, "type": typ},
            "verdict": verdict,
            "virustotal": {"malicious_count": mal, "total_engines": tot,
                           "reputation": -12, "as_owner": "MICROSOFT-CORP",
                           "country": "US", "network": "20.0.0.0/8"},
            "abuseipdb": ({"confidence_score": 92, "country_name": "United States",
                           "country_code": "US", "isp": "Microsoft Corporation",
                           "usage_type": "Data Center", "domain": "microsoft.com",
                           "hostnames": ["a.msedge.net", "b.msedge.net"]}
                          if typ == "ip" else None),
            "socradar": {"verdict": verdict,
                         "score": 88 if verdict == "malicious" else 5,
                         "categories": ["C2", "Malware"],
                         "top_findings": [
                             {"source": "FeedA", "category": "C2", "reliability": 90,
                              "last_seen": "2026-07-30T10:00:00Z"},
                             {"source": "FeedB", "category": "Phishing", "reliability": 70,
                              "last_seen": "2026-07-29T10:00:00Z"},
                             {"source": "FeedC", "category": "Scanner", "reliability": 40,
                              "last_seen": "2026-07-28T10:00:00Z"},
                         ]},
            "insights": ("Reported by multiple feeds as Cobalt Strike infrastructure."
                         if verdict == "malicious" else None),
        }

    long_text = ("This alert fires nightly from the backup agent performing an "
                 "authorised sweep across the server estate. " * 4)

    return dict(
        ioc_results=[
            obs("45.32.11.9", "ip", "malicious", 14, 72),
            obs("evil-c2.example.net", "domain", "malicious", 9, 68),
            obs("10.0.0.55", "ip", "suspicious", 2, 70),
            obs("8.8.8.8", "ip", "clean"),
            obs("microsoft.com", "domain", "clean"),
            obs("d41d8cd98f00b204e9800998ecf8427e", "hash", "clean"),
        ],
        overall_verdict="malicious",
        action_taken="Labelled True-Positive, assigned to L1",
        mitre_result={"techniques": [
            {"id": "T1059.001", "tactic": "Execution", "name": "PowerShell",
             "confidence": 0.85, "rationale": "Encoded PowerShell with hidden window."},
            {"id": "T1071.001", "tactic": "Command and Control", "name": "Web Protocols",
             "confidence": 0.7, "rationale": "Beaconing to an external host over HTTPS."},
        ]},
        historical={"total": 12, "true_positive": 2, "false_positive": 9,
                    "unknown": 1, "untriaged": 0, "window_hours": 24,
                    "rule_prefix": "Suspicious PowerShell execution detected on",
                    "first_seen_at": "2026-08-04T02:11:00Z"},
        rag_info={"pages_searched": 7, "status": "matched", "chunks": [
            {"text": long_text, "source": "Escalation Matrix", "score": 0.81},
            {"text": long_text, "source": "Known Activity", "score": 0.77},
        ]},
        kql_evidence={"workspace_name": "cust-sentinel-prod", "iterations": 3,
                      "total_rows": 41,
                      "queries": [{"iteration": i, "table": f"Table{i}",
                                   "row_count": i * 7, "rationale": long_text}
                                  for i in (1, 2, 3)]},
        recommendation=("Isolate WKSTN-4471 and reset svc_backup; the encoded "
                        "PowerShell beacons to known Cobalt Strike infrastructure."),
        whitelist_matches=[{"ioc": "8.8.8.8", "ioc_type": "ip",
                            "source": "Whitelists", "snippet": long_text}],
        whitelist_conflict=[{"ioc": "45.32.11.9"}],
        cmdline_analysis={"items": [
            {"verdict": "Malicious", "image": "powershell.exe",
             "command_line": "powershell -nop -w hidden -enc SQBFAFgA",
             "parent_image": "winword.exe", "analysis": long_text}]},
        code_explain={"items": [
            {"label": "Event ID", "code": "4625", "source": "builtin",
             "meaning": "An account failed to log on."},
            {"label": "Logon Type", "code": "3", "source": "web",
             "meaning": "Network logon."}]},
        ticket_key="SOC-1234",
        pattern={"window_days": 30, "total": 47, "true_positive": 4,
                 "false_positive": 40, "unknown": 3, "untriaged": 0,
                 "truncated": False, "timing_pattern": "after-hours-only",
                 "business_hours_count": 3, "after_hours_count": 44,
                 "first_seen_ever": "2026-05-02T18:30:00Z",
                 "entity_correlation": [
                     {"value": "svc_backup", "type": "account", "count": 31,
                      "false_positive": 30, "true_positive": 1,
                      "historically_benign": True},
                     {"value": "WKSTN-4471", "type": "host", "count": 6,
                      "false_positive": 2, "true_positive": 4},
                 ],
                 "tuning": {"recommended": True, "strength": "strong",
                            "rationale": "40 of 47 closed Benign-Positive over 30 days."}},
    )


def render(mode, mutate=None):
    """Re-import enrichment so the module-level verbosity read picks up `mode`."""
    os.environ["COMMENT_VERBOSITY"] = mode
    importlib.reload(enrichment)
    fx = fixture()
    if mutate:
        mutate(fx)
    return enrichment._build_comment(**fx), enrichment._build_comment_adf(**fx)


def walk(node, inside_expand=False, out=None):
    """Yield (node_type, is_inside_an_expand) for every node in an ADF doc."""
    out = [] if out is None else out
    if isinstance(node, dict):
        t = node.get("type")
        if t:
            out.append((t, inside_expand))
        nested = inside_expand or t == "expand"
        for child in node.get("content", []) or []:
            walk(child, nested, out)
    return out


def text_of(node):
    if not isinstance(node, dict):
        return ""
    if node.get("type") == "text":
        return node.get("text", "")
    return "".join(text_of(c) for c in node.get("content", []) or [])


full_txt, full_adf = render("full")
comp_txt, comp_adf = render("compact")
comp_json = json.dumps(comp_adf)

print("compact is materially shorter:")
f_lines, c_lines = len(full_txt.splitlines()), len(comp_txt.splitlines())
pct = 100 * (1 - c_lines / f_lines)
print(f"    worst-case ticket: {f_lines} -> {c_lines} lines ({pct:.0f}% shorter)")
check(f"plain-text at least 40% shorter (got {pct:.0f}%)", pct >= 40)

print("compact demotes rather than drops — every observable value survives:")
for r in fixture()["ioc_results"]:
    v = r["ioc"]["value"]
    check(f"{v} present in both renderers", v in comp_txt and v in comp_json)

print("decision-critical content survives:")
for s in ["TRUE-POSITIVE", "RECOMMENDED ACTION", "TUNING CANDIDATE",
          "WHITELIST CONFLICT", "T1059.001", "svc_backup"]:
    check(f"{s!r} kept", s in comp_txt and s in comp_json)

print("no-observable tickets no longer claim engines cleared them:")
no_iocs = lambda fx: fx.update(ioc_results=[], overall_verdict="unknown")
empty_compact, _ = render("compact", no_iocs)
empty_full, _ = render("full", no_iocs)
check("compact drops the 'No detections' triple", "No detections" not in empty_compact)
check("compact states no observables were extracted",
      "No extractable observables" in empty_compact)
check("full keeps the legacy triple unchanged", "No detections" in empty_full)

print("ADF structure is valid for Jira:")
nodes = walk(comp_adf)
check("compact emits expand nodes", any(t == "expand" for t, _ in nodes))
check("no expand nested inside an expand (Jira wants nestedExpand)",
      not any(t == "expand" and inside for t, inside in nodes))


def expands(node, out=None):
    out = [] if out is None else out
    if isinstance(node, dict):
        if node.get("type") == "expand":
            out.append(node)
        for c in node.get("content", []) or []:
            expands(c, out)
    return out


all_expands = expands(comp_adf)
check("every expand has a title", all(e.get("attrs", {}).get("title") for e in all_expands))
check("every expand has content", all(e.get("content") for e in all_expands))

print("safety-critical blocks are never collapsed:")


def collapsed_panels(node, inside=False, hits=None):
    hits = [] if hits is None else hits
    if isinstance(node, dict):
        t = node.get("type")
        if inside and t == "panel":
            hits.append(text_of(node))
        nested = inside or t == "expand"
        for c in node.get("content", []) or []:
            collapsed_panels(c, nested, hits)
    return hits


hidden = collapsed_panels(comp_adf)
for critical in ("WHITELIST CONFLICT", "KNOWN ACTIVITY", "VERDICT:"):
    check(f"{critical} stays outside every expander",
          not any(critical in h for h in hidden))

print("full mode is untouched (the rollback path):")
check("full mode emits no expand nodes",
      not any(t == "expand" for t, _ in walk(full_adf)))

# 2026-08-18 (Refactor 1 — comment assembler): structural/order regression net.
# The prior suite checked line-count delta and content presence but nothing about
# *section order* or completeness — exactly the property the mutate-in-place →
# pure-function conversion is most likely to break (silently dropping or
# reordering a section). This block pins the full-mode section sequence: every
# expected section present, in this order, with no duplicates. Order is asserted
# against the actual rendered output, not hand-transcribed, so it stays honest.
print("full-mode plain text has every section, in order, with no duplicates:")

# Stable line-start markers for each top-level section, in the order
# _build_comment() emits them on the worst-case fixture (every section populated).
EXPECTED_SECTIONS = [
    ("known-activity advisory", "KNOWN ACTIVITY (Customer Confluence)"),
    ("report header", "=== L1 Triage Report (Automated) ==="),
    ("IOC summary", "IOCs found:"),
    ("MITRE ATT&CK", "MITRE ATT&CK — Attack TTPs:"),
    ("direct whitelist match", "Direct Whitelist Match ("),
    ("customer knowledge base", "Customer Knowledge Base (Confluence)"),
    ("sentinel evidence", "Sentinel Evidence ("),
    ("similar alerts (24h)", "Similar Alerts (past 24h):"),
    ("alert pattern analysis (30d)", "Alert Pattern Analysis (30d):"),
    ("additional insights", "Additional Insights (Open-Source Web Research):"),
    ("command-line analysis", "Command-Line Analysis (AI + Open-Source Web Research):"),
    ("security code explanations", "Security Code Explanations:"),
    ("whitelist conflict", "WHITELIST CONFLICT:"),
    ("verdict", "VERDICT:"),
    ("auto-triage", "AUTO-TRIAGE:"),
    ("recommended action", "RECOMMENDED ACTION:"),
]

full_lines = full_txt.splitlines()


def _first_index(marker):
    """First 0-based line index whose text starts with `marker`, else -1."""
    for idx, ln in enumerate(full_lines):
        if ln.startswith(marker):
            return idx
    return -1


def _count(marker):
    return sum(1 for ln in full_lines if ln.startswith(marker))


positions = []
for label, marker in EXPECTED_SECTIONS:
    idx = _first_index(marker)
    check(f"section present: {label}", idx >= 0)
    check(f"section appears exactly once: {label}", _count(marker) == 1)
    positions.append(idx)

# Every section that IS present must appear in the declared order. Comparing the
# observed positions to their sorted copy catches any reordering.
present = [p for p in positions if p >= 0]
check("all sections render in the declared order",
      present == sorted(present))

print()
print(f"{'FAILED' if fails else 'OK'} — {fails} failure(s)")
sys.exit(1 if fails else 0)
