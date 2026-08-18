"""
IOC enrichment pipeline for Jira webhook processing.

Flow:
  1. extract_iocs_from_entity_fields() — read structured Sentinel-style entity custom fields (primary)
  2. extract_iocs() — regex fallback over summary + description text
  3. check_reputation()  — fan-out to SOCRadar (+ VT/AbuseIPDB when keys present)
  4. determine_verdict() — aggregate: any malicious → malicious
  5. post_jira_comment() — post enrichment summary as ADF comment
  6. assign_jira_ticket()— reassign based on verdict
  7. enrich_ticket()     — orchestrates all steps end-to-end
"""
import ipaddress
import json
import logging
import os
import re
from urllib.parse import urlparse

import httpx

from tools.jira_schema import default_schema

logger = logging.getLogger(__name__)

JIRA_URL = os.environ.get("JIRA_URL", "").rstrip("/")

# ─── L1 Triage labels ─────────────────────────────────────────────────────────
# Jira labels applied to triaged tickets based on the aggregated verdict.
# Phase 1 (2026-06-08): switched defaults from generic IOC_Detection /
# investigating to explicit True-Positive / Benign-Positive / Unknown so the
# label conveys the triage outcome directly. The label must already exist in
# the target Jira instance — the webhook handler only ADDS the label, it does
# not create it. Override via env if your Jira convention differs.
_TRIAGE_MALICIOUS_LABEL = os.environ.get("JIRA_TRIAGE_MALICIOUS_LABEL", "True-Positive")
_TRIAGE_CLEAN_LABEL     = os.environ.get("JIRA_TRIAGE_CLEAN_LABEL",     "Benign-Positive")
_TRIAGE_UNKNOWN_LABEL   = os.environ.get("JIRA_TRIAGE_UNKNOWN_LABEL",   "Unknown")

# ─── Custom field IDs for Sentinel-style structured entity fields ─────────────
# Override via env if Jira admin renumbers fields. Defaults are the SCDM project's
# current IDs (verified 2026-05-05 against SCDM-41).
_FIELD_IP_ENTITIES   = os.environ.get("JIRA_FIELD_IP_ENTITIES",   "customfield_10079")
_FIELD_HOST_ENTITIES = os.environ.get("JIRA_FIELD_HOST_ENTITIES", "customfield_10078")
_FIELD_DNS_ENTITIES  = os.environ.get("JIRA_FIELD_DNS_ENTITIES",  "customfield_10080")
_FIELD_URL_ENTITIES  = os.environ.get("JIRA_FIELD_URL_ENTITIES",  "customfield_10081")
_FIELD_HASH_ENTITIES = os.environ.get("JIRA_FIELD_HASH_ENTITIES", "customfield_10082")

ENTITY_FIELD_IDS = (
    _FIELD_IP_ENTITIES, _FIELD_HOST_ENTITIES, _FIELD_DNS_ENTITIES,
    _FIELD_URL_ENTITIES, _FIELD_HASH_ENTITIES,
)


def has_entity_data(fields: dict, schema=None) -> bool:
    """Return True if any Sentinel-style entity custom field is non-empty.

    Used by the webhook poller to detect when a Service Desk request form has
    finished merging its entity fields into the issue (which can take 30+
    seconds after the issue_created event fires)."""
    if not fields:
        return False
    for fid in (schema or default_schema()).entity_field_ids():
        val = fields.get(fid)
        if val is None:
            continue
        if isinstance(val, str) and val.strip():
            return True
        if isinstance(val, dict) and _extract_adf_text(val).strip():
            return True
        if isinstance(val, list) and any(val):
            return True
    return False

# ─── IOC regex patterns ───────────────────────────────────────────────────────

_RE_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
_RE_SHA1   = re.compile(r'\b[a-fA-F0-9]{40}\b')
_RE_MD5    = re.compile(r'\b[a-fA-F0-9]{32}\b')
_RE_IPV4   = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_RE_DOMAIN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:com|net|org|io|gov|edu|biz|info|xyz|ru|cn|tk|top|cc|pw|onion'
    r'|online|site|live|app|store|shop|tech|club|pro|co|me|us|uk|de|fr'
    r'|jp|au|nz|sg|my|id|ph|vn|in|br|za)\b',
    re.IGNORECASE,
)

_PRIVATE_NETS = [
    ipaddress.ip_network(n) for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8",
    )
]

# Domains that appear in normal Jira/SIEM ticket bodies but are not IOCs
_DOMAIN_ALLOWLIST = {
    "atlassian.net", "jira.com", "microsoft.com", "windows.com",
    "office.com", "azure.com", "cloudflare.com", "github.com",
    "amazonaws.com", "google.com", "gmail.com", "outlook.com",
    "logicalis.com", "sharepoint.com", "teams.microsoft.com",
}


def _is_private_ip(ip_str: str) -> bool:
    """True for any non-globally-routable address (skip from reputation checks).

    Handles IPv4 and IPv6, including IPv4-mapped IPv6 (``::ffff:a.b.c.d``) and
    link-local (``fe80::/10``). Reputation engines only make sense for public
    addresses, so private/loopback/link-local/reserved/multicast are all skipped."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        addr = mapped
    return (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_reserved or addr.is_multicast or addr.is_unspecified)


def _is_allowlisted_domain(domain: str) -> bool:
    domain = domain.lower()
    return any(
        domain == allowed or domain.endswith("." + allowed)
        for allowed in _DOMAIN_ALLOWLIST
    )


def _extract_adf_text(field_value) -> str:
    if not field_value:
        return ""
    if isinstance(field_value, str):
        return field_value
    parts = []

    def _walk(node):
        if isinstance(node, dict):
            if node.get("type") == "text":
                parts.append(node.get("text", ""))
            for child in node.get("content", []):
                _walk(child)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(field_value)
    return " ".join(parts).strip()


# ─── IOC Extraction ───────────────────────────────────────────────────────────

def extract_iocs(text: str) -> list[dict]:
    """Extract unique, public IOCs from plain text.

    Returns a list of {"type": "ip"|"domain"|"hash", "subtype": str, "value": str}.
    Hashes are checked longest-first to avoid MD5 matching inside SHA256.
    Private/loopback IPs and allowlisted domains are excluded.
    """
    seen: set[str] = set()
    iocs: list[dict] = []

    for m in _RE_SHA256.finditer(text):
        val = m.group().lower()
        if val not in seen:
            seen.add(val)
            iocs.append({"type": "hash", "subtype": "sha256", "value": val})

    for m in _RE_SHA1.finditer(text):
        val = m.group().lower()
        if val not in seen:
            seen.add(val)
            iocs.append({"type": "hash", "subtype": "sha1", "value": val})

    for m in _RE_MD5.finditer(text):
        val = m.group().lower()
        if val not in seen:
            seen.add(val)
            iocs.append({"type": "hash", "subtype": "md5", "value": val})

    for m in _RE_IPV4.finditer(text):
        val = m.group()
        if val not in seen and not _is_private_ip(val):
            seen.add(val)
            iocs.append({"type": "ip", "subtype": "ipv4", "value": val})

    for m in _RE_DOMAIN.finditer(text):
        val = m.group().lower()
        if val not in seen and not _is_allowlisted_domain(val):
            seen.add(val)
            iocs.append({"type": "domain", "subtype": "fqdn", "value": val})

    logger.info("extract_iocs: found %d IOCs", len(iocs))
    return iocs


# ─── Structured Entity Field Extraction ───────────────────────────────────────

def _entity_json_objects(text: str) -> list[dict] | None:
    """Sentinel/Defender exports store entity fields as one or more
    whitespace-separated JSON objects, e.g. ``{"address":"1.2.3.4","Type":"ip"}``
    or ``{"hashValue":"ab..","algorithm":"SHA1"}``. Parse them with a raw_decode
    loop so nested/escaped JSON (Host entity ``additionalData``) is handled.

    Returns the parsed objects, or None if the text is not JSON — in which case
    the caller falls back to legacy plain-value splitting. If the text starts as
    JSON but is malformed, also returns None (fall back rather than raise)."""
    s = text.strip()
    if not s.startswith("{"):
        return None
    objs: list[dict] = []
    dec = json.JSONDecoder()
    i, n = 0, len(s)
    while i < n:
        while i < n and s[i] in " \t\r\n,;":
            i += 1
        if i >= n:
            break
        try:
            obj, end = dec.raw_decode(s, i)
        except json.JSONDecodeError:
            return None
        if isinstance(obj, dict):
            objs.append(obj)
        i = end
    return objs or None


def _values_from_entity_objects(objs: list[dict], kind: str) -> list[str]:
    """Pull the canonical IOC value(s) from parsed entity objects, per field kind.
    Bare host names are intentionally skipped (asset context, not a domain to
    check); only dotted domains / FQDNs are emitted for host/dns fields."""
    out: list[str] = []
    for o in objs:
        if kind == "ip":
            v = o.get("address") or o.get("Address")
            if v:
                out.append(str(v))
        elif kind == "hash":
            v = o.get("hashValue") or o.get("Value") or o.get("value")
            if v:
                out.append(str(v))
        elif kind == "url":
            v = o.get("url") or o.get("Url") or o.get("address") or o.get("Address")
            if v:
                out.append(str(v))
        else:  # host / dns → dotted domains + FQDN only
            for key in ("dnsDomain", "domainName"):
                v = o.get(key)
                if v:
                    out.append(str(v))
            ad = o.get("additionalData")
            if isinstance(ad, dict) and ad.get("FQDN"):
                out.append(str(ad["FQDN"]))
    return out


def _split_entity_values(adf_field, kind: str = "generic") -> list[str]:
    """Flatten an ADF entity custom field into individual values.

    Handles two formats:
      * Sentinel/Defender JSON objects (what SCDM/Defender tickets actually
        export) — parsed, with the canonical value pulled per ``kind``.
      * Legacy plain values separated by whitespace / comma / semicolon — split.
    """
    text = _extract_adf_text(adf_field)
    if not text:
        return []
    objs = _entity_json_objects(text)
    if objs is not None:
        return _values_from_entity_objects(objs, kind)
    parts = re.split(r"[\s,;]+", text)
    return [p.strip() for p in parts if p.strip()]


def extract_iocs_from_entity_fields(fields: dict, schema=None) -> list[dict]:
    """Read Sentinel-style structured entity custom fields and produce typed IOCs.

    Returns the same shape as extract_iocs(): a list of
    {"type": "ip"|"domain"|"hash", "subtype": str, "value": str}.

    Entity field IDs come from the resolved per-customer `schema`; when None the
    global defaults (SCDM) are used, so existing callers behave identically.
    """
    sch = schema or default_schema()
    seen: set[str] = set()
    iocs: list[dict] = []

    # IP Address Entities
    for val in _split_entity_values(fields.get(sch.entity_fields["ip"]), "ip"):
        v = val.lower()
        if v in seen or _is_private_ip(val):
            continue
        try:
            _ip = ipaddress.ip_address(val)
        except ValueError:
            continue
        seen.add(v)
        iocs.append({"type": "ip", "subtype": "ipv6" if _ip.version == 6 else "ipv4", "value": val})

    # Host Entities and DNS Entities → both treated as domains
    for field_id, _kind in ((sch.entity_fields["host"], "host"), (sch.entity_fields["dns"], "dns")):
        for val in _split_entity_values(fields.get(field_id), _kind):
            v = val.lower()
            if v in seen or _is_allowlisted_domain(v):
                continue
            # Skip values that look like IPs or hashes (wrong field but defensive)
            if _RE_IPV4.fullmatch(val) or _RE_SHA256.fullmatch(val) or _RE_SHA1.fullmatch(val) or _RE_MD5.fullmatch(val):
                continue
            seen.add(v)
            iocs.append({"type": "domain", "subtype": "fqdn", "value": v})

    # URL Entities → extract host
    for val in _split_entity_values(fields.get(sch.entity_fields["url"]), "url"):
        try:
            host = urlparse(val if "://" in val else f"http://{val}").hostname
        except Exception:
            host = None
        if not host:
            continue
        h = host.lower()
        if h in seen or _is_allowlisted_domain(h):
            continue
        seen.add(h)
        iocs.append({"type": "domain", "subtype": "fqdn", "value": h})

    # FileHash Entities → classify by length
    for val in _split_entity_values(fields.get(sch.entity_fields["hash"]), "hash"):
        v = val.lower()
        if v in seen:
            continue
        if _RE_SHA256.fullmatch(v):
            subtype = "sha256"
        elif _RE_SHA1.fullmatch(v):
            subtype = "sha1"
        elif _RE_MD5.fullmatch(v):
            subtype = "md5"
        else:
            continue
        seen.add(v)
        iocs.append({"type": "hash", "subtype": subtype, "value": v})

    logger.info("extract_iocs_from_entity_fields: found %d IOCs", len(iocs))
    return iocs


# ─── Reputation Checking ──────────────────────────────────────────────────────

def check_reputation(ioc: dict, socradar_enabled: bool = True) -> dict:
    """Fan out IOC to all configured reputation sources: SOCRadar, VirusTotal,
    and AbuseIPDB. Returns a merged result + an aggregated verdict.

    SOCRadar wires through tools.socradar_rest.check_ioc() against the
    `/api/threat/analysis` endpoint — this needs the SOCRadar 'Threat Analysis
    API' key (env: SOCRADAR_THREAT_ANALYSIS_KEY). If the key is unset OR
    socradar_enabled is False, SOCRadar is skipped and the verdict falls
    through to VT + AbuseIPDB only.

    The `socradar_enabled` flag exists so the orchestrator (enrich_ticket)
    can cap SOCRadar lookups per ticket — the API has a 100/day budget and
    a 5-per-minute rate limit, so calling it on every IOC of a 16-IOC
    ticket would (a) burn 16% of the daily quota in one go and (b) stretch
    webhook latency past 5 minutes. Tickets typically have 1-3 IOCs that
    matter; the rest are duplicates or known-noise.

    Verdict aggregation: ANY source flagging malicious → ticket is malicious.
    All sources None → verdict is 'unknown' (no engines reachable).
    """
    from tools import virustotal_client, abuseipdb_client, socradar_rest

    ioc_type = ioc["type"]
    value = ioc["value"]

    result: dict = {
        "ioc": ioc,
        "virustotal": None,
        "abuseipdb": None,
        "socradar": None,
        "verdict": "unknown",
    }

    result["virustotal"] = virustotal_client.check_ioc(value, ioc_type)
    if ioc_type == "ip":
        result["abuseipdb"] = abuseipdb_client.check_ip(value)
    if socradar_enabled:
        result["socradar"] = socradar_rest.check_ioc(value, ioc_type)

    malicious = False
    if result["virustotal"] and result["virustotal"].get("malicious_count", 0) > 0:
        malicious = True
    if result["abuseipdb"] and result["abuseipdb"].get("confidence_score", 0) > 50:
        malicious = True
    if result["socradar"] and result["socradar"].get("verdict") == "malicious":
        malicious = True

    all_none = all(result[k] is None for k in ("virustotal", "abuseipdb", "socradar"))
    result["verdict"] = "malicious" if malicious else ("unknown" if all_none else "clean")

    return result


def determine_verdict(results: list[dict]) -> str:
    """Aggregate per-IOC verdicts into a single ticket verdict."""
    if not results:
        return "unknown"
    if any(r["verdict"] == "malicious" for r in results):
        return "malicious"
    if all(r["verdict"] == "unknown" for r in results):
        return "unknown"
    return "clean"


def decide_whitelist_override(overall_verdict: str, ioc_results: list[dict],
                              whitelist_matches: list[dict]) -> tuple[str, bool, list[dict]]:
    """Improvement #3 (2026-07-03) — pure decision for the Confluence-whitelist
    benign override. Returns ``(new_verdict, override_applied, conflict_matches)``.

    Rules (caller gates on WHITELIST_VERDICT_OVERRIDE_ENABLED):
    - Only whitelist matches with ``whitelist_context`` True count (precision guard).
    - **Reputation wins on conflict:** a 'malicious' verdict is NEVER overridden;
      instead we return the whitelisted-but-malicious matches as `conflict_matches`.
    - Otherwise force 'clean' ONLY when EVERY non-clean IOC is whitelist-approved,
      so an unexplained unknown/suspicious IOC can't be silently suppressed.
    """
    approved = {str(m.get("ioc", "")).lower() for m in (whitelist_matches or [])
                if m.get("whitelist_context")}
    if not approved:
        return overall_verdict, False, []

    def _val(r):
        return str((r.get("ioc") or {}).get("value", "")).lower()

    if overall_verdict == "malicious":
        conflict = [m for m in whitelist_matches if m.get("whitelist_context")
                    and any(_val(r) == str(m.get("ioc", "")).lower()
                            and r.get("verdict") == "malicious" for r in ioc_results)]
        return overall_verdict, False, conflict

    unresolved = [r for r in ioc_results if r.get("verdict") != "clean"]
    if all(_val(r) in approved for r in unresolved):
        return "clean", True, []
    return overall_verdict, False, []


def _rep_empty_label(source: str) -> str:
    """Label for a reputation source that returned no result. Distinguishes a
    genuinely-absent API key ("Not configured") from a key that IS present but
    whose lookup returned nothing or errored ("No data") — so a working engine
    fed an invalid/clean IOC no longer reads as unconfigured."""
    from tools import virustotal_client, abuseipdb_client, socradar_rest
    checker = {
        "virustotal": virustotal_client.is_configured,
        "abuseipdb": abuseipdb_client.is_configured,
        "socradar": socradar_rest.is_configured,
    }.get(source)
    try:
        return "No data" if (checker and checker()) else "Not configured"
    except Exception:
        return "Not configured"


# ─── Comment Builder ──────────────────────────────────────────────────────────

_VERDICT_LABEL = {
    "malicious": "TRUE-POSITIVE",
    "clean":     "BENIGN-POSITIVE",
    "unknown":   "UNKNOWN",
}


# ─── Comment verbosity (2026-08-05) ───────────────────────────────────────────
#
# The enrichment comment accreted 14 independent sections across roadmap phases
# 1-6, each rendering in full whenever its feature flag produced data. On a rich
# ticket that reached ~150-180 lines and analysts stopped reading it.
#
# COMMENT_VERBOSITY=compact drops the lines that carry no decision signal
# (cleared-observable detail, duplicated verdict trees, box drawing) and — on
# the ADF path — moves the surviving detail behind collapsible expanders. The
# information is not lost, it is demoted.
#
# Default stays "full" so this is opt-in per environment and revertible without
# a redeploy, matching the killswitch convention used by every other feature
# here. Set COMMENT_VERBOSITY=compact in the Container App env to enable.
#
# Verbosity resolution, the 6 truncation caps (compact + full), section order and
# final assembly now live in tools/comment_assembler.CommentAssembler — resolved
# ONCE per build and threaded into the section builders below as explicit
# `compact` / `caps` params, instead of every builder re-reading the env var and
# re-deriving "_COMPACT_x if compact else <inline literal>" on its own.
from tools.comment_assembler import CommentAssembler


def _truncate(s: str, limit: int) -> str:
    """Collapse internal whitespace and hard-cap length with an ellipsis."""
    oneline = " ".join((s or "").split())
    return oneline if len(oneline) <= limit else oneline[:limit - 3] + "..."


def _format_sgt(raw: str) -> str:
    """Render an ISO 8601 timestamp in Asia/Singapore (UTC+8). Returns the raw
    string unchanged if parsing fails — analysts still see *some* time rather
    than nothing if a source emits an unusual format."""
    if not raw:
        return ""
    try:
        from datetime import datetime, timezone
        from zoneinfo import ZoneInfo
        s = str(raw).strip()
        if s.endswith("Z"):  # python<3.11 fromisoformat can't parse trailing Z
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(ZoneInfo("Asia/Singapore")).strftime("%Y-%m-%d %H:%M:%S SGT")
    except Exception:
        return str(raw)


def _ip_origin_lines(vt: dict | None, ab: dict | None, *, compact: bool) -> list[str]:
    """Build the per-IP Origin block for the L1 Triage comment. Combines
    AbuseIPDB and VirusTotal metadata so the analyst sees who owns the IP
    and where it sits without expanding raw payloads. Returns 0 lines if no
    origin data is available from either source."""
    ab = ab or {}
    vt = vt or {}

    country_name = ab.get("country_name") or ""
    country_code = ab.get("country_code") or vt.get("country") or ""
    # AbuseIPDB's ISP is more human-readable ("Microsoft Corporation");
    # VT's as_owner is more technical ("MICROSOFT-CORP-MSN-AS-BLOCK").
    # Prefer ISP, fall back to as_owner. Show both only when they say
    # genuinely different things.
    isp        = ab.get("isp") or ""
    as_owner   = vt.get("as_owner") or ""
    network    = vt.get("network") or ""
    usage_type = ab.get("usage_type") or ""
    domain     = ab.get("domain") or ""
    hostnames  = ab.get("hostnames") or []

    origin_parts: list[str] = []
    if country_name and country_code:
        origin_parts.append(f"{country_name} ({country_code})")
    elif country_name or country_code:
        origin_parts.append(country_name or country_code)
    if isp:
        origin_parts.append(f"ISP: {isp}")
    elif as_owner:
        origin_parts.append(f"AS: {as_owner}")
    if network:
        origin_parts.append(f"Network: {network}")
    if usage_type:
        origin_parts.append(f"Usage: {usage_type}")

    if compact:
        # One line, unlabelled: country, owner, first PTR. Network/usage/domain
        # are dropped — an analyst who needs them opens the raw payload.
        bits: list[str] = []
        if country_name or country_code:
            bits.append(country_name or country_code)
        if isp or as_owner:
            bits.append(isp or as_owner)
        if hostnames:
            extra = f" (+{len(hostnames) - 1})" if len(hostnames) > 1 else ""
            bits.append(f"{hostnames[0]}{extra}")
        elif domain:
            bits.append(domain)
        return [f"  Origin: {' · '.join(bits)}"] if bits else []

    out: list[str] = []
    if origin_parts:
        out.append("  Origin: " + " • ".join(origin_parts))

    dns_parts: list[str] = []
    if domain:
        dns_parts.append(f"Domain: {domain}")
    if hostnames:
        # Show the first hostname; truncate the rest to a count to avoid a
        # noisy comment when an IP resolves to dozens of PTRs.
        first = hostnames[0]
        extra = f" (+{len(hostnames) - 1} more)" if len(hostnames) > 1 else ""
        dns_parts.append(f"Reverse: {first}{extra}")
    if dns_parts:
        out.append("  " + " • ".join(dns_parts))

    return out


def _append_insights_section(ioc_results: list[dict] | None, *, compact: bool, caps) -> list[str]:
    """Improvement #2 (2026-07-03): inject the AI web-research 'Additional Insights'
    section for malicious IOCs. Returns [] unless a malicious IOC carries an
    ``insights`` note (only populated when IOC_INSIGHTS_ENABLED is on)."""
    items = [((r.get("ioc") or {}).get("value", ""), r.get("insights"))
             for r in (ioc_results or [])
             if r.get("verdict") == "malicious" and r.get("insights")]
    if not items:
        return []
    lines: list[str] = ["Additional Insights (Open-Source Web Research):"]
    for value, text in items:
        if compact:
            lines.append(f"  [{value}] {' '.join((text or '').split())}")
            continue
        lines.append(f"  [{value}]")
        lines.append(f"    {text}")
    lines.append("")
    return lines


def _append_cmdline_section(cmdline_analysis: dict | None, *, compact: bool, caps) -> list[str]:
    """Improvement #4 (2026-07-06): AI command-line reputation check. Returns []
    unless CMDLINE_ANALYSIS_ENABLED produced results. ADVISORY ONLY — never affects
    the ticket verdict; it tells the analyst whether the process/PowerShell command
    line looks malicious or is legitimately associated with known software."""
    items = (cmdline_analysis or {}).get("items") or []
    if not items:
        return []
    lines: list[str] = ["Command-Line Analysis (AI + Open-Source Web Research):"]
    for it in items:
        img = it.get("image") or "process"
        if compact:
            # Fold the verdict/image/parent scaffolding onto one line. The
            # analysis text itself is NOT truncated — it is already capped at
            # ~90 words in the prompt and is the actionable part of the section.
            parent = f" ← {it['parent_image']}" if it.get("parent_image") else ""
            lines.append(f"  [{it.get('verdict', '?')}] {img}{parent}: "
                         f"{it.get('command_line', '')}")
            lines.append(f"    {' '.join((it.get('analysis') or '').split())}")
            continue
        lines.append(f"  [{it.get('verdict', '?')}] {img}")
        lines.append(f"    Command line: {it.get('command_line', '')}")
        if it.get("parent_image"):
            lines.append(f"    Parent: {it['parent_image']}")
        lines.append(f"    {it.get('analysis', '')}")
    lines.append("")
    return lines


def _append_code_explain_section(code_explain: dict | None, *, compact: bool, caps) -> list[str]:
    """Improvement #5 (2026-07-06): decode SIEM/XDR codes (Event IDs, Logon Types,
    NTSTATUS, Kerberos failure codes). Returns [] unless CODE_EXPLAIN_ENABLED
    produced items. Advisory only — never affects the verdict."""
    items = (code_explain or {}).get("items") or []
    if not items:
        return []
    lines: list[str] = ["Security Code Explanations:"]
    for it in items:
        src = " (web)" if it.get("source") == "web" else ""
        head = f"  [{it.get('label', '')}] {it.get('code', '')}{src}"
        if compact:
            lines.append(f"{head} — {' '.join((it.get('meaning') or '').split())}")
            continue
        lines.append(head)
        lines.append(f"    {it.get('meaning', '')}")
    lines.append("")
    return lines


def _append_mitre_section(mitre_result: dict | None, *, compact: bool, caps) -> list[str]:
    """Build the MITRE ATT&CK section lines. Returns [] if result is absent."""
    if not mitre_result:
        return []
    techniques = mitre_result.get("techniques") or []
    if not techniques:
        return []
    lines: list[str] = ["MITRE ATT&CK — Attack TTPs:"]
    for t in techniques:
        pct = int(round(t.get("confidence", 0) * 100))
        if compact:
            # One line per technique. The bare attack.mitre.org URL is dropped —
            # the technique ID is enough to look up, and it cost a full line
            # each. The ADF path keeps the link on the ID itself, where it's free.
            rationale = _truncate(t.get("rationale") or "", caps.snippet_chars)
            why = f" — {rationale}" if rationale else ""
            lines.append(f"  [{t['id']}] {t['tactic']} — {t['name']} ({pct}%){why}")
            continue
        lines.append(f"  [{t['id']}] {t['tactic']} — {t['name']} ({pct}% confidence)")
        rationale = t.get("rationale")
        if rationale:
            lines.append(f"    Why: {rationale}")
        lines.append(f"    {_mitre_technique_url(t['id'])}")
    lines.append("")
    return lines


def _append_sentinel_evidence_section(kql_result: dict | None, *, compact: bool, caps) -> list[str]:
    """Phase 5 (2026-06-15): inject the 'Sentinel Evidence' RAG-style block
    into the enrichment comment. No-op when kql_result is None or has no
    queries (KQL expansion disabled, customer has no Sentinel workspace,
    auth failure, timeout, or LLM returned nothing).

    Phase 5 MVP renders ONLY in the comment. NEVER fed into the LLM Triage
    prompt — same conservative ladder as Phase 4 → 4c (separate killswitch
    + threshold for prompt integration if/when we add Phase 5c)."""
    if not kql_result:
        return []
    queries = kql_result.get("queries") or []
    if not queries:
        return []

    workspace = kql_result.get("workspace_name") or "(unnamed)"
    iters = kql_result.get("iterations", len(queries))
    total = kql_result.get("total_rows", 0)
    iter_word = "iteration" if iters == 1 else "iterations"
    row_word = "row" if total == 1 else "rows"
    lines: list[str] = [
        f"Sentinel Evidence ({workspace} — {iters} {iter_word}, {total} {row_word} total):"
    ]

    for q in queries:
        i = q.get("iteration", 0)
        table = q.get("table") or "(unspecified table)"
        rationale = (q.get("rationale") or "").strip()
        row_count = q.get("row_count", 0)
        rc_word = "row" if row_count == 1 else "rows"
        # One-line summary per iteration. Full KQL is intentionally NOT
        # rendered in the comment to keep it scannable — pull it from the
        # logs if an analyst needs to reproduce.
        prefix = f"  [{i}] {table}: {row_count} {rc_word}"
        if rationale:
            prefix += f" — {_truncate(rationale, caps.rationale_chars)}"
        lines.append(prefix)
    lines.append("")
    return lines


def _append_customer_knowledge_section(rag_info: dict | None, *, compact: bool, caps) -> list[str]:
    """Phase 4 / 4b (2026-06-13 → 2026-06-15): inject the 'Customer Knowledge
    Base (Confluence)' block into the enrichment comment.

    rag_info shape (set by routes/webhook.py):
        {"pages_searched": int, "status": "matched"|"no_matches",
         "chunks": list[dict]}
    Caller passes None to suppress the section entirely — that's how the
    silent cases (RAG disabled, customer not resolved, customer has no
    Confluence pages, embed/store error) are filtered out *before* this
    function is invoked.

    Header always includes the page count so analysts can deduce that the
    AI consulted the customer's Confluence pages. When chunks is empty the
    block still renders (analyst signal that the lookup ran but didn't find
    anything above the similarity threshold).

    RAG content is rendered for the analyst only; it is NOT fed into the
    LLM Triage prompt (deliberate isolation against the prior failure mode
    where bad retrievals confused the LLM)."""
    if not rag_info:
        return []
    pages = int(rag_info.get("pages_searched") or 0)
    if pages <= 0:
        return []
    chunks = list(rag_info.get("chunks") or [])
    page_word = "page" if pages == 1 else "pages"
    lines: list[str] = [
        f"Customer Knowledge Base (Confluence) — searched {pages} {page_word}:"
    ]
    if not chunks:
        lines.append("  ► No relevant matches above similarity threshold.")
    else:
        for c in chunks:
            text = (c.get("text") or "").strip()
            if not text:
                continue
            source = c.get("source") or "doc"
            score = float(c.get("score") or 0.0)
            # Single-line render: collapse internal whitespace + trim
            # aggressively so the comment stays scannable. Full chunk is
            # in the vector store if an analyst needs the full context.
            lines.append(f"  ► [{source}] {_truncate(text, caps.snippet_chars)} — {score:.2f}")
    lines.append("")
    return lines


def _append_historical_section(historical: dict | None, *, compact: bool, caps) -> list[str]:
    """Phase 3 (2026-06-13): inject the 'Similar Alerts (past 24h)' block
    into the enrichment comment. Returns [] when historical is None or total=0
    (first-time occurrence — adding a "Similar Alerts: 0" line would be
    noise, not signal)."""
    if not historical or historical.get("total", 0) <= 0:
        return []
    window = historical.get("window_hours", 24)
    total = historical["total"]
    tp = historical.get("true_positive", 0)
    fp = historical.get("false_positive", 0)
    unk = historical.get("unknown", 0)
    unt = historical.get("untriaged", 0)
    prefix = historical.get("rule_prefix") or ""
    first_seen = _format_sgt(historical.get("first_seen_at") or "")

    lines: list[str] = [f"Similar Alerts (past {window}h): {total}"]
    lines.append(f"  ├─ True-Positive:  {tp}")
    lines.append(f"  ├─ Benign-Positive: {fp}")
    lines.append(f"  ├─ Unknown:        {unk}")
    suffix = " (still in flight)" if unt else ""
    lines.append(f"  └─ Untriaged:      {unt}{suffix}")
    if prefix:
        lines.append(f"  Matched on: \"{prefix}\"")
    if first_seen:
        lines.append(f"  Earliest sibling: {first_seen}")
    lines.append("")
    return lines


_TIMING_DISPLAY = {
    "business-hours-only": "business-hours-only",
    "after-hours-only": "after-hours-only — atypical timing, weigh toward suspicion",
    "mixed": "mixed",
    "insufficient-sample": "insufficient sample",
}


def _append_pattern_section(pattern: dict | None, *, compact: bool, caps) -> list[str]:
    """Alert Pattern Analysis (30d): frequency, verdict history, business-hours
    timing and the deterministic tuning recommendation. Returns [] when pattern is
    None. Unlike the 24h historical block, total=0 still renders a one-liner
    when this is the first occurrence of the rule ever — that IS signal."""
    if not pattern:
        return []
    days = pattern.get("window_days", 30)
    total = int(pattern.get("total") or 0)
    if total <= 0:
        if not pattern.get("first_seen_ever"):
            return [f"Alert Pattern Analysis ({days}d): first occurrence of this rule "
                    f"— no prior similar alerts found", ""]
        return []

    total_str = f"{total}+" if pattern.get("truncated") else str(total)
    lines: list[str] = [f"Alert Pattern Analysis ({days}d): {total_str} alerts"]
    lines.append(f"  ├─ True-Positive:  {pattern.get('true_positive', 0)}")
    lines.append(f"  ├─ Benign-Positive: {pattern.get('false_positive', 0)}")
    lines.append(f"  ├─ Unknown:        {pattern.get('unknown', 0)}")
    lines.append(f"  └─ Untriaged:      {pattern.get('untriaged', 0)}")

    first_ever = _format_sgt(pattern.get("first_seen_ever") or "")
    if first_ever:
        lines.append(f"  First seen (ever): {first_ever}")
    elif pattern.get("first_seen_in_window"):
        lines.append(f"  First seen (in window): {_format_sgt(pattern['first_seen_in_window'])}")

    timing = pattern.get("timing_pattern") or ""
    if timing:
        start = os.environ.get("BUSINESS_HOURS_START", "9")
        end = os.environ.get("BUSINESS_HOURS_END", "18")
        lines.append(f"  Timing: {_TIMING_DISPLAY.get(timing, timing)} — "
                     f"{pattern.get('business_hours_count', 0)} business-hours / "
                     f"{pattern.get('after_hours_count', 0)} after-hours "
                     f"(SGT {int(start):02d}:00-{int(end):02d}:00 Mon-Fri)")

    entities = pattern.get("entity_correlation") or []
    if entities:
        lines.append("  Entity history:")
        for e in entities:
            bits = []
            if e.get("false_positive"):
                bits.append(f"{e['false_positive']} Benign-Positive")
            if e.get("true_positive"):
                bits.append(f"{e['true_positive']} True-Positive")
            if e.get("unknown"):
                bits.append(f"{e['unknown']} Unknown")
            breakdown = f" ({', '.join(bits)})" if bits else ""
            benign = " — recurring benign" if e.get("historically_benign") else ""
            lines.append(f"    · {e.get('value','')} ({e.get('type','?')}) — "
                         f"{e.get('count', 0)} prior incidents{breakdown}{benign}")

    tuning = pattern.get("tuning")
    if tuning and tuning.get("recommended"):
        lines.append(f"  TUNING CANDIDATE ({tuning.get('strength', 'moderate')}): "
                     f"{tuning.get('rationale', '')}")
    lines.append("")
    return lines


def _append_alert_history_section(historical: dict | None, pattern: dict | None,
                                  *, compact: bool, caps) -> list[str]:
    """Single entry point for both verdict-history blocks.

    In full mode this is a pass-through that renders the 24h and 30d sections
    exactly as before. In compact mode the two are merged under one heading and
    flattened to a line each — they answer overlapping questions ("is this
    spiking now" vs "is this rule chronically noisy") with the same
    TP/BP/Unknown/Untriaged breakdown, and stacking two box-drawing trees cost
    ~23 lines to convey what fits in two.

    Entity correlation is reduced to the entities that are *historically
    benign* — the rest is background. Tuning candidacy survives in full because
    it is the one actionable output of the 30d window.
    """
    if not compact:
        return (_append_historical_section(historical, compact=compact, caps=caps)
                + _append_pattern_section(pattern, compact=compact, caps=caps))

    lines: list[str] = []
    body: list[str] = []

    if historical and historical.get("total", 0) > 0:
        window = historical.get("window_hours", 24)
        unt = historical.get("untriaged", 0)
        unt_str = f" / {unt} untriaged" if unt else ""
        body.append(
            f"  {window}h: {historical['total']} similar — "
            f"{historical.get('true_positive', 0)} TP / "
            f"{historical.get('false_positive', 0)} BP / "
            f"{historical.get('unknown', 0)} unknown{unt_str}"
        )

    if pattern:
        days = pattern.get("window_days", 30)
        total = int(pattern.get("total") or 0)
        if total <= 0:
            if not pattern.get("first_seen_ever"):
                body.append(f"  {days}d: first occurrence of this rule — no prior similar alerts")
        else:
            total_str = f"{total}+" if pattern.get("truncated") else str(total)
            bits = [
                f"  {days}d: {total_str} alerts — "
                f"{pattern.get('true_positive', 0)} TP / "
                f"{pattern.get('false_positive', 0)} BP / "
                f"{pattern.get('unknown', 0)} unknown"
            ]
            timing = pattern.get("timing_pattern") or ""
            # Only surface timing when it's a genuine signal — "mixed" and
            # "insufficient-sample" tell an analyst nothing.
            if timing in ("after-hours-only", "business-hours-only"):
                bits.append(timing)
            line = " · ".join(bits)
            benign = [e.get("value", "") for e in (pattern.get("entity_correlation") or [])
                      if e.get("historically_benign")]
            if benign:
                shown = ", ".join(benign[:3])
                more = f" (+{len(benign) - 3})" if len(benign) > 3 else ""
                line += f" · recurring benign: {shown}{more}"
            body.append(line)

            tuning = pattern.get("tuning")
            if tuning and tuning.get("recommended"):
                body.append(f"  TUNING CANDIDATE ({tuning.get('strength', 'moderate')}): "
                            f"{tuning.get('rationale', '')}")

    if body:
        lines.append("Alert history:")
        lines.extend(body)
        lines.append("")
    return lines


def _append_whitelist_match_section(matches: list[dict] | None, *, compact: bool, caps) -> list[str]:
    """Phase 5e (2026-06-16): direct (literal substring) IOC hits in the
    customer's Confluence chunks. Surfaces whitelist + reference-table
    matches that vector RAG misses because tabular data embeds poorly."""
    if not matches:
        return []
    lines: list[str] = [f"Direct Whitelist Match ({len(matches)}):"]
    for m in matches:
        ioc_type = (m.get("ioc_type") or "?").upper()
        head = f"  ► [{ioc_type}] {m.get('ioc','')} — {m.get('source','')}"
        snippet = m.get("snippet", "")
        if compact:
            # Fold the context onto the match line — the source name plus a
            # short quote is enough to judge whether the whitelist entry applies.
            ctx = f" « {_truncate(snippet, caps.snippet_chars)} »" if snippet else ""
            lines.append(head + ctx)
            continue
        lines.append(head)
        if snippet:
            lines.append(f"      « {snippet} »")
    lines.append("")
    return lines


# ─── Improvement #3 (2026-07-03) — known-activity advisory + whitelist conflict ──

def _known_activity_top_chunk(rag_info: dict | None, *, caps):
    """Return (snippet, source, score) for the single strongest customer-Confluence
    chunk when it clears KNOWN_ACTIVITY_ADVISORY_MIN_SCORE, else None. Gated by
    KNOWN_ACTIVITY_ADVISORY_ENABLED. Used only for the advisory box — never the verdict."""
    if os.environ.get("KNOWN_ACTIVITY_ADVISORY_ENABLED", "false").lower() != "true":
        return None
    if not rag_info:
        return None
    try:
        min_score = float(os.environ.get("KNOWN_ACTIVITY_ADVISORY_MIN_SCORE", "0.75"))
    except ValueError:
        min_score = 0.75
    best = None
    for c in (rag_info.get("chunks") or []):
        try:
            sc = float(c.get("score") or 0.0)
        except (TypeError, ValueError):
            continue
        if sc >= min_score and (best is None or sc > best[2]):
            best = (_truncate(c.get("text") or "", caps.snippet_chars),
                    c.get("source") or "Confluence", sc)
    return best


def _append_known_activity_advisory(rag_info: dict | None, *, compact: bool, caps) -> list[str]:
    top = _known_activity_top_chunk(rag_info, caps=caps)
    if not top:
        return []
    snippet, source, score = top
    return [
        "KNOWN ACTIVITY (Customer Confluence) — this alert pattern is documented as known/expected:",
        f"  ► [{source}] {snippet} (score {score:.2f})",
        "",
    ]


def _append_whitelist_conflict(whitelist_conflict: list[dict] | None, *, compact: bool, caps) -> list[str]:
    if not whitelist_conflict:
        return []
    lines: list[str] = []
    for m in whitelist_conflict:
        lines.append(f"WHITELIST CONFLICT: {m.get('ioc', '')} is whitelisted in Confluence but "
                     f"flagged malicious by threat intel — treated as True-Positive (possible "
                     f"stale whitelist or compromised asset); verify.")
    lines.append("")
    return lines


def _adf_known_activity_block(rag_info: dict | None, *, compact: bool, caps) -> list[dict]:
    top = _known_activity_top_chunk(rag_info, caps=caps)
    if not top:
        return []
    from tools import adf
    snippet, source, score = top
    return [adf.panel(
        "info",
        adf.paragraph(adf.text("Known Activity (Customer Confluence) — this alert pattern is "
                               "documented as known/expected.", bold=True)),
        adf.paragraph(adf.text(f"[{source}] ", bold=True), adf.text(f"{snippet} (score {score:.2f})")),
    )]


def _adf_whitelist_conflict_block(whitelist_conflict: list[dict] | None) -> list[dict]:
    if not whitelist_conflict:
        return []
    from tools import adf
    paras = []
    for m in whitelist_conflict:
        paras.append(adf.paragraph(
            adf.text("WHITELIST CONFLICT: ", bold=True),
            adf.text(f"{m.get('ioc', '')} is whitelisted in Confluence but flagged malicious by "
                     f"threat intel — treated as True-Positive (possible stale whitelist or "
                     f"compromised asset); verify."),
        ))
    return [adf.panel("warning", *paras)]


def _build_comment(ioc_results: list[dict], overall_verdict: str, action_taken: str,
                   mitre_result: dict | None = None,
                   historical: dict | None = None,
                   rag_info: dict | None = None,
                   kql_evidence: dict | None = None,
                   recommendation: str | None = None,
                   whitelist_matches: list[dict] | None = None,
                   whitelist_conflict: list[dict] | None = None,
                   cmdline_analysis: dict | None = None,
                   code_explain: dict | None = None,
                   ticket_key: str = "",
                   pattern: dict | None = None) -> str:
    # Resolve verbosity + truncation caps ONCE for this build; thread compact/caps
    # into every section builder instead of each re-reading the env var.
    assembler = CommentAssembler()
    compact, caps = assembler.compact, assembler.caps

    lines: list[str] = []
    # Improvement #3: top advisory box (never collapsed, in any mode).
    lines += _append_known_activity_advisory(rag_info, compact=compact, caps=caps)
    lines += ["=== L1 Triage Report (Automated) ===", ""]
    verdict_display = _VERDICT_LABEL.get(overall_verdict, overall_verdict.upper())

    if not ioc_results:
        # No IOCs to actually query — produce reputation-engine-shaped output for
        # consistency with tickets that DO have IOCs. The triage outcome is
        # Unknown (we can't confirm or refute without observables); the ticket
        # is routed to L2 for analyst review.
        if compact:
            # 2026-08-05: the three "No detections" lines below used to render
            # here for shape-consistency with tickets that DO have IOCs. They
            # read as three engines clearing the ticket when nothing was ever
            # queried, which is misleading as well as verbose. One honest line.
            lines += ["No extractable observables — reputation engines not queried.", ""]
        else:
            lines += [
                "Reputation engines (no extractable IOCs — no actual queries made):",
                "  - VirusTotal:  No detections",
                "  - AbuseIPDB:   No threat detected",
                "  - SOCRadar:    No detections",
                "",
            ]
        lines += _append_mitre_section(mitre_result, compact=compact, caps=caps)
        lines += _append_whitelist_match_section(whitelist_matches, compact=compact, caps=caps)
        lines += _append_customer_knowledge_section(rag_info, compact=compact, caps=caps)
        lines += _append_sentinel_evidence_section(kql_evidence, compact=compact, caps=caps)
        lines += _append_alert_history_section(historical, pattern, compact=compact, caps=caps)
        lines += _append_cmdline_section(cmdline_analysis, compact=compact, caps=caps)
        lines += _append_code_explain_section(code_explain, compact=compact, caps=caps)
        lines += _append_whitelist_conflict(whitelist_conflict, compact=compact, caps=caps)
        lines += [
            f"VERDICT: {verdict_display}",
            f"AUTO-TRIAGE: {action_taken}",
        ]
        if recommendation:
            lines.append(f"RECOMMENDED ACTION: {recommendation}")
        return assembler.render_plain(lines)

    # An "IOC" here means an observable that at least one reputation engine flagged
    # as malicious. Observables that all engines cleared (or returned no data for)
    # are still listed below for analyst visibility but don't bump the IOC count.
    ioc_count = sum(1 for r in ioc_results if r.get("verdict") == "malicious")
    if compact:
        lines.append(f"IOCs found: {ioc_count} of {len(ioc_results)} observables checked")
    else:
        lines.append(f"IOCs found: {ioc_count}")
        lines.append(f"(Extracted observables checked: {len(ioc_results)})")
    lines.append("")

    # TTP update (2026-07-10): MITRE section first, mirroring the ADF layout —
    # renders only on malicious verdicts now.
    lines += _append_mitre_section(mitre_result, compact=compact, caps=caps)

    # Phase 5b (2026-06-15): per-IOC historical lookup budget. Each malicious
    # IOC may consume one JQL call; cap protects webhook latency. Same shape
    # as the existing SOCRADAR_TRIAGE_BUDGET_PER_TICKET pattern.
    try:
        from tools.ioc_history import budget_per_ticket as _ioc_history_budget
        ioc_history_budget_remaining = _ioc_history_budget()
    except Exception:
        ioc_history_budget_remaining = 0

    # 2026-08-05 compact mode: only observables an engine actually flagged earn
    # a full block. The rest collapse to one line at the end of the list — on a
    # ticket with 6 observables where 5 came back clean that reclaims ~55 lines
    # while still recording every value that was checked.
    if compact:
        flagged = [r for r in ioc_results if r.get("verdict") in ("malicious", "suspicious")]
        cleared = [r for r in ioc_results if r.get("verdict") not in ("malicious", "suspicious")]
    else:
        flagged, cleared = ioc_results, []

    for i, result in enumerate(flagged, 1):
        ioc = result["ioc"]
        lines.append(f"[{i}] {ioc['value']} ({ioc['type'].upper()})")

        vt = result.get("virustotal")
        ab = result.get("abuseipdb")

        # Origin block (IPs only) — country + ISP/AS owner + reverse DNS.
        # Surfaces metadata both reputation engines already fetch but don't
        # historically display, so analysts see "Microsoft Azure IP from US"
        # at a glance instead of digging through raw payloads.
        if ioc["type"] == "ip":
            lines.extend(_ip_origin_lines(vt, ab, compact=compact))

        if vt:
            mal = vt.get("malicious_count", 0)
            tot = vt.get("total_engines", 0)
            rep = vt.get("reputation", 0)
            if tot > 0:
                confidence = (mal / tot) * 100
                lines.append(
                    f"  VirusTotal: {mal}/{tot} detections "
                    f"(Confidence {confidence:.1f}%, Reputation {rep})"
                )
            else:
                lines.append(f"  VirusTotal: {mal}/{tot} detections (Reputation {rep})")
        else:
            lines.append(f"  VirusTotal: {_rep_empty_label('virustotal')}")

        if ioc["type"] == "ip":
            if ab:
                lines.append(f"  AbuseIPDB: Confidence {ab.get('confidence_score', 0)}%")
            else:
                lines.append(f"  AbuseIPDB: {_rep_empty_label('abuseipdb')}")
        else:
            lines.append("  AbuseIPDB: N/A (IP only)")

        sr = result.get("socradar")
        if sr:
            verdict = sr.get("verdict", "unknown")
            score = sr.get("score", 0)
            cats = sr.get("categories") or []
            cats_str = (" — " + ", ".join(cats)) if cats else ""
            lines.append(f"  SOCRadar:  {verdict.title()} (score {score}/100){cats_str}")
            # Supporting findings justify a malicious call; on anything else
            # they are three lines of provenance for a verdict nobody disputes.
            if compact and result.get("verdict") != "malicious":
                findings = []
            else:
                findings = (sr.get("top_findings") or [])[:caps.socradar_findings]
            for f in findings:
                src = f.get("source") or "?"
                cat = f.get("category") or "?"
                rel = f.get("reliability") or 0
                last = _format_sgt(f.get("last_seen") or "")
                lines.append(f"    · {src} — {cat} (reliability {rel}, last seen {last})")
        else:
            lines.append(f"  SOCRadar:  {_rep_empty_label('socradar')}")

        # Phase 5b (2026-06-15): per-IOC historical Jira appearances for any
        # IOC the reputation engines flagged as malicious. Killswitch-gated;
        # budgeted to IOC_HISTORY_BUDGET_PER_TICKET to bound webhook latency
        # (each call is one JQL search, ~1-2s on Jira Cloud). Failure-
        # isolated: never raises out of this block — a None return just
        # skips the line for that IOC.
        if result.get("verdict") == "malicious" and ioc_history_budget_remaining > 0:
            try:
                from tools.ioc_history import lookup_ioc_history, render_line
                hist = lookup_ioc_history(ioc.get("value", ""), exclude_ticket_key=ticket_key)
                hist_line = render_line(hist)
                if hist_line:
                    lines.append(hist_line)
            except Exception as _hist_err:
                logger.warning("ioc_history render failed for %s (%s); skipping line",
                               ioc.get("value", ""), _hist_err)
            ioc_history_budget_remaining -= 1

        lines.append("")

    if cleared:
        values = ", ".join((r.get("ioc") or {}).get("value", "") for r in cleared)
        lines.append(f"Cleared by all engines ({len(cleared)}): {values}")
        lines.append("")

    lines += _append_whitelist_match_section(whitelist_matches, compact=compact, caps=caps)
    lines += _append_customer_knowledge_section(rag_info, compact=compact, caps=caps)
    lines += _append_sentinel_evidence_section(kql_evidence, compact=compact, caps=caps)
    lines += _append_alert_history_section(historical, pattern, compact=compact, caps=caps)
    lines += _append_insights_section(ioc_results, compact=compact, caps=caps)
    lines += _append_cmdline_section(cmdline_analysis, compact=compact, caps=caps)
    lines += _append_code_explain_section(code_explain, compact=compact, caps=caps)
    lines += _append_whitelist_conflict(whitelist_conflict, compact=compact, caps=caps)
    lines.append(f"VERDICT: {verdict_display}")
    lines.append(f"AUTO-TRIAGE: {action_taken}")
    if recommendation:
        lines.append(f"RECOMMENDED ACTION: {recommendation}")
    return assembler.render_plain(lines)


# ─── Phase 5c (2026-06-16) — ADF table renderer ──────────────────────────────
#
# Mirrors _build_comment() but emits ADF (Atlassian Document Format) so the
# enrichment comment renders as panels, headings, and tables in Jira instead
# of dense paragraphs. Feature-flagged via COMMENT_ADF_ENABLED — default off
# until verified end-to-end on a synthetic webhook. On Jira HTTP 400 (any
# ADF validation failure), enrich_ticket() falls back to the plain-text
# _build_comment() path so an analyst never sees an empty comment.

_VERDICT_PANEL_TYPE = {
    "malicious":  "error",   # red
    "suspicious": "warning", # amber
    "benign":     "success", # green
    "unknown":    "note",    # grey
}


def _adf_ioc_block(ioc_results: list[dict], ticket_key: str, *, compact: bool, caps) -> list[dict]:
    """Build the ADF nodes for the per-IOC details section.

    Each malicious IOC gets its own subheading + 2-col key/value Origin
    table (IPs only) + Reputation table + a 'Previously flagged' line if
    history is available. Same per-IOC budget rules as _build_comment.
    """
    from tools import adf

    if not ioc_results:
        return [
            adf.heading(3, "IOCs"),
            adf.paragraph(
                adf.text("No extractable IOCs in this ticket — reputation engines were not queried.", italic=True)
            ),
        ]

    ioc_count = sum(1 for r in ioc_results if r.get("verdict") == "malicious")
    out: list[dict] = [
        adf.heading(3, f"IOCs ({ioc_count} flagged · {len(ioc_results)} checked)")
    ]

    # 2026-08-05: mirrors the compact partition in _build_comment — a full
    # heading + origin table + reputation table per cleared observable is the
    # single largest source of length in this comment.
    if compact:
        cleared = [r for r in ioc_results
                   if r.get("verdict") not in ("malicious", "suspicious")]
        ioc_results = [r for r in ioc_results
                       if r.get("verdict") in ("malicious", "suspicious")]
    else:
        cleared = []

    try:
        from tools.ioc_history import budget_per_ticket as _ioc_history_budget
        ioc_history_budget_remaining = _ioc_history_budget()
    except Exception:
        ioc_history_budget_remaining = 0

    for i, result in enumerate(ioc_results, 1):
        ioc = result["ioc"]
        # 2026-06-16: bumped from h4 → h3 + bold mark on the IOC value so the
        # IP/domain/hash is the visual centre of each per-IOC block. We do
        # NOT also apply the `code` (monospace) mark because Jira ADF rejects
        # the strong+code mark combination on text inside a heading with
        # INVALID_INPUT (HTTP 400). Bold + larger heading already gives
        # plenty of visual weight; the monospace look is nice-to-have rather
        # than essential here.
        out.append(adf.heading(3, adf.text(f"[{i}] ", italic=True),
                                    adf.text(ioc["value"], bold=True),
                                    adf.text(f" ({ioc['type'].upper()})")))

        vt = result.get("virustotal")
        ab = result.get("abuseipdb")

        if ioc["type"] == "ip":
            origin_rows = _adf_origin_rows(vt, ab)
            if origin_rows:
                out.append(adf.table(["Field", "Value"], origin_rows))

        rep_rows: list[list] = []
        # VirusTotal row
        if vt:
            mal = vt.get("malicious_count", 0)
            tot = vt.get("total_engines", 0)
            rep = vt.get("reputation", 0)
            det = f"{mal} / {tot}" if tot else "—"
            conf = f"{(mal/tot)*100:.1f}%" if tot else "—"
            notes = f"Reputation {rep}"
            rep_rows.append(["VirusTotal", det, conf, notes])
        else:
            rep_rows.append(["VirusTotal", _rep_empty_label('virustotal'), "—", "—"])

        # AbuseIPDB row
        if ioc["type"] == "ip":
            if ab:
                rep_rows.append(["AbuseIPDB", "—", f"{ab.get('confidence_score', 0)}%", "—"])
            else:
                rep_rows.append(["AbuseIPDB", _rep_empty_label('abuseipdb'), "—", "—"])
        else:
            rep_rows.append(["AbuseIPDB", "N/A (IP only)", "—", "—"])

        # SOCRadar row
        sr = result.get("socradar")
        if sr:
            verdict = sr.get("verdict", "unknown").title()
            score = sr.get("score", 0)
            cats = sr.get("categories") or []
            notes = ", ".join(cats) if cats else "—"
            rep_rows.append(["SOCRadar", verdict, f"{score} / 100", notes])
            if compact and result.get("verdict") != "malicious":
                findings = []
            else:
                findings = (sr.get("top_findings") or [])[:caps.socradar_findings]
            for f in findings:
                src = f.get("source") or "?"
                cat = f.get("category") or "?"
                rel = f.get("reliability") or 0
                last = _format_sgt(f.get("last_seen") or "")
                rep_rows.append([
                    adf.paragraph(adf.text("  · ", italic=True), adf.text(src, italic=True)),
                    "—",
                    f"rel {rel}",
                    f"{cat} · last seen {last}",
                ])
        else:
            rep_rows.append(["SOCRadar", _rep_empty_label('socradar'), "—", "—"])

        out.append(adf.table(["Engine", "Detections", "Confidence", "Notes"], rep_rows))

        # Per-IOC historical
        if result.get("verdict") == "malicious" and ioc_history_budget_remaining > 0:
            try:
                from tools.ioc_history import lookup_ioc_history, render_line
                hist = lookup_ioc_history(ioc.get("value", ""), exclude_ticket_key=ticket_key)
                hist_line = render_line(hist)
                if hist_line:
                    out.append(adf.paragraph(adf.text(hist_line, italic=True)))
            except Exception as _hist_err:
                logger.warning("ioc_history ADF render failed for %s (%s)",
                               ioc.get("value", ""), _hist_err)
            ioc_history_budget_remaining -= 1

    if cleared:
        values = ", ".join((r.get("ioc") or {}).get("value", "") for r in cleared)
        out.append(adf.paragraph(
            adf.text(f"Cleared by all engines ({len(cleared)}): ", bold=True),
            adf.text(values),
        ))

    return out


def _adf_origin_rows(vt: dict | None, ab: dict | None) -> list[list]:
    """Build origin key/value rows for the per-IOC Origin table. Drops empty
    fields so the table stays compact."""
    ab = ab or {}
    vt = vt or {}
    rows: list[list] = []

    country_name = ab.get("country_name") or ""
    country_code = ab.get("country_code") or vt.get("country") or ""
    if country_name and country_code:
        rows.append(["Country", f"{country_name} ({country_code})"])
    elif country_name or country_code:
        rows.append(["Country", country_name or country_code])

    isp = ab.get("isp") or ""
    as_owner = vt.get("as_owner") or ""
    if isp:
        rows.append(["ISP", isp])
    elif as_owner:
        rows.append(["AS Owner", as_owner])

    if vt.get("network"):
        rows.append(["Network", vt["network"]])
    if ab.get("usage_type"):
        rows.append(["Usage", ab["usage_type"]])
    if ab.get("domain"):
        rows.append(["Domain", ab["domain"]])

    hostnames = ab.get("hostnames") or []
    if hostnames:
        first = hostnames[0]
        suffix = f" (+{len(hostnames) - 1} more)" if len(hostnames) > 1 else ""
        rows.append(["Reverse DNS", f"{first}{suffix}"])

    return rows


def _adf_insights_block(ioc_results: list[dict] | None) -> list[dict]:
    """Improvement #2 (2026-07-03): ADF 'Additional Insights' section for malicious
    IOCs. Returns [] unless a malicious IOC carries an ``insights`` note."""
    from tools import adf
    items = [((r.get("ioc") or {}).get("value", ""), r.get("insights"))
             for r in (ioc_results or [])
             if r.get("verdict") == "malicious" and r.get("insights")]
    if not items:
        return []
    blocks = [adf.heading(3, "Additional Insights (Open-Source Web Research)")]
    for value, text in items:
        blocks.append(adf.paragraph(adf.text(f"{value} — ", bold=True), adf.text(text)))
    return blocks


# Colour the command-line panel by verdict so an analyst reads it at a glance.
_CMDLINE_PANEL_TYPE = {
    "Malicious": "error", "Suspicious": "warning",
    "Legitimate": "success", "Inconclusive": "note",
}


def _adf_cmdline_block(cmdline_analysis: dict | None) -> list[dict]:
    """Improvement #4 (2026-07-06): ADF 'Command-Line Analysis' section — one
    colour-coded panel per command line. Returns [] unless the analyzer produced
    items. Advisory only (does not drive the verdict)."""
    from tools import adf
    items = (cmdline_analysis or {}).get("items") or []
    if not items:
        return []
    blocks = [adf.heading(3, "Command-Line Analysis (AI + Open-Source Web Research)")]
    for it in items:
        verdict = it.get("verdict", "Inconclusive")
        img = it.get("image") or "process"
        panel_type = _CMDLINE_PANEL_TYPE.get(verdict, "note")
        inner = [
            adf.paragraph(adf.text(f"{verdict}: ", bold=True), adf.text(img, bold=True)),
            adf.paragraph(adf.text("Command line: ", bold=True),
                          adf.text(it.get("command_line", ""), code=True)),
        ]
        if it.get("parent_image"):
            inner.append(adf.paragraph(adf.text("Parent: ", bold=True),
                                       adf.text(it["parent_image"], code=True)))
        inner.append(adf.paragraph(adf.text(it.get("analysis", ""))))
        blocks.append(adf.panel(panel_type, *inner))
    return blocks


def _adf_code_explain_block(code_explain: dict | None) -> list[dict]:
    """Improvement #5 (2026-07-06): ADF 'Security Code Explanations' section — a
    table decoding Event IDs / Logon Types / NTSTATUS / Kerberos codes. Returns []
    unless CODE_EXPLAIN_ENABLED produced items. Advisory only."""
    from tools import adf
    items = (code_explain or {}).get("items") or []
    if not items:
        return []
    rows = []
    for it in items:
        code = it.get("code", "")
        if it.get("source") == "web":
            code += " *"
        rows.append([code, it.get("label", ""), it.get("meaning", "")])
    return [
        adf.heading(3, "Security Code Explanations"),
        adf.table(["Code", "Type", "Meaning"], rows),
    ]


def _mitre_technique_url(technique_id: str) -> str:
    """attack.mitre.org page for a technique ID — sub-technique dot becomes a
    path segment: T1071.001 → /techniques/T1071/001/."""
    return f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"


def _adf_mitre_block(mitre_result: dict | None) -> list[dict]:
    from tools import adf
    if not mitre_result:
        return []
    techniques = mitre_result.get("techniques") or []
    if not techniques:
        return []
    rows = []
    for t in techniques:
        pct = int(round(t.get("confidence", 0) * 100))
        rows.append([
            adf.text(t["id"], link=_mitre_technique_url(t["id"])),
            t.get("tactic", "—"),
            t.get("name", "—"),
            f"{pct}%",
            t.get("rationale") or "—",
        ])
    return [
        adf.heading(3, "MITRE ATT&CK — Attack TTPs"),
        adf.table(["ID", "Tactic", "Name", "Confidence", "Why"], rows),
    ]


def _adf_whitelist_match_block(matches: list[dict] | None) -> list[dict]:
    """Phase 5e (2026-06-16): rendered as a 'success' panel with a 4-col
    table. Sits ABOVE Customer Knowledge Base because a literal whitelist
    hit is a stronger signal than a semantic similarity hit — analyst eye
    lands on it first within the comment body."""
    from tools import adf
    if not matches:
        return []
    rows = []
    for m in matches:
        rows.append([
            m.get("ioc", ""),
            (m.get("ioc_type") or "").upper(),
            m.get("source", ""),
            m.get("snippet", ""),
        ])
    return [
        adf.heading(3, "Direct Whitelist Match"),
        adf.paragraph(
            adf.text("IOC values found verbatim in the customer's Confluence knowledge base — strong signal of a known-benign destination/source.", italic=True)
        ),
        adf.table(["IOC", "Type", "Source", "Context"], rows),
    ]


def _adf_sentinel_block(kql_result: dict | None, *, compact: bool, caps) -> list[dict]:
    from tools import adf
    if not kql_result:
        return []
    queries = kql_result.get("queries") or []
    if not queries:
        return []
    workspace = kql_result.get("workspace_name") or "(unnamed)"
    iters = kql_result.get("iterations", len(queries))
    total = kql_result.get("total_rows", 0)
    iter_word = "iteration" if iters == 1 else "iterations"
    row_word = "row" if total == 1 else "rows"

    rows = []
    for q in queries:
        i = q.get("iteration", 0)
        table_name = q.get("table") or "(unspecified)"
        row_count = q.get("row_count", 0)
        rationale = _truncate(q.get("rationale") or "", caps.rationale_chars)
        rows.append([str(i), table_name, str(row_count), rationale or "—"])

    return [
        adf.heading(3, f"Sentinel Evidence ({workspace})"),
        adf.paragraph(
            adf.text(f"{iters} {iter_word} · {total} {row_word} total", italic=True)
        ),
        adf.table(["#", "Table", "Hits", "LLM rationale"], rows),
    ]


def _adf_customer_knowledge_block(rag_info: dict | None, *, compact: bool, caps) -> list[dict]:
    from tools import adf
    if not rag_info:
        return []
    pages = int(rag_info.get("pages_searched") or 0)
    if pages <= 0:
        return []
    chunks = list(rag_info.get("chunks") or [])
    page_word = "page" if pages == 1 else "pages"

    blocks = [
        adf.heading(3, "Customer Knowledge Base (Confluence)"),
        adf.paragraph(
            adf.text(f"Searched {pages} {page_word}", italic=True)
        ),
    ]
    if not chunks:
        blocks.append(adf.paragraph(
            adf.text("No relevant matches above similarity threshold.", italic=True)
        ))
        return blocks

    rows = []
    for c in chunks:
        text_val = (c.get("text") or "").strip()
        if not text_val:
            continue
        source = c.get("source") or "doc"
        score = float(c.get("score") or 0.0)
        rows.append([source, f"{score:.2f}", _truncate(text_val, caps.snippet_chars)])
    blocks.append(adf.table(["Source", "Score", "Snippet"], rows))
    return blocks


def _adf_historical_block(historical: dict | None) -> list[dict]:
    from tools import adf
    if not historical or historical.get("total", 0) <= 0:
        return []
    window = historical.get("window_hours", 24)
    total = historical["total"]
    tp = historical.get("true_positive", 0)
    fp = historical.get("false_positive", 0)
    unk = historical.get("unknown", 0)
    unt = historical.get("untriaged", 0)
    prefix = historical.get("rule_prefix") or ""
    first_seen = _format_sgt(historical.get("first_seen_at") or "")

    rows = [
        ["True-Positive", str(tp)],
        ["Benign-Positive", str(fp)],
        ["Unknown", str(unk)],
        ["Untriaged", f"{unt} (still in flight)" if unt else "0"],
    ]
    if prefix:
        rows.append(["Matched on", f'"{prefix}"'])
    if first_seen:
        rows.append(["Earliest sibling", first_seen])

    return [
        adf.heading(3, f"Similar Alerts (past {window}h)"),
        adf.paragraph(adf.text(f"{total} similar alert(s) found", italic=True)),
        adf.table(["Category", "Count"], rows),
    ]


def _adf_pattern_block(pattern: dict | None) -> list[dict]:
    """ADF twin of _append_pattern_section — Alert Pattern Analysis (30d)."""
    if not pattern:
        return []
    from tools import adf
    days = pattern.get("window_days", 30)
    total = int(pattern.get("total") or 0)

    if total <= 0:
        if pattern.get("first_seen_ever"):
            return []
        return [
            adf.heading(3, f"Alert Pattern Analysis ({days}d)"),
            adf.paragraph(adf.text("First occurrence of this rule — no prior "
                                   "similar alerts found", italic=True)),
        ]

    total_str = f"{total}+" if pattern.get("truncated") else str(total)
    rows = [
        ["True-Positive", str(pattern.get("true_positive", 0))],
        ["Benign-Positive", str(pattern.get("false_positive", 0))],
        ["Unknown", str(pattern.get("unknown", 0))],
        ["Untriaged", str(pattern.get("untriaged", 0))],
    ]
    first_ever = _format_sgt(pattern.get("first_seen_ever") or "")
    if first_ever:
        rows.append(["First seen (ever)", first_ever])
    elif pattern.get("first_seen_in_window"):
        rows.append(["First seen (in window)", _format_sgt(pattern["first_seen_in_window"])])

    timing = pattern.get("timing_pattern") or ""
    if timing:
        start = os.environ.get("BUSINESS_HOURS_START", "9")
        end = os.environ.get("BUSINESS_HOURS_END", "18")
        rows.append(["Timing", f"{_TIMING_DISPLAY.get(timing, timing)} — "
                               f"{pattern.get('business_hours_count', 0)} business-hours / "
                               f"{pattern.get('after_hours_count', 0)} after-hours "
                               f"(SGT {int(start):02d}:00-{int(end):02d}:00 Mon-Fri)"])

    blocks = [
        adf.heading(3, f"Alert Pattern Analysis ({days}d)"),
        adf.paragraph(adf.text(f"{total_str} similar alert(s) in the past {days} days",
                               italic=True)),
        adf.table(["Category", "Count"], rows),
    ]

    entities = pattern.get("entity_correlation") or []
    if entities:
        e_rows = []
        for e in entities:
            bits = []
            if e.get("false_positive"):
                bits.append(f"{e['false_positive']} Benign-Positive")
            if e.get("true_positive"):
                bits.append(f"{e['true_positive']} True-Positive")
            if e.get("unknown"):
                bits.append(f"{e['unknown']} Unknown")
            outcome = ", ".join(bits) or "all untriaged"
            if e.get("historically_benign"):
                outcome += " — recurring benign"
            e_rows.append([f"{e.get('value', '')} ({e.get('type', '?')})",
                           str(e.get("count", 0)), outcome])
        blocks.append(adf.heading(4, "Entity history (prior incidents)"))
        blocks.append(adf.table(["Entity", "Incidents", "Outcomes"], e_rows))

    tuning = pattern.get("tuning")
    if tuning and tuning.get("recommended"):
        blocks.append(adf.panel(
            "warning",
            adf.paragraph(
                adf.text(f"TUNING CANDIDATE ({tuning.get('strength', 'moderate')}): ", bold=True),
                adf.text(tuning.get("rationale", "")),
            ),
        ))
    return blocks


def _adf_alert_history_blocks(historical: dict | None, pattern: dict | None,
                             *, compact: bool, caps) -> list[dict]:
    """ADF twin of _append_alert_history_section. Full mode renders the 24h and
    30d sections unchanged; compact merges them into one three-column table."""
    if not compact:
        return _adf_historical_block(historical) + _adf_pattern_block(pattern)

    from tools import adf
    rows: list[list] = []

    if historical and historical.get("total", 0) > 0:
        unt = historical.get("untriaged", 0)
        rows.append([
            f"{historical.get('window_hours', 24)}h",
            str(historical["total"]),
            f"{historical.get('true_positive', 0)} TP / "
            f"{historical.get('false_positive', 0)} BP / "
            f"{historical.get('unknown', 0)} unknown"
            + (f" / {unt} untriaged" if unt else ""),
        ])

    tuning = None
    if pattern:
        days = pattern.get("window_days", 30)
        total = int(pattern.get("total") or 0)
        if total <= 0:
            if not pattern.get("first_seen_ever"):
                rows.append([f"{days}d", "0", "first occurrence of this rule"])
        else:
            outcome = (f"{pattern.get('true_positive', 0)} TP / "
                       f"{pattern.get('false_positive', 0)} BP / "
                       f"{pattern.get('unknown', 0)} unknown")
            timing = pattern.get("timing_pattern") or ""
            if timing in ("after-hours-only", "business-hours-only"):
                outcome += f" · {timing}"
            benign = [e.get("value", "") for e in (pattern.get("entity_correlation") or [])
                      if e.get("historically_benign")]
            if benign:
                shown = ", ".join(benign[:3])
                more = f" (+{len(benign) - 3})" if len(benign) > 3 else ""
                outcome += f" · recurring benign: {shown}{more}"
            rows.append([f"{days}d",
                         f"{total}+" if pattern.get("truncated") else str(total),
                         outcome])
            t = pattern.get("tuning")
            if t and t.get("recommended"):
                tuning = t

    if not rows:
        return []

    blocks = [
        adf.heading(3, "Alert history"),
        adf.table(["Window", "Alerts", "Outcome"], rows),
    ]
    if tuning:
        blocks.append(adf.panel("warning", adf.paragraph(
            adf.text(f"TUNING CANDIDATE ({tuning.get('strength', 'moderate')}): ", bold=True),
            adf.text(tuning.get("rationale", "")),
        )))
    return blocks


def _key_signals(ioc_results: list[dict] | None, mitre_result: dict | None,
                 historical: dict | None, pattern: dict | None) -> str:
    """One-line digest for the top verdict panel in compact mode.

    Everything named here is also available in full inside the expanders — this
    exists so an analyst can decide whether to open any of them at all.
    """
    bits: list[str] = []

    if ioc_results:
        flagged = sum(1 for r in ioc_results
                      if r.get("verdict") in ("malicious", "suspicious"))
        bits.append(f"{flagged} of {len(ioc_results)} observables flagged")
    else:
        # Says the quiet part out loud: nothing was queried, so a benign-looking
        # verdict here rests on the absence of observables, not on clean results.
        bits.append("no extractable observables")

    techniques = (mitre_result or {}).get("techniques") or []
    if techniques:
        top = techniques[0]
        extra = f" (+{len(techniques) - 1})" if len(techniques) > 1 else ""
        bits.append(f"{top.get('id', '')} {top.get('name', '')}{extra}".strip())

    # Prefer the 24h window — "is this spiking right now" beats the 30d baseline
    # for a triage decision. Fall back to 30d when there are no same-day siblings.
    if historical and historical.get("total", 0) > 0:
        bits.append(f"{historical.get('false_positive', 0)}/{historical['total']} similar "
                    f"closed Benign-Positive ({historical.get('window_hours', 24)}h)")
    elif pattern and int(pattern.get("total") or 0) > 0:
        bits.append(f"{pattern.get('false_positive', 0)}/{pattern.get('total')} "
                    f"Benign-Positive ({pattern.get('window_days', 30)}d)")

    tuning = (pattern or {}).get("tuning")
    if tuning and tuning.get("recommended"):
        bits.append("tuning candidate")

    return " · ".join(bits)


def _build_comment_adf(ioc_results: list[dict], overall_verdict: str, action_taken: str,
                      mitre_result: dict | None = None,
                      historical: dict | None = None,
                      rag_info: dict | None = None,
                      kql_evidence: dict | None = None,
                      recommendation: str | None = None,
                      whitelist_matches: list[dict] | None = None,
                      whitelist_conflict: list[dict] | None = None,
                      cmdline_analysis: dict | None = None,
                      code_explain: dict | None = None,
                      ticket_key: str = "",
                      pattern: dict | None = None) -> dict:
    """Return a full ADF document for the enrichment comment. Same input
    signature as _build_comment() so callers don't change."""
    from tools import adf

    # Resolve verbosity + truncation caps ONCE for this build; thread compact/caps
    # into every ADF section builder instead of each re-reading the env var.
    assembler = CommentAssembler()
    compact, caps = assembler.compact, assembler.caps

    verdict_display = _VERDICT_LABEL.get(overall_verdict, overall_verdict.upper())
    panel_type = _VERDICT_PANEL_TYPE.get(overall_verdict, "note")

    # Verdict panel at the top — color-coded for one-second triage.
    # VERDICT (outcome) → AUTO-TRIAGE (mechanical routing) → RECOMMENDED ACTION
    # (Phase 6 AI guidance, only when synthesis produced one).
    verdict_paras = [
        adf.paragraph(adf.text("VERDICT: ", bold=True), adf.text(verdict_display, bold=True)),
        adf.paragraph(adf.text("AUTO-TRIAGE: ", bold=True), adf.text(action_taken)),
    ]
    if recommendation:
        verdict_paras.append(
            adf.paragraph(adf.text("RECOMMENDED ACTION: ", bold=True), adf.text(recommendation))
        )

    if compact:
        signals = _key_signals(ioc_results, mitre_result, historical, pattern)
        if signals:
            verdict_paras.append(
                adf.paragraph(adf.text("KEY SIGNALS: ", bold=True), adf.text(signals))
            )

    # Improvement #3: known-activity advisory as the FIRST block (top of comment),
    # verdict panel next, then the whitelist/threat-intel conflict warning (if any).
    blocks: list[dict] = []
    blocks.extend(_adf_known_activity_block(rag_info, compact=compact, caps=caps))
    blocks.append(adf.panel(panel_type, *verdict_paras))
    blocks.extend(_adf_whitelist_conflict_block(whitelist_conflict))
    blocks.append(adf.heading(2, "L1 Triage Report (Automated)"))

    # TTP update (2026-07-10): MITRE section moved from last to FIRST under the
    # report heading — it now only renders on malicious verdicts, so it reads as
    # "TRUE-POSITIVE → here's the attack technique picture".
    if not compact:
        blocks.extend(_adf_mitre_block(mitre_result))
        blocks.extend(_adf_ioc_block(ioc_results, ticket_key, compact=compact, caps=caps))
        blocks.extend(_adf_whitelist_match_block(whitelist_matches))
        blocks.extend(_adf_customer_knowledge_block(rag_info, compact=compact, caps=caps))
        blocks.extend(_adf_sentinel_block(kql_evidence, compact=compact, caps=caps))
        blocks.extend(_adf_historical_block(historical))
        blocks.extend(_adf_pattern_block(pattern))
        blocks.extend(_adf_insights_block(ioc_results))
        blocks.extend(_adf_cmdline_block(cmdline_analysis))
        blocks.extend(_adf_code_explain_block(code_explain))
        return assembler.render_adf(blocks)

    # 2026-08-05 compact: same sections, same order, but demoted behind
    # collapsible expanders so the verdict panel is the whole of the first
    # screen. Nothing is dropped that full mode would have shown here.
    #
    # The known-activity advisory, the verdict panel and the whitelist-conflict
    # warning above deliberately stay OUTSIDE any expander — a reader who never
    # clicks must still see them. The assembler owns the expander helper.
    technique_count = len((mitre_result or {}).get("techniques") or [])
    blocks += assembler.expand(f"MITRE ATT&CK ({technique_count})",
                               _adf_mitre_block(mitre_result))
    blocks += assembler.expand(f"Observables ({len(ioc_results or [])})",
                               _adf_ioc_block(ioc_results, ticket_key, compact=compact, caps=caps))
    blocks += assembler.expand("Alert history",
                               _adf_alert_history_blocks(historical, pattern, compact=compact, caps=caps))
    blocks += assembler.expand("Customer knowledge & whitelist",
                               _adf_whitelist_match_block(whitelist_matches),
                               _adf_customer_knowledge_block(rag_info, compact=compact, caps=caps))
    blocks += assembler.expand("Sentinel evidence",
                               _adf_sentinel_block(kql_evidence, compact=compact, caps=caps))
    blocks += assembler.expand("Command-line & code analysis",
                               _adf_insights_block(ioc_results),
                               _adf_cmdline_block(cmdline_analysis),
                               _adf_code_explain_block(code_explain))

    return assembler.render_adf(blocks)


# ─── Jira Actions ─────────────────────────────────────────────────────────────

def _jira_headers() -> dict:
    import base64
    from tools.secrets import get_secret
    email = get_secret("JIRA_EMAIL")
    token = get_secret("JIRA_API_TOKEN")
    creds = base64.b64encode(f"{email}:{token}".encode()).decode()
    return {
        "Authorization": f"Basic {creds}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def post_jira_comment(ticket_key: str, text: str) -> bool:
    """Post a plain-text comment to a Jira issue. Each input line becomes one
    ADF paragraph — preserves today's pre-Phase-5c layout. Used as the
    fallback path when the structured ADF post fails."""
    if not JIRA_URL:
        logger.warning("JIRA_URL not set — cannot post comment to %s", ticket_key)
        return False

    url = f"{JIRA_URL}/rest/api/3/issue/{ticket_key}/comment"
    paragraphs = [
        {"type": "paragraph", "content": [{"type": "text", "text": line or " "}]}
        for line in text.split("\n")
    ]
    body = {"body": {"type": "doc", "version": 1, "content": paragraphs}}

    try:
        r = httpx.post(url, headers=_jira_headers(), json=body, timeout=30)
        if r.status_code >= 400:
            logger.error("post_jira_comment %s HTTP %s: %s", ticket_key, r.status_code, r.text[:300])
            return False
        logger.info("Posted enrichment comment to %s", ticket_key)
        return True
    except Exception as e:
        logger.error("post_jira_comment %s failed: %s", ticket_key, e)
        return False


def post_jira_comment_adf(ticket_key: str, adf_doc: dict) -> bool:
    """Post a pre-built ADF document as a Jira comment (Phase 5c).

    Returns True on success, False on any failure (HTTP error, network, or
    bad ADF shape). Caller is expected to fall back to ``post_jira_comment``
    with a plain-text rendering when this returns False so the analyst
    never sees an empty comment."""
    if not JIRA_URL:
        logger.warning("JIRA_URL not set — cannot post ADF comment to %s", ticket_key)
        return False

    url = f"{JIRA_URL}/rest/api/3/issue/{ticket_key}/comment"
    body = {"body": adf_doc}

    try:
        r = httpx.post(url, headers=_jira_headers(), json=body, timeout=30)
        if r.status_code >= 400:
            logger.error("post_jira_comment_adf %s HTTP %s: %s",
                         ticket_key, r.status_code, r.text[:500])
            return False
        logger.info("Posted ADF enrichment comment to %s", ticket_key)
        return True
    except Exception as e:
        logger.error("post_jira_comment_adf %s failed: %s", ticket_key, e)
        return False


def add_jira_label(ticket_key: str, label: str) -> bool:
    """Add a label to a Jira issue without removing existing labels."""
    if not JIRA_URL:
        logger.warning("JIRA_URL not set — cannot label %s", ticket_key)
        return False

    get_url = f"{JIRA_URL}/rest/api/3/issue/{ticket_key}"
    try:
        r = httpx.get(get_url, headers=_jira_headers(), timeout=30)
        if r.status_code >= 400:
            logger.error("add_jira_label GET %s HTTP %s", ticket_key, r.status_code)
            return False
        existing = r.json().get("fields", {}).get("labels", [])
        if label in existing:
            return True
        updated = existing + [label]
        put_url = f"{JIRA_URL}/rest/api/3/issue/{ticket_key}"
        r2 = httpx.put(put_url, headers=_jira_headers(),
                       json={"fields": {"labels": updated}}, timeout=30)
        if r2.status_code >= 400:
            logger.error("add_jira_label PUT %s HTTP %s: %s",
                         ticket_key, r2.status_code, r2.text[:200])
            return False
        logger.info("Added label '%s' to %s", label, ticket_key)
        return True
    except Exception as e:
        logger.error("add_jira_label %s failed: %s", ticket_key, e)
        return False


def assign_jira_ticket(ticket_key: str, account_id: str) -> bool:
    """Reassign a Jira ticket to the given Jira account ID."""
    if not JIRA_URL:
        logger.warning("JIRA_URL not set — cannot assign %s", ticket_key)
        return False

    url = f"{JIRA_URL}/rest/api/3/issue/{ticket_key}/assignee"
    try:
        r = httpx.put(url, headers=_jira_headers(), json={"accountId": account_id}, timeout=30)
        if r.status_code >= 400:
            logger.error("assign_jira_ticket %s → %s HTTP %s: %s",
                         ticket_key, account_id, r.status_code, r.text[:300])
            return False
        logger.info("Assigned %s to account %s", ticket_key, account_id)
        return True
    except Exception as e:
        logger.error("assign_jira_ticket %s failed: %s", ticket_key, e)
        return False


def set_priority(ticket_key: str, priority_name: str) -> bool:
    """Set the Jira priority on a ticket. priority_name must match a Jira
    priority option exactly (e.g. "Highest", "High", "Medium", "Low",
    "Lowest"). Added in Phase 1 for severity-sync + LLM Triage override."""
    if not JIRA_URL:
        logger.warning("JIRA_URL not set — cannot set priority on %s", ticket_key)
        return False
    if not priority_name:
        return False

    url = f"{JIRA_URL}/rest/api/3/issue/{ticket_key}"
    try:
        r = httpx.put(url, headers=_jira_headers(),
                      json={"fields": {"priority": {"name": priority_name}}},
                      timeout=30)
        if r.status_code >= 400:
            logger.error("set_priority %s → %s HTTP %s: %s",
                         ticket_key, priority_name, r.status_code, r.text[:300])
            return False
        logger.info("set_priority(%s) → %s", ticket_key, priority_name)
        return True
    except Exception as e:
        logger.error("set_priority %s failed: %s", ticket_key, e)
        return False


def remove_jira_label(ticket_key: str, label: str) -> bool:
    """Remove a label from a Jira issue. No-op if the label isn't present."""
    if not JIRA_URL:
        logger.warning("JIRA_URL not set — cannot remove label from %s", ticket_key)
        return False

    get_url = f"{JIRA_URL}/rest/api/3/issue/{ticket_key}"
    try:
        r = httpx.get(get_url, headers=_jira_headers(), timeout=30)
        if r.status_code >= 400:
            logger.error("remove_jira_label GET %s HTTP %s", ticket_key, r.status_code)
            return False
        existing = r.json().get("fields", {}).get("labels", [])
        if label not in existing:
            return True
        updated = [lbl for lbl in existing if lbl != label]
        r2 = httpx.put(get_url, headers=_jira_headers(),
                       json={"fields": {"labels": updated}}, timeout=30)
        if r2.status_code >= 400:
            logger.error("remove_jira_label PUT %s HTTP %s: %s",
                         ticket_key, r2.status_code, r2.text[:200])
            return False
        logger.info("Removed label '%s' from %s", label, ticket_key)
        return True
    except Exception as e:
        logger.error("remove_jira_label %s failed: %s", ticket_key, e)
        return False


# ─── Main Orchestrator ────────────────────────────────────────────────────────

def enrich_ticket(ticket_key: str, fields: dict,
                  historical: dict | None = None,
                  rag_info: dict | None = None,
                  kql_evidence: dict | None = None,
                  schema=None,
                  pattern: dict | None = None) -> dict:
    """Full enrichment pipeline for one Jira ticket.

    Reads typed Sentinel-style entity fields first (the canonical IOC source),
    then regexes summary + description as a belt-and-suspenders fallback for
    free-text mentions. Dedupes by value. Checks reputation across all
    configured sources, posts a comment with the findings, and reassigns the
    ticket based on verdict. Returns a summary dict for job status tracking.

    Phase 3 (2026-06-13): optional `historical` arg from
    tools.historical_alerts.query_similar_alerts(). When present and total>0,
    the comment renders a 'Similar Alerts (past 24h)' block between IOC
    reputations and the MITRE section.

    Phase 4 / 4b (2026-06-13 → 2026-06-15): optional `rag_info` arg built by
    routes/webhook.py from tools.rag_retrieval.retrieve_customer_context().
    Shape: {"pages_searched": int, "status": "matched"|"no_matches",
    "chunks": list[dict]}. Caller passes None to suppress the section.
    When present, renders a 'Customer Knowledge Base (Confluence)' block
    so analysts can see the AI consulted the customer's Confluence pages
    even when no relevant matches were found. Phase 4 deliberately does
    NOT pass rag_info into the LLM Triage call (mitigation against prior
    failure where bad retrievals confused the model).

    Alert Pattern Analysis (2026-07-08): optional `pattern` arg from
    tools.alert_pattern_analysis.analyze_alert_patterns(). When present,
    renders an 'Alert Pattern Analysis (30d)' block (frequency, verdict
    history, business-hours timing, entity correlation, tuning signal)
    directly after the 24h historical block.
    """
    from tools.secrets import get_secret
    from tools.jira_schema import detect_schema_mismatch

    sch = schema or default_schema()
    summary = fields.get("summary") or ""
    desc_text = _extract_adf_text(fields.get("description"))

    # Primary source: typed entity fields (canonical, populated by Sentinel)
    entity_iocs = extract_iocs_from_entity_fields(fields, sch)

    # Fallback source: regex over free text (catches analyst-pasted IOCs)
    regex_iocs = extract_iocs(f"{summary}\n{desc_text}")

    # Dedupe by value, prefer typed entries from entity fields
    seen_values: set[str] = {i["value"] for i in entity_iocs}
    iocs = list(entity_iocs)
    for i in regex_iocs:
        if i["value"] not in seen_values:
            seen_values.add(i["value"])
            iocs.append(i)

    logger.info(
        "enrich_ticket(%s): %d IOCs total (entity=%d, regex-fallback=%d)",
        ticket_key, len(iocs), len(entity_iocs), len(regex_iocs),
    )

    # Fail-LOUD: a public IP or file hash present in the ticket but 0 IOCs
    # extracted almost always means this customer's entity field mapping is
    # wrong. Surface it (log + health signal) instead of silently triaging blind.
    schema_warning = detect_schema_mismatch(fields, sch, iocs)
    if schema_warning:
        logger.warning("enrich_ticket(%s): SCHEMA MISMATCH — %s (suspect fields: %s)",
                       ticket_key, schema_warning["detail"], schema_warning.get("suspect_fields"))
        try:
            from tools.triage_health import record_schema_mismatch
            record_schema_mismatch(ticket_key.split("-")[0], schema_warning["detail"])
        except Exception:
            pass

    # Cap SOCRadar lookups per ticket (default 5). The API has a 100/day budget
    # and a 5-per-minute rate limit; calling it on every IOC of a 16-IOC ticket
    # would burn the daily quota fast and push webhook latency past 5 min.
    # Override via SOCRADAR_TRIAGE_BUDGET_PER_TICKET if you want different.
    socradar_budget = int(os.environ.get("SOCRADAR_TRIAGE_BUDGET_PER_TICKET", "5"))
    ioc_results = []
    socradar_used = 0
    for ioc in iocs:
        enabled = socradar_used < socradar_budget
        res = check_reputation(ioc, socradar_enabled=enabled)
        ioc_results.append(res)
        if res.get("socradar") is not None:
            socradar_used += 1
    if socradar_used >= socradar_budget and len(iocs) > socradar_budget:
        logger.info("enrich_ticket(%s): SOCRadar budget exhausted (%d/%d) — "
                    "remaining IOCs covered by VT + AbuseIPDB only",
                    ticket_key, socradar_used, len(iocs))
    overall_verdict = determine_verdict(ioc_results)

    # Phase 5e (2026-06-16) — literal-substring IOC lookup in the customer's
    # Confluence chunks. Hoisted here (Improvement #3, 2026-07-03) so it can DRIVE
    # the verdict, not just render in the comment. Killswitch-gated; [] on failure.
    whitelist_matches: list[dict] = []
    cid = ""
    try:
        from tools.whitelist_match import find_direct_matches
        from tools.customers import find_customer_by_jira_project
        project_key = ticket_key.split("-")[0] if ticket_key else ""
        cust = find_customer_by_jira_project(project_key) if project_key else None
        cid = (cust or {}).get("id", "")
        ioc_list = [r["ioc"] for r in ioc_results if isinstance(r, dict) and r.get("ioc")]
        whitelist_matches = find_direct_matches(customer_id=cid, iocs=ioc_list)
    except Exception:
        logger.exception("whitelist_match dispatch failed for %s", ticket_key)
        whitelist_matches = []

    # Improvement #3 (2026-07-03): a Confluence WHITELIST entry drives the verdict.
    # Benign-override only — an explicit, precision-guarded (whitelist_context)
    # whitelist entry forces Benign-Positive. Reputation WINS on conflict: a
    # vendor-malicious entity stays True-Positive; we surface the conflict instead.
    # Killswitch WHITELIST_VERDICT_OVERRIDE_ENABLED (default off); failure-isolated.
    whitelist_conflict: list[dict] = []
    whitelist_override_applied = False
    if os.environ.get("WHITELIST_VERDICT_OVERRIDE_ENABLED", "false").lower() == "true":
        try:
            overall_verdict, whitelist_override_applied, whitelist_conflict = \
                decide_whitelist_override(overall_verdict, ioc_results, whitelist_matches)
            if whitelist_override_applied:
                logger.info("enrich_ticket(%s): verdict overridden to benign — "
                            "entity whitelisted in customer Confluence", ticket_key)
            elif whitelist_conflict:
                logger.info("enrich_ticket(%s): whitelist/threat-intel conflict on %d entit(y/ies) "
                            "— kept True-Positive (reputation wins)", ticket_key, len(whitelist_conflict))
        except Exception:
            logger.exception("enrich_ticket(%s): whitelist verdict override failed — "
                             "keeping reputation verdict", ticket_key)

    # Phase 2 (2026-06-10): MITRE ATT&CK mapping — runs after full reputation
    # picture is available so SOCRadar categories can seed the LLM prompt.
    # Wrapped in try/except: any failure is logged and silently skipped.
    # TTP update (2026-07-10): gated on the malicious verdict — clean, unknown
    # (all engines unreachable) and whitelist-overridden benign tickets skip the
    # LLM call entirely. MITRE_MALICIOUS_ONLY=false restores run-on-everything.
    mitre_result = None
    _mitre_malicious_only = os.environ.get("MITRE_MALICIOUS_ONLY", "true").lower() != "false"
    if (os.environ.get("MITRE_MAPPING_ENABLED", "true").lower() != "false"
            and (overall_verdict == "malicious" or not _mitre_malicious_only)):
        try:
            from tools import mitre_mapper
            mitre_result = mitre_mapper.map_mitre(ticket_key, fields, ioc_results)
        except Exception as _e:
            logger.warning("enrich_ticket(%s): MITRE mapping failed (%s) — skipping",
                           ticket_key, _e)
    elif os.environ.get("MITRE_MAPPING_ENABLED", "true").lower() != "false":
        logger.info("enrich_ticket(%s): MITRE mapping skipped — verdict is %s, "
                    "not malicious (MITRE_MALICIOUS_ONLY)", ticket_key, overall_verdict)

    # Improvement #2 (2026-07-03): AI web-research insights for MALICIOUS IOCs.
    # For each IOC the vendors confirmed malicious, search the open web + have the
    # LLM write a short GROUNDED note, attached as ioc_result["insights"] and
    # rendered in an "Additional Insights" section. Killswitch IOC_INSIGHTS_ENABLED
    # (default off); capped per ticket; failure-isolated (never breaks the comment).
    if os.environ.get("IOC_INSIGHTS_ENABLED", "false").lower() == "true":
        try:
            from tools.ioc_insights import fetch_insights_for_malicious
            insights_map = fetch_insights_for_malicious(ioc_results)
            for r in ioc_results:
                val = (r.get("ioc") or {}).get("value")
                if r.get("verdict") == "malicious" and val in insights_map:
                    r["insights"] = insights_map[val]
        except Exception:
            logger.exception("enrich_ticket(%s): IOC insights synthesis failed — skipping",
                             ticket_key)

    # Improvement #4 (2026-07-06): AI command-line reputation check. The process /
    # PowerShell command line is NOT carried in the Jira ticket — it is fetched
    # from the customer's own Sentinel workspace (SecurityAlert.Entities), each
    # command line is researched on the open web, and the LLM judges whether it is
    # malicious or legitimately associated with known software. Rendered as a
    # "Command-Line Analysis" advisory section. ADVISORY ONLY — never changes the
    # verdict (honours the #3 / Phase-4 "advisory must not drive the verdict"
    # invariant). Killswitch CMDLINE_ANALYSIS_ENABLED (default off); the whole
    # block is failure-isolated so it can never break the comment.
    cmdline_analysis = None
    if os.environ.get("CMDLINE_ANALYSIS_ENABLED", "false").lower() == "true":
        try:
            from tools.cmdline_analysis import analyze_ticket_command_lines
            from tools.customers import find_customer_by_jira_project
            _pk = ticket_key.split("-")[0] if ticket_key else ""
            _cust = find_customer_by_jira_project(_pk) if _pk else None
            cmdline_analysis = analyze_ticket_command_lines(_cust, ticket_key, fields)
        except Exception:
            logger.exception("enrich_ticket(%s): command-line analysis failed — skipping",
                             ticket_key)

    # Improvement #5 (2026-07-06): decode SIEM/XDR codes (Windows Event IDs, Logon
    # Types, NTSTATUS logon sub-status, Kerberos failure codes) found in the ticket
    # text. Deterministic dictionary decode (offline) + optional LLM lookup for
    # unknown, marker-qualified codes. Precision-guarded (never decodes a bare
    # number). Rendered as a "Security Code Explanations" advisory section.
    # ADVISORY ONLY. Killswitch CODE_EXPLAIN_ENABLED (default off); failure-isolated.
    code_explain = None
    if os.environ.get("CODE_EXPLAIN_ENABLED", "false").lower() == "true":
        try:
            from tools.code_explain import explain_ticket_codes
            code_explain = explain_ticket_codes(fields)
        except Exception:
            logger.exception("enrich_ticket(%s): code explanation failed — skipping",
                             ticket_key)

    l1_id = get_secret("JIRA_L1_ACCOUNT_ID")
    l2_id = get_secret("JIRA_L2_ACCOUNT_ID")

    # Phase 1 (2026-06-08): verdict-to-label mapping is now explicit across all
    # three outcomes (True-Positive / Benign-Positive / Unknown). The "unknown"
    # case previously fell through to clean; it now gets its own label so an
    # analyst can distinguish "we checked and it's benign" from "we couldn't
    # tell" at a glance. Assignment routing (L1 for TP, L2 for FP and Unknown)
    # is unchanged — auto-close for FP is deferred to Phase 7.
    if overall_verdict == "malicious":
        add_jira_label(ticket_key, _TRIAGE_MALICIOUS_LABEL)
        action_taken = (f"Ticket flagged as a True Positive — labelled "
                        f"'{_TRIAGE_MALICIOUS_LABEL}'.")
        if l1_id:
            assign_jira_ticket(ticket_key, l1_id)
            action_taken += " Assigned to L1 Lead."
        else:
            action_taken += " (JIRA_L1_ACCOUNT_ID not configured — assignment skipped)"
            logger.warning("JIRA_L1_ACCOUNT_ID not set — cannot assign %s to L1 lead", ticket_key)
    elif overall_verdict == "unknown":
        add_jira_label(ticket_key, _TRIAGE_UNKNOWN_LABEL)
        action_taken = (f"Verdict Unknown — labelled '{_TRIAGE_UNKNOWN_LABEL}'. "
                        f"Routed to L2 SOC Analyst for manual review.")
        if l2_id:
            assign_jira_ticket(ticket_key, l2_id)
        else:
            action_taken += " (JIRA_L2_ACCOUNT_ID not configured — assignment skipped)"
            logger.warning("JIRA_L2_ACCOUNT_ID not set — cannot assign %s to L2", ticket_key)
    else:
        add_jira_label(ticket_key, _TRIAGE_CLEAN_LABEL)
        action_taken = (f"Ticket judged a Benign Positive — labelled "
                        f"'{_TRIAGE_CLEAN_LABEL}'. Routed to L2 SOC Analyst for sign-off.")
        if l2_id:
            assign_jira_ticket(ticket_key, l2_id)
        else:
            action_taken += " (JIRA_L2_ACCOUNT_ID not configured — assignment skipped)"
            logger.warning("JIRA_L2_ACCOUNT_ID not set — cannot assign %s to L2", ticket_key)

    # Improvement #3: make the whitelist-driven benign decision explicit to the analyst.
    if whitelist_override_applied:
        action_taken += (" Benign because the entity is whitelisted in the customer's "
                         "Confluence knowledge base.")

    # (whitelist_matches computed earlier — hoisted so it can drive the verdict.)

    # Phase 6 (2026-06-19) — synthesise a recommended next-action from ALL the
    # evidence assembled above and render it as a 'RECOMMENDED ACTION' line
    # inside the verdict box. Killswitch-gated (RECOMMENDATION_SYNTHESIS_ENABLED,
    # default OFF), failure-isolated (returns None on any error), and bounded by
    # RECOMMENDATION_TIMEOUT_S. Never short-circuits the rest of the comment.
    # Industry-aware context (2026-06-19): the customer's structured profile +
    # curated industry lens + asset-inventory match tailor the recommendation to
    # the customer's vertical and the asset at stake. Resolved here (failure-
    # isolated) so a lookup miss degrades to the prior generic recommendation
    # rather than dropping the line. Lens/profile are deterministic (no RAG
    # dependency); asset match is killswitch-gated substring lookup.
    customer_profile = None
    industry_lens = ""
    asset_matches: list[dict] = []
    try:
        from tools.customers import find_customer_by_jira_project
        from tools.industry_lens import get_industry_lens
        from tools.asset_inventory import find_asset_matches
        _pkey = ticket_key.split("-")[0] if ticket_key else ""
        _cust = find_customer_by_jira_project(_pkey) if _pkey else None
        if _cust:
            customer_profile = {
                "industry": _cust.get("industry") or "",
                "org_profile": _cust.get("org_profile") or "",
                "compliance_regime": _cust.get("compliance_regime") or [],
            }
            industry_lens = get_industry_lens(_cust.get("industry"))
            _ioc_list = [r["ioc"] for r in ioc_results if isinstance(r, dict) and r.get("ioc")]
            asset_matches = find_asset_matches(customer_id=_cust.get("id", ""), iocs=_ioc_list)
    except Exception:
        logger.exception("Industry-context resolution failed for %s", ticket_key)

    recommendation = None
    try:
        from tools.recommendation import synthesize_recommendation
        recommendation = synthesize_recommendation(
            ticket_summary=summary,
            ticket_description=desc_text,
            overall_verdict=overall_verdict,
            action_taken=action_taken,
            ioc_results=ioc_results,
            mitre_result=mitre_result,
            historical=historical,
            rag_info=rag_info,
            kql_evidence=kql_evidence,
            customer_profile=customer_profile,
            industry_lens=industry_lens,
            asset_matches=asset_matches,
        )
    except Exception:
        logger.exception("Recommendation synthesis dispatch failed for %s", ticket_key)
        recommendation = None

    # Phase 5c (2026-06-16) — try ADF first when killswitch ON; on any failure
    # (HTTP 400 from Jira on a malformed doc, network glitch, our renderer
    # throwing on unexpected input) fall back to the plain-text comment so an
    # analyst always sees the triage evidence.
    posted = False
    if os.environ.get("COMMENT_ADF_ENABLED", "false").lower() == "true":
        try:
            adf_doc = _build_comment_adf(ioc_results, overall_verdict, action_taken,
                                          mitre_result, historical, rag_info, kql_evidence,
                                          recommendation=recommendation,
                                          whitelist_matches=whitelist_matches,
                                          whitelist_conflict=whitelist_conflict,
                                          cmdline_analysis=cmdline_analysis,
                                          code_explain=code_explain,
                                          ticket_key=ticket_key,
                                          pattern=pattern)
            posted = post_jira_comment_adf(ticket_key, adf_doc)
        except Exception as e:
            logger.exception("ADF comment build/post failed for %s — falling back to plain text", ticket_key)

    if not posted:
        comment_text = _build_comment(ioc_results, overall_verdict, action_taken,
                                       mitre_result, historical, rag_info, kql_evidence,
                                       recommendation=recommendation,
                                       whitelist_matches=whitelist_matches,
                                       whitelist_conflict=whitelist_conflict,
                                       cmdline_analysis=cmdline_analysis,
                                       code_explain=code_explain,
                                       ticket_key=ticket_key,
                                       pattern=pattern)
        post_jira_comment(ticket_key, comment_text)

    return {
        "ticket": ticket_key,
        "iocs": ioc_results,
        "verdict": overall_verdict,
        "action": action_taken,
    }
