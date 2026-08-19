"""
Single owner for enrichment-comment verbosity, truncation caps, and assembly.

Before this module the COMMENT_VERBOSITY=compact killswitch (fd63aa4) was
implemented by having *every* section builder in tools/enrichment.py ask
"am I compact?" on its own and pick its own truncation limit inline. There was
no one place that owned the verbosity decision, the caps, or the final
join/assembly step.

CommentAssembler is that place. It:
  * resolves COMMENT_VERBOSITY ONCE per build (a live env read in __init__, so
    the test suite's importlib.reload semantics still pick up the mode), exposed
    as .compact;
  * owns the 6-value .caps bundle (compact + full snippet/rationale/socradar
    limits) that the section builders in enrichment.py thread through instead of
    re-deriving "_COMPACT_x if compact else <inline literal>" at each call site;
  * owns the section order and the final render step — join into a plain-text
    str, or wrap into an ADF {"type": "doc", ...} document, including the compact
    expander helper.

Deliberately does NOT import tools.enrichment: the 26 section builders and the
per-IOC row loop stay there (byte-identity guarantee), and enrichment.py imports
this module — keeping the dependency one-directional avoids an import cycle.
"""
import os


# ─── Truncation caps ──────────────────────────────────────────────────────────
# Compact caps existed before this refactor as module-level constants in
# enrichment.py; the "full" caps fold in literals that were previously inline at
# the builder call sites (e.g. the bare 240 / 200 / 3 in the "... else <n>"
# ternaries). Naming them here gives all six exactly one owner.
_COMPACT_SNIPPET_CHARS = 140      # Confluence chunk / whitelist snippet cap
_COMPACT_RATIONALE_CHARS = 120    # Sentinel per-query LLM rationale cap
_COMPACT_SOCRADAR_FINDINGS = 2    # top_findings shown, malicious IOCs only

_FULL_SNIPPET_CHARS = 240         # was inline at enrichment.py:765, 985, 1600
_FULL_RATIONALE_CHARS = 200       # was inline at enrichment.py:719, 1558
_FULL_SOCRADAR_FINDINGS = 3       # was inline at enrichment.py:1176, 1339


class Caps:
    """The 6 truncation limits, pre-selected for one verbosity mode.

    Builders read caps.snippet_chars / caps.rationale_chars / caps.socradar_findings
    directly instead of re-deriving "compact ? X : Y" per call site. The assembler
    hands each builder the bundle for the mode it resolved once.
    """

    __slots__ = ("snippet_chars", "rationale_chars", "socradar_findings")

    def __init__(self, snippet_chars: int, rationale_chars: int, socradar_findings: int):
        self.snippet_chars = snippet_chars
        self.rationale_chars = rationale_chars
        self.socradar_findings = socradar_findings


class CommentAssembler:
    """Owns verbosity resolution, the caps bundle, section order and assembly for
    one enrichment-comment build. Construct once per comment; feed it the section
    outputs; ask for the rendered str (plain text) or dict (ADF)."""

    def __init__(self):
        # Resolve verbosity ONCE, here, via a live env read — matching the old
        # _compact_comments() semantics so the test's importlib.reload(enrichment)
        # still flips the mode between renders.
        self.compact = (
            os.environ.get("COMMENT_VERBOSITY", "full").strip().lower() == "compact"
        )
        if self.compact:
            self.caps = Caps(
                snippet_chars=_COMPACT_SNIPPET_CHARS,
                rationale_chars=_COMPACT_RATIONALE_CHARS,
                socradar_findings=_COMPACT_SOCRADAR_FINDINGS,
            )
        else:
            self.caps = Caps(
                snippet_chars=_FULL_SNIPPET_CHARS,
                rationale_chars=_FULL_RATIONALE_CHARS,
                socradar_findings=_FULL_SOCRADAR_FINDINGS,
            )

    # ─── Plain-text assembly ──────────────────────────────────────────────────

    def render_plain(self, lines: list[str]) -> str:
        """Join the assembled plain-text lines into the final comment body."""
        return "\n".join(lines)

    # ─── ADF assembly ─────────────────────────────────────────────────────────

    def expand(self, title: str, *groups: list[dict]) -> list[dict]:
        """Compact-mode helper: wrap one or more section block-groups in a single
        collapsible ADF expand node. Returns [] when every group is empty so an
        empty expander is never emitted. Moved here from _build_comment_adf's
        inner _expand closure — the assembler owns expander construction.

        Safety-critical blocks (KNOWN ACTIVITY / verdict panel / WHITELIST
        CONFLICT) are assembled OUTSIDE this helper by the caller, in every mode.
        """
        from tools import adf

        inner = [b for g in groups for b in g]
        return [adf.expand(title, *inner)] if inner else []

    def render_adf(self, blocks: list[dict]) -> dict:
        """Wrap the assembled ADF section blocks into a top-level ADF document."""
        from tools import adf

        return adf.doc(*blocks)
