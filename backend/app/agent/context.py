"""Layer 1 — structured findings as direct agent context (no embeddings).

Every static-analysis source already emits the unified ``FindingOut`` shape
persisted to the ``findings`` table (androguard/semgrep/gitleaks for Android;
plist/lief/symbols/gitleaks/semgrep for iOS). This module is the Layer 1
normalizer for the agent:

1. derives each finding's **precision level** — ``file/line`` (semgrep,
   gitleaks, androguard manifest, Info.plist) vs ``binary-level presence only``
   (Mach-O protections/entitlements, import-table scanner);
2. filters to the scan platform's tool set (androguard is Android-only and
   must never appear in an iOS context);
3. renders the **full findings set** — no truncation, no subsetting — as a
   compact, precision-tagged context block.

This is a data lookup over the findings table, not retrieval: no embedding,
no vector store, no chunking.
"""
from __future__ import annotations

import dataclasses
import json

from sqlalchemy import select

from app.models import Finding, Scan

PRECISION_FILE_LINE = "file/line"
PRECISION_BINARY = "binary-level presence only, no specific location"

# Per-tool precision derivation (the single source of truth for Layer 1).
_TOOL_PRECISION: dict[str, str] = {
    "semgrep": PRECISION_FILE_LINE,
    "gitleaks": PRECISION_FILE_LINE,
    "androguard": PRECISION_FILE_LINE,
    "plist": PRECISION_FILE_LINE,
    "lief": PRECISION_BINARY,
    "symbols": PRECISION_BINARY,
}
_DEFAULT_PRECISION = PRECISION_BINARY

# Platform tool whitelists. androguard is Android/JVM-only and MUST NOT appear
# in the iOS path; semgrep is listed on iOS for completeness but is zero-yield
# by design (no decompiled source — the context notes this for the agent).
ANDROID_TOOLS = ("androguard", "semgrep", "gitleaks")
IOS_TOOLS = ("plist", "lief", "symbols", "gitleaks", "semgrep")
_PLATFORM_TOOLS: dict[str, frozenset[str]] = {
    "android": frozenset(ANDROID_TOOLS),
    "ios": frozenset(IOS_TOOLS),
}

_TOOL_LABELS: dict[str, str] = {
    "androguard": "manifest / signing (androguard)",
    "semgrep": "code patterns (semgrep)",
    "gitleaks": "secrets / strings (gitleaks)",
    "plist": "Info.plist (plist)",
    "lief": "Mach-O protections / entitlements (lief)",
    "symbols": "import-table scanner (symbols)",
}

IOS_SEMGREP_NOTE = (
    "semgrep: zero findings by design on iOS — the pipeline extracts binary "
    "structure via LIEF, not decompiled Swift/ObjC source, so semgrep has no "
    "parseable source to scan. Do not rely on it for iOS answers."
)

_DETAIL_MAX = 200
_FINDING_MAX_CHARS = 220


def derive_precision(tool: str) -> str:
    """Precision level for a finding's tool (Layer 1 requirement)."""
    return _TOOL_PRECISION.get(tool, _DEFAULT_PRECISION)


def platform_tools(platform: str | None) -> frozenset[str]:
    """The finding tools that belong to a platform's agent context."""
    return _PLATFORM_TOOLS.get(platform or "", frozenset())


@dataclasses.dataclass(frozen=True)
class FindingContextEntry:
    """One normalized finding as the agent sees it (all sources, one shape)."""

    id: int
    tool: str
    title: str
    severity: str
    category: str | None
    mastg_test_id: str | None
    file: str | None
    line: int | None
    precision: str
    detail: dict | None

    @property
    def location(self) -> str:
        if not self.file:
            return "(no file recorded)"
        return f"{self.file}:{self.line}" if self.line else self.file


@dataclasses.dataclass(frozen=True)
class FindingsContext:
    """The full Layer 1 context for one scan."""

    scan_id: int
    filename: str
    platform: str | None
    status: str
    entries: list[FindingContextEntry]
    rendered: str

    @property
    def count(self) -> int:
        return len(self.entries)


def _parse_detail(raw: str | None) -> dict | None:
    if not raw:
        return None
    try:
        value = json.loads(raw)
        return value if isinstance(value, dict) else {"raw": value}
    except json.JSONDecodeError:
        return {"raw": raw[:500]}


_KNOWN_FILES: dict[str, str] = {
    # Stages that emit manifest/plist findings without a per-finding file path:
    # the file is implied by the stage and is part of the precision contract
    # (file/line sources must name their file).
    "plist": "Info.plist",
    "androguard": "AndroidManifest.xml",
}


def _entry_from_finding(f: Finding) -> FindingContextEntry:
    return FindingContextEntry(
        id=f.id,
        tool=f.tool,
        title=f.title,
        severity=f.severity,
        category=f.category,
        mastg_test_id=f.mastg_test_id,
        file=f.file_path or _KNOWN_FILES.get(f.tool),
        line=f.line_number,
        precision=derive_precision(f.tool),
        detail=_parse_detail(f.detail),
    )


def build_findings_context(
    db,
    scan: Scan,
    *,
    max_findings: int | None = None,
) -> FindingsContext:
    """Assemble the full normalized findings context for a scan.

    ``max_findings`` is an explicit escape hatch for pathological findings
    counts — the default (None) is the full set, never a silent subset.
    """
    # Suppressed false positives are excluded from the agent context — they
    # were reviewed and dismissed, so grounding answers on them would be
    # misleading (owner decision, Aug 8).
    rows = db.scalars(
        select(Finding)
        .where(Finding.scan_id == scan.id, Finding.suppressed == False)  # noqa: E712
        .order_by(Finding.id)
    ).all()
    allowed = platform_tools(scan.platform)
    entries = [_entry_from_finding(f) for f in rows if f.tool in allowed]
    if max_findings is not None:
        entries = entries[:max_findings]
    return FindingsContext(
        scan_id=scan.id,
        filename=scan.filename,
        platform=scan.platform,
        status=scan.status,
        entries=entries,
        rendered=render_context(scan, entries),
    )


def render_context(scan: Scan, entries: list[FindingContextEntry]) -> str:
    """Compact precision-tagged rendering of the findings set for the agent."""
    lines: list[str] = []
    header = (
        f"FINDINGS CONTEXT — scan {scan.id} ({scan.filename}, platform "
        f"{scan.platform or 'unknown'}, status {scan.status}) — {len(entries)} "
        "findings across every static-analysis source. Full set, no truncation."
    )
    lines.append(header)
    lines.append("")
    lines.append("PRECISION LEGEND:")
    lines.append(
        f"  [{PRECISION_FILE_LINE}] — finding has a concrete source location "
        "(file, and line when shown)."
    )
    lines.append(
        f"  [{PRECISION_BINARY}] — the evidence exists somewhere in the app "
        "binary/bundle but has no specific source location (imports, "
        "entitlements, Mach-O flags). Never invent a file/line for these."
    )
    lines.append("")

    by_tool: dict[str, list[FindingContextEntry]] = {}
    for entry in entries:
        by_tool.setdefault(entry.tool, []).append(entry)

    for tool in _PLATFORM_TOOLS.get(scan.platform or "", ()):
        group = by_tool.get(tool, [])
        label = _TOOL_LABELS.get(tool, tool)
        lines.append(f"## {label} — {len(group)} finding(s)")
        for entry in group:
            lines.append(_render_entry(entry))
        lines.append("")

    if (scan.platform or "") == "ios" and not by_tool.get("semgrep"):
        lines.append(IOS_SEMGREP_NOTE)
        lines.append("")
    return "\n".join(lines)


def _render_entry(entry: FindingContextEntry) -> str:
    tag = f"[{entry.precision}]"
    sev = f"[{entry.severity}]"
    meta = entry.category or ""
    if entry.mastg_test_id:
        meta = f"{meta} (MASTG {entry.mastg_test_id})" if meta else f"MASTG {entry.mastg_test_id}"
    line = f"- {tag} {sev} {entry.title} — {entry.location}"
    if meta:
        line += f" — {meta}"
    if entry.detail:
        compact = json.dumps(entry.detail, separators=(",", ":"), default=str)
        if len(compact) > _DETAIL_MAX:
            compact = compact[:_DETAIL_MAX] + "…"
        line += f"\n    detail: {compact}"
    if len(line) > _FINDING_MAX_CHARS:
        line = line[:_FINDING_MAX_CHARS] + "…"
    return line
