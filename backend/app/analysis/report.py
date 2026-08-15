"""M9 report assembly - deterministic markdown from persisted scan data.

Phase A of M9 (docs/progress/M9.md): assemble the report body as structured
markdown from data the scan pipeline already produced. **No LLM call and no
new subprocess in this module** - the AI commentary surfaces are the EXISTING
cached rows (``scans.ai_summary`` / ``findings.explanation``, written by
``insights.py``); the Regenerate path (Phase B) and the export endpoints
(Phase C) live in the API layer. The assembly is a pure function of the
scan row + its non-suppressed findings + optional derived payloads
(dependencies inventory, builds/edits, web sources), so it is unit-testable
without a DB, network, or model.

Section contract (the report at a glance):
- Header: app filename, platform, scan date, security score + CVSS 4.0 band
  caption (the SecurityGauge contract), package/bundle id when derivable.
- Executive summary: cached ``scan.ai_summary``; a plain note when blank
  (the body never 400s on a missing model - decision 10).
- Severity breakdown: counts + risk line - ``risk.py`` is the source of
  truth, nothing re-derived here. When suppression excluded findings, a
  one-line ``Suppressed findings: n excluded`` footnote renders (open
  item 2 - "one line, no detail").
- Findings: full non-suppressed set, grouped by severity (high -> warning ->
  info), each with title, category/MASVS control, MASTG test tag,
  file/line, tool, and an explanation - the cached AI one when a model
  generated it, otherwise a DETERMINISTIC fallback from the persisted data
  + vendored MASTG mapping (the report is a complete deliverable with no
  model configured - the MobSF pattern: template-rendered findings, no
  LLM). EVERY non-suppressed finding is listed individually - findings
  inside bundled third-party libraries included (Aug 14 owner follow-up:
  the export must show every finding, never a per-library tally).
- Recommended priorities: a deterministic (no-LLM) top-N of the findings
  by severity + a static-only scope note - the "what to fix first" a
  client reads before the detail (manual-review follow-up).
- iOS binary profile: the linked-dylib list is the single authoritative
  dylib rendering; the Dependencies section points to it instead of
  re-listing every dylib (manual-review follow-up de-dupe).
- Platform sections: Android notes the jadx Java/smali edit surface; iOS
  renders the binary profile (Mach-O protections, entitlements, exported
  symbols, linked dylibs) from the persisted LIEF/symbols findings - the
  same evidence the ``analysis/`` synthetic root shows.
- Dependencies: the ``dependencies.py`` inventory payload (Android package
  groups / native libs / runtime markers; iOS dylibs / frameworks).
- External references: web-research source URLs (decision 3; the capture
  itself is open item 1 - the route supplies whatever is persisted).

The caller (the report route) owns the DB reads: it filters
``Finding.suppressed == False`` (the risk/summary/agent convention) and
passes the derived payloads. Best-effort throughout: a missing payload or a
blank summary degrades to an inline note, never a crash.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path

from app.analysis import mastg
from app.analysis.auto_explain import auto_explanation
from app.analysis.risk import SEVERITY_ORDER, security_from_risk
from app.config import settings

# Risk-index band of a RISK score (0-100) - must match the SecurityGauge
# exactly so the report header and the dashboard never disagree. The
# banded model (Aug 15, 2026) only ever produces 0, 40-69 or 70-99 - so
# the bands are high 70-99 · medium 40-69 · none 0 (the old 1-39 low band
# is unreachable and gone).
_BAND_RISK = {
    "high": (70, 99),
    "medium": (40, 69),
}
_BAND_LABEL = {
    "high": "High",
    "medium": "Medium",
    "none": "None",
}


def risk_band(risk_score: int | None) -> str:
    """Risk-index band name for a risk score (None -> 'none')."""
    if risk_score is None:
        return "none"
    for band, (lo, hi) in _BAND_RISK.items():
        if lo <= risk_score <= hi:
            return band
    return "none" if risk_score == 0 else "high"


def security_label(risk_score: int | None) -> str:
    """The gauge's human label for a security score (higher = better)."""
    band = risk_band(risk_score)
    if band == "high":
        return "Low security"
    if band == "medium":
        return "Medium security"
    return "Excellent security"


def _fmt_dt(value: datetime | None) -> str:
    if value is None:
        return "unknown"
    return value.strftime("%Y-%m-%d %H:%M UTC")


def _mastg_tag(finding) -> str | None:
    """The finding's MASTG test tag - ONLY when the test is current.

    The v1-era ids (``MASTG-TEST-0001..0093``) are deprecated in MASTG v2
    (Aug 12 owner follow-up: the report cited MASTG-TEST-0007, which is
    retired). Persisted rows may still carry an old id - skip those tags so
    the report never cites a deprecated standard as current; the MASVS
    control tag renders regardless.
    """
    test_id = getattr(finding, "mastg_test_id", None)
    if not test_id:
        return None
    info = mastg.mastg_test(test_id)
    if info is not None and info.get("status") == "deprecated":
        return None
    return test_id


def _finding_lines(finding) -> list[str]:
    """The finding's core lines: title, location, tags, explanation."""
    sev = finding.severity or "info"
    lines = [f"- **[{sev.upper()}] {finding.title}**"]
    loc = []
    if getattr(finding, "file_path", None):
        loc_text = finding.file_path
        if getattr(finding, "line_number", None):
            loc_text += f":{finding.line_number}"
        loc.append(f"`{loc_text}`")
    tags = []
    if getattr(finding, "category", None):
        tags.append(finding.category)
    mastg_tag = _mastg_tag(finding)
    if mastg_tag:
        tags.append(mastg_tag)
    if getattr(finding, "tool", None):
        tags.append(f"tool: {finding.tool}")
    if loc or tags:
        lines.append("  " + " · ".join(loc + tags))
    explanation = getattr(finding, "explanation", None)
    if explanation:
        lines.append("")
        lines.append("  > " + explanation.strip().replace("\n", "\n  > "))
    else:
        # No-AI path (Aug 13 follow-up): every finding carries a DETERMINISTIC
        # explanation - severity/tool/location + the MASVS/MASTG mapping from
        # persisted data - so the report is complete with no model configured
        # (the MobSF model: template-rendered findings, no LLM). The cached AI
        # explanation replaces this paragraph when a model has generated one.
        lines.append("")
        lines.append(
            "  > " + auto_explanation(finding).strip().replace("\n", "\n  > ")
        )
    return lines


def _auto_summary(scan, findings, platform: str) -> str:
    """Deterministic executive summary for the no-AI path (owner follow-up,
    Aug 12: the report must NOT DEPEND on AI - a user may or may not run a
    chat model, and the PDF/markdown export must read as a complete
    deliverable either way).

    Built only from persisted data: severity counts, the distinct MASVS
    controls touched, and the artifact identity. The cached AI narrative
    replaces this paragraph when a model has generated one; this fallback
    is a plain factual roll-up, never an apology or a "configure a model"
    note.
    """
    counts = _severity_counts(findings)
    total = sum(counts.values())
    bands = ", ".join(f"{n} {sev}" for sev, n in counts.items() if n)
    controls = sorted({f.category for f in findings if f.category})
    text = (
        f"This automated static assessment of **{scan.filename}** "
        f"({platform}) "
    )
    if total:
        text += f"found **{total} finding{'s' if total != 1 else ''}**"
        if bands:
            text += f" ({bands})"
        if controls:
            text += (
                f", touching **{len(controls)} MASVS control"
                f"{'s' if len(controls) != 1 else ''}**"
                f" ({', '.join(controls)})"
            )
        text += "."
    else:
        text += "found **no findings** - none of the static checks flagged an issue."
    return text


def _severity_counts(findings) -> dict[str, int]:
    """Counts per known severity band; anything outside the vocabulary lands
    in an ``other`` bucket so it can never silently vanish from the report
    (risk.py ignores unknown severities for scoring, but the findings tab
    still returns them - a human-readable report must not lose them)."""
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    counts["other"] = 0
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
        else:
            counts["other"] += 1
    return counts


def _ios_binary_profile(findings) -> dict:
    """Extract the binary-profile facts from the persisted LIEF/symbols
    findings - the same evidence the ``analysis/`` synthetic root renders.
    Best-effort: any missing slice just omits its section line. ``has_evidence``
    is False when the scan produced NO binary-level findings at all (the
    caller renders the fallback note then, never the "not flagged" defaults)."""
    lief = [f for f in findings if getattr(f, "tool", None) == "lief"]
    symbols = [f for f in findings if getattr(f, "tool", None) == "symbols"]

    def _detail(finding) -> dict:
        d = getattr(finding, "detail", None)
        if isinstance(d, str) and d:
            try:
                parsed = json.loads(d)
                return parsed if isinstance(parsed, dict) else {}
            except ValueError:
                return {}
        return d if isinstance(d, dict) else {}

    def _find(prefix: str):
        return next((f for f in lief if (f.title or "").startswith(prefix)), None)

    profile: dict = {"has_evidence": bool(lief or symbols)}
    slices = _find("Binary slices")
    if slices:
        profile["architectures"] = _detail(slices).get("architectures") or []
    # Protections render as an explicit list ONLY when a protection finding
    # exists (tree.py's honesty: an absent finding is "not flagged", never
    # a claim the stage ran).
    pie = _find("Position-independent executable (PIE) disabled")
    canary = _find("Stack canary missing")
    arc = _find("ARC enabled")
    fairplay = _find("FairPlay-encrypted")
    if pie or canary or arc or fairplay:
        profile["protections"] = [
            f"PIE {'disabled' if pie else 'not flagged'}",
            f"stack canary {'missing' if canary else 'not flagged'}",
            f"ARC {'enabled' if arc else 'not detected'}",
            f"FairPlay {'encrypted' if fairplay else 'not flagged'}",
        ]
    dylibs = _find("Linked dylibs")
    if dylibs:
        profile["dylibs"] = _detail(dylibs).get("dylibs") or []
    ents = _find("Entitlements granted")
    if ents:
        profile["entitlements"] = _detail(ents).get("entitlements") or {}
    exp = _find("Exported symbols")
    if exp:
        detail = _detail(exp)
        profile["exported_count"] = detail.get("count") or 0
        profile["exported_sample"] = detail.get("sample") or []
    profile["insecure_imports"] = [
        {"severity": f.severity, "title": f.title, "detail": _detail(f)}
        for f in symbols
    ]
    return profile


def _top_priorities(findings, limit: int = 10) -> list:
    """Deterministic top-priority findings - the app-owned set ordered by
    severity (high first), then file path, then line. Info rows are never
    "priorities" (a pentester wouldn't recommend fixing an info note
    first) - the detail section still lists them. Never an LLM call
    (decision 10): a plain ranking of the highest-risk app-owned rows, not
    a narrative."""

    def _rank(f):
        sev = f.severity if f.severity in SEVERITY_ORDER else ""
        idx = SEVERITY_ORDER.index(sev) if sev else len(SEVERITY_ORDER)
        return (idx, (f.file_path or "").lower(), f.line_number or 0)

    ranked = sorted(
        (f for f in findings if (f.severity or "") in ("high", "warning")),
        key=_rank,
    )
    return ranked[:limit]


def assemble_report(
    scan,
    findings,
    *,
    dependencies: dict | None = None,
    web_sources: list[str] | None = None,
    suppressed_count: int = 0,
) -> str:
    """Assemble the full markdown report body for one scan.

    ``findings`` must already be the scan's NON-suppressed rows (the caller
    filters - the risk/summary convention). ``dependencies`` is the
    ``dependencies.py`` inventory payload (or None to omit the section);
    ``web_sources`` the cited external URLs; ``suppressed_count`` the number
    of findings excluded by suppression (open item 2: a suppressed-only
    scan would otherwise read as "zero findings" with no explanation - one
    line, no detail). Pure: no I/O, no LLM, no exceptions for missing data.
    """
    # Defensive: the caller filters, but a stray suppressed row must never
    # leak into the report (the risk/summary/agent convention - same
    # getattr guard as ``compute_risk_score``).
    findings = [f for f in findings if not getattr(f, "suppressed", False)]

    platform = scan.platform or "unknown"

    # Aug 14 owner follow-up: EVERY non-suppressed finding is listed in full
    # below - findings inside bundled third-party libraries included. The
    # old vendored per-library tally was removed ("the report should show
    # every finding, not just 'warning x count'").
    ios_profile = _ios_binary_profile(findings) if platform == "ios" else None

    risk = scan.risk_score
    security = security_from_risk(risk)
    band = risk_band(risk)
    lines: list[str] = []

    # ---- Header ----------------------------------------------------------
    lines.append("# MASA security report")
    lines.append("")
    lines.append(f"- **App:** {scan.filename} ({platform})")
    lines.append(f"- **Analyzed:** {_fmt_dt(getattr(scan, 'created_at', None))}")
    if risk is not None:
        lines.append(
            f"- **Security score:** {security}/100 - {security_label(risk)} "
            f"(risk {risk}/100 · {_BAND_LABEL[band]})"
        )
    else:
        lines.append("- **Security score:** not yet scored")
    if dependencies:
        app_meta = dependencies.get("app") or {}
        if platform == "android" and app_meta.get("package"):
            lines.append(f"- **Package:** {app_meta['package']}")
        if platform == "ios" and app_meta.get("bundle_id"):
            lines.append(f"- **Bundle id:** {app_meta['bundle_id']}")
    # Standards provenance (Aug 12 follow-up): the report runs on MASVS v2
    # controls + MASTG v2 tests, vendored at a pinned upstream ref - stale
    # and deprecated data is auditable (and deprecated v1 ids are never
    # cited as current).
    _meta = mastg.source_metadata()
    if _meta.get("source_ref") or _meta.get("source_date"):
        lines.append(
            f"- **Standards:** MASVS v2 controls · OWASP MASTG v2 tests "
            f"(vendored from OWASP/owasp-mastg @ "
            f"{(_meta.get('source_ref') or '')[:10]}, "
            f"{_meta.get('source_date') or 'unknown date'}; deprecated v1 "
            f"test ids are not cited)"
        )
    lines.append("")

    # ---- Executive summary ----------------------------------------------
    lines.append("## Executive summary")
    lines.append("")
    summary = getattr(scan, "ai_summary", None)
    if summary:
        lines.append(summary.strip())
    else:
        # No-AI path (Aug 12 follow-up): a deterministic roll-up, not a
        # "No AI summary yet" placeholder - the export is a complete,
        # self-sufficient deliverable with or without a chat model.
        lines.append(_auto_summary(scan, findings, platform))
    lines.append("")

    # ---- Severity breakdown ---------------------------------------------
    lines.append("## Severity breakdown")
    lines.append("")
    counts = _severity_counts(findings)
    for sev in SEVERITY_ORDER:
        lines.append(f"- **{sev}:** {counts[sev]}")
    if counts.get("other"):
        lines.append(f"- **other:** {counts['other']}")
    # Open item 2 footnote - only when something was actually excluded, so
    # the breakdown of an unsuppressed scan stays clean. "One line, no
    # detail": the count, never the rows (suppressed rows are still
    # reviewable in the app's Findings tab).
    if suppressed_count > 0:
        lines.append(
            f"- **Suppressed findings:** {suppressed_count} "
            f"excluded (not scored, not listed below)"
        )
    if risk is not None:
        lines.append(
            f"- **Risk score:** {risk}/100 · "
            f"**Security score:** {security}/100"
        )
    lines.append("")

    # ---- Recommended priorities (deterministic - no LLM) -----------------
    # Manual-review follow-up: a client reads "what to fix first" before the
    # detail - the findings ranked by severity, highest first (info rows are
    # never priorities; the Findings section lists them all). Never an LLM
    # call (decision 10): the AI surfaces stay the summary + explanations.
    priorities = _top_priorities(findings)
    if priorities:
        lines.append("## Recommended priorities")
        lines.append("")
        lines.append(
            "Findings ranked by what to fix first - highest severity "
            "first. Every finding (all severities) is listed in full in "
            "the Findings section below."
        )
        lines.append("")
        for i, f in enumerate(priorities, 1):
            loc = ""
            if getattr(f, "file_path", None):
                loc = f.file_path
                if getattr(f, "line_number", None):
                    loc += f":{f.line_number}"
            # Same _mastg_tag rule as the findings listing: a deprecated v1
            # id is never cited as current in the human-readable body.
            mastg_tag = _mastg_tag(f)
            tag = f" ({mastg_tag})" if mastg_tag else ""
            lines.append(
                f"{i}. **[{f.severity.upper()}] {f.title}**"
                + (f" - `{loc}`" if loc else "")
                + tag
            )
        lines.append("")
        lines.append(
            "_Scope: automated static analysis of the uploaded artifact "
            "(manifest, decompiled code, secrets scan, dependency "
            "inventory"
            + (", binary profile" if platform == "ios" else "")
            + "). No dynamic, device, or emulator testing was performed; "
            "findings reflect code and binary structure, not runtime "
            "behavior. Severity bands follow the banded risk index "
            "(high/warning/info; not CVSS - a static scanner cannot "
            "honestly assess CVSS attack requirements or user interaction)._"
        )
        lines.append("")

    # ---- Findings, grouped by severity ----------------------------------
    lines.append("## Findings")
    lines.append("")
    if not findings:
        lines.append("_No findings for this scan._")
    else:
        grouped = {
            sev: [f for f in findings if f.severity == sev]
            for sev in SEVERITY_ORDER
        }
        others = [f for f in findings if f.severity not in grouped]
        for sev in SEVERITY_ORDER:
            group = grouped[sev]
            if not group:
                continue
            lines.append(f"### {sev.capitalize()} ({len(group)})")
            lines.append("")
            for f in group:
                lines.extend(_finding_lines(f))
                lines.append("")
        if others:
            lines.append(f"### Other ({len(others)})")
            lines.append("")
            for f in others:
                lines.extend(_finding_lines(f))
                lines.append("")

    # ---- Platform sections ----------------------------------------------
    if platform == "android":
        lines.append("## Android surface")
        lines.append("")
        lines.append(
            "Findings reference the jadx Java/Kotlin tree (``sources/...``). "
            "After the on-demand apktool decode, the same files are editable "
            "as smali under ``smali{,classesN}/``, ``res/``, and the decoded "
            "AndroidManifest.xml - see the Decompiler tab."
        )
        lines.append("")
    elif platform == "ios":
        profile = ios_profile
        lines.append("## iOS binary profile")
        lines.append("")
        if not profile.get("has_evidence"):
            lines.append("_No binary-profile findings recorded for this scan._")
        else:
            if profile.get("architectures"):
                lines.append(
                    "- **Architectures:** " + ", ".join(profile["architectures"])
                )
            if profile.get("protections"):
                lines.append("- **Protections:** " + " · ".join(profile["protections"]))
            if profile.get("dylibs"):
                # The profile is the report's authoritative dylib list (the
                # Dependencies section de-dupes to a pointer line) - cap high
                # enough to carry a real binary's full set (iBugBazaar: 35),
                # still bounded so a pathological 200-dylib build stays
                # readable with the truncation note.
                lines.append(
                    "- **Linked dylibs:** "
                    + ", ".join(str(d) for d in profile["dylibs"][:60])
                    + (" (truncated)" if len(profile["dylibs"]) > 60 else "")
                )
            if profile.get("entitlements"):
                lines.append(
                    "- **Entitlements:** "
                    + ", ".join(sorted(str(k) for k in profile["entitlements"])[:20])
                )
            if profile.get("exported_count"):
                lines.append(
                    f"- **Exported symbols:** {profile['exported_count']} "
                    f"(sample: {', '.join(str(s) for s in profile['exported_sample'][:10])})"
                )
            for imp in profile.get("insecure_imports", []):
                lines.append(
                    f"- **Import-table finding [{imp['severity'].upper()}]: "
                    f"{imp['title']}** - {imp['detail'].get('symbol')}"
                )
        lines.append("")

    # ---- Dependencies ----------------------------------------------------
    if dependencies and dependencies.get("dependencies"):
        lines.append("## Dependencies")
        lines.append("")
        deps_items = dependencies["dependencies"]
        # iOS de-dupe (manual-review follow-up): the linked dylibs already
        # render in the iOS binary profile above - a pointer line instead of
        # re-listing every dylib (a 35-row repeat is not something a
        # pentester would ship). Embedded frameworks still render.
        if platform == "ios" and ios_profile and ios_profile.get("dylibs"):
            dylib_items = [d for d in deps_items if d.get("kind") == "dylib"]
            deps_items = [d for d in deps_items if d.get("kind") != "dylib"]
            if dylib_items:
                lines.append(
                    f"- **Linked dylibs ({len(dylib_items)}):** listed in the "
                    "iOS binary profile above"
                )
        for dep in deps_items:
            name = dep.get("name") or dep.get("label") or "?"
            kind = dep.get("kind", "package")
            evidence = dep.get("evidence")
            line = f"- **{name}** ({kind})"
            if dep.get("finding_count"):
                line += (
                    f" - {dep['finding_count']} finding"
                    f"{'s' if dep['finding_count'] != 1 else ''} "
                    f"({dep.get('high_count', 0)} high)"
                )
            if evidence:
                line += f" - {evidence}"
            lines.append(line)
        if dependencies.get("runtime_markers"):
            lines.append(
                "- **Runtime:** " + ", ".join(dependencies["runtime_markers"])
            )
        lines.append("")

    # ---- External references (M7 web research) ---------------------------
    if web_sources:
        lines.append("## External references")
        lines.append("")
        lines.append(
            "Sources cited from agent web research (M7) - distinct from "
            "local-code-derived findings above."
        )
        lines.append("")
        for url in web_sources:
            lines.append(f"- {url}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


# ---- Assembled-body cache (decision 7: cache-first, recompute on change) ----
# The body is a pure function of persisted scan data, but it is cached per
# scan (``report_cache.json`` beside the scan's trees - the
# dependencies_cache.json pattern) so repeated Report-tab opens / exports
# skip re-assembly. The stored identity covers EVERY input that can change
# post-analysis - findings (suppress/restore + regenerate explanations),
# ``scan.ai_summary`` (regenerate), ``scan.risk_score`` (suppress), and the
# web-source ledger (a new capture) - so any of those recomputes lazily
# instead of serving a stale body. The dependencies payload is deterministic
# from (scan, findings) for a given scan (trees are immutable per scan), but
# its hash rides along anyway so a payload drift can never be served stale.
# v2 (manual-review follow-up): vendored roll-up + Recommended priorities +
# iOS dylib de-dupe changed the body shape - stale v1 cache files rebuild.
# v3 (Aug 13 follow-up): the no-AI deterministic per-finding explanation
# changed the body shape again - stale v2 cache files rebuild.
# v4 (Aug 14 follow-up): every finding listed in full (vendored roll-up
# removed) + the Resigned test builds section dropped - stale v3 rebuild.
# v5 (Aug 15): the header + scope lines dropped the 'CVSS 4.0' caption
# (banded risk index is not CVSS) - stale v4 rebuild.
_REPORT_CACHE_VERSION = 5
_REPORT_CACHE: dict[str, tuple[str, str]] = {}  # path -> (identity, body)
_REPORT_CACHE_MAX = 16


def report_cache_path(scan_id: int) -> Path:
    """The per-scan cache file (sibling of ``web_sources.json``)."""
    return settings.data_dir / "work" / str(scan_id) / "report_cache.json"


def _findings_fingerprint(findings) -> str:
    """Rich fingerprint: every finding field the body renders (unlike the
    dependencies fingerprint, which only needs tool+severity - the report
    also prints titles, tags, locations, and the cached explanation)."""
    h = hashlib.sha256()
    for f in sorted(findings, key=lambda x: x.id):
        h.update(
            "|".join(
                [
                    str(f.id),
                    getattr(f, "severity", None) or "",
                    getattr(f, "title", None) or "",
                    getattr(f, "category", None) or "",
                    getattr(f, "mastg_test_id", None) or "",
                    getattr(f, "file_path", None) or "",
                    str(getattr(f, "line_number", None) or ""),
                    getattr(f, "tool", None) or "",
                    getattr(f, "explanation", None) or "",
                ]
            ).encode()
        )
    return h.hexdigest()


# Bump when the BODY ASSEMBLY changes (not the inputs): the identity below
# covers the inputs, but a report-code change (e.g. the Aug 12 MASTG v2
# deprecated-id citation fix, the Aug 13 no-AI explanation fallback, the
# Aug 14 removal of the vendored roll-up + Resigned test builds section)
# must invalidate every persisted body too - same precedent as smali_map's
# _MAPPING_CACHE_VERSION.


def _cache_identity(
    scan,
    findings,
    *,
    dependencies: dict | None,
    web_sources: list[str] | None,
    suppressed_count: int = 0,
) -> str:
    """Identity of every body input - cheap strings + hashes only."""
    parts = [
        f"v{_REPORT_CACHE_VERSION}",
        scan.platform or "unknown",
        getattr(scan, "filename", None) or "",
        str(getattr(scan, "risk_score", None) or ""),
        getattr(scan, "ai_summary", None) or "",
        str(getattr(scan, "created_at", None) or ""),
        _findings_fingerprint(findings),
        "\n".join(web_sources or []),
        hashlib.sha256(
            json.dumps(dependencies or {}, sort_keys=True).encode()
        ).hexdigest(),
        str(suppressed_count or 0),
    ]
    return "\x1f".join(parts)


def _remember_cache(key: str, identity: str, body: str) -> None:
    _REPORT_CACHE[key] = (identity, body)
    while len(_REPORT_CACHE) > _REPORT_CACHE_MAX:
        _REPORT_CACHE.pop(next(iter(_REPORT_CACHE)))  # oldest-inserted first


def cached_body(
    scan,
    findings,
    *,
    dependencies: dict | None = None,
    web_sources: list[str] | None = None,
    suppressed_count: int = 0,
) -> str | None:
    """The cached assembled body, or None on a miss / identity change.

    Same contract as ``dependencies.cached_inventory``: a stale/torn file
    (shape change, partial write, or any input change since the cache was
    written) is a miss - the caller reassembles and stores."""
    identity = _cache_identity(
        scan,
        findings,
        dependencies=dependencies,
        web_sources=web_sources,
        suppressed_count=suppressed_count,
    )
    key = str(report_cache_path(scan.id))
    cached = _REPORT_CACHE.get(key)
    if cached is not None and cached[0] == identity:
        return cached[1]
    cache_path = Path(key)
    if cache_path.is_file():
        try:
            data = json.loads(cache_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = None
        if (
            data is not None
            and data.get("version") == _REPORT_CACHE_VERSION
            and data.get("identity") == identity
            and isinstance(data.get("body"), str)
        ):
            _remember_cache(key, identity, data["body"])
            return data["body"]
    return None


def store_body(
    scan,
    body: str,
    *,
    findings,
    dependencies: dict | None = None,
    web_sources: list[str] | None = None,
    suppressed_count: int = 0,
) -> None:
    """Persist an assembled body - in-memory + the on-disk cache file.

    Best-effort (a read-only FS still serves this process via the module
    cache); atomic tmp+rename so a torn write never becomes the cache."""
    identity = _cache_identity(
        scan,
        findings,
        dependencies=dependencies,
        web_sources=web_sources,
        suppressed_count=suppressed_count,
    )
    key = str(report_cache_path(scan.id))
    _remember_cache(key, identity, body)
    cache_path = Path(key)
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = cache_path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(
                {"version": _REPORT_CACHE_VERSION, "identity": identity, "body": body},
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        tmp.replace(cache_path)
    except OSError:
        pass  # best-effort cache
