"""M5 LLM insights: per-finding explanations + overview summaries.

Both surfaces are grounded in the scan's real data, cached on-row
(``findings.explanation`` / ``scans.ai_summary``), and resolve the chat
model exactly like the M4 agent (``app.model.selection.pick_chat_backend``)
so one model configured in Settings powers chat, explain, and summary alike.

Failure contract for the API layer:
- ``NoModelConfigured`` -> HTTP 400 (no chat model in Settings)
- :class:`InsightError` -> HTTP 502 (the upstream LLM call itself failed -
  the request was fine, the upstream wasn't)

The functions mutate ``finding.explanation`` / ``scan.ai_summary`` in place;
the caller (the route) owns the session and commits.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime

from app.agent.tools import read_file
from app.analysis.risk import SEVERITY_CVSS
from app.model.client import chat as client_chat
from app.model.client import model_arch_hint
from app.model.selection import pick_chat_backend

MAX_EXPLAIN_TOKENS = 700
MAX_SUMMARY_TOKENS = 800
SUMMARY_TOP_FINDINGS = 8
SOURCE_CONTEXT_RADIUS = 6
_SOURCE_CONTEXT_CHARS = 4000
_DETAIL_CHARS = 1500

_EXPLAIN_SYSTEM = (
    "You are MASA, a mobile application security assistant. Explain ONE "
    "static-analysis finding in plain language for a mobile pentester: what "
    "it means, why it is a risk in this app, and a concrete fix. Answer in "
    "3-6 sentences. Ground every claim in the finding data and source "
    "context below - never invent files, lines, or mitigations."
)

_SUMMARY_SYSTEM = (
    "You are MASA, a mobile application security assistant. Write a concise "
    "executive summary of this static-analysis scan (3-5 sentences): the "
    "overall security posture, the most important findings and why they "
    "matter, and the top priorities to fix. Ground every claim in the JSON "
    "data below; never invent findings that are not listed."
)


class InsightError(RuntimeError):
    """The upstream LLM call for an insight failed."""


def _now() -> datetime:
    return datetime.now(UTC)


def _finding_grounding(finding) -> str:
    parts = [f"Finding: {finding.title}", f"Severity: {finding.severity}"]
    if finding.file_path:
        parts.append(f"File: {finding.file_path}")
    if finding.line_number:
        parts.append(f"Line: {finding.line_number}")
    if finding.category:
        parts.append(f"MASVS control: {finding.category}")
    if finding.mastg_test_id:
        parts.append(f"MASTG test: {finding.mastg_test_id}")
    if finding.tool:
        parts.append(f"Produced by: {finding.tool}")
    if finding.detail:
        try:
            detail = (
                json.loads(finding.detail)
                if isinstance(finding.detail, str)
                else finding.detail
            )
        except json.JSONDecodeError:
            detail = finding.detail
        parts.append(f"Tool detail: {json.dumps(detail, default=str)[:_DETAIL_CHARS]}")
    return "\n".join(parts)


def _source_context(scan_id: int, finding) -> str:
    """Best-effort surrounding source lines; empty when not locatable.

    ``finding.file_path`` is relative to the platform tree root for code
    findings; manifest-path findings (AndroidManifest.xml lives under the
    ``resources`` root) may not resolve - that is fine, the caller's prompt
    simply omits context for them.
    """
    if not finding.file_path or not finding.line_number:
        return ""
    start = max(1, finding.line_number - SOURCE_CONTEXT_RADIUS)
    end = finding.line_number + SOURCE_CONTEXT_RADIUS
    try:
        text = read_file(
            scan_id, finding.file_path, line_start=start, line_end=end
        )
    except Exception:
        return ""
    if not text.strip():
        return ""
    return (
        f"Source context ({finding.file_path}:{start}-{end}):\n"
        f"{text[:_SOURCE_CONTEXT_CHARS]}"
    )


def _chat_text(backend, messages: list[dict], max_tokens: int) -> str:
    try:
        response = client_chat(
            backend, messages, max_tokens=max_tokens,
            temperature=0.2, timeout=60.0,
        )
    except Exception as exc:  # noqa: BLE001 - surface any upstream failure
        raise InsightError(model_arch_hint(f"LLM call failed: {exc}")) from exc
    text = (response.choices[0].message.content or "").strip()
    if not text:
        raise InsightError("LLM call returned an empty response")
    return text


def explain_finding(scan_id: int, finding, *, regenerate: bool = False) -> dict:
    """Plain-language explanation of one finding (cached on ``finding``).

    Returns ``{explanation, cached, model, generated_at}``. Mutates
    ``finding.explanation`` on a fresh generation; the route commits.
    A cached explanation is returned without any LLM call unless
    ``regenerate`` is set - the UI's Regenerate button is the explicit opt-in
    that spends cost; the default path is always cache-first.
    """
    if finding.explanation and not regenerate:
        return {
            "explanation": finding.explanation,
            "cached": True,
            "model": None,
            "generated_at": None,
        }
    backend = pick_chat_backend()
    user = (
        _finding_grounding(finding)
        + "\n\n"
        + _source_context(scan_id, finding)
        + "\n\nExplain this finding."
    )
    text = _chat_text(
        backend,
        [{"role": "system", "content": _EXPLAIN_SYSTEM},
         {"role": "user", "content": user}],
        max_tokens=MAX_EXPLAIN_TOKENS,
    )
    finding.explanation = text
    return {
        "explanation": text,
        "cached": False,
        "model": backend.model,
        "generated_at": _now(),
    }


def summarize_scan(
    scan, findings, security_score: int, *, regenerate: bool = False
) -> dict:
    """Executive summary of a whole scan (cached on ``scan.ai_summary``).

    Grounded in severity counts, total, security score (higher = better,
    CVSS 4.0-driven - worst finding plus a breadth bonus within its
    severity band), and the top findings by severity.
    Returns ``{summary, cached, model, generated_at}`` and mutates
    ``scan.ai_summary``; the route commits. A cached summary is returned
    without any LLM call unless ``regenerate`` is set (the UI's Regenerate
    button - explicit, cost-spending opt-in; default is cache-first).
    """
    if scan.ai_summary and not regenerate:
        return {
            "summary": scan.ai_summary,
            "cached": True,
            "model": None,
            "generated_at": None,
        }
    backend = pick_chat_backend()

    counts = {sev: 0 for sev in SEVERITY_CVSS}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    top = sorted(
        findings,
        key=lambda f: SEVERITY_CVSS.get(f.severity, 0.0),
        reverse=True,
    )[ : SUMMARY_TOP_FINDINGS]
    top_lines = [
        f"- [{f.severity}] {f.title}" + (f" ({f.file_path})" if f.file_path else "")
        for f in top
    ]
    data = {
        "app": scan.filename,
        "platform": scan.platform,
        "security_score": security_score,
        "security_score_note": "0-100, higher is better (100 = no findings above info); "
        "driven by the worst finding's CVSS 4.0 base score plus a breadth "
        "bonus within its severity band, capped at the band's CVSS 4.0 "
        "ceiling (high 89, medium 69, low 39)",
        "total_findings": len(findings),
        "severity_counts": counts,
        "top_findings": top_lines,
    }
    text = _chat_text(
        backend,
        [{"role": "system", "content": _SUMMARY_SYSTEM},
         {"role": "user", "content": json.dumps(data, indent=2, default=str)}],
        max_tokens=MAX_SUMMARY_TOKENS,
    )
    scan.ai_summary = text
    return {
        "summary": text,
        "cached": False,
        "model": backend.model,
        "generated_at": _now(),
    }
