"""M9 report - per-scan web-source capture (open item 1, resolved Aug 12).

The report's ``External references`` section (M9 decision 3) lists the web
URLs the agent actually consulted during M7 web research - cited distinctly
from local-code-derived findings. Today nothing persists "which URLs were
used" per scan: ``web_fetch`` runs inside chat turns and the result is
returned to the client, then gone.

This module captures them at **chat-turn completion** (the plan's option a):
the chat routes call :func:`capture_from_turn` with the turn's ``tool_runs``
(the persistent trace on ``AgentResult``); every successful ``web_fetch``
run contributes its **final post-redirect URL** - the exact URL the model
was told to cite (``web_fetch`` returns ``{"url", "title", "text"}``, url =
post-redirect). URLs are appended to a small per-scan JSON ledger beside the
scan's trees (``work/<scan_id>/web_sources.json`` - the dependencies_cache
pattern), deduplicated, and bounded so a research-heavy scan can't grow it
without limit. The report route reads the ledger and passes the list to
``report.assemble_report(web_sources=...)``.

Why capture here and not inside the agent tools: the agent layer stays
feature-agnostic - tools return data, they never persist for a downstream
consumer (the same discipline as ``dependencies.py`` deriving on demand).
The chat routes own the write because they are the one place every turn
(streamed or buffered) converges.

Why only ``web_fetch`` and not ``web_search``: a search returns candidate
URLs the model may not have read; the report should cite what was actually
fetched and cited. Search results that lead nowhere are noise.

Best-effort throughout: a missing/torn ledger reads as an empty list and a
failed write never raises (the dependencies_cache posture) - the report
simply omits the section.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from app.config import settings

# ---- Ledger format -----------------------------------------------------------
# Bump when the stored payload shape changes so stale persisted files are
# treated as torn (rebuilt from nothing).
_WEB_SOURCES_VERSION = 1
# Cap on the URL list per scan - an upper bound on the report's External
# references section (research-heavy scans stay bounded; 500 URLs is far
# beyond any realistic engagement, and the report previews first-N anyway).
_MAX_SOURCES = 500

# The web_fetch result JSON carries ``{"url", "title", "text"}`` with the
# FINAL post-redirect URL. The preview on the ToolRun trace is capped
# (chat.py ``_TOOL_RESULT_PREVIEW_MAX`` = 200 chars) - but the URL is the
# FIRST field of the JSON, so it always survives the cap. This regex is the
# defensive fallback for a preview that isn't clean JSON (never needed in
# practice - the URL precedes any truncation).
_URL_RE = re.compile(r'"url"\s*:\s*"([^"]+)"')


def ledger_path(scan_id: int) -> Path:
    """The per-scan ledger file (sibling of the trees, never scan output)."""
    return settings.data_dir / "work" / str(scan_id) / "web_sources.json"


def _url_from_preview(preview: str) -> str | None:
    """The final URL from a web_fetch result preview (None when unreadable)."""
    try:
        parsed = json.loads(preview)
        if isinstance(parsed, dict) and isinstance(parsed.get("url"), str):
            return parsed["url"]
    except ValueError:
        pass
    match = _URL_RE.search(preview)
    return match.group(1) if match else None


def capture_from_turn(scan_id: int, tool_runs) -> None:
    """Append the turn's fetched web URLs to the scan's ledger (dedup, cap).

    ``tool_runs`` is the ``AgentResult.tool_runs`` list (or any iterable of
    objects with ``name``/``status``/``result_preview`` - duck-typed so the
    module has no import dependency on the agent layer). Only successful
    ``web_fetch`` runs contribute; their ``result_preview`` carries the final
    post-redirect URL. Idempotent + bounded: existing URLs are not re-added,
    and the list is capped at ``_MAX_SOURCES`` (first-come first-kept).
    Best-effort: a failed write (read-only FS etc.) is a no-op, never an
    exception.
    """
    urls: list[str] = []
    seen: set[str] = set()
    for run in tool_runs or []:
        if getattr(run, "name", None) != "web_fetch":
            continue
        if getattr(run, "status", None) != "ok":
            continue
        url = _url_from_preview(getattr(run, "result_preview", "") or "")
        if not url or url in seen:
            continue
        seen.add(url)
        urls.append(url)
        if len(urls) >= _MAX_SOURCES:
            break
    if not urls:
        return

    path = ledger_path(scan_id)
    existing = _read_ledger(path)
    merged = existing + [u for u in urls if u not in set(existing)]
    merged = merged[:_MAX_SOURCES]
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps({"version": _WEB_SOURCES_VERSION, "urls": merged}, sort_keys=True),
            encoding="utf-8",
        )
        tmp.replace(path)
    except OSError:
        pass  # best-effort cache


def _read_ledger(path: Path) -> list[str]:
    """The ledger's URL list, or [] when missing/torn (never raises)."""
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if (
        isinstance(data, dict)
        and data.get("version") == _WEB_SOURCES_VERSION
        and isinstance(data.get("urls"), list)
    ):
        return [u for u in data["urls"] if isinstance(u, str)]
    return []


def sources_for(scan_id: int) -> list[str]:
    """The scan's captured web-source URLs, in first-seen order ([] when none).

    The report route passes this to ``assemble_report(web_sources=...)``.
    """
    return _read_ledger(ledger_path(scan_id))
