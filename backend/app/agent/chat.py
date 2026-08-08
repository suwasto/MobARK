"""M4 Layers 1-3 agent chat — findings context + grep/read/graph tools.

Orchestration: assemble the Layer 1 findings context (full set,
precision-tagged), then run a bounded tool-calling loop over the Layer 2/3
tools. Zero embeddings — the old RAG chat (vector/chat.py) was deleted with
the pipeline; this is its non-embedding replacement.

The chat model comes from the M3 backend store — no new config surface, and
the M3 \"no hard default model\" decision holds (a blank config raises
``ChatNotConfigured``, surfaced as a clear 400 by the API). Models that do
not emit tool calls get a context-only answer — the documented graceful
fallback (techstack: not every local model reliably follows structured
tool-call output).

The whole loop runs under a hard overall deadline (``AgentTimeout``,
``settings.chat_timeout_seconds`` by default): each round hands the model
client only the *remaining* budget, so a hung LLM call — including the
no-tools fallback retry — can never block the API worker beyond it.

The Stop button's server side: each in-flight chat registers a cancel flag
keyed by scan id (``_CANCEL_FLAGS``) and polls it at every round boundary
(and after each tool call). The cancel endpoint sets the flag, the loop
raises :class:`ChatInterrupted`, and the flag is cleared in a ``finally``
so the next chat starts fresh.
"""
from __future__ import annotations

import dataclasses
import json
import re
import threading
import time

from app.agent.context import FindingsContext, build_findings_context
from app.agent.tools import TOOL_SCHEMAS, read_file
from app.model.client import chat as client_chat
from app.model.client import model_arch_hint

SYSTEM_PROMPT = (
    "You are MASA, a mobile application security assistant answering "
    "questions about a scanned app (Android APK or iOS IPA).\n\n"
    "Evidence available to you:\n"
    "1. FINDINGS CONTEXT below — the complete static-analysis findings set. "
    "Every finding is tagged with its precision:\n"
    "   [file/line] findings have a concrete source location (file, and "
    "line when shown).\n"
    "   [binary-level presence only, no specific location] findings prove "
    "the evidence exists in the binary/bundle but have NO source location "
    "— never invent one for them.\n"
    "2. Tools: search_code (regex grep over the decompiled/extracted tree), "
    "read_file (read a file, optionally a line range), and for Android "
    "scans only, graph_query / graph_path / graph_explain (code "
    "call/import/inheritance graph).\n\n"
    "Rules:\n"
    "- Answer ONLY from the findings context and tool results. Never invent "
    "findings, files, lines, entitlements, symbols, or graph nodes.\n"
    "- Cite exact file paths inline, e.g. `com/app/MyWebViewClient.java:42`. "
    "For [binary] evidence, say so explicitly (\"binary-level presence — no "
    "specific source location\").\n"
    "- For structural questions (\"where is X\", \"what calls Y\") on "
    "Android, prefer the graph tools, then confirm details with read_file.\n"
    "- On iOS, semgrep yields nothing by design and the graph tools are "
    "Android-only.\n"
    "- If the evidence cannot answer the question, say you don't know rather "
    "than guessing."
)


class ChatNotConfigured(RuntimeError):
    """No chat model configured in the M3 backend store."""


class ChatUpstreamError(RuntimeError):
    """The upstream LLM backend failed (connection, model load, …).

    Raised when the model call fails even after the no-tools fallback. The
    API maps it to HTTP 502 carrying the upstream message so the UI can show
    *why* (e.g. Ollama's ``unknown model architecture``) instead of a raw 500.
    """


class AgentTimeout(RuntimeError):
    """The agent loop exceeded its overall deadline (hung LLM call).

    Raised when the model has not produced an answer within the configured
    budget — the API maps it to HTTP 504 so a hung upstream never blocks the
    worker forever.
    """


# Trivial greetings are answered without any LLM call (cost + reliability):
# no backend pick, no tool loop, no chance of the "tool-call limit" message.
_GREETING_RE = re.compile(r"^(hi+|hello+|hey+|yo+|howdy|hola)[!. ]*$", re.IGNORECASE)
_GREETING_ANSWER = (
    "Hello! I'm MASA, the security agent for this scan. Ask me anything about "
    "the findings, the decompiled code, or the app's security posture — try "
    "\"where is certificate pinning handled?\" or \"explain the WebView risk.\""
)


class ChatInterrupted(RuntimeError):
    """The user asked to stop this chat (Stop button -> cancel endpoint).

    Raised at the next agent-loop boundary after :func:`request_cancel` fires
    for the scan — the API maps it to HTTP 409 so a cancelled request never
    looks like a real answer. The registry entry is cleared in a ``finally``.
    """


# In-flight chat cancellation: scan_id -> threading.Event. Set by
# ``request_cancel`` (the POST /scans/{id}/chat/cancel endpoint, which runs on
# a *different* thread than the chat loop); polled by ``answer_question`` at
# every loop boundary so a Stop click halts the LLM loop at the next round
# instead of running to the end of the budget.
#
# One event per scan: the UI enforces a single in-flight chat per scan (the
# dock's ``sending`` guard), so collisions are only reachable through the raw
# API. ``_clear_cancel`` still identity-checks so an older request's ``finally``
# can never pop a *newer* request's flag.
_CANCEL_FLAGS: dict[int, threading.Event] = {}


def request_cancel(scan_id: int) -> None:
    """Ask any in-flight chat for ``scan_id`` to stop as soon as possible.

    No-op when nothing is running — the event only exists while a request is
    in flight, so cancelling before/after a chat changes nothing. Thread-safe:
    the cancel endpoint sets the flag while the chat loop reads it.
    """
    event = _CANCEL_FLAGS.get(scan_id)
    if event is not None:
        event.set()


def _register_cancel(scan_id: int) -> threading.Event:
    event = threading.Event()
    _CANCEL_FLAGS[scan_id] = event
    return event


def _clear_cancel(scan_id: int, event: threading.Event) -> None:
    # Identity check: with (rare) concurrent chats for the same scan, never
    # pop a flag registered by a *different* request.
    if _CANCEL_FLAGS.get(scan_id) is event:
        _CANCEL_FLAGS.pop(scan_id, None)


def _raise_if_cancelled(scan_id: int, event: threading.Event) -> None:
    if event.is_set():
        raise ChatInterrupted(
            f"agent chat for scan {scan_id} was interrupted by the user"
        )


@dataclasses.dataclass(frozen=True)
class Citation:
    file: str
    line: int | None
    snippet: str


@dataclasses.dataclass(frozen=True)
class AgentResult:
    answer: str
    citations: list[Citation]
    sources: list[str]
    tools_used: list[str]


def _deadline_remaining(deadline: float, scan_id: int, timeout: float) -> float:
    """Remaining budget in seconds, raising ``AgentTimeout`` when exhausted.

    Used at every round start and before/after each model call so a hung LLM
    call — including the no-tools fallback retry — can never extend the block
    past the overall deadline.
    """
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise AgentTimeout(
            f"agent chat for scan {scan_id} exceeded its {timeout:.0f}s budget"
        )
    return remaining


def _pick_chat_backend():
    """First enabled backend with a configured model (M3 store, no default).

    Delegates to the shared rule (app.model.selection) so chat, per-finding
    explain, and overview summary resolve the model identically — the M5
    plan's single-selection decision.
    """
    from app.model.selection import NoModelConfigured
    from app.model.selection import pick_chat_backend as _pick

    try:
        return _pick()
    except NoModelConfigured as exc:
        raise ChatNotConfigured(str(exc)) from exc


def _load_context(scan_id: int) -> FindingsContext:
    from app.db import SessionLocal
    from app.models import Scan

    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            raise ValueError(f"scan {scan_id} not found")
        return build_findings_context(db, scan)
    finally:
        db.close()


def answer_question(
    scan_id: int,
    question: str,
    *,
    max_tool_rounds: int = 3,
    temperature: float = 0.2,
    timeout: float | None = None,
) -> AgentResult:
    """Answer a question over Layers 1-3 (findings context + tools).

    The Layer 1 context is always present; tools are used only when the model
    emits tool calls. Returns cited answer + resolved citations.

    ``timeout`` is a hard *overall* deadline in seconds for the whole loop
    (default ``settings.chat_timeout_seconds``). Each round passes only the
    remaining budget to the model client, so the no-tools fallback retry
    cannot double the hang. Raises ``AgentTimeout`` when the budget is
    exhausted before an answer arrives.

    Trivial greetings ("hi", "hello") are answered with a canned reply — no
    LLM call, no backend pick. If the loop ends without a text answer (the
    model only emitted tool calls), one final plain-chat attempt is made with
    the original grounded prompt (the documented context-only fallback) before
    the graceful "tool-call limit" message is returned.
    """
    # Trivial greetings get a canned answer — no backend pick, no LLM call,
    # no tool loop. Regression: 'hi' used to make the model emit tool calls
    # every round, burn the whole budget, and come back as the confusing
    # "could not complete within the tool-call limit" message.
    if _GREETING_RE.match(question.strip()):
        return AgentResult(
            answer=_GREETING_ANSWER, citations=[], sources=[], tools_used=[]
        )

    from app.agent.tools import execute_tool
    from app.config import settings

    context = _load_context(scan_id)
    backend = _pick_chat_backend()

    if timeout is None:
        timeout = float(settings.chat_timeout_seconds)
    deadline = time.monotonic() + timeout

    messages: list[dict] = [
        {"role": "system", "content": SYSTEM_PROMPT + "\n\n" + context.rendered},
        {"role": "user", "content": question},
    ]
    # The original 2-turn prompt — used by the exhaustion fallback so the
    # final plain-chat call never carries tool-role messages a server may
    # reject without a `tools` parameter.
    prompt = list(messages)
    tools = TOOL_SCHEMAS
    tools_used: list[str] = []
    final_text = ""

    cancel = _register_cancel(scan_id)
    try:
        for _round in range(max_tool_rounds + 1):
            # Stop button: checked at every round boundary so an interrupt
            # lands before the next (expensive) LLM call.
            _raise_if_cancelled(scan_id, cancel)
            remaining = _deadline_remaining(deadline, scan_id, timeout)
            try:
                response = client_chat(
                    backend,
                    messages,
                    temperature=temperature,
                    timeout=remaining,
                    tools=tools,
                )
            except Exception:
                # Some backends reject the tools kwarg — degrade to plain chat,
                # but only with the *freshly* remaining budget. If the first call
                # already burned it (hung upstream), stop rather than retry — the
                # worker block stays bounded by the overall deadline.
                remaining = _deadline_remaining(deadline, scan_id, timeout)
                try:
                    response = client_chat(
                        backend, messages, temperature=temperature, timeout=remaining
                    )
                except Exception as exc:
                    # If the fallback itself burns the budget (hung upstream),
                    # surface a clean 504 rather than a raw 500; a fast backend
                    # error is wrapped so the API can surface a clean 502 with the
                    # upstream message (the request was valid, the upstream wasn't).
                    _deadline_remaining(deadline, scan_id, timeout)
                    raise ChatUpstreamError(
                        model_arch_hint(f"LLM call failed: {exc}")
                    ) from exc

            message = response.choices[0].message
            content = (message.content or "").strip()
            tool_calls = list(getattr(message, "tool_calls", None) or [])

            if not tool_calls:
                final_text = content
                break

            if content:
                final_text = content
            messages.append(
                {
                    "role": "assistant",
                    "content": content or None,
                    "tool_calls": [
                        {
                            "id": getattr(tc, "id", None) or f"call_{i}",
                            "type": "function",
                            "function": {
                                "name": tc.function.name if tc.function else None,
                                "arguments": tc.function.arguments if tc.function else "{}",
                            },
                        }
                        for i, tc in enumerate(tool_calls)
                    ],
                }
            )
            for i, tc in enumerate(tool_calls):
                fn = tc.function if tc.function else None
                name = fn.name if fn else None
                raw_args = fn.arguments if fn else "{}"
                call_id = getattr(tc, "id", None) or f"call_{i}"
                try:
                    args = json.loads(raw_args or "{}")
                except json.JSONDecodeError:
                    args = {}
                if name:
                    tools_used.append(name)
                result = (
                    execute_tool(scan_id, name, args)
                    if name
                    else json.dumps({"error": "malformed tool call"})
                )
                # Also checked after each tool so a slow tool can't hide an
                # interrupt until the whole round is done.
                _raise_if_cancelled(scan_id, cancel)
                messages.append(
                    {"role": "tool", "tool_call_id": call_id, "content": result}
                )
    finally:
        # Never leave a stale flag behind: the next chat for the same scan
        # must start fresh.
        _clear_cancel(scan_id, cancel)

    if not final_text:
        # The tool loop never produced a text answer (the model only ever
        # emitted tool calls, or returned empty content). One final plain-chat
        # attempt with the original grounded prompt — no tools — bounded by the
        # remaining budget. This is the documented context-only fallback, and
        # it fixes trivial prompts that used to end in "tool-call limit".
        remaining = _deadline_remaining(deadline, scan_id, timeout)
        try:
            response = client_chat(
                backend, prompt, temperature=temperature, timeout=remaining
            )
        except Exception as exc:
            _deadline_remaining(deadline, scan_id, timeout)
            raise ChatUpstreamError(model_arch_hint(f"LLM call failed: {exc}")) from exc
        final_text = (response.choices[0].message.content or "").strip()
        if not final_text:
            final_text = (
                "I could not complete a grounded answer within the tool-call "
                "limit. Try a more specific question, or ask about a specific "
                "file or finding."
            )

    return _build_result(scan_id, final_text, tools_used)


# ---- citation resolution ------------------------------------------------------

_CITE_RE = re.compile(
    r"([A-Za-z0-9_./-]+\.(?:java|xml|kt|kts|smali|swift|m|h|plist|json|txt|"
    r"properties|yml|yaml|html|strings|entitlements)):(\d+)"
)
_MAX_CITATIONS = 5


def _extract_citations(answer: str) -> list[tuple[str, int]]:
    return [(m.group(1), int(m.group(2))) for m in _CITE_RE.finditer(answer)]


def _build_result(scan_id: int, answer: str, tools_used: list[str]) -> AgentResult:
    citations: list[Citation] = []
    seen: set[tuple[str, int]] = set()
    for file, line in _extract_citations(answer):
        key = (file, line)
        if key in seen:
            continue
        seen.add(key)
        snippet = ""
        try:
            snippet = read_file(scan_id, file, line_start=line, line_end=line).strip()[:200]
        except Exception:
            snippet = ""
        citations.append(Citation(file=file, line=line, snippet=snippet))
        if len(citations) >= _MAX_CITATIONS:
            break
    sources = sorted({c.file for c in citations})
    return AgentResult(
        answer=answer,
        citations=citations,
        sources=sources,
        tools_used=sorted(set(tools_used)),
    )
