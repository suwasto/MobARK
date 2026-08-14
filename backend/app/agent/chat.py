"""M4 Layers 1-3 agent chat - findings context + grep/read/graph tools.

Orchestration: assemble the Layer 1 findings context (full set,
precision-tagged), then run a bounded tool-calling loop over the Layer 2/3
tools. Zero embeddings - the old RAG chat (vector/chat.py) was deleted with
the pipeline; this is its non-embedding replacement.

The chat model comes from the M3 backend store - no new config surface, and
the M3 \"no hard default model\" decision holds (a blank config raises
``ChatNotConfigured``, surfaced as a clear 400 by the API). Models that do
not emit tool calls get a context-only answer - the documented graceful
fallback (techstack: not every local model reliably follows structured
tool-call output).

The whole loop runs under a hard overall deadline (``AgentTimeout``,
``settings.chat_timeout_seconds`` by default): each round hands the model
client only the *remaining* budget, so a hung LLM call - including the
no-tools fallback retry - can never block the API worker beyond it.

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
from collections.abc import Callable

from app.agent.context import FindingsContext, build_findings_context
from app.agent.tools import read_file, schemas_for_platform
from app.model.client import chat as client_chat
from app.model.client import chat_stream, model_arch_hint
from app.request_ctx import current_master_key, current_user_id

SYSTEM_PROMPT = (
    "You are MASA, a mobile application security assistant answering "
    "questions about a scanned app (Android APK or iOS IPA).\n\n"
    "Evidence available to you:\n"
    "1. FINDINGS CONTEXT below - the complete static-analysis findings set. "
    "Every finding is tagged with its precision:\n"
    "   [file/line] findings have a concrete source location (file, and "
    "line when shown).\n"
    "   [binary-level presence only, no specific location] findings prove "
    "the evidence exists in the binary/bundle but have NO source location "
    "- never invent one for them.\n"
    "2. Tools: search_code (regex grep over the decompiled/extracted tree), "
    "read_file (read a file, optionally a line range), read_manifest "
    "(manifest/Info.plist summary), get_permissions (requested permissions "
    "/ usage strings), search_strings (grep over resources only), "
    "run_secrets_scan (on-demand gitleaks re-run over a targeted path), "
    "get_decompiled_class (Android only - read one decompiled class by name), "
    "and for Android scans only, graph_query / graph_path / graph_explain "
    "(code call/import/inheritance graph). iOS never gets "
    "get_decompiled_class - there is no decompiled Swift/ObjC source in v1.\n\n"
    "Rules:\n"
    "- Answer ONLY from the findings context and tool results. Never invent "
    "findings, files, lines, entitlements, symbols, or graph nodes.\n"
    "- Cite exact file paths inline, e.g. `com/app/MyWebViewClient.java:42`. "
    "For [binary] evidence, say so explicitly (\"binary-level presence - no "
    "specific source location\").\n"
    "- For structural questions (\"where is X\", \"what calls Y\") on "
    "Android, prefer the graph tools, then confirm details with read_file.\n"
    "- On iOS, semgrep yields nothing by design and the graph tools are "
    "Android-only.\n"
    "- If the evidence cannot answer the question, say you don't know rather "
    "than guessing.\n"
    "- NEVER describe an action you intend to take instead of taking it. If a "
    "question needs the code, actually call search_code / read_file / "
    "read_editable_file - a plan like \"Let's search for X\" with no tool call "
    "is not an answer. Call the tool, then compose the final answer from its "
    "real results."
)

# M8 Phase D: appended to the system prompt ONLY when the scan is Android
# AND the on-demand apktool decode is ready (edit_tools_allowed - the edit
# tools are otherwise never even offered). Explains the review contract so a
# real model proposes instead of claiming it applied a change.
_M8_EDIT_PROMPT = (
    "\n\nEDIT TOOLS ARE AVAILABLE for this scan (Android, smali decode ready). "
    "You can read and propose edits to the REBUILDABLE surface - smali files "
    "(smali/...), resources (res/...), and the decoded AndroidManifest.xml:\n"
    "- search_code(pattern): find the relevant code in the jadx Java tree "
    "(e.g. 'password' or 'verify').\n"
    "- find_smali_sibling(path): map a jadx class path from search_code or a "
    "@mention (e.g. 'sources/com/foo/AuthManager.java') to its editable "
    "apktool smali sibling ('smali/com/foo/AuthManager.smali').\n"
    "- read_editable_file(path): read the CURRENT content of an editable file "
    "(includes already-applied edits - exactly what a rebuild would compile).\n"
    "- propose_smali_edit(path, instruction, new_content): store an edit "
    "proposal with a generated diff.\n"
    "IMPORTANT: propose_smali_edit NEVER applies anything - it stores a "
    "proposed edit for the human to review and apply/reject per file in the "
    "Review edits panel. Always read the file first and compose the FULL "
    "edited content (byte-exact); never claim an edit was applied - say it "
    "was PROPOSED and cite the file. For non-editable files (jadx Java, iOS "
    "bundle) say they are read-only and explain why. When the user "
    "@mentions a file (e.g. '@AndroidManifest.xml'), treat it as the target "
    "of the request - the file's current content is already attached in the "
    "USER-MENTIONED FILES section.\n"
    "CHANGE REQUESTS MUST END IN A PROPOSAL: when the user asks to change, "
    "bypass, disable, remove, or patch something ('bypass the root check', "
    "'disable certificate pinning'), your answer is NOT complete until you "
    "call propose_smali_edit on the target file - or, when the target is not "
    "editable, state that explicitly. Never finish such a request with a "
    "read-only summary and no proposal.\n"
    "ONE FILE PER TURN: a request that spans MULTIPLE files is handled one "
    "file per turn - propose the FIRST file's edit, end your turn telling "
    "the user it is stored for review (Review edits panel) and to reply "
    "'continue' for the next file. Do NOT batch several files' proposals "
    "into one turn: the human reviews each proposal before the next one is "
    "made. Prior proposals and their verdicts are listed in the EDIT "
    "REVIEW STATE section (when present) - never re-propose an "
    "already-applied or rejected change to the same file."
)


# M8 follow-up: user @-mentions of files in the dock. The frontend extracts
# `@path` tokens from the draft and sends them as
# ChatRequest.mentioned_files; this section renders each file's CURRENT
# content (applied edits included for editable files - exactly what a rebuild
# would compile) so the model answers / proposes edits about the mentioned
# files directly, with no search round needed.
_MENTION_MAX_FILES = 10
_MENTION_FILE_CHARS = 20_000
_MENTION_TOTAL_CHARS = 60_000


# M8 follow-up (Aug 11): models - local ones especially - sometimes answer
# with PLAN NARRATION instead of a tool call ("Let's search for login-related
# files… Let's read LoginActivity.java…") and the loop would previously treat
# that as the final answer: no search ever ran, no rollup. When a round
# returns content that describes an intended tool action but emits no tool
# call, inject a bounded nudge and continue the loop so the model actually
# calls search_code / read_file and composes a grounded answer from the real
# results.
_NARRATION_INTENT_RE = re.compile(
    r"\b(let'?s|let me|i'?ll|i will|i'?m going to|i am going to|"
    r"we should|we need to|i should|i need to|i want to)"
    r"\s+(search|look|read|check|inspect|find|scan|investigate|open|"
    r"explore|query|examine|review|analyze)",
    re.IGNORECASE,
)
# Bound the nudge: a model that simply cannot emit tool calls must not loop
# forever - after this many nudges its narration is accepted as-is.
_MAX_NARRATION_NUDGES = 2
_NARRATION_NUDGE = (
    "You described an action (search/read/check/inspect…) but did not call "
    "any tool. Actually call the tool NOW (e.g. search_code, read_file, "
    "read_editable_file) and answer from the real results - a plan without "
    "a tool call is not an answer."
)


# M8 follow-up (Aug 12): the "ends on read" problem - a change request
# ("bypass the root check") would search + read the editable file, then write
# a summary answer WITHOUT ever calling propose_smali_edit. When the question
# asks for a change and the model has been reading/searching but produced
# zero proposals, inject a bounded nudge that demands the proposal (or an
# explicit read-only explanation). Mirror of the narration nudge: bounded, so
# a model that cannot propose eventually gets its answer accepted.
_EDIT_INTENT_RE = re.compile(
    r"\b(bypass|by-pass|disable|enable|remove|delete|change|edit|patch|"
    r"modify|fix|block|prevent|allow|skip|short[- ]circuit|neutralize|"
    r"deactivate|turn off|turn on|strip out|make it|stop it from|get past|"
    r"get around|re-enable)",
    re.IGNORECASE,
)
# M9 follow-up (Aug 14): edit-intent inheritance is now gated on an ACTUAL
# continuation - a bare "continue"/"next" cue, or a question that references
# the scan's pending proposals. Without the gate, ANY old turn that used a
# change verb ("bypass the root check") kept ``edit_intent`` true for every
# later question, so an unrelated follow-up ("why is the app debuggable?") in
# the same session could be pushed by the edit nudge into proposing an edit it
# was never asked for. The cue must be (nearly) the WHOLE question - "next" as
# a sentence opener ("Next, explain the WebView risk") is NOT a continuation.
_EDIT_CONTINUATION_RE = re.compile(
    r"^\s*(?:continue|go\s*on|proceed|keep\s*going|keep\s*editing|"
    r"yes|yeah|yep|y|ok|okay|sure|go\s*ahead|do\s*it|and\s*then|again|more|"
    r"next|next\s+one|next\s+file|next\s+edit|next\s+proposal|what'?s\s*next|"
    r"what\s*next)"
    r"[\s.!?,]*(?:please|now|with\s+it)*[\s.!?]*$",
    re.IGNORECASE,
)
# A question that references the edit-review surface ("the edit", "is the
# proposal applied yet?", "pending") is treated as a continuation cue too -
# the human is talking about the prior edit task, not a new topic.
_EDIT_REFERENCE_RE = re.compile(r"\b(edit|propos|pending)\w*\b", re.IGNORECASE)
# Tools whose execution counts as "the model already did the reading/search"
# for the edit-task nudge - the change request has progressed but stalled.
_EDIT_READ_TOOLS = frozenset(
    {
        "search_code",
        "read_file",
        "read_editable_file",
        "find_smali_sibling",
        "get_decompiled_class",
        "read_manifest",
    }
)
_MAX_EDIT_NUDGES = 2
_EDIT_PROPOSE_NUDGE = (
    "The user asked you to CHANGE code. You have already searched/read the "
    "relevant files but proposed nothing. Call propose_smali_edit NOW with "
    "the FULL edited content for the target file (read it first if you "
    "haven't), or - if the target is genuinely not editable - state that "
    "explicitly and end your turn."
)


# M8 follow-up (Aug 12): the client-side thread ships recent turns so a
# follow-up ("continue the edit task") keeps the original request - the
# backend never used to persist chat. Cap the injected history (turns +
# per-turn chars) so a long dock thread can't balloon the prompt. M9
# follow-up: sessions feed the FULL persisted thread through this same
# path, so the window is wider (20 turns) than the old client-side 6.
_MAX_HISTORY_TURNS = 20
_MAX_HISTORY_CHARS = 24_000


# M7: appended to the system prompt ONLY when the scan's web-research opt-in
# AND an Active search engine both hold (the web tools are otherwise never
# even offered - see schemas_for_platform).
_WEB_PROMPT = (
    "\n\nWEB RESEARCH IS ENABLED for this scan (the per-scan opt-in is on and "
    "a search engine is Active). You have two extra tools:\n"
    "- web_search(query): search public web sources (CVE databases, OWASP "
    "MASTG guidance, dependency advisories) when a question needs CURRENT or "
    "EXTERNAL information the scan data cannot answer.\n"
    "- web_fetch(url): read one page (static content only) from a search "
    "result, e.g. a CVE advisory, then cite its final URL in your answer.\n"
    "Use these SPARINGLY - only when the question genuinely needs external "
    "facts; never search for information already in the findings context. "
    "Queries leave this machine by design (the scan opted in). Always cite "
    "the source URLs you actually used."
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
    budget - the API maps it to HTTP 504 so a hung upstream never blocks the
    worker forever.
    """


# Trivial greetings are answered without any LLM call (cost + reliability):
# no backend pick, no tool loop, no chance of the "tool-call limit" message.
_GREETING_RE = re.compile(r"^(hi+|hello+|hey+|yo+|howdy|hola)[!. ]*$", re.IGNORECASE)
_GREETING_ANSWER = (
    "Hello! I'm MASA, the security agent for this scan. Ask me anything about "
    "the findings, the decompiled code, or the app's security posture - try "
    "\"where is certificate pinning handled?\" or \"explain the WebView risk.\""
)


class ChatInterrupted(RuntimeError):
    """The user asked to stop this chat (Stop button -> cancel endpoint).

    Raised at the next agent-loop boundary after :func:`request_cancel` fires
    for the scan - the API maps it to HTTP 409 so a cancelled request never
    looks like a real answer. The registry entry is cleared in a ``finally``.
    """


TOOL_MODE_TOOLS = "tools"
TOOL_MODE_CONTEXT = "context-only"

# Cap for the result preview carried on tool_end events + the final trace
# (the full result is still passed to the model - this is UI-only truncation).
_TOOL_RESULT_PREVIEW_MAX = 200


@dataclasses.dataclass(frozen=True)
class AgentEvent:
    """One observable event from the agent loop while a turn runs.

    Kinds: ``token`` (``{"delta"}`` - streamed answer text), ``tool_start``
    (``{"id", "name", "args"}``), ``tool_end`` (``{"id", "name",
    "status", "duration_ms", "result_preview", "error", "count"}``). The
    final answer is the return value (AgentResult), not an event - the
    stream route emits the ``answer`` frame itself.
    """

    kind: str
    payload: dict


@dataclasses.dataclass(frozen=True)
class ToolRun:
    """One executed tool call - the persistent trace on AgentResult / the
    chat response, so the dock can render a collapsible per-tool record even
    after the live events are gone."""

    id: str
    name: str
    args: dict
    status: str  # "ok" | "error"
    duration_ms: int
    result_preview: str = ""
    error: str | None = None
    count: int | None = None  # list-result length (search hits, secrets rows, ...)


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

    No-op when nothing is running - the event only exists while a request is
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
    # M6 Phase B: "tools" when the model actually emitted tool calls this
    # turn, "context-only" when it answered from the findings context alone.
    tool_mode: str = TOOL_MODE_CONTEXT
    # M6 follow-up: the persistent per-tool trace (args, status, duration,
    # capped result preview) - powers the dock's collapsible "Tools (n)".
    tool_runs: list[ToolRun] = dataclasses.field(default_factory=list)


def _deadline_remaining(deadline: float, scan_id: int, timeout: float) -> float:
    """Remaining budget in seconds, raising ``AgentTimeout`` when exhausted.

    Used at every round start and before/after each model call so a hung LLM
    call - including the no-tools fallback retry - can never extend the block
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
    explain, and overview summary resolve the model identically - the M5
    plan's single-selection decision.
    """
    from app.model.selection import NoModelConfigured
    from app.model.selection import pick_chat_backend as _pick

    try:
        return _pick()
    except NoModelConfigured as exc:
        raise ChatNotConfigured(str(exc)) from exc


def check_configured() -> None:
    """Raise :class:`ChatNotConfigured` when no chat backend is configured.

    The stream route calls this BEFORE the SSE response starts, so a missing
    model is a clean HTTP 400 rather than the first frame of an already-
    sent 200 stream.
    """
    _pick_chat_backend()


def _emit(
    on_event: Callable[[AgentEvent], None] | None,
    kind: str,
    payload: dict,
) -> None:
    if on_event is not None:
        on_event(AgentEvent(kind=kind, payload=payload))


def _get(obj, key: str, default=None):
    """Attribute-or-dict access - litellm chunk deltas may be pydantic models
    OR plain dicts depending on provider/version."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _accumulate_tool_call_deltas(calls: dict, order: list, deltas) -> None:
    """Merge one chunk's tool_call deltas into ``calls`` (keyed by index),
    preserving first-seen order.

    litellm normalizes every provider to OpenAI's incremental shape: ``index``
    identifies the call, ``id``/``function.name`` arrive on the first delta
    for that index, and ``function.arguments`` is a partial JSON string
    concatenated across chunks. Local servers occasionally omit the index or
    split arguments awkwardly - this is defensive against both.
    """
    for raw in deltas:
        if raw is None:
            continue
        idx = _get(raw, "index")
        cid = _get(raw, "id")
        fn = _get(raw, "function") or {}
        name = _get(fn, "name")
        args = _get(fn, "arguments")
        if idx is None:
            # Malformed servers omit the index - fall back to the call id,
            # then to first-seen position.
            idx = cid if cid else len(order)
        if idx not in calls:
            calls[idx] = {"id": None, "name": None, "arguments": ""}
            order.append(idx)
        entry = calls[idx]
        if cid and not entry["id"]:
            entry["id"] = cid
        if name and not entry["name"]:
            entry["name"] = name
        if args:
            entry["arguments"] += args


def _normalized_tool_calls(calls: dict, order: list) -> list:
    """Build buffered-shape tool_call objects (``.id``, ``.function.name``,
    ``.function.arguments``) from the accumulated deltas."""
    from types import SimpleNamespace

    out = []
    for n, idx in enumerate(order):
        entry = calls[idx]
        out.append(
            SimpleNamespace(
                id=entry["id"] or f"call_{n}",
                type="function",
                function=SimpleNamespace(
                    name=entry["name"],
                    arguments=entry["arguments"] or "{}",
                ),
            )
        )
    return out


def _stream_round(
    backend,
    messages: list[dict],
    *,
    temperature: float,
    timeout: float,
    tools: list[dict] | None,
    on_token: Callable[[str], None] | None,
):
    """One streaming model round: consume litellm chunks, accumulate content
    + tool-call deltas into the buffered response shape, and forward content
    tokens live via ``on_token``.

    Returns an object shaped like the buffered ``client_chat`` response
    (``.choices[0].message`` with ``content`` + ``tool_calls``) so the agent
    loop treats both paths identically.
    """
    from types import SimpleNamespace

    # Omit the tools kwarg entirely when None - some providers reject an
    # explicit null and the fallback call must look like a plain chat.
    stream_kwargs = {"temperature": temperature, "timeout": timeout}
    if tools is not None:
        stream_kwargs["tools"] = tools

    content_parts: list[str] = []
    calls: dict = {}
    order: list = []

    for chunk in chat_stream(backend, messages, **stream_kwargs):
        if not getattr(chunk, "choices", None):
            continue
        delta = getattr(chunk.choices[0], "delta", None)
        if delta is None:
            continue
        content = getattr(delta, "content", None)
        if content:
            content_parts.append(content)
            if on_token is not None:
                on_token(content)
        tcs = getattr(delta, "tool_calls", None)
        if tcs:
            _accumulate_tool_call_deltas(calls, order, tcs)

    return SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(
                    content="".join(content_parts) or None,
                    tool_calls=_normalized_tool_calls(calls, order),
                )
            )
        ]
    )


def _model_round(
    backend,
    messages: list[dict],
    *,
    temperature: float,
    timeout: float,
    tools: list[dict] | None,
    stream: bool,
    on_token: Callable[[str], None] | None,
):
    """One model round: streaming (deltas accumulated + tokens forwarded)
    or buffered - the loop calls this uniformly so both paths share the
    same fallback logic."""
    if stream:
        return _stream_round(
            backend,
            messages,
            temperature=temperature,
            timeout=timeout,
            tools=tools,
            on_token=on_token,
        )
    # Same omission rule as the streaming path: the plain-chat fallback must
    # not carry a tools kwarg at all (existing callers detect its absence).
    kwargs: dict = {"temperature": temperature, "timeout": timeout}
    if tools is not None:
        kwargs["tools"] = tools
    return client_chat(backend, messages, **kwargs)


def _classify_tool_result(result: str) -> tuple[str, str, str | None, int | None]:
    """``(status, preview, error, count)`` for one tool result JSON string.

    ``error`` is set when the result carries the ToolError shape; ``count``
    is the length when the result is a list (search hits, secrets rows, …).
    The preview is capped - the full result still reaches the model.
    """
    try:
        parsed = json.loads(result)
    except json.JSONDecodeError:
        parsed = None
    preview = result[:_TOOL_RESULT_PREVIEW_MAX]
    if isinstance(parsed, dict) and "error" in parsed:
        return "error", preview, str(parsed["error"]), None
    if isinstance(parsed, list):
        return "ok", preview, None, len(parsed)
    return "ok", preview, None, None


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


def _load_mentioned_files(scan_id: int, paths: list[str]) -> str:
    """Render the USER-MENTIONED FILES section for the system prompt.

    Each mentioned path is read with the same guarded content read the
    decompiler viewer uses (``tree.read_tree_file``) - traversal-guarded,
    binary files refused, plists decoded, and **editable files carry the
    applied-edit overlay** so the model sees the current state a rebuild
    would compile. Unreadable/missing paths degrade to an inline note, never
    a crash. Capped per file + in total so a mention dump can't blow the
    prompt budget.
    """
    if not paths:
        return ""
    from app.analysis import tree
    from app.db import SessionLocal
    from app.models import Scan

    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
    finally:
        db.close()
    if scan is None:
        return ""

    sections: list[str] = []
    total = 0
    # Dedup - a raw API caller could otherwise attach the same path twice and
    # double its content in the prompt (wasting the total cap).
    for path in list(dict.fromkeys(paths))[:_MENTION_MAX_FILES]:
        try:
            resp = tree.read_tree_file(scan, path)
            content = resp.content
        except (tree.TreeError, FileNotFoundError) as exc:
            sections.append(f"- {path}: [could not load - {exc}]")
            continue
        if len(content) > _MENTION_FILE_CHARS:
            content = content[:_MENTION_FILE_CHARS] + "\n… [truncated]"
        room = _MENTION_TOTAL_CHARS - total
        if room <= 0:
            break
        if len(content) > room:
            content = content[:room] + "\n… [truncated]"
        total += len(content)
        sections.append(f"- {path}:\n{content}")
    if not sections:
        return ""
    return (
        "\n\nUSER-MENTIONED FILES - the user explicitly attached these files "
        "to the question (via @mention in the dock). Treat them as the focus: "
        "answer about them directly instead of searching for them. When the "
        "question asks to change code, propose edits to the EDITABLE ones "
        "(smali/, res/, AndroidManifest.xml) via propose_smali_edit; jadx "
        "sources and iOS bundle files are read-only. Content follows (current "
        "state, applied edits included):\n" + "\n".join(sections)
    )


def _load_edit_review_state(scan_id: int) -> str:
    """Render the EDIT REVIEW STATE section for the system prompt - the
    scan's M8 edit proposals + their review verdicts, newest first.

    This is what makes the sequential edit flow work across turns: when the
    user says "continue" (or asks about prior edits), the agent sees which
    proposals are still ``proposed`` (awaiting apply/reject), which were
    ``applied``, and which were ``rejected`` - so it never re-proposes a
    resolved file and knows what remains of the original task. Compact (12
    newest rows, instruction truncated); empty string when there are no
    edits. Only rendered when the edit tools are allowed (Android +
    decode-ready), like the rest of the M8 surface.
    """
    from sqlalchemy import select

    from app.db import SessionLocal
    from app.models import Edit

    db = SessionLocal()
    try:
        rows = list(
            db.scalars(
                select(Edit)
                .where(Edit.scan_id == scan_id)
                .order_by(Edit.id.desc())
                .limit(12)
            )
        )
    finally:
        db.close()
    if not rows:
        return ""
    lines: list[str] = []
    for e in rows:
        instruction = (e.instruction or "").strip().replace("\n", " ")[:120]
        row = f"- edit #{e.id} {e.file_path} [{e.status}]"
        if instruction:
            row += f" \"{instruction}\""
        lines.append(row)
    return (
        "\n\nEDIT REVIEW STATE - the M8 edit proposals for this scan and "
        "their verdicts (the Review edits panel):\n"
        + "\n".join(lines)
        + "\n[proposed] = stored, NOT applied - the human has not reviewed it "
        "yet. When the user says 'continue', review this list and propose the "
        "NEXT file the original task needs (never re-propose a resolved "
        "file), or say the task is complete."
    )


def _load_pending_edits(scan_id: int) -> list[dict]:
    """The scan's PENDING edit proposals (``status == "proposed"``) as
    ``{id, file_path}`` - the targets a "continue" / reference question is
    about. Used by the edit-intent gate so intent is inherited from history
    only when the current question actually points at a pending proposal
    (M9 follow-up, Aug 14: an unrelated later question must never inherit the
    edit frame from an old turn that used a change verb). Empty list when
    there are none."""
    from sqlalchemy import select

    from app.db import SessionLocal
    from app.models import Edit

    db = SessionLocal()
    try:
        rows = db.scalars(
            select(Edit).where(Edit.scan_id == scan_id, Edit.status == "proposed")
        ).all()
    finally:
        db.close()
    return [{"id": e.id, "file_path": e.file_path} for e in rows]


def _is_edit_continuation(question: str, pending_edits: list[dict]) -> bool:
    """True when ``question`` is a continuation of a PRIOR edit task - a bare
    continue/next cue, or a reference to one of the scan's pending proposals
    (a pending file path, or the edit/proposal vocabulary). Only then may
    edit intent be inherited from history (a prior turn's change verb) - an
    unrelated question in the same session never is."""
    q = question.strip()
    if _EDIT_CONTINUATION_RE.match(q):
        return True
    if _EDIT_REFERENCE_RE.search(q):
        return True
    for p in pending_edits:
        if p["file_path"] in q:
            return True
    return False


def answer_question(
    scan_id: int,
    question: str,
    *,
    max_tool_rounds: int | None = None,
    temperature: float = 0.2,
    timeout: float | None = None,
    stream: bool = False,
    on_event: Callable[[AgentEvent], None] | None = None,
    mentioned_files: list[str] | None = None,
    history: list[dict] | None = None,
    # M9.1 Phase C: the owning user's id - the chat loop resolves the USER's
    # model/search stores (``get_store`` / ``get_search_store`` read
    # ``request_ctx.current_user_id``). Set here (not by the caller's
    # thread) because the /chat/stream route runs this on a WORKER thread
    # that does not inherit the request thread's contextvars; None = system
    # store (agent-level callers, auth-off mode).
    user_id: int | None = None,
    # M9.1 vault: the user's unwrapped master key, captured on the request
    # thread and set here for the worker thread (same rationale as
    # ``user_id``) so the agent's model/search reads can decrypt the
    # at-rest key blobs. None = system store / auth-off / vault locked.
    master_key: bytes | None = None,
) -> AgentResult:
    """Answer a question over Layers 1-3 (findings context + tools).

    The Layer 1 context is always present; tools are used only when the model
    emits tool calls. Returns cited answer + resolved citations + the tool
    run trace (``tool_runs``).

    ``history`` is the recent client-side thread (``{role, content}`` turns)
    injected before the current question - the backend never persists chat,
    so a follow-up like "continue the edit task" needs the original request
    to stay coherent. Capped in chat.py (turns + total chars).

    ``timeout`` is a hard *overall* deadline in seconds for the whole loop
    (default ``settings.chat_timeout_seconds``). Each round passes only the
    remaining budget to the model client, so the no-tools fallback retry
    cannot double the hang. Raises ``AgentTimeout`` when the budget is
    exhausted before an answer arrives.

    ``stream=True`` switches the model calls to ``chat_stream``: content
    tokens are forwarded live via ``on_event`` (kind ``token``), and every
    executed tool call emits ``tool_start``/``tool_end`` events around its
    execution - the same loop, just observable (the dock's live steps).
    ``on_event`` is also honored when ``stream=False`` for the tool events,
    so callers can build a trace without token streaming.

    Trivial greetings ("hi", "hello") are answered with a canned reply - no
    LLM call, no backend pick. If the loop ends without a text answer (the
    model only emitted tool calls), one final plain-chat attempt is made with
    the original grounded prompt (the documented context-only fallback) before
    the graceful "tool-call limit" message is returned.
    """
    # Trivial greetings get a canned answer - no backend pick, no LLM call,
    # no tool loop. Regression: 'hi' used to make the model emit tool calls
    # every round, burn the whole budget, and come back as the confusing
    # "could not complete within the tool-call limit" message.
    # M9.1 Phase C: resolve the per-user stores AND the vault key for THIS
    # thread (the worker thread the stream route spawns does not inherit the
    # request thread's contextvars, so the explicit args land here).
    if user_id is not None:
        current_user_id.set(user_id)
        current_master_key.set(master_key)

    if _GREETING_RE.match(question.strip()):
        return AgentResult(
            answer=_GREETING_ANSWER,
            citations=[],
            sources=[],
            tools_used=[],
            tool_mode=TOOL_MODE_CONTEXT,
        )

    on_token = (lambda delta: _emit(on_event, "token", {"delta": delta})) if on_event else None

    from app.agent.tools import edit_tools_allowed, execute_tool, web_tools_allowed
    from app.config import settings

    context = _load_context(scan_id)
    backend = _pick_chat_backend()

    if timeout is None:
        timeout = float(settings.chat_timeout_seconds)
    deadline = time.monotonic() + timeout

    # M6 Phase C: max_tool_rounds is a settings knob (same pattern as
    # chat_timeout_seconds) - the per-call default comes from settings, an
    # explicit argument wins.
    if max_tool_rounds is None:
        max_tool_rounds = int(settings.max_tool_rounds)

    # M7: both gates - the scan's web-research opt-in AND an Active search
    # engine. When they hold, the web tools are offered (and the system
    # prompt tells the model when to use them + to cite URLs).
    web_allowed = web_tools_allowed(scan_id)
    # M8 Phase D: edit tools only when the scan is Android AND the on-demand
    # apktool decode is ready - same never-even-offered rule (the model gets
    # the review contract explained when they ARE available).
    edit_allowed = edit_tools_allowed(scan_id)
    system_prompt = SYSTEM_PROMPT + (_WEB_PROMPT if web_allowed else "")
    if edit_allowed:
        system_prompt += _M8_EDIT_PROMPT
    # M8 follow-up: user @-mentions - the mentioned files' content is attached
    # so the model answers/proposes about them directly (no search round).
    mentioned_section = _load_mentioned_files(scan_id, mentioned_files or [])
    # M8 follow-up (Aug 12): the EDIT REVIEW STATE section - the scan's
    # proposals + verdicts - so a "continue" turn knows what was applied /
    # rejected and proposes the next file of the original task. Only when
    # the edit tools exist for this scan.
    review_state = _load_edit_review_state(scan_id) if edit_allowed else ""

    messages: list[dict] = [
        {
            "role": "system",
            "content": (
                system_prompt
                + "\n\n"
                + context.rendered
                + mentioned_section
                + review_state
            ),
        },
    ]
    # M8 follow-up: the client-side thread re-sent with a follow-up - recent
    # user/assistant turns before the current question, capped so a long dock
    # thread can't balloon the prompt. Lets "continue the edit task" keep the
    # original request ("bypass the root check") without server persistence.
    total = 0
    for turn in (history or [])[-_MAX_HISTORY_TURNS:]:
        role = turn.get("role") if isinstance(turn, dict) else None
        content = (turn.get("content") if isinstance(turn, dict) else "") or ""
        content = content.strip()
        if role not in ("user", "assistant") or not content:
            continue
        if total >= _MAX_HISTORY_CHARS:
            break
        content = content[:4000]
        total += len(content)
        messages.append({"role": role, "content": content})
    messages.append({"role": "user", "content": question})
    # The original grounded prompt - used by the exhaustion fallback so the
    # final plain-chat call never carries tool-role messages a server may
    # reject without a `tools` parameter.
    prompt = list(messages)
    # M6 Phase B: offer only the tools that exist for this scan's platform
    # (iOS never sees get_decompiled_class). M7: plus the web tools when the
    # two gates hold. M8: plus the edit tools when the scan is Android AND
    # decode-ready.
    tools = schemas_for_platform(
        context.platform,
        web_research_enabled=web_allowed,
        edit_tools_enabled=edit_allowed,
    )
    tools_used: list[str] = []
    tool_runs: list[ToolRun] = []
    final_text = ""
    narration_nudges = 0
    # M8 follow-up (Aug 12): edit-task loop state. ``edit_intent`` - the
    # question asks to change code AND the edit tools exist - gates the
    # "ends on read" nudge so normal Q&A is never pushed to propose.
    # ``proposals_this_turn`` / ``edit_reads_this_turn`` track the executed
    # tools; ``edit_nudges`` bounds the nudge like narration. A bare
    # "continue" follow-up has no change verb of its own - inherit the
    # intent from the client-side history (the original edit request) so the
    # nudge keeps guarding the sequential flow across turns.
    # M9 follow-up (Aug 14): the inheritance is now GATED on an actual
    # continuation - the current question is a continue/next cue or references
    # a pending proposal (``_is_edit_continuation``) AND some prior turn used
    # a change verb. An unrelated later question in the same session (e.g.
    # "why is the app debuggable?" after an earlier "bypass the root check")
    # never inherits the edit frame, so the nudge cannot push it into
    # proposing an edit it was never asked for.
    pending_edits = _load_pending_edits(scan_id) if edit_allowed else []
    edit_intent = edit_allowed and bool(
        _EDIT_INTENT_RE.search(question)
        or (
            _is_edit_continuation(question, pending_edits)
            and any(
                _EDIT_INTENT_RE.search(str(t.get("content") or ""))
                for t in (history or [])
                if isinstance(t, dict)
            )
        )
    )
    proposals_this_turn = 0
    edit_reads_this_turn = 0
    edit_nudges = 0

    cancel = _register_cancel(scan_id)
    try:
        for _round in range(max_tool_rounds + 1):
            # Stop button: checked at every round boundary so an interrupt
            # lands before the next (expensive) LLM call.
            _raise_if_cancelled(scan_id, cancel)
            remaining = _deadline_remaining(deadline, scan_id, timeout)
            try:
                response = _model_round(
                    backend,
                    messages,
                    temperature=temperature,
                    timeout=remaining,
                    tools=tools,
                    stream=stream,
                    on_token=on_token,
                )
            except Exception:
                # Some backends reject the tools kwarg - degrade to plain chat,
                # but only with the *freshly* remaining budget. If the first call
                # already burned it (hung upstream), stop rather than retry - the
                # worker block stays bounded by the overall deadline.
                remaining = _deadline_remaining(deadline, scan_id, timeout)
                try:
                    response = _model_round(
                        backend,
                        messages,
                        temperature=temperature,
                        timeout=remaining,
                        tools=None,
                        stream=stream,
                        on_token=on_token,
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
                # M8 follow-up (Aug 11): plan narration must not be the final
                # answer. When the content describes an intended tool action
                # but emitted no call, nudge (bounded) and continue - the
                # assistant message is still recorded so the follow-up prompt
                # stays coherent, and the model's next round can actually run
                # the search/read and roll up a grounded answer. Guard: a
                # content that already cites `file:line` is a real answer, not
                # narration ("…com/app/W.java:42. Let's also check the
                # manifest." must not be re-opened).
                if (
                    narration_nudges < _MAX_NARRATION_NUDGES
                    and content
                    and not _CITE_RE.search(content)
                    and _NARRATION_INTENT_RE.search(content)
                ):
                    narration_nudges += 1
                    messages.append({"role": "assistant", "content": content or None})
                    messages.append({"role": "user", "content": _NARRATION_NUDGE})
                    # Clear any earlier round's `final_text` (e.g. narration
                    # that accompanied a tool call). If the loop then exhausts
                    # its round budget instead of breaking with a real answer,
                    # an empty final_text falls through to the grounded
                    # plain-chat fallback rather than returning stale
                    # plan-narration (review catch, Aug 11).
                    final_text = ""
                    continue
                # M8 follow-up (Aug 12): the "ends on read" fix - a change
                # request whose model searched/read the code but wrote a
                # summary without ever proposing. Nudge (bounded) toward
                # propose_smali_edit; the nudge explicitly allows a read-only
                # explanation so an unchangeable target isn't forced.
                if (
                    edit_intent
                    and proposals_this_turn == 0
                    and edit_reads_this_turn > 0
                    and edit_nudges < _MAX_EDIT_NUDGES
                    and content
                ):
                    edit_nudges += 1
                    messages.append({"role": "assistant", "content": content or None})
                    messages.append({"role": "user", "content": _EDIT_PROPOSE_NUDGE})
                    final_text = ""
                    continue
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
                    if name in _EDIT_READ_TOOLS:
                        edit_reads_this_turn += 1
                _emit(
                    on_event,
                    "tool_start",
                    {"id": call_id, "name": name, "args": args},
                )
                started = time.monotonic()
                result = (
                    execute_tool(scan_id, name, args)
                    if name
                    else json.dumps({"error": "malformed tool call"})
                )
                # M8 follow-up: a SUCCESSFUL propose_smali_edit counts for the
                # edit-task nudges (the sequential flow: one proposal per turn,
                # then the human reviews and says "continue").
                if name == "propose_smali_edit":
                    try:
                        parsed = json.loads(result)
                    except json.JSONDecodeError:
                        parsed = None
                    if isinstance(parsed, dict) and "error" not in parsed:
                        proposals_this_turn += 1
                duration_ms = int((time.monotonic() - started) * 1000)
                status, preview, error, count = _classify_tool_result(result)
                tool_runs.append(
                    ToolRun(
                        id=call_id,
                        name=name or "unknown",
                        args=args,
                        status=status,
                        duration_ms=duration_ms,
                        result_preview=preview,
                        error=error,
                        count=count,
                    )
                )
                _emit(
                    on_event,
                    "tool_end",
                    {
                        "id": call_id,
                        "name": name,
                        "status": status,
                        "duration_ms": duration_ms,
                        "result_preview": preview,
                        "error": error,
                        "count": count,
                    },
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
        # attempt with the original grounded prompt - no tools - bounded by the
        # remaining budget. This is the documented context-only fallback, and
        # it fixes trivial prompts that used to end in "tool-call limit".
        remaining = _deadline_remaining(deadline, scan_id, timeout)
        try:
            response = _model_round(
                backend,
                prompt,
                temperature=temperature,
                timeout=remaining,
                tools=None,
                stream=stream,
                on_token=on_token,
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

    return _build_result(scan_id, final_text, tools_used, tool_runs)


# ---- citation resolution ------------------------------------------------------

_CITE_RE = re.compile(
    r"([A-Za-z0-9_./-]+\.(?:java|xml|kt|kts|smali|swift|m|h|plist|json|txt|"
    r"properties|yml|yaml|html|strings|entitlements)):(\d+)"
)
_MAX_CITATIONS = 5


def _extract_citations(answer: str) -> list[tuple[str, int]]:
    return [(m.group(1), int(m.group(2))) for m in _CITE_RE.finditer(answer)]


def _build_result(
    scan_id: int,
    answer: str,
    tools_used: list[str],
    tool_runs: list[ToolRun] | None = None,
) -> AgentResult:
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
        # M6 Phase B: surfaced on ChatResponse so the dock can show whether
        # tools ran this turn. tools_used is non-empty iff the model emitted
        # at least one tool call that dispatched.
        tool_mode=TOOL_MODE_TOOLS if tools_used else TOOL_MODE_CONTEXT,
        tool_runs=tool_runs or [],
    )
