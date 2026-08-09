"""Dev-only deterministic fake LLM (M6 follow-up) — demo the Agent dock's
live tool steps + token streaming with zero Ollama.

``MASA_FAKE_MODEL=1`` (``Settings.fake_model_enabled``) seeds a ``fake``
backend into the M3 store; ``model/client.py`` short-circuits its chat calls
here. The fake never touches a real server — instead it scripts one
deterministic turn that still runs the REAL agent loop + REAL tools:

  round 1: a little \"thinking aloud\" text (streamed tokens), then two tool
           calls — ``search_code`` (the pattern split across two streamed
           deltas on purpose, so the demo also exercises the defensive
           tool-call accumulation path) and ``read_manifest``. Both execute
           against the scan's real tree, so the steps show real hit counts.
  round 2: a final answer composed from the REAL tool results — it cites the
           actual first search hit (``file:line`` -> clickable src-chip) when
           one exists, and mentions the manifest summary otherwise.

The script itself is constant; only the scan's real data shapes the final
text. Calls without a ``tools`` kwarg (insights explain/summary, the
plain-chat fallback) get a canned plain answer. ``health`` short-circuits the
Settings probe for the fake so the card renders green.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

FAKE_MODEL = "demo"

# Deterministic script constants.
_THINK_TEXT = (
    "Let me search the decompiled source for WebView usage, "
    "then check what the manifest declares."
)
# search_code arguments split across two streamed chunks — the demo exercises
# _accumulate_tool_call_deltas' concatenation exactly like a real local server.
_TOOL_CALLS_STREAM = [
    {
        "index": 0,
        "id": "call_search",
        "function": {"name": "search_code", "arguments": '{"pattern": "WebV'},
    },
    {"index": 0, "function": {"arguments": 'iew"}'}},
    {
        "index": 1,
        "id": "call_manifest",
        "function": {"name": "read_manifest", "arguments": "{}"},
    },
]
_PLAIN_ANSWER = (
    "This is a dev-demo answer from the built-in fake model "
    "(MASA_FAKE_MODEL=1) — no LLM was contacted. It streams like a real "
    "answer so the dock's token + tool-step UI can be verified without "
    "Ollama running."
)


def is_fake(backend) -> bool:
    """True for the dev-only fake backend (short-circuit target)."""
    return getattr(backend, "provider_id", None) == "fake"


def _has_tool_results(messages: list[dict]) -> bool:
    """True once a prior round's tool result is in the conversation — the
    fake's round 2 (compose the final answer from real tool results)."""
    return any(m.get("role") == "tool" for m in messages)


def _tool_results(messages: list[dict]) -> list[dict]:
    """The JSON-decoded tool-role contents, in order."""
    out = []
    for m in messages:
        if m.get("role") != "tool":
            continue
        try:
            out.append(json.loads(m.get("content") or ""))
        except (json.JSONDecodeError, TypeError):
            out.append({})
    return out


def _compose_answer(messages: list[dict]) -> str:
    """The final answer, derived from the REAL tool results.

    ``search_code`` returns ``[{file, line, snippet}]`` — cite the first hit
    so the dock renders a clickable file:line chip that jumps the Decompiler
    tab (the same path a real model's citation takes). ``read_manifest``
    returns a JSON object — surface a one-line summary as a fallback so even
    a no-hit scan (iOS) gets a real, grounded answer.
    """
    search_hits: list[dict] = []
    manifest: dict = {}
    for result in _tool_results(messages):
        # A failed tool comes back as {"error": ...} — never mistake it for
        # manifest data (review catch: a broken read_manifest used to render
        # as "the manifest summary is available").
        if isinstance(result, dict) and "error" in result:
            continue
        has_file = (
            isinstance(result, list)
            and result
            and isinstance(result[0], dict)
            and "file" in result[0]
        )
        if has_file:
            search_hits = result
        elif isinstance(result, dict) and result:
            manifest = result

    if search_hits:
        top = search_hits[0]
        snippet = (top.get("snippet") or "").strip()[:120]
        line = top.get("line")
        loc = f"{top['file']}:{line}" if line else top["file"]
        text = (
            "I found WebView usage in the decompiled source. The first match "
            f"is in `{loc}` — `{snippet}`. "
            "This is a dev-demo answer from the built-in fake model "
            "(MASA_FAKE_MODEL=1); no LLM was contacted."
        )
        return text
    if manifest:
        package = manifest.get("package") or manifest.get("bundle_identifier")
        head = "The search found no source-level WebView match, but the "
        head += "manifest summary is available"
        if package:
            head += f" (package/bundle `{package}`)"
        return (
            head + ". This is a dev-demo answer from the built-in fake model "
            "(MASA_FAKE_MODEL=1); no LLM was contacted."
        )
    return _PLAIN_ANSWER


def _chunk(content=None, tool_calls=None):
    """One litellm-shaped streaming chunk (OpenAI delta shape)."""
    return SimpleNamespace(
        choices=[SimpleNamespace(delta=SimpleNamespace(content=content, tool_calls=tool_calls))]
    )


def _tool_call(call_id: str, name: str, arguments: str):
    return SimpleNamespace(
        id=call_id, type="function", function=SimpleNamespace(name=name, arguments=arguments)
    )


def fake_chat_response(messages: list[dict], tools: list[dict] | None):
    """Buffered-shape response (``.choices[0].message``) for the fake.

    Mirrors ``_stream_round``'s script: tools offered + no results yet ->
    thinking content + two tool calls; tools offered + results present ->
    composed answer; no tools (plain chat/insights) -> canned plain answer.
    """
    if tools is None:
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=_PLAIN_ANSWER))]
        )
    if _has_tool_results(messages):
        return SimpleNamespace(
            choices=[
                SimpleNamespace(message=SimpleNamespace(content=_compose_answer(messages)))
            ]
        )
    return SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(
                    content=_THINK_TEXT,
                    tool_calls=[
                        _tool_call("call_search", "search_code", '{"pattern": "WebView"}'),
                        _tool_call("call_manifest", "read_manifest", "{}"),
                    ],
                )
            )
        ]
    )


def fake_stream_chunks(messages: list[dict], tools: list[dict] | None):
    """Yield litellm-shaped streaming chunks for the fake backend."""
    if tools is None:
        for word in _PLAIN_ANSWER.split(" "):
            yield _chunk(content=word + " ")
        return
    if _has_tool_results(messages):
        for word in _compose_answer(messages).split(" "):
            yield _chunk(content=word + " ")
        return
    # Round 1: thinking tokens, then the two tool calls (args split across
    # deltas — the same incremental accumulation shape litellm normalizes).
    for word in _THINK_TEXT.split(" "):
        yield _chunk(content=word + " ")
    for delta in _TOOL_CALLS_STREAM:
        yield _chunk(tool_calls=[delta])
