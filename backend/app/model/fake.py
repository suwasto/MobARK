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

# M7: the web-research demo script — used when the offered tool set includes
# the gated web tools (scan opt-in on + Active engine). Mirrors the flagship
# "does library X have known CVEs?" case with REAL tools against REAL search
# results: round 1 streams thinking + web_search (the query is the USER'S OWN
# question text, so a manual test can type its own search), round 2
# web_fetch's the top hit's URL, round 3 composes the answer citing the
# source URL — from the page when it read cleanly, else from the search
# results themselves (a bot-hostile page must never be retried until the
# round limit; hit live in the containerized e2e, Aug 9: medium.com 403s the
# honest MASA UA).
_WEB_THINK_TEXT = (
    "This needs current external information — let me search the web for "
    "known advisories, then read the top source."
)
# Fallback query when the user's question is empty / too short to search.
_WEB_SEARCH_QUERY = "InsecureBankv2 known vulnerabilities CVE"


def _web_query(messages: list[dict]) -> str:
    """The round-1 web_search query: the user's ACTUAL question text when it's
    a plausible query (>=4 chars), else the canned demo query — so a manual
    web-search test types its own search and the fake runs it verbatim (a
    real model would paraphrase; the fake is a script)."""
    for m in reversed(messages):
        if m.get("role") == "user" and (m.get("content") or "").strip():
            q = m["content"].strip()
            return q if len(q) >= 4 else _WEB_SEARCH_QUERY
    return _WEB_SEARCH_QUERY


def _offers_web(tools: list[dict] | None) -> bool:
    """True when the offered tool schemas include the gated web tools."""
    if not tools:
        return False
    return any(
        (t.get("function") or {}).get("name") == "web_search" for t in tools
    )


def _compose_web_answer(messages: list[dict]) -> str:
    """Final web-research answer from the REAL tool results: cite the fetched
    page (title + first text + final URL) when available, else the top search
    result — so the demo renders clickable URLs, like a real model's answer.
    A failed page read is acknowledged but never rendered as evidence."""
    results: list[dict] = []
    page: dict = {}
    fetch_failed = False
    for result in _tool_results(messages):
        if isinstance(result, dict) and "error" in result:
            fetch_failed = True
            continue  # a failed tool must never render as evidence
        if isinstance(result, list) and result and isinstance(result[0], dict):
            if "url" in result[0]:
                results = result
        elif isinstance(result, dict) and "url" in result and "text" in result:
            page = result
    tail = (
        "This is a dev-demo answer from the built-in fake model "
        "(MASA_FAKE_MODEL=1); no LLM was contacted."
    )
    if page:
        title = page.get("title") or page.get("url")
        excerpt = (page.get("text") or "").strip()[:220]
        return (
            "I researched this via web search and read the top advisory. "
            f"**{title}** — {excerpt} Source: {page.get('url')}. " + tail
        )
    if results:
        top = results[0]
        blocked = (
            " (the top page blocked direct reading, so I'm citing the search "
            "result itself)"
            if fetch_failed
            else ""
        )
        return (
            f"Web search returned {len(results)} results; the top one is "
            f"`{top.get('title')}` ({top.get('url')}){blocked}. " + tail
        )
    return _PLAIN_ANSWER


def _web_response(messages: list[dict]):
    """Buffered round response for the web-research demo script.

    Deterministic 3-round shape (fits the default ``max_tool_rounds=3``):
    round 1 issues ``web_search``; round 2 fetches the TOP result once;
    round 3 composes the final cited answer — from the fetched page when it
    read cleanly, else from the search results themselves. A failed fetch
    (e.g. HTTP 403 from a bot-hostile page like medium.com — hit live in the
    containerized e2e, Aug 9) is NEVER retried on the same URL: the old
    script re-fetched it until the round limit and the answer lost its
    citation.
    """
    results = _tool_results(messages)
    search_rows: list[dict] = []
    fetch_tried = False
    for r in results:
        if isinstance(r, list) and r and isinstance(r[0], dict) and "url" in r[0]:
            search_rows = r
        elif isinstance(r, dict) and ("text" in r or "error" in r):
            fetch_tried = True  # a page read OR a failed fetch attempt
    if not search_rows and not fetch_tried:
        # No results yet (or the first search came back empty) — search with
        # the user's own question text (manual tests type their query).
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content=_WEB_THINK_TEXT,
                        tool_calls=[
                            _tool_call(
                                "call_search",
                                "web_search",
                                json.dumps({"query": _web_query(messages)}),
                            )
                        ],
                    )
                )
            ]
        )
    if search_rows and not fetch_tried:
        # Round 2: fetch the top result exactly once.
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content="Now reading the top advisory.",
                        tool_calls=[
                            _tool_call(
                                "call_fetch",
                                "web_fetch",
                                json.dumps({"url": search_rows[0]["url"]}),
                            )
                        ],
                    )
                )
            ]
        )
    # Round 3 (fetch attempted — success OR failure): compose the answer.
    return SimpleNamespace(
        choices=[
            SimpleNamespace(message=SimpleNamespace(content=_compose_web_answer(messages)))
        ]
    )


def _web_stream_chunks(messages: list[dict]):
    """Streaming chunks for the web-research demo script (same round logic as
    ``_web_response``, tokenized for the SSE demo)."""
    resp = _web_response(messages)
    message = resp.choices[0].message
    content = message.content or ""
    tool_calls = list(getattr(message, "tool_calls", None) or [])
    for word in content.split(" "):
        yield _chunk(content=word + " ")
    for tc in tool_calls:
        fn = tc.function
        yield _chunk(
            tool_calls=[
                {
                    "index": 0,
                    "id": tc.id,
                    "function": {"name": fn.name, "arguments": fn.arguments},
                }
            ]
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

    Script selection: web tools offered (M7 scan opt-in + Active engine) ->
    the web-research demo (web_search -> web_fetch -> cited answer);
    otherwise tools offered + no results yet -> thinking content + two tool
    calls; tools offered + results present -> composed answer; no tools
    (plain chat/insights) -> canned plain answer.
    """
    if tools is None:
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=_PLAIN_ANSWER))]
        )
    if _offers_web(tools):
        return _web_response(messages)
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
    if _offers_web(tools):
        yield from _web_stream_chunks(messages)
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
