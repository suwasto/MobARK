"""Layers 1-3 + M6 chat orchestration - client_chat monkeypatched, no
network, no LLM.

Ollama is off during development (owner decision): every test here is a
mocked unit test; live-model acceptance is manual.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from app.agent import chat as chat_mod
from app.agent.chat import ChatNotConfigured, answer_question
from app.models import Edit, Finding, Scan


@pytest.fixture()
def env(monkeypatch, db_session_factory, tmp_path):
    monkeypatch.setattr("app.config.settings.data_dir", tmp_path)
    monkeypatch.setattr("app.db.SessionLocal", db_session_factory)
    with db_session_factory() as session:
        scan = Scan(filename="app.apk", platform="android", status="done")
        session.add(scan)
        session.commit()
        scan_id = scan.id
        session.add(
            Finding(
                scan_id=scan_id,
                tool="semgrep",
                title="WebView with JavaScript enabled",
                severity="medium",
                file_path="com/app/W.java",
                line_number=42,
                category="MASVS-PLATFORM-2",
            )
        )
        session.commit()
    root = tmp_path / "work" / str(scan_id) / "decompiled" / "sources"
    (root / "com/app").mkdir(parents=True)
    # WebView client class lands on line 42 so citations resolve to a snippet.
    lines = [f"// {i}" for i in range(1, 42)]
    lines.append("public class W extends WebViewClient {")
    lines.append("  void m() {}")
    lines.append("}")
    (root / "com/app/W.java").write_text("\n".join(lines) + "\n")
    return scan_id


def _msg(content, tool_calls=None):
    return SimpleNamespace(content=content, tool_calls=tool_calls)


def _resp(message):
    return SimpleNamespace(choices=[SimpleNamespace(message=message)])


def _tool_call(call_id, name, arguments):
    return SimpleNamespace(id=call_id, function=SimpleNamespace(name=name, arguments=arguments))


def test_answer_without_tool_calls_uses_findings_context(env, monkeypatch):
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    captured = {}

    def fake_chat(backend, messages, **kwargs):
        captured["messages"] = messages
        captured["tools"] = kwargs.get("tools")
        return _resp(_msg("The WebView client is defined in com/app/W.java:42."))

    monkeypatch.setattr(chat_mod, "client_chat", fake_chat)

    result = answer_question(scan_id, "where is the webview client?")

    assert "com/app/W.java:42" in result.answer
    assert result.citations[0].file == "com/app/W.java"
    assert result.citations[0].line == 42
    assert result.citations[0].snippet == "public class W extends WebViewClient {"
    assert result.sources == ["com/app/W.java"]
    assert result.tools_used == []
    assert result.tool_mode == "context-only"  # M6 Phase B

    # Layer 1 context is in the system message, precision-tagged, full set.
    system = captured["messages"][0]["content"]
    assert "FINDINGS CONTEXT" in system
    assert "WebView with JavaScript enabled" in system
    assert "[file/line]" in system
    assert captured["tools"]  # tool schemas offered


def test_mentioned_files_content_attached_to_context(env, monkeypatch):
    """M8 follow-up: the dock's @-mentions. ChatRequest.mentioned_files
    paths get their current content attached to the system prompt (the
    USER-MENTIONED FILES section) so the model answers about them directly -
    no search round needed."""
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    captured = {}

    def fake_chat(backend, messages, **kwargs):
        captured["messages"] = messages
        return _resp(_msg("It is the WebView client."))

    monkeypatch.setattr(chat_mod, "client_chat", fake_chat)

    result = answer_question(
        scan_id,
        "@com/app/W.java what does this class do?",
        mentioned_files=["sources/com/app/W.java"],
    )

    assert result.answer == "It is the WebView client."
    system = captured["messages"][0]["content"]
    assert "USER-MENTIONED FILES" in system
    assert "sources/com/app/W.java" in system
    assert "public class W extends WebViewClient" in system  # the content
    # The raw mention stays in the user message for the model to cite.
    assert "@com/app/W.java" in captured["messages"][1]["content"]


def test_mentioned_files_deduped(env, monkeypatch):
    """The same path mentioned twice must render its content ONCE in the
    context (a raw API caller could otherwise double the prompt spend)."""
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    captured = {}

    def fake_chat(backend, messages, **kwargs):
        captured["messages"] = messages
        return _resp(_msg("ok"))

    monkeypatch.setattr(chat_mod, "client_chat", fake_chat)

    result = answer_question(
        scan_id,
        "@com/app/W.java what is this?",
        mentioned_files=["sources/com/app/W.java", "sources/com/app/W.java"],
    )

    assert result.answer == "ok"
    system = captured["messages"][0]["content"]
    assert system.count("public class W extends WebViewClient") == 1


def test_mentioned_files_missing_path_degrades_to_note(env, monkeypatch):
    """A mentioned path that doesn't exist must degrade to an inline note -
    never a crash (the model sees '[could not load ...]')."""
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    captured = {}

    def fake_chat(backend, messages, **kwargs):
        captured["messages"] = messages
        return _resp(_msg("ok"))

    monkeypatch.setattr(chat_mod, "client_chat", fake_chat)

    result = answer_question(
        scan_id,
        "@sources/com/app/Nope.java what is this?",
        mentioned_files=["sources/com/app/Nope.java"],
    )

    assert result.answer == "ok"
    system = captured["messages"][0]["content"]
    assert "could not load" in system
    assert "sources/com/app/Nope.java" in system


def test_answer_tool_loop_appends_tool_results(env, monkeypatch):
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    batches: list[list[dict]] = []
    responses = iter(
        [
            _resp(
                _msg(
                    None,
                    tool_calls=[
                        _tool_call("c1", "search_code", json_args({"pattern": "WebView"})),
                    ],
                )
            ),
            _resp(_msg("Found it in com/app/W.java:42.")),
        ]
    )

    def fake_chat(backend, messages, **kwargs):
        batches.append(list(messages))
        return next(responses)

    monkeypatch.setattr(chat_mod, "client_chat", fake_chat)

    result = answer_question(scan_id, "where is the webview?")

    assert result.tools_used == ["search_code"]
    assert "com/app/W.java:42" in result.answer
    # second batch carries the assistant tool_call + the tool result
    roles = [m["role"] for m in batches[1]]
    assert "tool" in roles
    tool_msg = next(m for m in batches[1] if m["role"] == "tool")
    assert tool_msg["tool_call_id"] == "c1"
    assert "com/app/W.java" in tool_msg["content"]
    # assistant tool_call message kept for the follow-up
    asst = next(m for m in batches[1] if m["role"] == "assistant")
    assert asst["tool_calls"][0]["function"]["name"] == "search_code"


def test_tool_error_surfaces_as_json_not_crash(env, monkeypatch):
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    batches: list[list[dict]] = []
    responses = iter(
        [
            _resp(
                _msg(
                    None,
                    tool_calls=[
                        _tool_call("c1", "search_code", json_args({"pattern": "("})),
                    ],
                )
            ),
            _resp(_msg("I could not run that search.")),
        ]
    )

    def fake_chat(backend, messages, **kwargs):
        batches.append(list(messages))
        return next(responses)

    monkeypatch.setattr(chat_mod, "client_chat", fake_chat)
    result = answer_question(scan_id, "search for (")
    assert "I could not run that search." == result.answer
    tool_msg = next(m for m in batches[1] if m["role"] == "tool")
    assert '"error"' in tool_msg["content"]


def test_agent_timeout_raises_when_budget_exhausted(env, monkeypatch):
    """A hung LLM call can't exceed the overall deadline: an exhausted budget
    raises AgentTimeout (the API maps it to 504) instead of blocking."""
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    # Deterministic clock: every monotonic() read jumps +1000s. The remaining
    # budget at any round is timeout - jump = 120 - 1000 < 0 regardless of who
    # else reads the clock first (context load, backend store, …).
    clock = {"t": 0.0}

    def fast_forward():
        clock["t"] += 1000.0
        return clock["t"]

    monkeypatch.setattr(chat_mod.time, "monotonic", fast_forward)
    with pytest.raises(chat_mod.AgentTimeout, match="budget"):
        answer_question(scan_id, "what is the main risk?", timeout=120.0)


def test_fallback_gets_remaining_budget_not_full_timeout(env, monkeypatch):
    """Regression: when the tools call fails and the plain-chat fallback runs,
    it must receive the *remaining* budget - otherwise a hung call plus its
    retry doubles the block time."""
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    timeouts: list[float] = []
    call = {"n": 0}

    def flaky_chat(backend, messages, **kwargs):
        call["n"] += 1
        timeouts.append(kwargs.get("timeout"))
        if call["n"] == 1:
            raise RuntimeError("simulated hung/tool-rejecting call")
        return _resp(_msg("recovered."))

    monkeypatch.setattr(chat_mod, "client_chat", flaky_chat)
    result = answer_question(scan_id, "what is the storage risk?", timeout=60.0)
    assert result.answer == "recovered."
    assert len(timeouts) == 2
    first, fallback = timeouts
    assert 0 < fallback <= first <= 60.0


def test_fallback_skipped_when_first_call_exhausted_budget(env, monkeypatch):
    """Regression: if the tools call burns the whole budget (hung upstream),
    the plain-chat fallback must NOT retry - it raises AgentTimeout instead,
    keeping the worker block bounded by the deadline."""
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())

    def hung_chat(backend, messages, **kwargs):
        raise RuntimeError("simulated call that used the whole budget")

    monkeypatch.setattr(chat_mod, "client_chat", hung_chat)

    real_monotonic = chat_mod.time.monotonic
    clock = {"t": real_monotonic()}
    calls = {"n": 0}

    def hung_chat(backend, messages, **kwargs):
        calls["n"] += 1
        raise RuntimeError("simulated call that used the whole budget")

    monkeypatch.setattr(chat_mod, "client_chat", hung_chat)

    def stateful_clock():
        # Reads before the first client_chat attempt report a fresh clock;
        # any read after it (the except-path recompute) reports the budget
        # as already spent. Contamination-proof: deadline/remaining always
        # read t while the first call is pending.
        if calls["n"] == 0:
            return clock["t"]
        return clock["t"] + 1000.0

    monkeypatch.setattr(chat_mod.time, "monotonic", stateful_clock)
    with pytest.raises(chat_mod.AgentTimeout, match="budget"):
        answer_question(scan_id, "what is the main risk?", timeout=1.0)


def test_upstream_llm_failure_wrapped_not_raw(env, monkeypatch):
    """Regression: a model call that fails on both the tools attempt and the
    no-tools fallback must raise ChatUpstreamError carrying the upstream
    message - the API maps it to 502, not a raw 500 (the 500 the user saw
    when Ollama couldn't load the model)."""
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    calls = {"n": 0}

    def dead_chat(backend, messages, **kwargs):
        calls["n"] += 1
        raise RuntimeError("OllamaException - unknown model architecture: 'nanbeige'")

    monkeypatch.setattr(chat_mod, "client_chat", dead_chat)
    with pytest.raises(chat_mod.ChatUpstreamError, match="unknown model architecture"):
        answer_question(scan_id, "what is the main risk?", timeout=60.0)
    assert calls["n"] == 2  # tools call + plain-chat fallback both failed


def test_upstream_error_carries_arch_hint(env, monkeypatch):
    """The nanbeige-style error gets the shared actionable hint in the chat
    bubble too - not just in the Settings probe."""
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())

    def dead_chat(backend, messages, **kwargs):
        raise RuntimeError("OllamaException - unknown model architecture: 'nanbeige'")

    monkeypatch.setattr(chat_mod, "client_chat", dead_chat)
    with pytest.raises(chat_mod.ChatUpstreamError, match="upgrade Ollama"):
        answer_question(scan_id, "what is the main risk?", timeout=60.0)


def test_default_budget_from_settings(env, monkeypatch):
    """Omitted timeout falls back to settings.chat_timeout_seconds."""
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    import app.config

    monkeypatch.setattr(app.config.settings, "chat_timeout_seconds", 7)
    captured = {}

    def fake_chat(backend, messages, **kwargs):
        captured["timeout"] = kwargs.get("timeout")
        return _resp(_msg("ok"))

    monkeypatch.setattr(chat_mod, "client_chat", fake_chat)
    result = answer_question(scan_id, "what is the main risk?")
    assert result.answer == "ok"
    assert 0 < captured["timeout"] <= 7.0


def test_chat_not_configured_when_no_backend(env, monkeypatch):
    scan_id = env

    def no_backend():
        raise ChatNotConfigured("no chat model configured")

    monkeypatch.setattr(chat_mod, "_pick_chat_backend", no_backend)
    with pytest.raises(ChatNotConfigured, match="no chat model configured"):
        answer_question(scan_id, "what is the main risk?")


def test_citations_deduplicated_and_capped(env, monkeypatch):
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())

    def fake_chat(backend, messages, **kwargs):
        answer = " ".join("see com/app/W.java:42 and com/app/W.java:42" for _ in range(6))
        return _resp(_msg(answer))

    monkeypatch.setattr(chat_mod, "client_chat", fake_chat)
    result = answer_question(scan_id, "cite it many times")
    assert len(result.citations) == 1  # deduped
    assert result.citations[0].line == 42


# ---- M6 follow-up: streaming turns (token + tool events, on_event) ------------


def _chunk(content=None, tool_calls=None):
    """One litellm streaming chunk (OpenAI delta shape)."""
    return SimpleNamespace(
        choices=[
            SimpleNamespace(delta=SimpleNamespace(content=content, tool_calls=tool_calls))
        ]
    )


def _tc_delta(index, call_id=None, name=None, arguments=None):
    """One incremental tool-call delta (``function`` fields optional - arrive
    on the first chunk for the index, arguments concatenate across chunks)."""
    fn = {}
    if name:
        fn["name"] = name
    if arguments:
        fn["arguments"] = arguments
    delta = {"index": index, "function": fn}
    if call_id:
        delta["id"] = call_id
    return delta


def test_stream_emits_tokens_then_answer(env, monkeypatch):
    """stream=True forwards content tokens live and returns the accumulated
    answer - same result as the buffered path."""
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    events: list[chat_mod.AgentEvent] = []
    chunks = iter([_chunk(content="The "), _chunk(content="answer.")])
    monkeypatch.setattr(chat_mod, "chat_stream", lambda backend, messages, **kw: chunks)

    result = answer_question(scan_id, "what is the risk?", stream=True, on_event=events.append)

    tokens = "".join(e.payload["delta"] for e in events if e.kind == "token")
    assert tokens == "The answer."
    assert result.answer == "The answer."
    assert result.tool_mode == "context-only"
    assert result.tool_runs == []


def test_stream_accumulates_tool_call_and_emits_steps(env, monkeypatch):
    """Tool-call arguments split across chunks merge correctly, and the loop
    emits tool_start/tool_end around the execution with a recorded ToolRun."""
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    events: list[chat_mod.AgentEvent] = []
    chunks = iter(
        [
            _chunk(
                tool_calls=[
                    _tc_delta(0, call_id="c1", name="search_code", arguments='{"pat'),
                ]
            ),
            _chunk(tool_calls=[_tc_delta(0, arguments='tern": "WebView"}')]),
            _chunk(content="Found it in com/app/W.java:42."),
        ]
    )
    monkeypatch.setattr(chat_mod, "chat_stream", lambda backend, messages, **kw: chunks)

    result = answer_question(scan_id, "where is the webview?", stream=True, on_event=events.append)

    kinds = [e.kind for e in events]
    assert "tool_start" in kinds and "tool_end" in kinds
    start = next(e for e in events if e.kind == "tool_start")
    assert start.payload["id"] == "c1"
    assert start.payload["name"] == "search_code"
    assert start.payload["args"] == {"pattern": "WebView"}  # merged across chunks
    end = next(e for e in events if e.kind == "tool_end")
    assert end.payload["status"] == "ok"
    assert end.payload["count"] == 1  # one hit in com/app/W.java
    assert end.payload["duration_ms"] >= 0
    assert result.tools_used == ["search_code"]
    assert result.tool_mode == "tools"
    assert len(result.tool_runs) == 1
    run = result.tool_runs[0]
    assert run.name == "search_code" and run.status == "ok" and run.args == {"pattern": "WebView"}
    assert run.count == 1


def test_stream_tool_error_records_error_status(env, monkeypatch):
    """A tool that fails (ToolError -> {"error": ...}) ends its step as an
    error with the message - never a crash."""
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    events: list[chat_mod.AgentEvent] = []
    chunks = iter(
        [
            _chunk(
                tool_calls=[
                    _tc_delta(0, call_id="c1", name="search_code", arguments='{"pattern": "("}'),
                ]
            ),
            _chunk(content="the search failed"),
        ]
    )
    monkeypatch.setattr(chat_mod, "chat_stream", lambda backend, messages, **kw: chunks)

    result = answer_question(scan_id, "search for (", stream=True, on_event=events.append)

    end = next(e for e in events if e.kind == "tool_end")
    assert end.payload["status"] == "error"
    assert "invalid regex" in end.payload["error"]
    assert result.tool_runs[0].status == "error"
    assert "invalid regex" in result.tool_runs[0].error


def test_stream_defensive_tool_call_without_index(env, monkeypatch):
    """Malformed local-server deltas without an index still execute (fall
    back to the call id / position)."""
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    chunks = iter(
        [
            _chunk(
                tool_calls=[
                    {
                        "id": "c1",
                        "function": {"name": "search_code", "arguments": '{"pattern": "WebView"}'},
                    }
                ]
            ),
            _chunk(content="done"),
        ]
    )
    monkeypatch.setattr(chat_mod, "chat_stream", lambda backend, messages, **kw: chunks)
    result = answer_question(scan_id, "where?", stream=True)
    assert len(result.tool_runs) == 1
    assert result.tool_runs[0].name == "search_code"


def test_stream_fallback_on_tools_rejection_streams_too(env, monkeypatch):
    """If the backend rejects the tools kwarg mid-stream, the plain-chat
    fallback also streams tokens (same shape, same events)."""
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    events: list[chat_mod.AgentEvent] = []
    calls = {"n": 0}

    def flaky_stream(backend, messages, **kwargs):
        calls["n"] += 1
        if "tools" in kwargs:
            raise RuntimeError("backend rejects the tools kwarg")
        return iter([_chunk(content="recovered from fallback")])

    monkeypatch.setattr(chat_mod, "chat_stream", flaky_stream)
    result = answer_question(scan_id, "what is the risk?", stream=True, on_event=events.append)

    assert calls["n"] == 2  # tools call + plain fallback
    assert result.answer == "recovered from fallback"
    tokens = "".join(e.payload["delta"] for e in events if e.kind == "token")
    assert tokens == "recovered from fallback"


def test_stream_cancel_raises_interrupted_between_rounds(env, monkeypatch):
    """The Stop button's flag still stops a streaming turn at the next round
    boundary (token/tool events before it are fine - no half-answer)."""
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    calls = {"n": 0}

    def one_round_then_cancel(backend, messages, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            # Round 1 returns a tool call (forcing a round 2) and the cancel
            # lands before round 2's boundary check runs.
            chat_mod.request_cancel(scan_id)
            return iter(
                [
                    _chunk(
                        tool_calls=[
                            _tc_delta(
                                0,
                                call_id="c1",
                                name="search_code",
                                arguments='{"pattern": "WebView"}',
                            ),
                        ]
                    )
                ]
            )
        raise AssertionError("round 2 must never run after cancel")

    monkeypatch.setattr(chat_mod, "chat_stream", one_round_then_cancel)
    with pytest.raises(chat_mod.ChatInterrupted, match="interrupted"):
        answer_question(scan_id, "where is the webview?", stream=True)
    assert calls["n"] == 1
    assert scan_id not in chat_mod._CANCEL_FLAGS


# ---- M6: multi-step orchestration + tool_mode + platform filtering ------------


def test_multi_step_search_then_decompiled_class(env, monkeypatch):
    """Phase D multi-step: the fake model runs search_code FIRST, then reads
    the hit via get_decompiled_class, then answers - assert the ordered tool
    results reach the follow-up prompt and tools_used reflects both."""
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    batches: list[list[dict]] = []
    responses = iter(
        [
            _resp(
                _msg(
                    None,
                    tool_calls=[
                        _tool_call("c1", "search_code", json_args({"pattern": "WebView"})),
                    ],
                )
            ),
            _resp(
                _msg(
                    None,
                    tool_calls=[
                        _tool_call("c2", "get_decompiled_class", json_args({"fqcn": "com.app.W"})),
                    ],
                )
            ),
            _resp(_msg("The WebView client is com/app/W.java - see line 42.")),
        ]
    )

    def fake_chat(backend, messages, **kwargs):
        batches.append(list(messages))
        return next(responses)

    monkeypatch.setattr(chat_mod, "client_chat", fake_chat)

    result = answer_question(scan_id, "find the WebView class and read it")

    assert result.tools_used == ["get_decompiled_class", "search_code"]
    assert result.tool_mode == "tools"
    assert "com/app/W.java" in result.answer
    # the final prompt carries BOTH tool results in call order (the history
    # accumulates; earlier batches only hold the results seen so far)
    tool_msgs = [m for m in batches[-1] if m["role"] == "tool"]
    assert [m["tool_call_id"] for m in tool_msgs] == ["c1", "c2"]
    # the class source (from get_decompiled_class) reached the final prompt
    assert "public class W extends WebViewClient" in tool_msgs[1]["content"]


def test_flagship_question_uses_graph_query_first(env, monkeypatch, tmp_path):
    """Phase D flagship: 'where is certificate pinning located' - the fake
    model picks graph_query FIRST (Layer 3, not the context-only path); the
    graph result reaches the answer and is cited."""
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    graph_file = tmp_path / "graphs" / str(scan_id) / "graphify-out" / "graph.json"
    graph_file.parent.mkdir(parents=True)
    graph_file.write_text(json.dumps({"nodes": [{"id": "n1"}], "links": []}))

    from app.graph import graphify

    monkeypatch.setattr(
        graphify,
        "query",
        lambda p, q, budget=1500: {
            "found": True,
            "text": "certificate pinning: com/app/NetSec.java:12 uses CertificatePinner (okhttp)",
            "nodes": ["com/app/NetSec.java"],
            "via": "search",
        },
    )
    batches: list[list[dict]] = []
    responses = iter(
        [
            _resp(
                _msg(
                    None,
                    tool_calls=[
                        _tool_call(
                            "g1",
                            "graph_query",
                            json_args({"question": "where is certificate pinning located"}),
                        ),
                    ],
                )
            ),
            _resp(
                _msg(
                    "Certificate pinning is in com/app/NetSec.java:12 (okhttp CertificatePinner)."
                )
            ),
        ]
    )

    def fake_chat(backend, messages, **kwargs):
        batches.append(list(messages))
        return next(responses)

    monkeypatch.setattr(chat_mod, "client_chat", fake_chat)

    result = answer_question(scan_id, "where is certificate pinning located")

    assert result.tool_mode == "tools"
    assert result.tools_used == ["graph_query"]
    assert "com/app/NetSec.java:12" in result.answer
    assert any(c.file == "com/app/NetSec.java" and c.line == 12 for c in result.citations)
    tool_msg = next(m for m in batches[1] if m["role"] == "tool")
    assert "CertificatePinner" in tool_msg["content"]


def test_max_tool_rounds_knob_from_settings(env, monkeypatch):
    """M6 Phase C: max_tool_rounds defaults from settings - with the knob
    set to 1 the loop runs at most 2 tool rounds before the plain fallback."""
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    import app.config

    monkeypatch.setattr(app.config.settings, "max_tool_rounds", 1)
    rounds = {"n": 0}

    def always_tools(backend, messages, **kwargs):
        if "tools" in kwargs:
            rounds["n"] += 1
            return _resp(
                _msg(
                    None,
                    tool_calls=[
                        _tool_call("c1", "search_code", json_args({"pattern": "WebView"})),
                    ],
                )
            )
        return _resp(_msg("context-only answer"))

    monkeypatch.setattr(chat_mod, "client_chat", always_tools)
    result = answer_question(scan_id, "where is the webview?")
    assert rounds["n"] == 2  # settings knob (1) + the final no-tools round is separate
    assert result.answer == "context-only answer"
    assert result.tools_used == ["search_code"]


def test_max_tool_rounds_explicit_argument_wins(env, monkeypatch):
    """M6 Phase C: an explicit max_tool_rounds argument overrides settings."""
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    import app.config

    monkeypatch.setattr(app.config.settings, "max_tool_rounds", 1)
    rounds = {"n": 0}

    def always_tools(backend, messages, **kwargs):
        if "tools" in kwargs:
            rounds["n"] += 1
            return _resp(
                _msg(
                    None,
                    tool_calls=[
                        _tool_call("c1", "search_code", json_args({"pattern": "WebView"})),
                    ],
                )
            )
        return _resp(_msg("done"))

    monkeypatch.setattr(chat_mod, "client_chat", always_tools)
    result = answer_question(scan_id, "where is the webview?", max_tool_rounds=3)
    # the loop runs max_tool_rounds + 1 iterations, so 3 => 4 tool rounds
    assert rounds["n"] == 4
    assert result.answer == "done"


def test_any_model_gets_tools_offered_soft_gate(env, monkeypatch):
    """M6 Phase B soft gate: tools are offered to ANY configured model - the
    known-good list (Qwen2.5/2.5-coder, Llama 3.1+) is a documented
    recommendation, not a hard gate. An arbitrary (off-list) backend still
    receives the full platform tool schemas."""
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    captured = {}

    def fake_chat(backend, messages, **kwargs):
        captured["tools"] = kwargs.get("tools")
        return _resp(_msg("off-list model answers from context"))

    monkeypatch.setattr(chat_mod, "client_chat", fake_chat)
    result = answer_question(scan_id, "what is the main risk?")
    assert result.answer == "off-list model answers from context"
    names = {t["function"]["name"] for t in captured["tools"]}
    assert "search_code" in names and "read_manifest" in names


def test_ios_never_offered_get_decompiled_class(monkeypatch, db_session_factory, tmp_path):
    """M6 Phase B: an iOS scan's tool schemas exclude the Android-only class
    tool - the model can't waste a round on a guaranteed-failing call."""
    monkeypatch.setattr("app.config.settings.data_dir", tmp_path)
    monkeypatch.setattr("app.db.SessionLocal", db_session_factory)
    with db_session_factory() as session:
        scan = Scan(filename="app.ipa", platform="ios", status="done")
        session.add(scan)
        session.commit()
        scan_id = scan.id
    app_root = tmp_path / "work" / str(scan_id) / "bundle" / "Payload" / "Test.app"
    app_root.mkdir(parents=True)
    (app_root / "Info.plist").write_bytes(
        __import__("plistlib").dumps(
            {"CFBundleIdentifier": "com.example.iosapp"}, fmt=__import__("plistlib").FMT_BINARY
        )
    )
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    captured = {}

    def fake_chat(backend, messages, **kwargs):
        captured["tools"] = kwargs.get("tools")
        return _resp(_msg("the bundle id is com.example.iosapp"))

    monkeypatch.setattr(chat_mod, "client_chat", fake_chat)
    result = answer_question(scan_id, "what is the bundle id?")
    assert "com.example.iosapp" in result.answer
    names = {t["function"]["name"] for t in captured["tools"]}
    assert "get_decompiled_class" not in names
    assert {"read_manifest", "get_permissions", "search_strings", "run_secrets_scan"} <= names


# ---- greetings + loop-exhaustion fallback -------------------------------------


def test_greeting_answered_without_llm_or_backend(env, monkeypatch):
    """'hi' gets a canned greeting - no backend pick, no LLM call, no tool
    loop (regression: it used to burn the whole tool budget and return the
    confusing 'tool-call limit' message)."""
    scan_id = env
    calls = {"chat": 0, "pick": 0}

    def fake_pick():
        calls["pick"] += 1
        return object()

    def fake_chat(backend, messages, **kwargs):
        calls["chat"] += 1
        return _resp(_msg("should never run"))

    monkeypatch.setattr(chat_mod, "_pick_chat_backend", fake_pick)
    monkeypatch.setattr(chat_mod, "client_chat", fake_chat)
    result = answer_question(scan_id, "hi")
    assert "MASA" in result.answer
    assert result.citations == []
    assert calls["chat"] == 0
    assert calls["pick"] == 0


def test_greeting_variants_short_circuit(env, monkeypatch):
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    monkeypatch.setattr(chat_mod, "client_chat", lambda *a, **k: _resp(_msg("nope")))
    for q in ("Hello!", "hey", "yo", "HI", "howdy", "hola!"):
        result = answer_question(scan_id, q)
        assert "MASA" in result.answer


def test_greeting_like_question_still_uses_llm(env, monkeypatch):
    """'hi, …' is a real question, not a greeting - it must go through the
    agent normally (the short-circuit only catches bare greetings)."""
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())

    def fake_chat(backend, messages, **kwargs):
        return _resp(_msg("Here's what the scan covers."))

    monkeypatch.setattr(chat_mod, "client_chat", fake_chat)
    result = answer_question(scan_id, "hi, what does this scan cover?")
    assert "scan" in result.answer


def test_loop_exhaustion_falls_back_to_plain_chat(env, monkeypatch):
    """If the model only ever emits tool calls, the loop ends and ONE final
    no-tools attempt replays the original grounded prompt - the 'tool-call
    limit' message must not be the answer (regression: 'hi' style prompts)."""
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    calls = []

    def tool_loop_then_answer(backend, messages, **kwargs):
        calls.append({"messages": list(messages), "kwargs": kwargs})
        if "tools" in kwargs:  # the 4 tool rounds
            return _resp(
                _msg(
                    None,
                    tool_calls=[
                        _tool_call("c1", "search_code", json_args({"pattern": "WebView"})),
                    ],
                )
            )
        return _resp(_msg("The WebView client lives in com/app/W.java:42."))

    monkeypatch.setattr(chat_mod, "client_chat", tool_loop_then_answer)
    # Pin the round budget explicitly - the settings default is now the
    # CLI-agent-like 20 (M9 follow-up), and this test asserts the exact
    # round count of the exhaustion path.
    result = answer_question(
        scan_id, "where is the webview client?", timeout=60.0, max_tool_rounds=3
    )
    assert "WebView client" in result.answer
    assert len(calls) == 5  # 4 tool rounds + 1 plain fallback
    # the fallback carries no tool schemas and replays the original 2-turn
    # prompt (system + user), not the tool-polluted conversation
    assert "tools" not in calls[-1]["kwargs"]
    assert len(calls[-1]["messages"]) == 2


def test_loop_exhaustion_fallback_failure_raises_upstream(env, monkeypatch):
    """If the final plain-chat attempt also fails, it surfaces as
    ChatUpstreamError (502) like any other LLM failure."""
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    calls = {"n": 0}

    def tool_loop_then_boom(backend, messages, **kwargs):
        calls["n"] += 1
        if "tools" in kwargs:
            return _resp(
                _msg(
                    None,
                    tool_calls=[
                        _tool_call("c1", "search_code", json_args({"pattern": "WebView"})),
                    ],
                )
            )
        raise RuntimeError("upstream refused the final plain call")

    monkeypatch.setattr(chat_mod, "client_chat", tool_loop_then_boom)
    with pytest.raises(chat_mod.ChatUpstreamError, match="LLM call failed"):
        answer_question(
            scan_id, "where is the webview client?", timeout=60.0, max_tool_rounds=3
        )
    assert calls["n"] == 5


def test_loop_exhaustion_empty_fallback_returns_graceful_message(env, monkeypatch):
    """If even the final plain-chat attempt returns nothing, the answer is
    the graceful 'tool-call limit' guidance instead of a bare empty string."""
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())

    def tool_loop_then_empty(backend, messages, **kwargs):
        if "tools" in kwargs:
            return _resp(
                _msg(
                    None,
                    tool_calls=[
                        _tool_call("c1", "search_code", json_args({"pattern": "WebView"})),
                    ],
                )
            )
        return _resp(_msg("   "))

    monkeypatch.setattr(chat_mod, "client_chat", tool_loop_then_empty)
    result = answer_question(
        scan_id, "where is the webview client?", timeout=60.0, max_tool_rounds=3
    )
    assert "tool-call limit" in result.answer
    assert "Try a more specific question" in result.answer


# ---- interrupt (Stop button) --------------------------------------------------


def test_request_cancel_stops_loop_at_next_round(env, monkeypatch):
    """The Stop button's server side: request_cancel(scan_id) makes the loop
    raise ChatInterrupted at the next round boundary - the second LLM call
    never happens, and the registry entry is cleared in the finally."""
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    calls = {"n": 0}

    def one_round_then_interrupt(backend, messages, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            # First round returns a tool call (forcing a second round) and
            # the cancel lands before round 2's boundary check runs.
            chat_mod.request_cancel(scan_id)
            return _resp(
                _msg(
                    None,
                    tool_calls=[
                        _tool_call("c1", "search_code", json_args({"pattern": "WebView"})),
                    ],
                )
            )
        raise AssertionError("the second LLM call must never happen after cancel")

    monkeypatch.setattr(chat_mod, "client_chat", one_round_then_interrupt)
    with pytest.raises(chat_mod.ChatInterrupted, match="interrupted"):
        answer_question(scan_id, "where is the webview?", timeout=60.0)
    assert calls["n"] == 1
    # The flag must not leak into the next chat for the same scan.
    assert scan_id not in chat_mod._CANCEL_FLAGS


def test_cancel_registry_cleared_after_normal_answer(env, monkeypatch):
    """A chat that completes normally must not leave a cancel flag behind
    (otherwise a stale flag could kill the *next* chat for the scan)."""
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())

    def fake_chat(backend, messages, **kwargs):
        return _resp(_msg("plain answer, no tools"))

    monkeypatch.setattr(chat_mod, "client_chat", fake_chat)
    assert scan_id not in chat_mod._CANCEL_FLAGS
    result = answer_question(scan_id, "what is the main risk?")
    assert result.answer == "plain answer, no tools"
    assert scan_id not in chat_mod._CANCEL_FLAGS


def test_request_cancel_noop_without_in_flight_chat(env, monkeypatch):
    """Cancelling before/after a chat changes nothing (the flag only exists
    while a request is in flight) - a later chat still answers normally."""
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    chat_mod.request_cancel(scan_id)  # no event registered yet
    assert scan_id not in chat_mod._CANCEL_FLAGS

    def fake_chat(backend, messages, **kwargs):
        return _resp(_msg("still answers"))

    monkeypatch.setattr(chat_mod, "client_chat", fake_chat)
    result = answer_question(scan_id, "what is the main risk?")
    assert result.answer == "still answers"


def test_plan_narration_nudges_model_to_actually_call_tool(env, monkeypatch):
    """M8 follow-up (Aug 11): a model that responds with plan narration
    ('Let's search for login-related files… Let's read LoginActivity.java…')
    instead of emitting a tool call must NOT have that narration accepted as
    the final answer. The loop injects a bounded nudge and continues, so the
    model actually runs search_code and rolls up a grounded answer."""
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    batches: list[list[dict]] = []
    responses = iter(
        [
            # Round 1: pure plan narration - NO tool call (the bug).
            _resp(
                _msg(
                    "To remove password validation we need to inspect the login "
                    "logic. Let's search for login-related files in the codebase "
                    "using search_code, then read the class."
                )
            ),
            # Round 2 (after the nudge): the model actually calls search_code.
            _resp(
                _msg(
                    None,
                    tool_calls=[
                        _tool_call("c1", "search_code", json_args({"pattern": "password"})),
                    ],
                )
            ),
            # Round 3: the rollup - a real answer composed from the results.
            _resp(
                _msg(
                    "The login flow verifies the password in "
                    "com/android/insecurebankv2/LoginActivity.java:88."
                )
            ),
        ]
    )

    def fake_chat(backend, messages, **kwargs):
        batches.append(list(messages))
        return next(responses)

    monkeypatch.setattr(chat_mod, "client_chat", fake_chat)

    result = answer_question(scan_id, "disable password validation in authentication")

    # The tool actually ran - the narration was NOT the answer.
    assert result.tools_used == ["search_code"]
    assert result.tool_mode == "tools"
    assert "LoginActivity.java:88" in result.answer
    assert result.citations[0].file == "com/android/insecurebankv2/LoginActivity.java"
    # The nudge is a user message between the narration and the tool call.
    assert "plan without a tool call is not an answer" in batches[1][-1]["content"]


def test_plan_narration_bounded_after_max_nudges(env, monkeypatch):
    """A model that simply cannot emit tool calls must not loop forever: after
    _MAX_NARRATION_NUDGES nudges its narration is accepted as the answer."""
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    calls = {"n": 0}
    narration = "I think we should search for the relevant code, then read it."

    def always_narrates(backend, messages, **kwargs):
        calls["n"] += 1
        return _resp(_msg(narration))

    monkeypatch.setattr(chat_mod, "client_chat", always_narrates)

    result = answer_question(scan_id, "find the password check")

    # original + _MAX_NARRATION_NUDGES nudges, then the next narration is
    # accepted - bounded, no infinite loop.
    assert calls["n"] == chat_mod._MAX_NARRATION_NUDGES + 1
    assert result.answer == narration
    assert result.tools_used == []


def test_stale_final_text_cleared_when_nudging_then_exhausting(env, monkeypatch):
    """Review catch (Aug 11): a round that emits narration WITH a tool call
    sets final_text; if later rounds are nudged and the loop then EXHAUSTS
    its round budget, the stale narration must not win - an empty final_text
    falls through to the grounded plain-chat fallback."""
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    import app.config

    monkeypatch.setattr(app.config.settings, "max_tool_rounds", 2)  # 3 iterations
    calls = {"n": 0}

    def scripted(backend, messages, **kwargs):
        calls["n"] += 1
        if "tools" not in kwargs:
            return _resp(_msg("The WebView client is com/app/W.java:42."))
        if calls["n"] == 1:
            # Narration + tool call - sets final_text to the narration.
            return _resp(
                _msg(
                    "Let me search the code for the WebView client.",
                    tool_calls=[
                        _tool_call("c1", "search_code", json_args({"pattern": "WebView"})),
                    ],
                )
            )
        # Round 2: pure narration, no tool call -> nudge (bounded).
        return _resp(_msg("Let's look at the relevant files to find the answer."))

    monkeypatch.setattr(chat_mod, "client_chat", scripted)

    result = answer_question(scan_id, "where is the webview?", timeout=60.0)

    # The answer is the GROUNDED fallback, not the stale round-1 narration.
    assert "WebView client is com/app/W.java:42" in result.answer
    assert calls["n"] >= 3  # tool round + nudge + (exhausted) fallback


def test_plan_narration_regex_matches_real_wording(env, monkeypatch):
    """The intent regex catches the exact phrasing seen live with a local
    model (ollama/lm-studio narrating instead of calling)."""
    samples = [
        "Let's search for login-related files in the codebase using search_code.",
        "Let's read com/android/insecurebankv2/LoginActivity.java or search for password checks.",
        "We need to inspect the login logic and locate where password verification occurs.",
        "I'll look at the manifest to check the exported components.",
    ]
    for s in samples:
        assert chat_mod._NARRATION_INTENT_RE.search(s), s
    # Real answers that merely cite a file must NOT be flagged as narration.
    not_narration = [
        "The WebView client is defined in com/app/W.java:42.",
        "The app stores the AES key in CryptoClass.java:26.",
    ]
    for s in not_narration:
        assert not chat_mod._NARRATION_INTENT_RE.search(s), s


# ---- M9 follow-up: edit-task nudges + history + review state ----------------

# A decoded apktool tree (edit tools become allowed) - mirrors the
# test_edit_tools.py helper, inlined so this module stays self-contained.
_NUDGE_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.example.demo">
    <uses-sdk android:minSdkVersion="21"/>
    <application android:allowBackup="true" android:debuggable="true">
        <activity android:name=".MainActivity" android:exported="true"/>
    </application>
</manifest>
"""


def _apktool_tree(tmp_path, scan_id) -> None:
    root = tmp_path / "work" / str(scan_id) / "apktool"
    (root / "smali/com/foo").mkdir(parents=True)
    (root / "AndroidManifest.xml").write_text(_NUDGE_MANIFEST)
    (root / "smali/com/foo/AuthManager.smali").write_text(
        ".class public Lcom/foo/AuthManager;\n.super Ljava/lang/Object;\n"
    )


def test_history_injected_before_question(env, monkeypatch):
    """M9 follow-up: the client-side thread (history) is injected between the
    system prompt and the current question - a 'continue' follow-up keeps the
    original edit request without server persistence."""
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    captured = {}

    def fake_chat(backend, messages, **kwargs):
        captured["messages"] = list(messages)
        return _resp(_msg("ok"))

    monkeypatch.setattr(chat_mod, "client_chat", fake_chat)
    result = answer_question(
        scan_id,
        "continue",
        history=[
            {"role": "user", "content": "bypass the root check"},
            {"role": "assistant", "content": "Proposed edit #1 - review it."},
        ],
    )
    assert result.answer == "ok"
    roles = [m["role"] for m in captured["messages"]]
    assert roles == ["system", "user", "assistant", "user"]
    assert captured["messages"][1]["content"] == "bypass the root check"
    assert captured["messages"][2]["content"] == "Proposed edit #1 - review it."
    assert captured["messages"][3]["content"] == "continue"


def test_history_bad_roles_dropped(env, monkeypatch):
    """History turns with unknown roles / blank content are dropped - a raw
    API caller can't smuggle tool-role or empty turns into the prompt."""
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    captured = {}

    def fake_chat(backend, messages, **kwargs):
        captured["messages"] = list(messages)
        return _resp(_msg("ok"))

    monkeypatch.setattr(chat_mod, "client_chat", fake_chat)
    answer_question(
        scan_id,
        "q",
        history=[
            {"role": "tool", "content": "smuggle"},
            {"role": "assistant", "content": "   "},
            {"role": "user", "content": "the real prior ask"},
        ],
    )
    roles = [m["role"] for m in captured["messages"]]
    assert roles == ["system", "user", "user"]
    assert captured["messages"][1]["content"] == "the real prior ask"


def test_edit_review_state_attached_when_edit_tools_ready(
    env, tmp_path, db_session_factory, monkeypatch
):
    """The EDIT REVIEW STATE section renders the scan's edits + verdicts into
    the system prompt when the edit tools are allowed - so a 'continue' turn
    knows what was applied/rejected and never re-proposes it."""
    scan_id = env
    _apktool_tree(tmp_path, scan_id)
    with db_session_factory() as session:
        session.add(
            Edit(
                scan_id=scan_id,
                file_path="AndroidManifest.xml",
                original_content="a",
                new_content="b",
                unified_diff="-a\n+b\n",
                source="agent",
                instruction="disable debuggable",
                status="applied",
            )
        )
        session.commit()
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    captured = {}

    def fake_chat(backend, messages, **kwargs):
        captured["system"] = messages[0]["content"]
        return _resp(_msg("ok"))

    monkeypatch.setattr(chat_mod, "client_chat", fake_chat)
    answer_question(scan_id, "continue")
    assert "EDIT REVIEW STATE" in captured["system"]
    assert "AndroidManifest.xml [applied]" in captured["system"]
    assert "disable debuggable" in captured["system"]


def test_edit_task_nudge_proposes_after_read(env, tmp_path, monkeypatch, db_session_factory):
    """The 'ends on read' fix: a change request ("bypass the root check") whose
    model searches/reads then writes a summary WITHOUT proposing is nudged
    (bounded) to call propose_smali_edit - the turn ends with a real proposal
    row instead of a read-only summary."""
    scan_id = env
    _apktool_tree(tmp_path, scan_id)
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    calls: list[dict] = []
    new_manifest = _NUDGE_MANIFEST.replace(
        'android:debuggable="true"', 'android:debuggable="false"'
    )

    def scripted(backend, messages, **kwargs):
        calls.append({"messages": list(messages), "tools": "tools" in kwargs})
        if not kwargs.get("tools"):
            return _resp(_msg("context-only"))
        n = len(calls)
        if n == 1:
            # Round 1: the model searches - real tool execution against the
            # jadx tree from the env fixture.
            return _resp(
                _msg(
                    "Let me search the code for the root check.",
                    tool_calls=[
                        _tool_call("c1", "search_code", json_args({"pattern": "class W"})),
                    ],
                )
            )
        if n == 2:
            # Round 2: the model STOPS with a summary - no proposal. The
            # edit-task nudge must fire here.
            return _resp(_msg("The root check lives in com/app/W.java:42."))
        if n == 3:
            # Round 3 (after the nudge): propose for real.
            return _resp(
                _msg(
                    "Proposing the manifest change.",
                    tool_calls=[
                        _tool_call(
                            "c3",
                            "propose_smali_edit",
                            json_args(
                                {
                                    "path": "AndroidManifest.xml",
                                    "instruction": "disable debuggable",
                                    "new_content": new_manifest,
                                }
                            ),
                        )
                    ],
                )
            )
        # Round 4: final answer after the proposal.
        return _resp(_msg("Done - proposed edit #1 for AndroidManifest.xml."))

    monkeypatch.setattr(chat_mod, "client_chat", scripted)
    result = answer_question(scan_id, "bypass the root check", timeout=60.0)

    assert "proposed edit #1" in result.answer
    assert "propose_smali_edit" in result.tools_used
    # The nudge was injected between rounds 2 and 3.
    nudge_msgs = [m for m in calls[2]["messages"] if m["role"] == "user"]
    assert any("propose_smali_edit NOW" in m["content"] for m in nudge_msgs)
    # A real proposal row was stored (proposed, never applied).
    with db_session_factory() as session:
        rows = list(session.query(Edit).filter(Edit.scan_id == scan_id).all())
        assert len(rows) == 1
        assert rows[0].status == "proposed"
        assert rows[0].file_path == "AndroidManifest.xml"


def test_edit_nudge_not_for_plain_question(env, tmp_path, monkeypatch):
    """A read-only question ("where is the webview?") is never pushed to
    propose - the nudge requires change intent in the question."""
    scan_id = env
    _apktool_tree(tmp_path, scan_id)
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    calls: list[dict] = []

    def scripted(backend, messages, **kwargs):
        calls.append({"messages": list(messages), "tools": "tools" in kwargs})
        if not kwargs.get("tools"):
            return _resp(_msg("context-only"))
        if len(calls) == 1:
            return _resp(
                _msg(
                    None,
                    tool_calls=[
                        _tool_call("c1", "search_code", json_args({"pattern": "WebView"})),
                    ],
                )
            )
        return _resp(_msg("The WebView client is com/app/W.java:42."))

    monkeypatch.setattr(chat_mod, "client_chat", scripted)
    result = answer_question(scan_id, "where is the webview?", timeout=60.0)
    assert result.answer == "The WebView client is com/app/W.java:42."
    assert len(calls) == 2  # search round + answer round - NO nudge round
    assert "propose_smali_edit" not in result.tools_used


def json_args(args: dict) -> str:
    import json

    return json.dumps(args)
