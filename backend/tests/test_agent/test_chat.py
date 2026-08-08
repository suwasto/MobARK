"""Layers 1-3 chat orchestration — client_chat monkeypatched, no network, no LLM.

Ollama is off during development (owner decision): every test here is a
mocked unit test; live-model acceptance is manual.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.agent import chat as chat_mod
from app.agent.chat import ChatNotConfigured, answer_question
from app.models import Finding, Scan


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

    # Layer 1 context is in the system message, precision-tagged, full set.
    system = captured["messages"][0]["content"]
    assert "FINDINGS CONTEXT" in system
    assert "WebView with JavaScript enabled" in system
    assert "[file/line]" in system
    assert captured["tools"]  # tool schemas offered


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
    it must receive the *remaining* budget — otherwise a hung call plus its
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
    the plain-chat fallback must NOT retry — it raises AgentTimeout instead,
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
    message — the API maps it to 502, not a raw 500 (the 500 the user saw
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
    bubble too — not just in the Settings probe."""
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


# ---- greetings + loop-exhaustion fallback -------------------------------------


def test_greeting_answered_without_llm_or_backend(env, monkeypatch):
    """'hi' gets a canned greeting — no backend pick, no LLM call, no tool
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
    """'hi, …' is a real question, not a greeting — it must go through the
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
    no-tools attempt replays the original grounded prompt — the 'tool-call
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
    result = answer_question(scan_id, "where is the webview client?", timeout=60.0)
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
        answer_question(scan_id, "where is the webview client?", timeout=60.0)
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
    result = answer_question(scan_id, "where is the webview client?", timeout=60.0)
    assert "tool-call limit" in result.answer
    assert "Try a more specific question" in result.answer


# ---- interrupt (Stop button) --------------------------------------------------


def test_request_cancel_stops_loop_at_next_round(env, monkeypatch):
    """The Stop button's server side: request_cancel(scan_id) makes the loop
    raise ChatInterrupted at the next round boundary — the second LLM call
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
    while a request is in flight) — a later chat still answers normally."""
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    chat_mod.request_cancel(scan_id)  # no event registered yet
    assert scan_id not in chat_mod._CANCEL_FLAGS

    def fake_chat(backend, messages, **kwargs):
        return _resp(_msg("still answers"))

    monkeypatch.setattr(chat_mod, "client_chat", fake_chat)
    result = answer_question(scan_id, "what is the main risk?")
    assert result.answer == "still answers"


def json_args(args: dict) -> str:
    import json

    return json.dumps(args)
