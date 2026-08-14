"""M5 insights unit tests - explain + summary with the LLM client mocked.

No network, no model store churn: ``pick_chat_backend`` and ``client_chat``
are monkeypatched per test.
"""
from __future__ import annotations

import types
from datetime import datetime

import pytest

from app.agent import insights
from app.agent.insights import InsightError
from app.model.selection import NoModelConfigured


class _Msg:
    def __init__(self, content: str):
        self.content = content


class _Choice:
    def __init__(self, content: str):
        self.message = _Msg(content)


class _Resp:
    def __init__(self, content: str):
        self.choices = [_Choice(content)]


def _finding(**over):
    base = dict(
        title="Session token stored in plaintext SharedPreferences",
        severity="high",
        file_path="com/foo/AuthManager.java",
        line_number=117,
        category="MASVS-STORAGE-1",
        mastg_test_id="MASTG-TEST-0073",
        tool="semgrep",
        detail=None,
        explanation=None,
    )
    base.update(over)
    return types.SimpleNamespace(**base)


def _backend(model="qwen2.5:7b"):
    return types.SimpleNamespace(model=model)


# ---- explain ----------------------------------------------------------------


def test_explain_cache_hit_skips_llm(monkeypatch):
    finding = _finding(explanation="already explained")

    def boom(*args, **kwargs):
        raise AssertionError("LLM must not be called on a cache hit")

    monkeypatch.setattr(insights, "client_chat", boom)
    result = insights.explain_finding(1, finding)
    assert result["cached"] is True
    assert result["explanation"] == "already explained"
    assert result["model"] is None


def test_explain_generates_and_persists(monkeypatch):
    finding = _finding()
    captured = {}

    def fake_chat(backend, messages, **kwargs):
        captured["messages"] = messages
        captured["backend"] = backend
        return _Resp(
            "It is stored with MODE_PRIVATE and is readable on rooted devices. "
            "Fix: use EncryptedSharedPreferences."
        )

    monkeypatch.setattr(insights, "client_chat", fake_chat)
    monkeypatch.setattr(insights, "pick_chat_backend", lambda: _backend())
    # No real scan tree in a unit test - fake the source-context read.
    monkeypatch.setattr(
        insights, "read_file", lambda *a, **k: "e.putString(\"session_token\", res.getToken());"
    )
    result = insights.explain_finding(1, finding)

    assert result["cached"] is False
    assert result["model"] == "qwen2.5:7b"
    assert isinstance(result["generated_at"], datetime)
    # persisted onto the finding for the route to commit
    assert "EncryptedSharedPreferences" in finding.explanation
    # grounded: finding data + source context in the user message
    user = captured["messages"][1]["content"]
    assert "AuthManager.java" in user
    assert "high" in user
    assert "Source context" in user


def test_explain_regenerate_bypasses_cache(monkeypatch):
    """regenerate=True re-runs the LLM even on a cached finding and overwrites
    the stored explanation - the Regenerate button's explicit cost spend."""
    finding = _finding(explanation="already explained")
    calls = {"n": 0}

    def fake_chat(backend, messages, **kwargs):
        calls["n"] += 1
        return _Resp("fresh explanation")

    monkeypatch.setattr(insights, "client_chat", fake_chat)
    monkeypatch.setattr(insights, "pick_chat_backend", lambda: _backend())
    monkeypatch.setattr(insights, "read_file", lambda *a, **k: "ctx")
    result = insights.explain_finding(1, finding, regenerate=True)

    assert result["cached"] is False
    assert result["explanation"] == "fresh explanation"
    assert calls["n"] == 1  # LLM called despite the cache
    assert finding.explanation == "fresh explanation"


def test_explain_no_model_falls_back_to_deterministic(monkeypatch):
    """Aug 13 follow-up: no model configured -> the explain surface returns
    the DETERMINISTIC explanation (the same text the report renders, marked
    ``fallback``) instead of propagating NoModelConfigured - the app matches
    the report's no-AI body."""
    finding = _finding(
        detail={"check_id": "mastg-android-sdk-version"},
        tool="semgrep",
        severity="medium",
        file_path="com/foo/Main.java",
        line_number=3,
        category="MASVS-PLATFORM",
    )

    def no_model():
        raise NoModelConfigured("no chat model configured")

    monkeypatch.setattr(insights, "pick_chat_backend", no_model)
    result = insights.explain_finding(1, finding)

    assert result["fallback"] is True
    assert result["cached"] is False
    assert result["model"] is None
    # the deterministic paragraph - rule description + mapping + scope note
    assert "This semgrep check (mastg-android-sdk-version: " in result["explanation"]
    assert (
        "This rule scans for API that checks the version of the operating system"
        in result["explanation"]
    )
    assert "mapped to MASVS control MASVS-PLATFORM" in result["explanation"]
    assert "Static-only finding" in result["explanation"]
    # never persisted as a cached AI explanation
    assert finding.explanation is None


def test_explain_upstream_failure_raises_insight_error(monkeypatch):
    def boom(*args, **kwargs):
        raise ConnectionError("upstream refused")

    monkeypatch.setattr(insights, "client_chat", boom)
    monkeypatch.setattr(insights, "pick_chat_backend", lambda: _backend())
    with pytest.raises(InsightError):
        insights.explain_finding(1, _finding())


def test_explain_empty_response_raises_insight_error(monkeypatch):
    monkeypatch.setattr(insights, "client_chat", lambda *a, **k: _Resp("   "))
    monkeypatch.setattr(insights, "pick_chat_backend", lambda: _backend())
    with pytest.raises(InsightError):
        insights.explain_finding(1, _finding())


def test_explain_without_location_omits_source_context(monkeypatch):
    finding = _finding(file_path=None, line_number=None)
    captured = {}

    def fake_chat(backend, messages, **kwargs):
        captured["messages"] = messages
        return _Resp("ok")

    monkeypatch.setattr(insights, "client_chat", fake_chat)
    monkeypatch.setattr(insights, "pick_chat_backend", lambda: _backend())
    insights.explain_finding(1, finding)
    assert "Source context" not in captured["messages"][1]["content"]


# ---- summary ----------------------------------------------------------------


def _findings():
    return [
        types.SimpleNamespace(severity="high", title="Token in prefs", file_path="A.java"),
        types.SimpleNamespace(severity="medium", title="Pinning off", file_path="B.java"),
        types.SimpleNamespace(severity="info", title="Debug build", file_path="C.java"),
    ]


def _scan(ai_summary=None):
    return types.SimpleNamespace(
        filename="app.apk", platform="android", ai_summary=ai_summary
    )


def test_summary_generates_grounded_text(monkeypatch):
    captured = {}

    def fake_chat(backend, messages, **kwargs):
        captured["messages"] = messages
        return _Resp("High risk: storage and network findings dominate.")

    monkeypatch.setattr(insights, "client_chat", fake_chat)
    monkeypatch.setattr(insights, "pick_chat_backend", lambda: _backend())
    scan = _scan()
    result = insights.summarize_scan(scan, _findings(), security_score=42)

    assert result["cached"] is False
    assert result["model"] == "qwen2.5:7b"
    # persisted onto the scan row for the route to commit
    assert scan.ai_summary == "High risk: storage and network findings dominate."
    user = captured["messages"][1]["content"]
    assert '"security_score": 42' in user
    assert "higher is better" in user
    assert '"high": 1' in user
    assert "Token in prefs" in user  # top finding included


def test_summary_cache_hit_skips_llm(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("LLM must not be called on a cache hit")

    monkeypatch.setattr(insights, "client_chat", boom)
    scan = _scan(ai_summary="cached summary")
    result = insights.summarize_scan(scan, _findings(), security_score=100)
    assert result["cached"] is True
    assert result["summary"] == "cached summary"


def test_summary_regenerate_bypasses_cache(monkeypatch):
    """regenerate=True re-runs the LLM even with a cached summary and
    overwrites the stored row - same explicit-opt-in contract as explain."""
    scan = _scan(ai_summary="cached summary")
    calls = {"n": 0}

    def fake_chat(backend, messages, **kwargs):
        calls["n"] += 1
        return _Resp("fresh overview")

    monkeypatch.setattr(insights, "client_chat", fake_chat)
    monkeypatch.setattr(insights, "pick_chat_backend", lambda: _backend())
    result = insights.summarize_scan(
        scan, _findings(), security_score=100, regenerate=True
    )

    assert result["cached"] is False
    assert result["summary"] == "fresh overview"
    assert calls["n"] == 1  # LLM called despite the cache
    assert scan.ai_summary == "fresh overview"


def test_summary_no_model_propagates(monkeypatch):
    def no_model():
        raise NoModelConfigured("no chat model configured")

    monkeypatch.setattr(insights, "pick_chat_backend", no_model)
    with pytest.raises(NoModelConfigured):
        insights.summarize_scan(_scan(), _findings(), security_score=100)


def test_summary_upstream_failure_raises_insight_error(monkeypatch):
    def boom(*args, **kwargs):
        raise TimeoutError("hung upstream")

    monkeypatch.setattr(insights, "client_chat", boom)
    monkeypatch.setattr(insights, "pick_chat_backend", lambda: _backend())
    with pytest.raises(InsightError):
        insights.summarize_scan(_scan(), _findings(), security_score=100)
