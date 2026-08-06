"""health.check_backend / list_models — httpx + litellm monkeypatched, no network."""

import httpx

from app.model.backends import ModelBackend
from app.model.health import check_backend, list_models
from app.model.providers import PROVIDERS


def _backend(
    provider_id: str, base_url: str | None = None, model: str = "", api_key: str | None = None
):
    p = PROVIDERS[provider_id]
    return ModelBackend(
        id=provider_id,
        provider_id=provider_id,
        name=p.name,
        kind=p.kind,
        base_url=base_url or p.default_base_url,
        model=model,
        api_key=api_key if api_key is not None else p.dummy_key,
    )


class _FakeResponse:
    def __init__(self, payload=None, exc=None):
        self._payload = payload or {"data": []}
        self._exc = exc

    def raise_for_status(self):
        if self._exc:
            raise self._exc

    def json(self):
        return self._payload


def _fake_get(payload=None, exc=None):
    return lambda *args, **kwargs: _FakeResponse(payload, exc)


# ---- list_models ---------------------------------------------------------


def test_list_models_live(monkeypatch):
    payload = {"data": [{"id": "qwen2.5:7b"}, {"id": "llama3.1:8b"}]}
    monkeypatch.setattr("app.model.health.httpx.get", _fake_get(payload))
    models, source, error = list_models(_backend("ollama", model="qwen2.5:7b"))
    assert source == "live"
    assert error is None
    assert models == ["qwen2.5:7b", "llama3.1:8b"]


def test_list_models_unavailable_on_connection_error(monkeypatch):
    monkeypatch.setattr(
        "app.model.health.httpx.get", _fake_get(exc=httpx.ConnectError("connection refused"))
    )
    models, source, error = list_models(_backend("ollama"))
    assert source == "unavailable"
    assert models == []
    assert "connection refused" in error.lower()


def test_list_models_does_not_send_dummy_key_header_to_local(monkeypatch):
    seen = {}

    def capture(url, **kwargs):
        seen.update(kwargs)
        return _FakeResponse({"data": [{"id": "m"}]})

    monkeypatch.setattr("app.model.health.httpx.get", capture)
    list_models(_backend("ollama", model="m"))
    assert "headers" not in seen or not seen["headers"]


def test_list_models_anthropic_static_suggestions():
    # No network call at all: Anthropic has no OpenAI-compatible listing.
    models, source, error = list_models(
        _backend("anthropic", model="claude-sonnet-4-20250514", api_key="sk-x")
    )
    assert source == "suggested"
    assert error is None
    assert models, "expected static fallback models for Anthropic"


# ---- check_backend -------------------------------------------------------


def test_check_reachable_with_probe(monkeypatch):
    monkeypatch.setattr(
        "app.model.health.httpx.get",
        _fake_get({"data": [{"id": "qwen2.5:7b"}]}),
    )
    monkeypatch.setattr("app.model.health.litellm.completion", lambda **k: {})
    h = check_backend(_backend("ollama", model="qwen2.5:7b"))
    assert h.reachable is True
    assert h.status == "ok"
    assert h.model_source == "live"
    assert h.probe_model == "qwen2.5:7b"
    assert h.probe_ok is True
    assert h.latency_ms is not None


def test_check_unreachable_never_raises(monkeypatch):
    monkeypatch.setattr(
        "app.model.health.httpx.get", _fake_get(exc=httpx.ConnectError("conn refused"))
    )
    h = check_backend(_backend("ollama"), probe=True)  # must not raise
    assert h.reachable is False
    assert h.status == "unreachable"
    assert h.probe_ok is None  # no probe attempted against a dead server
    assert h.error


def test_check_live_but_probe_failed(monkeypatch):
    monkeypatch.setattr("app.model.health.httpx.get", _fake_get({"data": [{"id": "qwen2.5:7b"}]}))

    def failing_completion(**kwargs):
        raise RuntimeError("model not found")

    monkeypatch.setattr("app.model.health.litellm.completion", failing_completion)
    h = check_backend(_backend("ollama", model="qwen2.5:7b"))
    assert h.reachable is True  # server answered; the model is the problem
    assert h.status == "ok"
    assert h.probe_ok is False
    assert "probe failed" in (h.error or "")


def test_check_no_models_listed_no_probe(monkeypatch):
    monkeypatch.setattr("app.model.health.httpx.get", _fake_get({"data": []}))
    monkeypatch.setattr("app.model.health.litellm.completion", lambda **k: {})
    h = check_backend(_backend("ollama"))
    assert h.reachable is True
    assert h.probe_model is None
    assert h.probe_ok is None
    assert h.models == []


def test_check_anthropic_probe_ok(monkeypatch):
    # No httpx call (no listing endpoint); probe succeeds.
    monkeypatch.setattr("app.model.health.litellm.completion", lambda **k: {})
    h = check_backend(
        _backend("anthropic", model="claude-sonnet-4-20250514", api_key="sk-x"), probe=True
    )
    assert h.reachable is True
    assert h.status == "ok"
    assert h.model_source == "suggested"
    assert h.probe_model == "claude-sonnet-4-20250514"


def test_check_anthropic_probe_failed(monkeypatch):
    def failing_completion(**kwargs):
        raise RuntimeError("invalid api key")

    monkeypatch.setattr("app.model.health.litellm.completion", failing_completion)
    h = check_backend(
        _backend("anthropic", model="claude-sonnet-4-20250514", api_key="bad"), probe=True
    )
    assert h.reachable is False
    assert h.status == "unreachable"
    assert h.error


def test_check_anthropic_no_model_falls_back_to_first_suggestion(monkeypatch):
    # No model configured, but Anthropic carries static suggestions: the probe
    # falls back to the first one, so the backend is still verifiable.
    monkeypatch.setattr("app.model.health.litellm.completion", lambda **k: {})
    h = check_backend(_backend("anthropic"), probe=True)
    assert h.reachable is True
    assert h.probe_model == "claude-sonnet-4-20250514"


def test_check_lightweight_no_probe(monkeypatch):
    # probe=False on a no-live-listing provider must read "unknown", not
    # "unreachable" — the lightweight listing cannot verify it.
    monkeypatch.setattr("app.model.health.litellm.completion", lambda **k: {})
    h = check_backend(
        _backend("anthropic", model="claude-sonnet-4-20250514", api_key="sk-x"), probe=False
    )
    assert h.reachable is False
    assert h.status == "unknown"
    assert "POST /test" in (h.error or "")


def test_check_lightweight_skips_probe_on_live_backend(monkeypatch):
    seen = {"probe": False}

    def failing_probe(**kwargs):
        seen["probe"] = True
        raise RuntimeError("should not be called")

    monkeypatch.setattr("app.model.health.httpx.get", _fake_get({"data": [{"id": "m"}]}))
    monkeypatch.setattr("app.model.health.litellm.completion", failing_probe)
    h = check_backend(_backend("ollama", model="m"), probe=False)
    assert h.reachable is True
    assert seen["probe"] is False
    assert h.probe_ok is None
