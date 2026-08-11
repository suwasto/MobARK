"""health.check_backend / list_models - httpx + litellm monkeypatched, no network."""

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


def test_list_models_anthropic_live(monkeypatch):
    """Anthropic's List Models is live-fetched: OpenAI-shaped `data[].id`
    parse, but with its own auth headers - x-api-key + anthropic-version, no
    Bearer."""
    seen = {}

    def capture(url, **kwargs):
        seen.update(kwargs)
        return _FakeResponse(
            {
                "data": [
                    {"id": "claude-sonnet-4-20250514", "type": "model"},
                    {"id": "claude-haiku-4-5-20251001", "type": "model"},
                ]
            }
        )

    monkeypatch.setattr("app.model.health.httpx.get", capture)
    models, source, error = list_models(_backend("anthropic", api_key="sk-x"))
    assert source == "live"
    assert error is None
    assert models == ["claude-sonnet-4-20250514", "claude-haiku-4-5-20251001"]
    headers = seen.get("headers") or {}
    assert headers.get("x-api-key") == "sk-x"
    assert headers.get("anthropic-version") == "2023-06-01"
    assert "Authorization" not in headers


def test_list_models_anthropic_falls_back_to_suggested_on_error(monkeypatch):
    """A failed live fetch must degrade to the curated list (source
    'suggested'), never [] - the app keeps working on key errors / offline."""
    monkeypatch.setattr(
        "app.model.health.httpx.get", _fake_get(exc=httpx.ConnectError("no network"))
    )
    models, source, error = list_models(_backend("anthropic", api_key="sk-x"))
    assert source == "suggested"
    assert models == list(PROVIDERS["anthropic"].suggested_models)
    assert error is not None


def test_list_models_anthropic_requires_key():
    """No key configured - skip the network entirely and degrade to the
    curated fallback with a self-explanatory reason."""
    models, source, error = list_models(_backend("anthropic"))
    assert source == "suggested"
    assert models == list(PROVIDERS["anthropic"].suggested_models)
    assert "API key" in (error or "")


def test_list_models_gemini_live(monkeypatch):
    """Gemini's models.list is live-fetched (no hardcoded list): `?key=`
    query auth, `models/` prefix stripped, entries filtered to
    generateContent-capable base models (embeddings/tuned excluded)."""
    payload = {
        "models": [
            {
                "name": "models/gemini-3.5-flash",
                "supportedGenerationMethods": ["generateContent", "countTokens"],
            },
            {
                "name": "models/gemini-3.5-flash-lite",
                "supportedGenerationMethods": ["generateContent"],
            },
            {
                "name": "models/text-embedding",
                "supportedGenerationMethods": ["embedContent"],
            },
            {
                "name": "tunedModels/my-tuned",
                "supportedGenerationMethods": ["generateContent"],
            },
        ]
    }
    seen = {}

    def capture(url, **kwargs):
        seen.update(kwargs)
        return _FakeResponse(payload)

    monkeypatch.setattr("app.model.health.httpx.get", capture)
    models, source, error = list_models(_backend("gemini", api_key="AIza-x"))
    assert source == "live"
    assert error is None
    assert models == ["gemini-3.5-flash", "gemini-3.5-flash-lite"]
    # Gemini auth rides the query string - never an OpenAI-style Bearer header.
    assert seen.get("params") == {"key": "AIza-x"}
    assert not seen.get("headers")


def test_list_models_gemini_falls_back_to_suggested_on_error(monkeypatch):
    """A failed or empty live fetch must degrade to the curated list (source
    'suggested'), never [] - the app keeps working on key errors / offline,
    and the completion probe surfaces the connectivity problem."""
    monkeypatch.setattr(
        "app.model.health.httpx.get", _fake_get(exc=httpx.ConnectError("no network"))
    )
    models, source, error = list_models(_backend("gemini", api_key="AIza-x"))
    assert source == "suggested"
    assert models == list(PROVIDERS["gemini"].suggested_models)
    assert error is not None  # the real listing failure stays available


def test_check_gemini_lightweight_surfaces_listing_failure(monkeypatch):
    """GET /backends runs probe=False. A failed Gemini live listing must not
    claim the provider has 'no live listing endpoint' (it does - the fetch
    failed); the real reason is surfaced instead."""
    monkeypatch.setattr(
        "app.model.health.httpx.get", _fake_get(exc=httpx.ConnectError("key rejected"))
    )
    h = check_backend(_backend("gemini", api_key="bad"), probe=False)
    assert h.reachable is False
    assert h.status == "unknown"
    assert "no live listing endpoint" not in (h.error or "")
    assert "live model listing failed" in (h.error or "")
    assert "ConnectError" in (h.error or "")


def test_check_gemini_live_probes_first_served_model(monkeypatch):
    """With a live listing, check_backend probes the first actually-served
    model - no stale curated walk needed because the list IS current."""
    monkeypatch.setattr(
        "app.model.health.httpx.get",
        _fake_get(
            {
                "models": [
                    {
                        "name": "models/gemini-3.5-flash",
                        "supportedGenerationMethods": ["generateContent"],
                    }
                ]
            }
        ),
    )
    monkeypatch.setattr("app.model.health.litellm.completion", lambda **k: {})
    h = check_backend(_backend("gemini", api_key="AIza-x"))
    assert h.reachable is True
    assert h.status == "ok"
    assert h.model_source == "live"
    assert h.probe_model == "gemini-3.5-flash"
    assert h.probe_ok is True


def test_check_gemini_live_walks_curated_when_first_is_deprecated(monkeypatch):
    """Google's models.list still lists deprecated IDs (gemini-2.5-flash 404s
    on use for new keys) - often FIRST. With no model configured, the probe
    must skip the raw first entry and walk the curated ∩ live candidates, so
    a fresh BYOK setup shows Connected instead of a bogus probe failure."""
    attempts: list[str] = []

    def flaky_completion(**kwargs):
        attempts.append(kwargs["model"])
        if len(attempts) == 1:
            raise RuntimeError(
                "GeminiException - 404: model is no longer available to new users"
            )
        return {"choices": [{"message": {"content": "ok"}}]}

    monkeypatch.setattr(
        "app.model.health.httpx.get",
        _fake_get(
            {
                "models": [
                    {
                        "name": "models/gemini-2.5-flash",
                        "supportedGenerationMethods": ["generateContent"],
                    },
                    {
                        "name": "models/gemini-3.5-flash",
                        "supportedGenerationMethods": ["generateContent"],
                    },
                    {
                        "name": "models/gemini-3.6-flash",
                        "supportedGenerationMethods": ["generateContent"],
                    },
                ]
            }
        ),
    )
    monkeypatch.setattr("app.model.health.litellm.completion", flaky_completion)
    h = check_backend(_backend("gemini", api_key="AIza-x"))
    assert h.reachable is True
    assert h.status == "ok"
    assert h.probe_ok is True
    # The deprecated raw-first entry (gemini-2.5-flash) is never probed; the
    # walk starts at curated ∩ live and moves on when the first fails.
    assert attempts == ["gemini/gemini-3.5-flash", "gemini/gemini-3.6-flash"]
    assert h.probe_model == "gemini-3.6-flash"


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
    # The probe must carry the *upstream* reason, not a bare false - the
    # Settings UI renders this verbatim.
    assert "probe failed" in (h.error or "")
    assert "model not found" in (h.error or "")


def test_check_probe_failure_carries_upstream_message(monkeypatch):
    """Regression: old Ollama builds reject newer model architectures
    (``unknown model architecture``). The health error must surface that
    message plus an actionable hint, so Settings explains the failure."""
    monkeypatch.setattr("app.model.health.httpx.get", _fake_get({"data": [{"id": "m:latest"}]}))

    def failing_completion(**kwargs):
        raise RuntimeError(
            "OllamaException - error loading model: "
            "unknown model architecture: 'nanbeige'"
        )

    monkeypatch.setattr("app.model.health.litellm.completion", failing_completion)
    h = check_backend(_backend("ollama", model="m:latest"))
    assert h.probe_ok is False
    assert "unknown model architecture: 'nanbeige'" in (h.error or "")
    assert "upgrade Ollama" in (h.error or "")


def test_check_no_models_listed_no_probe(monkeypatch):
    monkeypatch.setattr("app.model.health.httpx.get", _fake_get({"data": []}))
    monkeypatch.setattr("app.model.health.litellm.completion", lambda **k: {})
    h = check_backend(_backend("ollama"))
    assert h.reachable is True
    assert h.probe_model is None
    assert h.probe_ok is None
    assert h.models == []


def test_check_anthropic_probe_ok(monkeypatch):
    # Live listing succeeds (x-api-key auth) + probe succeeds.
    monkeypatch.setattr(
        "app.model.health.httpx.get",
        _fake_get({"data": [{"id": "claude-sonnet-4-20250514"}]}),
    )
    monkeypatch.setattr("app.model.health.litellm.completion", lambda **k: {})
    h = check_backend(
        _backend("anthropic", model="claude-sonnet-4-20250514", api_key="sk-x"), probe=True
    )
    assert h.reachable is True
    assert h.status == "ok"
    assert h.model_source == "live"
    assert h.probe_model == "claude-sonnet-4-20250514"


def test_check_anthropic_probe_failed(monkeypatch):
    # Live listing works but the completion probe fails - same contract as
    # any live backend: reachable, probe_ok False, error carries the reason.
    monkeypatch.setattr(
        "app.model.health.httpx.get",
        _fake_get({"data": [{"id": "claude-sonnet-4-20250514"}]}),
    )

    def failing_completion(**kwargs):
        raise RuntimeError("invalid api key")

    monkeypatch.setattr("app.model.health.litellm.completion", failing_completion)
    h = check_backend(
        _backend("anthropic", model="claude-sonnet-4-20250514", api_key="bad"), probe=True
    )
    assert h.reachable is True
    assert h.status == "ok"
    assert h.probe_ok is False
    assert "probe failed" in (h.error or "")


def test_check_anthropic_no_model_prefers_curated_live(monkeypatch):
    # No model configured - the probe targets the first CURATED ∩ live model
    # (the curated list is the known-current seed), not the raw first entry.
    monkeypatch.setattr(
        "app.model.health.httpx.get",
        _fake_get(
            {
                "data": [
                    {"id": "claude-haiku-4-5-20251001"},
                    {"id": "claude-sonnet-4-20250514"},
                ]
            }
        ),
    )
    monkeypatch.setattr("app.model.health.litellm.completion", lambda **k: {})
    h = check_backend(_backend("anthropic", api_key="sk-x"), probe=True)
    assert h.reachable is True
    # Curated order wins over the raw live order (sonnet before haiku).
    assert h.probe_model == "claude-sonnet-4-20250514"


def test_check_suggested_walks_models_when_first_is_deprecated(monkeypatch):
    """Google 404s retired model IDs for new API keys (the gemini-2.5-flash
    case). With no model configured, the probe must walk the curated list - a
    stale first entry must not mark the whole backend unreachable. (The
    listing fails too, so the backend degrades to the curated fallback.)"""
    attempts: list[str] = []

    def flaky_completion(**kwargs):
        attempts.append(kwargs["model"])
        if len(attempts) == 1:
            raise RuntimeError(
                "GeminiException - 404: model is no longer available to new users"
            )
        return {"choices": [{"message": {"content": "ok"}}]}

    monkeypatch.setattr("app.model.health.httpx.get", _fake_get(exc=httpx.ConnectError("offline")))
    monkeypatch.setattr("app.model.health.litellm.completion", flaky_completion)
    h = check_backend(_backend("gemini", api_key="AIza-x"))
    assert h.reachable is True
    assert h.status == "ok"
    assert h.probe_ok is True
    # The walk moved on to the next curated model and recorded it.
    assert attempts == ["gemini/gemini-3.5-flash", "gemini/gemini-3.6-flash"]
    assert h.probe_model == "gemini-3.6-flash"


def test_check_suggested_configured_model_probed_as_is(monkeypatch):
    """A user-picked model is probed exactly - the walk only applies when no
    model is configured (so a broken choice fails loudly, not silently)."""
    attempts: list[str] = []

    def failing_completion(**kwargs):
        attempts.append(kwargs["model"])
        raise RuntimeError("model not found")

    monkeypatch.setattr("app.model.health.httpx.get", _fake_get(exc=httpx.ConnectError("offline")))
    monkeypatch.setattr("app.model.health.litellm.completion", failing_completion)
    h = check_backend(_backend("gemini", model="gemini-3.5-flash", api_key="AIza-x"))
    assert h.probe_ok is False
    assert attempts == ["gemini/gemini-3.5-flash"]


def test_check_suggested_deprecated_all_fail_carries_hint(monkeypatch):
    """The Settings probe must explain Google's deprecation 404 with an
    actionable hint, not just a bare failure."""

    def failing_completion(**kwargs):
        raise RuntimeError(
            "GeminiException - { \"error\": { \"code\": 404, \"message\": "
            "\"This model models/gemini-2.5-flash is no longer available to new users\" } }"
        )

    monkeypatch.setattr("app.model.health.httpx.get", _fake_get(exc=httpx.ConnectError("offline")))
    monkeypatch.setattr("app.model.health.litellm.completion", failing_completion)
    h = check_backend(_backend("gemini", api_key="AIza-x"))
    assert h.reachable is False
    assert h.status == "unreachable"
    assert "no longer available to new users" in (h.error or "")
    assert "no longer served to this account" in (h.error or "")


def test_check_anthropic_lightweight_verifies_via_live_listing(monkeypatch):
    # probe=False on a live-listing provider (Anthropic now) verifies via the
    # listing alone - no completion round-trip, but genuinely reachable.
    seen = {"probe": False}

    def failing_probe(**kwargs):
        seen["probe"] = True
        raise RuntimeError("should not be called")

    monkeypatch.setattr(
        "app.model.health.httpx.get",
        _fake_get({"data": [{"id": "claude-sonnet-4-20250514"}]}),
    )
    monkeypatch.setattr("app.model.health.litellm.completion", failing_probe)
    h = check_backend(
        _backend("anthropic", model="claude-sonnet-4-20250514", api_key="sk-x"), probe=False
    )
    assert h.reachable is True
    assert h.status == "ok"
    assert seen["probe"] is False
    assert h.probe_ok is None


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
