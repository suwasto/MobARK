"""client.chat / model_string — litellm monkeypatched, no network."""

import pytest

from app.model import client
from app.model.backends import ModelBackend
from app.model.providers import PROVIDERS


def _backend(provider_id: str, base_url: str, model: str = "qwen2.5", api_key: str | None = None):
    p = PROVIDERS[provider_id]
    return ModelBackend(
        id=provider_id,
        provider_id=provider_id,
        name=p.name,
        kind=p.kind,
        base_url=base_url,
        model=model,
        api_key=api_key or p.dummy_key,
    )


def test_model_string_local_ollama():
    assert client.model_string(_backend("ollama", "http://localhost:11434")) == "ollama/qwen2.5"


def test_model_string_lm_studio_uses_openai_prefix():
    b = _backend("lm-studio", "http://localhost:1234/v1")
    assert client.model_string(b) == "openai/qwen2.5"


def test_model_string_byok_prefixed():
    b = _backend("openai", "https://api.openai.com/v1", model="gpt-4o-mini", api_key="sk-x")
    assert client.model_string(b) == "openai/gpt-4o-mini"


def test_model_string_openrouter_keeps_full_path():
    b = _backend(
        "openrouter",
        "https://openrouter.ai/api/v1",
        model="anthropic/claude-3.5-sonnet",
        api_key="sk-x",
    )
    assert client.model_string(b) == "openrouter/anthropic/claude-3.5-sonnet"


def test_model_string_custom_raw():
    b = _backend("custom", "http://192.168.1.5:8080/v1", model="my-model")
    assert client.model_string(b) == "my-model"


def test_model_string_requires_model():
    b = _backend("ollama", "http://localhost:11434", model="")
    with pytest.raises(ValueError, match="no model"):
        client.model_string(b)


def test_chat_passes_backend_mapping(monkeypatch):
    captured = {}

    def fake_completion(**kwargs):
        captured.update(kwargs)
        return {"choices": [{"message": {"content": "hi"}}]}

    monkeypatch.setattr(client.litellm, "completion", fake_completion)
    b = _backend("ollama", "http://localhost:11434")
    out = client.chat(b, [{"role": "user", "content": "ping"}], max_tokens=1)

    assert out["choices"][0]["message"]["content"] == "hi"
    assert captured["model"] == "ollama/qwen2.5"
    assert captured["api_base"] == "http://localhost:11434"
    assert captured["api_key"] == "ollama"  # dummy key for local servers
    assert captured["max_tokens"] == 1
    # Local thinking models (Nanbeige4.2) would burn the budget on <think>
    # blocks — Ollama calls must carry think:false.
    assert captured["extra_body"] == {"think": False}


def test_chat_byok_passes_key(monkeypatch):
    captured = {}

    def fake_completion(**kwargs):
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(client.litellm, "completion", fake_completion)
    b = _backend("openai", "https://api.openai.com/v1", model="gpt-4o-mini", api_key="sk-real")
    client.chat(b, [{"role": "user", "content": "ping"}])
    assert captured["model"] == "openai/gpt-4o-mini"
    assert captured["api_key"] == "sk-real"
    assert "extra_body" not in captured  # think:false is Ollama-only


def test_chat_callers_extra_body_merged_with_think_false(monkeypatch):
    """A caller-supplied extra_body survives alongside the think flag."""
    captured = {}

    def fake_completion(**kwargs):
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(client.litellm, "completion", fake_completion)
    b = _backend("ollama", "http://localhost:11434")
    client.chat(b, [{"role": "user", "content": "ping"}], extra_body={"num_ctx": 8192})
    assert captured["extra_body"] == {"num_ctx": 8192, "think": False}


def test_chat_raises_without_model(monkeypatch):
    def fake_completion(**kwargs):  # pragma: no cover - must not be reached
        raise AssertionError("completion must not be called without a model")

    monkeypatch.setattr(client.litellm, "completion", fake_completion)
    b = _backend("ollama", "http://localhost:11434", model="")
    with pytest.raises(ValueError, match="no model"):
        client.chat(b, [{"role": "user", "content": "ping"}])
