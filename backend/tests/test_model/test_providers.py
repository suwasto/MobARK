"""Provider table invariants — single source of truth for M3 backends."""

import dataclasses

from app.model.providers import PROVIDERS


def test_curated_provider_set_present():
    ids = set(PROVIDERS)
    assert {
        "ollama",
        "lm-studio",
        "openai",
        "anthropic",
        "deepseek",
        "openrouter",
        "custom",
    } <= ids


def test_local_providers_need_no_key():
    for pid in ("ollama", "lm-studio"):
        p = PROVIDERS[pid]
        assert p.kind == "local"
        assert p.key_required is False
        assert p.key_env_var is None
        assert p.dummy_key, "local servers must carry a dummy key for LiteLLM"


def test_byok_providers_require_keys_with_env_vars():
    for pid in ("openai", "anthropic", "deepseek", "openrouter"):
        p = PROVIDERS[pid]
        assert p.kind == "byok"
        assert p.key_required is True
        assert p.key_env_var and p.key_env_var.endswith("_API_KEY")


def test_custom_is_base_url_only():
    p = PROVIDERS["custom"]
    assert p.kind == "custom"
    assert p.key_required is False
    assert p.base_url_required is True
    assert p.model_prefix == ""


def test_live_listing_paths():
    # Ollama serves its OpenAI-compatible /models under /v1; the others under
    # their base URL root.
    assert PROVIDERS["ollama"].models_path == "/v1/models"
    for pid in ("lm-studio", "openai", "deepseek", "openrouter", "custom"):
        assert PROVIDERS[pid].models_path == "/models"
    assert PROVIDERS["anthropic"].models_path is None


def test_ollama_uses_ollama_prefix_lmstudio_openai_prefix():
    assert PROVIDERS["ollama"].model_prefix == "ollama/"
    assert PROVIDERS["lm-studio"].model_prefix == "openai/"


def test_entries_are_frozen_dataclasses():
    for p in PROVIDERS.values():
        assert dataclasses.is_dataclass(p)
        assert dataclasses.fields(p)  # not a plain dict entry
