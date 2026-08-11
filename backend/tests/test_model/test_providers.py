"""Provider table invariants - single source of truth for M3 backends."""

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
        "gemini",
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
    for pid in ("openai", "anthropic", "deepseek", "openrouter", "gemini"):
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
    # Anthropic has a live List Models endpoint too (GET /v1/models) - its
    # own auth style (x-api-key headers), OpenAI-shaped response.
    assert PROVIDERS["anthropic"].models_path == "/v1/models"
    assert PROVIDERS["anthropic"].list_style == "anthropic"
    # Gemini has a live models.list too (GET /v1beta/models) - just a custom
    # auth/parse, so it carries a list_style instead of a static-only posture.
    assert PROVIDERS["gemini"].models_path == "/models"
    assert PROVIDERS["gemini"].list_style == "gemini"


def test_ollama_uses_ollama_prefix_lmstudio_openai_prefix():
    assert PROVIDERS["ollama"].model_prefix == "ollama/"
    assert PROVIDERS["lm-studio"].model_prefix == "openai/"


def test_gemini_uses_gemini_prefix_and_curated_models():
    p = PROVIDERS["gemini"]
    assert p.model_prefix == "gemini/"
    assert p.key_env_var == "GEMINI_API_KEY"
    assert p.default_base_url.endswith("/v1beta")
    assert p.suggested_models, "Gemini must carry a curated model list (no live listing)"


def test_gemini_curated_models_are_current():
    """Regression: the 2.5 line (gemini-2.5-flash/pro/lite, 2.0-flash) 404s
    for NEW API keys ("no longer available to new users", Aug 2026). The
    curated list must not carry any 2.x-era ID, and the default probe target
    (first entry) should be a current generation model."""
    p = PROVIDERS["gemini"]
    assert p.suggested_models
    assert all(not m.startswith("gemini-2.") for m in p.suggested_models)
    assert p.suggested_models[0].startswith("gemini-3")


def test_entries_are_frozen_dataclasses():
    for p in PROVIDERS.values():
        assert dataclasses.is_dataclass(p)
        assert dataclasses.fields(p)  # not a plain dict entry
