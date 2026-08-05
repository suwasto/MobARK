"""Provider table — single source of truth for M3's backend definitions.

One auditable place for each provider's LiteLLM model-string prefix, env-var
name, key-required vs base-URL-only posture, OpenAI-compatible model-listing
path, and a static fallback model list (used when a provider exposes no live
listing endpoint, e.g. Anthropic).

Curated v1 BYOK set (owner decision): OpenAI, Anthropic, DeepSeek, OpenRouter,
plus a base-URL-only ``custom`` kind for any OpenAI-compatible endpoint.
LiteLLM's env-var names and model-string formats drift across versions, so
anything touching a provider goes through this table rather than being
scattered through the code.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Provider:
    id: str
    name: str
    kind: str  # "local" | "byok" | "custom"
    model_prefix: str  # LiteLLM model-string prefix, e.g. "ollama/", "openai/", ""
    key_required: bool
    key_env_var: str | None  # env var that seeds the API key (None: no key)
    base_url_required: bool
    default_base_url: str
    models_path: str | None  # path under base_url for the GET /models listing
    # Static fallback models when there is no live listing endpoint. Kept
    # deliberately small — model names drift; update in place when needed.
    suggested_models: tuple[str, ...] = ()
    dummy_key: str | None = None  # placeholder key for local servers


PROVIDERS: dict[str, Provider] = {
    p.id: p
    for p in [
        Provider(
            id="ollama",
            name="Ollama",
            kind="local",
            model_prefix="ollama/",
            key_required=False,
            key_env_var=None,
            base_url_required=False,
            default_base_url="http://localhost:11434",
            models_path="/v1/models",
            dummy_key="ollama",
        ),
        Provider(
            id="lm-studio",
            name="LM Studio",
            kind="local",
            model_prefix="openai/",
            key_required=False,
            key_env_var=None,
            base_url_required=False,
            default_base_url="http://localhost:1234/v1",
            models_path="/models",
            dummy_key="lm-studio",
        ),
        Provider(
            id="openai",
            name="OpenAI",
            kind="byok",
            model_prefix="openai/",
            key_required=True,
            key_env_var="OPENAI_API_KEY",
            base_url_required=False,
            default_base_url="https://api.openai.com/v1",
            models_path="/models",
            suggested_models=("gpt-4o-mini", "gpt-4o", "gpt-4.1-mini"),
        ),
        Provider(
            id="anthropic",
            name="Anthropic",
            kind="byok",
            model_prefix="anthropic/",
            key_required=True,
            key_env_var="ANTHROPIC_API_KEY",
            base_url_required=False,
            default_base_url="https://api.anthropic.com",
            models_path=None,  # no OpenAI-compatible listing endpoint
            suggested_models=(
                "claude-sonnet-4-20250514",
                "claude-opus-4-20250514",
                "claude-haiku-4-5-20251001",
            ),
        ),
        Provider(
            id="deepseek",
            name="DeepSeek",
            kind="byok",
            model_prefix="deepseek/",
            key_required=True,
            key_env_var="DEEPSEEK_API_KEY",
            base_url_required=False,
            default_base_url="https://api.deepseek.com",
            models_path="/models",
            suggested_models=("deepseek-chat", "deepseek-reasoner"),
        ),
        Provider(
            id="openrouter",
            name="OpenRouter",
            kind="byok",
            model_prefix="openrouter/",
            key_required=True,
            key_env_var="OPENROUTER_API_KEY",
            base_url_required=False,
            default_base_url="https://openrouter.ai/api/v1",
            models_path="/models",
            suggested_models=(
                "openai/gpt-4o-mini",
                "anthropic/claude-3.5-sonnet",
                "deepseek/deepseek-chat",
            ),
        ),
        Provider(
            id="custom",
            name="Custom (OpenAI-compatible)",
            kind="custom",
            model_prefix="",
            key_required=False,
            key_env_var=None,
            base_url_required=True,
            default_base_url="",
            models_path="/models",
        ),
    ]
}


def models_url(provider: Provider, base_url: str) -> str | None:
    """Absolute URL for the OpenAI-compatible model listing, or None if the
    provider has no such endpoint."""
    if provider.models_path is None:
        return None
    return f"{base_url.rstrip('/')}{provider.models_path}"
