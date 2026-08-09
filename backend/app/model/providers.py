"""Provider table — single source of truth for M3's backend definitions.

One auditable place for each provider's LiteLLM model-string prefix, env-var
name, key-required vs base-URL-only posture, model-listing path + parsing
style (``list_style``: OpenAI-shaped Bearer auth, Gemini's
``?key=``/``models/`` format, Anthropic's ``x-api-key`` headers), and a
static fallback model list (used only as the offline fallback when a live
fetch fails — Anthropic/Gemini — or when a provider has no endpoint at
all).

Curated v1 BYOK set (owner decision): OpenAI, Anthropic, DeepSeek, OpenRouter,
Google Gemini, plus a base-URL-only ``custom`` kind for any OpenAI-compatible
endpoint. LiteLLM's env-var names and model-string formats drift across
versions, so anything touching a provider goes through this table rather than
being scattered through the code.
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
    # How the listing endpoint is called + parsed:
    #   "openai" — Bearer auth, `{"data": [{"id": ...}]}` (Ollama/LM
    #              Studio/OpenAI-compatible)
    #   "gemini" — `?key=` auth, `{"models": [{"name": "models/..."}]}`,
    #              filtered to generateContent-capable base models
    #   "anthropic" — `x-api-key` + `anthropic-version` headers (no Bearer),
    #              `{"data": [{"id": ...}]}` parse (OpenAI-shaped response)
    list_style: str = "openai"
    # Static fallback models used ONLY when a live listing fails or returns
    # empty (Anthropic/Gemini) or no listing endpoint exists. Kept
    # deliberately small — model names drift; the live list is the source of
    # truth whenever it works.
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
            # Anthropic DOES ship a live listing (`GET /v1/models`) — the
            # response is OpenAI-shaped but auth is not (x-api-key +
            # anthropic-version, no Bearer), so list_style="anthropic"
            # handles it. The curated list below is the OFFLINE fallback
            # only — the live list is the source of truth.
            models_path="/v1/models",
            list_style="anthropic",
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
            id="gemini",
            name="Google Gemini",
            kind="byok",
            model_prefix="gemini/",
            key_required=True,
            key_env_var="GEMINI_API_KEY",
            base_url_required=False,
            # LiteLLM builds `{api_base}/models/{model}:generateContent` — the
            # base must carry the API version root. v1beta is pinned because
            # MASA always passes api_base; only v1beta-compatible models are
            # curated (litellm routes Gemini 3+ previews to v1alpha on its own).
            default_base_url="https://generativelanguage.googleapis.com/v1beta",
            # Gemini DOES have a live listing (`GET /v1beta/models`) — it's
            # just not OpenAI-shaped, so list_style="gemini" handles the
            # `?key=` auth + `models/`-prefixed parse + generateContent
            # filter. The curated list below is the OFFLINE fallback only
            # (bad key / no network) — the live list is the source of truth,
            # so provider deprecations can never hard-break the app again.
            models_path="/models",
            list_style="gemini",
            suggested_models=(
                "gemini-3.5-flash",
                "gemini-3.6-flash",
                "gemini-3.5-flash-lite",
                "gemini-3.1-pro-preview",
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
        # Dev-only (M6 follow-up): MASA_FAKE_MODEL=1 seeds this backend and
        # model/client.py short-circuits it to a deterministic script — the
        # Agent dock's live steps + token streaming are demoable with zero
        # Ollama. Never contacted; the fake has no base_url and the model
        # listing falls back to the static "demo" model.
        Provider(
            id="fake",
            name="Fake (dev demo)",
            kind="local",
            model_prefix="fake/",
            key_required=False,
            key_env_var=None,
            base_url_required=False,
            default_base_url="",
            models_path=None,
            suggested_models=("demo",),
            dummy_key="fake",
        ),
    ]
}


def models_url(provider: Provider, base_url: str) -> str | None:
    """Absolute URL for the OpenAI-compatible model listing, or None if the
    provider has no such endpoint."""
    if provider.models_path is None:
        return None
    return f"{base_url.rstrip('/')}{provider.models_path}"
