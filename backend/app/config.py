from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """MASA backend configuration.

    All values can be overridden via environment variables using the ``MASA_``
    prefix (e.g. ``MASA_REDIS_URL``) or a local ``.env`` file.
    """

    model_config = SettingsConfigDict(env_prefix="MASA_", env_file=".env", extra="ignore")

    app_name: str = "MASA"
    version: str = "0.1.0"

    database_url: str = "sqlite:///./data/masa.db"
    redis_url: str = "redis://localhost:6379/0"
    data_dir: Path = Path("./data")
    log_level: str = "INFO"

    # ---- M1 analysis tools ----
    # Directory containing vendored tool installs (Docker layout). On the
    # host the tools are resolved from PATH unless the *_CMD overrides are set.
    tools_dir: Path = Path("/opt/masa-tools")
    jadx_cmd: str | None = None
    gitleaks_cmd: str | None = None
    semgrep_cmd: str | None = None
    java_home: str | None = None  # needed when jadx's JVM is not on PATH
    jadx_timeout_seconds: int = 1200
    jadx_threads: int = 4
    gitleaks_timeout_seconds: int = 600
    semgrep_timeout_seconds: int = 900

    # ---- M3 model backends ----
    # Local LLM servers on the host. Docker Compose overrides these with
    # host.docker.internal URLs so the container reaches the host.
    ollama_base_url: str = "http://localhost:11434"
    lm_studio_base_url: str = "http://localhost:1234/v1"

    # BYOK providers (curated v1 set; keys can also be entered at runtime via
    # the Settings modal / API — they seed the config store, not the app).
    openai_base_url: str = "https://api.openai.com/v1"
    anthropic_base_url: str = "https://api.anthropic.com"
    deepseek_base_url: str = "https://api.deepseek.com"
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    gemini_base_url: str = "https://generativelanguage.googleapis.com/v1beta"

    openai_api_key: str | None = None
    anthropic_api_key: str | None = None
    deepseek_api_key: str | None = None
    openrouter_api_key: str | None = None
    gemini_api_key: str | None = None

    # No hard default (M3 owner decision): blank means the user picks a model
    # from what the backend actually serves. Set MASA_DEFAULT_CHAT_MODEL to
    # seed a concrete default into every backend's config.
    default_chat_model: str = ""

    # ---- M4 Layer 3: Graphify code graph (Android) ----
    # The RAG/embedding path was removed from v1 by owner decision — no
    # embedding model or vector store config exists anymore.
    # graphify CLI (resolved from PATH when None, like jadx_cmd/gitleaks_cmd).
    graphify_cmd: str | None = None
    graphify_timeout_seconds: int = 1800

    # ---- M4/M6 agent chat ----
    # Dev-only fake LLM (M6 follow-up): MASA_FAKE_MODEL=1 seeds a
    # deterministic "fake" backend whose completions never touch a real
    # server — the dock's live tool steps + token streaming can be demoed
    # with zero Ollama. See app/model/fake.py for the script.
    # Alias note (live-verified Aug 9): pydantic-settings derives env names
    # from FIELD NAMES — ``fake_model_enabled`` would silently become
    # MASA_FAKE_MODEL_ENABLED, not the documented MASA_FAKE_MODEL. The
    # string alias fixes the env name; pydantic-settings uses the raw alias
    # for env lookup (the MASA_ prefix is NOT re-applied to aliases).
    fake_model_enabled: bool = Field(
        default=False,
        validation_alias="MASA_FAKE_MODEL",
    )
    # Hard overall deadline (seconds) for the whole agent tool loop in
    # answer_question — a hung LLM call can never block the API worker beyond
    # this. Per-request override: POST /scans/{id}/chat {timeout_seconds}.
    chat_timeout_seconds: int = 120
    # M6 Phase C: max tool-calling rounds before the context-only fallback.
    # Same pattern as chat_timeout_seconds: settings is the default, an
    # explicit argument (or ChatRequest.max_tool_rounds) wins.
    max_tool_rounds: int = 3

    # ---- M7 web research ----
    # The bundled SearXNG engine (compose profile `web`):
    # `docker compose --profile web up -d searxng`. Seeds the bundled search
    # backend's base URL (search_backends.json); editable in Settings.
    searxng_base_url: str = "http://localhost:8888"
    # Keyed search engines (Aug 9 follow-up): Brave/Serper/Mojeek. Keys seed
    # the search store only when set via env (mirrors the model BYOK
    # seeding — no keyless entry is ever seeded); the Settings -> Search &
    # research add-form is the runtime path. Env names derive from the field
    # names: MASA_BRAVE_API_KEY, MASA_SERPER_API_KEY, MASA_MOJEK_API_KEY.
    brave_api_key: str | None = None
    serper_api_key: str | None = None
    mojeek_api_key: str | None = None
    # Per-call bounds for the agent's web tools (web_search / web_fetch).
    web_search_timeout_seconds: int = 20
    web_fetch_timeout_seconds: int = 20
    # Hard cap on the raw HTML read into memory before trafilatura extraction.
    web_fetch_max_bytes: int = 1_000_000

    # ---- M5 dashboard ----
    # Upload size cap for POST /api/v1/scans (413 over the limit).
    max_upload_mb: int = 200
    # Built frontend (frontend/dist) served by FastAPI with an SPA fallback
    # when the directory exists; no-op during backend-only dev.
    frontend_dist: Path = Path("../frontend/dist")


settings = Settings()
