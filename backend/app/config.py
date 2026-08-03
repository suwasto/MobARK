from pathlib import Path

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


settings = Settings()
