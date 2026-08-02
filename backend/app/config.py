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


settings = Settings()
