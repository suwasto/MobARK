import json
from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator


class HealthResponse(BaseModel):
    status: str  # "ok" | "degraded"
    version: str
    redis_ok: bool
    db_ok: bool


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    filename: str
    platform: str | None
    status: str
    risk_score: int | None
    error: str | None
    created_at: datetime


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    title: str
    severity: str
    file_path: str | None
    line_number: int | None
    category: str | None
    mastg_test_id: str | None
    tool: str
    detail: dict | None = None
    static_only: bool = True
    created_at: datetime

    @field_validator("detail", mode="before")
    @classmethod
    def _parse_detail(cls, value):
        """The detail column stores tool payloads as JSON text."""
        if isinstance(value, str) and value:
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return {"raw": value}
        return value


# ---- M3 model backends (consumed by M5's Settings modal) ----


class ModelBackendHealth(BaseModel):
    reachable: bool
    status: str  # "ok" | "unreachable" | "unknown"
    latency_ms: int | None = None
    models: list[str] = []
    model_source: str = "none"  # "live" | "suggested" | "unavailable" | "none"
    probe_model: str | None = None
    probe_ok: bool | None = None
    error: str | None = None
    checked_at: datetime | None = None


class ModelBackendRead(BaseModel):
    id: str
    provider_id: str
    name: str
    kind: str  # "local" | "byok" | "custom"
    base_url: str
    model: str = ""
    enabled: bool = True
    local: bool
    has_api_key: bool  # never the key itself
    health: ModelBackendHealth | None = None


class ModelBackendUpsert(BaseModel):
    """Runtime edits to a backend's config. Empty ``api_key`` clears the stored
    key; None leaves the field unchanged."""

    base_url: str | None = None
    model: str | None = None
    api_key: str | None = None
    enabled: bool | None = None


class ModelBackendModels(BaseModel):
    models: list[str] = []
    source: str = "none"  # "live" | "suggested" | "unavailable"
    error: str | None = None
