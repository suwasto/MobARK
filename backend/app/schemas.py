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
