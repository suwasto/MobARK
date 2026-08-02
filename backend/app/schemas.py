from datetime import datetime

from pydantic import BaseModel, ConfigDict


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
    tool: str
    created_at: datetime
