from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import settings
from app.db import get_db
from app.schemas import HealthResponse
from app.workers.redis import get_redis

router = APIRouter(tags=["health"])

DbSession = Annotated[Session, Depends(get_db)]


@router.get("/health", response_model=HealthResponse)
def health(db: DbSession) -> HealthResponse:
    """Liveness + dependency health. Also used as the Docker container healthcheck."""
    redis_ok = True
    try:
        get_redis().ping()
    except Exception:
        redis_ok = False

    db_ok = True
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        db_ok = False

    return HealthResponse(
        status="ok" if (redis_ok and db_ok) else "degraded",
        version=settings.version,
        redis_ok=redis_ok,
        db_ok=db_ok,
    )
