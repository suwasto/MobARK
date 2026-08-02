from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.routes import health, scans
from app.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create the working data directory on startup."""
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    yield


app = FastAPI(title=settings.app_name, version=settings.version, lifespan=lifespan)

app.include_router(health.router, prefix="/api/v1")
app.include_router(scans.router, prefix="/api/v1")


@app.get("/")
def root() -> dict:
    return {"app": settings.app_name, "version": settings.version, "docs": "/docs"}
