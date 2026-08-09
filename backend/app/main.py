from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import health, models, scans, search
from app.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create the working data directory on startup."""
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    yield


app = FastAPI(title=settings.app_name, version=settings.version, lifespan=lifespan)

app.include_router(health.router, prefix="/api/v1")
app.include_router(scans.router, prefix="/api/v1")
app.include_router(models.router, prefix="/api/v1")
app.include_router(search.router, prefix="/api/v1")


@app.get("/")
def root():
    """Serve the SPA shell at the root when the frontend is bundled (the
    container), otherwise the bare API banner (backend-only dev)."""
    if (_frontend_dist / "index.html").is_file():
        return FileResponse(_frontend_dist / "index.html")
    return {"app": settings.app_name, "version": settings.version, "docs": "/docs"}


# ---- M5: serve the built frontend from the same origin -----------------------
# No-op while frontend/dist doesn't exist (backend-only dev); when it does,
# the SPA fallback answers every non-/api path with index.html so the Vite
# build works without a separate static server. Unknown /api/* paths still
# 404 rather than silently returning the SPA shell.
_frontend_dist = settings.frontend_dist.resolve()
if (_frontend_dist / "index.html").is_file():
    _assets = _frontend_dist / "assets"
    if _assets.is_dir():
        app.mount("/assets", StaticFiles(directory=_assets), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa_fallback(path: str) -> FileResponse:
        if path == "api" or path.startswith("api/"):
            raise HTTPException(status_code=404, detail="unknown API route")
        candidate = _frontend_dist / path
        if path and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(_frontend_dist / "index.html")
