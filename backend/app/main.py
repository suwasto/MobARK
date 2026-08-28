from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.deps import get_current_user
from app.api.middleware import OriginCheckMiddleware
from app.api.routes import health, models, scans, search
from app.auth import routes as auth_routes
from app.config import settings
from app.dynamic.base import DynamicError
from app.dynamic.mirror_router import router as mirror_router
from app.dynamic.router import router as dynamic_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create the working data directory on startup."""
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    yield


app = FastAPI(title=settings.app_name, version=settings.version, lifespan=lifespan)


@app.exception_handler(DynamicError)
async def dynamic_error_handler(request, exc: DynamicError) -> JSONResponse:
    """M11: the dynamic layer's errors carry their own HTTP status + human
    message - map them to clean 4xx/5xx responses so a known dynamic
    condition (missing tool, unreachable device, no-session, single-active
    conflict) never bubbles out as an opaque 500."""
    return JSONResponse(status_code=exc.status, content={"detail": exc.message})

# M9.1 (owner decision 7): health + auth are the ONLY open routers; every
# other /api/v1 route sits behind get_current_user via the router-level
# dependency (auth OFF -> the guard returns None and routes behave as
# before - the dev/CI parity mode).
_AUTH_DEPENDENCIES = [Depends(get_current_user)]

app.add_middleware(OriginCheckMiddleware)

# Auth stays OPEN - this is how a user becomes authenticated.
app.include_router(auth_routes.router, prefix="/api/v1")
app.include_router(health.router, prefix="/api/v1")
app.include_router(scans.router, prefix="/api/v1", dependencies=_AUTH_DEPENDENCIES)
app.include_router(models.router, prefix="/api/v1", dependencies=_AUTH_DEPENDENCIES)
app.include_router(search.router, prefix="/api/v1", dependencies=_AUTH_DEPENDENCIES)
app.include_router(dynamic_router, prefix="/api/v1", dependencies=_AUTH_DEPENDENCIES)
# M13: the mirror WebSocket route CANNOT ride a router whose list-deps
# include the Request-typed get_current_user (FastAPI can't build a Request
# from a websocket scope - verified). It authenticates IN-HANDLER (cookie ->
# session -> scan access) and 401/404-closes on failure. Included without
# the auth list-dep; the origin/cookie posture is unchanged.
app.include_router(mirror_router, prefix="/api/v1")


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
