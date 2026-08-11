"""M7 API surface for search backends (web research engines).

    GET    /api/v1/search/backends            config + lightweight reachability
    POST   /api/v1/search/backends            add a custom SearXNG-compatible instance
    DELETE /api/v1/search/backends/{id}       remove a backend
    PUT    /api/v1/search/backends/{id}       upsert base_url / enabled (radio)
    POST   /api/v1/search/backends/{id}/test  full probe (real search query)
    POST   /api/v1/search/backends/{id}/start one-click start (bundled engine only)

``PUT {enabled: true}`` enforces the one-Active radio server-side
(``SearchStore.enable_only``) - a raw API client can never leave two engines
Active, mirroring ``pick_chat_backend`` determinism in the model layer
(owner decision, Aug 9). The bundled ``searxng`` entry is deletable/editable
like any other (the store file, not the seed table, is the source of truth).
"""
from __future__ import annotations

import subprocess
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException, Response

from app.schemas import (
    SearchBackendCreate,
    SearchBackendRead,
    SearchBackendUpsert,
    SearchProviderRead,
)
from app.search.backends import SearchBackend, SearchStore, get_search_store
from app.search.client import SearchHealth, check_backend
from app.search.providers import SEARCH_PROVIDERS

router = APIRouter(prefix="/search", tags=["search"])


def _to_health(h: SearchHealth):
    """SearchHealth dataclass -> the API schema (kept local so the route
    file stays small - the schema lives in app.schemas, mirrored by the
    frontend types)."""
    from app.schemas import SearchBackendHealth

    return SearchBackendHealth(
        reachable=h.reachable,
        status=h.status,
        latency_ms=h.latency_ms,
        error=h.error,
        checked_at=h.checked_at,
        result_count=h.result_count,
        sample_title=h.sample_title,
    )


def _to_read(backend: SearchBackend, health: SearchHealth | None) -> SearchBackendRead:
    return SearchBackendRead(
        id=backend.id,
        provider_id=backend.provider_id,
        name=backend.name,
        kind=backend.kind,
        base_url=backend.base_url,
        enabled=backend.enabled,
        order=backend.order,
        # The key itself is never returned - only whether one is set.
        has_api_key=backend.has_api_key(),
        health=_to_health(health) if health else None,
    )


def _find(store: SearchStore, backend_id: str) -> SearchBackend:
    backend = store.get(backend_id)
    if backend is None:
        raise HTTPException(status_code=404, detail=f"unknown search backend {backend_id!r}")
    return backend


@router.get("/backends", response_model=list[SearchBackendRead])
def list_search_backends() -> list[SearchBackendRead]:
    """All configured search engines with lightweight reachability (base URL
    HTTP check only - the real search probe lives in POST /test).

    SearXNG-style engines (bundled + custom) are probed even when INACTIVE:
    their lightweight check is a cheap base-URL HTTP GET, and the Settings
    radio needs it to keep the Active toggle disabled until the engine is
    actually reachable (owner follow-up, Aug 11 - a dead engine can't be
    activated, and the Agent dock 🌐 toggle needs the same liveness signal
    for the Active engine). Keyed engines keep the enabled-only rule: their
    honest health check IS a real query (it validates the key - the base URL
    has no meaningful root endpoint), so an inactive keyed engine is never
    probed on the list route. Cost note: a list call blocks up to the 3s
    lightweight timeout per dead searxng-style backend - fine for the bundled
    engine; a large fleet of dead custom instances could stack (accepted at
    this scale, and the UI poll is 4s)."""
    store = get_search_store()
    backends = store.read()
    return [
        _to_read(
            b,
            check_backend(b, probe=False)
            if b.enabled or b.provider.query_style == "searxng"
            else None,
        )
        for b in backends
    ]


@router.get("/providers", response_model=list[SearchProviderRead])
def list_search_providers() -> list[SearchProviderRead]:
    """The addable engine set (Settings add-form picker) - everything except
    the bundled SearXNG, which is always present and edited, never re-added.
    Single source of truth: the provider table, mirrored to the UI."""
    return [
        SearchProviderRead(
            id=p.id,
            name=p.name,
            kind=p.kind,
            base_url_required=p.base_url_required,
            key_required=p.key_required,
            default_base_url=p.default_base_url,
        )
        for p in SEARCH_PROVIDERS.values()
        if p.id != "searxng"
    ]


@router.post("/backends", response_model=SearchBackendRead, status_code=201)
def create_search_backend(payload: SearchBackendCreate) -> SearchBackendRead:
    """Add a search engine (Settings -> Search & research): a custom
    SearXNG-compatible instance (base URL required, no key) or a keyed
    provider (Brave/Serper/Mojeek - API key required, base URL optional with
    a per-provider default). The new backend becomes Active (radio)."""
    store = get_search_store()
    provider = SEARCH_PROVIDERS.get(payload.provider_id)
    if provider is None:
        raise HTTPException(
            status_code=400,
            detail=f"unknown search provider {payload.provider_id!r} "
            f"(expected one of {', '.join(sorted(SEARCH_PROVIDERS))})",
        )
    if provider.id == "searxng":
        raise HTTPException(
            status_code=400,
            detail=f"{provider.name} is bundled - edit it via "
            "PUT /api/v1/search/backends/{id}",
        )
    if provider.key_required and not payload.api_key:
        raise HTTPException(
            status_code=400,
            detail=f"{provider.name} requires an API key",
        )
    if provider.base_url_required and not payload.base_url:
        raise HTTPException(
            status_code=400,
            detail=f"{provider.name} requires a base URL",
        )
    base_url = (payload.base_url or "").strip() or provider.default_base_url
    backend = SearchBackend(
        id=provider.id,
        provider_id=provider.id,
        name=provider.name,
        kind=provider.kind,
        base_url=base_url,
        api_key=payload.api_key,
        enabled=True,  # the radio: adding it turns the other engines off
    )
    try:
        store.add(backend)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _to_read(backend, None)


@router.delete("/backends/{backend_id}", status_code=204)
def delete_search_backend(backend_id: str) -> Response:
    """Remove a search backend. The bundled searxng entry is deletable too -
    the store file is the source of truth; a later re-add is a Settings
    action (or re-seed by removing the store file)."""
    store = get_search_store()
    if store.get(backend_id) is None:
        raise HTTPException(status_code=404, detail=f"unknown search backend {backend_id!r}")
    store.remove(backend_id)
    return Response(status_code=204)


@router.post("/backends/{backend_id}/test", response_model=SearchBackendRead)
def test_search_backend(backend_id: str) -> SearchBackendRead:
    """Full probe: a real search query against the engine, reporting the
    normalized result count - the honest check that the JSON format is
    enabled on the instance."""
    backend = _find(get_search_store(), backend_id)
    return _to_read(backend, check_backend(backend, probe=True))


@router.put("/backends/{backend_id}", response_model=SearchBackendRead)
def update_search_backend(backend_id: str, payload: SearchBackendUpsert) -> SearchBackendRead:
    """Runtime upsert of a search backend. ``enabled: true`` triggers the
    one-Active radio semantics (``enable_only``) server-side."""
    store = get_search_store()
    try:
        backend = store.upsert(
            backend_id,
            base_url=payload.base_url,
            api_key=payload.api_key,
            enabled=payload.enabled,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return _to_read(backend, None)


# ---- one-click start for the bundled engine (owner request, Aug 9) ----------
# Settings -> Search & research: when the probe fails on the bundled SearXNG,
# the UI offers a "Start engine" button instead of only the compose hint text.
# The backend runs the documented compose command - a FIXED argv list, no
# shell, no user input, so this is not an injection surface - then polls the
# engine until it answers. Only works when the API process has Docker on its
# host (host-run dev mode); inside the app container there is no docker
# CLI/socket and the error carries the manual command, exactly like every
# other self-explaining failure in MASA.


class _StartError(Exception):
    """Raised inside the start endpoint -> mapped to an HTTP error whose
    detail is self-explaining (the manual compose command on failure)."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def _find_compose_file() -> Path | None:
    """docker-compose.yml / compose.yml discovered upward from cwd - compose's
    own discovery only works when cwd IS the repo root; searching lets the
    backend run from anywhere (dev runs from ``backend/``). None when no file
    is found (e.g. inside the app container) - the plain command then fails
    with compose's own "no configuration file" error, surfaced as-is.

    Assumption (documented layout): the first match walking upward IS MASA's
    compose file. In a nested checkout inside a larger project with its own
    compose file, the wrong file could be picked - the 502 then surfaces the
    real error (stderr tail) so it stays diagnosable."""
    start = Path.cwd().resolve()
    for d in (start, *start.parents):
        for name in (
            "docker-compose.yml",
            "docker-compose.yaml",
            "compose.yml",
            "compose.yaml",
        ):
            candidate = d / name
            if candidate.is_file():
                return candidate
    return None


def _run_compose_up() -> None:
    """Run the documented bundled-engine start command and wait for compose to
    return (container started - NOT yet booted; callers poll the probe).
    Raises ``_StartError`` with the manual command on any failure."""
    cmd = ["docker", "compose", "--profile", "web", "up", "-d", "searxng"]
    compose_file = _find_compose_file()
    if compose_file is not None:
        cmd[2:2] = ["-f", str(compose_file)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        raise _StartError(
            502,
            "Docker isn't reachable from this process - start the engine "
            "manually: `docker compose --profile web up -d searxng`",
        ) from None
    except subprocess.TimeoutExpired:
        raise _StartError(
            504,
            "starting the engine timed out (an image pull may still be "
            "running) - start it manually: "
            "`docker compose --profile web up -d searxng`",
        ) from None
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()
        detail = tail[-1] if tail else "unknown error"
        raise _StartError(
            502,
            f"engine failed to start: {detail} - start it manually: "
            "`docker compose --profile web up -d searxng`",
        )


def _wait_for_engine(
    backend: SearchBackend,
    attempts: int = 12,
    delay: float = 3.0,
) -> SearchHealth:
    """After ``compose up`` returns, SearXNG still needs ~10-30s to boot -
    poll the lightweight reachability check, then run the full probe (a real
    query) once it answers. Never raises: a slow boot just returns the last
    unreachable health and the UI can re-test."""
    health = check_backend(backend, probe=False)
    for _ in range(attempts):
        if health.reachable:
            return check_backend(backend, probe=True)
        time.sleep(delay)
        health = check_backend(backend, probe=False)
    return health


@router.post("/backends/{backend_id}/start", response_model=SearchBackendRead)
def start_search_backend(backend_id: str) -> SearchBackendRead:
    """One-click start for the BUNDLED SearXNG engine (Settings -> Search &
    research - owner request, Aug 9). Runs the documented compose command
    server-side, waits for the engine to answer, and returns the fresh
    health. Custom instances are self-hosted and have no start command (400);
    Docker unreachable degrades to a 502 carrying the manual command."""
    store = get_search_store()
    backend = _find(store, backend_id)
    if backend.kind != "bundled":
        raise HTTPException(
            status_code=400,
            detail=f"{backend.name} is not bundled - only the bundled engine "
            "has a start command (custom instances are self-hosted)",
        )
    try:
        _run_compose_up()
    except _StartError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.message) from exc
    health = _wait_for_engine(backend)
    return _to_read(backend, health)
