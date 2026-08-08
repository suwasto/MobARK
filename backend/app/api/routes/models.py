"""M3/M5 API surface for model backends — what the Settings modal consumes.

    GET    /api/v1/model/backends            config + lightweight reachability
    POST   /api/v1/model/backends            create/activate BYOK or custom (M5)
    DELETE /api/v1/model/backends/{id}       remove a backend (M5)
    POST   /api/v1/model/backends/{id}/test  full health check (completion probe)
    GET    /api/v1/model/backends/{id}/models
    PUT    /api/v1/model/backends/{id}       upsert base_url/model/api_key/enabled

API keys are never returned — only ``has_api_key``.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, HTTPException, Response

from app.model.backends import BackendStore, ModelBackend, get_store
from app.model.health import BackendHealth, check_backend, list_models
from app.model.providers import PROVIDERS
from app.schemas import (
    ModelBackendCreate,
    ModelBackendHealth,
    ModelBackendModels,
    ModelBackendRead,
    ModelBackendUpsert,
)

router = APIRouter(prefix="/model", tags=["model"])


def _to_health(h: BackendHealth) -> ModelBackendHealth:
    return ModelBackendHealth(
        reachable=h.reachable,
        status=h.status,
        latency_ms=h.latency_ms,
        models=h.models,
        model_source=h.model_source,
        probe_model=h.probe_model,
        probe_ok=h.probe_ok,
        error=h.error,
        checked_at=h.checked_at,
    )


def _to_read(backend, health: BackendHealth | None) -> ModelBackendRead:
    return ModelBackendRead(
        id=backend.id,
        provider_id=backend.provider_id,
        name=backend.name,
        kind=backend.kind,
        base_url=backend.base_url,
        model=backend.model,
        enabled=backend.enabled,
        local=backend.local,
        has_api_key=backend.has_api_key(),
        suggested_models=list(backend.provider.suggested_models),
        health=_to_health(health) if health else None,
    )


def _find(store: BackendStore, backend_id: str):
    backend = store.get(backend_id)
    if backend is None:
        raise HTTPException(status_code=404, detail=f"unknown backend {backend_id!r}")
    return backend


@router.get("/backends", response_model=list[ModelBackendRead])
def list_backends() -> list[ModelBackendRead]:
    """All configured backends with a lightweight reachability state
    (model listing only — no completion probe; the probe lives in POST /test)."""
    store = get_store()
    backends = store.read()
    with ThreadPoolExecutor(max_workers=max(len(backends), 1)) as pool:
        healths = list(pool.map(lambda b: check_backend(b, probe=False), backends))
    return [_to_read(b, h) for b, h in zip(backends, healths, strict=True)]


@router.post("/backends", response_model=ModelBackendRead, status_code=201)
def create_backend(payload: ModelBackendCreate) -> ModelBackendRead:
    """Create/activate a BYOK or custom backend (Settings -> BYOK tab).

    - BYOK (openai/anthropic/deepseek/openrouter/gemini): requires an API
      key (BYOK backends are no longer seeded keyless — owner decision, Aug
      8 2026 — so this is the only way in); upserts the existing entry if
      present (re-activates a deleted or disabled one), otherwise creates it.
    - ``custom``: requires a base URL; id ``custom`` (one custom endpoint).
    - Local backends are pre-configured — edit them via PUT, not here.

    API keys are stored but never returned (only ``has_api_key``).
    """
    store = get_store()
    provider = PROVIDERS.get(payload.provider_id)
    if provider is None:
        raise HTTPException(
            status_code=400,
            detail=f"unknown provider {payload.provider_id!r} "
            f"(expected one of {', '.join(sorted(PROVIDERS))})",
        )
    if provider.kind == "local":
        raise HTTPException(
            status_code=400,
            detail=f"{provider.name} is a local backend — edit it via "
            "PUT /api/v1/model/backends/{id}",
        )

    existing = store.get(provider.id)
    if existing is not None:
        backend = store.upsert(
            provider.id,
            base_url=payload.base_url,
            api_key=payload.api_key,
            model=payload.model,
            enabled=True,
        )
        return _to_read(backend, None)

    if provider.kind == "byok":
        if not payload.api_key:
            raise HTTPException(
                status_code=400,
                detail=f"{provider.name} requires an API key",
            )
        backend = ModelBackend(
            id=provider.id,
            provider_id=provider.id,
            name=provider.name,
            kind="byok",
            base_url=payload.base_url or provider.default_base_url,
            model=payload.model or "",
            api_key=payload.api_key,
            enabled=True,
        )
    else:  # custom — requires a base URL
        if not payload.base_url:
            raise HTTPException(
                status_code=400,
                detail="custom backends require a base URL",
            )
        backend = ModelBackend(
            id="custom",
            provider_id="custom",
            name="Custom (OpenAI-compatible)",
            kind="custom",
            base_url=payload.base_url,
            model=payload.model or "",
            api_key=payload.api_key,
            enabled=True,
        )
    try:
        store.add(backend)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _to_read(backend, None)


@router.delete("/backends/{backend_id}", status_code=204)
def delete_backend(backend_id: str) -> Response:
    """Remove a backend from the store.

    Local backends are protected (400) — removing the only local option is a
    footgun; disable them via PUT ``enabled: false`` instead. BYOK/custom
    can be re-added any time with POST /backends.
    """
    store = get_store()
    backend = store.get(backend_id)
    if backend is None:
        raise HTTPException(status_code=404, detail=f"unknown backend {backend_id!r}")
    if backend.kind == "local":
        raise HTTPException(
            status_code=400,
            detail="local backends cannot be removed — disable via PUT enabled=false",
        )
    store.remove(backend_id)
    return Response(status_code=204)


@router.post("/backends/{backend_id}/test", response_model=ModelBackendRead)
def test_backend(backend_id: str) -> ModelBackendRead:
    """Full health check: model listing + a cheap max_tokens=1 completion probe."""
    backend = _find(get_store(), backend_id)
    return _to_read(backend, check_backend(backend, probe=True))


@router.get("/backends/{backend_id}/models", response_model=ModelBackendModels)
def backend_models(backend_id: str) -> ModelBackendModels:
    backend = _find(get_store(), backend_id)
    models, source, error = list_models(backend)
    return ModelBackendModels(models=models, source=source, error=error)


@router.put("/backends/{backend_id}", response_model=ModelBackendRead)
def update_backend(backend_id: str, payload: ModelBackendUpsert) -> ModelBackendRead:
    """Runtime upsert of a backend's config (base_url/model/api_key/enabled)."""
    store = get_store()
    try:
        backend = store.upsert(
            backend_id,
            base_url=payload.base_url,
            model=payload.model,
            api_key=payload.api_key,
            enabled=payload.enabled,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return _to_read(backend, None)
