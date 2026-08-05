"""M3 API surface for model backends — what M5's Settings modal will consume.

    GET  /api/v1/model/backends            config + lightweight reachability
    POST /api/v1/model/backends/{id}/test  full health check (completion probe)
    GET  /api/v1/model/backends/{id}/models
    PUT  /api/v1/model/backends/{id}       upsert base_url/model/api_key/enabled

API keys are never returned — only ``has_api_key``.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, HTTPException

from app.model.backends import BackendStore, get_store
from app.model.health import BackendHealth, check_backend, list_models
from app.schemas import (
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
