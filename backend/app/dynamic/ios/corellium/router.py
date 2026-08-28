"""M17 Corellium config API (opt-in, off by default).

    GET    /api/v1/dynamic/corellium/config   the config (key never returned)
    PUT    /api/v1/dynamic/corellium/config   upsert base_url / api_key / enabled
    DELETE /api/v1/dynamic/corellium/config   clear (off by default again)
    POST   /api/v1/dynamic/corellium/test     reachability + instance-count probe

Per-user: ``get_corellium_store`` resolves the CALLER's store from the request
context (``request_ctx.current_user_id``), so a Corellium key is isolated per
user exactly like the model/search BYOK keys (M9.1). API keys are stored
vault-encrypted (AES-GCM) in a per-user store and NEVER returned - only
``has_api_key`` / ``configured``.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Response

from app.auth import vault
from app.dynamic.ios.corellium.client import CorelliumClient, CorelliumError
from app.dynamic.ios.corellium.config import get_corellium_store
from app.schemas import CorelliumConfigRead, CorelliumConfigUpsert, CorelliumHealth

router = APIRouter(prefix="/dynamic/corellium", tags=["dynamic"])


@router.get("/config", response_model=CorelliumConfigRead)
def get_config() -> CorelliumConfigRead:
    """The Corellium config, key never returned (only ``has_api_key``)."""
    cfg = get_corellium_store().read()
    return CorelliumConfigRead(
        base_url=cfg.base_url,
        has_api_key=cfg.has_api_key(),
        configured=cfg.configured(),
        enabled=cfg.enabled,
    )


@router.put("/config", response_model=CorelliumConfigRead)
def put_config(payload: CorelliumConfigUpsert) -> CorelliumConfigRead:
    """Upsert the Corellium config (base_url / api_key / enabled). An empty
    ``api_key`` clears the key; an empty ``base_url`` clears the whole config.
    A key-write on a per-user store requires the vault unlocked (never lands
    plaintext at rest)."""
    store = get_corellium_store()
    try:
        cfg = store.upsert(
            base_url=payload.base_url,
            api_key=payload.api_key,
            enabled=payload.enabled,
        )
    except vault.VaultLockedError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return CorelliumConfigRead(
        base_url=cfg.base_url,
        has_api_key=cfg.has_api_key(),
        configured=cfg.configured(),
        enabled=cfg.enabled,
    )


@router.delete("/config", status_code=204)
def delete_config() -> Response:
    """Clear the Corellium config - back to the off-by-default unconfigured
    state (FR-D5a)."""
    get_corellium_store().clear()
    return Response(status_code=204)


@router.post("/test", response_model=CorelliumHealth)
def test_config() -> CorelliumHealth:
    """Reachability probe: validates the base URL + API key against the real
    Corellium API and reports how many virtual iOS instances the key can see
    (the Settings probe - the same role as model/search ``/test``)."""
    store = get_corellium_store()
    cfg = store.read()
    if not cfg.configured():
        return CorelliumHealth(configured=False, reachable=False)
    key = cfg.resolved_api_key()
    client = CorelliumClient(cfg.base_url, key or "")
    try:
        instances = client.instances()
    except CorelliumError as exc:
        return CorelliumHealth(
            configured=True, reachable=False, instance_count=0, error=exc.message
        )
    return CorelliumHealth(
        configured=True, reachable=True, instance_count=len(instances)
    )