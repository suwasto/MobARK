"""M11 (V2) dynamic analysis API - device discovery + session lifecycle.

    GET  /api/v1/dynamic/devices?platform=android|ios
    GET  /api/v1/dynamic/preflight?platform=&device_id=&target_app=
    POST /api/v1/dynamic/session/connect   {scan_id, platform, device_id, target_app}
    POST /api/v1/dynamic/session/disconnect
    GET  /api/v1/dynamic/session

Mounted in main.py under ``Depends(get_current_user)`` (auth stays the outer
gate) with the ``/api/v1/dynamic/...`` prefix - same posture as scans. Every
known failure maps to a clean HTTP error via ``DynamicError`` (never a raw
500): 404 no-session / foreign-scan, 409 preflight-reject or already-active
(FR-D5 one-scan-one-device), 502 device/tool unreachable.
"""
from __future__ import annotations

import json
import queue
import threading
from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from app.api.deps import DbSession, require_scan_access
from app.dynamic import base, events, scripts
from app.dynamic.base import (
    DynamicError,
    NoActiveSession,
    PreflightError,
    SessionConflict,
)
from app.dynamic.client import get_backend
from app.models import DynamicSession
from app.request_ctx import current_user_id
from app.schemas import (
    DynamicDefaultHook,
    DynamicDevice,
    DynamicEvent,
    DynamicEventCreate,
    DynamicPreflight,
    DynamicSessionConnect,
    DynamicSessionRead,
)

router = APIRouter(prefix="/dynamic", tags=["dynamic"])


def _device_name(backend, device_id: str, platform: str) -> str:
    try:
        for dev in backend.list_devices():
            if dev["id"] == device_id:
                return dev["name"]
    except DynamicError:
        pass
    return device_id


@router.get("/devices", response_model=list[DynamicDevice])
def list_devices(platform: str) -> list[DynamicDevice]:
    """Discovery (FR-D2): ``adb`` for Android, ``pymobiledevice3`` for iOS.
    An empty list is a clean response (no devices), not an error."""
    backend = get_backend(platform)
    return [
        DynamicDevice(
            id=d["id"],
            name=d["name"],
            platform=platform,
            model=d["model"],
            detail=d["detail"],
        )
        for d in backend.list_devices()
    ]


@router.get("/preflight", response_model=DynamicPreflight)
def preflight(
    platform: str, device_id: str, target_app: str
) -> DynamicPreflight:
    """FR-D1 gate: per-check booleans, never a crash for a failed check.
    Returns the checklist (adb_ok/device_present/frida_server_reachable/
    target_installed for Android; device_reachable/frida_server_reachable/
    jailbreak_detected/target_installed for iOS)."""
    backend = get_backend(platform)
    checks = backend.preflight(device_id, target_app)
    return DynamicPreflight(
        platform=platform,
        device_id=device_id,
        target_app=target_app,
        checks=checks,
        ok=all(checks.values()),
    )


@router.post("/session/connect", response_model=DynamicSessionRead)
def connect_session(payload: DynamicSessionConnect, db: DbSession) -> DynamicSessionRead:
    """Start a dynamic session: verify scan access, gate on preflight, attach
    Frida by package/bundle id, persist + activate (FR-D3, FR-D5)."""
    if base.active_session() is not None:
        raise SessionConflict(
            409,
            "a dynamic session is already active - disconnect it first",
        )
    scan = require_scan_access(db, payload.scan_id, current_user_id.get())
    if scan.platform is not None and scan.platform != payload.platform:
        raise HTTPException(
            status_code=409,
            detail=f"scan {scan.id} is {scan.platform}, not {payload.platform}",
        )
    backend = get_backend(payload.platform)
    checks = backend.preflight(payload.device_id, payload.target_app)
    failed = [name for name, ok in checks.items() if not ok]
    if failed:
        raise PreflightError(
            409,
            "dynamic session not started - preflight failed: "
            + ", ".join(failed)
            + " (each check must pass before connecting)",
        )
    artifact_path = None
    if payload.platform == "android" and scan.storage_path:
        artifact = Path(scan.storage_path) / scan.filename
        if artifact.is_file():
            artifact_path = str(artifact)
    try:
        meta = backend.attach(
            payload.device_id, payload.target_app, artifact_path
        )
    except DynamicError as exc:
        row = DynamicSession(
            scan_id=scan.id,
            platform=payload.platform,
            state="error",
            device_id=payload.device_id,
            connection_type="adb" if payload.platform == "android" else "ssh",
            last_error=exc.message,
        )
        db.add(row)
        db.commit()
        raise HTTPException(status_code=exc.status, detail=exc.message) from exc
    row = DynamicSession(
        scan_id=scan.id,
        platform=payload.platform,
        state="attached",
        device_id=payload.device_id,
        device_name=_device_name(backend, payload.device_id, payload.platform),
        connection_type=meta.get("connection_type"),
        frida_version=meta.get("frida_version"),
        target_pid=meta.get("target_pid"),
        root_status=meta.get("root_status"),
        jailbreak_method=meta.get("jailbreak_method"),
        corellium_enabled=False,
        started_at=datetime.now(UTC),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    try:
        base.begin_session(
            base.ActiveSession(
                row_id=row.id,
                scan_id=scan.id,
                platform=payload.platform,
                device_id=payload.device_id,
                device_name=row.device_name or payload.device_id,
                backend=backend,
                meta=meta,
                # M12: the session owns its live event feed (FR-D10) - torn
                # down with the session on disconnect.
                feed=events.EventFeed(payload.platform),
            )
        )
    except SessionConflict:
        # Another thread claimed the slot between our check and now - the
        # attached row is a duplicate of an active session; roll it back.
        row.state = "error"
        row.last_error = "another session became active concurrently"
        db.commit()
        raise SessionConflict(
            409, "a dynamic session is already active - disconnect it first"
        ) from None
    return DynamicSessionRead.model_validate(row)


@router.post("/session/disconnect", response_model=DynamicSessionRead)
def disconnect_session(db: DbSession) -> DynamicSessionRead:
    """Disconnect the active session (FR-D4): tear down hooks/scripts/mirror,
    flip the row to ``disconnected``, release the single-active slot. 404 when
    no session is live."""
    active = base.active_session()
    if active is None:
        raise NoActiveSession()
    try:
        active.backend.disconnect()
    except DynamicError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.message) from exc
    finally:
        base.end_session()
    row = db.get(DynamicSession, active.row_id)
    if row is not None:
        row.state = "disconnected"
        row.ended_at = datetime.now(UTC)
        db.commit()
    if row is None:
        raise NoActiveSession()
    return DynamicSessionRead.model_validate(row)


@router.get("/session", response_model=DynamicSessionRead | None)
def get_session(db: DbSession) -> DynamicSessionRead | None:
    """The single ACTIVE dynamic session (FR-D5) or null when none is live."""
    active = base.active_session()
    if active is None:
        return None
    row = db.get(DynamicSession, active.row_id)
    if row is None:
        return None
    return DynamicSessionRead.model_validate(row)


def _require_feed() -> events.EventFeed:
    """The active session's live event feed, or a clean 404 when none is
    live (the single shared feed is scoped to the one active session)."""
    active = base.active_session()
    if active is None or active.feed is None:
        raise NoActiveSession()
    return active.feed


# ---- M12: live event feed (FR-D10) ----


def _event_frame(event) -> str:
    return "event: hook\ndata: " + json.dumps(event.asdict(), default=str) + "\n\n"


@router.get("/session/events", response_model=list[DynamicEvent])
def session_events() -> list[DynamicEvent]:
    """Catch-up snapshot of the ACTIVE session's recent events (the HTTP
    fallback a reconnect uses to re-sync the feed). 404 when no session."""
    return _require_feed().snapshot()


@router.post("/session/events", response_model=DynamicEvent, status_code=201)
def post_event(payload: DynamicEventCreate) -> DynamicEvent:
    """Push an observation into the active session's live feed. This is the
    HTTP fallback / test surface that drives the feed in the fake-device
    posture - the later attach/execution path publishes with the same code
    id so real hooks land here unchanged. ``platform``/``ts`` are stamped by
    the backend from the active session, never the caller."""
    feed = _require_feed()
    return feed.publish(
        source=payload.source, tag=payload.tag, text=payload.text, code=payload.code
    )


def _stream_events(feed: events.EventFeed):
    """The SSE event-stream generator (the chat-streaming pattern: a worker
    thread + queue + keepalive ping). Replays the buffered snapshot first
    (catch-up), then streams live ``hook`` frames until the owning session
    ends (disconnect swaps ``feed`` out of the registry) or the client
    disconnects, then yields None to end cleanly. Extracted to module level
    so tests drive it directly (no open HTTP stream to tear down)."""
    frames: queue.Queue[str | None] = queue.Queue()
    sub = feed.subscribe()

    def relay() -> None:
        for ev in feed.snapshot():
            frames.put(_event_frame(ev))
        while True:
            active = base.active_session()
            if active is None or active.feed is not feed:
                frames.put(None)
                return
            try:
                ev = sub.get(timeout=15)
            except queue.Empty:
                frames.put(": ping\n\n")  # keepalive
                continue
            if ev is None:
                break
            frames.put(_event_frame(ev))
        frames.put(None)

    t = threading.Thread(target=relay, daemon=True)
    t.start()
    try:
        while True:
            frame = frames.get()
            if frame is None:
                break
            yield frame
    finally:
        feed.unsubscribe(sub)


@router.get("/session/events/stream")
def events_stream() -> StreamingResponse:
    """Live SSE feed of the ACTIVE session's events (the chat-streaming
    pattern). Streams ``hook`` frames until the session disconnects (or the
    client disconnects), then ends cleanly. 404 when no session is live."""
    feed = _require_feed()
    return StreamingResponse(
        _stream_events(feed),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
    )


@router.get("/session/scripts", response_model=list[DynamicDefaultHook])
def list_default_hooks(platform: str | None = None) -> list[DynamicDefaultHook]:
    """The default hook scripts for the active session's platform (FR-D9) -
    the real frida JS bodies, exposed so the UI can list them. ``platform``
    may be given to list another platform's scripts; defaults to the active
    session's platform."""
    if platform is None:
        active = base.active_session()
        if active is None:
            raise NoActiveSession()
        platform = active.platform
    if platform not in scripts.available_platforms():
        raise DynamicError(400, f"unknown platform {platform!r} (expected android|ios)")
    return [DynamicDefaultHook(**h) for h in scripts.default_hooks(platform)]
