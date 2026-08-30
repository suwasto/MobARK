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

import base64
import json
import queue
import threading
from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy import select

from app.api.deps import DbSession, require_scan_access
from app.dynamic import base, events, mirror, script_runner, scripts, traffic
from app.dynamic.android import traffic as android_traffic
from app.dynamic.base import (
    DynamicError,
    NoActiveSession,
    PreflightError,
    SessionConflict,
)
from app.dynamic.client import get_backend
from app.dynamic.ios import traffic as ios_traffic
from app.models import DynamicScript, DynamicSession, Scan
from app.request_ctx import current_user_id
from app.schemas import (
    DynamicCaStatus,
    DynamicDefaultHook,
    DynamicDevice,
    DynamicEvent,
    DynamicEventCreate,
    DynamicMirrorPublish,
    DynamicMirrorState,
    DynamicPreflight,
    DynamicScriptCreate,
    DynamicScriptRead,
    DynamicScriptUpdate,
    DynamicSessionConnect,
    DynamicSessionRead,
    DynamicTrafficCreate,
    DynamicTrafficLog,
    DynamicTrafficRow,
)

router = APIRouter(prefix="/dynamic", tags=["dynamic"])

# M19: states that CLAIM a live session. A ``dynamic_sessions`` row in one
# of these states with no process-local ``ActiveSession`` is stale - the
# process holding it ended without a clean disconnect.
_STALE_SESSION_STATES = ("attached", "preflight")


def _reap_stale_sessions(db: DbSession, user_id: int | None) -> int:
    """M19 session cleanup: flip stale ``dynamic_sessions`` rows that claim
    an ACTIVE session but whose process-local handle is gone to
    ``disconnected``.

    The single-active registry (FR-D5, ``app/dynamic/base.py``) is
    process-local and torn down on disconnect, so an ``attached``/``preflight``
    row with no live ``ActiveSession`` is PROVABLY dead - its process (app or
    worker) restarted or crashed mid-session. Each such row becomes
    ``disconnected`` with an honest ``ended_at`` + ``last_error`` note, so the
    durable history never lies about a live session that no longer exists and
    a fresh connect can't pile a second ``attached`` row onto a dead one.

    Scoped to the caller's OWN scans (``Scan.user_id == user_id``) - a user
    can never mutate another user's session history (the M9.1 isolation rule,
    no existence leak). Returns the number of rows reaped (0 in the common
    case - no session history is touched on a normal read)."""
    rows = db.scalars(
        select(DynamicSession)
        .join(Scan, DynamicSession.scan_id == Scan.id)
        .where(
            DynamicSession.state.in_(_STALE_SESSION_STATES),
            Scan.user_id == user_id,
        )
    ).all()
    for row in rows:
        row.state = "disconnected"
        row.ended_at = datetime.now(UTC)
        row.last_error = (
            "stale session reaped: the process holding it ended without a "
            "clean disconnect (M19 session cleanup)"
        )
    if rows:
        db.commit()
    return len(rows)


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
    # M19: no live session, so any ``attached`` row for this user's scans is
    # a dead row from a process that ended without a clean disconnect - reap
    # it before connecting so the new row is the only ``attached`` one and
    # the history never lies about an active session that no longer exists.
    _reap_stale_sessions(db, current_user_id.get())
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
            connection_type=(
                "corellium"
                if payload.device_id.startswith("corellium:")
                else ("adb" if payload.platform == "android" else "ssh")
            ),
            corellium_enabled=payload.device_id.startswith("corellium:"),
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
        corellium_enabled=bool(meta.get("corellium_enabled")),
        started_at=datetime.now(UTC),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    try:
        # M12: the session owns its live event feed (FR-D10) - torn down
        # with the session on disconnect. The SAME feed instance drives the
        # M14 FR-D10 ``net`` events so every captured request mirrors into
        # the live feed (traffic.TrafficLog publishes them).
        session_feed = events.EventFeed(payload.platform)
        base.begin_session(
            base.ActiveSession(
                row_id=row.id,
                scan_id=scan.id,
                platform=payload.platform,
                device_id=payload.device_id,
                device_name=row.device_name or payload.device_id,
                backend=backend,
                meta=meta,
                feed=session_feed,
                # M13: the session owns its live screen mirror (FR-D6/D7/D8).
                # continuous=True on Android (scrcpy relay), False on iOS
                # (polled screenshotr) - the FR-D7 fidelity flag.
                mirror=mirror.MirrorRelay(
                    payload.platform, continuous=payload.platform == "android"
                ),
                # M14: the session owns its captured-traffic log (FR-D12/D13/
                # D14). The same feed drives the FR-D10 ``net`` events.
                traffic=traffic.TrafficLog(payload.platform, feed=session_feed),
                # M15: the session owns its per-scan script runner (FR-D15/D16/
                # D17) - flag-tracking which scripts are running in the fake
                # posture (real frida injection is an owner manual checkpoint).
                scripts=script_runner.ScriptRunner(),
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
        # M19: nothing live to disconnect - but any stale ``attached`` row
        # for this user (a dead process) is reaped so the click still leaves
        # an honest history, then the designed 404.
        _reap_stale_sessions(db, current_user_id.get())
        raise NoActiveSession()
    try:
        active.backend.disconnect()
    except DynamicError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.message) from exc
    finally:
        # FR-D4: stop the mirror stream + the traffic capture too, then
        # release the single-active slot (mirror/feed/traffic/scripts die with
        # the ActiveSession - no leak into the next session).
        if active.mirror is not None:
            active.mirror.stop()
        if active.traffic is not None:
            active.traffic.stop()
        if active.scripts is not None:
            active.scripts.clear()
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
    """The single ACTIVE dynamic session (FR-D5) or null when none is live.
    Self-healing (M19): when nothing is live, any stale ``attached`` row for
    this user is reaped so the history keeps itself honest after an app/
    worker restart."""
    active = base.active_session()
    if active is None:
        _reap_stale_sessions(db, current_user_id.get())
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


# ---- M13: device mirror relay (FR-D6/D7/D8) ----

def _require_mirror() -> mirror.MirrorRelay:
    """The active session's mirror relay, or a clean 404 when none is live."""
    active = base.active_session()
    if active is None or active.mirror is None:
        raise NoActiveSession()
    return active.mirror


@router.get("/session/mirror", response_model=DynamicMirrorState)
def mirror_state() -> DynamicMirrorState:
    """The ACTIVE session's mirror state (FR-D7): the continuous|polled
    fidelity flag, live status, frame count, latest frame + latency. 404 when
    no session is live."""
    return DynamicMirrorState(**_require_mirror().stats())


@router.post("/session/mirror/publish", response_model=DynamicMirrorState, status_code=201)
def mirror_publish(payload: DynamicMirrorPublish) -> DynamicMirrorState:
    """Push a frame into the active session's mirror relay. The HTTP fallback
    / test surface that drives the mirror in the fake-device posture - the
    later per-platform capture path publishes the same bytes so real frames
    land in the same relay unchanged. ``data`` is base64 (a WS message is
    binary; this is the JSON fallback). Never raises on an oversized/empty
    frame - the relay drops it."""
    relay = _require_mirror()
    data = base64.b64decode(payload.data) if payload.data else b""
    relay.publish(
        data, codec=payload.encoding or ("jpeg" if relay.polled else "h264")
    )
    return _mirror_state_read(relay)


@router.post("/session/mirror/start", response_model=DynamicMirrorState)
def mirror_start() -> DynamicMirrorState:
    """Start the ACTIVE session's frame source (idempotent). In the fake
    posture this marks the relay running; the real per-platform capture is an
    owner manual checkpoint."""
    relay = _require_mirror()
    relay.start()
    return _mirror_state_read(relay)


@router.post("/session/mirror/stop", response_model=DynamicMirrorState)
def mirror_stop() -> DynamicMirrorState:
    """Stop the ACTIVE session's frame source (idempotent; FR-D4 teardown
    always stops it)."""
    relay = _require_mirror()
    relay.stop()
    return _mirror_state_read(relay)


def _mirror_state_read(relay: mirror.MirrorRelay) -> DynamicMirrorState:
    return DynamicMirrorState(**relay.stats())


# ---- M14: network traffic capture (FR-D12/D13/D14/D14a) ----


def _require_traffic() -> traffic.TrafficLog:
    """The active session's captured-traffic log, or a clean 404 when none is
    live (scoped to the single active session, like the feed/mirror)."""
    active = base.active_session()
    if active is None or active.traffic is None:
        raise NoActiveSession()
    return active.traffic


@router.get("/session/traffic", response_model=DynamicTrafficLog)
def session_traffic() -> DynamicTrafficLog:
    """The ACTIVE session's captured traffic (FR-D12/D14): the buffered rows
    ({method, path, status} + the FR-D13 flag signal), the running request
    count, and the capture-active flag. 404 when no session is live."""
    return DynamicTrafficLog(**(_require_traffic().snapshot()))


@router.post("/session/traffic", response_model=DynamicTrafficRow, status_code=201)
def post_traffic(payload: DynamicTrafficCreate) -> DynamicTrafficRow:
    """Push one captured request into the active session's traffic log. This
    is the HTTP fallback / test surface that drives the log in the fake
    posture - the later capture path publishes the same data so real flows
    land here unchanged. Bodies (optional) run through the FR-D13 detector
    and are never retained; each row also mirrors into the FR-D10 feed as a
    ``net`` event. ``platform``/``ts`` are stamped by the backend from the
    active session, never the caller."""
    row = _require_traffic().publish(
        method=payload.method,
        path=payload.path,
        host=payload.host,
        status=payload.status,
        size_bytes=payload.size_bytes,
        request_body=payload.request_body,
        response_body=payload.response_body,
    )
    return DynamicTrafficRow(**row.asdict())


@router.post("/session/traffic/start", response_model=DynamicTrafficLog)
def traffic_start() -> DynamicTrafficLog:
    """Start capturing traffic for the ACTIVE session (idempotent). The
    platform's capture tool is resolved first - a clean 502 when mitmdump is
    missing (never a crash). FR-D4 teardown always stops capture."""
    _require_traffic()
    active = base.active_session()
    if active.platform == "android":
        android_traffic.make_source().check()
    else:
        ios_traffic.make_source().check()
    active.traffic.start()
    return DynamicTrafficLog(**active.traffic.snapshot())


@router.post("/session/traffic/stop", response_model=DynamicTrafficLog)
def traffic_stop() -> DynamicTrafficLog:
    """Stop capturing traffic for the ACTIVE session (idempotent)."""
    log = _require_traffic()
    log.stop()
    return DynamicTrafficLog(**log.snapshot())


@router.get("/session/traffic/ca-status", response_model=DynamicCaStatus)
def traffic_ca_status() -> DynamicCaStatus:
    """The FR-D14a CA-trust gate. iOS: the config-profile step is REQUIRED -
    ``trusted`` reports whether the profile is installed + trusted and
    ``profile_available`` whether the ``.mobileconfig`` artifact exists to
    serve. Android: no profile step (``required=False`` - the CA is trusted
    via device settings). 404 when no session is live."""
    active = base.active_session()
    if active is None:
        raise NoActiveSession()
    if active.platform == "android":
        return DynamicCaStatus(
            platform="android", required=False, trusted=None, profile_available=False
        )
    source = ios_traffic.make_source()
    profile = source.ca_profile_path()
    return DynamicCaStatus(
        platform="ios",
        required=True,
        trusted=source.ca_trusted(),
        profile_available=profile is not None,
    )


@router.get("/session/traffic/ca-profile")
def traffic_ca_profile() -> FileResponse:
    """Serve the mitmproxy CA configuration profile (``.mobileconfig``) for
    the tester to install on an iOS device (FR-D14a). iOS-only: Android
    trusts the CA via device settings and 400s here. A clean 404 when no
    session is live, the session is Android, or no profile artifact exists."""
    active = base.active_session()
    if active is None:
        raise NoActiveSession()
    if active.platform != "ios":
        raise DynamicError(
            400,
            "the CA configuration profile is iOS-only - Android trusts the "
            "CA via device settings",
        )
    source = ios_traffic.make_source()
    profile = source.ca_profile_path()
    if profile is None:
        raise HTTPException(
            status_code=404,
            detail=(
                "the mitmproxy CA configuration profile is not available yet "
                "- generate it on the iOS device path first"
            ),
        )
    return FileResponse(
        profile,
        media_type="application/x-apple-aspen-config",
        filename=Path(profile).name,
    )


# ---- M15: per-scan script management (FR-D15/D16/D17) ----

# Validation caps for a manual script (FR-D16: name + JS body + description).
_SCRIPT_NAME_MAX = 128
_SCRIPT_BODY_MAX = 256 * 1024
_SCRIPT_DESC_MAX = 2000


def _require_runner() -> tuple[base.ActiveSession, script_runner.ScriptRunner]:
    """The active session + its per-scan script runner, or a clean 404 when
    none is live (scoped to the single active session, like feed/mirror/
    traffic)."""
    active = base.active_session()
    if active is None or active.scripts is None:
        raise NoActiveSession()
    return active, active.scripts


def _seed_builtins(db: DbSession, scan_id: int, platform: str) -> None:
    """Seed the scan's built-in library from the M12 default hooks, idempotent
    (rows keyed by scan_id + the stable hook ``code``). This is the M15
    built-in-library seed - no static-finding auto-suggestion (FR-D11 was
    removed at owner direction in M12); the built-ins are simply listed and
    picked manually (FR-D15/D16)."""
    existing = {
        r.code
        for r in db.scalars(
            select(DynamicScript).where(
                DynamicScript.scan_id == scan_id,
                DynamicScript.origin == "builtin",
            )
        )
    }
    for hook in scripts.default_hooks(platform):
        if hook["id"] not in existing:
            db.add(
                DynamicScript(
                    scan_id=scan_id,
                    name=hook["name"],
                    body=hook["script"],
                    platform=platform,
                    origin="builtin",
                    description=hook["description"],
                    code=hook["id"],
                    status="ready",
                )
            )
    db.commit()


def _script_read(
    row: DynamicScript, runner: script_runner.ScriptRunner | None = None
) -> DynamicScriptRead:
    running = runner.is_running(row.id) if runner is not None else False
    return DynamicScriptRead(
        id=row.id,
        scan_id=row.scan_id,
        name=row.name,
        platform=row.platform,
        origin=row.origin,
        status=row.status,
        description=row.description,
        code=row.code,
        script=row.body,
        running=running,
        created_at=row.created_at,
    )


def _get_managed_script(
    db: DbSession, scan_id: int, script_id: int
) -> DynamicScript:
    """A script row scoped to the active session's scan (foreign 404 - the
    per-scan isolation rule, no existence leak)."""
    row = db.scalar(
        select(DynamicScript).where(
            DynamicScript.id == script_id,
            DynamicScript.scan_id == scan_id,
        )
    )
    if row is None:
        raise HTTPException(
            status_code=404, detail="script not found for this scan"
        )
    return row


def _publish_script_event(active: base.ActiveSession, row: DynamicScript, verb: str) -> None:
    """Mirror a script lifecycle change into the FR-D10 live feed (the
    dual-surface pattern: the script is a first-class citizen of the feed)."""
    if active.feed is not None:
        active.feed.publish(
            source="note", tag="script", text=f"script '{row.name}' {verb}", code=row.code
        )


@router.get("/session/scripts/managed", response_model=list[DynamicScriptRead])
def list_managed_scripts(db: DbSession) -> list[DynamicScriptRead]:
    """The ACTIVE session's per-scan scripts (built-in + manual + agent), each
    with the live ``running`` flag (FR-D15: view active scripts + stop any).
    The built-in library is seeded lazily + idempotently. 404 when no session
    is live. Platform-tagged: everything here is the active session's platform."""
    active, runner = _require_runner()
    _seed_builtins(db, active.scan_id, active.platform)
    rows = db.scalars(
        select(DynamicScript)
        .where(DynamicScript.scan_id == active.scan_id)
        .order_by(DynamicScript.id)
    ).all()
    return [_script_read(r, runner) for r in rows]


@router.post(
    "/session/scripts/managed", response_model=DynamicScriptRead, status_code=201
)
def create_managed_script(payload: DynamicScriptCreate, db: DbSession) -> DynamicScriptRead:
    """Author a manual script (FR-D16): name + JS body + optional description.
    ``origin`` is set to ``manual`` and ``platform`` to the active session's
    platform (never the caller). Validates name/body bounds up front."""
    active, runner = _require_runner()
    name = payload.name.strip()
    body = payload.body.strip()
    if not name:
        raise DynamicError(400, "script name is required")
    if len(name) > _SCRIPT_NAME_MAX:
        raise DynamicError(400, f"script name must be {_SCRIPT_NAME_MAX} chars or fewer")
    if not body:
        raise DynamicError(400, "script body is required")
    if len(body) > _SCRIPT_BODY_MAX:
        raise DynamicError(400, f"script body must be {_SCRIPT_BODY_MAX} chars or fewer")
    desc = (payload.description or "").strip()
    if len(desc) > _SCRIPT_DESC_MAX:
        raise DynamicError(400, f"script description must be {_SCRIPT_DESC_MAX} chars or fewer")
    row = DynamicScript(
        scan_id=active.scan_id,
        name=name,
        body=body,
        platform=active.platform,
        origin="manual",
        description=desc or None,
        status="ready",
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return _script_read(row, runner)


@router.get(
    "/session/scripts/managed/{script_id}", response_model=DynamicScriptRead
)
def get_managed_script(script_id: int, db: DbSession) -> DynamicScriptRead:
    """One per-scan script (scoped to the active session's scan; foreign 404)."""
    active, runner = _require_runner()
    return _script_read(_get_managed_script(db, active.scan_id, script_id), runner)


@router.put(
    "/session/scripts/managed/{script_id}", response_model=DynamicScriptRead
)
def update_managed_script(
    script_id: int, payload: DynamicScriptUpdate, db: DbSession
) -> DynamicScriptRead:
    """Edit a MANUAL script (name/body/description; all optional). A built-in
    or agent script is read-only and 400s (FR-D16: manual authoring)."""
    active, runner = _require_runner()
    row = _get_managed_script(db, active.scan_id, script_id)
    if row.origin != "manual":
        raise DynamicError(
            400,
            "only manual scripts can be edited - built-in and agent scripts "
            "are read-only",
        )
    if payload.name is not None:
        name = payload.name.strip()
        if not name:
            raise DynamicError(400, "script name cannot be empty")
        if len(name) > _SCRIPT_NAME_MAX:
            raise DynamicError(400, f"script name must be {_SCRIPT_NAME_MAX} chars or fewer")
        row.name = name
    if payload.body is not None:
        body = payload.body.strip()
        if not body:
            raise DynamicError(400, "script body cannot be empty")
        if len(body) > _SCRIPT_BODY_MAX:
            raise DynamicError(400, f"script body must be {_SCRIPT_BODY_MAX} chars or fewer")
        row.body = body
    if payload.description is not None:
        desc = payload.description.strip()
        if len(desc) > _SCRIPT_DESC_MAX:
            raise DynamicError(400, f"script description must be {_SCRIPT_DESC_MAX} chars or fewer")
        row.description = desc or None
    db.commit()
    db.refresh(row)
    return _script_read(row, runner)


@router.delete("/session/scripts/managed/{script_id}")
def delete_managed_script(script_id: int, db: DbSession) -> dict:
    """Delete a MANUAL script (stops it if running), or REJECT an
    unapproved agent-authored draft (origin=agent, status=proposed - the
    M16 rejection path). A built-in or an already-approved agent script is
    read-only and 400s."""
    active, runner = _require_runner()
    row = _get_managed_script(db, active.scan_id, script_id)
    if row.origin != "manual" and not (
        row.origin == "agent" and row.status == "proposed"
    ):
        raise DynamicError(
            400,
            "only manual scripts can be deleted, or a still-unapproved agent "
            "draft rejected - built-in and approved agent scripts are read-only",
        )
    runner.stop(script_id)
    db.delete(row)
    db.commit()
    return {"ok": True}


def _require_ready(row: DynamicScript) -> None:
    """The FR-D19 approval gate: an unapproved agent draft (status=proposed)
    cannot run or be stopped - it is not a manageable script yet. Clean 400,
    never a crash."""
    if row.status != "ready":
        raise DynamicError(
            400,
            f"script '{row.name}' is an unapproved agent draft "
            f"(status={row.status}) - approve it first before running "
            "(FR-D19: no silent execution of agent-authored scripts)",
        )


@router.post(
    "/session/scripts/managed/{script_id}/run", response_model=DynamicScriptRead
)
def run_managed_script(script_id: int, db: DbSession) -> DynamicScriptRead:
    """Run a per-scan script (FR-D16). In the fake posture this just marks it
    running (flag-tracking); real frida injection of the body is an owner
    manual checkpoint. An unapproved agent draft 400s (FR-D19 approval gate).
    Mirrors a ``note`` event into the live feed. 404 when the script isn't in
    the active session's scan."""
    active, runner = _require_runner()
    row = _get_managed_script(db, active.scan_id, script_id)
    _require_ready(row)
    runner.start(script_id)
    _publish_script_event(active, row, "started")
    return _script_read(row, runner)


@router.post(
    "/session/scripts/managed/{script_id}/stop", response_model=DynamicScriptRead
)
def stop_managed_script(script_id: int, db: DbSession) -> DynamicScriptRead:
    """Stop a per-scan script individually (FR-D15: stop any active script).
    Idempotent (stopping an already-stopped script is a no-op). An unapproved
    agent draft 400s (FR-D19 - it can never have been started)."""
    active, runner = _require_runner()
    row = _get_managed_script(db, active.scan_id, script_id)
    _require_ready(row)
    runner.stop(script_id)
    _publish_script_event(active, row, "stopped")
    return _script_read(row, runner)


@router.post(
    "/session/scripts/managed/{script_id}/approve", response_model=DynamicScriptRead
)
def approve_agent_script(script_id: int, db: DbSession) -> DynamicScriptRead:
    """FR-D19 approval gate: approve an AGENT-authored script draft
    (origin=agent, status=proposed) - it becomes ``ready`` and is then
    indistinguishable from manual/built-in (FR-D20): runnable, listed,
    managed identically. Refuses anything that is not a proposed agent draft
    (a manual/built-in script, or an already-approved agent script) with a
    clean 400. Mirrors a ``note`` event into the live feed. 404 when the
    draft isn't in the active session's scan."""
    active, runner = _require_runner()
    row = _get_managed_script(db, active.scan_id, script_id)
    if row.origin != "agent" or row.status != "proposed":
        raise DynamicError(
            400,
            "only a proposed agent-authored script draft can be approved - "
            "manual/built-in scripts are already ready and an approved agent "
            "script stays approved",
        )
    row.status = "ready"
    db.commit()
    db.refresh(row)
    _publish_script_event(active, row, "approved")
    return _script_read(row, runner)
