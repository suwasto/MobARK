"""M13 (V2) device-mirror WebSocket relay.

The mirror is a continuous stream of BINARY frames (H.264 NAL / JPEG) - a
poor fit for the SSE event feed (which stays as-is for events), so this is
the codebase's first WebSocket endpoint, scoped to the mirror only.

IMPORTANT routing decision: the WS route CANNOT ride the dynamic router's
list-level ``Depends(get_current_user)`` - that dependency is ``Request``-
typed and FastAPI fails to build it from a websocket scope (verified with a
probe). So ``mirror_router`` is included in ``main.py`` WITHOUT the list-in
auth dependency, and the endpoint authenticates IN-HANDLER:

1. read ``websocket.cookies[SESSION_COOKIE]`` -> ``sessions.user_from_token``
   -> 401-close (code 4401) on failure (auth-off parity: early-return when
   ``auth_enabled`` is False - the open dev/CI mode);
2. ``require_scan_access`` on the ACTIVE session's scan_id - a foreign-scan
   session reads as 404 (close code 4404), never an existence leak.

FR-D7/D8: the relay is server->client only (no input). The control frame
announces ``continuous|polled`` + codec so the UI is honest about iOS's
polled fidelity; the client's only allowed message is the latency ping,
echoed by the server as a pong. Disconnect tears the subscription down.
"""
from __future__ import annotations

import time

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect

from app.auth import sessions
from app.auth.security import SESSION_COOKIE
from app.config import settings
from app.db import get_db
from app.dynamic import base
from app.dynamic.base import NoActiveSession
from app.dynamic.mirror import MirrorRelay

router = APIRouter(prefix="/dynamic")

# WebSocket close codes the mirror uses for clean auth/state failures.
_WS_UNAUTHENTICATED = 4401  # no valid session cookie (the 401 analogue)
_WS_NO_SESSION = 4404  # no active session / foreign-scan (the 404 analogue)


def _ws_db():
    """A database session resolved through FastAPI's ``dependency_overrides``
    so tests (and any future DB-swap) hit the same store the HTTP routes use.
    Deferred ``app.main`` import - the app is fully loaded by the time a
    websocket arrives, so there is no import cycle."""
    from app.main import app

    factory = app.dependency_overrides.get(get_db, get_db)
    return next(factory())


def _ws_authenticated(db, ws) -> int | None:
    """Resolve the session cookie to a user id (auth-off parity returns None
    but is ``True``-ish - see ``_auth_ok``). Never raises. The caller uses the
    id for the per-scan ownership check and the boolean for the auth gate."""
    if not settings.auth_enabled:
        return None
    raw_token = ws.cookies.get(SESSION_COOKIE)
    if not raw_token:
        return None
    user = sessions.user_from_token(
        db, raw_token, session_days=settings.session_days
    )
    return user.id if user is not None else None


def _auth_ok(user_id: int | None) -> bool:
    """The auth gate: a valid user id, or auth-off parity (None is fine)."""
    return True if not settings.auth_enabled else user_id is not None


def _active_mirror() -> MirrorRelay:
    """The active session's mirror relay, or a clean NoActiveSession."""
    active = base.active_session()
    if active is None or active.mirror is None:
        raise NoActiveSession()
    return active.mirror


@router.websocket("/session/mirror/ws")
async def mirror_ws(ws: WebSocket) -> None:
    """Live mirror relay for the ACTIVE dynamic session (FR-D6/D7/D8).

    Flow: accept -> auth (close 4401 on failure; 4404 on no-session/foreign)
    -> send the control frame (``continuous|polled``, codec, latency) ->
    stream the latest frame + every live frame as a BINARY WebSocket message
    -> answer latency pings (the one allowed client message) -> end cleanly
    on disconnect (FR-D4 teardown). View-only: no input frames are accepted.
    """
    import asyncio
    import queue as _queue
    import threading

    try:
        await ws.accept()
    except Exception:
        return
    db = _ws_db()
    try:
        user_id = _ws_authenticated(db, ws)
        if not _auth_ok(user_id):
            await ws.close(
                code=_WS_UNAUTHENTICATED, reason="authentication required"
            )
            return
        try:
            relay = _active_mirror()
        except NoActiveSession:
            await ws.close(
                code=_WS_NO_SESSION, reason="no active dynamic session"
            )
            return
        # Per-scan isolation (M9.1): the ACTIVE session's scan must belong to
        # the authenticated user - a foreign-scan session reads as 404 (the
        # mirror analogue of require_scan_access's 404, never a leak).
        active = base.active_session()
        if active is not None and active.scan_id is not None:
            from app.api.deps import require_scan_access

            try:
                require_scan_access(db, active.scan_id, user_id)
            except HTTPException:
                await ws.close(
                    code=_WS_NO_SESSION, reason="scan not accessible"
                )
                return
    finally:
        db.close()

    # Broadcast the control envelope first (fidelity + codec + live latency).
    try:
        await ws.send_json(relay.stats())
    except Exception:
        return

    # A bridge thread pulls frames off the relay's subscriber queue into a
    # plain send queue (the chat-SSE ``_stream_events`` pattern). The async
    # side polls that queue with get_nowait + sleep rather than a blocking
    # ``asyncio.to_thread(queue.get)`` - a thread blocked forever on
    # queue.get is uncancellable and hangs the event loop's teardown.
    sub = relay.subscribe()
    send_q: _queue.Queue[bytes | None] = _queue.Queue()
    latest = relay.latest()
    if latest is not None:
        send_q.put(latest.data)  # late-join catch-up frame first

    def bridge() -> None:
        while True:
            active = base.active_session()
            if active is None or active.mirror is not relay:
                send_q.put(None)
                return
            try:
                frame = sub.get(timeout=0.5)
            except _queue.Empty:
                continue
            if frame is None:
                send_q.put(None)
                return
            send_q.put(frame.data)

    threading.Thread(target=bridge, daemon=True).start()

    async def next_frame() -> bytes | None:
        """Poll the send queue without blocking a worker thread (see above).
        Returns the frame bytes, or None at teardown (the bridge sent it)."""
        while True:
            try:
                item = send_q.get_nowait()
            except _queue.Empty:
                await asyncio.sleep(0.05)
                continue
            return item

    recv_task = asyncio.create_task(ws.receive())
    frame_task: asyncio.Task | None = None
    try:
        while True:
            if frame_task is None:
                frame_task = asyncio.create_task(next_frame())
            done, _ = await asyncio.wait(
                {recv_task, frame_task}, return_when=asyncio.FIRST_COMPLETED
            )
            if frame_task in done:
                frame = frame_task.result()
                frame_task = None
                if frame is None:
                    break
                try:
                    await ws.send_bytes(frame)
                except Exception:
                    break
            if recv_task in done:
                try:
                    msg = recv_task.result()
                except Exception:
                    break
                recv_task = asyncio.create_task(ws.receive())
                if msg.get("type") == "websocket.disconnect":
                    break
                payload = msg.get("text") or msg.get("bytes")
                # View-only (FR-D8): the ONLY allowed client message is the
                # latency ping; everything else is ignored, never forwarded.
                if isinstance(payload, str) and payload == "ping":
                    sent = time.monotonic()
                    try:
                        await ws.send_text("pong")
                        relay.set_latency(int((time.monotonic() - sent) * 1000))
                    except Exception:
                        break
    except WebSocketDisconnect:
        pass
    finally:
        relay.unsubscribe(sub)
        if frame_task is not None:
            frame_task.cancel()
        try:
            recv_task.cancel()
        except Exception:
            pass