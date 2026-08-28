"""M13 (V2) device mirror relay - the live, view-only screen mirror.

FR-D6/FR-D7/FR-D8: once connected, the device screen streams into the
dashboard (view-only, no input), with a live indicator + approximate
latency, and an honest per-platform fidelity flag. This module is the mirror
analogue of :mod:`app.dynamic.events`:

- ``MirrorRelay`` holds the ACTIVE session's latest frame + a live
  ``continuous | polled`` fidelity flag, a bounded frame-store (only the most
  recent frame is meaningful for a screen mirror), a binary-subscriber
  fan-out (the WebSocket relay) and a live ``latency_ms`` from a ping/pong
  handshake.
- The relay is EPHEMERAL like the event feed: it lives on the process-local
  ``ActiveSession.mirror`` slot (never the DB), dies with the session, and
  is torn down on disconnect (FR-D4) so nothing leaks into the next session.

Frame delivery is server->client only (FR-D8 - view-only, no input). A
client's only allowed message is the latency ping. ``publish`` never raises
on a slow/absent client - the mirror is best-effort and a lagging observer
must never break the source.
"""
from __future__ import annotations

import queue
import threading
from dataclasses import dataclass
from typing import Any


@dataclass
class MirrorFrame:
    """One viewable frame handed to subscribers.

    ``seq`` is a monotonic counter; ``ts`` an ISO-8601 UTC string (the live
    timestamp the UI shows); ``polled`` records the FR-D7 fidelity flag for
    THIS frame (Android continuous => False, iOS polled => True); ``codec``
    is a hint (``h264`` | ``jpeg``); ``data`` is the binary blob (bytes).
    """

    seq: int
    ts: str
    platform: str
    polled: bool
    codec: str
    data: bytes

    def payload(self) -> dict[str, Any]:
        """The JSON control envelope a subscriber sends (no binary here -
        the WS relay sends ``data`` separately as a binary frame)."""
        return {
            "type": "frame",
            "seq": self.seq,
            "ts": self.ts,
            "platform": self.platform,
            "polled": self.polled,
            "codec": self.codec,
            "len": len(self.data),
        }


class MirrorRelay:
    """The active session's screen-mirror hub.

    One ``MirrorRelay`` hangs off the active ``ActiveSession`` (created at
    connect, torn down on disconnect). ``publish`` stores the latest frame
    + fans out to every subscribed binary queue; ``latest()`` returns the
    newest frame (the catch-up a new client reads before its first live
    frame); ``latency_ms`` is measured by the WS ping/pong handshake.

    All access is mutex-guarded - the router, the frame-source worker thread
    (Android continuous / iOS polled), and each subscriber relay thread may
    touch it concurrently.
    """

    def __init__(self, platform: str, *, continuous: bool) -> None:
        self._platform = platform
        self._continuous = continuous
        self._latest: MirrorFrame | None = None
        self._seq = 0
        self._started = False
        self._lock = threading.Lock()
        self._subscribers: list[Any] = []
        self._sub_lock = threading.Lock()
        self._latency_ms: int | None = None

    @property
    def platform(self) -> str:
        return self._platform

    @property
    def continuous(self) -> bool:
        """FR-D7: True = continuous relay (Android); False = polled (iOS)."""
        return self._continuous

    @property
    def polled(self) -> bool:
        return not self._continuous

    @property
    def latency_ms(self) -> int | None:
        with self._lock:
            return self._latency_ms

    def set_latency(self, ms: int | None) -> None:
        with self._lock:
            self._latency_ms = ms

    def publish(
        self, data: bytes, *, codec: str = "jpeg", polled: bool | None = None
    ) -> MirrorFrame | None:
        """Store + fan out one frame. Never raises: an oversized frame, an
        empty frame, or a slow/absent subscriber must not break the source.
        Returns the produced frame, or None if it was dropped."""
        from app.config import settings

        max_bytes = settings.mirror_frame_bytes
        if not data or len(data) > max_bytes:
            return None
        from datetime import UTC, datetime

        if polled is None:
            polled = self.polled
        with self._lock:
            self._seq += 1
            frame = MirrorFrame(
                seq=self._seq,
                ts=datetime.now(UTC).isoformat(),
                platform=self._platform,
                polled=polled,
                codec=codec,
                data=data,
            )
            self._latest = frame
        with self._sub_lock:
            subscribers = list(self._subscribers)
        for sub in subscribers:
            try:
                sub.put(frame)
            except Exception:  # noqa: BLE001 - fan-out is best-effort
                pass
        return frame

    def latest(self) -> MirrorFrame | None:
        with self._lock:
            return self._latest

    def stats(self) -> dict[str, Any]:
        """The relay state for ``GET .../session/mirror``."""
        latest = self.latest()
        return {
            "platform": self._platform,
            "continuous": self._continuous,
            "polled": self.polled,
            "live": self._running(),
            "frame_count": self._seq,
            "last_frame": latest and latest.payload() or None,
            "latency_ms": self.latency_ms,
            "subscribers": self._subscriber_count(),
        }

    def _running(self) -> bool:
        return self._started

    def start(self) -> None:
        """Mark the frame source running (FR-D4: disconnect always stops it).
        Idempotent - starting an already-running relay is a no-op."""
        with self._lock:
            self._started = True

    def stop(self) -> None:
        """Mark the frame source stopped. Idempotent."""
        with self._lock:
            self._started = False

    def _subscriber_count(self) -> int:
        with self._sub_lock:
            return len(self._subscribers)

    # ---- subscription plumbing (WS relay threads) ----------------------
    def subscribe(self) -> queue.Queue[MirrorFrame | None]:
        """Register a binary subscriber queue; the caller MUST unsubscribe it
        (an abandoned subscriber leaks forever)."""
        q: queue.Queue[MirrorFrame | None] = queue.Queue()
        with self._sub_lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q) -> None:
        with self._sub_lock:
            try:
                self._subscribers.remove(q)
            except ValueError:
                pass