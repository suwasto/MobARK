"""M12 (V2) live event feed - the shared, platform-agnostic event shape.

FR-D10: every hook / bypass / network observation surfaces as ONE live,
timestamped, tagged event. ``DynamicEvent`` is that shape - platform-agnostic
in the UI, tagged by platform - and this module owns the bounded ring buffer
that backs the live feed.

The feed is EPHEMERAL (M12): events live in memory on the process-local
``ActiveSession`` (never the DB - the ``dynamic_events`` table ships in M15),
so the buffer dies with the session. It is scoped to the single active
session (FR-D5) - disconnect tears it down; nothing leaks into the next
session.

In the fake-device posture nothing injects the real hook scripts (their
on-device execution is an owner manual checkpoint, deferred). The feed is
driven by the HTTP fallback (``POST /api/v1/dynamic/session/events``) and by
fake backends in tests. The later attach/execution path calls :func:`publish`
with the same ``code`` id so real hooks land in the same feed with zero
consumer changes.
"""
from __future__ import annotations

import queue
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

# The bounded number of events the ring buffer keeps per session (the UI's
# catch-up snapshot plus a little room - far beyond any realistic live burst
# a human needs to scroll back through).
_BUFFER_CAP = 200

# Valid ``source`` values (the FR-D10 ``type`` axis).
EVENT_SOURCES = ("hook", "bypass", "net", "note")


@dataclass
class DynamicEvent:
    """One live event: platform-agnostic, tagged by platform.

    ``source`` is the FR-D10 type (hook | bypass | net | note). ``tag`` is a
    short machine label (``pinning``, ``root``, ``keychain``, ...) that groups
    events in the UI; ``platform`` (android|ios) tags which device produced it;
    ``code`` is the producing hook-script id (null for a manual ``note``);
    ``text`` is the human-readable line.
    """

    ts: str  # ISO-8601 UTC (serialized for SSE/pydantic directly)
    source: str
    tag: str
    platform: str
    text: str
    code: str | None = None

    @staticmethod
    def now() -> str:
        """ISO-8601 UTC timestamp string for an event."""
        return datetime.now(UTC).isoformat()

    def asdict(self) -> dict[str, Any]:
        return {
            "ts": self.ts,
            "source": self.source,
            "tag": self.tag,
            "platform": self.platform,
            "text": self.text,
            "code": self.code,
        }


class EventFeed:
    """A per-session bounded ring buffer + live-subscriber fan-out.

    One ``EventFeed`` hangs off the active ``ActiveSession``. ``publish``
    appends to the buffer and fans out to every subscribed SSE queue (each
    subscriber drains its own queue on its own thread); ``snapshot`` returns
    the buffered events in order for the HTTP catch-up. All access is
    mutex-guarded (the router, the subscriber worker threads, and a future
    frida callback thread may all touch it concurrently).
    """

    def __init__(self, platform: str) -> None:
        self._platform = platform
        self._events: list[DynamicEvent] = []
        self._lock = threading.Lock()
        self._subscribers: list[list[DynamicEvent]] = []
        self._sub_lock = threading.Lock()

    @property
    def platform(self) -> str:
        return self._platform

    def publish(self, source: str, tag: str, text: str, code: str | None = None) -> DynamicEvent:
        """Append a live event + fan out to subscribers. Never raises - the
        feed is best-effort (a slow/no subscriber must not break a hook)."""
        if source not in EVENT_SOURCES:
            source = "note"
        event = DynamicEvent(
            ts=DynamicEvent.now(),
            source=source,
            tag=tag,
            platform=self._platform,
            text=text,
            code=code,
        )
        with self._lock:
            self._events.append(event)
            if len(self._events) > _BUFFER_CAP:
                del self._events[: len(self._events) - _BUFFER_CAP]
        with self._sub_lock:
            subscribers = list(self._subscribers)
        for sub in subscribers:
            try:
                sub.put(event)
            except Exception:  # noqa: BLE001 - fan-out is best-effort
                pass
        return event

    def snapshot(self) -> list[DynamicEvent]:
        """The buffered events in order (the catch-up / HTTP-fallback read)."""
        with self._lock:
            return list(self._events)

    # ---- SSE subscriber plumbing -------------------------------------
    def subscribe(self) -> queue.Queue[DynamicEvent | None]:
        """Register a live subscriber queue; the caller owns it and MUST
        ``unsubscribe`` it (an abandoned subscriber leaks forever)."""
        q: queue.Queue[DynamicEvent | None] = queue.Queue()
        with self._sub_lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q) -> None:
        with self._sub_lock:
            try:
                self._subscribers.remove(q)
            except ValueError:
                pass