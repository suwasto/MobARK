"""M11 dynamic analysis (V2) - shared errors + the process-local session
runtime.

This is the "per-scan runtime store" from the M11 task line. The
``dynamic_sessions`` table is the DURABLE lifecycle record; the LIVE handles
(the attached frida session, a future mirror stream) live HERE - module-level,
process-local, single-active (FR-D5), torn down on disconnect. The router
reads/writes this registry; tests drive it with fake backends.

``DynamicError`` is the one error the router maps to an HTTP status: its
``status`` becomes the response code and ``message`` the human detail. Every
missing-tool / unreachable-device / no-session / conflict path raises a
subclass so the API never emits a raw 500 for a known dynamic condition.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any


class DynamicError(Exception):
    """Base error for the dynamic layer -> mapped to an HTTP response."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class DeviceError(DynamicError):
    """A device/tool command failed (adb/frida/pymobiledevice3 absent or
    returned a non-zero/error result)."""


class PreflightError(DynamicError):
    """The pre-flight check rejected the connect (a prerequisite failed)."""


class NoActiveSession(DynamicError):
    """No live dynamic session to disconnect / inspect."""

    def __init__(self) -> None:
        super().__init__(404, "no active dynamic session")


class SessionConflict(DynamicError):
    """A connect was attempted while a session is already active (FR-D5)."""


@dataclass
class ActiveSession:
    """The one LIVE dynamic session (process-local).

    ``backend`` is the attached platform backend whose ``disconnect()`` tears
    down hooks/scripts/mirror; ``meta`` carries the FR-D3 identity
    (frida_version, target_pid, root_status, jailbreak_method). The DB row
    id is kept so disconnect can flip its state without re-querying by scan.

    ``feed`` is the M12 live event feed (FR-D10) for this session - a bounded
    ring buffer + SSE subscriber fan-out, ephemeral, torn down with the
    session. Set by the router at connect time (after the platform is known).

    ``mirror`` is the M13 live screen mirror (FR-D6/D7/D8) - a
    ``MirrorRelay`` carrying the latest frame + ``continuous|polled``
    fidelity flag + latency, ephemeral, torn down with the session. Created
    at connect time, stopped + released on disconnect (FR-D4).
    """

    row_id: int
    scan_id: int
    platform: str
    device_id: str
    device_name: str
    backend: Any
    meta: dict[str, Any] = field(default_factory=dict)
    feed: Any = field(default=None, repr=False)
    mirror: Any = field(default=None, repr=False)

    @property
    def connection_type(self) -> str:
        return self.meta.get("connection_type", "")


# Single-active registry (FR-D5): at most one live session at a time.
_lock = threading.Lock()
_active: ActiveSession | None = None


def active_session() -> ActiveSession | None:
    return _active


def begin_session(session: ActiveSession) -> None:
    """Claim the single live-session slot. Raises SessionConflict (409) when
    another session is already active - the one-scan-one-device rule."""
    global _active
    with _lock:
        if _active is not None:
            raise SessionConflict(
                409,
                "a dynamic session is already active - disconnect it first",
            )
        _active = session


def end_session() -> None:
    """Release the live-session slot (called after teardown)."""
    global _active
    with _lock:
        _active = None
