"""M15 (V2) process-local frida script runner state (FR-D15/D16/D17).

The RUNNING state of the scan's scripts - the process-local analogue of the
feed/mirror/traffic slots on the ``ActiveSession``. A ``ScriptRunner`` hangs
off ``ActiveSession.scripts`` (created at connect, torn down with the session
on disconnect - nothing leaks into the next session, FR-D4).

In the fake-device posture run/stop just flip the running flag; real frida
injection of the script body is an owner manual checkpoint (deferred), same
as M11/M12/M13/M14's real device execution. The router calls :meth:`start` /
:meth:`stop` after validating the script row exists in the active session's
scan; the UI reads :meth:`is_running` to show which scripts are active
(FR-D15) and can stop any of them individually.
"""
from __future__ import annotations

import threading
from datetime import UTC, datetime


class ScriptRunner:
    """Tracks which of the scan's scripts are currently running.

    ``_running`` maps script id -> started ISO timestamp (the UI can show
    when each started). Mutex-guarded: the router and a future frida
    callback thread may touch it concurrently.
    """

    def __init__(self) -> None:
        self._running: dict[int, str] = {}
        self._lock = threading.Lock()

    def start(self, script_id: int) -> None:
        """Mark a script as running (idempotent - a re-run keeps the original
        start time)."""
        with self._lock:
            self._running.setdefault(script_id, datetime.now(UTC).isoformat())

    def stop(self, script_id: int) -> None:
        """Mark a script as stopped (idempotent - clearing an already-stopped
        script is a no-op)."""
        with self._lock:
            self._running.pop(script_id, None)

    def is_running(self, script_id: int) -> bool:
        with self._lock:
            return script_id in self._running

    def running_ids(self) -> set[int]:
        with self._lock:
            return set(self._running)

    def clear(self) -> None:
        """Stop everything (FR-D4 teardown - disconnect calls this)."""
        with self._lock:
            self._running.clear()
