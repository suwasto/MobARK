"""M14 (V2) network traffic capture - the per-session traffic log.

FR-D12/D14: once a pinning/ATS bypass is active, decrypted request/response
traffic is captured and shown as ``{method, path, status}`` rows with a
running request count for the session. This module is the traffic analogue
of :mod:`app.dynamic.events`:

- ``TrafficLog`` holds the ACTIVE session's captured rows: a bounded ring
  buffer (``traffic_max_rows``), a monotonic ``total`` counter (the FR-D14
  running count that never shrinks when the buffer drops), a
  ``capture_active`` flag, and ``publish`` as the single ingestion seam.
- Every captured request ALSO lands in the FR-D10 live event feed as a
  ``net`` event (``tag="traffic"``) - FR-D10 requires *every hook/bypass/
  network observation* in the single live feed; the panel's rows live here
  and the ``net`` event is the live-feed mirror of each row (the same dual
  surface M12/M13 use).
- Bodies are scanned by :mod:`app.dynamic.flag` (FR-D13) and then DROPPED -
  a row carries only ``flagged`` + bounded ``flags[]`` snippets, never the
  raw body (data-minimizing by construction).
- The log is EPHEMERAL like the feed/mirror: it lives on the process-local
  ``ActiveSession.traffic`` slot (never the DB - the ``dynamic_events``/
  ``dynamic_scripts`` tables are M15), dies with the session, and is stopped
  + released on disconnect (FR-D4) so nothing leaks into the next session.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.dynamic import flag


@dataclass
class TrafficRow:
    """One captured request (FR-D12 shape + the flag signal).

    ``method``/``path``/``status`` are the FR-D12 surface; ``host`` the
    request authority; ``size_bytes`` a hint of the total payload size;
    ``flagged`` + ``flags`` are the FR-D13 signal (never the raw body).
    """

    id: int
    ts: str
    method: str
    path: str
    host: str | None = None
    status: int | None = None
    size_bytes: int = 0
    flagged: bool = False
    flags: list[dict[str, Any]] = field(default_factory=list)

    def asdict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "ts": self.ts,
            "method": self.method,
            "path": self.path,
            "host": self.host,
            "status": self.status,
            "size_bytes": self.size_bytes,
            "flagged": self.flagged,
            "flags": self.flags,
        }


class TrafficLog:
    """The active session's traffic hub.

    One ``TrafficLog`` hangs off the active ``ActiveSession`` (created at
    connect, stopped + released on disconnect). ``publish`` appends a row,
    bumps the FR-D14 running count, runs the FR-D13 detector on any supplied
    bodies (then drops them), and fans the row into the FR-D10 feed as a
    ``net`` event. ``snapshot`` returns the buffered rows + count + the
    capture-active flag for the HTTP catch-up.

    All access is mutex-guarded - the router, a future capture-worker thread,
    and the HTTP fallback may all touch it concurrently. ``publish`` never
    raises: a missing feed, an oversized body, or a slow consumer must not
    break a capture.
    """

    def __init__(self, platform: str, feed: Any = None) -> None:
        from app.config import settings

        self._platform = platform
        self._feed = feed
        self._max_rows = settings.traffic_max_rows
        self._rows: list[TrafficRow] = []
        self._seq = 0
        self._total = 0
        self._active = False
        self._lock = threading.Lock()

    @property
    def platform(self) -> str:
        return self._platform

    @property
    def capture_active(self) -> bool:
        with self._lock:
            return self._active

    def publish(
        self,
        method: str,
        path: str,
        host: str | None = None,
        status: int | None = None,
        size_bytes: int = 0,
        request_body: Any = None,
        response_body: Any = None,
    ) -> TrafficRow:
        """Ingest one captured request. Runs the FR-D13 detector on any
        bodies (bounded, then dropped - never retained), stores the bounded
        row, and mirrors it into the FR-D10 feed as a ``net`` event. Never
        raises."""
        flags = flag.detect(request_body)
        flags.extend(flag.detect(response_body))
        seen: set[str] = set()
        deduped: list[dict[str, Any]] = []
        for f in flags:
            key = f["category"]
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        with self._lock:
            self._seq += 1
            self._total += 1
            row = TrafficRow(
                id=self._seq,
                ts=datetime.now(UTC).isoformat(),
                method=method,
                path=path,
                host=host,
                status=status,
                size_bytes=size_bytes,
                flagged=bool(deduped),
                flags=deduped,
            )
            self._rows.append(row)
            if len(self._rows) > self._max_rows:
                del self._rows[: len(self._rows) - self._max_rows]
        if self._feed is not None:
            text = f"{method} {path}"
            if row.flagged:
                labels = ", ".join(f["label"] for f in row.flags)
                text += f" - flagged ({labels})"
            try:
                self._feed.publish("net", "traffic", text, code=None)
            except Exception:  # noqa: BLE001 - the feed is best-effort
                pass
        return row

    def snapshot(self) -> dict[str, Any]:
        """The catch-up read for ``GET .../session/traffic``: the buffered
        rows in order (oldest first), the running count, and the
        capture-active flag."""
        with self._lock:
            return {
                "platform": self._platform,
                "capture_active": self._active,
                "total": self._total,
                "rows": [r.asdict() for r in self._rows],
            }

    def start(self) -> None:
        """Mark capture running (FR-D4: disconnect always stops it).
        Idempotent - starting an already-running log is a no-op."""
        with self._lock:
            self._active = True

    def stop(self) -> None:
        """Mark capture stopped. Idempotent."""
        with self._lock:
            self._active = False