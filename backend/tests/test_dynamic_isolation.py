"""M19 (V2) session hardening tests - stale-session reaping + cross-scan
isolation.

Fake-device posture (no adb/frida/pymobiledevice3): a monkeypatched backend
drives the whole HTTP surface, exactly like M11-M17. Covers the M19
teardown/isolation hardening:

- **Stale-session reaping:** a ``dynamic_sessions`` row stuck in
  ``attached`` (or ``preflight``) with no process-local ``ActiveSession`` is
  PROVABLY dead - the process holding it ended without a clean disconnect
  (an app/worker restart or crash). The M19 cleanup flips such rows to
  ``disconnected`` with an honest ``ended_at`` + ``last_error`` note on
  connect / session-read / disconnect, so the durable history never claims a
  live session that no longer exists - and the reap is SCOPED to the
  caller's own scans (a user can never rewrite another user's history).
- **Cross-scan isolation:** a disconnect fully tears down the ephemeral
  per-session state (FR-D10 feed / FR-D7 mirror / FR-D14 traffic / FR-D15
  scripts) so session A never leaks into scan B across connect/disconnect
  cycles - the PRD's "most likely source of confusing bugs" hardened.
"""
from __future__ import annotations

import base64
from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from app.dynamic import base
from app.models import DynamicSession, Scan


class FakeBackend:
    platform = "android"

    def __init__(self):
        self.attach_meta = {
            "connection_type": "adb",
            "frida_version": "16.0.0",
            "target_pid": 1234,
            "root_status": True,
        }
        self.checks = {
            "adb_ok": True,
            "device_present": True,
            "frida_server_reachable": True,
            "target_installed": True,
        }

    def list_devices(self):
        return [{"id": "emulator-5554", "name": "emulator-5554",
                 "model": "pixel", "detail": None}]

    def preflight(self, device_id, target_app):
        return dict(self.checks)

    def attach(self, device_id, target_app, artifact_path=None):
        return dict(self.attach_meta)

    def disconnect(self):
        pass


@pytest.fixture()
def patch_backend(monkeypatch):
    import app.dynamic.router as router

    backend = FakeBackend()
    monkeypatch.setattr(router, "get_backend", lambda platform: backend)
    return backend


@pytest.fixture(autouse=True)
def _reset_active():
    yield
    base.end_session()


def _make_scan(factory, user_id, *, platform="android", filename="app.apk"):
    with factory() as db:
        scan = Scan(filename=filename, status="done", platform=platform, user_id=user_id)
        db.add(scan)
        db.commit()
        return scan.id


def _make_stale_row(db, scan_id, *, state="attached"):
    """Write a ``dynamic_sessions`` row directly - simulating a process that
    died mid-session (its process-local handle never got torn down)."""
    row = DynamicSession(
        scan_id=scan_id,
        platform="android",
        state=state,
        device_id="emulator-5554",
        connection_type="adb",
        frida_version="16.0.0",
        target_pid=1234,
        root_status=True,
        started_at=datetime.now(UTC),
    )
    db.add(row)
    db.commit()
    return row.id


def _sessions(db, scan_id=None):
    q = select(DynamicSession)
    if scan_id is not None:
        q = q.where(DynamicSession.scan_id == scan_id)
    return db.scalars(q.order_by(DynamicSession.id)).all()


def _connect(client, scan_id, platform="android", device="emulator-5554"):
    return client.post(
        "/api/v1/dynamic/session/connect",
        json={
            "scan_id": scan_id,
            "platform": platform,
            "device_id": device,
            "target_app": "com.example.app",
        },
    )


# ---- stale-session reaping (M19) ----------------------------------------


def test_connect_reaps_stale_attached_row(
    client, patch_backend, db_session_factory, auth_user_id
):
    scan_id = _make_scan(db_session_factory, auth_user_id)
    with db_session_factory() as db:
        stale_id = _make_stale_row(db, scan_id)
    resp = _connect(client, scan_id)
    assert resp.status_code == 200, resp.text
    assert base.active_session() is not None
    with db_session_factory() as db:
        rows = _sessions(db, scan_id)
        assert len(rows) == 2  # the reaped stale row + the fresh attached one
        stale, live = rows
        assert stale.id == stale_id
        assert stale.state == "disconnected"
        assert stale.ended_at is not None
        assert "stale session reaped" in stale.last_error
        assert live.state == "attached"
        assert live.id != stale_id


def test_get_session_self_heals_stale_row(
    client, patch_backend, db_session_factory, auth_user_id
):
    scan_id = _make_scan(db_session_factory, auth_user_id)
    with db_session_factory() as db:
        _make_stale_row(db, scan_id)
    # No live session -> null, but the dead row is reaped on read.
    assert client.get("/api/v1/dynamic/session").json() is None
    with db_session_factory() as db:
        rows = _sessions(db, scan_id)
        assert len(rows) == 1 and rows[0].state == "disconnected"
        assert rows[0].ended_at is not None


def test_disconnect_reaps_stale_row_then_404(
    client, patch_backend, db_session_factory, auth_user_id
):
    scan_id = _make_scan(db_session_factory, auth_user_id)
    with db_session_factory() as db:
        _make_stale_row(db, scan_id)
    resp = client.post("/api/v1/dynamic/session/disconnect")
    assert resp.status_code == 404
    with db_session_factory() as db:
        rows = _sessions(db, scan_id)
        assert rows and all(r.state == "disconnected" for r in rows)


def test_stale_reap_is_scoped_to_own_scans(
    client, auth_client, patch_backend, db_session_factory, auth_user_id
):
    # user A (auth_user_id) owns a stale attached row on scan A. user B
    # (auth_client) polling GET /session must NOT reap A's row - the
    # isolation rule: a user can never rewrite another user's history.
    scan_a = _make_scan(db_session_factory, auth_user_id)
    with db_session_factory() as db:
        _make_stale_row(db, scan_a)
    assert auth_client.get("/api/v1/dynamic/session").json() is None
    with db_session_factory() as db:
        rows = _sessions(db, scan_a)
        assert len(rows) == 1 and rows[0].state == "attached"  # untouched
    # A's own read reaps it.
    assert client.get("/api/v1/dynamic/session").json() is None
    with db_session_factory() as db:
        assert _sessions(db, scan_a)[0].state == "disconnected"


# ---- cross-scan teardown isolation (M19) ---------------------------------

# Each test drives session A (events/mirror/traffic/scripts), disconnects,
# connects session B, and proves B starts with a CLEAN slate - no ephemeral
# per-session state leaks across connect/disconnect cycles.


def test_event_feed_does_not_leak_across_sessions(
    client, patch_backend, db_session_factory, auth_user_id
):
    scan_a = _make_scan(db_session_factory, auth_user_id)
    _connect(client, scan_a)
    resp = client.post(
        "/api/v1/dynamic/session/events",
        json={"source": "note", "tag": "test", "text": "session-A event"},
    )
    assert resp.status_code == 201
    assert client.get("/api/v1/dynamic/session/events").json()
    assert client.post("/api/v1/dynamic/session/disconnect").status_code == 200

    scan_b = _make_scan(db_session_factory, auth_user_id)
    _connect(client, scan_b)
    # B's feed is a fresh ring - A's event is gone.
    assert client.get("/api/v1/dynamic/session/events").json() == []
    assert client.get("/api/v1/dynamic/session").json()["scan_id"] == scan_b


def test_mirror_does_not_leak_across_sessions(
    client, patch_backend, db_session_factory, auth_user_id
):
    scan_a = _make_scan(db_session_factory, auth_user_id)
    _connect(client, scan_a)
    frame = base64.b64encode(b"fake-jpeg-frame").decode()
    assert client.post(
        "/api/v1/dynamic/session/mirror/publish", json={"data": frame}
    ).status_code == 201
    assert client.get("/api/v1/dynamic/session/mirror").json()["frame_count"] == 1
    assert client.post("/api/v1/dynamic/session/disconnect").status_code == 200

    scan_b = _make_scan(db_session_factory, auth_user_id)
    _connect(client, scan_b)
    state = client.get("/api/v1/dynamic/session/mirror").json()
    assert state["frame_count"] == 0  # no leaked frame
    assert state["live"] is False
    assert state["last_frame"] is None


def test_traffic_does_not_leak_across_sessions(
    client, patch_backend, db_session_factory, auth_user_id
):
    scan_a = _make_scan(db_session_factory, auth_user_id)
    _connect(client, scan_a)
    assert client.post(
        "/api/v1/dynamic/session/traffic",
        json={"method": "GET", "path": "/login", "host": "evil.example"},
    ).status_code == 201
    assert client.get("/api/v1/dynamic/session/traffic").json()["total"] == 1
    assert client.post("/api/v1/dynamic/session/disconnect").status_code == 200

    scan_b = _make_scan(db_session_factory, auth_user_id)
    _connect(client, scan_b)
    log = client.get("/api/v1/dynamic/session/traffic").json()
    assert log["total"] == 0  # the FR-D14 running count never leaks
    assert log["rows"] == []


def test_scripts_do_not_leak_across_sessions(
    client, patch_backend, db_session_factory, auth_user_id
):
    scan_a = _make_scan(db_session_factory, auth_user_id)
    _connect(client, scan_a)
    created = client.post(
        "/api/v1/dynamic/session/scripts/managed",
        json={"name": "a-manual", "body": "console.log('a')", "description": None},
    )
    assert created.status_code == 201
    script_id = created.json()["id"]
    assert client.post(
        f"/api/v1/dynamic/session/scripts/managed/{script_id}/run"
    ).json()["running"] is True
    assert client.post("/api/v1/dynamic/session/disconnect").status_code == 200

    scan_b = _make_scan(db_session_factory, auth_user_id)
    _connect(client, scan_b)
    scripts = client.get("/api/v1/dynamic/session/scripts/managed").json()
    # B sees only its OWN scripts (the lazily-seeded built-ins) - A's manual
    # script is scoped to A's scan and B's runner starts with nothing running.
    names = {s["name"] for s in scripts}
    assert "a-manual" not in names
    assert scripts and all(s["running"] is False for s in scripts)


def test_reconnect_same_scan_starts_clean(
    client, patch_backend, db_session_factory, auth_user_id
):
    scan_id = _make_scan(db_session_factory, auth_user_id)
    first = _connect(client, scan_id)
    assert first.status_code == 200
    first_id = first.json()["id"]
    assert client.post(
        "/api/v1/dynamic/session/events",
        json={"source": "note", "tag": "test", "text": "pre-disconnect"},
    ).status_code == 201
    assert client.post("/api/v1/dynamic/session/disconnect").status_code == 200

    second = _connect(client, scan_id)
    assert second.status_code == 200
    assert second.json()["id"] != first_id  # a fresh session row, not a reuse
    # A reconnect is a new session: the old feed is gone, the new one is empty.
    assert client.get("/api/v1/dynamic/session/events").json() == []
    assert client.get("/api/v1/dynamic/session").json()["state"] == "attached"