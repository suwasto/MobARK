"""M11 (V2) dynamic session API tests - fake-device posture.

The whole HTTP surface runs against a FAKE backend (monkeypatched
``app.dynamic.router.get_backend``), so no adb/frida/pymobiledevice3 is
required - the fake-device build posture. Covers: discovery, preflight,
connect/disconnect lifecycle, FR-D5 single-active, per-user isolation, and
the DynamicError -> HTTP mapping (never a raw 500 for a known condition).
"""
from __future__ import annotations

import pytest
from sqlalchemy import select

from app.dynamic import base
from app.dynamic.base import DeviceError
from app.models import Scan


class FakeBackend:
    platform = "android"

    def __init__(
        self,
        *,
        devices=None,
        checks=None,
        attach_meta=None,
        fail_attach=None,
    ):
        self.devices = devices or []
        self.checks = checks or {}
        self.attach_meta = attach_meta or {
            "connection_type": "adb",
            "frida_version": "16.0.0",
            "target_pid": 1234,
            "root_status": True,
        }
        self.fail_attach = fail_attach
        self.attach_calls = []
        self.disconnect_calls = 0

    def list_devices(self):
        return self.devices

    def preflight(self, device_id, target_app):
        return self.checks

    def attach(self, device_id, target_app, artifact_path=None):
        self.attach_calls.append((device_id, target_app, artifact_path))
        if self.fail_attach:
            raise DeviceError(502, self.fail_attach)
        return dict(self.attach_meta)

    def disconnect(self):
        self.disconnect_calls += 1


@pytest.fixture(autouse=True)
def _reset_active():
    yield
    base.end_session()


@pytest.fixture()
def fake_backend():
    return FakeBackend(
        devices=[
            {
                "id": "emulator-5554",
                "name": "emulator-5554",
                "model": "pixel",
                "detail": None,
            }
        ],
        checks={
            "adb_ok": True,
            "device_present": True,
            "frida_server_reachable": True,
            "target_installed": True,
        },
    )


@pytest.fixture()
def patch_backend(monkeypatch, fake_backend):
    import app.dynamic.router as router

    monkeypatch.setattr(router, "get_backend", lambda platform: fake_backend)
    return fake_backend


def _make_scan(factory, user_id, *, platform="android", filename="app.apk"):
    with factory() as db:
        scan = Scan(filename=filename, status="done", platform=platform, user_id=user_id)
        db.add(scan)
        db.commit()
        return scan.id


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


def test_devices_returns_fake_list(client, patch_backend):
    resp = client.get("/api/v1/dynamic/devices?platform=android")
    assert resp.status_code == 200
    assert resp.json()[0]["id"] == "emulator-5554"


def test_preflight_returns_checks(client, patch_backend):
    resp = client.get(
        "/api/v1/dynamic/preflight?platform=android&device_id=emulator-5554&target_app=com.example.app"
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["checks"]["target_installed"] is True


def test_dynamic_routes_behind_auth(unauth_client, patch_backend):
    resp = unauth_client.get("/api/v1/dynamic/devices?platform=android")
    assert resp.status_code == 401


def test_connect_happy_path(
    client, patch_backend, fake_backend, db_session_factory, auth_user_id
):
    scan_id = _make_scan(db_session_factory, auth_user_id)
    resp = _connect(client, scan_id)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["state"] == "attached"
    assert body["platform"] == "android"
    assert body["target_pid"] == 1234
    assert body["root_status"] is True
    assert body["frida_version"] == "16.0.0"
    assert body["connection_type"] == "adb"
    assert fake_backend.attach_calls[0][0] == "emulator-5554"
    # persisted row
    with db_session_factory() as db:
        from app.models import DynamicSession

        sess = db.scalars(
            select(DynamicSession).where(DynamicSession.scan_id == scan_id)
        ).all()
        assert len(sess) == 1
        assert sess[0].state == "attached"


def test_connect_foreign_scan_404(auth_client, patch_backend, db_session_factory, auth_user_id):
    # tester's scan (owned by auth_user_id); a DIFFERENT user (auth_client =
    # tester2) connecting to it must read as 404 - the isolation gate.
    scan_id = _make_scan(db_session_factory, auth_user_id)
    resp = _connect(auth_client, scan_id)
    assert resp.status_code == 404


def test_connect_preflight_failure_409(
    client, patch_backend, fake_backend, db_session_factory, auth_user_id
):
    fake_backend.checks = {
        "adb_ok": False,
        "device_present": False,
        "frida_server_reachable": False,
        "target_installed": False,
    }
    scan_id = _make_scan(db_session_factory, auth_user_id)
    resp = _connect(client, scan_id)
    assert resp.status_code == 409
    assert "preflight failed" in resp.json()["detail"]
    assert base.active_session() is None


def test_connect_already_active_409(
    client, patch_backend, fake_backend, db_session_factory, auth_user_id
):
    scan_id = _make_scan(db_session_factory, auth_user_id)
    assert _connect(client, scan_id).status_code == 200
    scan2 = _make_scan(db_session_factory, auth_user_id)
    resp = _connect(client, scan2)
    assert resp.status_code == 409
    assert "already active" in resp.json()["detail"]


def test_connect_platform_mismatch_409(
    client, patch_backend, db_session_factory, auth_user_id
):
    scan_id = _make_scan(db_session_factory, auth_user_id, platform="ios", filename="app.ipa")
    resp = _connect(client, scan_id, platform="android")
    assert resp.status_code == 409
    assert "not android" in resp.json()["detail"]


def test_connect_attach_failure_502_writes_error_row(
    client, patch_backend, fake_backend, db_session_factory, auth_user_id
):
    fake_backend.fail_attach = "cannot reach frida-server"
    scan_id = _make_scan(db_session_factory, auth_user_id)
    resp = _connect(client, scan_id)
    assert resp.status_code == 502
    assert "cannot reach frida-server" in resp.json()["detail"]
    with db_session_factory() as db:
        from app.models import DynamicSession

        sess = db.scalars(
            select(DynamicSession).where(DynamicSession.scan_id == scan_id)
        ).all()
        assert sess and sess[0].state == "error"
        assert sess[0].last_error == "cannot reach frida-server"


def test_disconnect_happy_path(
    client, patch_backend, fake_backend, db_session_factory, auth_user_id
):
    scan_id = _make_scan(db_session_factory, auth_user_id)
    _connect(client, scan_id)
    assert base.active_session() is not None
    resp = client.post("/api/v1/dynamic/session/disconnect")
    assert resp.status_code == 200
    assert resp.json()["state"] == "disconnected"
    assert resp.json()["ended_at"] is not None
    assert base.active_session() is None
    assert fake_backend.disconnect_calls == 1


def test_disconnect_no_active_404(client, patch_backend):
    resp = client.post("/api/v1/dynamic/session/disconnect")
    assert resp.status_code == 404


def test_get_session_after_disconnect_null(
    client, patch_backend, db_session_factory, auth_user_id
):
    assert client.get("/api/v1/dynamic/session").json() is None
    scan_id = _make_scan(db_session_factory, auth_user_id)
    _connect(client, scan_id)
    assert client.get("/api/v1/dynamic/session").json()["state"] == "attached"
    client.post("/api/v1/dynamic/session/disconnect")
    assert client.get("/api/v1/dynamic/session").json() is None


def test_unknown_platform_400(client, db_session_factory):
    # Real get_backend dispatch (factory NOT patched): an unknown platform
    # must 400 via DynamicError, not fall through to a fake backend.
    resp = client.get("/api/v1/dynamic/devices?platform=webos")
    assert resp.status_code == 400
    assert "unknown platform" in resp.json()["detail"]
