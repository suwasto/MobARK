"""M15 (V2) per-scan script management tests - fake-posture.

Covers FR-D15/D16/D17: the ScriptRunner (flag-tracking run/stop, idempotent,
cleared on disconnect), the lazy built-in library seed from the M12 default
hooks (origin=builtin, stable code), manual authoring (name + JS body, saved
with origin=manual + the active session's platform), edit/delete (manual
only - built-in/agent are read-only 400), run/stop (running flag + a ``note``
feed event), per-scan isolation (a script from another scan 404s), and the
guarded API (404 no-session, 401 unauth). No real frida - the runner just
flips flags; real injection is an owner manual checkpoint.
"""
from __future__ import annotations

import pytest

from app.dynamic import base, script_runner
from app.models import Scan


class FakeBackend:
    platform = "android"

    def __init__(self, platform="android"):
        self.platform = platform
        if platform == "ios":
            self.attach_meta = {
                "connection_type": "ssh",
                "frida_version": "16.0.0",
                "target_pid": 999,
                "jailbreak_method": "palera1n",
            }
            self.checks = {
                "device_reachable": True,
                "frida_server_reachable": True,
                "jailbreak_detected": True,
                "target_installed": True,
            }
        else:
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


@pytest.fixture()
def patch_backend_ios(monkeypatch):
    import app.dynamic.router as router

    backend = FakeBackend("ios")
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


def _connected(client, db_session_factory, auth_user_id, platform="android"):
    scan_id = _make_scan(db_session_factory, auth_user_id, platform=platform)
    _connect(client, scan_id, platform=platform)
    return scan_id


MANAGED = "/api/v1/dynamic/session/scripts/managed"


# ---- ScriptRunner unit behaviour -------------------------------------------


def test_runner_start_stop_is_running():
    r = script_runner.ScriptRunner()
    assert r.running_ids() == set()
    r.start(1)
    assert r.is_running(1)
    r.start(1)  # idempotent - keeps the original start time
    assert r.is_running(1)
    r.stop(1)
    assert not r.is_running(1)
    r.stop(1)  # idempotent - clearing an already-stopped script is a no-op
    assert not r.is_running(1)


def test_runner_clear_stops_everything():
    r = script_runner.ScriptRunner()
    r.start(1)
    r.start(2)
    r.clear()
    assert r.running_ids() == set()


# ---- built-in library seed (from the M12 default hooks) --------------------


def test_builtins_seeded_from_default_hooks(
    client, patch_backend, db_session_factory, auth_user_id
):
    _connected(client, db_session_factory, auth_user_id)  # android
    resp = client.get(MANAGED)
    assert resp.status_code == 200
    rows = resp.json()
    assert any(r["origin"] == "builtin" and r["code"] == "android-pinning"
               for r in rows)
    assert any(r["origin"] == "builtin" and r["code"] == "android-root-detection"
               for r in rows)
    # built-ins carry the FR-D17 description + the real JS body
    pinning = next(r for r in rows if r["code"] == "android-pinning")
    assert pinning["platform"] == "android"
    assert pinning["description"]
    assert "SCRIPT_ID" in pinning["script"]
    assert pinning["running"] is False


def test_builtins_seed_is_idempotent(
    client, patch_backend, db_session_factory, auth_user_id
):
    _connected(client, db_session_factory, auth_user_id)
    first = len(client.get(MANAGED).json())
    second = len(client.get(MANAGED).json())
    assert first == second


def test_builtins_platform_tagged_ios(
    client, patch_backend_ios, db_session_factory, auth_user_id
):
    _connected(client, db_session_factory, auth_user_id, platform="ios")
    rows = client.get(MANAGED).json()
    codes = {r["code"] for r in rows if r["origin"] == "builtin"}
    assert {"ios-pinning", "ios-jailbreak-detection", "ios-keychain"} <= codes
    assert all(r["platform"] == "ios" for r in rows)


# ---- manual script authoring (FR-D16) --------------------------------------


def test_create_manual_script(
    client, patch_backend, db_session_factory, auth_user_id
):
    _connected(client, db_session_factory, auth_user_id)
    resp = client.post(
        MANAGED,
        json={
            "name": "log https",
            "body": "Java.perform(function () { console.log('hi'); });",
            "description": "Logs every https call.",
        },
    )
    assert resp.status_code == 201
    row = resp.json()
    assert row["name"] == "log https"
    assert row["origin"] == "manual"
    assert row["platform"] == "android"  # taken from the active session
    assert row["description"] == "Logs every https call."
    assert row["script"].startswith("Java.perform")
    assert row["running"] is False
    # it shows up in the list alongside the built-ins
    codes = {r["origin"] for r in client.get(MANAGED).json()}
    assert "manual" in codes


def test_create_manual_validation(client, patch_backend, db_session_factory, auth_user_id):
    _connected(client, db_session_factory, auth_user_id)
    # empty name / empty body / oversize body all 400 cleanly, never 500
    assert client.post(MANAGED, json={"name": "", "body": "x"}).status_code == 400
    assert client.post(MANAGED, json={"name": "x", "body": "  "}).status_code == 400
    big = client.post(
        MANAGED, json={"name": "x", "body": "y" * (256 * 1024 + 1)}
    )
    assert big.status_code == 400


def test_create_uses_active_session_platform_ios(
    client, patch_backend_ios, db_session_factory, auth_user_id
):
    _connected(client, db_session_factory, auth_user_id, platform="ios")
    row = client.post(
        MANAGED, json={"name": "ats", "body": "ObjC.schedulePerformBlock()"}
    ).json()
    assert row["origin"] == "manual"
    assert row["platform"] == "ios"


# ---- edit / delete (manual only; built-in read-only) -----------------------


def test_update_manual_script(
    client, patch_backend, db_session_factory, auth_user_id
):
    _connected(client, db_session_factory, auth_user_id)
    sid = client.post(MANAGED, json={"name": "a", "body": "x"}).json()["id"]
    resp = client.put(f"{MANAGED}/{sid}", json={"body": "y", "name": "b"})
    assert resp.status_code == 200
    assert resp.json()["script"] == "y"
    assert resp.json()["name"] == "b"


def test_update_builtin_400(client, patch_backend, db_session_factory, auth_user_id):
    _connected(client, db_session_factory, auth_user_id)
    builtin = next(
        r for r in client.get(MANAGED).json() if r["origin"] == "builtin"
    )
    resp = client.put(f"{MANAGED}/{builtin['id']}", json={"body": "x"})
    assert resp.status_code == 400  # built-in/agent scripts are read-only


def test_delete_manual_script(
    client, patch_backend, db_session_factory, auth_user_id
):
    _connected(client, db_session_factory, auth_user_id)
    sid = client.post(MANAGED, json={"name": "a", "body": "x"}).json()["id"]
    client.post(f"{MANAGED}/{sid}/run")  # run it, then delete
    assert client.delete(f"{MANAGED}/{sid}").status_code == 200
    assert client.get(f"{MANAGED}/{sid}").status_code == 404


def test_delete_builtin_400(client, patch_backend, db_session_factory, auth_user_id):
    _connected(client, db_session_factory, auth_user_id)
    builtin = next(
        r for r in client.get(MANAGED).json() if r["origin"] == "builtin"
    )
    assert client.delete(f"{MANAGED}/{builtin['id']}").status_code == 400


# ---- run / stop (FR-D15/D16, flag-tracking) --------------------------------


def test_run_stop_toggles_running_flag(
    client, patch_backend, db_session_factory, auth_user_id
):
    _connected(client, db_session_factory, auth_user_id)
    sid = client.post(MANAGED, json={"name": "a", "body": "x"}).json()["id"]
    assert client.post(f"{MANAGED}/{sid}/run").json()["running"] is True
    # the list reflects the running flag (FR-D15: view active scripts)
    listed = next(r for r in client.get(MANAGED).json() if r["id"] == sid)
    assert listed["running"] is True
    assert client.post(f"{MANAGED}/{sid}/run").json()["running"] is True  # idempotent
    assert client.post(f"{MANAGED}/{sid}/stop").json()["running"] is False
    assert client.post(f"{MANAGED}/{sid}/stop").json()["running"] is False  # idempotent


def test_run_stop_mirror_note_event(
    client, patch_backend, db_session_factory, auth_user_id
):
    _connected(client, db_session_factory, auth_user_id)
    sid = client.post(
        MANAGED, json={"name": "a", "body": "x", "description": "the desc"}
    ).json()["id"]
    client.post(f"{MANAGED}/{sid}/run")
    evs = client.get("/api/v1/dynamic/session/events").json()
    assert evs[-1]["source"] == "note"
    assert evs[-1]["tag"] == "script"
    assert "started" in evs[-1]["text"]


def test_run_builtin(client, patch_backend, db_session_factory, auth_user_id):
    _connected(client, db_session_factory, auth_user_id)
    builtin = next(
        r for r in client.get(MANAGED).json() if r["code"] == "android-pinning"
    )
    assert client.post(f"{MANAGED}/{builtin['id']}/run").json()["running"] is True


# ---- platform tagging / per-scan isolation ---------------------------------


def test_platform_tagged_scripts_only(
    client, patch_backend_ios, db_session_factory, auth_user_id
):
    # on an iOS session, the managed list is iOS-only (no Android built-ins)
    _connected(client, db_session_factory, auth_user_id, platform="ios")
    rows = client.get(MANAGED).json()
    assert all(r["platform"] == "ios" for r in rows)


def test_foreign_scan_script_404(
    client, patch_backend, db_session_factory, auth_user_id
):
    # a script from a PREVIOUS session's scan is invisible after connecting a
    # new scan (per-scan isolation - the managed surface is scan-scoped).
    first_scan = _connected(client, db_session_factory, auth_user_id)
    sid = client.post(MANAGED, json={"name": "a", "body": "x"}).json()["id"]
    client.post("/api/v1/dynamic/session/disconnect")
    _connect(client, first_scan)  # reconnect the SAME scan -> still visible
    assert client.get(f"{MANAGED}/{sid}").status_code == 200
    client.post("/api/v1/dynamic/session/disconnect")
    # a different scan (same user) -> the old script is foreign (404)
    second_scan = _make_scan(db_session_factory, auth_user_id, platform="android")
    _connect(client, second_scan)
    assert client.get(f"{MANAGED}/{sid}").status_code == 404


# ---- guarded API: 404 no-session / 401 unauth / disconnect teardown --------


def test_scripts_404_without_session(client, patch_backend):
    assert client.get(MANAGED).status_code == 404
    assert client.post(MANAGED, json={"name": "a", "body": "x"}).status_code == 404
    assert client.post(f"{MANAGED}/1/run").status_code == 404
    assert client.post(f"{MANAGED}/1/stop").status_code == 404
    assert client.get(f"{MANAGED}/1").status_code == 404


def test_scripts_behind_auth(unauth_client, patch_backend):
    assert unauth_client.get(MANAGED).status_code == 401
    assert (
        unauth_client.post(MANAGED, json={"name": "a", "body": "x"}).status_code
        == 401
    )
    assert unauth_client.post(f"{MANAGED}/1/run").status_code == 401


def test_scripts_404_after_disconnect(
    client, patch_backend, db_session_factory, auth_user_id
):
    # isolation: after disconnect the managed surface is gone (no leak into
    # the next session - the runner + rows die with the ActiveSession).
    _connected(client, db_session_factory, auth_user_id)
    client.post("/api/v1/dynamic/session/disconnect")
    assert client.get(MANAGED).status_code == 404


def test_foreign_scan_cannot_connect(
    auth_client, patch_backend, db_session_factory, auth_user_id
):
    # a foreign scan reads as 404 at the connect gate (require_scan_access) -
    # the script surface inherits the isolation from the scan-scoped connect
    scan_id = _make_scan(db_session_factory, auth_user_id, platform="android")
    assert _connect(auth_client, scan_id).status_code == 404
