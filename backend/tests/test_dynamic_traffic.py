"""M14 (V2) network traffic capture tests - fake-posture.

Covers FR-D12/D13/D14/D14a: the TrafficLog (bounded row buffer + running
count + capture-active flag + bodies-never-retained), the FR-D13 flagged-data
detector (credentials / bearer / PII - in-process, NOT gitleaks), the
per-platform capture sources (Android mitmdump + device-settings proxy shape;
iOS mitmdump + config-profile CA trust), and the guarded traffic API (GET log
/ POST row + feed event / start / stop / ca-status / ca-profile). No real
mitmdump / device / bypass - the log is driven through the fake-backend
connect + the HTTP fallback, exactly like M11/M12/M13.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from app.dynamic import base, flag, traffic
from app.dynamic.android import traffic as android_traffic
from app.dynamic.base import DeviceError
from app.dynamic.ios import traffic as ios_traffic
from app.models import Scan


class FakeBackend:
    platform = "android"

    def __init__(self):
        self.attach_meta = {
            "connection_type": "adb",
            "frida_version": "16.0.0",
            "target_pid": 1234,
            "root_status": True,
        }
        self.checks = {"adb_ok": True, "device_present": True,
                       "frida_server_reachable": True, "target_installed": True}

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


# ---- FR-D13 flagged-data detector (in-process, NOT gitleaks) ---------------


def test_detect_credentials():
    hits = flag.detect('{"password": "hunter2", "api_key": "abc12345", "x": 1}')
    cats = {h["category"] for h in hits}
    assert "credential" in cats
    assert hits[0]["label"] == "credentials"


def test_detect_bearer_token():
    token = "eyJhbGciOiJIUzI1NiJ9." + "a" * 40 + "." + "b" * 27
    hits = flag.detect(f"Authorization: Bearer {token}")
    assert any(h["category"] == "bearer" for h in hits)
    assert hits[0]["label"] == "bearer_token"


def test_detect_pii_email_ssn_phone():
    body = "contact alice@example.com ssn 123-45-6789 call +1 (415) 555-0199"
    labels = {h["label"] for h in flag.detect(body)}
    assert {"email", "ssn", "phone"} <= labels


def test_detect_credit_card_luhn_valid():
    hits = flag.detect("card 4111 1111 1111 1111")  # a valid Luhn (Visa test)
    assert any(h["label"] == "credit_card" for h in hits)


def test_detect_credit_card_rejects_luhn_lookalike():
    hits = flag.detect("card 4111 1111 1111 1112")  # same length, bad checksum
    assert not any(h["label"] == "credit_card" for h in hits)


def test_detect_benign_body_no_false_positive():
    body = '{"username": "jane", "bio": "software engineer", "city": "Oslo"}'
    assert flag.detect(body) == []


def test_detect_none_and_binary_safe():
    assert flag.detect(None) == []
    assert flag.detect(b"\xff\xfe\x00binary-blob") == []  # undecodable - no crash
    hits = flag.detect(b'{"password": "hunter2"}')
    assert any(h["category"] == "credential" for h in hits)


def test_detect_snippets_bounded():
    body = '{"password": "' + "x" * 300 + '"}'
    hits = flag.detect(body)
    assert hits
    assert all(len(h["snippet"]) <= 120 for h in hits)


def test_detect_respects_body_cap():
    # a credential AFTER the cap is invisible (scanned only up to body_cap)
    body = "A" * 1000 + '{"password": "hunter2"}'
    hits = flag.detect(body, body_cap=500)
    assert not any(h["category"] == "credential" for h in hits)
    hits = flag.detect(body, body_cap=2000)
    assert any(h["category"] == "credential" for h in hits)


# ---- TrafficLog unit behaviour ---------------------------------------------


def test_log_bounded_and_running_count():
    log = traffic.TrafficLog("android")
    for i in range(40):
        log.publish(method="GET", path=f"/p/{i}", status=200)
    snap = log.snapshot()
    assert len(snap["rows"]) == 40  # under the default cap (500) - all kept
    assert snap["total"] == 40
    # bump over the cap: only the newest rows are retained, total never drops
    for i in range(40, 560):
        log.publish(method="GET", path=f"/p/{i}", status=200)
    snap = log.snapshot()
    assert len(snap["rows"]) == 500
    assert snap["total"] == 560
    assert snap["rows"][0]["path"] == "/p/60"
    assert snap["rows"][-1]["path"] == "/p/559"


def test_log_rows_chronological_with_ids():
    log = traffic.TrafficLog("android")
    log.publish(method="GET", path="/a", status=200)
    log.publish(method="POST", path="/b", status=201)
    rows = log.snapshot()["rows"]
    assert [r["path"] for r in rows] == ["/a", "/b"]
    assert rows[0]["id"] == 1 and rows[1]["id"] == 2
    assert rows[1]["status"] == 201


def test_log_capture_active_flag():
    log = traffic.TrafficLog("android")
    assert log.capture_active is False
    log.start()
    assert log.capture_active is True
    log.start()  # idempotent
    assert log.capture_active is True
    log.stop()
    assert log.capture_active is False


def test_log_detects_and_never_retains_bodies():
    log = traffic.TrafficLog("android")
    row = log.publish(
        method="POST",
        path="/login",
        status=200,
        request_body='{"password": "hunter2"}',
        response_body="ok",
    )
    assert row.flagged is True
    assert row.flags[0]["category"] == "credential"
    assert "hunter2" in row.flags[0]["snippet"]  # the bounded snippet rides
    # the raw body is NEVER retained - only the bounded flag snippet
    assert '{"password": "hunter2"}' not in json.dumps(log.snapshot())


def test_log_mirrors_net_event_into_feed():
    from app.dynamic import events

    feed = events.EventFeed("android")
    log = traffic.TrafficLog("android", feed=feed)
    log.publish(method="GET", path="/x", status=200)
    ev = feed.snapshot()[-1]
    assert ev.source == "net"
    assert ev.tag == "traffic"
    assert "GET /x" in ev.text


def test_log_mirrors_flagged_net_event():
    from app.dynamic import events

    feed = events.EventFeed("android")
    log = traffic.TrafficLog("android", feed=feed)
    log.publish(method="POST", path="/login", status=200,
                request_body='{"password": "hunter2"}')
    ev = feed.snapshot()[-1]
    assert "flagged" in ev.text
    assert "credentials" in ev.text


def test_log_without_feed_is_fine():
    log = traffic.TrafficLog("android")
    row = log.publish(method="GET", path="/a", status=200)
    assert row.flagged is False


# ---- per-platform capture sources ------------------------------------------


def test_android_source_check_resolves(monkeypatch):
    monkeypatch.setattr(android_traffic, "resolve_binary", lambda *a, **k: "/fake/mitmdump")
    s = android_traffic.make_source("emulator-5554")
    s.check()  # resolves - no raise


def test_android_source_missing_tool_raises_clean(monkeypatch):
    monkeypatch.setattr(android_traffic, "resolve_binary", lambda *a, **k: None)
    s = android_traffic.make_source()
    with pytest.raises(DeviceError) as exc:
        s.check()
    assert exc.value.status == 502
    assert "mitmdump" in exc.value.message


def test_android_proxy_cmd_shape(monkeypatch):
    import app.dynamic.android.devices as android_devices

    monkeypatch.setattr(android_devices, "resolve_binary", lambda *a, **k: "/fake/adb")
    cmd = android_traffic._proxy_cmd("emulator-5554", 8080)
    assert cmd[:3] == ["/fake/adb", "-s", "emulator-5554"]
    assert "settings" in cmd and "http_proxy" in cmd
    assert "127.0.0.1:8080" in cmd


def test_ios_source_check_resolves(monkeypatch):
    monkeypatch.setattr(ios_traffic, "resolve_binary", lambda *a, **k: "/fake/mitmdump")
    ios_traffic.make_source().check()  # resolves - no raise


def test_ios_source_missing_tool_raises_clean(monkeypatch):
    monkeypatch.setattr(ios_traffic, "resolve_binary", lambda *a, **k: None)
    with pytest.raises(DeviceError) as exc:
        ios_traffic.make_source().check()
    assert exc.value.status == 502
    assert "mitmdump" in exc.value.message


def test_ios_source_ca_surface_fake_posture():
    s = ios_traffic.make_source()
    assert s.ca_trusted() is False  # FR-D14a: 'trust not installed' until done
    assert s.ca_profile_path() is None  # no .mobileconfig artifact in fake


# ---- guarded traffic API ----------------------------------------------------


def test_traffic_404_without_session(client, patch_backend):
    assert client.get("/api/v1/dynamic/session/traffic").status_code == 404
    assert (
        client.post(
            "/api/v1/dynamic/session/traffic", json={"method": "GET", "path": "/"}
        ).status_code
        == 404
    )
    assert client.post("/api/v1/dynamic/session/traffic/start").status_code == 404
    assert client.get("/api/v1/dynamic/session/traffic/ca-status").status_code == 404
    assert client.get("/api/v1/dynamic/session/traffic/ca-profile").status_code == 404


def test_traffic_log_and_publish(
    client, patch_backend, db_session_factory, auth_user_id
):
    _connected(client, db_session_factory, auth_user_id)
    snap = client.get("/api/v1/dynamic/session/traffic").json()
    assert snap["platform"] == "android"
    assert snap["total"] == 0
    assert snap["capture_active"] is False
    assert snap["rows"] == []
    resp = client.post(
        "/api/v1/dynamic/session/traffic",
        json={
            "method": "POST",
            "path": "/login",
            "status": 200,
            "request_body": '{"password": "hunter2"}',
        },
    )
    assert resp.status_code == 201
    row = resp.json()
    assert row["method"] == "POST"
    assert row["path"] == "/login"
    assert row["status"] == 200
    assert row["flagged"] is True
    assert row["flags"][0]["category"] == "credential"
    snap = client.get("/api/v1/dynamic/session/traffic").json()
    assert snap["total"] == 1
    assert len(snap["rows"]) == 1
    # the raw body is never retained - only the bounded flag snippet
    assert '{"password": "hunter2"}' not in json.dumps(snap)


def test_traffic_row_mirrors_net_event(
    client, patch_backend, db_session_factory, auth_user_id
):
    _connected(client, db_session_factory, auth_user_id)
    client.post(
        "/api/v1/dynamic/session/traffic",
        json={"method": "GET", "path": "/x", "status": 200},
    )
    events = client.get("/api/v1/dynamic/session/events").json()
    assert events[-1]["source"] == "net"
    assert events[-1]["tag"] == "traffic"
    assert "GET /x" in events[-1]["text"]


def test_traffic_start_stop(
    client, patch_backend, db_session_factory, auth_user_id, monkeypatch
):
    _connected(client, db_session_factory, auth_user_id)
    monkeypatch.setattr(android_traffic, "resolve_binary", lambda *a, **k: "/fake/mitmdump")
    assert client.post("/api/v1/dynamic/session/traffic/start").json()["capture_active"] is True
    # idempotent - starting an already-running log is a no-op
    assert client.post("/api/v1/dynamic/session/traffic/start").json()["capture_active"] is True
    assert client.post("/api/v1/dynamic/session/traffic/stop").json()["capture_active"] is False


def test_traffic_start_502_when_tool_missing(
    client, patch_backend, db_session_factory, auth_user_id, monkeypatch
):
    _connected(client, db_session_factory, auth_user_id)
    monkeypatch.setattr(android_traffic, "resolve_binary", lambda *a, **k: None)
    resp = client.post("/api/v1/dynamic/session/traffic/start")
    assert resp.status_code == 502


def test_traffic_404_after_disconnect(
    client, patch_backend, db_session_factory, auth_user_id
):
    # isolation: after disconnect the log is gone (no leak into the next)
    _connected(client, db_session_factory, auth_user_id)
    client.post("/api/v1/dynamic/session/disconnect")
    assert client.get("/api/v1/dynamic/session/traffic").status_code == 404


def test_traffic_routes_behind_auth(unauth_client, patch_backend):
    assert unauth_client.get("/api/v1/dynamic/session/traffic").status_code == 401
    assert (
        unauth_client.post(
            "/api/v1/dynamic/session/traffic", json={"method": "GET", "path": "/"}
        ).status_code
        == 401
    )
    assert unauth_client.post("/api/v1/dynamic/session/traffic/start").status_code == 401
    assert unauth_client.get("/api/v1/dynamic/session/traffic/ca-status").status_code == 401


def test_traffic_foreign_scan_cannot_connect(
    auth_client, patch_backend, db_session_factory, auth_user_id
):
    # a foreign scan reads as 404 at the connect gate (require_scan_access) -
    # the traffic surface inherits the isolation from the scan-scoped connect
    scan_id = _make_scan(db_session_factory, auth_user_id, platform="android")
    resp = _connect(auth_client, scan_id)
    assert resp.status_code == 404


# ---- FR-D14a CA-trust gate --------------------------------------------------


def test_ca_status_android(client, patch_backend, db_session_factory, auth_user_id):
    _connected(client, db_session_factory, auth_user_id, platform="android")
    status = client.get("/api/v1/dynamic/session/traffic/ca-status").json()
    assert status["platform"] == "android"
    assert status["required"] is False  # CA trusted via device settings
    assert status["trusted"] is None
    assert status["profile_available"] is False


def test_ca_status_ios(client, patch_backend, db_session_factory, auth_user_id):
    _connected(client, db_session_factory, auth_user_id, platform="ios")
    status = client.get("/api/v1/dynamic/session/traffic/ca-status").json()
    assert status["platform"] == "ios"
    assert status["required"] is True  # the config-profile step is required
    assert status["trusted"] is False  # 'trust not installed' until done
    assert status["profile_available"] is False


def test_ca_profile_400_on_android(client, patch_backend, db_session_factory, auth_user_id):
    _connected(client, db_session_factory, auth_user_id, platform="android")
    assert client.get("/api/v1/dynamic/session/traffic/ca-profile").status_code == 400


def test_ca_profile_serve_and_404(
    client, patch_backend, db_session_factory, auth_user_id, monkeypatch, tmp_path
):
    import app.dynamic.router as router

    _connected(client, db_session_factory, auth_user_id, platform="ios")
    # no artifact -> clean 404
    stub = SimpleNamespace(ca_trusted=lambda: False, ca_profile_path=lambda: None)
    monkeypatch.setattr(router.ios_traffic, "make_source", lambda: stub)
    assert client.get("/api/v1/dynamic/session/traffic/ca-profile").status_code == 404

    # with a real .mobileconfig artifact -> served as the download
    profile = tmp_path / "mitm-ca.mobileconfig"
    profile.write_text("PROFILE-BYTES")
    stub = SimpleNamespace(
        ca_trusted=lambda: True, ca_profile_path=lambda: str(profile)
    )
    monkeypatch.setattr(router.ios_traffic, "make_source", lambda: stub)
    resp = client.get("/api/v1/dynamic/session/traffic/ca-profile")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/x-apple-aspen-config")
    assert resp.content == b"PROFILE-BYTES"