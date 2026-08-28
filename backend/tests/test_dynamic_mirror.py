"""M13 (V2) device-mirror tests - fake-device posture.

Covers FR-D6/D7/D8: the MirrorRelay (bounded frame store + subscriber
fan-out + latency + continuous|polled fidelity), the per-platform frame
sources (Android continuous / iOS polled), the WebSocket relay (auth gate,
no-session/foreign-scan close, control frame -> binary frames, latency
ping/pong, view-only, disconnect teardown), and the guarded mirror control
API (GET state / publish / start / stop). No real scrcpy/screenshotr/device -
the mirror is driven through the fake-backend connect + the HTTP publish
fallback, exactly like M11/M12.
"""
from __future__ import annotations

import base64

import pytest
from starlette.websockets import WebSocketDisconnect

from app.dynamic import base, mirror
from app.dynamic.android import mirror as android_mirror
from app.dynamic.ios import mirror as ios_mirror
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


def _begin_active_session(scan_id, platform="android", continuous=True):
    """Build + claim the single-active slot directly (mirrors what the
    connect route does) for relay/WS tests that need a live session."""
    relay = mirror.MirrorRelay(platform, continuous=continuous)
    base.begin_session(
        base.ActiveSession(
            row_id=1,
            scan_id=scan_id,
            platform=platform,
            device_id="emulator-5554",
            device_name="emulator-5554",
            backend=FakeBackend(),
            meta={"connection_type": "adb"},
            feed=None,
            mirror=relay,
        )
    )
    return relay


# ---- MirrorRelay unit behaviour ------------------------------------------


def test_relay_flags_and_latest():
    r = mirror.MirrorRelay("android", continuous=True)
    assert r.continuous is True
    assert r.polled is False
    frame = r.publish(b"\x00\x00\x00\x01\x67" * 4, codec="h264")
    assert frame.seq == 1
    assert frame.polled is False
    assert frame.codec == "h264"
    assert r.latest() is frame
    assert r.stats()["continuous"] is True
    assert r.stats()["polled"] is False
    assert r.stats()["frame_count"] == 1
    assert r.stats()["last_frame"]["seq"] == 1


def test_ios_relay_is_polled():
    r = mirror.MirrorRelay("ios", continuous=False)
    assert r.polled is True
    assert r.continuous is False
    frame = r.publish(b"\xff\xd8\xff\xe0" + b"\x00" * 8, codec="jpeg")
    assert frame.polled is True


def test_relay_drops_oversized_and_empty():
    r = mirror.MirrorRelay("android", continuous=True)
    assert r.publish(b"") is None
    assert r.publish(b"\x00" * (8 * 1024 * 1024 + 1)) is None
    assert r.stats()["frame_count"] == 0


def test_relay_subscribe_unsubscribe_fanout():
    r = mirror.MirrorRelay("android", continuous=True)
    q = r.subscribe()
    f = r.publish(b"frame-one", codec="h264")
    got = q.get(timeout=1)
    assert got is f
    r.unsubscribe(q)
    r.publish(b"frame-two", codec="h264")
    assert q.empty()


def test_relay_latency_roundtrip():
    r = mirror.MirrorRelay("android", continuous=True)
    assert r.latency_ms is None
    r.set_latency(42)
    assert r.latency_ms == 42
    assert r.stats()["latency_ms"] == 42


def test_relay_start_stop():
    r = mirror.MirrorRelay("android", continuous=True)
    assert r.stats()["live"] is False
    r.start()
    assert r.stats()["live"] is True
    r.start()  # idempotent
    assert r.stats()["live"] is True
    r.stop()
    assert r.stats()["live"] is False


# ---- platform frame sources -----------------------------------------------


def test_android_source_continuous(monkeypatch):
    monkeypatch.setattr(android_mirror, "resolve_binary", lambda *a, **k: "/fake/scrcpy")
    s = android_mirror.make_source()
    assert s.continuous is True
    assert s.poll_interval_seconds is None
    s.check()  # resolves - no raise


def test_android_source_missing_tool_raises_clean(monkeypatch):
    monkeypatch.setattr(android_mirror, "resolve_binary", lambda *a, **k: None)
    s = android_mirror.make_source()
    from app.dynamic.base import DeviceError

    with pytest.raises(DeviceError) as exc:
        s.check()
    assert exc.value.status == 502
    assert "scrcpy" in exc.value.message


def test_ios_source_polled(monkeypatch):
    monkeypatch.setattr(
        ios_mirror, "ScreenshotrSource", ios_mirror.ScreenshotrSource
    )
    # pmd3 resolution: patch _pmd3 to succeed (no real tool needed)
    monkeypatch.setattr(
        "app.dynamic.ios.mirror._screenshot_cmd",
        lambda: ["fake-pmd3", "screenshot"],
    )
    s = ios_mirror.make_source()
    assert s.continuous is False
    assert s.polled is True
    assert s.poll_interval_seconds == 2
    s.check()  # resolves - no raise


def test_ios_source_poll_interval_honors_settings(monkeypatch):
    import app.config as app_config

    monkeypatch.setattr(app_config.settings, "mirror_poll_interval_seconds", 5)
    monkeypatch.setattr(
        "app.dynamic.ios.mirror._screenshot_cmd",
        lambda: ["fake-pmd3", "screenshot"],
    )
    s = ios_mirror.make_source()
    assert s.poll_interval_seconds == 5


# ---- guarded mirror control API -------------------------------------------


def test_mirror_state_404_without_session(client, patch_backend):
    assert client.get("/api/v1/dynamic/session/mirror").status_code == 404


def test_mirror_publish_404_without_session(client, patch_backend):
    assert (
        client.post("/api/v1/dynamic/session/mirror/publish", json={"data": "YQ=="})
        .status_code
        == 404
    )


def test_mirror_state_and_publish(
    client, patch_backend, db_session_factory, auth_user_id
):
    _connected(client, db_session_factory, auth_user_id)
    # fresh relay: no frames yet, continuous (android), not live
    state = client.get("/api/v1/dynamic/session/mirror").json()
    assert state["continuous"] is True
    assert state["polled"] is False
    assert state["frame_count"] == 0
    assert state["live"] is False
    # publish a frame through the HTTP fallback
    blob = base64.b64encode(b"\x00\x00\x00\x01\x67\x42" + b"\x00" * 16).decode()
    resp = client.post(
        "/api/v1/dynamic/session/mirror/publish", json={"data": blob, "encoding": "h264"}
    )
    assert resp.status_code == 201
    state = resp.json()
    assert state["frame_count"] == 1
    assert state["last_frame"]["seq"] == 1
    assert state["last_frame"]["polled"] is False
    # start/stop flip the live flag
    assert client.post("/api/v1/dynamic/session/mirror/start").json()["live"] is True
    assert client.post("/api/v1/dynamic/session/mirror/stop").json()["live"] is False


def test_mirror_state_polled_on_ios(
    client, patch_backend, db_session_factory, auth_user_id
):
    _connected(client, db_session_factory, auth_user_id, platform="ios")
    state = client.get("/api/v1/dynamic/session/mirror").json()
    assert state["polled"] is True
    assert state["continuous"] is False


def test_mirror_state_404_after_disconnect(
    client, patch_backend, db_session_factory, auth_user_id
):
    # isolation: after disconnect the mirror is gone (no leak into the next)
    _connected(client, db_session_factory, auth_user_id)
    client.post("/api/v1/dynamic/session/disconnect")
    assert client.get("/api/v1/dynamic/session/mirror").status_code == 404


def test_mirror_routes_behind_auth(unauth_client, patch_backend):
    assert unauth_client.get("/api/v1/dynamic/session/mirror").status_code == 401
    assert (
        unauth_client.post("/api/v1/dynamic/session/mirror/start").status_code == 401
    )
    assert (
        unauth_client.post("/api/v1/dynamic/session/mirror/publish", json={"data": "YQ=="})
        .status_code
        == 401
    )


# ---- WebSocket relay -------------------------------------------------------


def test_ws_closes_unauth_without_cookie(unauth_client):
    with pytest.raises(Exception) as ctx:
        with unauth_client.websocket_connect("/api/v1/dynamic/session/mirror/ws") as ws:
            try:
                ws.receive_text()
            except WebSocketDisconnect as exc:
                raise exc
    assert ctx.value.code == 4401


def test_ws_closes_no_session(client, patch_backend):
    with pytest.raises(Exception) as ctx:
        with client.websocket_connect("/api/v1/dynamic/session/mirror/ws") as ws:
            try:
                ws.receive_text()
            except WebSocketDisconnect as exc:
                raise exc
    assert ctx.value.code == 4404


def test_ws_single_client_control_and_binary_frames(
    client, patch_backend, db_session_factory, auth_user_id
):
    _connected(client, db_session_factory, auth_user_id)
    relay = base.active_session().mirror
    with client.websocket_connect("/api/v1/dynamic/session/mirror/ws") as ws:
        # control envelope first (JSON): fidelity + codec + latency
        control = ws.receive_json()
        assert control["continuous"] is True
        assert control["polled"] is False
        assert control["platform"] == "android"
        # publish a frame while connected -> arrives as a binary WS message
        relay.publish(b"\x00\x00\x00\x01\x67" * 8, codec="h264")
        got = ws.receive_bytes()
        assert got == b"\x00\x00\x00\x01\x67" * 8


def test_ws_catchup_latest_frame_on_join(
    client, patch_backend, db_session_factory, auth_user_id
):
    _connected(client, db_session_factory, auth_user_id)
    relay = base.active_session().mirror
    relay.publish(b"\xaa" * 16, codec="h264")
    with client.websocket_connect("/api/v1/dynamic/session/mirror/ws") as ws:
        ws.receive_json()  # control
        # the latest frame is replayed so a late-join isn't blank
        assert ws.receive_bytes() == b"\xaa" * 16


def test_ws_latency_ping_pong(
    client, patch_backend, db_session_factory, auth_user_id
):
    _connected(client, db_session_factory, auth_user_id)
    relay = base.active_session().mirror
    assert relay.latency_ms is None
    with client.websocket_connect("/api/v1/dynamic/session/mirror/ws") as ws:
        ws.receive_json()  # control
        ws.send_text("ping")
        assert ws.receive_text() == "pong"
        # the relay now has a measured latency
        assert relay.latency_ms is not None


def test_ws_view_only_ignores_other_messages(
    client, patch_backend, db_session_factory, auth_user_id
):
    _connected(client, db_session_factory, auth_user_id)
    with client.websocket_connect("/api/v1/dynamic/session/mirror/ws") as ws:
        ws.receive_json()  # control
        ws.send_text("tap(100,200)")  # input attempt - must be ignored (FR-D8)
        ws.send_text("ping")  # still functional
        assert ws.receive_text() == "pong"


def test_ws_foreign_scan_closes_4404(
    client, patch_backend, db_session_factory, auth_user_id
):
    # A session active on a scan owned by ANOTHER user (not the WS caller)
    # must read as 404 - the mirror analogue of require_scan_access.
    foreign_scan = _make_scan(db_session_factory, auth_user_id + 100, platform="android")
    _begin_active_session(foreign_scan, platform="android", continuous=True)
    with pytest.raises(Exception) as ctx:
        with client.websocket_connect("/api/v1/dynamic/session/mirror/ws") as ws:
            try:
                ws.receive_text()
            except WebSocketDisconnect as exc:
                raise exc
    assert ctx.value.code == 4404


def test_ws_disconnect_teardown_frees_mirror(
    client, patch_backend, db_session_factory, auth_user_id
):
    _connected(client, db_session_factory, auth_user_id)
    with client.websocket_connect("/api/v1/dynamic/session/mirror/ws") as ws:
        ws.receive_json()
    # after disconnect the relay is gone (no leak into the next session)
    client.post("/api/v1/dynamic/session/disconnect")
    assert client.get("/api/v1/dynamic/session/mirror").status_code == 404


def test_ws_multi_client_fanout(
    client, patch_backend, db_session_factory, auth_user_id
):
    _connected(client, db_session_factory, auth_user_id)
    relay = base.active_session().mirror
    with client.websocket_connect("/api/v1/dynamic/session/mirror/ws") as ws1:
        with client.websocket_connect("/api/v1/dynamic/session/mirror/ws") as ws2:
            ws1.receive_json()
            ws2.receive_json()
            relay.publish(b"\xbb" * 8, codec="h264")
            assert ws1.receive_bytes() == b"\xbb" * 8
            assert ws2.receive_bytes() == b"\xbb" * 8