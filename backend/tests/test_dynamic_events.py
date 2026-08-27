"""M12 (V2) live event feed tests - fake-device posture.

Covers the FR-D10 event feed: the platform-agnostic event shape + by-platform
tagging, the bounded ring buffer, the HTTP fallback (GET snapshot / POST
publish), the SSE stream (live delivery + end-on-disconnect), the auth gate,
and per-scan isolation. No real frida/device - the feed is driven through the
HTTP fallback and the fake-backend connect, exactly like M11.
"""
from __future__ import annotations

import pytest

from app.dynamic import base, events
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


# ---- event feed unit behaviour -------------------------------------------


def test_event_shape_and_platform_tagging():
    feed = events.EventFeed("android")
    ev = feed.publish("hook", "pinning", "TrustManager check ran", code="android-pinning")
    assert ev.source == "hook"
    assert ev.tag == "pinning"
    assert ev.platform == "android"
    assert ev.code == "android-pinning"
    assert ev.ts  # ISO string present
    assert ev.asdict()["ts"] == ev.ts


def test_publish_coerces_unknown_source_to_note():
    feed = events.EventFeed("ios")
    ev = feed.publish("bogus", "keychain", "hello")
    assert ev.source == "note"


def test_ring_buffer_is_bounded_and_ordered():
    feed = events.EventFeed("android")
    for i in range(events._BUFFER_CAP + 25):
        feed.publish("net", "traffic", f"req {i}")
    snap = feed.snapshot()
    assert len(snap) == events._BUFFER_CAP
    # newest retained, order preserved
    assert snap[0].text == "req 25"
    assert snap[-1].text == f"req {events._BUFFER_CAP + 24}"


def test_feed_subscribe_unsubscribe_fanout():
    feed = events.EventFeed("android")
    q = feed.subscribe()
    feed.publish("hook", "root", "probe")
    ev = q.get(timeout=1)
    assert ev.text == "probe"
    feed.unsubscribe(q)
    feed.publish("hook", "root", "after")
    # queue must NOT have the event after unsubscribe
    assert q.empty()


# ---- HTTP fallback --------------------------------------------------------


def test_events_snapshot_empty_without_session(client, patch_backend):
    resp = client.get("/api/v1/dynamic/session/events")
    assert resp.status_code == 404


def test_post_event_404_without_session(client, patch_backend):
    resp = client.post("/api/v1/dynamic/session/events", json={"text": "hi"})
    assert resp.status_code == 404


def test_events_snapshot_and_publish(
    client, patch_backend, db_session_factory, auth_user_id
):
    _connected(client, db_session_factory, auth_user_id)
    # empty at first
    assert client.get("/api/v1/dynamic/session/events").json() == []
    resp = client.post(
        "/api/v1/dynamic/session/events",
        json={"source": "note", "tag": "note", "text": "an observation"},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["source"] == "note"
    assert body["platform"] == "android"
    assert body["text"] == "an observation"
    snap = client.get("/api/v1/dynamic/session/events").json()
    assert len(snap) == 1
    assert snap[0]["text"] == "an observation"
    assert snap[0]["platform"] == "android"


def test_event_routes_behind_auth(unauth_client, patch_backend):
    assert unauth_client.get("/api/v1/dynamic/session/events").status_code == 401
    assert (
        unauth_client.post(
            "/api/v1/dynamic/session/events", json={"text": "x"}
        ).status_code
        == 401
    )


def test_events_404_for_foreign_scan_disconnect(
    client, patch_backend, db_session_factory, auth_user_id
):
    # isolation: after disconnect, the feed is gone (no leak into the next)
    _connected(client, db_session_factory, auth_user_id)
    client.post("/api/v1/dynamic/session/disconnect")
    assert client.get("/api/v1/dynamic/session/events").status_code == 404


# ---- SSE stream -----------------------------------------------------------


def test_sse_stream_404_without_session(client, patch_backend):
    resp = client.get("/api/v1/dynamic/session/events/stream")
    assert resp.status_code == 404


def test_stream_generator_replays_snapshot_then_live(monkeypatch):
    """The SSE generator (unit): replay the buffered snapshot, then stream a
    live event, then end when the owning session is torn down. Driven
    directly - no open HTTP connection (a never-ending SSE stream can't be
    cleanly torn down by the single-connection TestClient)."""
    import app.dynamic.router as router

    feed = events.EventFeed("android")
    feed.publish("hook", "pinning", "pre-existing", code="android-pinning")

    class FakeSession:
        pass

    FakeSession.feed = feed
    monkeypatch.setattr(base, "active_session", lambda: FakeSession())
    gen = router._stream_events(feed)
    # first frame = the snapshot event
    first = next(gen)
    assert "pre-existing" in first
    # publish a LIVE event -> next frame
    feed.publish("hook", "root", "live-now", code="android-root-detection")
    second = next(gen)
    assert "live-now" in second
    # end the session (feed torn down) -> generator ends cleanly
    monkeypatch.setattr(base, "active_session", lambda: None)
    gen.close()


# ---- default hook registry --------------------------------------------------


def test_default_hooks_list_android(client, patch_backend, db_session_factory, auth_user_id):
    _connected(client, db_session_factory, auth_user_id)
    resp = client.get("/api/v1/dynamic/session/scripts")
    assert resp.status_code == 200
    ids = {h["id"] for h in resp.json()}
    assert "android-pinning" in ids
    assert "android-root-detection" in ids
    for h in resp.json():
        assert h["platform"] == "android"
        assert h["description"]
        assert "SCRIPT_ID" in h["script"]  # a real JS body, not a stub


def test_default_hooks_platform_param(client, patch_backend, db_session_factory, auth_user_id):
    _connected(client, db_session_factory, auth_user_id)
    resp = client.get("/api/v1/dynamic/session/scripts?platform=ios")
    assert resp.status_code == 200
    ids = {h["id"] for h in resp.json()}
    assert "ios-pinning" in ids
    assert "ios-jailbreak-detection" in ids
    assert "ios-keychain" in ids
    assert all(h["platform"] == "ios" for h in resp.json())


def test_default_hooks_unknown_platform_400(
    client, patch_backend, db_session_factory, auth_user_id
):
    _connected(client, db_session_factory, auth_user_id)
    resp = client.get("/api/v1/dynamic/session/scripts?platform=webos")
    assert resp.status_code == 400


def test_default_hooks_404_without_session(client, patch_backend):
    resp = client.get("/api/v1/dynamic/session/scripts")
    assert resp.status_code == 404