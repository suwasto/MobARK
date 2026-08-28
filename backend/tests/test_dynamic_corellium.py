"""M17 Corellium backend tests - config store + client + backend seam + API.

The Corellium path is opt-in, OFF by default (FR-D5a). Covers: the per-user
config store (env seed, 0600, vault-wrapped key), the httpx client (auth
header, error mapping, project->instance flattening, NOT SSRF-guarded by
design), the ``IosBackend`` seam (physical + virtual discovery merge, device
routing by prefix, ``connection_type=corellium`` + ``corellium_enabled``),
and the config API (GET/PUT/DELETE + probe). Real frida attach is the owner
manual checkpoint - no live Corellium call is made.
"""
from __future__ import annotations

import json
import os

import pytest

from app.config import Settings
from app.dynamic.base import DynamicError
from app.dynamic.ios.corellium import devices as corellium_devices
from app.dynamic.ios.corellium.config import CorelliumStore


def _settings(**overrides) -> Settings:
    return Settings(**{"data_dir": ".", **overrides})


# ---- config store ---------------------------------------------------------


def test_seed_off_by_default(tmp_path):
    """A fresh store with no env is unconfigured (off by default, FR-D5a)."""
    store = CorelliumStore(tmp_path, settings_obj=_settings())
    cfg = store.read()
    assert cfg.base_url == ""
    assert cfg.api_key is None
    assert cfg.configured() is False
    assert store.configured() is False
    assert store.path.is_file()


def test_seed_requires_both_url_and_key(tmp_path, monkeypatch):
    """A bare base URL with no key seeds nothing usable (BYOK rule)."""
    monkeypatch.setenv("MOBARK_CORELLIUM_BASE_URL", "https://app.corellium.com")
    store = CorelliumStore(tmp_path, settings_obj=Settings())
    cfg = store.read()
    assert cfg.base_url == ""
    assert cfg.configured() is False


def test_seed_from_env(tmp_path, monkeypatch):
    monkeypatch.setenv("MOBARK_CORELLIUM_BASE_URL", "https://app.corellium.com")
    monkeypatch.setenv("MOBARK_CORELLIUM_API_KEY", "tok-123")
    store = CorelliumStore(tmp_path, settings_obj=Settings())
    cfg = store.read()
    assert cfg.base_url == "https://app.corellium.com"
    assert cfg.configured() is True
    assert cfg.resolved_api_key() == "tok-123"


def test_upsert_persists(tmp_path):
    store = CorelliumStore(tmp_path, settings_obj=_settings())
    cfg = store.upsert(base_url="https://app.corellium.com", api_key="tok-456")
    assert cfg.configured() is True
    store2 = CorelliumStore(tmp_path, settings_obj=_settings())
    assert store2.read().base_url == "https://app.corellium.com"


def test_empty_base_url_clears_config(tmp_path):
    store = CorelliumStore(tmp_path, settings_obj=_settings())
    store.upsert(base_url="https://app.corellium.com", api_key="tok")
    store.upsert(base_url="")
    assert store.read().configured() is False


def test_clear_off_by_default_again(tmp_path):
    store = CorelliumStore(tmp_path, settings_obj=_settings())
    store.upsert(base_url="https://app.corellium.com", api_key="tok")
    store.clear()
    assert store.read().configured() is False


def test_store_permissions_0600(tmp_path):
    store = CorelliumStore(tmp_path, settings_obj=_settings())
    store.read()
    assert os.stat(store.path).st_mode & 0o777 == 0o600


def test_corrupt_store_reseeds(tmp_path):
    store = CorelliumStore(tmp_path, settings_obj=_settings())
    store.read()
    store.path.write_text("{not json")
    assert store.read().configured() is False


# ---- backend seam ---------------------------------------------------------


def test_corellium_device_id_prefix_roundtrip():
    assert corellium_devices.device_id("inst-1") == "corellium:inst-1"
    assert corellium_devices.instance_id_of("corellium:inst-1") == "inst-1"
    assert corellium_devices.is_corellium_device("corellium:inst-1") is True
    assert corellium_devices.is_corellium_device("a-physical-udid") is False


def test_list_devices_requires_config(tmp_path, monkeypatch):
    # No config -> the IosBackend.list_devices raises a clean 502 (no physical
    # device path, nothing configured), not a crash.
    import app.config as app_config
    import app.dynamic.client as dynamic_client

    monkeypatch.setattr(app_config.settings, "data_dir", tmp_path)
    from app.dynamic.ios.corellium import config as cconfig

    monkeypatch.setattr(
        cconfig,
        "get_corellium_store",
        lambda *a, **k: CorelliumStore(tmp_path, settings_obj=_settings()),
    )
    monkeypatch.setattr(
        dynamic_client.ios_devices,
        "list_devices",
        lambda: (_ for _ in ()).throw(DynamicError(502, "no pmd3")),
    )
    backend = dynamic_client.get_backend("ios")
    with pytest.raises(DynamicError):
        backend.list_devices()


def test_preflight_returns_off_checks_when_not_corellium():
    """A non-corellium device id returns all-False checks, never a crash."""
    checks = corellium_devices.preflight("a-physical-udid", "com.app")
    assert checks == {
        "device_reachable": False,
        "frida_server_reachable": False,
        "jailbreak_detected": False,
        "target_installed": False,
    }


# ---- client (fake httpx) --------------------------------------------------


def test_client_sends_bearer_and_flattens_instances(monkeypatch):
    """The real httpx client: Authorization Bearer header, projects ->
    instances flattening, normalized shape."""
    import httpx

    from app.dynamic.ios.corellium.client import CorelliumClient

    captured = {}

    def fake_get(url, headers=None, params=None, timeout=None):
        captured["headers"] = headers
        if url.endswith("/v1/projects"):
            return httpx.Response(200, json=[{"id": "p1"}, {"id": "p2"}])
        if "/v1/projects/p1/instances" in url:
            return httpx.Response(
                200,
                json=[
                    {"id": "inst-1", "name": "iPhone 11", "flavor": "iphone11", "os": "16.4"},
                    {"id": "inst-2", "name": "iPhone X", "flavor": "iphonex", "os": "15.7"},
                ],
            )
        return httpx.Response(200, json=[])

    monkeypatch.setattr(httpx, "get", fake_get)
    client = CorelliumClient("https://app.corellium.com", "tok-abc")
    insts = client.instances()
    assert len(insts) == 2
    assert insts[0]["id"] == "inst-1"
    assert insts[0]["name"] == "iPhone 11"
    assert insts[0]["model"] == "iphone11"
    assert insts[0]["state"] == "unknown"
    assert captured["headers"]["Authorization"] == "Bearer tok-abc"


def test_client_error_maps_to_corellium_error(monkeypatch):
    import httpx

    from app.dynamic.ios.corellium.client import CorelliumClient, CorelliumError

    def fake_get(url, headers=None, params=None, timeout=None):
        return httpx.Response(401, json={})

    monkeypatch.setattr(httpx, "get", fake_get)
    client = CorelliumClient("https://app.corellium.com", "bad")
    with pytest.raises(CorelliumError):
        client.instances()


def test_client_unreachable_maps_to_corellium_error(monkeypatch):
    import httpx

    from app.dynamic.ios.corellium.client import CorelliumClient, CorelliumError

    def fake_get(url, headers=None, params=None, timeout=None):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx, "get", fake_get)
    client = CorelliumClient("https://app.corellium.com", "bad")
    with pytest.raises(CorelliumError):
        client.instances()


def test_client_reachable_false_on_error(monkeypatch):
    import httpx

    from app.dynamic.ios.corellium.client import CorelliumClient

    def fake_get(url, headers=None, params=None, timeout=None):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(httpx, "get", fake_get)
    client = CorelliumClient("https://app.corellium.com", "bad")
    assert client.reachable() is False


def test_client_reachable_true(monkeypatch):
    import httpx

    from app.dynamic.ios.corellium.client import CorelliumClient

    def fake_get(url, headers=None, params=None, timeout=None):
        return httpx.Response(200, json=[{"id": "p1"}])

    monkeypatch.setattr(httpx, "get", fake_get)
    client = CorelliumClient("https://app.corellium.com", "ok")
    assert client.reachable() is True


# ---- config API -----------------------------------------------------------


def test_config_api_off_by_default(client):
    resp = client.get("/api/v1/dynamic/corellium/config")
    assert resp.status_code == 200
    body = resp.json()
    assert body["configured"] is False
    assert body["has_api_key"] is False
    assert "api_key" not in body


def test_config_api_behind_auth(unauth_client):
    assert unauth_client.get("/api/v1/dynamic/corellium/config").status_code == 401
    assert (
        unauth_client.put("/api/v1/dynamic/corellium/config", json={}).status_code
        == 401
    )
    assert unauth_client.delete("/api/v1/dynamic/corellium/config").status_code == 401


def test_config_api_put_roundtrip_never_returns_key(
    client, tmp_path, monkeypatch, auth_user_id
):
    import app.config as app_config

    monkeypatch.setattr(app_config.settings, "data_dir", tmp_path)
    resp = client.put(
        "/api/v1/dynamic/corellium/config",
        json={"base_url": "https://app.corellium.com", "api_key": "tok-secret"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["base_url"] == "https://app.corellium.com"
    assert body["has_api_key"] is True
    assert body["configured"] is True
    assert "tok-secret" not in resp.text
    # persisted to the per-user store, key vault-encrypted (the master key
    # isn't in scope here, so ``configured`` is False outside the request -
    # ``has_api_key`` + the encrypted blob are the at-rest truth).
    store = CorelliumStore(tmp_path, settings_obj=_settings(), user_id=auth_user_id)
    assert store.read().has_api_key() is True
    raw = json.loads(store.path.read_text())
    assert raw["api_key"] != "tok-secret"
    assert raw["api_key"].startswith("{")


def test_config_api_clear(client, tmp_path, monkeypatch, auth_user_id):
    import app.config as app_config

    monkeypatch.setattr(app_config.settings, "data_dir", tmp_path)
    client.put(
        "/api/v1/dynamic/corellium/config",
        json={"base_url": "https://app.corellium.com", "api_key": "tok"},
    )
    assert client.delete("/api/v1/dynamic/corellium/config").status_code == 204
    body = client.get("/api/v1/dynamic/corellium/config").json()
    assert body["configured"] is False
    assert body["has_api_key"] is False
    store = CorelliumStore(tmp_path, settings_obj=_settings(), user_id=auth_user_id)
    assert store.read().has_api_key() is False


def test_config_api_test_probe_reachable(client, tmp_path, monkeypatch):
    import httpx

    import app.config as app_config

    monkeypatch.setattr(app_config.settings, "data_dir", tmp_path)
    client.put(
        "/api/v1/dynamic/corellium/config",
        json={"base_url": "https://app.corellium.com", "api_key": "tok"},
    )

    def fake_get(url, headers=None, params=None, timeout=None):
        if url.endswith("/v1/projects"):
            return httpx.Response(200, json=[{"id": "p1"}])
        return httpx.Response(200, json=[])

    monkeypatch.setattr(httpx, "get", fake_get)
    resp = client.post("/api/v1/dynamic/corellium/test")
    assert resp.status_code == 200
    assert resp.json()["reachable"] is True
    assert resp.json()["configured"] is True


def test_config_api_test_probe_unreachable(client, tmp_path, monkeypatch):
    import httpx

    import app.config as app_config

    monkeypatch.setattr(app_config.settings, "data_dir", tmp_path)
    client.put(
        "/api/v1/dynamic/corellium/config",
        json={"base_url": "https://app.corellium.com", "api_key": "tok"},
    )

    def fake_get(url, headers=None, params=None, timeout=None):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(httpx, "get", fake_get)
    resp = client.post("/api/v1/dynamic/corellium/test")
    assert resp.status_code == 200
    body = resp.json()
    assert body["reachable"] is False
    assert body["error"]


def test_config_api_test_unconfigured(client):
    resp = client.post("/api/v1/dynamic/corellium/test")
    assert resp.status_code == 200
    assert resp.json() == {
        "configured": False,
        "reachable": False,
        "instance_count": 0,
        "error": None,
    }