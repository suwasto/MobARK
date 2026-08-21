"""Regression test: adding a second BYOK provider must not remove the first."""

import pytest

from app.config import Settings
from app.model.backends import BackendStore, ModelBackend


@pytest.fixture()
def store(tmp_path):
    return BackendStore(tmp_path, settings_obj=Settings())


@pytest.fixture()
def api(store, monkeypatch, client):
    """Authenticated client with monkeypatched store + health."""
    import app.api.routes.models as m
    from app.model.health import BackendHealth

    monkeypatch.setattr(m, "get_store", lambda: store)
    monkeypatch.setattr(
        m,
        "check_backend",
        lambda b, probe=False: BackendHealth(
            backend_id=b.id,
            reachable=True,
            status="ok",
            latency_ms=12,
            models=[],
            model_source="live",
            probe_model=None,
            probe_ok=None,
        ),
    )
    monkeypatch.setattr(m, "list_models", lambda b: ([], "live", None))
    return client


def test_add_two_byok_providers_persists_both(api, store):
    """User adds gemini, then openrouter — both must remain visible."""
    # Step 1: add gemini
    r1 = api.post(
        "/api/v1/model/backends",
        json={"provider_id": "gemini", "api_key": "gkey-test"},
    )
    assert r1.status_code == 201
    assert r1.json()["id"] == "gemini"
    assert r1.json()["has_api_key"] is True

    # Step 2: list — gemini should be there
    r_list1 = api.get("/api/v1/model/backends")
    ids1 = {b["id"] for b in r_list1.json()}
    assert "gemini" in ids1, f"gemini missing after first add: {ids1}"

    # Step 3: add openrouter
    r2 = api.post(
        "/api/v1/model/backends",
        json={"provider_id": "openrouter", "api_key": "orkey-test"},
    )
    assert r2.status_code == 201
    assert r2.json()["id"] == "openrouter"
    assert r2.json()["has_api_key"] is True

    # Step 4: list — BOTH gemini and openrouter must be there
    r_list2 = api.get("/api/v1/model/backends")
    ids2 = {b["id"] for b in r_list2.json()}
    assert "gemini" in ids2, f"gemini missing after adding openrouter: {ids2}"
    assert "openrouter" in ids2, f"openrouter missing after add: {ids2}"

    cloud = [b for b in r_list2.json() if not b["local"]]
    assert len(cloud) >= 2, f"Expected at least 2 cloud backends, got {cloud}"


def test_add_two_byok_then_delete_one_preserves_other(api, store):
    """Add gemini + openrouter, delete gemini — openrouter must remain."""
    api.post("/api/v1/model/backends", json={"provider_id": "gemini", "api_key": "gk"})
    api.post("/api/v1/model/backends", json={"provider_id": "openrouter", "api_key": "ok"})

    # Delete gemini
    r = api.delete("/api/v1/model/backends/gemini")
    assert r.status_code == 204

    # openrouter must still be there
    r_list = api.get("/api/v1/model/backends")
    ids = {b["id"] for b in r_list.json()}
    assert "openrouter" in ids, f"openrouter missing after deleting gemini: {ids}"
    assert "gemini" not in ids


def test_store_persists_multiple_byok_across_instances(tmp_path):
    """BackendStore.add preserves data across new store instances."""
    s1 = BackendStore(tmp_path)
    s1.add(ModelBackend(
        id="gemini", provider_id="gemini", name="Gemini",
        kind="byok", base_url="https://generativelanguage.googleapis.com/v1beta",
        api_key="gkey", enabled=True,
    ))
    s1.add(ModelBackend(
        id="openrouter", provider_id="openrouter", name="OpenRouter",
        kind="byok", base_url="https://openrouter.ai/api/v1",
        api_key="orkey", enabled=True,
    ))

    # Fresh store instance should see both
    s2 = BackendStore(tmp_path)
    ids = {b.id for b in s2.read()}
    assert "gemini" in ids
    assert "openrouter" in ids
    cloud = [b for b in s2.read() if not b.local]
    assert len(cloud) == 2


def test_add_three_byok_providers(api, store):
    """Add gemini, openrouter, openai — all three must persist."""
    for pid, key in [("gemini", "gk"), ("openrouter", "ok"), ("openai", "sk")]:
        r = api.post("/api/v1/model/backends", json={"provider_id": pid, "api_key": key})
        assert r.status_code == 201, f"Failed to add {pid}: {r.json()}"

    r = api.get("/api/v1/model/backends")
    ids = {b["id"] for b in r.json()}
    assert ids >= {"gemini", "openrouter", "openai"}, f"Missing providers: {ids}"
