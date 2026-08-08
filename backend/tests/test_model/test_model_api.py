"""M3 API surface — health functions monkeypatched, no network, no disk store
churn on the real data dir."""

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import app
from app.model.backends import BackendStore
from app.model.health import BackendHealth
from app.model.providers import PROVIDERS


@pytest.fixture()
def store(tmp_path):
    return BackendStore(tmp_path, settings_obj=Settings())


@pytest.fixture()
def api(store, monkeypatch):
    import app.api.routes.models as m

    monkeypatch.setattr(m, "get_store", lambda: store)
    monkeypatch.setattr(
        m,
        "check_backend",
        lambda b, probe=False: BackendHealth(
            backend_id=b.id,
            reachable=True,
            status="ok",
            latency_ms=12,
            models=["qwen2.5:7b"] if b.id == "ollama" else [],
            model_source="live",
            probe_model="qwen2.5:7b" if b.id == "ollama" else None,
            probe_ok=True if b.id == "ollama" else None,
        ),
    )
    monkeypatch.setattr(m, "list_models", lambda b: (["m1", "m2"], "live", None))
    with TestClient(app) as c:
        yield c


def test_list_backends_shape_and_redaction(api):
    r = api.get("/api/v1/model/backends")
    assert r.status_code == 200
    data = r.json()
    ids = {b["id"] for b in data}
    # BYOK backends are NOT seeded keyless (owner decision, Aug 8 2026) — a
    # fresh store carries only the local backends; cloud providers are added
    # via POST /backends (the BYOK menu).
    assert {"ollama", "lm-studio"} == ids
    assert all("api_key" not in b for b in data)

    ollama = next(b for b in data if b["id"] == "ollama")
    assert ollama["local"] is True
    assert ollama["kind"] == "local"
    assert ollama["health"]["reachable"] is True


def test_gemini_added_via_byok_carries_suggested_models(api):
    """The curated model list rides along so the Settings UI can show a
    small set by default with a "see all" reveal for the full served list."""
    r = api.post(
        "/api/v1/model/backends",
        json={"provider_id": "gemini", "api_key": "gkey-secret"},
    )
    assert r.status_code == 201
    body = r.json()
    assert body["id"] == "gemini"
    assert body["local"] is False
    assert body["has_api_key"] is True
    assert body["suggested_models"] == list(  # provider table is source of truth
        PROVIDERS["gemini"].suggested_models
    )


def test_test_endpoint_runs_full_check(api):
    r = api.post("/api/v1/model/backends/ollama/test")
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == "ollama"
    assert body["health"]["status"] == "ok"
    assert body["health"]["probe_model"] == "qwen2.5:7b"


def test_models_endpoint(api):
    r = api.get("/api/v1/model/backends/ollama/models")
    assert r.status_code == 200
    assert r.json() == {"models": ["m1", "m2"], "source": "live", "error": None}


def test_unknown_backend_404(api):
    assert api.get("/api/v1/model/backends/nope/models").status_code == 404
    assert api.post("/api/v1/model/backends/nope/test").status_code == 404
    assert api.put("/api/v1/model/backends/nope", json={"model": "x"}).status_code == 404


def test_upsert_persists_config_and_never_leaks_key(api):
    # BYOK backends start absent — add via POST (the BYOK menu) first.
    api.post("/api/v1/model/backends", json={"provider_id": "openai", "api_key": "sk-secret"})
    r = api.put("/api/v1/model/backends/openai", json={"model": "gpt-4o", "api_key": "sk-secret"})
    assert r.status_code == 200
    body = r.json()
    assert body["model"] == "gpt-4o"
    assert body["has_api_key"] is True
    assert "api_key" not in body

    # Persisted to the store file, and still redacted on subsequent reads.
    r2 = api.get("/api/v1/model/backends")
    openai = next(b for b in r2.json() if b["id"] == "openai")
    assert openai["model"] == "gpt-4o"
    assert openai["has_api_key"] is True
    assert "api_key" not in openai


def test_upsert_empty_key_clears(api):
    api.post("/api/v1/model/backends", json={"provider_id": "openai", "api_key": "sk-secret"})
    api.put("/api/v1/model/backends/openai", json={"api_key": ""})
    openai = next(b for b in api.get("/api/v1/model/backends").json() if b["id"] == "openai")
    assert openai["has_api_key"] is False


# ---- M5 lifecycle: POST create/activate + DELETE remove ---------------------


def test_create_byok_activates_with_key_and_persists(api, store):
    r = api.post("/api/v1/model/backends", json={"provider_id": "openai", "api_key": "sk-secret"})
    assert r.status_code == 201
    body = r.json()
    assert body["id"] == "openai"
    assert body["has_api_key"] is True
    assert body["local"] is False
    assert "api_key" not in body
    # persisted for subsequent reads
    openai = next(b for b in api.get("/api/v1/model/backends").json() if b["id"] == "openai")
    assert openai["has_api_key"] is True


def test_create_byok_requires_key_when_absent(api, store):
    store.remove("openai")
    r = api.post("/api/v1/model/backends", json={"provider_id": "openai"})
    assert r.status_code == 400
    assert "API key" in r.json()["detail"]


def test_create_custom_requires_base_url(api):
    r = api.post("/api/v1/model/backends", json={"provider_id": "custom"})
    assert r.status_code == 400
    assert "base URL" in r.json()["detail"]


def test_create_custom_success(api):
    r = api.post(
        "/api/v1/model/backends",
        json={"provider_id": "custom", "base_url": "http://localhost:9999/v1", "model": "my-model"},
    )
    assert r.status_code == 201
    body = r.json()
    assert body["id"] == "custom"
    assert body["kind"] == "custom"
    assert body["model"] == "my-model"
    assert body["local"] is False


def test_create_custom_upserts_when_present(api):
    api.post(
        "/api/v1/model/backends",
        json={"provider_id": "custom", "base_url": "http://localhost:9999/v1"},
    )
    r = api.post(
        "/api/v1/model/backends",
        json={"provider_id": "custom", "base_url": "http://localhost:10000/v1"},
    )
    assert r.status_code == 201
    assert r.json()["base_url"] == "http://localhost:10000/v1"


def test_create_unknown_provider_400(api):
    r = api.post("/api/v1/model/backends", json={"provider_id": "nope", "api_key": "k"})
    assert r.status_code == 400
    assert "unknown provider" in r.json()["detail"]


def test_create_local_backend_rejected_400(api):
    r = api.post("/api/v1/model/backends", json={"provider_id": "ollama"})
    assert r.status_code == 400
    assert "local backend" in r.json()["detail"]


def test_delete_custom_204_and_gone(api):
    api.post(
        "/api/v1/model/backends",
        json={"provider_id": "custom", "base_url": "http://localhost:9999/v1"},
    )
    assert api.delete("/api/v1/model/backends/custom").status_code == 204
    ids = {b["id"] for b in api.get("/api/v1/model/backends").json()}
    assert "custom" not in ids


def test_delete_local_backend_rejected_400(api):
    r = api.delete("/api/v1/model/backends/ollama")
    assert r.status_code == 400
    assert "cannot be removed" in r.json()["detail"]


def test_delete_unknown_backend_404(api):
    assert api.delete("/api/v1/model/backends/nope").status_code == 404


def test_delete_byok_then_reactivate(api, store):
    api.post("/api/v1/model/backends", json={"provider_id": "openai", "api_key": "sk-secret"})
    assert api.delete("/api/v1/model/backends/openai").status_code == 204
    ids = {b["id"] for b in api.get("/api/v1/model/backends").json()}
    assert "openai" not in ids
    # re-add via POST with a fresh key
    r = api.post("/api/v1/model/backends", json={"provider_id": "openai", "api_key": "sk-new"})
    assert r.status_code == 201
    openai = next(b for b in api.get("/api/v1/model/backends").json() if b["id"] == "openai")
    assert openai["has_api_key"] is True


def test_store_add_duplicate_id_raises(store):
    from app.model.backends import ModelBackend

    store.add(
        ModelBackend(
            id="custom", provider_id="custom", name="Custom", kind="custom",
            base_url="http://localhost:9999/v1",
        )
    )
    import pytest

    with pytest.raises(ValueError):
        store.add(
            ModelBackend(
                id="custom", provider_id="custom", name="Custom", kind="custom",
                base_url="http://localhost:9999/v1",
            )
        )
