"""M3 API surface — health functions monkeypatched, no network, no disk store
churn on the real data dir."""

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import app
from app.model.backends import BackendStore
from app.model.health import BackendHealth


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
    assert {"ollama", "lm-studio", "openai", "anthropic", "deepseek", "openrouter"} <= ids
    assert all("api_key" not in b for b in data)

    ollama = next(b for b in data if b["id"] == "ollama")
    assert ollama["local"] is True
    assert ollama["kind"] == "local"
    assert ollama["health"]["reachable"] is True

    openai = next(b for b in data if b["id"] == "openai")
    assert openai["local"] is False
    assert openai["has_api_key"] is False
    assert openai["health"]["status"] == "ok"


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
    api.put("/api/v1/model/backends/openai", json={"api_key": "sk-secret"})
    api.put("/api/v1/model/backends/openai", json={"api_key": ""})
    openai = next(b for b in api.get("/api/v1/model/backends").json() if b["id"] == "openai")
    assert openai["has_api_key"] is False
