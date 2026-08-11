"""M7 search-backend API — CRUD + the one-Active radio enforced server-side
(no network; the store + health check are monkeypatched)."""

import json

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import app
from app.search.backends import SearchStore
from app.search.client import SearchHealth


@pytest.fixture()
def store(tmp_path):
    return SearchStore(tmp_path, settings_obj=Settings())


@pytest.fixture()
def api(store, monkeypatch):
    import app.api.routes.search as r

    monkeypatch.setattr(r, "get_search_store", lambda: store)
    monkeypatch.setattr(
        r,
        "check_backend",
        lambda b, probe=False: SearchHealth(
            backend_id=b.id,
            reachable=True,
            status="ok",
            latency_ms=5,
            result_count=3 if probe else None,
            sample_title="probe hit" if probe else None,
        ),
    )
    with TestClient(app) as c:
        yield c


def test_list_backends_seeds_bundled_searxng(api):
    r = api.get("/api/v1/search/backends")
    assert r.status_code == 200
    data = r.json()
    assert [b["id"] for b in data] == ["searxng"]
    assert data[0]["kind"] == "bundled"
    assert data[0]["enabled"] is True
    assert data[0]["health"]["reachable"] is True


def test_put_enabled_false_then_active_none(api, store):
    r = api.put("/api/v1/search/backends/searxng", json={"enabled": False})
    assert r.status_code == 200
    assert r.json()["enabled"] is False
    assert store.active() is None


def test_radio_two_puts_leave_one_active(api, store):
    """The Settings toggle is one UI over this path: PUT {enabled:true} on a
    second engine turns the first off — the radio is server-enforced."""
    api.post(
        "/api/v1/search/backends",
        json={"provider_id": "custom", "base_url": "http://searxng.example:8080"},
    )
    api.put("/api/v1/search/backends/searxng", json={"enabled": True})
    assert store.active().id == "searxng"
    api.put("/api/v1/search/backends/custom", json={"enabled": True})
    assert store.active().id == "custom"
    enabled = [b for b in store.read() if b.enabled]
    assert len(enabled) == 1


def test_custom_add_requires_base_url(api):
    r = api.post("/api/v1/search/backends", json={"provider_id": "custom"})
    assert r.status_code == 400
    assert "base URL" in r.json()["detail"]


def test_custom_add_unknown_provider_400(api):
    r = api.post(
        "/api/v1/search/backends",
        json={"provider_id": "yandex", "base_url": "http://x"},
    )
    assert r.status_code == 400
    assert "unknown search provider" in r.json()["detail"]


def test_custom_add_bundled_rejected(api):
    r = api.post(
        "/api/v1/search/backends",
        json={"provider_id": "searxng", "base_url": "http://x"},
    )
    assert r.status_code == 400


def test_custom_add_success_becomes_active(api, store):
    r = api.post(
        "/api/v1/search/backends",
        json={"provider_id": "custom", "base_url": "http://searxng.example:8080"},
    )
    assert r.status_code == 201
    body = r.json()
    assert body["id"] == "custom"
    assert body["kind"] == "custom"
    assert body["enabled"] is True
    assert store.active().id == "custom"
    assert store.get("searxng").enabled is False  # radio


def test_custom_add_duplicate_409(api):
    api.post(
        "/api/v1/search/backends",
        json={"provider_id": "custom", "base_url": "http://searxng.example:8080"},
    )
    r = api.post(
        "/api/v1/search/backends",
        json={"provider_id": "custom", "base_url": "http://other.example:8080"},
    )
    assert r.status_code == 409


def test_update_base_url_persists(api, store):
    r = api.put("/api/v1/search/backends/searxng", json={"base_url": "http://localhost:9000"})
    assert r.status_code == 200
    assert r.json()["base_url"] == "http://localhost:9000"
    assert store.get("searxng").base_url == "http://localhost:9000"


def test_delete_bundled_and_custom(api, store):
    assert api.delete("/api/v1/search/backends/custom").status_code == 404
    api.post(
        "/api/v1/search/backends",
        json={"provider_id": "custom", "base_url": "http://searxng.example:8080"},
    )
    assert api.delete("/api/v1/search/backends/custom").status_code == 204
    assert store.get("custom") is None
    # The bundled entry is deletable too (store file is the source of truth).
    assert api.delete("/api/v1/search/backends/searxng").status_code == 204
    assert store.active() is None


def test_unknown_backend_404(api):
    assert api.get("/api/v1/search/backends/nope").status_code == 404
    assert api.put("/api/v1/search/backends/nope", json={"enabled": True}).status_code == 404
    assert api.post("/api/v1/search/backends/nope/test").status_code == 404
    assert api.delete("/api/v1/search/backends/nope").status_code == 404


def test_test_endpoint_runs_full_probe(api):
    r = api.post("/api/v1/search/backends/searxng/test")
    assert r.status_code == 200
    body = r.json()
    assert body["health"]["status"] == "ok"
    assert body["health"]["result_count"] == 3
    assert body["health"]["sample_title"] == "probe hit"


def test_disabled_searxng_backend_still_gets_lightweight_health(api, store):
    """SearXNG-style engines are probed on the list even when INACTIVE — the
    cheap base-URL check — so the Settings Active radio stays disabled until
    the engine is actually reachable (owner follow-up, Aug 11)."""
    api.put("/api/v1/search/backends/searxng", json={"enabled": False})
    data = api.get("/api/v1/search/backends").json()
    searxng = next(b for b in data if b["id"] == "searxng")
    assert searxng["enabled"] is False
    assert searxng["health"] is not None
    assert searxng["health"]["reachable"] is True  # monkeypatched probe


def test_disabled_keyed_backend_has_no_health(api, store):
    """Keyed engines keep the enabled-only rule: their honest health check is
    a real query (validates the key — the base URL has no meaningful root
    endpoint), so an INACTIVE keyed engine is never probed on the list route.
    The (also inactive) bundled SearXNG still carries lightweight health."""
    api.post(
        "/api/v1/search/backends",
        json={"provider_id": "brave", "api_key": "bsk-secret"},
    )
    # Adding brave turned searxng off (radio); now deactivate brave itself.
    api.put("/api/v1/search/backends/brave", json={"enabled": False})
    data = api.get("/api/v1/search/backends").json()
    brave = next(b for b in data if b["id"] == "brave")
    assert brave["enabled"] is False
    assert brave["health"] is None
    searxng = next(b for b in data if b["id"] == "searxng")
    assert searxng["health"] is not None


# ---- providers endpoint + keyed creation ------------------------------------


def test_providers_endpoint_lists_addable_engines(api):
    """The Settings add-form picker — everything except the bundled SearXNG
    (always present, edited not re-added). Single source of truth."""
    r = api.get("/api/v1/search/providers")
    assert r.status_code == 200
    by_id = {p["id"]: p for p in r.json()}
    assert set(by_id) == {"custom", "brave", "serper", "mojeek"}
    assert by_id["custom"]["base_url_required"] is True
    assert by_id["custom"]["key_required"] is False
    assert by_id["brave"]["key_required"] is True
    assert by_id["brave"]["base_url_required"] is False
    assert by_id["mojeek"]["default_base_url"] == "https://www.mojeek.com"


def test_create_keyed_provider_with_key(api, store):
    r = api.post(
        "/api/v1/search/backends",
        json={"provider_id": "brave", "api_key": "bsk-secret"},
    )
    assert r.status_code == 201
    body = r.json()
    assert body["id"] == "brave"
    assert body["kind"] == "keyed"
    assert body["has_api_key"] is True
    assert body["enabled"] is True  # radio: adding it turns the others off
    # The key itself is never returned — only has_api_key (honesty rule).
    assert "api_key" not in body
    assert "bsk-secret" not in json.dumps(body)
    stored = store.get("brave")
    assert stored.api_key == "bsk-secret"
    assert stored.base_url == "https://api.search.brave.com"  # provider default
    assert store.get("searxng").enabled is False  # radio


def test_create_keyed_provider_requires_key(api):
    r = api.post("/api/v1/search/backends", json={"provider_id": "serper"})
    assert r.status_code == 400
    assert "API key" in r.json()["detail"]


def test_create_keyed_duplicate_409(api):
    api.post(
        "/api/v1/search/backends",
        json={"provider_id": "mojeek", "api_key": "mk"},
    )
    r = api.post(
        "/api/v1/search/backends",
        json={"provider_id": "mojeek", "api_key": "mk2"},
    )
    assert r.status_code == 409


def test_upsert_api_key_round_trips(api, store):
    api.post(
        "/api/v1/search/backends",
        json={"provider_id": "brave", "api_key": "bsk-secret"},
    )
    r = api.put("/api/v1/search/backends/brave", json={"api_key": "bsk-new"})
    assert r.status_code == 200
    assert r.json()["has_api_key"] is True
    assert store.get("brave").api_key == "bsk-new"


# ---- one-click start for the bundled engine ---------------------------------


def test_start_bundled_runs_compose_and_returns_health(api, monkeypatch):
    """The one-click start: compose up runs (fixed command), then the engine
    wait returns the probed health — the card the Settings UI renders."""
    import app.api.routes.search as r

    calls: dict = {}

    def fake_compose_up():
        calls["ran"] = True

    def fake_wait(b, **kwargs):
        calls["waited"] = b.id
        return SearchHealth(
            backend_id=b.id,
            reachable=True,
            status="ok",
            latency_ms=5,
            result_count=2,
            sample_title="start probe",
        )

    monkeypatch.setattr(r, "_run_compose_up", fake_compose_up)
    monkeypatch.setattr(r, "_wait_for_engine", fake_wait)
    res = api.post("/api/v1/search/backends/searxng/start")
    assert res.status_code == 200
    body = res.json()
    assert calls["ran"] is True
    assert calls["waited"] == "searxng"
    assert body["health"]["reachable"] is True
    assert body["health"]["result_count"] == 2
    assert body["health"]["sample_title"] == "start probe"


def test_start_custom_backend_400(api):
    """Custom instances are self-hosted — no start command."""
    api.post(
        "/api/v1/search/backends",
        json={"provider_id": "custom", "base_url": "http://searxng.example:8080"},
    )
    res = api.post("/api/v1/search/backends/custom/start")
    assert res.status_code == 400
    assert "not bundled" in res.json()["detail"]


def test_start_failure_carries_manual_command(api, monkeypatch):
    """Docker unreachable / compose failed -> a 502 carrying the manual
    command, never a raw 500 — the Settings card shows it under the button."""
    import app.api.routes.search as r

    def boom():
        raise r._StartError(
            502,
            "Docker isn't reachable from this process — start the engine "
            "manually: `docker compose --profile web up -d searxng`",
        )

    monkeypatch.setattr(r, "_run_compose_up", boom)
    res = api.post("/api/v1/search/backends/searxng/start")
    assert res.status_code == 502
    assert "docker compose" in res.json()["detail"]


def test_start_unknown_backend_404(api):
    assert api.post("/api/v1/search/backends/nope/start").status_code == 404


def test_find_compose_file_searches_upward(monkeypatch, tmp_path):
    """The compose file is discovered upward from cwd so the backend can run
    from anywhere (dev runs from `backend/`, the file lives at repo root)."""
    from app.api.routes.search import _find_compose_file

    root = tmp_path / "repo"
    root.mkdir(parents=True)
    (root / "docker-compose.yml").write_text("services: {}\n")
    (root / "backend").mkdir()
    monkeypatch.chdir(root / "backend")
    assert _find_compose_file() == root / "docker-compose.yml"


def test_find_compose_file_returns_none_without_one(monkeypatch, tmp_path):
    from app.api.routes.search import _find_compose_file

    monkeypatch.chdir(tmp_path)
    assert _find_compose_file() is None
