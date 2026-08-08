def test_root(client):
    """The root route serves the SPA shell when the frontend dist is bundled
    (M5 Phase I — the container), otherwise the bare API banner
    (backend-only dev)."""
    from pathlib import Path

    dist = Path(__file__).resolve().parents[2] / "frontend" / "dist"
    r = client.get("/")
    assert r.status_code == 200
    if (dist / "index.html").is_file():
        assert "text/html" in r.headers["content-type"]
        assert "<!doctype html" in r.text.lower()
    else:
        body = r.json()
        assert body["app"] == "MASA"
        assert "version" in body


def test_health_returns_schema(client):
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] in ("ok", "degraded")
    assert isinstance(body["version"], str) and body["version"]
    assert isinstance(body["redis_ok"], bool)
    # The scratch DB is always reachable through the overridden dependency.
    assert body["db_ok"] is True
