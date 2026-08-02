def test_root(client):
    r = client.get("/")
    assert r.status_code == 200
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
