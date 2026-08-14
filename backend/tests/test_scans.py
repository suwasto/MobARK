from app.models import Scan
from tests.conftest import authed_user_id


def test_list_scans_empty(client):
    r = client.get("/api/v1/scans")
    assert r.status_code == 200
    assert r.json() == []


def test_scan_create_and_fetch(client, db_session_factory):
    factory = db_session_factory
    with factory() as session:
        scan = Scan(
            filename="test.apk", status="queued",
            user_id=authed_user_id(factory),
        )
        session.add(scan)
        session.commit()
        scan_id = scan.id

    r = client.get(f"/api/v1/scans/{scan_id}")
    assert r.status_code == 200
    body = r.json()
    assert body["filename"] == "test.apk"
    assert body["status"] == "queued"
    assert body["platform"] is None

    r = client.get("/api/v1/scans")
    assert r.status_code == 200
    assert len(r.json()) == 1


def test_get_missing_scan_returns_404(client):
    r = client.get("/api/v1/scans/999999")
    assert r.status_code == 404
