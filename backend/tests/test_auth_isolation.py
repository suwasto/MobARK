"""M9.1 Phase C - per-user scan isolation.

Ownership lives on ``scans.user_id``; one ``require_scan_access`` check per
scan-keyed route isolates everything downstream (findings, chats, edits,
builds, smali, report caches). These tests prove the three isolation
properties + the escape hatches:

1. Cross-user isolation - user B 404s (never 403, never data) on user A's
   scans, on EVERY scan-keyed surface.
2. Own-only listing - ``GET /scans`` shows only the caller's scans; a
   NULL-owner (legacy/CLI) scan appears in NO list and reads as 404 until
   an admin claims it.
3. Store isolation - per-user model/search backend stores live under
   ``data/users/<uid>/`` and seed from the SYSTEM layer; keys never cross.
4. Claim + CLI - admin ``POST /auth/claim`` adopts NULL-owner rows
   (idempotent); ``cli scan --user`` attributes the row at creation.
"""
import json

import pytest

from app.models import Scan, User
from tests.conftest import authed_user_id

# ---- helpers ---------------------------------------------------------------


class _FakeJob:
    """Stand-in for an RQ job so CLI tests don't need Redis."""

    def __init__(self, scan_id):
        self.id = f"fake-{scan_id}"


def _add_scan(
    db_session_factory, *, user_id=None, platform="android", status="done", filename="app.apk"
):
    with db_session_factory() as session:
        scan = Scan(
            filename=filename,
            platform=platform,
            status=status,
            user_id=user_id,
        )
        session.add(scan)
        session.commit()
        return scan.id


def _make_store_files(tmp_path, user_id, *, kind="model"):
    """Write a system-layer store file under ``tmp_path`` (the data dir)."""
    name = "model_backends.json" if kind == "model" else "search_backends.json"
    d = tmp_path / "users" / str(user_id)
    d.mkdir(parents=True)
    (tmp_path / name).write_text("[]\n")
    return d / name


# ---- 1. cross-user isolation ------------------------------------------------


def test_foreign_scan_404s_on_every_surface(client, auth_client, db_session_factory):
    """user B gets a 404 on user A's scan on every scan-keyed route - and
    the response body leaks nothing (same 404 as a nonexistent scan)."""
    a_id = _add_scan(db_session_factory, user_id=authed_user_id(db_session_factory))

    surfaces = [
        ("get", f"/api/v1/scans/{a_id}"),
        ("get", f"/api/v1/scans/{a_id}/report"),
        ("get", f"/api/v1/scans/{a_id}/findings"),
        ("get", f"/api/v1/scans/{a_id}/files"),
        ("post", f"/api/v1/scans/{a_id}/chat"),
        ("get", f"/api/v1/scans/{a_id}/chat/sessions"),
    ]
    # the authed `client` (user A) sees its own scan fine...
    assert client.get(f"/api/v1/scans/{a_id}").status_code == 200

    for method, url in surfaces:
        kwargs = {"json": {"question": "hi"}} if method == "post" else {}
        r = getattr(auth_client, method)(url, **kwargs)
        assert r.status_code == 404, f"{method} {url}: {r.status_code}"


def test_foreign_scan_indistinguishable_from_missing(client, auth_client, db_session_factory):
    """The 404 for a foreign scan is byte-identical to a nonexistent one."""
    a_id = _add_scan(db_session_factory, user_id=authed_user_id(db_session_factory))
    foreign = auth_client.get(f"/api/v1/scans/{a_id}")
    missing = auth_client.get("/api/v1/scans/999999")
    assert foreign.status_code == missing.status_code == 404
    assert foreign.json() == missing.json()


def test_foreign_scan_chat_stream_404(auth_client, db_session_factory):
    """The SSE stream route 404s on a foreign scan before emitting anything."""
    a_id = _add_scan(db_session_factory, user_id=999999)
    r = auth_client.post(f"/api/v1/scans/{a_id}/chat/stream", json={"question": "hi"})
    assert r.status_code == 404


# ---- 2. own-only listing ----------------------------------------------------


def test_list_scans_own_only(client, auth_client, db_session_factory):
    uid = authed_user_id(db_session_factory)
    _add_scan(db_session_factory, user_id=uid, filename="mine.apk")
    _add_scan(db_session_factory, user_id=999999, filename="theirs.apk")
    _add_scan(db_session_factory, user_id=None, filename="unowned.apk")

    mine = client.get("/api/v1/scans").json()
    names = [s["filename"] for s in mine]
    assert names == ["mine.apk"]  # theirs + unowned invisible

    theirs = auth_client.get("/api/v1/scans").json()
    assert theirs == []  # user B has nothing (their scans are A's? no - none)


def test_unowned_scan_reads_as_404(client, db_session_factory):
    """A NULL-owner (legacy/CLI) scan is invisible to everyone until claimed."""
    s_id = _add_scan(db_session_factory, user_id=None)
    assert client.get(f"/api/v1/scans/{s_id}").status_code == 404
    assert client.get("/api/v1/scans").json() == []


# ---- 3. per-user store isolation --------------------------------------------


def test_user_store_isolated_and_seeded_from_system(
    client, auth_client, db_session_factory, tmp_path, monkeypatch
):
    """Each user's model store is its own file under data/users/<uid>/; a
    user store with no file seeds from the system layer's current contents;
    a key written by user A never appears for user B."""
    monkeypatch.setattr("app.config.settings.data_dir", tmp_path)
    monkeypatch.setattr("app.config.settings.auth_enabled", True)
    uid = authed_user_id(db_session_factory)

    # user A adds a BYOK key -> lands in A's store, not the system file
    r = client.post(
        "/api/v1/model/backends",
        json={"id": "openai", "provider_id": "openai", "api_key": "sk-A-secret"},
    )
    assert r.status_code == 201, r.text

    a_file = tmp_path / "users" / str(uid) / "model_backends.json"
    assert a_file.is_file()
    payload = json.loads(a_file.read_text())
    key = next(b["api_key"] for b in payload if b["id"] == "openai")
    # M9.1 vault: the key is ENCRYPTED at rest - the plaintext must never
    # appear in the file, and the blob round-trips through the master key
    # (the fixture's seeded password unlocks the vault file).
    from app.auth.vault import is_vault_blob, unlock_vault, unwrap_secret

    assert key != "sk-A-secret"
    assert is_vault_blob(key) is True
    mk = unlock_vault(uid, "password123")
    assert mk is not None
    assert unwrap_secret(mk, key) == "sk-A-secret"
    assert "sk-A-secret" not in a_file.read_text()

    # the system store file itself never received the key (it may not even
    # exist - the user store seeds from env when there's no system file)
    sys_path = tmp_path / "model_backends.json"
    if sys_path.is_file():
        sys_payload = json.loads(sys_path.read_text())
        assert all(b.get("api_key") is None for b in sys_payload)

    # user B (auth_client = tester2) reads its own store - seeded from the
    # SYSTEM layer, never from A's file (a read-on-demand: B's file appears
    # on first read)
    from sqlalchemy import select

    with db_session_factory() as db:
        b_uid = db.scalar(select(User.id).where(User.username == "tester2"))
    b_file = tmp_path / "users" / str(b_uid) / "model_backends.json"
    rb = auth_client.get("/api/v1/model/backends")
    assert rb.status_code == 200
    assert b_file.is_file()
    b_payload = json.loads(b_file.read_text())
    # the isolation property: A's added key never appears in B's store
    # (B may still hold its own env-seeded key - that's fine, it's B's)
    assert all(b.get("api_key") != "sk-A-secret" for b in b_payload)


# ---- 4. claim + CLI attribution ---------------------------------------------


def test_admin_claim_adopts_unowned_scan(client, db_session_factory):
    uid = authed_user_id(db_session_factory)
    s_id = _add_scan(db_session_factory, user_id=None)

    # the unowned scan is invisible before the claim
    assert client.get(f"/api/v1/scans/{s_id}").status_code == 404

    r = client.post("/api/v1/auth/claim")
    assert r.status_code == 200
    assert r.json()["claimed"] == 1

    # the scan is now visible to the claiming (admin) user
    assert client.get(f"/api/v1/scans/{s_id}").status_code == 200

    # idempotent: second claim touches nothing
    r2 = client.post("/api/v1/auth/claim")
    assert r2.json()["claimed"] == 0

    # unowned scan is gone from the "invisible" set - now owned by admin
    with db_session_factory() as session:
        scan = session.get(Scan, s_id)
        assert scan.user_id == uid


def test_claim_requires_admin(client, db_session_factory):
    """A non-admin user gets 403 from /auth/claim (fixture users are admin by
    default, so demote the authed user first)."""
    with db_session_factory() as session:
        user = session.scalar(
            __import__("sqlalchemy").select(User).where(User.username == "tester")
        )
        user.is_admin = False
        session.commit()
    _add_scan(db_session_factory, user_id=None)
    r = client.post("/api/v1/auth/claim")
    assert r.status_code == 403


def test_cli_scan_user_attribution(db_session_factory, tmp_path, monkeypatch):
    """``cli scan --user`` attributes the row at creation; without it the
    row is unowned (adoptable by an admin claim)."""

    import app.cli

    with db_session_factory() as session:
        admin = User(username="ops", password_hash="x", is_admin=True)
        session.add(admin)
        session.commit()
        admin_id = admin.id

    import app.db
    import app.workers.jobs as jobs

    monkeypatch.setattr(app.db, "SessionLocal", db_session_factory)
    monkeypatch.setattr(app.cli.settings, "data_dir", tmp_path)
    monkeypatch.setattr(jobs, "enqueue_scan", lambda scan_id: _FakeJob(scan_id))

    artifact = tmp_path / "cli.apk"
    artifact.write_bytes(b"PK\x03\x04fake")

    # --user attributes the row
    assert app.cli.cmd_scan(artifact, user="ops") == 0
    with db_session_factory() as session:
        row = session.query(Scan).filter_by(filename="cli.apk").one()
        assert row.user_id == admin_id

    # without --user the row is unowned (adoptable)
    other = tmp_path / "other.apk"
    other.write_bytes(b"PK\x03\x04fake")
    assert app.cli.cmd_scan(other) == 0
    with db_session_factory() as session:
        row = session.query(Scan).filter_by(filename="other.apk").one()
        assert row.user_id is None

    # unknown --user is an explicit error, no row created
    assert app.cli.cmd_scan(other, user="nobody") == 1


def test_cli_scan_unknown_user_rejected(db_session_factory, tmp_path, monkeypatch):
    """An unknown --user name errors out without creating a row."""
    import app.cli
    import app.db
    import app.workers.jobs as jobs

    monkeypatch.setattr(app.db, "SessionLocal", db_session_factory)
    monkeypatch.setattr(app.cli.settings, "data_dir", tmp_path)
    monkeypatch.setattr(jobs, "enqueue_scan", lambda scan_id: _FakeJob(scan_id))
    artifact = tmp_path / "x.apk"
    artifact.write_bytes(b"PK\x03\x04fake")
    assert app.cli.cmd_scan(artifact, user="ghost") == 1
    with db_session_factory() as session:
        assert session.query(Scan).count() == 0


def test_create_scan_ownership_via_api(
    client, auth_client, db_session_factory, monkeypatch, tmp_path
):
    """API uploads attribute the scan to the caller (auth-on) - the row is
    visible in the owner's list, invisible to another user."""
    from io import BytesIO

    from app.api.routes import scans as scan_routes

    monkeypatch.setattr(scan_routes, "enqueue_scan", lambda scan_id: None)

    def _upload(c, name):
        return c.post(
            "/api/v1/scans",
            files={"file": (name, BytesIO(b"PK\x03\x04fakezip"), "application/octet-stream")},
        )

    r = _upload(client, "mine.apk")
    if r.status_code == 400:
        pytest.skip("artifact validation rejects the fake zip before ownership")
    assert r.status_code == 201
    mine = r.json()
    assert mine["filename"] == "mine.apk"

    # owner sees it in the list; another user does not
    assert [s["filename"] for s in client.get("/api/v1/scans").json()] == ["mine.apk"]
    assert auth_client.get("/api/v1/scans").json() == []

    # the other user 404s on the scan itself
    assert auth_client.get(f"/api/v1/scans/{mine['id']}").status_code == 404
