"""M9.1 Phase E - hardening edge coverage.

The Phase A-C suites prove the happy paths + the main rejections. These
tests close the edge list from the plan:

- **cookie tampering** - a forged/unknown cookie value 401s on every
  guarded route (malformed, plausible-but-unknown, and length-spoofed
  tokens all rejected before any DB query).
- **concurrent first-user claim** - two racing registrations must yield
  exactly ONE admin. The DB backstop (partial unique index on is_admin,
  migration 0014) plus the register route's IntegrityError re-derivation
  are tested at three levels: the schema guarantee, a real threaded race
  through the API, and the sequential second-user-is-not-admin property.
- **auth-off parity for owned scans** - with MASA_AUTH_ENABLED=0 an OWNED
  scan (user_id set) is fully readable without a session; ownership is
  invisible in parity mode, byte-for-byte the pre-M9.1 open behavior.
"""
import threading

import pytest
from sqlalchemy import func, select

import app.config
from app.auth.security import SESSION_COOKIE
from app.models import Scan, User
from app.models import Session as AuthSession


@pytest.fixture(autouse=True)
def _pin_data_dir(tmp_path, monkeypatch):
    """The register race creates vault files under settings.data_dir - pin
    it to the test tmp dir so the real backend/data is never touched."""
    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)

# ---- cookie tampering -------------------------------------------------------


def test_garbage_cookie_401(client, db_session_factory):
    """A random non-token cookie value is rejected (never a crash)."""
    client.cookies.set(SESSION_COOKIE, "garbage-not-a-token!!")
    assert client.get("/api/v1/scans").status_code == 401


def test_unknown_but_plausible_token_401(client, db_session_factory):
    """A well-formed token_urlsafe value with no matching session row is
    rejected - the honest unknown-token case (not a crash, not a leak)."""
    import secrets

    client.cookies.set(SESSION_COOKIE, secrets.token_urlsafe(32))
    assert client.get("/api/v1/scans").status_code == 401
    # And the row count is unchanged - no phantom session is created.
    with db_session_factory() as db:
        assert db.scalar(select(func.count()).select_from(AuthSession)) == 1


def test_tampered_session_still_401_after_logout_elsewhere(client, db_session_factory):
    """A session revoked by another device (row deleted) instantly 401s - the
    mid-use revocation path (e.g. a password reset elsewhere)."""
    with db_session_factory() as db:
        db.execute(AuthSession.__table__.delete())
        db.commit()
    # The client still carries the cookie - the guard must reject it.
    assert client.get("/api/v1/scans").status_code == 401
    assert client.get("/api/v1/auth/me").status_code == 401


# ---- concurrent first-user claim (exactly one admin) ------------------------


def test_schema_guarantees_single_admin(db_session_factory):
    """Migration 0014's partial unique index: a second admin row cannot be
    inserted, even directly in SQL - the DB is the backstop for the race."""

    with db_session_factory() as db:
        db.add(User(username="first", password_hash="x", is_admin=True))
        db.commit()
    with db_session_factory() as db:
        try:
            db.add(User(username="second", password_hash="x", is_admin=True))
            db.commit()
            raise AssertionError("second admin row should have been rejected")
        except Exception as exc:  # sqlalchemy IntegrityError (rolled back)
            db.rollback()
            assert "UNIQUE" in str(exc)
    # A non-admin second row is fine.
    with db_session_factory() as db:
        db.add(User(username="third", password_hash="x", is_admin=False))
        db.commit()


def test_second_registered_user_not_admin(unauth_client):
    """The sequential property: the first user is admin, the second is not."""
    r1 = unauth_client.post(
        "/api/v1/auth/register",
        json={"username": "alice", "password": "password123"},
    )
    assert r1.status_code == 201
    assert r1.json()["user"]["is_admin"] is True

    r2 = unauth_client.post(
        "/api/v1/auth/register",
        json={"username": "bob", "password": "password123"},
    )
    assert r2.status_code == 201
    assert r2.json()["user"]["is_admin"] is False


def test_concurrent_registration_single_admin(unauth_client, db_session_factory):
    """Two racing registrations on an empty DB produce exactly ONE admin.

    Real threads + a barrier maximize the race (both requests read zero
    users before either commits). The DB's partial unique index lets one
    admin row through; the register route's IntegrityError handler turns the
    loser into a non-admin (201, not 500, not a second admin)."""
    from fastapi.testclient import TestClient

    from app.db import get_db
    from app.main import app

    # ONE shared override for both threads (clearing it inside a thread's
    # finally would race the other thread's in-flight request back onto the
    # real DB). Each thread still needs its OWN TestClient - the shared
    # `unauth_client` fixture isn't thread-safe.
    def override_get_db():
        db = db_session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    barrier = threading.Barrier(2)
    statuses: list[int] = []
    admins: list[bool] = []
    lock = threading.Lock()

    def register(username: str):
        client = TestClient(app)
        barrier.wait(timeout=10)
        r = client.post(
            "/api/v1/auth/register",
            json={"username": username, "password": "password123"},
        )
        with lock:
            statuses.append(r.status_code)
            if r.status_code == 201:
                admins.append(r.json()["user"]["is_admin"])

    t1 = threading.Thread(target=register, args=("racer1",))
    t2 = threading.Thread(target=register, args=("racer2",))
    t1.start()
    t2.start()
    t1.join(timeout=15)
    t2.join(timeout=15)
    app.dependency_overrides.clear()

    # Both registrations succeeded (the loser re-derived, never 500s).
    assert sorted(statuses) == [201, 201]
    # Exactly one admin across the two.
    assert sum(1 for a in admins if a) == 1
    with db_session_factory() as db:
        assert db.scalar(select(func.count()).select_from(User)) == 2
        assert (
            db.scalar(select(func.count()).select_from(User).where(User.is_admin))
            == 1
        )


# ---- auth-off parity for owned scans ----------------------------------------


def test_auth_off_owned_scan_fully_readable(unauth_client, db_session_factory, monkeypatch):
    """Parity contract: with auth off, an OWNED scan (user_id set) is fully
    readable with no session - ownership is invisible in dev/CI mode."""
    monkeypatch.setattr("app.config.settings.auth_enabled", False)
    with db_session_factory() as session:
        scan = Scan(
            filename="owned.apk",
            platform="android",
            status="done",
            user_id=1,  # owned by a user that doesn't even need to exist
        )
        session.add(scan)
        session.commit()
        scan_id = scan.id
    r = unauth_client.get(f"/api/v1/scans/{scan_id}")
    assert r.status_code == 200
    assert r.json()["id"] == scan_id
    assert [s["id"] for s in unauth_client.get("/api/v1/scans").json()] == [scan_id]
    # The whole downstream surface reads open too (findings endpoint).
    assert unauth_client.get(f"/api/v1/scans/{scan_id}/findings").status_code == 200
    assert unauth_client.get(f"/api/v1/scans/{scan_id}/report").status_code == 200


def test_auth_off_session_cookie_irrelevant(unauth_client, db_session_factory, monkeypatch):
    """Parity mode: even a garbage session cookie doesn't change anything -
    the guard is fully off, not 'accept any session'."""
    monkeypatch.setattr("app.config.settings.auth_enabled", False)
    unauth_client.cookies.set(SESSION_COOKIE, "totally-bogus")
    assert unauth_client.get("/api/v1/scans").status_code == 200
    assert unauth_client.get("/api/v1/auth/me").status_code == 200
    assert unauth_client.get("/api/v1/auth/me").json() is None
