"""M9.1 Phase A auth tests - password hashing, sessions, the auth routes,
the router guard, the Origin check, and the auth-off parity mode.

``client`` is the authenticated fixture (M9.1 flip); ``unauth_client`` has
no cookie - the 401 assertions, the health/auth-route tests, and the
full register/login flows all go through it. No network, no OAuth (Phase B).
"""
from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import func, select

import app.config
from app.auth.security import (
    SESSION_COOKIE,
    hash_password,
    new_session_token,
    token_hash,
    verify_password,
)
from app.auth.sessions import create_session
from app.auth.users import count_users, find_by_username
from app.models import Scan, User, utcnow
from app.models import Session as AuthSession


@pytest.fixture(autouse=True)
def _pin_data_dir(tmp_path, monkeypatch):
    """Register/login/CLI-reset now create vault files + per-user stores
    under settings.data_dir - pin it to the test tmp dir so the real
    backend/data is never touched (and per-test uids don't collide)."""
    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)


# ---- password hashing (stdlib scrypt, zero new deps - decision 4) -----------


def test_hash_password_format_and_round_trip():
    encoded = hash_password("correct horse battery")
    parts = encoded.split("$")
    assert parts[0] == "scrypt"
    assert len(parts) == 6  # scrypt $ n $ r $ p $ salt $ hash
    n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
    assert n >= 2 and r >= 1 and p >= 1
    assert len(bytes.fromhex(parts[4])) >= 16  # per-user salt
    assert verify_password("correct horse battery", encoded) is True


def test_verify_password_wrong_and_tampered():
    encoded = hash_password("right-password")
    assert verify_password("wrong-password", encoded) is False
    # Tamper with the hash body -> False, never a crash.
    parts = encoded.split("$")
    parts[5] = "00" * 32
    assert verify_password("right-password", "$".join(parts)) is False
    # Tamper with cost params -> rejected before verification.
    parts = encoded.split("$")
    parts[1] = "1"  # n < 2 is absurd - refuse
    assert verify_password("right-password", "$".join(parts)) is False


def test_verify_password_malformed_inputs():
    assert verify_password("x", "") is False
    assert verify_password("x", "bcrypt$whatever") is False
    assert verify_password("x", "scrypt$not$hex") is False
    assert verify_password("x", None) is False


def test_salts_are_unique_per_hash():
    assert hash_password("same") != hash_password("same")


def test_session_token_digest_is_sha256_of_raw():
    raw, digest = new_session_token()
    assert raw != digest
    assert digest == token_hash(raw)
    assert len(raw) == 43  # token_urlsafe(32)
    assert len(digest) == 64  # sha256 hex


# ---- register / first-user admin + legacy claim -----------------------------


def test_register_first_user_is_admin_and_sets_cookie(unauth_client, db_session_factory):
    r = unauth_client.post(
        "/api/v1/auth/register",
        json={"username": "alice", "password": "password123"},
    )
    assert r.status_code == 201
    body = r.json()["user"]
    assert body["username"] == "alice"
    assert body["is_admin"] is True  # first registered user = admin (decision 5)
    assert "mobark_session" in r.headers["set-cookie"]
    with db_session_factory() as db:
        assert count_users(db) == 1


def test_register_claims_legacy_unowned_scans(unauth_client, db_session_factory):
    with db_session_factory() as db:
        db.add_all(
            [
                Scan(filename="old.apk", status="done"),  # NULL user_id - legacy
                Scan(filename="old2.ipa", status="done"),  # NULL user_id - legacy
            ]
        )
        db.commit()
    r = unauth_client.post(
        "/api/v1/auth/register",
        json={"username": "admin", "password": "password123"},
    )
    assert r.status_code == 201
    with db_session_factory() as db:
        user = find_by_username(db, "admin")
        assert user is not None
        owner_ids = set(db.scalars(select(Scan.user_id)).all())
        assert owner_ids == {user.id}  # both legacy rows claimed, exactly once


def test_register_duplicate_username_409(unauth_client, db_session_factory):
    with db_session_factory() as db:
        db.add(User(username="bob", password_hash=hash_password("password123")))
        db.commit()
    r = unauth_client.post(
        "/api/v1/auth/register",
        json={"username": "bob", "password": "password123"},
    )
    assert r.status_code == 409
    assert "already registered" in r.json()["detail"]


def test_register_duplicate_email_409(unauth_client, db_session_factory):
    with db_session_factory() as db:
        db.add(User(username="bob", email="bob@example.com", password_hash="x"))
        db.commit()
    r = unauth_client.post(
        "/api/v1/auth/register",
        json={"username": "carol", "email": "bob@example.com", "password": "password123"},
    )
    assert r.status_code == 409


def test_register_invalid_inputs_422(unauth_client):
    for payload in [
        {"username": "ab", "password": "password123"},  # username too short
        {"username": "bad name!", "password": "password123"},  # bad chars
        {"username": "alice", "password": "short"},  # password too short
        {"username": "alice"},  # missing password
    ]:
        r = unauth_client.post("/api/v1/auth/register", json=payload)
        assert r.status_code == 422, payload


# ---- login (no user enumeration) --------------------------------------------


def test_login_success_sets_cookie_and_me_round_trip(unauth_client):
    unauth_client.post(
        "/api/v1/auth/register",
        json={"username": "alice", "password": "password123"},
    )
    r = unauth_client.post(
        "/api/v1/auth/login",
        json={"username": "alice", "password": "password123"},
    )
    assert r.status_code == 200
    assert r.json()["user"]["username"] == "alice"
    assert "mobark_session" in r.headers["set-cookie"]
    # The login cookie now authenticates /auth/me.
    me = unauth_client.get("/api/v1/auth/me")
    assert me.status_code == 200
    assert me.json()["username"] == "alice"


def test_login_by_email(unauth_client):
    unauth_client.post(
        "/api/v1/auth/register",
        json={"username": "alice", "email": "alice@example.com", "password": "password123"},
    )
    r = unauth_client.post(
        "/api/v1/auth/login",
        json={"username": "alice@example.com", "password": "password123"},
    )
    assert r.status_code == 200


def test_login_mobark_default_credentials(unauth_client, db_session_factory):
    """The `mobark:mobark` login works end to end.

    ``mobark`` is only 6 chars, so the *password* can't pass the register
    route's 8-char minimum (that's by design - it's a demo/host-seeded
    credential, not a self-registration). Seed the account directly in the
    DB the same way the conftest fixture does, then prove the login
    round-trip: 200 + session cookie, and the cookie now authenticates
    /auth/me.
    """
    with db_session_factory() as db:
        user = User(username="mobark", password_hash=hash_password("mobark"))
        db.add(user)
        db.commit()

    r = unauth_client.post(
        "/api/v1/auth/login",
        json={"username": "mobark", "password": "mobark"},
    )
    assert r.status_code == 200
    assert r.json()["user"]["username"] == "mobark"
    assert "mobark_session" in r.headers["set-cookie"]

    me = unauth_client.get("/api/v1/auth/me")
    assert me.status_code == 200
    assert me.json()["username"] == "mobark"


def test_login_no_user_enumeration(unauth_client, db_session_factory):
    with db_session_factory() as db:
        db.add(
            User(username="known", password_hash=hash_password("password123"))
        )
        db.commit()
    unknown = unauth_client.post(
        "/api/v1/auth/login",
        json={"username": "ghost", "password": "password123"},
    )
    wrong = unauth_client.post(
        "/api/v1/auth/login",
        json={"username": "known", "password": "wrong-password"},
    )
    # Identical status AND detail - a probe can't tell them apart.
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json()["detail"] == wrong.json()["detail"] == "invalid username or password"


def test_login_disabled_user_same_message(unauth_client, db_session_factory):
    with db_session_factory() as db:
        db.add(
            User(
                username="gone",
                password_hash=hash_password("password123"),
                is_active=False,
            )
        )
        db.commit()
    r = unauth_client.post(
        "/api/v1/auth/login",
        json={"username": "gone", "password": "password123"},
    )
    assert r.status_code == 401
    assert r.json()["detail"] == "invalid username or password"


# ---- logout -----------------------------------------------------------------


def test_logout_revokes_exact_session(client, db_session_factory):
    token = client.cookies.get(SESSION_COOKIE)
    assert token is not None
    r = client.post("/api/v1/auth/logout")
    assert r.status_code == 204
    # The response deletes the cookie (max-age=0) - and, the real property,
    # the exact session row is revoked server-side: the SAME cookie token
    # can no longer reach a guarded route.
    assert "max-age=0" in r.headers["set-cookie"].lower()
    assert client.get("/api/v1/scans").status_code == 401
    with db_session_factory() as db:
        assert db.scalar(select(func.count()).select_from(AuthSession)) == 0
    # Idempotent: a second logout (no session left) is still 204.
    assert client.post("/api/v1/auth/logout").status_code == 204


# ---- me / providers ---------------------------------------------------------


def test_me_requires_session(unauth_client):
    assert unauth_client.get("/api/v1/auth/me").status_code == 401


def test_providers_local_only_and_auth_enabled(unauth_client):
    body = unauth_client.get("/api/v1/auth/providers").json()
    assert body == {"auth_enabled": True, "providers": ["local"]}


# ---- the guard: 401 on every guarded router, health stays open --------------
# (Phase C threads require_scan_access per scan route; Phase A proves the
# router-level wall + the open exceptions.)


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/scans",
        "/api/v1/model/backends",
        "/api/v1/search/backends",
    ],
)
def test_guarded_routers_401_without_session(unauth_client, path):
    assert unauth_client.get(path).status_code == 401


def test_health_stays_open(unauth_client):
    r = unauth_client.get("/api/v1/health")
    assert r.status_code == 200


def test_auth_routes_stay_open(unauth_client):
    assert unauth_client.get("/api/v1/auth/providers").status_code == 200
    assert unauth_client.get("/api/v1/auth/me").status_code == 401  # still needs a session


# ---- sessions: expiry + deactivation ----------------------------------------


def test_expired_session_401(client, db_session_factory):
    # Point the authenticated client's cookie at an EXPIRED session row.
    with db_session_factory() as db:
        row = db.scalar(select(AuthSession).limit(1))
        row.expires_at = utcnow() - timedelta(days=1)
        db.commit()
    # The guard must reject it (and the row is revoked on sight).
    assert client.get("/api/v1/scans").status_code == 401
    with db_session_factory() as db:
        assert db.scalar(select(func.count()).select_from(AuthSession)) == 0


def test_disabled_user_session_401(client, db_session_factory):
    with db_session_factory() as db:
        user = db.scalar(select(User).limit(1))
        user.is_active = False
        db.commit()
    assert client.get("/api/v1/scans").status_code == 401


def test_sliding_expiry_refreshes(client, db_session_factory):
    # A session created ~6 days ago expires SOON (now + 1 day): still valid,
    # and using it slides the window forward to now + session_days.
    with db_session_factory() as db:
        row = db.scalar(select(AuthSession).limit(1))
        row.expires_at = utcnow() + timedelta(days=1)
        db.commit()
    assert client.get("/api/v1/scans").status_code == 200
    with db_session_factory() as db:
        row = db.scalar(select(AuthSession).limit(1))
        # The window slid from now+1d out to ~now+session_days (a couple ms
        # of guard/test clock skew aside - bound it loosely).
        slid = row.expires_at.replace(tzinfo=None)
        assert slid > (utcnow() + timedelta(days=6)).replace(tzinfo=None)
        assert slid <= (utcnow() + timedelta(days=8)).replace(tzinfo=None)


# ---- origin check (decision 8: CSRF posture, no new dep) --------------------


def test_mutating_cross_origin_rejected(unauth_client):
    r = unauth_client.post(
        "/api/v1/auth/login",
        json={"username": "x", "password": "password123"},
        headers={"Origin": "http://evil.example"},
    )
    assert r.status_code == 403
    assert "cross-origin" in r.json()["detail"]


def test_same_origin_mutating_passes(unauth_client):
    r = unauth_client.post(
        "/api/v1/auth/login",
        json={"username": "x", "password": "password123"},
        headers={"Origin": "http://testserver"},  # TestClient's default host
    )
    assert r.status_code == 401  # reached the route (bad creds), NOT the middleware


def test_get_with_foreign_origin_not_blocked(unauth_client):
    # Reads are not CSRF-sensitive - only mutating methods are checked.
    r = unauth_client.get(
        "/api/v1/scans", headers={"Origin": "http://evil.example"}
    )
    assert r.status_code == 401  # the auth guard, not the origin middleware


# ---- auth-off parity mode (MOBARK_AUTH_ENABLED=0 - dev/CI) ------------------


def test_auth_off_open_routes(unauth_client, monkeypatch):
    monkeypatch.setattr(app.config.settings, "auth_enabled", False)
    assert unauth_client.get("/api/v1/scans").status_code == 200
    assert unauth_client.get("/api/v1/model/backends").status_code == 200


def test_auth_off_unowned_scans_visible(unauth_client, db_session_factory, monkeypatch):
    """The dev/CI parity contract: with auth off, an unowned (NULL-owner)
    scan is fully visible - byte-for-byte the pre-M9.1 open behavior. The
    ownership gate only engages when auth is on."""
    monkeypatch.setattr(app.config.settings, "auth_enabled", False)
    with db_session_factory() as session:
        scan = Scan(filename="app.apk", platform="android", status="done")
        session.add(scan)
        session.commit()
        scan_id = scan.id
    r = unauth_client.get(f"/api/v1/scans/{scan_id}")
    assert r.status_code == 200
    assert r.json()["id"] == scan_id
    assert [s["id"] for s in unauth_client.get("/api/v1/scans").json()] == [scan_id]


def test_auth_off_register_login_inert(unauth_client, monkeypatch):
    monkeypatch.setattr(app.config.settings, "auth_enabled", False)
    r = unauth_client.post(
        "/api/v1/auth/register",
        json={"username": "alice", "password": "password123"},
    )
    assert r.status_code == 400
    r = unauth_client.post(
        "/api/v1/auth/login",
        json={"username": "alice", "password": "password123"},
    )
    assert r.status_code == 400


def test_auth_off_me_returns_null(unauth_client, monkeypatch):
    monkeypatch.setattr(app.config.settings, "auth_enabled", False)
    r = unauth_client.get("/api/v1/auth/me")
    assert r.status_code == 200
    assert r.json() is None


def test_auth_off_providers_flag(unauth_client, monkeypatch):
    monkeypatch.setattr(app.config.settings, "auth_enabled", False)
    body = unauth_client.get("/api/v1/auth/providers").json()
    assert body["auth_enabled"] is False


# ---- CLI password-reset escape hatch (open item 1) --------------------------


def test_cli_reset_password(db_session_factory, monkeypatch):
    from app.auth.users import find_by_username
    from app.cli import cmd_auth_reset_password

    monkeypatch.setattr("app.db.SessionLocal", db_session_factory)
    with db_session_factory() as db:
        user = User(username="alice", password_hash=hash_password("old-pass-123"))
        db.add(user)
        db.commit()
        create_session(db, user, session_days=7)  # one live session to revoke
        before = user.password_hash
        user_id = user.id

    assert cmd_auth_reset_password("alice", "new-pass-456") == 0
    with db_session_factory() as db:
        user = find_by_username(db, "alice")
        assert user.password_hash != before
        assert verify_password("new-pass-456", user.password_hash)
        assert verify_password("old-pass-123", user.password_hash) is False
        # Sessions die with the old password.
        remaining = db.scalar(
            select(func.count())
            .select_from(AuthSession)
            .where(AuthSession.user_id == user_id)
        )
        assert remaining == 0

    # Unknown user -> exit 1, no crash.
    assert cmd_auth_reset_password("nobody", "whatever123") == 1


def test_cli_reset_password_short_password_rejected(db_session_factory, monkeypatch):
    from app.cli import cmd_auth_reset_password

    monkeypatch.setattr("app.db.SessionLocal", db_session_factory)
    with db_session_factory() as db:
        db.add(User(username="alice", password_hash=hash_password("old-pass-123")))
        db.commit()
    assert cmd_auth_reset_password("alice", "short") == 1
