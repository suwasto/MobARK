import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.auth.security import SESSION_COOKIE, hash_password
from app.auth.sessions import create_session
from app.db import Base, get_db
from app.main import app
from app.models import User


def authed_user_id(factory):
    """The id of the authenticated fixture user (``tester``) in a scratch
    DB, or None when the ``client`` fixture hasn't run (auth/legacy tests).
    M9.1 Phase C: scans a test creates directly in the DB must be attributed
    to the authed user or they read as foreign (404)."""
    from sqlalchemy import select

    from app.models import User

    with factory() as db:
        return db.scalar(select(User.id).where(User.username == "tester"))


@pytest.fixture()
def auth_user_id(client, db_session_factory):
    """The authenticated user's id behind the ``client`` fixture (Phase C
    isolation tests attribute scans to it / assert own-only lists)."""
    return authed_user_id(db_session_factory)


@pytest.fixture()
def db_session_factory(tmp_path):
    """A scratch-file SQLite engine + session factory, isolated per test."""
    db_file = tmp_path / "test.db"
    engine = create_engine(
        f"sqlite:///{db_file}", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    yield factory
    engine.dispose()


def make_test_client(factory, *, username: str = "tester"):
    """A TestClient whose cookie jar carries a valid session for a user.

    M9.1 flip: auth is ON by default, so the API suites run in the
    production posture (authenticated requests). The user + session are
    seeded directly in the DB - no register API call, no scrypt cost per
    test - and the raw cookie token is set straight into the client's jar
    (TestClient persists it across requests, exactly like a browser).
    Exported so store-only API suites (model/search routes build their own
    TestClient) can authenticate the same way.

    M9.1 vault: the fixture session is FULLY UNLOCKED (the local-user
    shape) - a vault is created for the seeded password and the master key
    is wrapped under the session token, so per-user key writes through the
    API exercise the encrypted-at-rest path. Tests that pin
    ``settings.data_dir`` themselves still work: the guard unwraps the key
    from the session (no vault-file access), and the stores go wherever the
    test points ``data_dir``.
    """
    def override_get_db():
        db = factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    with factory() as db:
        # Phase E: the single-admin partial unique index (migration 0014)
        # means at most ONE admin row can exist - the FIRST fixture user is
        # admin, later users (tester2 etc.) are regular users. This matches
        # production reality (first registered user = admin) and keeps the
        # isolation suites' multi-client tests valid.
        from sqlalchemy import func, select

        from app.auth import vault as _vault

        is_first = db.scalar(select(func.count()).select_from(User)) == 0
        user = User(
            username=username,
            password_hash=hash_password("password123"),
            is_admin=is_first,
        )
        db.add(user)
        db.commit()
        mk = _vault.create_vault(user.id, "password123")
        raw_token, row = create_session(db, user, session_days=7)
        row.vault_wrap = _vault.wrap_for_session(mk, raw_token)
        db.commit()
    client.cookies.set(SESSION_COOKIE, raw_token)
    return client


@pytest.fixture()
def client(db_session_factory, tmp_path, monkeypatch):
    """Authenticated API client - the default for the (flipped) suites.
    Exercises the guarded surface in the production posture: auth ON + a
    valid session cookie. ``settings.data_dir`` is pinned to a tmp dir so
    the vault files the fixture creates never touch the real backend/data.
    """
    import app.config as app_config

    monkeypatch.setattr(app_config.settings, "data_dir", tmp_path)
    with make_test_client(db_session_factory) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture()
def auth_client(db_session_factory, tmp_path, monkeypatch):
    """A fresh-user authenticated client (distinct user per use). The
    isolation suites (Phase C) spin up two of these to prove user B 404s on
    user A's scans; the auth suites use it to assert login/me round-trips
    through the REAL register/login routes. data_dir pinned like ``client``.
    """
    import app.config as app_config

    monkeypatch.setattr(app_config.settings, "data_dir", tmp_path)
    with make_test_client(db_session_factory, username="tester2") as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture()
def unauth_client(db_session_factory):
    """Raw TestClient with NO session cookie - the 401 assertions, the
    health/auth-route tests, and the auth-off parity suite."""
    def override_get_db():
        db = db_session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
