"""M9.1 vault - envelope encryption of BYOK/search API keys at rest.

Covers the crypto primitives (scrypt KEK + AES-GCM envelope), the per-user
store protection (keys are blobs on disk, plaintext only in memory via
``resolved_api_key``), the locked-vault rejections, the lazy migration of
pre-vault plaintext files, and the auth flows (register/login unlock, the
OAuth passphrase endpoints, the ``vault_locked`` flag on /auth/me).
"""

from __future__ import annotations

import json

import pytest

from app.auth import vault
from app.auth.security import SESSION_COOKIE
from app.auth.vault import (
    VaultLockedError,
    create_vault,
    destroy_vault,
    generate_master_key,
    has_vault,
    is_vault_blob,
    unlock_vault,
    unwrap_from_session,
    unwrap_secret,
    wrap_for_session,
    wrap_secret,
)
from app.config import Settings
from app.model.backends import BackendStore, ModelBackend
from app.request_ctx import current_master_key
from app.search.backends import SearchBackend, SearchStore

# ---- primitives --------------------------------------------------------------


def test_wrap_unwrap_round_trip():
    mk = generate_master_key()
    blob = wrap_secret(mk, "sk-secret-123")
    assert is_vault_blob(blob) is True
    assert unwrap_secret(mk, blob) == "sk-secret-123"
    # A different master key cannot decrypt (AES-GCM tag check).
    assert unwrap_secret(generate_master_key(), blob) is None
    # Garbage never raises - just None.
    assert unwrap_secret(mk, "not-a-blob") is None
    assert unwrap_secret(mk, '{"v": 1, "nope": 1}') is None


def test_is_vault_blob():
    mk = generate_master_key()
    assert is_vault_blob(wrap_secret(mk, "x")) is True
    assert is_vault_blob("sk-plaintext") is False
    assert is_vault_blob('{"weird": "json"}') is False
    assert is_vault_blob("") is False
    assert is_vault_blob(None) is False


def test_create_unlock_destroy_vault(data_dir):
    mk = create_vault(9, "correct horse battery")
    assert has_vault(9) is True
    assert unlock_vault(9, "correct horse battery") == mk
    # Wrong password -> None (AES-GCM authenticates); file untouched.
    assert unlock_vault(9, "wrong-password-123") is None
    assert has_vault(9) is True
    destroy_vault(9)
    assert has_vault(9) is False
    assert unlock_vault(9, "correct horse battery") is None
    # Destroy on a missing vault is a no-op.
    destroy_vault(9)


def test_vault_file_is_0600_and_holds_no_plaintext(data_dir):
    create_vault(9, "password123")
    path = vault.vault_path(9)
    assert path.is_file()
    assert (path.stat().st_mode & 0o777) == 0o600
    raw = path.read_text()
    assert "password123" not in raw
    assert "master" not in raw


def test_session_wrap_round_trip():
    mk = generate_master_key()
    token = "a" * 43  # token_urlsafe shape
    wrap = wrap_for_session(mk, token)
    assert unwrap_from_session(wrap, token) == mk
    assert unwrap_from_session(wrap, "b" * 43) is None  # wrong token
    assert unwrap_from_session("garbage", token) is None


@pytest.fixture()
def data_dir(tmp_path, monkeypatch):
    import app.config as app_config

    monkeypatch.setattr(app_config.settings, "data_dir", tmp_path)
    return tmp_path


# ---- store at-rest protection -------------------------------------------------


def _mk(material: bytes | None = None):
    key = material if material is not None else b"m" * 32
    current_master_key.set(key)
    return key


def _openai_backend(api_key: str | None = "sk-secret") -> ModelBackend:
    return ModelBackend(
        id="openai",
        provider_id="openai",
        name="OpenAI",
        kind="byok",
        base_url="https://api.openai.com/v1",
        api_key=api_key,
    )


def test_per_user_store_encrypts_at_rest(tmp_path):
    _mk()
    store = BackendStore(tmp_path, settings_obj=Settings(), user_id=5)
    store.add(_openai_backend("sk-secret"))
    store.remove("fake")  # not seeded; no-op guard

    raw = (tmp_path / "users" / "5" / "model_backends.json").read_text()
    assert "sk-secret" not in raw  # plaintext never lands on disk
    backend = store.get("openai")
    assert backend is not None
    assert backend.has_api_key() is True
    assert is_vault_blob(backend.api_key) is True
    assert backend.resolved_api_key() == "sk-secret"


def test_system_store_stays_plaintext(tmp_path):
    _mk()  # even with a master key in context, the SYSTEM store is plaintext
    store = BackendStore(tmp_path, settings_obj=Settings())  # user_id None
    store.add(_openai_backend("sk-secret"))
    raw = (tmp_path / "model_backends.json").read_text()
    assert "sk-secret" in raw
    backend = store.get("openai")
    assert backend.resolved_api_key() == "sk-secret"
    assert is_vault_blob(backend.api_key) is False


def test_key_write_locked_raises(tmp_path):
    current_master_key.set(None)  # vault locked
    store = BackendStore(tmp_path, settings_obj=Settings(), user_id=5)
    with pytest.raises(VaultLockedError):
        store.add(_openai_backend("sk-secret"))
    # Upserting a key onto an existing backend raises too...
    store2 = BackendStore(tmp_path, settings_obj=Settings(), user_id=5)
    store2.add(_openai_backend(None))  # keyless add is fine
    with pytest.raises(VaultLockedError):
        store2.upsert("openai", api_key="sk-secret")
    # ...but non-key writes (enabled toggle, base URL) are not blocked.
    store2.upsert("openai", base_url="http://x")  # no raise


def test_resolved_key_none_when_locked(tmp_path):
    _mk()
    store = BackendStore(tmp_path, settings_obj=Settings(), user_id=5)
    store.add(_openai_backend("sk-secret"))
    current_master_key.set(None)  # lock AFTER the write
    backend = store.get("openai")
    assert backend.has_api_key() is True  # the blob exists at rest...
    assert backend.resolved_api_key() is None  # ...but can't be decrypted


def test_lazy_migration_encrypts_pre_vault_plaintext(tmp_path):
    # A pre-vault per-user store file holding plaintext keys (auth-off /
    # pre-upgrade writes) is migrated in place on first unlocked read.
    store = BackendStore(tmp_path, settings_obj=Settings(), user_id=5)
    path = tmp_path / "users" / "5" / "model_backends.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps([{**_backend_row(), "api_key": "sk-old"}]))
    _mk()
    backends = store.read()
    migrated = next(b for b in backends if b.id == "openai")
    # The in-memory list stays plaintext (memory is never the guarantee) -
    # the FILE is what gets encrypted by the migration rewrite.
    assert migrated.resolved_api_key() == "sk-old"
    raw = path.read_text()
    assert "sk-old" not in raw  # the rewrite replaced the plaintext bytes
    parsed = json.loads(raw)
    blob = next(b["api_key"] for b in parsed if b["id"] == "openai")
    assert is_vault_blob(blob) is True


def _backend_row() -> dict:
    return {
        "id": "openai",
        "provider_id": "openai",
        "name": "OpenAI",
        "kind": "byok",
        "base_url": "https://api.openai.com/v1",
        "model": "",
        "enabled": True,
    }


def test_clear_api_keys_drops_blobs(tmp_path):
    _mk()
    store = BackendStore(tmp_path, settings_obj=Settings(), user_id=5)
    store.add(_openai_backend("sk-secret"))
    store.clear_api_keys()
    backend = store.get("openai")
    assert backend.has_api_key() is False
    raw = (tmp_path / "users" / "5" / "model_backends.json").read_text()
    assert "sk-secret" not in raw


def test_search_store_encrypts_keyed_keys(tmp_path):
    _mk()
    store = SearchStore(tmp_path, settings_obj=Settings(), user_id=5)
    store.add(
        SearchBackend(
            id="brave",
            provider_id="brave",
            name="Brave",
            kind="keyed",
            base_url="https://api.search.brave.com",
            api_key="bsk-secret",
        )
    )
    raw = (tmp_path / "users" / "5" / "search_backends.json").read_text()
    assert "bsk-secret" not in raw
    backend = store.get("brave")
    assert is_vault_blob(backend.api_key) is True
    assert backend.resolved_api_key() == "bsk-secret"


def test_search_store_locked_raise_and_clear(tmp_path):
    current_master_key.set(None)
    store = SearchStore(tmp_path, settings_obj=Settings(), user_id=5)
    with pytest.raises(VaultLockedError):
        store.add(
            SearchBackend(
                id="brave",
                provider_id="brave",
                name="Brave",
                kind="keyed",
                base_url="https://api.search.brave.com",
                api_key="bsk-secret",
            )
        )


# ---- auth flows ---------------------------------------------------------------


def test_register_creates_vault_and_api_keys_encrypted(
    unauth_client, db_session_factory, tmp_path, monkeypatch
):
    """End to end: register -> vault created + session unlocked; a BYOK key
    added through the API lands as a blob in the user's store file."""
    import app.config as app_config

    monkeypatch.setattr(app_config.settings, "data_dir", tmp_path)
    r = unauth_client.post(
        "/api/v1/auth/register",
        json={"username": "alice", "password": "password123"},
    )
    assert r.status_code == 201
    with db_session_factory() as db:
        from app.models import User

        uid = db.scalar(
            __import__("sqlalchemy").select(User.id).where(User.username == "alice")
        )
    assert has_vault(uid) is True

    # The registered session is unlocked: a key write succeeds and the file
    # holds only ciphertext.
    r = unauth_client.post(
        "/api/v1/model/backends",
        json={"provider_id": "openai", "api_key": "sk-e2e-secret"},
    )
    assert r.status_code == 201, r.text
    store_file = tmp_path / "users" / str(uid) / "model_backends.json"
    raw = store_file.read_text()
    assert "sk-e2e-secret" not in raw
    payload = json.loads(raw)
    blob = next(b["api_key"] for b in payload if b["id"] == "openai")
    mk = unlock_vault(uid, "password123")
    assert unwrap_secret(mk, blob) == "sk-e2e-secret"


def test_login_re_wraps_vault_for_session(
    unauth_client, db_session_factory, tmp_path, monkeypatch
):
    import app.config as app_config
    from app.auth.sessions import user_from_token

    monkeypatch.setattr(app_config.settings, "data_dir", tmp_path)
    unauth_client.post(
        "/api/v1/auth/register",
        json={"username": "alice", "password": "password123"},
    )
    unauth_client.post("/api/v1/auth/logout")
    r = unauth_client.post(
        "/api/v1/auth/login",
        json={"username": "alice", "password": "password123"},
    )
    assert r.status_code == 200
    token = unauth_client.cookies.get(SESSION_COOKIE)
    with db_session_factory() as db:
        _user, row = user_from_token(
            db, token, session_days=7, with_row=True
        )
        assert row is not None and row.vault_wrap is not None


def _oauth_client(db_session_factory, tmp_path, monkeypatch):
    """A TestClient with an OAuth-only user (no password) and a session that
    has NOT unlocked the vault - the shape an OAuth callback produces."""
    from fastapi.testclient import TestClient

    import app.config as app_config
    from app.auth.sessions import create_session
    from app.db import get_db
    from app.main import app
    from app.models import User

    monkeypatch.setattr(app_config.settings, "data_dir", tmp_path)

    def override_get_db():
        db = db_session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    with db_session_factory() as db:
        user = User(username="alice", auth_provider="github", oauth_id="42")
        db.add(user)
        db.commit()
        raw, _ = create_session(db, user, session_days=7)  # no vault wrap
        uid = user.id
    client.cookies.set(SESSION_COOKIE, raw)
    return client, uid


def test_oauth_vault_unlock_create_wrong_reset(db_session_factory, tmp_path, monkeypatch):
    client, uid = _oauth_client(db_session_factory, tmp_path, monkeypatch)
    try:
        # /auth/me reports the session vault-locked.
        me = client.get("/api/v1/auth/me").json()
        assert me["vault_locked"] is True

        # First unlock CREATES the vault; the session becomes unlocked.
        assert has_vault(uid) is False
        r = client.post(
            "/api/v1/auth/vault/unlock", json={"passphrase": "correct-horse-battery"}
        )
        assert r.status_code == 200
        assert has_vault(uid) is True
        assert client.get("/api/v1/auth/me").json()["vault_locked"] is False

        # A wrong passphrase on the EXISTING vault 401s and leaves it intact
        # (never silently re-created - that would orphan the stored keys).
        r2 = client.post("/api/v1/auth/vault/unlock", json={"passphrase": "wrong-pass-123"})
        assert r2.status_code == 401
        assert has_vault(uid) is True
        assert client.get("/api/v1/auth/me").json()["vault_locked"] is False  # still unlocked

        # Reset (forgot the passphrase) destroys the vault.
        r3 = client.post("/api/v1/auth/vault/reset")
        assert r3.status_code == 200
        assert has_vault(uid) is False
    finally:
        from app.main import app as fastapi_app

        fastapi_app.dependency_overrides.clear()


def test_local_user_cannot_use_passphrase_endpoints(
    unauth_client, db_session_factory, tmp_path, monkeypatch
):
    import app.config as app_config

    monkeypatch.setattr(app_config.settings, "data_dir", tmp_path)
    unauth_client.post(
        "/api/v1/auth/register",
        json={"username": "alice", "password": "password123"},
    )
    r = unauth_client.post(
        "/api/v1/auth/vault/unlock", json={"passphrase": "whatever-pass-123"}
    )
    assert r.status_code == 400
    assert "password" in r.json()["detail"]


def test_vault_locked_flag_false_for_local_users(
    unauth_client, db_session_factory, tmp_path, monkeypatch
):
    import app.config as app_config

    monkeypatch.setattr(app_config.settings, "data_dir", tmp_path)
    unauth_client.post(
        "/api/v1/auth/register",
        json={"username": "alice", "password": "password123"},
    )
    assert unauth_client.get("/api/v1/auth/me").json()["vault_locked"] is False
