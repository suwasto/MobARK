"""M9.1 vault: envelope encryption for BYOK/search API keys at rest.

Why: the store files (``model_backends.json`` / ``search_backends.json``)
previously held API keys in plaintext at 0600 perms - fine against other OS
users, but readable by the host operator (root owns the volume) and by any
backup of it. The vault moves keys to ciphertext at rest so a disk/backup
read yields nothing without the user's own secret.

Envelope (two layers - the 1Password model):

- A random 32-byte MASTER KEY per user wraps every API key (AES-GCM, a
  fresh nonce per key). It never touches disk in plaintext.
- The master key is itself wrapped by a KEK derived from a secret the user
  knows: the MASA password for local users (``hashlib.scrypt``, the same
  cost parameters as ``app/auth/security.py``), or a dedicated vault
  passphrase for OAuth-only users (who have no password).
- ``key_wrap.json`` (0600) under the user's store dir holds the wrapped
  master key: ``{v, kdf, n, r, p, salt, nonce, ct}``.

The unwrapped master key never persists. At login the password yields the
KEK -> MK, which is then wrapped AGAIN under the raw session token and
stored on the session row (``sessions.vault_wrap``, migration 0015). Every
guarded request unwraps it from the cookie-held token into
``request_ctx.current_master_key`` for that request only. A DB leak exposes
only ciphertext: the MK wrapped under a token whose raw form only the
browser holds - the SHA-256 digest in the DB cannot be inverted to unwrap
it.

One API key inside a store file is either a plaintext string (the SYSTEM
store: owner env-seeded keys, pre-vault files, auth-off mode) or a vault
blob ``{"v": 1, "nonce": <b64>, "ct": <b64>}`` (per-user store).
``is_vault_blob`` tells them apart.

Honest limits (documented in the evaluation): the host operator can still
extract a key from the app's process memory at runtime - true of every
local app. The guarantee is at rest: disk, backups, volume copies, and
tenant isolation.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.auth.security import _DK_BYTES, _SALT_BYTES, _SCRYPT_N, _SCRYPT_P, _SCRYPT_R
from app.config import settings

VAULT_FILENAME = "key_wrap.json"
VAULT_MODE = 0o600
USER_STORE_DIR = "users"

# AES-GCM nonce length (the standard 96-bit recommendation).
_NONCE_BYTES = 12


class VaultLockedError(Exception):
    """A key-write to a per-user store requires the vault unlocked - raising
    this (instead of silently persisting plaintext) keeps the at-rest
    guarantee honest. The routes map it to a 400 with the unlock hint."""


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.b64decode(value)


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    """The KEK derivation - the same scrypt the password hasher uses (cost
    params ride inside the wrap so a future bump can verify old vaults)."""
    return hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=_DK_BYTES
    )


# ---- one-key blobs (AES-GCM, fresh nonce) -----------------------------------


def wrap_secret(mk: bytes, plaintext: str) -> str:
    """Encrypt one API key under the master key -> a vault blob string."""
    nonce = secrets.token_bytes(_NONCE_BYTES)
    ct = AESGCM(mk).encrypt(nonce, plaintext.encode("utf-8"), None)
    return json.dumps({"v": 1, "nonce": _b64(nonce), "ct": _b64(ct)})


def unwrap_secret(mk: bytes, blob: str) -> str | None:
    """Decrypt one vault blob. None on any failure (tampered/malformed
    blob, wrong master key - AES-GCM raises InvalidTag) - never raises."""
    try:
        data = json.loads(blob) if isinstance(blob, str) else blob
        if not isinstance(data, dict) or data.get("v") != 1:
            return None
        pt = AESGCM(mk).decrypt(_unb64(data["nonce"]), _unb64(data["ct"]), None)
        return pt.decode("utf-8")
    except Exception:
        return None


def is_vault_blob(value: object) -> bool:
    """True when ``value`` is a vault blob (a JSON object with ``v: 1`` +
    ``nonce``/``ct``) rather than a plaintext key. Plaintext keys that
    happen to be JSON-shaped are vanishingly unlikely to carry all three."""
    if not isinstance(value, str) or not value.startswith("{"):
        return False
    try:
        data = json.loads(value)
    except json.JSONDecodeError:
        return False
    return (
        isinstance(data, dict)
        and data.get("v") == 1
        and "nonce" in data
        and "ct" in data
    )


# ---- master key <-> password KEK (key_wrap.json) ----------------------------


def generate_master_key() -> bytes:
    return secrets.token_bytes(_DK_BYTES)


def _write_json(path: Path, data: dict) -> None:
    """0600 atomic write (the temp file is created 0600 from the start - no
    world-readable window before the chmod, unlike a plain write-then-chmod)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, indent=2) + "\n"
    tmp = path.with_name(f"{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, VAULT_MODE)
    with os.fdopen(fd, "w") as f:
        f.write(payload)
    tmp.replace(path)
    try:
        os.chmod(path, VAULT_MODE)
    except OSError:
        pass


def vault_path(user_id: int) -> Path:
    """``data_dir/users/<uid>/key_wrap.json`` - the same per-user dir the
    store files live in (M9.1 decision 3)."""
    return Path(settings.data_dir) / USER_STORE_DIR / str(user_id) / VAULT_FILENAME


def has_vault(user_id: int) -> bool:
    return vault_path(user_id).is_file()


def create_vault(user_id: int, password: str) -> bytes:
    """Create ``key_wrap.json`` for ``user_id`` with a fresh master key
    wrapped under ``password`` (scrypt KEK). Returns the master key.

    Callers use this at register (no vault yet) and as the self-healing
    path when unlock fails on a missing/unwrappable file (a corrupt vault
    orphans old key blobs - the user re-enters them; the alternative,
    silently locking keys behind a vault the user can never open, is
    worse)."""
    mk = generate_master_key()
    salt = secrets.token_bytes(_SALT_BYTES)
    kek = _scrypt(password, salt, _SCRYPT_N, _SCRYPT_R, _SCRYPT_P)
    nonce = secrets.token_bytes(_NONCE_BYTES)
    ct = AESGCM(kek).encrypt(nonce, mk, None)
    _write_json(
        vault_path(user_id),
        {
            "v": 1,
            "kdf": "scrypt",
            "n": _SCRYPT_N,
            "r": _SCRYPT_R,
            "p": _SCRYPT_P,
            "salt": _b64(salt),
            "nonce": _b64(nonce),
            "ct": _b64(ct),
        },
    )
    return mk


def unlock_vault(user_id: int, password: str) -> bytes | None:
    """Unwrap and return the master key for ``password``. None when the
    vault file is missing OR the password is wrong / the file is
    malformed (AES-GCM authenticates - a wrong KEK fails the tag check).
    Never raises."""
    path = vault_path(user_id)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text())
        kek = _scrypt(
            password,
            _unb64(data["salt"]),
            int(data["n"]),
            int(data["r"]),
            int(data["p"]),
        )
        return AESGCM(kek).decrypt(_unb64(data["nonce"]), _unb64(data["ct"]), None)
    except Exception:
        return None


def destroy_vault(user_id: int) -> None:
    """Delete ``key_wrap.json`` - the password-reset / forgot-passphrase
    path. The wrapped keys become unrecoverable; callers must also clear
    the user's stored keys (``destroy_vault`` cannot - the store files are
    the stores' business)."""
    path = vault_path(user_id)
    try:
        path.unlink()
    except FileNotFoundError:
        pass


# ---- master key <-> session token (sessions.vault_wrap) ---------------------
# The unwrapped MK must be recoverable on every guarded request without the
# password. The only per-request secret is the raw session token, so the MK
# is wrapped under a key derived from it and stored on the session row.


def _session_key(raw_token: str) -> bytes:
    return hashlib.sha256(b"masa-vault-session:" + raw_token.encode()).digest()


def wrap_for_session(mk: bytes, raw_token: str) -> str:
    """Wrap the master key under the session token (for sessions.vault_wrap)."""
    nonce = secrets.token_bytes(_NONCE_BYTES)
    ct = AESGCM(_session_key(raw_token)).encrypt(nonce, mk, None)
    return json.dumps({"v": 1, "nonce": _b64(nonce), "ct": _b64(ct)})


def unwrap_from_session(wrap: str, raw_token: str) -> bytes | None:
    """Recover the master key from a session's ``vault_wrap``. None on any
    failure - never raises."""
    try:
        data = json.loads(wrap)
        return AESGCM(_session_key(raw_token)).decrypt(
            _unb64(data["nonce"]), _unb64(data["ct"]), None
        )
    except Exception:
        return None
