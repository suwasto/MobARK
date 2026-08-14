"""M9.1 auth primitives - password hashing + opaque session tokens.

Zero new runtime dependencies (owner decision 4): stdlib ``hashlib`` /
``hmac`` / ``secrets`` only.

Passwords: ``hashlib.scrypt`` with a per-user random salt, encoded as
``scrypt$n$r$p$salt_hex$hash_hex``. The cost parameters are persisted in
the hash itself so a future cost bump can verify old hashes (and re-hash
on login) without a migration. Verification is constant-time
(``hmac.compare_digest``) and fails cleanly on malformed/tampered input.

Sessions: opaque ``secrets.token_urlsafe(32)`` raw tokens go in the cookie;
ONLY their SHA-256 digest is stored in the ``sessions`` table - a DB leak
exposes verifier rows, never usable tokens (and the raw token has 256 bits
of entropy, so the digest gains an attacker nothing).
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

# scrypt cost parameters (OWASP-style memory-hard defaults for an
# interactive login: 16 MiB, n=2^14).
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SALT_BYTES = 16
_DK_BYTES = 32

# The cookie name is the only magic string the auth surface and the
# frontend share.
SESSION_COOKIE = "masa_session"


def hash_password(password: str) -> str:
    """Hash a password with a fresh random salt -> ``scrypt$n$r$p$salt$hash``."""
    salt = secrets.token_bytes(_SALT_BYTES)
    dk = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_DK_BYTES,
    )
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt.hex()}${dk.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    """Constant-time password check against a stored hash.

    Returns False (never raises) for malformed or unknown-scheme hashes so
    a corrupt DB row degrades to a login failure, not a 500.
    """
    try:
        scheme, n_s, r_s, p_s, salt_hex, hash_hex = encoded.split("$")
        if scheme != "scrypt":
            return False
        n, r, p = int(n_s), int(r_s), int(p_s)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except (ValueError, AttributeError):
        return False
    if n < 2 or r < 1 or p < 1:
        return False  # absurd cost params = tampered hash; never verify
    try:
        dk = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=len(expected),
        )
    except ValueError:
        return False
    return hmac.compare_digest(dk, expected)


def new_session_token() -> tuple[str, str]:
    """Generate a session: ``(raw_token, sha256_digest)``.

    The raw token goes in the HttpOnly cookie; the digest is what the
    ``sessions`` table stores. The raw token is never persisted anywhere.
    """
    token = secrets.token_urlsafe(32)
    return token, token_hash(token)


def token_hash(token: str) -> str:
    """SHA-256 hex digest of a raw session token (the DB verifier)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
