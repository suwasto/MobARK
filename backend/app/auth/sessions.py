"""M9.1 session store - create/lookup/revoke over the ``sessions`` table.

The cookie carries the opaque raw token; only its SHA-256 digest is
queried here. ``expires_at`` is a **sliding** window (owner decision 5):
every successful lookup extends it by ``session_days``, so an active
session never expires mid-work while a dormant one dies after the window.
Expired rows are lazily deleted on create/login (no background job needed
at this scale).
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session as DbSession

from app.auth.security import new_session_token, token_hash
from app.models import Session as AuthSession
from app.models import User, utcnow


def _now() -> datetime:
    return datetime.now(UTC)


def create_session(
    db: DbSession, user: User, *, session_days: int, now: datetime | None = None
) -> tuple[str, AuthSession]:
    """Create a session row for ``user``; returns ``(raw_token, row)``.

    ``raw_token`` goes into the HttpOnly cookie; only its digest is stored.
    """
    now = now or _now()
    raw_token, digest = new_session_token()
    row = AuthSession(
        user_id=user.id,
        token_hash=digest,
        created_at=now,
        expires_at=now + timedelta(days=session_days),
    )
    db.add(row)
    db.commit()
    return raw_token, row


def user_from_token(
    db: DbSession,
    raw_token: str | None,
    *,
    session_days: int,
    now: datetime | None = None,
    with_row: bool = False,
) -> User | None | tuple[User | None, AuthSession | None]:
    """Resolve a raw cookie token to its user, or None.

    None covers: no/malformed token, unknown digest, an EXPIRED session,
    or a deactivated user (``is_active=False`` -> 401). A valid session
    slides its ``expires_at`` forward (the sliding window) and returns the
    user. Malformed tokens (anything that doesn't look like a
    ``token_urlsafe`` string) are rejected before the hash query.

    ``with_row=True`` also returns the session row (``(user, row)``) so
    the vault guard can read ``row.vault_wrap`` without a second query.
    """
    if not raw_token or not _plausible_token(raw_token):
        return (None, None) if with_row else None
    now = now or _now()
    row = db.scalar(
        select(AuthSession).where(AuthSession.token_hash == token_hash(raw_token))
    )
    if row is None:
        return (None, None) if with_row else None
    # SQLite round-trips DateTime as naive - compare both sides naive UTC.
    if row.expires_at.replace(tzinfo=None) <= now.replace(tzinfo=None):
        db.delete(row)  # expired: revoke on sight, keep the table tidy
        db.commit()
        return (None, None) if with_row else None
    user = db.get(User, row.user_id)
    if user is None or not user.is_active:
        return (None, None) if with_row else None
    # Sliding expiry: refresh on use so active sessions don't die mid-work.
    new_expiry = now + timedelta(days=session_days)
    if row.expires_at.replace(tzinfo=None) != new_expiry.replace(tzinfo=None):
        row.expires_at = new_expiry
        db.commit()
    return (user, row) if with_row else user


def set_vault_wrap(db: DbSession, raw_token: str | None, wrap: str) -> bool:
    """Persist the vault wrap on the session behind a raw token (the
    OAuth unlock endpoint - local users get the wrap at login instead).
    Returns True when a session row was updated."""
    if not raw_token or not _plausible_token(raw_token):
        return False
    row = db.scalar(
        select(AuthSession).where(AuthSession.token_hash == token_hash(raw_token))
    )
    if row is None:
        return False
    row.vault_wrap = wrap
    db.commit()
    return True


def revoke_session(db: DbSession, raw_token: str | None) -> bool:
    """Delete the session row for a raw token (logout); True if one was
    revoked. Idempotent - an already-revoked or unknown token returns False
    without error."""
    if not raw_token or not _plausible_token(raw_token):
        return False
    result = db.execute(
        delete(AuthSession).where(AuthSession.token_hash == token_hash(raw_token))
    )
    db.commit()
    return result.rowcount > 0


def revoke_user_sessions(db: DbSession, user_id: int) -> int:
    """Delete every session row for a user (password reset / deactivation).
    Returns the count revoked. The CLI password-reset escape hatch uses this
    so a stolen cookie dies with the old password."""
    result = db.execute(delete(AuthSession).where(AuthSession.user_id == user_id))
    db.commit()
    return result.rowcount or 0


def delete_expired(db: DbSession, now: datetime | None = None) -> int:
    """Housekeeping: drop expired session rows (called opportunistically on
    register/login so the table never grows unbounded). Returns the count
    removed."""
    now = now or _now()
    result = db.execute(delete(AuthSession).where(AuthSession.expires_at <= now))
    db.commit()
    return result.rowcount or 0


def _plausible_token(token: str) -> bool:
    """token_urlsafe output is [A-Za-z0-9_-]{43}; reject anything else so a
    garbage cookie never even reaches the hashing/query path."""
    if len(token) != 43:
        return False
    return all(c.isalnum() or c in "_-" for c in token)


# The model's utcnow is exported for callers that want a single clock.
__all__ = [
    "create_session",
    "user_from_token",
    "revoke_session",
    "revoke_user_sessions",
    "delete_expired",
    "utcnow",
]
