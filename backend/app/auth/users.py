"""M9.1 user store - create/find + the legacy ownership claim.

``claim_unowned`` implements owner decision 5: the FIRST registered user is
the instance admin AND automatically adopts every legacy unowned scan
(``scans.user_id IS NULL``) - fresh installs have none; existing
dev/volume DBs (and auth-off scans) get claimed on first registration. It
is transactional and idempotent: it only ever touches NULL-owner rows, so
running it twice (or racing two registrations - the DB layer still allows
it) can never double-assign. Phase C adds an admin-callable claim endpoint
so post-first-user CLI scans (``cli scan --user``) can be adopted.
"""
from __future__ import annotations

import re

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session as DbSession

from app.models import Scan, User


def create_user(
    db: DbSession,
    *,
    username: str,
    password_hash: str | None = None,
    email: str | None = None,
    auth_provider: str = "local",
    oauth_id: str | None = None,
    is_admin: bool = False,
) -> User:
    """Insert a user. Raises sqlalchemy IntegrityError on duplicate
    username/email - the routes map it to a clean 400/409."""
    user = User(
        username=username,
        password_hash=password_hash,
        email=email or None,
        auth_provider=auth_provider,
        oauth_id=oauth_id,
        is_admin=is_admin,
        is_active=True,
    )
    db.add(user)
    db.commit()
    return user


def count_users(db: DbSession) -> int:
    """Total registered users - register uses it for the first-user check."""
    return db.scalar(select(func.count()).select_from(User)) or 0


def find_by_username(db: DbSession, username: str) -> User | None:
    return db.scalar(select(User).where(User.username == username))


def find_by_email(db: DbSession, email: str) -> User | None:
    return db.scalar(select(User).where(User.email == email))


def find_by_login(db: DbSession, login: str) -> User | None:
    """Login accepts username OR email (one lookup, no enumeration)."""
    user = find_by_username(db, login)
    if user is None:
        user = find_by_email(db, login)
    return user


def find_or_create_oauth_user(
    db: DbSession,
    *,
    provider_id: str,
    oauth_id: str,
    email: str | None,
    preferred_username: str | None,
) -> User:
    """Resolve an OAuth identity to a user (the callback's account step).

    Resolution order (owner decision, Phase B plan):
    1. provider + ``oauth_id`` (the identity's own stable key);
    2. verified ``email`` - LINKS the identity to an existing account
       (a local user who already registered with that email becomes the
       same account, gaining the OAuth sign-in);
    3. create a fresh user.

    The FIRST user overall (OAuth or local) is the admin and claims legacy
    unowned scans (owner decision 5 - the same rule as register). Username
    derives from the profile (login / name) or the email local part, made
    unique with a numeric suffix on collision. Note: a user row holds ONE
    oauth binding (``auth_provider`` + ``oauth_id``); signing in with a
    second provider re-binds it (v1 scope - see the M9.1 plan's open items).
    """
    user = db.scalar(
        select(User).where(
            User.auth_provider == provider_id, User.oauth_id == oauth_id
        )
    )
    if user is None and email:
        user = find_by_email(db, email)
    if user is None:
        first = count_users(db) == 0
        user = create_user(
            db,
            username=_unique_username(db, preferred_username or email or provider_id),
            email=email,
            auth_provider=provider_id,
            oauth_id=oauth_id,
            is_admin=first,
        )
        if first:
            claim_unowned(db, user)
    else:
        # (Re)bind this provider identity onto the existing account.
        user.auth_provider = provider_id
        user.oauth_id = oauth_id
        if email and not user.email:
            user.email = email
        db.commit()
    return user


def _unique_username(db: DbSession, base: str) -> str:
    """A username-safe derivation of ``base`` (profile login/name, or the
    EMAIL LOCAL PART for google-style profiles without a login), made unique
    with a numeric suffix when taken."""
    if "@" in (base or ""):
        base = base.split("@", 1)[0]
    clean = re.sub(r"[^A-Za-z0-9_.-]+", "", base or "")[:32] or "user"
    candidate = clean
    n = 0
    while find_by_username(db, candidate) is not None:
        n += 1
        candidate = f"{clean}{n}"
    return candidate


def claim_unowned(db: DbSession, user: User) -> int:
    """Adopt every scan with a NULL ``user_id`` (legacy rows). Transactional
    (single UPDATE + commit) and idempotent - NULL-owner rows only, so a
    re-run or a concurrent duplicate is a no-op. Returns the count claimed.
    """
    claimed = db.execute(
        update(Scan).where(Scan.user_id.is_(None)).values(user_id=user.id)
    )
    db.commit()
    return claimed.rowcount or 0
