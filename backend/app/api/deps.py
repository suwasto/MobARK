"""M9.1 shared API dependencies.

``get_current_user`` is the ONE guard every guarded router mounts
(``main.py`` adds it as a router-level dependency to scans/models/search;
health + auth stay open - owner decision 7). It also publishes the caller
into ``request_ctx.current_user_id`` so the store factories resolve the
per-user model/search backend files (decision 3).

``require_scan_access`` is the single ownership check every scan-keyed
route passes through (decision 2/6): 404 - not 403 - for unknown OR
foreign scans, so an unowned scan reads exactly like a nonexistent one
(no existence leak). Everything downstream of a scan (findings, chats,
edits, builds, report caches) keys off the scan row, so this one check at
the API boundary isolates it all.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.auth import sessions
from app.auth.security import SESSION_COOKIE
from app.auth.vault import unwrap_from_session
from app.config import settings
from app.db import get_db
from app.models import Scan, User
from app.request_ctx import current_master_key, current_user_id

DbSession = Annotated[Session, Depends(get_db)]


async def get_current_user(request: Request, db: DbSession) -> User | None:
    """Resolve the session cookie to its user; 401 without a valid session.

    Publishes the user id into ``request_ctx.current_user_id`` for the
    per-user store resolution (always set - None in auth-off mode - so the
    next request can never read a stale value), and the session's unwrapped
    vault master key into ``request_ctx.current_master_key`` (None when the
    session has no vault wrap - OAuth users who haven't unlocked, or
    auth-off mode).

    Auth-off mode (``MASA_AUTH_ENABLED=0``) returns None - the dev/CI
    parity mode where every guarded route behaves exactly as before M9.1
    (no session, no cookie, no checks, system store).
    """
    if not settings.auth_enabled:
        current_user_id.set(None)
        current_master_key.set(None)
        return None
    raw_token = request.cookies.get(SESSION_COOKIE)
    user, row = sessions.user_from_token(
        db,
        raw_token,
        session_days=settings.session_days,
        with_row=True,
    )
    if user is None:
        raise HTTPException(status_code=401, detail="authentication required")
    current_user_id.set(user.id)
    current_master_key.set(
        unwrap_from_session(row.vault_wrap, raw_token)
        if row is not None and row.vault_wrap
        else None
    )
    return user


CurrentUser = Annotated[User | None, Depends(get_current_user)]


def require_scan_access(db: DbSession, scan_id: int, user_id: int | None) -> Scan:
    """The scan-ownership gate: 404 for unknown OR foreign scans.

    Auth-off mode (``user_id`` is None) keeps today's open behavior - every
    scan is readable. Auth-on mode requires ``scan.user_id == user_id``;
    a NULL-owner (legacy/CLI) scan is unowned and reads as 404 until an
    admin claims it.
    """
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    if settings.auth_enabled and (user_id is None or scan.user_id != user_id):
        raise HTTPException(status_code=404, detail="scan not found")
    return scan
