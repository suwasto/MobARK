"""M9.1 auth routes - register / login / logout / me / providers.

These stay OPEN (no ``get_current_user``): they are how a user BECOMES
authenticated. Everything else under /api/v1 sits behind the guard
(``app/api/deps.py::get_current_user`` via router-level dependencies in
``main.py``); health + auth are the only unauthenticated routers.

Error posture (a security tool's baseline): login failures are a single
message - ``invalid username or password`` - for unknown user, wrong
password, and disabled account alike (no user enumeration). Register
failures are specific (the username/email is the caller's own input).

OAuth (Phase B) mounts ``/auth/oauth/{provider}/start`` + ``callback`` on
this router. Phase A ships local only; ``/auth/providers`` reports exactly
what is configured so the UI never renders a broken button.
"""
from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.auth import oauth, sessions, users, vault
from app.auth.security import SESSION_COOKIE, hash_password, verify_password
from app.auth.sessions import delete_expired
from app.config import settings
from app.db import get_db
from app.models import User
from app.request_ctx import current_master_key
from app.schemas import (
    AuthResponse,
    LoginRequest,
    ProvidersResponse,
    RegisterRequest,
    UserRead,
    VaultPassphraseRequest,
)

router = APIRouter(prefix="/auth", tags=["auth"])

DbSession = Annotated[Session, Depends(get_db)]


def _set_session_cookie(response: Response, raw_token: str) -> None:
    """The HttpOnly + SameSite=Lax session cookie. ``Secure`` only when the
    app is served over TLS (``MOBARK_COOKIE_SECURE=1``) - same-origin SPA +
    JSON bodies + the Origin check (Phase A middleware) cover the local
    HTTP case without it."""
    response.set_cookie(
        SESSION_COOKIE,
        raw_token,
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        max_age=settings.session_days * 86400,
    )


def _start_session_with_vault(db: DbSession, user: User, mk: bytes | None) -> str:
    """Create a session and, when a master key is available, wrap it under
    the raw token onto the session row (the vault guard recovers it per
    request - see ``deps.get_current_user``). Returns the raw token for the
    cookie. Local users pass the MK (unlocked at login/register); the OAuth
    callback passes None (no password) - the session stays vault-locked
    until the user unlocks via POST /auth/vault/unlock."""
    raw_token, row = sessions.create_session(
        db, user, session_days=settings.session_days
    )
    if mk is not None:
        row.vault_wrap = vault.wrap_for_session(mk, raw_token)
        db.commit()
    return raw_token


def _clear_stored_keys(user_id: int) -> None:
    """Drop every stored API key (model + search) for a user whose vault was
    destroyed - undecryptable blobs must not linger behind
    ``has_api_key``."""
    from app.model.backends import BackendStore
    from app.search.backends import SearchStore

    BackendStore(settings.data_dir, user_id=user_id).clear_api_keys()
    SearchStore(settings.data_dir, user_id=user_id).clear_api_keys()


def _require_auth_enabled() -> None:
    """Auth-off parity mode: the register/login surface is inert - a fresh
    ``MOBARK_AUTH_ENABLED=0`` install is fully open by design (dev/CI), and a
    login screen with no guard behind it would just confuse."""
    if not settings.auth_enabled:
        raise HTTPException(
            status_code=400,
            detail="authentication is disabled (MOBARK_AUTH_ENABLED=0)",
        )


@router.post("/register", response_model=AuthResponse, status_code=201)
def register(payload: RegisterRequest, db: DbSession, response: Response) -> AuthResponse:
    """Create an account and start a session (cookie in Set-Cookie).

    The FIRST registered user is the instance admin and auto-claims every
    legacy unowned scan (transactional, idempotent - owner decision 5).
    400 invalid input (pydantic) / auth disabled · 409 username or email
    already taken (never leak which one).
    """
    _require_auth_enabled()
    delete_expired(db)  # opportunistic housekeeping on every entry point
    username = payload.username.strip()
    email = (payload.email or "").strip() or None
    if users.find_by_username(db, username) is not None or (
        email and users.find_by_email(db, email) is not None
    ):
        raise HTTPException(status_code=409, detail="username or email already registered")
    # Phase E hardening: the first-user check is read-then-write, so two
    # concurrent registrations can BOTH read zero users. The DB backstop
    # (partial unique index on is_admin, migration 0014) lets exactly ONE
    # admin row commit; the loser re-derives here as a non-admin instead of
    # 500ing or - worse - silently minting a second admin.
    try:
        first = users.count_users(db) == 0
        user = users.create_user(
            db,
            username=username,
            email=email,
            password_hash=hash_password(payload.password),
            is_admin=first,
        )
    except IntegrityError:
        db.rollback()
        # The race loser (or a duplicate that slipped past the pre-check).
        # Re-check duplicates so the error is honest, then join as a regular
        # non-admin user - the first user is already taken.
        if users.find_by_username(db, username) is not None or (
            email and users.find_by_email(db, email) is not None
        ):
            raise HTTPException(
                status_code=409, detail="username or email already registered"
            ) from None
        user = users.create_user(
            db,
            username=username,
            email=email,
            password_hash=hash_password(payload.password),
            is_admin=False,
        )
        first = False
    if first:
        users.claim_unowned(db, user)
    # M9.1 vault: a fresh account starts with a fresh master key wrapped
    # under the chosen password (there are no keys to protect yet).
    mk = vault.create_vault(user.id, payload.password)
    raw_token = _start_session_with_vault(db, user, mk)
    _set_session_cookie(response, raw_token)
    return AuthResponse(user=user)


@router.post("/login", response_model=AuthResponse)
def login(payload: LoginRequest, db: DbSession, response: Response) -> AuthResponse:
    """Start a session (cookie in Set-Cookie). Username OR email.

    One message for every failure - unknown user, wrong password, disabled
    account, OAuth-only account with no local password - so a login probe
    cannot distinguish existing accounts (no user enumeration).
    """
    _require_auth_enabled()
    delete_expired(db)
    user = users.find_by_login(db, payload.username.strip())
    valid = (
        user is not None
        and user.is_active
        and user.password_hash is not None
        and verify_password(payload.password, user.password_hash)
    )
    if not valid:
        raise HTTPException(status_code=401, detail="invalid username or password")
    # M9.1 vault: the password IS the KEK - unwrap the master key (creating
    # the vault on a fresh/self-healing login), then wrap it under the
    # session token so every guarded request can recover it from the cookie.
    mk = vault.unlock_vault(user.id, payload.password)
    if mk is None:
        mk = vault.create_vault(user.id, payload.password)
    raw_token = _start_session_with_vault(db, user, mk)
    _set_session_cookie(response, raw_token)
    return AuthResponse(user=user)


@router.post("/logout", status_code=204)
def logout(request: Request, db: DbSession) -> Response:
    """Revoke the exact session row behind this cookie + clear the cookie.
    Idempotent: logging out twice (or with an already-expired session) is a
    204 no-op, never an error."""
    sessions.revoke_session(db, request.cookies.get(SESSION_COOKIE))
    response = Response(status_code=204)
    response.delete_cookie(SESSION_COOKIE)
    return response


@router.get("/me", response_model=UserRead | None)
def me(current_user: Annotated[User | None, Depends(get_current_user)]) -> User | None:
    """The session cookie's user (boot check for the frontend).

    401 no/expired session · 200 ``null`` when auth is disabled (the
    frontend keys off ``/auth/providers.auth_enabled`` to skip login).

    ``vault_locked`` is true when THIS session cannot access the vault: an
    OAuth-only account (no password) whose session has no unlocked vault
    wrap - the Settings UI then offers the vault passphrase form. Local
    users unlock at login, so it is always false for them.
    """
    if current_user is None:
        return None
    locked = current_user.password_hash is None and current_master_key.get() is None
    return UserRead.model_validate(current_user).model_copy(
        update={"vault_locked": locked}
    )


# ---- M9.1 vault (OAuth-only accounts) ----------------------------------------
# Local users unlock the vault at login (the password is the KEK). OAuth
# users have no password, so they set a dedicated vault passphrase and enter
# it once per session: unwrap the master key from key_wrap.json, wrap it
# under the CURRENT session token, and the guard recovers it per request.


def _require_vaultable(current_user: User | None) -> None:
    if current_user is None:
        raise HTTPException(status_code=401, detail="authentication required")
    if current_user.password_hash is not None:
        raise HTTPException(
            status_code=400,
            detail="your account password already unlocks the vault - "
            "a separate passphrase is only for OAuth accounts",
        )


@router.post("/vault/unlock")
def vault_unlock(
    payload: VaultPassphraseRequest,
    request: Request,
    db: DbSession,
    current_user: Annotated[User | None, Depends(get_current_user)],
) -> dict:
    """Unlock the vault with the vault passphrase (OAuth accounts only).

    First use CREATES the vault with this passphrase (there is nothing to
    unlock yet); later uses verify it (AES-GCM rejects a wrong passphrase
    with 401 - the vault is NEVER recreated over an existing one, which
    would silently orphan the stored keys). On success the master key is
    wrapped under the current session token and the session row is updated,
    so every subsequent guarded request recovers it from the cookie - no
    per-request passphrase, no persistence of the key itself.
    """
    _require_vaultable(current_user)
    if vault.has_vault(current_user.id):
        mk = vault.unlock_vault(current_user.id, payload.passphrase)
        if mk is None:
            raise HTTPException(status_code=401, detail="wrong vault passphrase")
    else:
        mk = vault.create_vault(current_user.id, payload.passphrase)
    raw_token = request.cookies.get(SESSION_COOKIE)
    if not sessions.set_vault_wrap(
        db, raw_token, vault.wrap_for_session(mk, raw_token or "")
    ):
        raise HTTPException(status_code=401, detail="authentication required")
    current_master_key.set(mk)
    return {"unlocked": True}


@router.post("/vault/reset")
def vault_reset(
    db: DbSession,
    current_user: Annotated[User | None, Depends(get_current_user)],
) -> dict:
    """Forgot the vault passphrase? Destroy the vault and clear the stored
    API keys - the recovery path (there is no way to recover keys wrapped
    under a lost passphrase). The user re-enters their keys after setting a
    fresh passphrase.
    """
    _require_vaultable(current_user)
    vault.destroy_vault(current_user.id)
    _clear_stored_keys(current_user.id)
    return {"reset": True}


@router.post("/claim")
def claim_unowned(
    current_user: Annotated[User | None, Depends(get_current_user)], db: DbSession
) -> dict:
    """Adopt every NULL-owner scan into the caller's account - ADMIN ONLY
    (Phase C audit gap 1). This is the runtime path for unowned rows created
    AFTER the first-user legacy claim, e.g. a host-operator CLI scan
    (``cli scan --user`` or without). Idempotent: only NULL-owner rows are
    touched, so re-running (or racing) can never double-assign. 401 no
    session · 403 not admin.
    """
    if not settings.auth_enabled:
        raise HTTPException(status_code=400, detail="authentication is disabled")
    if current_user is None or not current_user.is_admin:
        raise HTTPException(status_code=403, detail="admin privileges required")
    claimed = users.claim_unowned(db, current_user)
    return {"claimed": claimed}


@router.get("/providers", response_model=ProvidersResponse)
def providers() -> ProvidersResponse:
    """Which sign-in methods are configured. ``local`` always; ``github`` /
    ``google`` appear only when their client id + secret env vars are set
    (owner decision 1 - the login page renders a button only for a
    configured provider; no config, no button, never a broken flow)."""
    configured = ["local"]
    configured += [pid for pid in ("github", "google") if oauth.is_configured(pid)]
    return ProvidersResponse(auth_enabled=settings.auth_enabled, providers=configured)


# ---- OAuth (Phase B): start + callback --------------------------------------
# The start URL redirects the browser to the provider; the state (and the
# PKCE verifier for google) ride in a SHORT-LIVED HttpOnly cookie scoped to
# the callback path. The callback validates the round-trip, exchanges the
# code, resolves the identity (find-or-create + verified-email linking),
# starts a session, and lands on "/" - every failure is a redirect to
# /login?error=... (never a 500, never a crash).


_OAUTH_STATE_TTL = 600  # seconds: long enough for the provider round-trip


def _oauth_cookie_name(provider: str) -> str:
    return f"mobark_oauth_{provider}"


def _read_oauth_cookie(request: Request, provider: str) -> dict | None:
    """The state payload the start route set - None on missing/malformed
    (the callback then rejects the round-trip)."""
    raw = request.cookies.get(_oauth_cookie_name(provider))
    if not raw:
        return None
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _oauth_fail(key: str) -> RedirectResponse:
    """Every OAuth failure funnels through here: a redirect to the login
    page with a machine-readable error key (the frontend maps it to copy)."""
    return RedirectResponse(f"/login?error={key}", status_code=302)


@router.get("/oauth/{provider}/start")
def oauth_start(provider: str, response: Response) -> RedirectResponse:
    """Send the browser to the provider's authorize URL.

    404 for an unknown OR unconfigured provider (``MOBARK_GITHUB_CLIENT_ID/
    SECRET`` / ``MOBARK_GOOGLE_CLIENT_ID/SECRET`` unset) - the login page
    only renders buttons for configured providers, so this should never be
    hit from the UI; a raw client gets the configure-in-env detail.
    """
    if provider not in oauth.PROVIDERS or not oauth.is_configured(provider):
        raise HTTPException(
            status_code=404,
            detail=f"oauth provider {provider!r} is not configured - set the "
            "client id/secret env vars (MOBARK_<PROVIDER>_CLIENT_ID/SECRET)",
        )
    state = oauth.new_state()
    verifier = oauth.new_code_verifier() if oauth.PROVIDERS[provider].pkce else None
    url = oauth.build_authorize_url(provider, state=state, code_verifier=verifier)
    # The cookie must ride the RETURNED response - setting it on FastAPI's
    # injected ``response`` param is discarded when the return value is
    # already a Response.
    redirect = RedirectResponse(url, status_code=302)
    redirect.set_cookie(
        _oauth_cookie_name(provider),
        json.dumps({"state": state, "verifier": verifier}),
        httponly=True,
        samesite="lax",
        max_age=_OAUTH_STATE_TTL,
        path=f"/api/v1/auth/oauth/{provider}",
    )
    return redirect


@router.get("/oauth/{provider}/callback")
def oauth_callback(
    provider: str,
    db: DbSession,
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
) -> RedirectResponse:
    """The provider's redirect back - validate state, exchange the code,
    resolve the identity, start a session, land on "/".

    404 unknown provider. Every other failure - missing/mismatched state
    (CSRF), the user denying the flow (the provider's own ``error`` param),
    an upstream exchange/profile failure, an unverified Google email - is a
    302 to ``/login?error=...`` with a machine-readable key.
    """
    if provider not in oauth.PROVIDERS:
        raise HTTPException(status_code=404, detail=f"unknown oauth provider {provider!r}")
    if error:
        return _oauth_fail("access_denied")  # the user (or provider) declined
    payload = _read_oauth_cookie(request, provider)
    if not payload or payload.get("state") != state or not code:
        return _oauth_fail("invalid_state")
    try:
        token = oauth.exchange_code(
            provider, code=code, code_verifier=payload.get("verifier")
        )
        profile = oauth.normalize_profile(provider, oauth.fetch_profile(provider, token))
    except oauth.OAuthError:
        return _oauth_fail("oauth_failed")
    if oauth.PROVIDERS[provider].email_verified_field is not None and not profile.email_verified:
        return _oauth_fail("email_not_verified")
    user = users.find_or_create_oauth_user(
        db=db,
        provider_id=provider,
        oauth_id=profile.oauth_id,
        email=profile.email,
        preferred_username=profile.preferred_username,
    )
    # Same cookie-on-the-returned-response rule as ``start``: the session
    # cookie must ride the redirect, not the discarded injected response.
    # No vault wrap (no password) - the session starts vault-locked; the
    # user unlocks with their vault passphrase from Settings.
    raw_token = _start_session_with_vault(db, user, None)
    redirect = RedirectResponse("/", status_code=302)
    _set_session_cookie(redirect, raw_token)
    redirect.delete_cookie(_oauth_cookie_name(provider))
    return redirect
