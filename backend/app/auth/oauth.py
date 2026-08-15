"""M9.1 OAuth (Phase B): GitHub + Google authorization-code flows.

httpx only (owner decision 4 - it is already a runtime dep since M3; no new
rows in the license audit). One registry, two flows:

- ``github``: ``state`` only (no PKCE - GitHub does not support it on the
  code exchange); profile is ``GET /user`` (``read:user`` + ``user:email``
  scopes; ``email`` may be null for accounts with no public email).
- ``google``: ``state`` + PKCE (S256 code challenge) with an
  ``email_verified`` gate - a Google account whose email is not verified is
  rejected at the callback.

The ``state`` (and the PKCE ``code_verifier``) travel in a SHORT-LIVED
HttpOnly cookie scoped to the callback path (``/api/v1/auth/oauth/<provider>``)
so the callback can validate the round-trip and JS can never read them.
Every upstream failure raises ``OAuthError`` - the callback route catches it
and redirects to ``/login?error=...`` (never a 500, never a crash).
"""
from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx

from app.config import settings

GITHUB_AUTHORIZE = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN = "https://github.com/login/oauth/access_token"
GITHUB_PROFILE = "https://api.github.com/user"

GOOGLE_AUTHORIZE = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO = "https://openidconnect.googleapis.com/v1/userinfo"

_HTTP_TIMEOUT = 10.0


@dataclass(frozen=True)
class ProviderSpec:
    id: str
    authorize_url: str
    token_url: str
    profile_url: str
    scopes: tuple[str, ...]
    # google: state + PKCE (S256); github: state only.
    pkce: bool
    # google: the profile field that gates sign-in (must be true).
    email_verified_field: str | None


PROVIDERS: dict[str, ProviderSpec] = {
    "github": ProviderSpec(
        id="github",
        authorize_url=GITHUB_AUTHORIZE,
        token_url=GITHUB_TOKEN,
        profile_url=GITHUB_PROFILE,
        scopes=("read:user", "user:email"),
        pkce=False,
        email_verified_field=None,
    ),
    "google": ProviderSpec(
        id="google",
        authorize_url=GOOGLE_AUTHORIZE,
        token_url=GOOGLE_TOKEN,
        profile_url=GOOGLE_USERINFO,
        scopes=("openid", "email", "profile"),
        pkce=True,
        email_verified_field="email_verified",
    ),
}


class OAuthError(Exception):
    """Any upstream OAuth failure (unconfigured, unreachable, bad token,
    bad profile). The callback catches it and redirects to /login?error=..."""


# ---- configuration ---------------------------------------------------------


def is_configured(provider_id: str) -> bool:
    """A provider is configured only when BOTH its client id and secret are
    set (owner decision 1 - no config, no button, no broken flow)."""
    if provider_id not in PROVIDERS:
        return False
    if provider_id == "github":
        return bool(settings.github_client_id and settings.github_client_secret)
    if provider_id == "google":
        return bool(settings.google_client_id and settings.google_client_secret)
    return False


def client_credentials(provider_id: str) -> tuple[str | None, str | None]:
    if provider_id == "github":
        return settings.github_client_id, settings.github_client_secret
    return settings.google_client_id, settings.google_client_secret


def redirect_uri(provider_id: str) -> str:
    """The OAuth redirect_uri - derived ONLY from ``MOBARK_PUBLIC_BASE_URL``,
    never from the request (an attacker cannot redirect the flow to their
    own origin by tampering with query params or the Host header)."""
    return f"{settings.public_base_url.rstrip('/')}/api/v1/auth/oauth/{provider_id}/callback"


# ---- PKCE + state ----------------------------------------------------------


def new_state() -> str:
    return secrets.token_urlsafe(32)


def new_code_verifier() -> str:
    return secrets.token_urlsafe(32)


def code_challenge(verifier: str) -> str:
    """S256 PKCE challenge: base64url(SHA256(verifier)), unpadded."""
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


# ---- the provider redirect -------------------------------------------------


def build_authorize_url(
    provider_id: str, *, state: str, code_verifier: str | None = None
) -> str:
    """The browser-facing authorize URL for ``start``. PKCE params are added
    for providers that use them (google)."""
    spec = PROVIDERS[provider_id]
    client_id, _secret = client_credentials(provider_id)
    if not client_id:
        raise OAuthError(f"{provider_id} is not configured - set the client id/secret in env")
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri(provider_id),
        "response_type": "code",
        "scope": " ".join(spec.scopes),
        "state": state,
    }
    if code_verifier is not None:
        params["code_challenge"] = code_challenge(code_verifier)
        params["code_challenge_method"] = "S256"
    return f"{spec.authorize_url}?{urlencode(params)}"


# ---- the code exchange -----------------------------------------------------


def exchange_code(
    provider_id: str, *, code: str, code_verifier: str | None = None
) -> str:
    """POST the authorization code for an access token; returns the token.
    Raises ``OAuthError`` on any upstream failure (never raises httpx)."""
    spec = PROVIDERS[provider_id]
    client_id, client_secret = client_credentials(provider_id)
    if not client_id or not client_secret:
        raise OAuthError(f"{provider_id} is not configured - set the client id/secret in env")
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "redirect_uri": redirect_uri(provider_id),
        "grant_type": "authorization_code",
    }
    if code_verifier is not None:
        data["code_verifier"] = code_verifier
    try:
        resp = httpx.post(
            spec.token_url,
            data=data,
            headers={"Accept": "application/json"},  # GitHub returns form-encoded by default
            timeout=_HTTP_TIMEOUT,
        )
    except httpx.HTTPError as exc:
        raise OAuthError(f"{provider_id} token exchange unreachable: {exc}") from exc
    if resp.status_code != 200:
        raise OAuthError(f"{provider_id} token exchange failed (HTTP {resp.status_code})")
    try:
        payload = resp.json()
    except ValueError as exc:
        raise OAuthError(f"{provider_id} token exchange returned non-JSON") from exc
    access_token = payload.get("access_token")
    if not access_token:
        raise OAuthError(f"{provider_id} token exchange returned no access_token")
    return access_token


# ---- the profile -----------------------------------------------------------


def fetch_profile(provider_id: str, access_token: str) -> dict:
    """GET the provider's profile endpoint with the Bearer token. Raises
    ``OAuthError`` on any upstream failure."""
    spec = PROVIDERS[provider_id]
    try:
        resp = httpx.get(
            spec.profile_url,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            },
            timeout=_HTTP_TIMEOUT,
        )
    except httpx.HTTPError as exc:
        raise OAuthError(f"{provider_id} profile fetch unreachable: {exc}") from exc
    if resp.status_code != 200:
        raise OAuthError(f"{provider_id} profile fetch failed (HTTP {resp.status_code})")
    try:
        return resp.json()
    except ValueError as exc:
        raise OAuthError(f"{provider_id} profile fetch returned non-JSON") from exc


@dataclass(frozen=True)
class OAuthProfile:
    provider_id: str
    oauth_id: str
    email: str | None
    email_verified: bool
    preferred_username: str | None


def normalize_profile(provider_id: str, raw: dict) -> OAuthProfile:
    """Map a provider's raw profile JSON to the canonical shape. For google,
    ``email_verified`` must be exactly True (the gate); github has no gate
    and its email may be null (no public email) - linking then relies on
    the provider+oauth_id match alone."""
    if provider_id == "github":
        return OAuthProfile(
            provider_id=provider_id,
            oauth_id=str(raw.get("id", "")).strip(),
            email=(raw.get("email") or "").strip() or None,
            email_verified=True,
            preferred_username=(raw.get("login") or "").strip() or None,
        )
    return OAuthProfile(
        provider_id=provider_id,
        oauth_id=str(raw.get("sub", "")).strip(),
        email=(raw.get("email") or "").strip() or None,
        email_verified=raw.get("email_verified") is True,
        preferred_username=(raw.get("name") or "").strip() or None,
    )
