"""M9.1 Phase B OAuth tests - GitHub + Google, httpx monkeypatched (the
M3/M7 discipline: every upstream call is faked, no network).

Covers: start URL shape (client_id / redirect_uri / state / PKCE), the
state+verifier cookie, the callback happy path per provider (token exchange
data + profile fetch), the google ``email_verified`` gate, state rejection
(CSRF), verified-email account linking, the first-OAuth-user admin + legacy
claim, provider-unreachable -> clean error redirect, and the redirect_uri
always deriving from ``MASA_PUBLIC_BASE_URL``.
"""
from __future__ import annotations

import json
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from sqlalchemy import func, select

import app.auth.oauth as oauth_mod
import app.config
from app.auth.security import hash_password
from app.auth.users import find_by_username
from app.models import Scan, User

GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_PROFILE_URL = "https://api.github.com/user"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"


@pytest.fixture()
def oauth_env(monkeypatch):
    """Both providers configured (the env-seeding precedent: a provider is
    visible only when its client id AND secret are set)."""
    monkeypatch.setattr(app.config.settings, "github_client_id", "gh_id")
    monkeypatch.setattr(app.config.settings, "github_client_secret", "gh_secret")
    monkeypatch.setattr(app.config.settings, "google_client_id", "gg_id")
    monkeypatch.setattr(app.config.settings, "google_client_secret", "gg_secret")
    monkeypatch.setattr(app.config.settings, "public_base_url", "http://masa.example")
    return None


def _install_fakes(
    monkeypatch,
    *,
    token_status: int = 200,
    token_payload: dict | None = None,
    profile: dict | None = None,
    profile_status: int = 200,
    post_exc: Exception | None = None,
    get_exc: Exception | None = None,
):
    """Fake httpx.post (token exchange) + httpx.get (profile fetch). Records
    the last calls for assertions; raises ``post_exc``/``get_exc`` to
    simulate an unreachable provider."""
    calls: dict = {"post": {}, "get": {}}

    def fake_post(url, **kwargs):
        calls["post"] = {"url": url, "data": kwargs.get("data"), "headers": kwargs.get("headers")}
        if post_exc is not None:
            raise post_exc
        if token_status != 200:
            return httpx.Response(token_status, text="{}")
        return httpx.Response(200, json=token_payload or {"access_token": "tok_123"})

    def fake_get(url, **kwargs):
        calls["get"] = {"url": url, "headers": kwargs.get("headers")}
        if get_exc is not None:
            raise get_exc
        if profile_status != 200:
            return httpx.Response(profile_status, text="{}")
        return httpx.Response(200, json=profile or {})

    monkeypatch.setattr(oauth_mod.httpx, "post", fake_post)
    monkeypatch.setattr(oauth_mod.httpx, "get", fake_get)
    return calls


def _start(client, provider: str):
    """Run the start route; returns (response, parsed query params, state).
    ``follow_redirects=False`` - Starlette's TestClient follows redirects by
    default, and these 302s point at real provider URLs."""
    r = client.get(f"/api/v1/auth/oauth/{provider}/start", follow_redirects=False)
    assert r.status_code == 302
    params = parse_qs(urlsplit(r.headers["location"]).query)
    return r, params, params["state"][0]


def _cookie_payload(response, provider: str) -> dict:
    """The state-cookie payload, parsed from the Set-Cookie header (the
    TestClient jar quotes/escapes the JSON value, so read the raw header)."""
    from http.cookies import SimpleCookie

    jar = SimpleCookie(response.headers["set-cookie"])
    return json.loads(jar[f"masa_oauth_{provider}"].value)


# ---- start: URL shape + state/PKCE cookie -----------------------------------


def test_start_github_url_shape_and_state_cookie(unauth_client, oauth_env):
    r, params, _state = _start(unauth_client, "github")
    assert params["client_id"] == ["gh_id"]
    assert params["response_type"] == ["code"]
    assert params["redirect_uri"] == [
        "http://masa.example/api/v1/auth/oauth/github/callback"
    ]
    assert "read:user" in params["scope"][0]
    # github: state only, NO PKCE
    assert "code_challenge" not in params
    cookie_header = r.headers["set-cookie"]
    assert "masa_oauth_github" in cookie_header
    assert "httponly" in cookie_header.lower()
    assert "path=/api/v1/auth/oauth/github" in cookie_header.lower()
    payload = _cookie_payload(r, "github")
    assert payload["state"] == _state
    assert "verifier" in payload  # present but unused by github


def test_start_google_includes_pkce(unauth_client, oauth_env):
    r, params, _state = _start(unauth_client, "google")
    assert params["client_id"] == ["gg_id"]
    assert params["redirect_uri"] == [
        "http://masa.example/api/v1/auth/oauth/google/callback"
    ]
    assert params["code_challenge_method"] == ["S256"]
    assert params["code_challenge"][0]
    payload = _cookie_payload(r, "google")
    assert payload["state"] == _state
    assert payload["verifier"]
    # The challenge must differ from the verifier (S256 digest, not the key).
    assert payload["verifier"] != params["code_challenge"][0]


def test_start_unconfigured_provider_404(unauth_client):
    # No client id/secret configured - the button would not render, and a
    # raw client gets a 404 with configure-in-env detail.
    r = unauth_client.get("/api/v1/auth/oauth/github/start")
    assert r.status_code == 404
    assert "not configured" in r.json()["detail"]


def test_start_unknown_provider_404(unauth_client, oauth_env):
    r = unauth_client.get("/api/v1/auth/oauth/gitlab/start")
    assert r.status_code == 404


def test_redirect_uri_derived_only_from_config(unauth_client, oauth_env):
    """The redirect_uri comes from MASA_PUBLIC_BASE_URL - the request cannot
    influence it (no user-supplied redirect param exists; the exchange posts
    the config-derived URI too)."""
    _start(unauth_client, "github")
    # A different Host on the request changes nothing.
    r2 = unauth_client.get(
        "/api/v1/auth/oauth/github/start",
        headers={"Host": "evil.example"},
        follow_redirects=False,
    )
    params = parse_qs(urlsplit(r2.headers["location"]).query)
    assert params["redirect_uri"] == [
        "http://masa.example/api/v1/auth/oauth/github/callback"
    ]


# ---- callback: github happy path --------------------------------------------


def test_callback_github_happy_path(
    unauth_client, oauth_env, monkeypatch, db_session_factory
):
    _r, _params, state = _start(unauth_client, "github")
    calls = _install_fakes(
        monkeypatch,
        profile={"id": 42, "login": "alice", "email": "alice@example.com"},
    )

    r = unauth_client.get(
        f"/api/v1/auth/oauth/github/callback?code=the-code&state={state}",
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert r.headers["location"] == "/"

    # Token exchange: correct endpoint + payload (config-derived redirect_uri).
    assert calls["post"]["url"] == GITHUB_TOKEN_URL
    data = calls["post"]["data"]
    assert data["code"] == "the-code"
    assert data["client_secret"] == "gh_secret"
    assert data["redirect_uri"] == "http://masa.example/api/v1/auth/oauth/github/callback"
    # Profile fetch: Bearer token on the /user endpoint.
    assert calls["get"]["url"] == GITHUB_PROFILE_URL
    assert calls["get"]["headers"]["Authorization"] == "Bearer tok_123"

    # The session cookie authenticates /auth/me as the created user.
    assert unauth_client.cookies.get("masa_session")
    me = unauth_client.get("/api/v1/auth/me")
    assert me.status_code == 200
    assert me.json()["username"] == "alice"
    with db_session_factory() as db:
        user = find_by_username(db, "alice")
        assert user.auth_provider == "github"
        assert user.oauth_id == "42"
        assert user.email == "alice@example.com"


# ---- callback: google happy path (PKCE + verified email) ---------------------


def test_callback_google_happy_path_with_pkce(
    unauth_client, oauth_env, monkeypatch, db_session_factory
):
    start_r, _params, state = _start(unauth_client, "google")
    verifier = _cookie_payload(start_r, "google")["verifier"]
    calls = _install_fakes(
        monkeypatch,
        profile={"sub": "g-1", "email": "bob@example.com", "email_verified": True},
    )

    r = unauth_client.get(
        f"/api/v1/auth/oauth/google/callback?code=the-code&state={state}",
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert r.headers["location"] == "/"

    # The PKCE verifier rides the token exchange.
    assert calls["post"]["url"] == GOOGLE_TOKEN_URL
    assert calls["post"]["data"]["code_verifier"] == verifier
    assert calls["get"]["url"] == GOOGLE_USERINFO_URL

    me = unauth_client.get("/api/v1/auth/me")
    assert me.json()["username"] == "bob"  # email local part
    with db_session_factory() as db:
        user = find_by_username(db, "bob")
        assert user.auth_provider == "google"
        assert user.oauth_id == "g-1"


def test_callback_google_unverified_email_rejected(
    unauth_client, oauth_env, monkeypatch, db_session_factory
):
    _r, _params, state = _start(unauth_client, "google")
    _install_fakes(
        monkeypatch,
        profile={"sub": "g-1", "email": "evil@example.com", "email_verified": False},
    )
    r = unauth_client.get(
        f"/api/v1/auth/oauth/google/callback?code=the-code&state={state}",
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert "error=email_not_verified" in r.headers["location"]
    with db_session_factory() as db:
        assert db.scalar(select(func.count()).select_from(User)) == 0  # no user created


# ---- state validation (CSRF) ------------------------------------------------


def test_callback_unknown_state_rejected(unauth_client, oauth_env, monkeypatch):
    _r, _params, _state = _start(unauth_client, "github")
    calls = _install_fakes(monkeypatch, profile={"id": 42, "login": "alice"})
    r = unauth_client.get(
        "/api/v1/auth/oauth/github/callback?code=the-code&state=WRONG",
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert "error=invalid_state" in r.headers["location"]
    assert calls["post"] == {}  # never exchanged - the round-trip is broken


def test_callback_without_state_cookie_rejected(unauth_client, oauth_env, monkeypatch):
    # No start -> no state cookie -> the callback rejects before any exchange.
    calls = _install_fakes(monkeypatch, profile={})
    r = unauth_client.get(
        "/api/v1/auth/oauth/github/callback?code=the-code&state=whatever",
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert "error=invalid_state" in r.headers["location"]
    assert calls["post"] == {}


def test_callback_missing_code_rejected(unauth_client, oauth_env, monkeypatch):
    _r, _params, state = _start(unauth_client, "github")
    calls = _install_fakes(monkeypatch, profile={})
    r = unauth_client.get(
        f"/api/v1/auth/oauth/github/callback?state={state}",
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert "error=invalid_state" in r.headers["location"]
    assert calls["post"] == {}


def test_callback_provider_denied_rejected(unauth_client, oauth_env, monkeypatch):
    # The provider's own error param (user clicked "deny").
    _r, _params, state = _start(unauth_client, "github")
    calls = _install_fakes(monkeypatch, profile={})
    r = unauth_client.get(
        f"/api/v1/auth/oauth/github/callback?error=access_denied&state={state}",
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert "error=access_denied" in r.headers["location"]
    assert calls["post"] == {}


# ---- account linking + first-user claim -------------------------------------


def test_callback_links_existing_local_user_by_email(
    unauth_client, oauth_env, monkeypatch, db_session_factory
):
    with db_session_factory() as db:
        db.add(
            User(
                username="alice",
                email="alice@example.com",
                password_hash=hash_password("password123"),
            )
        )
        db.commit()
        local_id = db.scalar(select(User.id).where(User.username == "alice"))
    _r, _params, state = _start(unauth_client, "github")
    _install_fakes(
        monkeypatch,
        profile={"id": 999, "login": "alice", "email": "alice@example.com"},
    )
    r = unauth_client.get(
        f"/api/v1/auth/oauth/github/callback?code=the-code&state={state}",
        follow_redirects=False,
    )
    assert r.status_code == 302
    with db_session_factory() as db:
        # Same row - the identity was linked, not duplicated.
        assert db.scalar(select(func.count()).select_from(User)) == 1
        user = db.get(User, local_id)
        assert user.auth_provider == "github"
        assert user.oauth_id == "999"
        # The local password still works too (both sign-ins converge).
        assert user.password_hash is not None


def test_first_oauth_user_is_admin_and_claims_legacy(
    unauth_client, oauth_env, monkeypatch, db_session_factory
):
    with db_session_factory() as db:
        db.add_all([Scan(filename="old.apk", status="done")])
        db.commit()
    _r, _params, state = _start(unauth_client, "google")
    _install_fakes(
        monkeypatch,
        profile={"sub": "g-1", "email": "admin@example.com", "email_verified": True},
    )
    r = unauth_client.get(
        f"/api/v1/auth/oauth/google/callback?code=the-code&state={state}",
        follow_redirects=False,
    )
    assert r.status_code == 302
    with db_session_factory() as db:
        user = find_by_username(db, "admin")
        assert user is not None
        assert user.is_admin is True  # first registered user = admin (decision 5)
        owner = db.scalar(select(Scan.user_id))
        assert owner == user.id  # the legacy scan was claimed


def test_callback_username_collision_gets_suffix(
    unauth_client, oauth_env, monkeypatch, db_session_factory
):
    with db_session_factory() as db:
        db.add(User(username="alice", password_hash=hash_password("password123")))
        db.commit()
    _r, _params, state = _start(unauth_client, "google")
    _install_fakes(
        monkeypatch,
        profile={"sub": "g-2", "email": "alice@other.com", "email_verified": True},
    )
    r = unauth_client.get(
        f"/api/v1/auth/oauth/google/callback?code=the-code&state={state}",
        follow_redirects=False,
    )
    assert r.status_code == 302
    with db_session_factory() as db:
        assert db.scalar(select(func.count()).select_from(User)) == 2
        assert find_by_username(db, "alice1") is not None  # suffix applied


# ---- upstream failures: clean redirect, never a 500 -------------------------


def test_callback_provider_unreachable_clean_redirect(
    unauth_client, oauth_env, monkeypatch, db_session_factory
):
    _r, _params, state = _start(unauth_client, "github")
    _install_fakes(monkeypatch, post_exc=httpx.ConnectError("connection refused"))
    r = unauth_client.get(
        f"/api/v1/auth/oauth/github/callback?code=the-code&state={state}",
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert "error=oauth_failed" in r.headers["location"]
    with db_session_factory() as db:
        assert db.scalar(select(func.count()).select_from(User)) == 0


def test_callback_token_rejected_clean_redirect(
    unauth_client, oauth_env, monkeypatch, db_session_factory
):
    _r, _params, state = _start(unauth_client, "github")
    _install_fakes(monkeypatch, token_status=400)
    r = unauth_client.get(
        f"/api/v1/auth/oauth/github/callback?code=bad-code&state={state}",
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert "error=oauth_failed" in r.headers["location"]
    with db_session_factory() as db:
        assert db.scalar(select(func.count()).select_from(User)) == 0


def test_callback_profile_failure_clean_redirect(
    unauth_client, oauth_env, monkeypatch, db_session_factory
):
    _r, _params, state = _start(unauth_client, "google")
    _install_fakes(
        monkeypatch,
        profile={"sub": "g-1", "email": "x@example.com", "email_verified": True},
        profile_status=403,  # revoked token / scope issue
    )
    r = unauth_client.get(
        f"/api/v1/auth/oauth/google/callback?code=the-code&state={state}",
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert "error=oauth_failed" in r.headers["location"]
    with db_session_factory() as db:
        assert db.scalar(select(func.count()).select_from(User)) == 0


def test_callback_unknown_provider_404(unauth_client, oauth_env):
    r = unauth_client.get(
        "/api/v1/auth/oauth/gitlab/callback?code=x&state=y",
        follow_redirects=False,
    )
    assert r.status_code == 404


# ---- providers endpoint reflects configuration ------------------------------


def test_providers_lists_configured_oauth(unauth_client, oauth_env):
    body = unauth_client.get("/api/v1/auth/providers").json()
    assert body["providers"] == ["local", "github", "google"]


def test_providers_without_oauth_config(unauth_client):
    # The auth fixture DB is per-test; no oauth_env here -> local only.
    body = unauth_client.get("/api/v1/auth/providers").json()
    assert body["providers"] == ["local"]
