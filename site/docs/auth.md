# Authentication (M9.1)

Auth is **ON by default** (owner decision, Aug 2026): a fresh install
lands on the register/login screen, and every `/api/v1` route except
health + auth sits behind a session.

## First run — the admin account

The **first account registered** (username/password or OAuth) becomes
the instance **admin** and adopts any pre-existing unowned scans. For a
local evaluation you can register the demo users
[from the quickstart](quickstart.md#demo-users-local-installs)
(`admin` / `password123`, then `alice` / `password123`).

## Sign-in methods

| Method | When it appears |
|---|---|
| Username / password | Always (local auth). Passwords hashed with stdlib `hashlib.scrypt` — no new deps. |
| GitHub OAuth | Only when **both** `MASA_GITHUB_CLIENT_ID` and `MASA_GITHUB_CLIENT_SECRET` are set |
| Google OAuth | Only when **both** `MASA_GOOGLE_CLIENT_ID` and `MASA_GOOGLE_CLIENT_SECRET` are set |

A provider's button renders only when configured (no config → no
button → never a broken flow). Redirect URIs are derived from
`MASA_PUBLIC_BASE_URL` — never from the request:

```
{MASA_PUBLIC_BASE_URL}/api/v1/auth/oauth/{github|google}/callback
```

Register the app at https://github.com/settings/developers and
https://console.cloud.google.com/apis/credentials with that URI.

OAuth identities resolve to accounts by (provider, oauth_id) then by
verified email (which links an existing local account to the OAuth
sign-in), creating a fresh account when neither matches.

## Sessions

- The session is an **HttpOnly + SameSite=Lax cookie**; set `Secure`
  automatically when `MASA_COOKIE_SECURE=1` (serve over TLS).
- Sessions are **sliding**: refreshed on use, so an active session never
  expires mid-work; a dormant one dies after `MASA_SESSION_DAYS` (7).
- Logout revokes the exact session row behind the cookie (idempotent).
- An `OriginCheckMiddleware` guards cross-origin requests.

## Per-user isolation

Every scan, chat session, edit, and build is owned by the user who
created it:

- `GET /scans` lists **your** scans only.
- A foreign scan reads as **404 — byte-identical to a nonexistent scan**
  (no existence leak). This is structural: every scan-keyed route
  resolves the owner from the request context.
- The first user's registration claims any legacy unowned scans; the
  admin can also claim unowned rows via `POST /api/v1/auth/claim`
  (e.g. CLI-created scans with `python -m app.cli scan --user ...`).

## The vault (per-user key encryption)

BYOK model/search API keys are stored **per user** under
`data/users/<uid>/` and **encrypted at rest** (envelope encryption:
scrypt-derived KEK + AES-GCM):

- Local users: the **password is the key-encryption key** — the vault
  unlocks automatically at login.
- OAuth users: set a dedicated **vault passphrase** once (Settings →
  vault), entered once per session.
- Forgot the passphrase? `POST /api/v1/auth/vault/reset` destroys the
  vault and clears the stored keys (there is no way to recover keys
  wrapped under a lost passphrase) — re-enter them after.
- Host operator password reset (`python -m app.cli auth reset-password
  <user>`) revokes every session and destroys the vault for the same
  reason.

## Disabling auth (dev/CI)

`MASA_AUTH_ENABLED=0` restores the fully-open pre-M9.1 single-user
behavior byte-for-byte — the dev/CI parity mode. The register/login
surface becomes inert (400), `/auth/me` returns `null`, and all routes
are reachable without a session.

## Security notes

- Login failures are one message — `invalid username or password` — for
  unknown user, wrong password, and disabled account alike (no user
  enumeration).
- Register failures are specific (the input is the caller's own).
- Only one admin can ever exist (partial unique index on `is_admin`).
