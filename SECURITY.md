# Security Policy

## Reporting a vulnerability

Please **do not open a public issue** for security vulnerabilities.
Report them privately via **GitHub private vulnerability reporting**
(the repository's Security tab → "Report a vulnerability"), or email
the maintainer (see the GitHub profile).

Please include:

- The affected version / commit
- A minimal reproduction (artifact type, steps, config)
- Impact and any suggested mitigation

You should receive an acknowledgment within a few days and a status
update as the issue is triaged and fixed. Public disclosure happens
after a fix is released (coordinated disclosure).

## Supported versions

MobARK is pre-1.0 and iterates quickly. Security fixes land on `main`
and ship with the next release; there is no LTS line yet. **Run the
latest release** and rebuild your Docker images (`docker compose build
&& docker compose up -d`) to pick up fixes.

## Security posture

- **Self-hosted by design.** Scan data (APK/IPA uploads, decompiled
  trees, findings) stays on the host running MobARK; the default
  configuration makes no outbound network calls except opt-in agent web
  research. Running MobARK on an untrusted network exposes whatever data
  it holds: keep it on a trusted host, or put the web UI behind your
  own reverse proxy with auth.
- **Authentication.** Auth is on by default; the first
  registered user is the admin. Session cookies are HttpOnly +
  SameSite=Lax (Secure when `MOBARK_COOKIE_SECURE=1`: set it when
  serving over TLS). Per-user isolation is structural: foreign scans
  read as 404 (no existence leak).
- **No seeded credentials.** No accounts are pre-seeded: the first
  registration becomes the admin, and the passwords shown in the docs
  (`password123`, etc.) are **examples only** — nothing ships with a
  known password. Never expose an install with example credentials to
  a network: use real, unique passwords.
- **Keys at rest.** BYOK model/search API keys are encrypted at rest in
  a per-user vault (scrypt KEK + AES-GCM); the password is the key-
  encryption key.
- **Dependency posture.** All imported libraries are permissive
  (MIT/Apache-2.0/BSD). GPL/LGPL tools run subprocess-only. Dependabot
  runs weekly; the license audit gates upgrades.

## Security-relevant configuration

| Setting | Recommendation |
|---|---|
| `MOBARK_COOKIE_SECURE=1` | when serving over TLS |
| `MOBARK_PUBLIC_BASE_URL` | set to the real public origin (OAuth redirects derive from it) |
| OAuth client id/secret | only set the providers you actually use |
| `MOBARK_AUTH_ENABLED` | keep `1` (default) on any non-throwaway install |
