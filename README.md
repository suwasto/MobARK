<p align="center">
  <img src="site/assets/mobark-header.svg" alt="MobARK: Mobile Application Reverse Kit" width="720" />
</p>

<p align="center">
  <b>Self Hosted mobile application security testing</b>: static analysis + AI Agent for Android &amp; iOS.
</p>

<p align="center">
  <a href="https://github.com/suwasto/MobARK/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-green.svg" alt="License: Apache-2.0" /></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python 3.11+" /></a>
  <a href="https://nodejs.org/"><img src="https://img.shields.io/badge/node-18+-blue.svg" alt="Node 18+" /></a>
  <a href="https://github.com/suwasto/MobARK/actions/workflows/backend.yml"><img src="https://github.com/suwasto/MobARK/actions/workflows/backend.yml/badge.svg" alt="Backend CI" /></a>
  <a href="https://github.com/suwasto/MobARK/actions/workflows/frontend.yml"><img src="https://github.com/suwasto/MobARK/actions/workflows/frontend.yml/badge.svg" alt="Frontend CI" /></a>
  <a href="https://suwasto.github.io/MobARK/"><img src="https://img.shields.io/badge/docs-github.io-4a7dff.svg" alt="Documentation" /></a>
</p>

---

**MobARK** is a self-hosted dashboard for mobile application security
testing: Android (APK) and iOS (IPA). Upload a binary and MobARK
decompiles it, runs static analysis (jadx / apktool / semgrep / gitleaks
/ LIEF), scores findings with a plain severity-based risk index
(`high | warning | info`: deliberately not CVSS, which needs a human
analyst for disclosed CVEs), and gives you an **AI Agent
that can chat with the decompiled code**: all through your own local
LLM (Ollama / LM Studio) with **nothing leaving your machine by
default**.

## Features

- **Static analysis**: Android (manifests, jadx decompile, curated +
  OWASP MASTG semgrep rules, secrets scanning, dependency inventory) and
  iOS (Mach-O via LIEF, entitlements, Info.plist, insecure-import
  scanning)
- **AI Agent**: chat with the decompiled code (findings context +
  code search/read + per-scan code graph tools), live step/token
  streaming, **opt-in web research** through a bundled SearXNG
- **Edit & recompile** (Android): apktool decode, smali edits,
  resigned test APK builds
- **Reports**: deterministic Markdown/PDF with banded risk-index
  scoring (`high | warning | info` severities, no CVSS claim),
  per-finding suppression, AI (or no-model) explanations
- **Multi-user auth**: username/password + GitHub/Google OAuth,
  per-user data isolation, encrypted per-user key vault
- **Local-first**: app, worker, Redis, and the search engine all run
  locally under `docker compose`

## Quick start (Docker)

> Requires Docker with the Compose v2 plugin.

```bash
docker compose up --build
```

Open **http://localhost:8000**. Auth is on by default: a fresh install
lands on the register/login screen and the **first registered account
becomes the admin**.

For a quick local evaluation, register these two demo accounts:

| Username | Password | Role |
|---|---|---|
| `admin` | `password123` | Admin: register first |
| `alice` | `password123` | Regular user: sees only her own scans |

> **Warning:** demo credentials are for local installs only: never
> expose an install with known passwords to a network.

To skip auth entirely (dev/CI): set `MOBARK_AUTH_ENABLED=0` in `.env`.

See [Quickstart](https://suwasto.github.io/MobARK/quickstart/) for local
development setup and the full configuration reference.

## Architecture

MobARK is one `docker compose` stack: a FastAPI backend, an RQ worker,
Redis (the job queue), and a bundled SearXNG search engine, all sharing
a SQLite database and a data dir. The React SPA is served from the same
FastAPI origin (no separate static server).

- **Auth is the outer gate.** Every `/api/v1` router (except `health` and
  `auth`) sits behind a session cookie; all scan-keyed routes resolve the
  owner from the request context, so per-user isolation is structural.
- **Per-user stores + vault.** Model/search BYOK configs live under
  `data/users/<uid>/`; API keys are encrypted at rest with a per-user
  master key derived from the login password.
- **Long work is async.** Scan analysis, apktool decode, code-graph
  builds, and rebuilds are RQ jobs shared between the API and the worker
  over Redis.
- **Agent = local-first, tool-using chat.** The chat loop layers findings
  context, file tools, graph tools, and edit/recompile tools, with
  opt-in web research through the bundled SearXNG (SSRF-guarded, HTTP
  JSON only). Streaming is SSE.

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the module map and the
full component diagram.

## Documentation

- **Full docs site:** https://suwasto.github.io/MobARK/ (source:
  [`site/`](site/), MkDocs + Material)
- **Architecture:** [`ARCHITECTURE.md`](ARCHITECTURE.md)
- **Dependency licenses:** third-party attribution lives in
  [`site/docs/licenses.md`](site/docs/licenses.md) (rendered on the
  [licenses page](https://suwasto.github.io/MobARK/licenses/))
- **Contributing:** [`CONTRIBUTING.md`](CONTRIBUTING.md)
- **Security:** [`SECURITY.md`](SECURITY.md)

## Screenshots

> **OWNER: add.** Placeholders, replace with captures of a real scan.

<p align="center">
  <img src="site/assets/demo/dashboard.png" alt="Dashboard (placeholder)" width="720" />
</p>

<p align="center">
  <img src="site/assets/demo/agent-dock.png" alt="Agent dock (placeholder)" width="720" />
</p>

<p align="center">
  <img src="site/assets/demo/report.png" alt="Report (placeholder)" width="720" />
</p>

## Project status

**Shipped:**

- **Static analysis**: Android (manifest, jadx decompile, curated +
  vendored MASTG semgrep rules, secrets, dependency inventory) and
  iOS (Mach-O via LIEF, entitlements, Info.plist, insecure-import
  scanning)
- **AI Agent**: chat with the decompiled code via a local LLM, with
  live tool/token streaming and opt-in web research
- **Edit & recompile** (Android): apktool decode, smali edits,
  resigned test APK builds
- **Reports**: deterministic Markdown/PDF with banded risk-index
  scoring, per-finding suppression, AI (or no-model) explanations
- **Multi-user auth**: username/password + GitHub/Google OAuth,
  per-user data isolation, encrypted per-user key vault

**Future plans:** dynamic analysis (runtime/device testing) is next on
 the roadmap: see [`CHANGELOG.md`](CHANGELOG.md) for the full history.

## License

Apache-2.0: see [`LICENSE`](LICENSE). GPL/LGPL tools in the stack
(Semgrep, SearXNG) run subprocess-only / as separate containers; every
imported library is permissive. See the
[license audit](site/docs/licenses.md) and the
[site licenses page](https://suwasto.github.io/MobARK/licenses/).
