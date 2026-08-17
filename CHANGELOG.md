# Changelog

All notable changes to MobARK are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-08-17

### Added

- Multi-arch images: the release workflow now builds
  `linux/amd64` + `linux/arm64` and the Dockerfile is arch-aware
  (gitleaks per-arch tarballs, semgrep aarch64 wheels; jadx/apktool
  are JVM jars). Apple Silicon / ARM hosts pull the native arm64
  image. One amd64-only gap stays: **edit & recompile** needs Google's
  Android build-tools (zipalign/apksigner) + apktool's `aapt2`, which
  are Linux x86_64-only — the arm64 image skips them and the rebuild
  pipeline fails loudly with a clear message.
- Release pipeline: `docker.yml` workflow builds and pushes
  `suwasto/mobark` to Docker Hub on `v*` tags (version + `latest`,
  multi-arch), with the tag version baked into the image
  (`MOBARK_VERSION`, surfaced by `/api/v1/health`). Compose now
  references the published image (`image: suwasto/mobark`, tag
  overridable via `MOBARK_IMAGE_TAG`), so releases install with
  `docker compose pull && docker compose up`; the image can also be
  smoke-tested standalone with `docker run` (UI/auth only — analysis
  needs the full stack).
- Public documentation site: tracked `site/` MkDocs project (Material
  theme) with curated pages: index, quickstart, features,
  architecture, auth, status, demo, third-party licenses
  ([mkdocs.yml](mkdocs.yml)).
- Community files: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  `SECURITY.md`, `CHANGELOG.md`, issue + PR templates under `.github/`.
- CI: GitHub Actions workflows for backend (pytest + ruff), frontend
  (`tsc -b` + vite build), and Pages deploy; Dependabot for pip + npm.
- Header/social assets: vendored brand banner, dark-background header
  SVG, social-preview PNG (see [site/assets/](site/assets/)).
- README rewritten for the public repo: pitch, badges, quick start,
  configuration table, screenshot placeholders, docs links.
- Documented local demo users (`admin` / `password123`, `alice` /
  `password123`) in the quickstart + auth pages.

## [0.1.0] - 2026-08-17

First tagged release (git tag `v0.1.0` → Docker Hub publish). The
pre-release feature history below is summarized for context.

## Pre-release history

### Auth + per-user isolation (Aug 14, 2026)

- Username/password auth (stdlib scrypt) + GitHub/Google OAuth
  (env-configured only)
- Sliding HttpOnly sessions, admin-first-user rule, structural per-user
  scan isolation (foreign scans 404)
- Per-user encrypted key vault (scrypt KEK + AES-GCM) for BYOK/search
  keys; host-operator CLI password reset
- `MOBARK_AUTH_ENABLED=0` dev/CI parity mode

### Reports (Aug 12, 2026)

- Deterministic report assembly (no model needed), banded risk-index
  scoring, per-finding suppression, Markdown + PDF export; persistent
  chat sessions (follow-up)

### Edit & recompile (Aug 10, 2026)

- apktool decode → smali tree, agent-proposed + manual smali edits,
  diff review, resigned test APK builds (apksigner/zipalign)
- Decoded-source zip download (`{stem}-source.zip`, applied edits
  overlaid) alongside the resigned APK in the Edit & recompile modal

### Agent web research (Aug 9, 2026)

- `web_search` / `web_fetch` agent tools through a bundled always-on
  SearXNG (SSRF-guarded), per-scan opt-in

### Tools + streaming (Aug 9, 2026)

- App-oriented agent tools (manifest, class, permissions, secrets re-
  scan, string search); SSE token/tool-step streaming; dev-only fake
  LLM (`MOBARK_FAKE_MODEL=1`)

### Dashboard (Aug 8, 2026)

- Overview/security gauge, findings tab with AI explain, decompiler
  (file tree + code viewer + annotation rail), agent dock, upload flow

### Agent layers (Aug 6, 2026)

- Findings context (L1), search/read tools (L2), code-graph tools (L3),
  per-scan code graph + Code maps tab; RAG/embeddings dropped from v1

### Model backends (Aug 5, 2026)

- Ollama/LM Studio + BYOK providers via LiteLLM, backend store,
  health/probe, model listing

### iOS static core (Aug 4, 2026)

- LIEF Mach-O analysis, entitlements, Info.plist, import-table scanner

### Android static analysis (Aug 3, 2026)

- jadx decompile, androguard manifest inspection, semgrep (curated +
  vendored MASTG rules), gitleaks, orchestrator

### Scaffolding (Aug 2, 2026)

- Repo skeleton, FastAPI + RQ worker + Redis, React/Vite SPA, SQLite +
  Alembic, docker-compose
