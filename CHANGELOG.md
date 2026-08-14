# Changelog

All notable changes to MASA are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added (M10 — open-source readiness)

- Public documentation site: tracked `site/` MkDocs project (Material
  theme) with curated pages — index, quickstart, features,
  architecture, auth, milestones, demo, third-party licenses
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

## [0.1.0] - planned

First tagged release (M10 Phase F). The M1–M9.1 feature history below
is summarized for context.

## Milestone history (pre-release, M0–M9.1)

### M9.1 — Auth + per-user isolation (Aug 14, 2026)

- Username/password auth (stdlib scrypt) + GitHub/Google OAuth
  (env-configured only)
- Sliding HttpOnly sessions, admin-first-user rule, structural per-user
  scan isolation (foreign scans 404)
- Per-user encrypted key vault (scrypt KEK + AES-GCM) for BYOK/search
  keys; host-operator CLI password reset
- `MASA_AUTH_ENABLED=0` dev/CI parity mode

### M9 — Reports (Aug 12, 2026)

- Deterministic report assembly (no model needed), CVSS 4.0 band-
  symmetric risk scoring, per-finding suppression, Markdown + PDF
  export; persistent chat sessions (follow-up)

### M8 — Edit & recompile (Aug 10, 2026)

- apktool decode → smali tree, agent-proposed + manual smali edits,
  diff review, resigned test APK builds (apksigner/zipalign)

### M7 — Agent web research (Aug 9, 2026)

- `web_search` / `web_fetch` agent tools through a bundled always-on
  SearXNG (SSRF-guarded), per-scan opt-in

### M6 / M6.1 — Tools + streaming (Aug 9, 2026)

- App-oriented agent tools (manifest, class, permissions, secrets re-
  scan, string search); SSE token/tool-step streaming; dev-only fake
  LLM (`MASA_FAKE_MODEL=1`)

### M5 — Dashboard (Aug 8, 2026)

- Overview/security gauge, findings tab with AI explain, decompiler
  (file tree + code viewer + annotation rail), agent dock, upload flow

### M4 — Agent layers (Aug 6, 2026)

- Findings context (L1), search/read tools (L2), code-graph tools (L3),
  per-scan code graph + Code maps tab; RAG/embeddings dropped from v1

### M3 — Model backends (Aug 5, 2026)

- Ollama/LM Studio + BYOK providers via LiteLLM, backend store,
  health/probe, model listing

### M2 — iOS static core (Aug 4, 2026)

- LIEF Mach-O analysis, entitlements, Info.plist, import-table scanner

### M1 — Android static analysis (Aug 3, 2026)

- jadx decompile, androguard manifest inspection, semgrep (curated +
  vendored MASTG rules), gitleaks, orchestrator

### M0 — Scaffolding (Aug 2, 2026)

- Repo skeleton, FastAPI + RQ worker + Redis, React/Vite SPA, SQLite +
  Alembic, docker-compose
