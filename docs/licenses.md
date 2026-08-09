# MASA — Dependency & License Audit

**Project license: Apache-2.0** (see [LICENSE](../LICENSE)).

> Updated Aug 9, 2026 (M7) — the audit now lists **only what MASA actually
> installs and uses as of M7**. Nothing is listed on a "planned" basis:
> future-M8 tools (apktool, apksigner/zipalign, ldid) are **not yet
> installed or used** and will be audited when they land.

## Compliance posture (the non-negotiable rule)

MASA ships under Apache-2.0. Because the Apache-2.0 license must not be
contaminated by copyleft, **any GPL/LGPL-licensed tool in the stack is
invoked strictly as a subprocess/CLI and never imported as a library**. This
applies today to Semgrep (LGPL-2.1) and to SearXNG (AGPL-3.0, a separate
container reached only over HTTP — see below), and is observed operationally
for all the analysis CLIs (jadx, gitleaks, graphify) regardless of their
permissive licenses, since they are command-line tools by design. ldid (a
GPL-family CLI) is planned for M8's iOS resign step and will follow the same
subprocess-only rule when it is actually added.

The library dependencies actually imported by MASA are all permissive
(MIT / Apache-2.0 / BSD), so Apache-2.0 + subprocess-only is fully workable.

Audit method: backend dependencies are pinned in
[`backend/requirements.txt`](../backend/requirements.txt) (frontend in
[`frontend/package.json`](../frontend/package.json)). Regenerate the Python
license list with:

```bash
cd backend && .venv/bin/pip-licenses --format=plain --with-urls
```

## Installed & in use — backend, pinned (by milestone)

### M0 — base runtime (all still in use)

| Package | Version | License | Notes |
|---|---|---|---|
| fastapi | 0.115.6 | MIT | |
| uvicorn[standard] | 0.34.0 | BSD-3-Clause | |
| starlette | 0.41.3 | BSD-3-Clause | pinned: fastapi 0.115.x requires <0.42 (semgrep's venv isolates its newer starlette) |
| sqlalchemy | 2.0.36 | MIT | |
| alembic | 1.14.0 | MIT | migrations (head 0008) |
| pydantic | 2.10.3 | MIT | |
| pydantic-settings | 2.7.0 | MIT | `Settings` (MASA_* env) |
| redis | 5.2.1 | MIT | RQ broker |
| rq | 2.0.0 | BSD-3-Clause | scan jobs |
| python-multipart | 0.0.20 | MIT | M5: multipart upload parsing (FastAPI UploadFile) |

Dev tooling (`requirements-dev.txt`, not shipped in the image): pytest 8.3.4
(MIT), ruff 0.8.4 (MIT), pip-licenses 5.0.0 (MIT), httpx 0.28.1 (BSD-3-Clause,
also a runtime dep since M3).

Transitive (permissive): Mako (MIT), MarkupSafe (BSD), annotated-types (MIT),
anyio (MIT), certifi (MPL-2.0), click (BSD), greenlet (MIT), h11 (MIT),
httpcore (BSD), httptools (MIT), idna (BSD), iniconfig (MIT), packaging
(BSD/Apache), pluggy (MIT), pydantic-core (MIT), python-dotenv (BSD-3-Clause),
typing-extensions (PSF), uvloop (MIT/Apache), watchfiles (MIT), websockets
(BSD).

### M1 — Android analysis (all still in use)

| Package | Version | License | Notes |
|---|---|---|---|
| androguard | 4.1.4 | Apache-2.0 | manifest/cert/netsec parsing |
| PyYAML | 6.0.3 | MIT | direct dep (MASTG sync script) |

### M2 — iOS static analysis

| Package | Version | License | Notes |
|---|---|---|---|
| LIEF | 1.0.0 | Apache-2.0 | iOS Mach-O parsing, code-signature blob access; manylinux wheels (no macOS-only binaries) |

### M3 — model backends (LiteLLM)

| Package | Version | License | Notes |
|---|---|---|---|
| LiteLLM | 1.95.0 | MIT | model client: chat + BYOK provider abstraction (OpenAI/Anthropic/DeepSeek/OpenRouter/Gemini/local) |
| httpx | 0.28.1 | BSD-3-Clause | runtime dep since M3 (health model listing, web_search/web_fetch at M7); was dev-only at M0 |

### M4 — code graph (Layer 3)

| Package | Version | License | Notes |
|---|---|---|---|
| graphifyy | 0.9.32 | MIT/Apache-2.0 dual | per-scan code graphs (Layer 3); CLI invoked as a subprocess. Validated surface: `update <dir> --no-cluster` build + `query`/`path`/`explain`/`affected` |
| tree-sitter | (via graphifyy) | MIT | language grammars for graph extraction |
| networkx | (via graphifyy) | BSD-3-Clause | graph build |
| rapidfuzz | (via graphifyy) | MIT | fuzzy matching |

> **Removed from v1 (owner decision, Aug 6, 2026):** chromadb (1.5.9) and
> llama-index-core (0.14.24) were uninstalled with the RAG/embedding pipeline —
> M4 is now Layers 1-3 (findings context + search/read tools + Graphify), all
> non-embedding. No vector store remains.

### M7 — web research

| Package | Version | License | Notes |
|---|---|---|---|
| trafilatura | ≥1.8.0,<2.0 (1.12.2 installed) | **Apache-2.0 (v1.8.0+ only)** | `web_fetch` article extraction. The pin IS the license boundary — earlier versions were GPLv3+ |

> **M6 / M6.1 — no new dependencies.** The M6 tool-calling surface (agent
> tools) and the M6.1 dev-only fake LLM are built-in Python, and the M6
> streaming path reuses litellm's existing `completion(stream=True)` — no new
> packages were added.

## Installed & in use — frontend (M5+, pinned)

| Package | Version | License | Notes |
|---|---|---|---|
| react / react-dom | ^18.3.1 | MIT | UI framework |
| react-markdown | ^10.1.0 | MIT | renders LLM markdown (AI summary / explain / agent chat) |
| remark-gfm / remark-breaks | ^4.0.1 / ^4.0.0 | MIT | markdown plugins (tables, single-newline fidelity) |
| vite | ^6.0.5 | MIT | dev build tool |
| typescript | ~5.6.3 | Apache-2.0 | dev |
| @vitejs/plugin-react | ^4.3.4 | MIT | dev |
| tailwindcss + @tailwindcss/vite | ^4.3.3 | MIT | design system (CSS-first `@theme` tokens) |
| @fontsource/ibm-plex-sans + @fontsource/ibm-plex-mono | ^5.3.0 | SIL OFL 1.1 | bundled fonts — no Google Fonts CDN (local-first) |
| highlight.js | ^11.11.1 | BSD-3-Clause | decompiler code tokenization |
| @types/react, @types/react-dom, @types/node | — | MIT (DefinitelyTyped) | dev type stubs |

## CLI tools (subprocess-only, baked into the app image)

| Tool | License | Type | Version pin |
|---|---|---|---|
| jadx | Apache-2.0 | CLI (needs JVM) | 1.5.6 |
| Gitleaks | MIT | CLI (Go) | 8.30.1 |
| Semgrep | LGPL-2.1 | CLI (subprocess-only) | 1.172.0 (`semgrep` pip dist, OSS mode) |

Semgrep is installed into its **own venv** (`/opt/semgrep-venv`) inside the
image, exposed on PATH via a symlink: its dependency tree requires
`starlette>=0.49.1`, which conflicts with the FastAPI 0.115.x pin
(`starlette<0.42`) — the two cannot share one site-packages. Re-verify
Semgrep's pinned-version license at install time (its licensing has shifted
across versions).

`keytool` ships inside the bundled `eclipse-temurin:17-jre-jammy` OpenJDK
(GPLv2+CE) that jadx needs — it is present in the image because the JRE is,
not as a separate dependency. Its planned M8 use (test keystore) is future.

## Container services (network boundary only — never imported, never vendored)

| Service | Image | License | Posture |
|---|---|---|---|
| Redis | `redis:7-alpine` | BSD-3-Clause | RQ broker; always-on |
| SearXNG | `searxng/searxng` | **AGPL-3.0** | M7 web research. Runs as an **unmodified upstream container** under the `web` compose profile (`docker compose --profile web up -d searxng`), reached only over its HTTP JSON API (`/search?format=json`). AGPL §13 reaches modified copies of SearXNG itself — MASA never copies, pip-installs, forks, or patches it, so the copyleft does not cross the process boundary. Our own minimal `settings.yml` (a config artifact, not SearXNG code) enables the json format. **Violations to avoid**: vendoring SearXNG code into this repo, `pip install searxng`, or shipping a modified/forked instance. |

## Notes

- **Copyleft items in use: Semgrep (LGPL-2.1 CLI) and SearXNG (AGPL-3.0
  container service).** Both keep MASA's Apache-2.0 clean because the
  copyleft never crosses a process boundary: Semgrep is a subprocess from an
  isolated venv, SearXNG is an unmodified separate container reached only
  over HTTP. Re-verify Semgrep's pinned version license at install time.
  (ldid, the planned M8 iOS resign CLI, is not yet installed.)
- **MASVS/MASTG mapping data** (M1/M2) is sourced from the OWASP MASTG repo
  (MIT/CC-BY-4.0 style project data), vendored/cached locally — not a code
  dependency. The vendored mapping includes both Android and iOS tests
  (129 iOS tests), so M2 backfills `mastg_test_id` the same way M1 does.
- **Sample test artifacts** vendored for integration testing (not code
  dependencies): `docs/InsecureBankv2.apk` (Android, M1) and
  `docs/iBugBazaar.ipa` (payatu/iBugBazaar, MASTG-APP-0030; see
  `docs/progress/M2.md` for the pinned release + sha256).
- Docker images: `python:3.11-slim` (PSF license) and `redis:7-alpine`
  (BSD-3-Clause). The app image additionally bundles the
  `eclipse-temurin:17-jre-jammy` OpenJDK JRE (GPLv2+CE) for jadx and the
  semgrep venv described above.
- **Not yet used (future milestones, not installed):** apktool,
  apksigner/zipalign, and ldid are M8 items — they are absent from the image
  and the codebase today, and will be audited here when M8 lands. The
  deep-research / browser-automation stack planned for the original M7 was
  dropped (owner decision, Aug 9) and its rows (gpt-researcher,
  agent-browser) never shipped.
- This file is informational: the Apache-2.0 posture above is the constraint
  that governs future dependency additions — run the audit check before
  adding any new dependency.
