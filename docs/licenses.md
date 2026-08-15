# MASA — Dependency & License Audit

**Project license: Apache-2.0** (see [LICENSE](../LICENSE)).

> Updated Aug 10, 2026 (M8 Phase A) — the audit lists **only what MASA
> actually installs and uses**. M8 toolchain status after Phase A:
> **apktool (3.0.3) + Android build-tools apksigner/zipalign (35.0.1) are
> now bundled in the app image** (both Apache-2.0 — see the CLI table);
> **ldid is deferred to v1.1** with the iOS edit/recompile cut (owner
> decision, Aug 10, 2026) — not an M8 item.

## Compliance posture (the non-negotiable rule)

MASA ships under Apache-2.0. Because the Apache-2.0 license must not be
contaminated by copyleft, **any GPL/LGPL-licensed tool in the stack is
invoked strictly as a subprocess/CLI and never imported as a library**. This
applies today to Semgrep (LGPL-2.1) and to SearXNG (AGPL-3.0, a separate
container reached only over HTTP — see below), and is observed operationally
for all the analysis CLIs (jadx, gitleaks, graphify) regardless of their
permissive licenses, since they are command-line tools by design. ldid (a
GPL-family CLI) was planned for M8's iOS resign step, but iOS edit/recompile
was **deferred to v1.1** at the M8 kickoff (Aug 10, 2026) — it will follow
the same subprocess-only rule if it is ever added. apktool and the Android
build-tools (zipalign/apksigner, both Apache-2.0) are M8 additions and are
audited here when they land.

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

### M9 — report export (Phase C, Aug 12 2026)

| Package | Version | License | Notes |
|---|---|---|---|
| reportlab | 4.5.1 | BSD-3-Clause | platypus PDF renderer (direct dep). Chosen over xhtml2pdf at the Aug 12 follow-up — see the rejection note below |
| markdown (Python-Markdown) | 3.10.3 | BSD-3-Clause | md→HTML conversion of the assembled body; the reportlab renderer lays out that constrained fragment (Paragraphs/ListFlowable) |

### M9.1 — auth + vault (Aug 14 2026)

| Package | Version | License | Notes |
|---|---|---|---|
| cryptography | 44.0.0 | Apache-2.0 (or BSD) | M9.1 vault: AES-GCM envelope encryption of per-user BYOK/search API keys at rest. The KEK uses stdlib `hashlib.scrypt` (same params as the password hasher); this package provides the authenticated cipher only. Permissive (Apache-2.0/BSD dual) — no license-posture change |

> **xhtml2pdf REJECTED (owner decision, Aug 12 2026 follow-up).** The Phase C
> kickoff picked xhtml2pdf (Apache-2.0) as the "license-pure" HTML→PDF option.
> The audit (the project's own `pip-licenses` check, run before shipping the
> Phase C deps) proved that claim false at the transitive level: xhtml2pdf
> 0.2.17 imports **LGPL `python-bidi`** (eagerly, for RTL text shaping) and
> **LGPLv3 `svglib`** (lazy, for SVG images) — a violation of the hard rule
> that all imported libraries are permissive (MIT/Apache-2.0/BSD). WeasyPrint
> was no better (its tree includes pyphen, LGPL/MPL). reportlab (BSD-3-Clause,
> already a transitive) now renders the same body directly; the LGPL pair and
> the PAdES (pyHanko) bloat are gone from the image. The xhtml2pdf / bidi /
> svglib / pyhanko / pyhanko-certvalidator / arabic-reshaper / html5lib
> packages were uninstalled.
> **M9 fonts:** DejaVu Sans is bundled in the app image via `fonts-dejavu-core`
> (Bitstream Vera license — permissive, may be embedded/redistributed; not a
> license-posture change). Registered as the `MasaReport` TTF
> (`MASA_REPORT_FONT` default `/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf`);
> when missing the render falls back to Helvetica (never a crash).
> **M9 dev-only:** `pypdf==6.15.0` (BSD-3-Clause) added to
> `requirements-dev.txt` — PDF text extraction in the export tests
> (section-heading gate), not shipped in the image.

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
| apktool | Apache-2.0 | CLI (needs JVM; bundled aapt2) | 3.0.3 (pinned official jar + wrapper script) |
| zipalign + apksigner (Android build-tools) | Apache-2.0 | CLI (needs JVM for apksigner) | 35.0.1 (build-tools_r35.0.1_linux.zip) |

Semgrep is installed into its **own venv** (`/opt/semgrep-venv`) inside the
image, exposed on PATH via a symlink: its dependency tree requires
`starlette>=0.49.1`, which conflicts with the FastAPI 0.115.x pin
(`starlette<0.42`) — the two cannot share one site-packages. Re-verify
Semgrep's pinned-version license at install time (its licensing has shifted
across versions).

`keytool` ships inside the bundled `eclipse-temurin:17-jre-jammy` OpenJDK
(GPLv2+CE) that jadx needs — it is present in the image because the JRE is,
not as a separate dependency. Its M8 use (the install-scoped test keystore
for resigning, Phase C) is active as of Phase A.

## Container services (network boundary only — never imported, never vendored)

| Service | Image | License | Posture |
|---|---|---|---|
| Redis | `redis:7-alpine` | BSD-3-Clause | RQ broker; always-on |
| SearXNG | `searxng/searxng` | **AGPL-3.0** | M7 web research. Runs as an **unmodified upstream container**, always-on in the compose stack (no profile gate since Aug 14 — `docker compose up` starts it with the app; a stopped container is restarted with `docker compose up -d searxng`), reached only over its HTTP JSON API (`/search?format=json`). AGPL §13 reaches modified copies of SearXNG itself — MASA never copies, pip-installs, forks, or patches it, so the copyleft does not cross the process boundary. Our own minimal `settings.yml` (a config artifact, not SearXNG code) enables the json format. **Violations to avoid**: vendoring SearXNG code into this repo, `pip install searxng`, or shipping a modified/forked instance. |

## Notes

- **Copyleft items in use: Semgrep (LGPL-2.1 CLI) and SearXNG (AGPL-3.0
  container service).** Both keep MASA's Apache-2.0 clean because the
  copyleft never crosses a process boundary: Semgrep is a subprocess from an
  isolated venv, SearXNG is an unmodified separate container reached only
  over HTTP. Re-verify Semgrep's pinned version license at install time.
  (ldid, originally planned as the M8 iOS resign CLI, is not installed —
  iOS edit/recompile was deferred to v1.1 at the M8 kickoff, Aug 10, 2026.)
- **MASVS/MASTG mapping data** (M1/M2) is sourced from the OWASP MASTG repo
  (CC BY-SA 4.0 - `License.md` at the pinned ref), vendored/cached locally —
  not a code dependency. The vendored mapping includes both Android and iOS
  tests (129 iOS tests), so M2 backfills `mastg_test_id` the same way M1 does.
- **Vendored MASTG semgrep rules** (`app/analysis/rules/mastg/`, 51 files):
  CC BY-SA 4.0 as vendored from OWASP/owasp-mastg. **Two rules were
  REWRITTEN from scratch (Aug 13, 2026)** because their previous pattern
  bodies traced via `original_source` to
  mindedsecurity/semgrep-rules-android-security, which is **GPL-3.0** —
  `mastg-android-non-random-use.yml` and
  `mastg-android-random-apis-insufficient-entropy.yml` now carry original
  pattern expression for the same MASTG-CRYPTO-6 detection intent (the
  GPL method-body wrapper is gone; the `java.util.Random` API surface is
  enumerated explicitly), and the `original_source` field was removed. The
  rules' `id`/`message`/`summary` remain MASTG CC BY-SA text. Semgrep's own
  registry rules ("Semgrep Rules License v1.0") are NEVER loaded — the scan
  invokes only the local `rules/{masa,mastg}` dirs.
- **Sample test artifacts** vendored for integration testing (not code
  dependencies): `docs/InsecureBankv2.apk` (Android, M1) and
  `docs/iBugBazaar.ipa` (payatu/iBugBazaar, MASTG-APP-0030; see
  `docs/progress/M2.md` for the pinned release + sha256).
- Docker images: `python:3.11-slim` (PSF license) and `redis:7-alpine`
  (BSD-3-Clause). The app image additionally bundles the
  `eclipse-temurin:17-jre-jammy` OpenJDK JRE (GPLv2+CE) for jadx and the
  semgrep venv described above.
- **M8 toolchain (Aug 10, 2026, Phase A):** apktool (Apache-2.0, 3.0.3) and
  Android build-tools `zipalign`/`apksigner` (Apache-2.0, 35.0.1) are now
  installed in the app image at `/opt/masa-tools/apktool` (jar + wrapper
  script) and `/opt/masa-tools/build-tools` — both invoked as subprocesses
- **Build-tools pin 35.0.0 → 35.0.1 (Aug 10, 2026, Phase E container gate):**
  Google stopped serving the hyphen-named archive —
  `build-tools_r35.0.0-linux.zip` now 404s, and 35.0.0 was never published
  under the current underscore scheme (`build-tools_r<v>_linux.zip`, verified
  against `repository2-3.xml`). The Dockerfile pin + URL scheme were updated
  in the same change that rebuilt the images for the Phase E e2e.
  by convention, matching jadx/gitleaks. The `keytool` row above is now
  *in use* by M8 (test keystore generation, Phase C). **Deferred to v1.1:**
  ldid (the iOS resign CLI) — iOS edit/recompile was cut from M8 at kickoff
  (Aug 10, 2026), so ldid is not an M8 item. The deep-research /
  browser-automation stack planned for the original M7 was dropped (owner
  decision, Aug 9) and its rows (gpt-researcher, agent-browser) never
  shipped.
- **M9.1 auth (Aug 14, 2026): no new rows.** Authentication adds ZERO
  runtime dependencies: passwords are hashed with the stdlib's
  `hashlib.scrypt`, OAuth (GitHub + Google) is hand-rolled over the
  already-pinned `httpx` (OAuth flows are plain HTTP exchanges — no SDK
  needed), and session tokens use `secrets.token_urlsafe` + `hashlib.sha256`.
  The frontend auth surface (login/register view, session handling) is
  stock React/TypeScript + the existing fetch wrapper — no auth library
  was added. The audit posture is unchanged: every imported library stays
  permissive (see the rows above).
- This file is informational: the Apache-2.0 posture above is the constraint
  that governs future dependency additions — run the audit check before
  adding any new dependency.
