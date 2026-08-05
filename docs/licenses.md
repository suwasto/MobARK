# MASA — Dependency & License Audit

**Project license: Apache-2.0** (see [LICENSE](../LICENSE)).

## Compliance posture (the non-negotiable rule)

MASA ships under Apache-2.0. Because the Apache-2.0 license must not be
contaminated by copyleft, **any GPL/LGPL-licensed tool in the stack is
invoked strictly as a subprocess/CLI and never imported as a library**. This
applies to Semgrep (LGPL-2.1) and ldid, and is observed operationally for the
other analysis CLIs (jadx, apktool, gitleaks) regardless of their permissive
licenses, since they are command-line tools by design.

The library dependencies actually imported by MASA are all permissive
(MIT / Apache-2.0 / BSD), so Apache-2.0 + subprocess-only is fully workable.

Audit method: backend dependencies are pinned in
[`backend/requirements.txt`](../backend/requirements.txt) and enumerated here
from `pip-licenses` output at M0 time. Regenerate with:

```bash
cd backend && .venv/bin/pip-licenses --format=plain --with-urls
```

## Installed in M0 (backend, pinned)

| Package | Version | License | Notes |
|---|---|---|---|
| fastapi | 0.115.6 | MIT | |
| uvicorn | 0.34.0 | BSD-3-Clause | + extras |
| starlette | 0.41.3 | BSD-3-Clause | pinned: fastapi 0.115.x requires <0.42 (see M1 notes) |
| sqlalchemy | 2.0.36 | MIT | |
| alembic | 1.14.0 | MIT | |
| pydantic | 2.10.3 | MIT | |
| pydantic-settings | 2.7.0 | MIT | |
| redis | 5.2.1 | MIT | |
| rq | 2.0.0 | BSD-3-Clause | |
| httpx | 0.28.1 | BSD-3-Clause | dev/test |
| pytest | 8.3.4 | MIT | dev |
| ruff | 0.8.4 | MIT | dev |

Transitive (permissive): Mako (MIT), MarkupSafe (BSD), annotated-types (MIT),
anyio (MIT), certifi (MPL-2.0), click (BSD), greenlet (MIT), h11 (MIT),
httpcore (BSD), httptools (MIT), idna (BSD), iniconfig (MIT), packaging
(BSD/Apache), pluggy (MIT), pydantic-core (MIT), python-dotenv (BSD-3-Clause),
typing-extensions (PSF), uvloop (MIT/Apache), watchfiles (MIT), websockets
(BSD).

## Installed in M1 (backend, pinned)

| Package | Version | License | Notes |
|---|---|---|---|
| androguard | 4.1.4 | Apache-2.0 | manifest/cert/netsec parsing |
| PyYAML | 6.0.3 | MIT | now a direct dep (MASTG sync script); was transitive |

## Installed in M2 (backend, pinned)

| Package | Version | License | Notes |
|---|---|---|---|
| LIEF | 1.0.0 | Apache-2.0 | iOS Mach-O parsing, code-signature blob access; manylinux wheels (no macOS-only binaries) |

## M1 CLI tools (baked into the app image, subprocess-only)

| Tool | License | Type | Version pin |
|---|---|---|---|
| jadx | Apache-2.0 | CLI (needs JVM) | 1.5.6 |
| Gitleaks | MIT | CLI (Go) | 8.30.1 |
| Semgrep | LGPL-2.1 | CLI (subprocess-only) | 1.172.0 (`semgrep` pip dist, OSS mode) |
| keytool | GPLv2 (OpenJDK runtime) | CLI | ships with the bundled temurin 17 JRE (also used at M8 for the test keystore) |

Semgrep is installed into its **own venv** (`/opt/semgrep-venv`) inside the
image, exposed on PATH via a symlink: its dependency tree requires
`starlette>=0.49.1`, which conflicts with the FastAPI 0.115.x pin
(`starlette<0.42`) — the two cannot share one site-packages. This keeps the
app environment intact while semgrep runs as a normal subprocess. Re-verify
Semgrep's pinned-version license at install time (its licensing has shifted
across versions).

## Planned — installed in later milestones

CLI tools are invoked as subprocesses only (never imported):

| Tool | License | Type | Milestone | Version pin |
|---|---|---|---|---|
| apktool | Apache-2.0 | CLI | M1 (smali), M8 (rebuild) | pin at install |
| apksigner / zipalign | Apache-2.0 | CLI (Android build-tools) | M8 | pin at install |
| ldid | GPL-family (various forks) | CLI (subprocess-only) | M2 (iOS resign) | pin at install |

Python libraries imported by MASA (all permissive — safe under Apache-2.0):

| Library | License | Milestone | Version pin |
|---|---|---|---|
| LiteLLM | MIT | M3 | pin at install |
| LlamaIndex (CodeSplitter) | MIT | M4 | pin at install |
| tree-sitter | MIT | M4 (via LlamaIndex) | pin at install |
| chromadb | Apache-2.0 | M4 | pin at install |
| gpt-researcher | Apache-2.0 | M7 (adapted pipeline) | pin at install |

## Notes

- **Semgrep & ldid are the only copyleft items.** Both are CLI tools and are
  wrapped as subprocess modules (M1 / M2), which keeps MASA's Apache-2.0
  license clean. Re-verify Semgrep's pinned version license at install time (its CLI
  licensing has shifted across versions).
- **MASVS/MASTG mapping data** (M1/M2) is sourced from the OWASP MASTG repo
  (MIT/CC-BY-4.0 style project data), vendored/cached locally — not a code
  dependency. The vendored mapping includes both Android and iOS tests
  (129 iOS tests), so M2 backfills `mastg_test_id` the same way M1 does.
- **Sample test artifact** `docs/iBugBazaar.ipa` (payatu/iBugBazaar,
  MASTG-APP-0030) is vendored for M2 integration testing; see
  `docs/progress/M2.md` for the pinned release + sha256.
- Docker images: `python:3.11-slim` (PSF license) and `redis:7-alpine`
  (BSD-3-Clause). The M1 image additionally bundles an
  `eclipse-temurin:17-jre-jammy` OpenJDK JRE (GPLv2+CE) copied into the image
  for jadx, and the semgrep venv described above.
- This file is informational: the Apache-2.0 posture above is the constraint that
  governs future dependency additions — run the audit check before adding any
  new dependency.
