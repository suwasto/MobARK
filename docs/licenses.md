# MASA — Dependency & License Audit

**Project license: MIT** (see [LICENSE](../LICENSE)).

## Compliance posture (the non-negotiable rule)

MASA ships under MIT. Because the MIT license must not be contaminated by
copyleft, **any GPL/LGPL-licensed tool in the stack is invoked strictly as a
subprocess/CLI and never imported as a library**. This applies to Semgrep
(LGPL-2.1) and ldid, and is observed operationally for the other analysis
CLIs (jadx, apktool, gitleaks) regardless of their permissive licenses, since
they are command-line tools by design.

The library dependencies actually imported by MASA are all permissive
(MIT / Apache-2.0 / BSD), so MIT + subprocess-only is fully workable.

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
| starlette | 0.41.3 | BSD-3-Clause | transitive |
| sqlalchemy | 2.0.36 | MIT | |
| alembic | 1.14.0 | MIT | |
| pydantic | 2.10.3 | MIT | |
| pydantic-settings | 2.7.0 | MIT | |
| redis | 5.2.1 | MIT | |
| rq | 2.0.0 | BSD-3-Clause | |
| httpx | 0.28.1 | BSD-3-Clause | dev/test |
| pytest | 8.3.4 | MIT | dev |
| ruff | 0.8.4 | MIT | dev |

Transitive (permissive): Mako (MIT), MarkupSafe (BSD), PyYAML (MIT),
annotated-types (MIT), anyio (MIT), certifi (MPL-2.0), click (BSD), greenlet
(MIT), h11 (MIT), httpcore (BSD), httptools (MIT), idna (BSD), iniconfig
(MIT), packaging (BSD/Apache), pluggy (MIT), pydantic-core (MIT),
python-dotenv (BSD-3-Clause), typing-extensions (PSF), uvloop (MIT/Apache),
watchfiles (MIT), websockets (BSD).

## Planned — installed in later milestones

CLI tools are invoked as subprocesses only (never imported):

| Tool | License | Type | Milestone | Version pin |
|---|---|---|---|---|
| Gitleaks | MIT | CLI (Go) | M1 | pin at install |
| Semgrep | LGPL-2.1 | CLI (subprocess-only) | M1 | pin at install |
| jadx | Apache-2.0 | CLI (needs JVM) | M1 | pin at install |
| apktool | Apache-2.0 | CLI | M1 (smali), M8 (rebuild) | pin at install |
| apksigner / zipalign | Apache-2.0 | CLI (Android build-tools) | M8 | pin at install |
| keytool | GPLv2 (OpenJDK runtime) | CLI | M8 | ships with JVM |
| ldid | GPL-family (various forks) | CLI (subprocess-only) | M2 (iOS resign) | pin at install |

Python libraries imported by MASA (all permissive — safe under MIT):

| Library | License | Milestone | Version pin |
|---|---|---|---|
| androguard | Apache-2.0 | M1 | pin at install |
| LIEF | Apache-2.0 | M2 | pin at install |
| LiteLLM | MIT | M3 | pin at install |
| LlamaIndex (CodeSplitter) | MIT | M4 | pin at install |
| tree-sitter | MIT | M4 (via LlamaIndex) | pin at install |
| chromadb | Apache-2.0 | M4 | pin at install |
| gpt-researcher | Apache-2.0 | M7 (adapted pipeline) | pin at install |

## Notes

- **Semgrep & ldid are the only copyleft items.** Both are CLI tools and are
  wrapped as subprocess modules (M1 / M2), which keeps MASA's MIT license
  clean. Re-verify Semgrep's pinned version license at install time (its CLI
  licensing has shifted across versions).
- **MASVS/MASTG mapping data** (M1) is sourced from the OWASP MASTG repo
  (MIT/CC-BY-4.0 style project data), vendored/cached locally — not a code
  dependency.
- Docker images: `python:3.11-slim` (PSF license) and `redis:7-alpine`
  (BSD-3-Clause). The JVM bundled in M1 is an OpenJDK distribution.
- This file is informational: the MIT posture above is the constraint that
  governs future dependency additions — run the audit check before adding any
  new dependency.
