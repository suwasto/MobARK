# Third-party licenses

**MASA itself is Apache-2.0** (see [LICENSE](https://github.com/suwasto/masa/blob/main/LICENSE)).
This page is the public attribution summary; the full audit (versions,
pins, decision history) lives in
[`docs/licenses.md`](https://github.com/suwasto/masa/blob/main/docs/licenses.md)
(in the repository working tree — it is gitignored).

## Compliance posture

MASA ships under Apache-2.0. Any **GPL/LGPL-licensed tool** in the stack
is invoked strictly as a **subprocess / separate container** and never
imported as a library — the copyleft never crosses a process boundary:

- **Semgrep** (LGPL-2.1) — CLI subprocess from an isolated venv
- **SearXNG** (AGPL-3.0) — unmodified separate container, reached only
  over its HTTP JSON API

All libraries actually imported by MASA are permissive (MIT /
Apache-2.0 / BSD).

## Backend runtime dependencies (pinned in `backend/requirements.txt`)

| Package | License |
|---|---|
| fastapi | MIT |
| starlette | BSD-3-Clause |
| uvicorn | BSD-3-Clause |
| sqlalchemy | MIT |
| alembic | MIT |
| pydantic / pydantic-settings | MIT |
| redis / rq | MIT / BSD-3-Clause |
| python-multipart | MIT |
| androguard | Apache-2.0 |
| PyYAML | MIT |
| LIEF | Apache-2.0 |
| LiteLLM | MIT |
| httpx | BSD-3-Clause |
| trafilatura (≥1.8.0) | Apache-2.0 |
| cryptography | Apache-2.0 (or BSD) |
| reportlab | BSD-3-Clause |
| markdown (Python-Markdown) | BSD-3-Clause |
| graphifyy | MIT/Apache-2.0 dual (CLI subprocess) |

**M9.1 note:** auth + vault add **zero** new runtime dependencies —
passwords use stdlib `hashlib.scrypt`, OAuth is hand-rolled over the
already-pinned `httpx`, session tokens use `secrets` + `hashlib`.

## Frontend dependencies (in `frontend/package.json`)

| Package | License |
|---|---|
| react / react-dom | MIT |
| react-markdown | MIT |
| remark-gfm / remark-breaks | MIT |
| vite | MIT |
| typescript | Apache-2.0 |
| @vitejs/plugin-react | MIT |
| tailwindcss + @tailwindcss/vite | MIT |
| @fontsource/ibm-plex-sans / mono | SIL OFL 1.1 |
| highlight.js | BSD-3-Clause |
| @types/react, @types/react-dom, @types/node | MIT (DefinitelyTyped) |

## CLI tools (subprocess-only, baked into the app image)

| Tool | License |
|---|---|
| jadx | Apache-2.0 |
| Gitleaks | MIT |
| Semgrep | LGPL-2.1 (isolated venv, subprocess-only) |
| apktool | Apache-2.0 |
| zipalign / apksigner (Android build-tools) | Apache-2.0 |

## Container services

| Service | License | Posture |
|---|---|---|
| Redis (`redis:7-alpine`) | BSD-3-Clause | RQ broker |
| SearXNG (`searxng/searxng`) | AGPL-3.0 | unmodified container over HTTP JSON only |

## Data & rules (not code dependencies)

- **OWASP MASTG mapping + vendored semgrep rules** — CC BY-SA 4.0
  (two rules rewritten from scratch to remove GPL-3.0 traced bodies).
- **Sample test artifacts** — InsecureBankv2.apk, iBugBazaar.ipa
  (used for integration testing only).

The standing rule: run the audit check (`cd backend &&
.venv/bin/pip-licenses --format=plain --with-urls`) before adding any
new dependency.
