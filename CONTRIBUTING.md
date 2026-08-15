# Contributing to MobARK

Thanks for your interest! MobARK is a self-hosted, local-first mobile
application security testing dashboard. This guide covers how to set up
a dev environment, run the checks, and submit a pull request.

## Scope expectations

- Scan data must not leave the machine by default; LLM and search are
  user-supplied (local Ollama / LM Studio, or BYOK keys, or the bundled
  SearXNG). Features that would phone home by default are out of scope.
- **Apache-2.0 posture.** GPL/LGPL tools (Semgrep, LGPL-2.1; SearXNG,
  AGPL-3.0) are **subprocess-only: never imported**. The rest of the
  toolchain (jadx, apktool, gitleaks) is permissively licensed and
  invoked as CLIs anyway. New dependencies must be permissive (MIT /
  Apache-2.0 / BSD); run the license audit before adding one (see
  [Third-party licenses](site/docs/licenses.md)).
- Prefer **fewest changes** that address the issue; match existing
  conventions.

## Dev setup

### Backend (Python 3.11+)

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
alembic upgrade head          # create the SQLite schema
uvicorn app.main:app --reload # http://localhost:8000
```

### Frontend (Node 18+)

```bash
cd frontend
npm install
npm run dev                  # http://localhost:5173 - proxies /api -> http://localhost:8000
```

### Full stack (Docker)

```bash
docker compose up --build    # http://localhost:8000
```

Register the first account (it becomes the admin). For local demos the
documented test users are `admin` / `password123` and `alice` /
`password123`: see [site/docs/quickstart.md](site/docs/quickstart.md).

## Checks (run before submitting)

```bash
# Backend: tests + lint
cd backend && .venv/bin/python -m pytest      # unit tests (integration excluded by default)
cd backend && .venv/bin/ruff check .

# Frontend: typecheck + build
cd frontend && npm run build                   # tsc -b && vite build

# Docs site (if you touched site/): build locally
python3 -m venv /tmp/mobark-docs-venv && /tmp/mobark-docs-venv/bin/pip install mkdocs mkdocs-material
/tmp/mobark-docs-venv/bin/mkdocs build
```

## Pull request flow

1. Fork the repo and create a branch off `main`.
2. Make your change: one logical change per PR, with tests.
3. Run the checks above (they run in CI too).
4. Open the PR against `main`; describe the change and how you verified
   it (tests run, manual steps).

## Issue templates

Use the issue templates for bug reports and feature requests: they
prompt for the environment and reproduction steps that make security-
tool issues actionable.

## Reporting security issues

Do **not** open a public issue for a security vulnerability. Report it
via the private path: see [SECURITY.md](SECURITY.md).
