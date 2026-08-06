# MASA — Mobile Application Security Assistant

A self-hosted, local-first dashboard for mobile application security testing
(Android + iOS) with a built-in AI copilot. Static analysis of APK/IPA files,
chat-with-decompiled-code via a local LLM (Ollama / LM Studio), all without
any scan data leaving your machine.

- **License:** Apache-2.0 — see [LICENSE](LICENSE)
- **Docs:** [Product requirements](docs/masa-prd.md) · [Tech stack](docs/masa-techstack.md) · [Task list](docs/masa-tasks.md) · [UI mockup](docs/masa-dashboard-mockup.html) · [Dependency licenses](docs/licenses.md)

## Status

Milestone-driven development. **M0 (project scaffolding)** in progress:

- [x] Repo skeleton: `backend/` (FastAPI + RQ worker), `frontend/` (React + Vite), `docker/`
- [x] `docker-compose.yml`: `app` + `worker` + `redis` (searxng added in M7)
- [x] FastAPI base app with `/api/v1/health`
- [x] SQLite schema + Alembic migrations for `scans` and `findings`
- [x] Redis + RQ worker wired up, tested with a dummy job
- [x] Dependency/license audit (`docs/licenses.md`)

## Quick start (Docker)

> Requires Docker with the Compose v2 plugin.

```bash
docker compose up --build
```

Then open http://localhost:8000/api/v1/health — you should see
`{"status":"ok","redis_ok":true,"db_ok":true,...}`.

## Local development

### Backend (Python 3.11+)

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
alembic upgrade head          # create the SQLite schema
uvicorn app.main:app --reload # http://localhost:8000
```

Tests:

```bash
pytest                       # unit tests (no services needed)
```

RQ integration tests need Redis + a running worker. With the compose stack up
(the `redis` service isn't published to the host, so run them inside the
worker container):

```bash
docker compose exec worker sh -c "pip install pytest httpx && python -m pytest tests/test_worker.py -m integration"
```

Or locally with a Redis on `localhost:6379` and `python worker.py` running in
a second terminal: `pytest -m integration`.

Lint: `ruff check .`

### Frontend (Node 18+)

```bash
cd frontend
npm install
npm run dev                  # http://localhost:5173 — proxies /api -> http://localhost:8000
```

## Configuration

All settings are optional and read from the `MASA_` environment prefix (see
[.env.example](.env.example)).

| Variable | Default | Purpose |
|---|---|---|
| `MASA_DATABASE_URL` | `sqlite:///./data/masa.db` | SQLite location |
| `MASA_REDIS_URL` | `redis://localhost:6379/0` | RQ queue/worker broker |
| `MASA_DATA_DIR` | `./data` | Uploads / decompiled output / graphs |
| `MASA_LOG_LEVEL` | `INFO` | Logging level |
