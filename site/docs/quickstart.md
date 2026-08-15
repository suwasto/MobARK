# Quickstart

## Docker (recommended)

> Requires Docker with the Compose v2 plugin.

```bash
docker compose up --build
```

Then open http://localhost:8000.

The stack is fully local: `app` (FastAPI) + `worker` (RQ) + `redis` +
`searxng` (the agent's bundled search engine): a plain `docker compose
up` starts everything.

### First run: authentication

A fresh install lands on the **register/login screen**: auth is ON by
default. The **first account registered becomes the instance admin**
and adopts any pre-existing (unowned) scans.

Register an account, sign in, and upload an APK or IPA. MobARK analyzes it
locally: nothing leaves your machine by default.

#### Demo users (local installs)

For a quick local evaluation, register these two accounts:

| Username | Password     | Role    |
|----------|--------------|---------|
| `admin`  | `password123` | Admin: the first registered user |
| `alice`  | `password123` | Regular user |

Register `admin` **first** (it becomes the admin), then `alice` to see
per-user isolation in action: each account sees only its own scans, and
`admin`'s scans read as 404 for `alice` (no existence leak).

!!! danger "Demo credentials only"
    These are **local demo credentials** for trying the app: not
    seeded, not secure. Change them (or register your own accounts) on
    any install that faces a network. Never ship a public deployment
    with known passwords.

#### Skip auth entirely (dev/CI)

Set `MOBARK_AUTH_ENABLED=0` in `.env`: MobARK then behaves exactly as the
pre-auth single-user tool (the dev/CI parity mode).

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

RQ integration tests need Redis + a running worker. With the compose
stack up (the `redis` service isn't published to the host, so run them
inside the worker container):

```bash
docker compose exec worker sh -c "pip install pytest httpx && python -m pytest tests/test_worker.py -m integration"
```

Or locally with a Redis on `localhost:6379` and `python worker.py`
running in a second terminal: `pytest -m integration`.

Lint: `ruff check .`

### Frontend (Node 18+)

```bash
cd frontend
npm install
npm run dev                  # http://localhost:5173 - proxies /api -> http://localhost:8000
```

## Configuration

All settings are optional and read from the `MOBARK_` environment prefix
(see [.env.example](https://github.com/suwasto/MobARK/blob/main/.env.example)).

| Variable | Default | Purpose |
|---|---|---|
| `MOBARK_DATABASE_URL` | `sqlite:///./data/mobark.db` | SQLite location |
| `MOBARK_REDIS_URL` | `redis://localhost:6379/0` | RQ queue/worker broker |
| `MOBARK_DATA_DIR` | `./data` | Uploads / decompiled output / graphs |
| `MOBARK_LOG_LEVEL` | `INFO` | Logging level |
| `MOBARK_AUTH_ENABLED` | `1` | `0` restores the fully-open single-user behavior (dev/CI) |
| `MOBARK_SESSION_DAYS` | `7` | Session lifetime (sliding: refreshed on use) |
| `MOBARK_COOKIE_SECURE` | `0` | `1` when serving over TLS (session cookie gets the Secure attribute) |
| `MOBARK_GITHUB_CLIENT_ID` / `MOBARK_GITHUB_CLIENT_SECRET` | - | GitHub OAuth (login page shows the button only when both are set) |
| `MOBARK_GOOGLE_CLIENT_ID` / `MOBARK_GOOGLE_CLIENT_SECRET` | - | Google OAuth (same, configured-only button) |
| `MOBARK_PUBLIC_BASE_URL` | `http://localhost:8000` | Public origin: OAuth `redirect_uri`s are derived from it |

See [Authentication](auth.md) for the full auth surface (OAuth setup,
per-user isolation, the vault).
