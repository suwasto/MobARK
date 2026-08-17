# Quickstart

## Docker (recommended)

> Requires Docker with the Compose v2 plugin. Prebuilt images are
> **`linux/amd64`** in v0.1.0 — the bundled analysis toolchain is
> x86_64-only (see [RELEASING.md](https://github.com/suwasto/MobARK/blob/main/RELEASING.md)
> before running on arm64 hosts).

### Install a release from Docker Hub

MobARK runs as **four containers** that `docker-compose.yml`
orchestrates: `app` (the web UI + API), `worker` (runs the analysis),
`redis` (the job queue between them), and `searxng` (the search engine
the agent's web research uses). Everything is downloaded from **Docker
Hub** — a release install never builds or clones the source code.

**Step 1 — Download the config files.** `docker-compose.yml` is the
recipe that tells Docker which images to run and how to connect them;
`.env` holds your settings. In a folder of your choice:

```bash
curl -O https://raw.githubusercontent.com/suwasto/MobARK/main/docker-compose.yml
curl -O https://raw.githubusercontent.com/suwasto/MobARK/main/.env.example
mv .env.example .env
mkdir -p docker/searxng
curl -o docker/searxng/settings.yml https://raw.githubusercontent.com/suwasto/MobARK/main/docker/searxng/settings.yml
```

That last file is the SearXNG config the stack mounts into the search
container (it enables the JSON API the agent's web research searches
through) — the stack will not start without it.

**Step 2 — Download the images.** `docker compose pull` reads the
recipe and downloads the three images it references from Docker Hub:
`suwasto/mobark:0.1.0` (the app + worker), `redis:7-alpine`, and
`searxng/searxng:latest`. Nothing runs yet — this step is just the
download:

```bash
docker compose pull
```

**Step 3 — Start the stack.** `docker compose up` launches the four
containers — `app` and `worker` both run the `suwasto/mobark` image
with different commands — and starts them wired together:

```bash
docker compose up
```

To pin another release instead of `0.1.0`, set `MOBARK_IMAGE_TAG=<version>`
in `.env`, then re-run `docker compose pull` and `docker compose up`.

### Build from source (dev)

```bash
git clone https://github.com/suwasto/MobARK.git
cd MobARK
docker compose up --build
```

Then open http://localhost:8000.

### First run: authentication

A fresh install lands on the **register/login screen**: auth is ON by
default. The **first account registered becomes the instance admin**
and adopts any pre-existing (unowned) scans.

Register an account, sign in, and upload an APK or IPA. MobARK analyzes it
on your own infrastructure: nothing leaves your install by default.

!!! note "Platform coverage"
    Android (APK) and iOS (IPA) both get full static analysis and the
    AI Agent. Past that, Android is ahead: **edit & recompile**
    (apktool decode, smali edits, resigned test APK) is Android-only -
    iOS stays read-only in v1, and rebuilding an IPA would need an
    Apple Developer account and signing certificates. See
    [Features](features.md) for the full parity table.

#### First account is the admin

There are no seeded accounts: the **first account you register becomes
the instance admin**, and every later account is a regular user who
sees only their own scans (a foreign scan reads as 404: no existence
leak). The first account also automatically **claims any unowned
scans** — data scanned while auth was disabled (pre-auth builds) or via
the CLI without `--user` — so it appears on the admin's dashboard.

For example, register a first account with the username of your choice
(e.g. `admin`) and **a password you pick yourself**: the `password123`
used throughout these docs is only an example, never a default or
seeded credential.

!!! danger "Example credentials only"
    Credentials shown in these docs (`password123`, etc.) are
    **examples only**: nothing is pre-seeded and no account ships with
    a known password. Use real, unique passwords on any install that
    faces a network, and never ship a public deployment with example
    passwords.

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
| `MOBARK_IMAGE_TAG` | `0.1.0` | Compose-only: which `suwasto/mobark` tag to run (`docker compose pull`) |
| `MOBARK_VERSION` | `0.1.0` | Compose-only: version baked into locally-built images |

See [Authentication](auth.md) for the full auth surface (OAuth setup,
per-user isolation, the vault).
