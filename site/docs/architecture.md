# Architecture

MobARK (Mobile Application Reverse Kit) is a self-hosted dashboard for
static analysis of Android (APK) and iOS (IPA) apps, with a
chat-with-decompiled-code agent. This page is the module-level map,
kept in sync with [`ARCHITECTURE.md`](https://github.com/suwasto/MobARK/blob/main/ARCHITECTURE.md);
the interactive entity graph lives in `graphify-out/graph.html` (rebuild
with the graphify skill / `graphify update .`).

## Project structure

```text
.
├── docker-compose.yml          # app + worker + redis + searxng (always-on)
├── backend/                    # FastAPI app + RQ worker (Python 3.11)
│   ├── app/
│   │   ├── api/routes/         # /api/v1 routers (health · auth · scans · models · search)
│   │   ├── agent/              # chat loop + SSE · tools · insights · chat sessions
│   │   ├── analysis/           # orchestrator · Android/iOS stages · edits · rebuild · report/PDF
│   │   ├── auth/               # users · sessions · OAuth · per-user key vault
│   │   ├── graph/              # per-scan code graph (graphify)
│   │   ├── model/              # LLM providers · per-user BackendStore · client · health
│   │   ├── search/             # search providers · SearchStore · SearXNG client · web_fetch
│   │   ├── workers/            # RQ jobs (run_scan · decode · graph · rebuild)
│   │   ├── cli.py              # host operator CLI (scan/jobs/graph/agent/auth)
│   │   ├── config.py           # env-driven settings (MOBARK_* prefix)
│   │   ├── db.py               # SQLAlchemy engine + session
│   │   └── main.py             # FastAPI app + SPA serving
│   ├── alembic/                # schema migrations
│   ├── tests/                  # pytest suite (unit; integration marked)
│   └── worker.py               # RQ worker entrypoint
├── frontend/                   # React SPA (Vite + Tailwind v4, TypeScript)
│   └── src/
│       ├── components/         # panels · agent dock · settings · auth views · code viewer
│       ├── api/                # typed API client (REST + SSE)
│       ├── hooks/              # chat · upload · settings · resize/persistence
│       ├── lib/                # sse · markdown · formatting helpers
│       └── state/              # app context + localStorage persistence
├── docker/                     # Dockerfile.app · bundled SearXNG settings
├── scripts/                    # e2e gates · asset sync (wordmark · social preview)
├── site/                       # public MkDocs docs (site/docs) + assets
└── .github/                    # CI workflows · issue templates · dependabot
```

Runtime state that stays out of git: `data/` (uploads, per-user stores,
vaults, SQLite), `docs/` (internal milestone notes, gitignored) and
`graphify-out/` (generated code graphs).

## Component diagram

```mermaid
flowchart LR
    subgraph Browser["Browser"]
        SPA["React SPA (Vite + Tailwind v4)<br/>panels · agent dock · settings · auth views"]
    end

    subgraph Compose["docker compose: app · worker · redis · searxng"]
        API["FastAPI app (:8000)<br/>alembic upgrade + uvicorn"]

        subgraph APILayer["API routes /api/v1"]
            R_AUTH["auth: register/login/OAuth<br/>session cookie + vault unlock"]
            R_HEALTH["health"]
            R_SCANS["scans: upload · findings ·<br/>decompiler · chat/SSE · edits ·<br/>rebuild · report · graph · sessions"]
            R_MODELS["models: BYOK backends<br/>probe · list · health"]
            R_SEARCH["search: backends CRUD ·<br/>test · start engine"]
        end

        subgraph Services["Backend services"]
            AGENT["agent: chat loop · tools<br/>context · insights · sessions"]
            ANALYSIS["analysis: orchestrator<br/>Android (jadx/semgrep/gitleaks/mastg/apktool)<br/>iOS (LIEF/plist/macho/entitlements)"]
            MODEL["model: providers (ollama/lm-studio/<br/>openai/anthropic/gemini/…)<br/>BackendStore (per-user) · client · health"]
            SEARCHSVC["search: providers · SearchStore<br/>SearXNG client (SSRF-guarded) · web_fetch"]
            GRAPH["graph: per-scan code graph<br/>explorer data + search/hubs/node"]
            AUTH["auth: users · sessions · oauth · vault<br/>(per-user API-key vault)"]
            WORKER["RQ worker: jobs.py<br/>run_scan · apktool decode ·<br/>graph build · rebuild"]
        end

        REDIS[("Redis: RQ queue")]
        SEARXNG["SearXNG (:8888)<br/>bundled search engine (AGPL boundary)"]
    end

    DB[("SQLite /data/mobark.db<br/>scans · findings · edits · builds<br/>chat sessions · users<br/>sessions.vault_wrap (MK under token)")]
    FILES[("data dir /data/work/{scan}<br/>uploads · decompiled trees ·<br/>graphs · caches · builds")]
    VAULT[("data dir /data/users/{uid}/<br/>key_wrap.json (MK under password)<br/>per-user model/search stores<br/>(API keys as vault blobs)")]
    CTX["request context (per request)<br/>current_user_id · current_master_key"]

    LLM["Local LLM (Ollama / LM Studio)<br/>host.docker.internal"]
    CLOUD["Cloud LLMs (BYOK)<br/>OpenAI · Anthropic · Gemini · …"]
    GH["GitHub / Google OAuth"]

    SPA -->|HTTP /api/v1| API
    API --> R_AUTH & R_HEALTH & R_SCANS & R_MODELS & R_SEARCH
    R_SCANS --> AGENT & ANALYSIS & GRAPH & WORKER
    R_MODELS --> MODEL
    R_SEARCH --> SEARCHSVC
    R_AUTH --> AUTH
    AGENT --> MODEL
    AGENT --> SEARCHSVC
    AGENT --> ANALYSIS
    AGENT --> GRAPH
    ANALYSIS --> FILES
    ANALYSIS --> DB
    MODEL --> LLM
    MODEL --> CLOUD
    SEARCHSVC --> SEARXNG
    AUTH -->|password → scrypt KEK<br/>create/unlock MK| VAULT
    WORKER --> REDIS
    API --> REDIS
    API --> DB
    API --> FILES
    AUTH --> GH
    API --> SPA

    %% per-user store + vault flow
    AUTH -->|MK wrapped under token<br/>→ sessions.vault_wrap| DB
    API -->|cookie token + vault_wrap<br/>→ unwrap MK| DB
    API -->|guard sets per request| CTX
    CTX --> MODEL
    CTX --> SEARCHSVC
    MODEL -->|resolve store · unwrap key blobs| VAULT
    SEARCHSVC -->|resolve store · unwrap key blobs| VAULT
```

## How the pieces fit

- **Single origin.** FastAPI serves the built SPA at `/` (with an SPA
  fallback) plus the `/api/v1` routes: no separate static server.
  Backend-only dev runs without `frontend/dist`; the root then returns a
  bare API banner.
- **Auth is the outer gate.** `health` and `auth` are the only open
  routers; every other `/api/v1` router depends on `get_current_user`
  (session cookie → user). `MOBARK_AUTH_ENABLED=0` restores the fully-open
  single-user mode (dev/CI parity). All scan-keyed routes resolve the owner
  from the request context (`request_ctx`), so isolation is structural.
- **Per-user stores + vault.** Model/search BYOK configs live in
  `data/users/<uid>/`; API keys are stored there as AES-GCM vault blobs
  under a per-user master key (MK) that never touches disk in plaintext.
  The MK is wrapped under the login password (scrypt KEK) in
  `key_wrap.json` at register/login, then re-wrapped under the raw session
  token into `sessions.vault_wrap`; every guarded request unwraps it from
  the cookie + session row into the request context (`current_user_id`,
  `current_master_key`), which the store factories read to decrypt keys at
  use. OAuth-only accounts (no password) unlock the same vault with a
  dedicated passphrase per session. The agent loop receives `user_id` +
  `master_key` explicitly because it runs on a worker thread that does not
  inherit the request thread's contextvars.
- **Long work is async.** Scan analysis, apktool decode, code-graph
  builds, and rebuilds are RQ jobs enqueued by the API and run by the
  worker over Redis: both services share the SQLite DB and data dir.
- **Agent = tool-using chat.** The chat loop layers: findings
  context (Layer 1), code/file tools (Layer 2), graph tools (Layer 3),
  edit/recompile tools, and opt-in web research (`web_search` /
  `web_fetch` through the bundled SearXNG: SSRF-guarded, AGPL boundary
  kept by talking HTTP JSON only). Streaming is SSE
  (`POST /scans/{id}/chat/stream`).
- **Analysis pipeline.** The orchestrator runs Android stages
  (manifest, jadx decompile, semgrep MASTG rules, gitleaks secrets,
  dependency inventory, apktool decode on demand) and iOS stages
  (unzip, Info.plist, Mach-O via LIEF, entitlement carving, symbol
  import scanning) into persisted `Finding` rows, then computes the
  banded risk index (high | warning | info, deliberately not CVSS).

## Key modules

| Area | Path | Responsibility |
|---|---|---|
| API routes | `backend/app/api/routes/` | `health` · `auth` · `scans` · `models` · `search` |
| Auth | `backend/app/auth/` | users, sessions (sliding cookies), GitHub/Google OAuth, password-derived key vault |
| Agent | `backend/app/agent/` | chat loop + SSE, tools, findings context, insights, chat sessions |
| Analysis | `backend/app/analysis/` | orchestrator, Android/iOS stages, edits, rebuild, report (+PDF), risk, dependency inventory |
| Model | `backend/app/model/` | providers, per-user BackendStore, client (litellm), health/probe, fake dev model |
| Search | `backend/app/search/` | providers, SearchStore (one-active radio), SearXNG client, web_fetch |
| Graph | `backend/app/graph/` | per-scan graphify build + explorer endpoints |
| Workers | `backend/app/workers/` | RQ jobs + Redis wiring |
| CLI | `backend/app/cli.py` | host operator commands (run/scan/jobs/graph/agent/auth reset) |
| Frontend | `frontend/src/` | React SPA: panels, agent dock, settings, auth views, code viewer |
| Compose | `docker-compose.yml` | app + worker + redis + searxng (always-on), shared `/data` volume |

The interactive entity graph (module/function level, ~3.7k nodes) is
generated by the graphify skill into `graphify-out/graph.html`: run
`/graphify` in the repo to (re)build it.
