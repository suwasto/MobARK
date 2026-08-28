# graphify
- **graphify** (`~/.claude/skills/graphify/SKILL.md`) - any input to knowledge graph. Trigger: `/graphify`
When the user types `/graphify`, use the installed graphify skill or instructions before doing anything else.


# MobARK

MobARK (Mobile Application Reverse Kit), formerly MASA (renamed Aug 15,
2026: the old name collided with Google's MASA Mobile App Security
Assessment program; `github.com/suwasto/masa` redirects to
`github.com/suwasto/MobARK`). Apache-2.0, copyright Anang Suwasto.

## What this project is

A **self-hosted web application** (React SPA + FastAPI backend, deployed
as one `docker compose` stack) for mobile application security testing:
Android (APK) and iOS (IPA) static analysis, an AI Agent that chats with
the decompiled code, Android edit-and-recompile, and deterministic
Markdown/PDF reports. Data stays on the deployer's own infrastructure by
default; the only outbound traffic is opt-in agent web research.

> **Wording (Aug 16, 2026):** the docs say **self-hosted**, not
> local-first, and the privacy claim is "nothing leaves your
> infrastructure / your install" (not "your machine"). See the change
> log at the bottom.

## Where the real docs live

`docs/` is **GITIGNORED/untracked** (deliberate: ~44MB of sample
APKs/IPAs/icons/mockups don't belong in git). The files remain on disk.
Read them via explicit paths (read_files works regardless of gitignore);
SEARCH them with the `--no-ignore` rg flag (default code-search respects
.gitignore and will silently miss docs/).

- `docs/mobark-prd.md` — product requirements
- `docs/mobark-techstack.md` — tech stack + decisions
- `docs/mobark-tasks.md` — granular task checklist (gitignored)
- `docs/mobark-*.html` — dashboard mockups
- `docs/licenses.md` — license audit (tracked copy: `site/docs/licenses.md`)
- `docs/progress/M*.md` — per-milestone plans + implementation records
  (M0–M10; historical, kept on disk)
- `docs/InsecureBankv2.apk` + `docs/iBugBazaar.ipa` — sample artifacts

The **public docs site** lives in the TRACKED `site/` dir (MkDocs +
Material → GitHub Pages, `mkdocs.yml` → `site/docs/*.md`): curated, not
synced from `docs/`. Editing `site/` is the committed surface. Build
locally: `python3 -m venv /tmp/mobark-docs-venv && .../pip install
mkdocs mkdocs-material && .../mkdocs build`.

## Hard constraints

- **Apache-2.0 only**: permissive imports only (MIT/Apache-2.0/BSD).
  GPL/LGPL tools run subprocess/container only, never imported: Semgrep
  (LGPL-2.1), SearXNG (AGPL-3.0), trafilatura (Apache-2.0 only at
  >=1.8.0). jadx/apktool/gitleaks are permissive CLIs; ldid is not GPL.
- **No default outbound calls / data exfiltration**: the default
  configuration makes no network calls except the opt-in agent web
  research. Features that would phone home by default are out of scope.
- **Scan data stays on the deployer's host(s)**: per-user data isolation
  is structural (foreign scans read as 404, no existence leak).

## Architecture (see ARCHITECTURE.md + site/docs/architecture.md)

One compose stack: `app` (FastAPI, serves the built React SPA at `/`
+ `/api/v1`) + `worker` (RQ) + `redis` + `searxng` (bundled search
engine, always-on since Aug 14). Shared SQLite DB + `data/` dir
(uploads, per-scan work, per-user stores/vaults).

- **Auth is the outer gate.** `health` + `auth` are the only open
  routers; everything else requires a session cookie. `MOBARK_AUTH_ENABLED=0`
  restores the fully-open single-user dev/CI mode. First registered user
  becomes admin (partial unique index) + claims unowned scans. OAuth
  (GitHub/Google) is env-only.
- **Per-user stores + vault.** Model/search BYOK configs live under
  `data/users/<uid>/`; API keys are AES-GCM blobs under a per-user master
  key (MK) that never touches disk in plaintext. MK is wrapped under the
  login password (scrypt KEK) in `key_wrap.json`, then re-wrapped under
  the session token in `sessions.vault_wrap`; each guarded request unwraps
  it into the request context (`current_user_id`, `current_master_key`).
  OAuth-only accounts unlock with a passphrase per session. The agent
  loop receives `user_id` + `master_key` explicitly (worker thread, no
  inherited contextvars).
- **Long work is async.** Scan analysis, apktool decode, code-graph
  builds, and rebuilds are RQ jobs shared over Redis.
- **Agent = tool-using chat.** Context layers: findings (L1), code/file
  tools (L2), graph tools (L3), edit tools, opt-in web research. SSE
  streaming (`POST /scans/{id}/chat/stream`). RAG/embeddings were
  DELETED (too slow); the three non-embedding layers replace them.
- **Analysis pipeline.** Android: manifest, jadx decompile, semgrep MASTG
  rules, gitleaks secrets, dependency inventory, on-demand apktool
  decode. iOS: unzip, Info.plist, Mach-O via LIEF, entitlements, symbol
  import scanning. Then the banded risk index (see below).
- **Edit & recompile: Android only** (iOS stays read-only; ldid resign
  deferred to v1.1). apktool decode is on-demand; edits are DB diffs
  applied at rebuild onto a fresh copy of the decode (never silent tree
  edits); rebuild = apply → `apktool b` → `zipalign -f 4` → `apksigner
  sign` → `apksigner verify`. One install-scoped test keystore
  (`data/mobark-test.jks`, random passphrase, 0600).
- **Reports are deterministic, no AI dependency.** Assembled from
  persisted scan data only; a no-model exec summary + per-finding
  explanations fall back to deterministic text (`_auto_summary`,
  `auto_explain.py`). PDF via reportlab platypus (BSD) + python-markdown;
  wordmark vendored into `backend/app/analysis/wordmark_data.py` from the
  frontend SVG (`scripts/sync_wordmark.py`).

## Scoring model (current, supersedes all older log entries)

Findings vocabulary: `high | warning | info` (no critical, no
medium/low — migrations 0016 + 0017 re-scored). Risk = banded index:
worst finding picks the band (high 80–89 / warning 55–69 /
info never scores), +1 per extra finding at that band
(`int(0.9*(n-1)+0.5)`) capped at the band ceiling; `security = 100 −
risk`. Bands never overlap (any high ≥ 80 > any warning-only ≤ 69).

## Key decisions that still govern future work

- Model/search providers are **BYOK**: local (Ollama/LM Studio) + cloud
  (OpenAI/Anthropic/Gemini/DeepSeek/OpenRouter/custom). BYOK backends
  seed only when a real key is configured; the store file is source of
  truth. Gemini/Anthropic model lists are FETCHED LIVE (curated lists
  are offline fallbacks only).
- Search: bundled SearXNG (AGPL boundary: unmodified container, HTTP
  JSON only) + keyed providers (brave/serper/mojeek); one Active engine
  at a time (radio); `web_fetch` is SSRF-guarded at every hop.
- The dev-only **fake model** (`MOBARK_FAKE_MODEL=1`) demos the full
  agent loop (tools, streaming, web research, edit proposals) with zero
  Ollama. Remember: pydantic-settings needs explicit
  `validation_alias="MOBARK_FAKE_MODEL"` (the prefix is not re-applied).
- Chat sessions are persisted server-side (DB), per-scan; `@file` mention
  chips in the dock feed the agent `mentioned_files`.
- Graphify code graph is Android-only in v1 (iOS has no source files).
- `docker compose build app` does NOT rebuild the worker image (separate
  tag): always `docker compose build` (both) when analysis code changes.

## Operational notes (dev/CI)

- Backend: `backend/.venv`, Python 3.11+; `pytest` unit tests (integration
  marked, need Redis + worker), `ruff check .`. Frontend: `npm run build`
  (tsc -b && vite build). Full stack: `docker compose up --build`.
- Migration head is **0017** (see `backend/alembic/versions/`).
- E2E scripts: `scripts/e2e_auth.sh`, `scripts/e2e_report.sh`,
  `scripts/e2e_gemini.sh`, `scripts/render_social_preview.sh` (headless
  Chrome PNG), `scripts/sync_wordmark.py`.

## Change log (checkpoints marked done)

- **Aug 16, 2026 — DONE: docs wording "local-first" → "self-hosted".**
  All user-facing copy swapped to self-hosted (README, ARCHITECTURE,
  CONTRIBUTING, SECURITY, site/docs, mkdocs description, docker-compose
  comment, .github templates, social-preview tagline + PNG regenerated).
  Privacy claims now say "your infrastructure / your install". Bonus:
  site/docs/index.md's stale "demo users" line repointed to the
  first-account flow. Left alone: this file's past log (pre-slimming),
  code comments ("derived locally, no network"), and "local LLM" (a real
  local-vs-cloud contrast). Docs build verified (`mkdocs build` clean).

- **Aug 15, 2026 — DONE: rebrand MASA → MobARK + docs de-AI.** Logo
  retyped, repo renamed, 642 em dashes swept from tracked md, "Local-first
  is a hard constraint" dropped from CONTRIBUTING (kept the default
  no-exfil rule).

- **Aug 14–15, 2026 — DONE: M9.1 auth + vault + severity rework.** (Detail
  now lives in `docs/progress/M9.1.md` / git history; this file keeps only
  the durable parts above.)
- **Aug 27, 2026 — DONE: M11 (V2 dynamic analysis) device + session
  foundation.** First V2 milestone. `backend/app/dynamic/` mirrors
  `analysis/` (`android/` + `ios/` subpackages behind one shared router,
  mounted in `main.py` under `Depends(get_current_user)` at
  `/api/v1/dynamic/...`). Sessions are **scan-scoped + single-active**
  (FR-D5): the `dynamic_sessions` table (migration **0018**) is the durable
  lifecycle; the LIVE frida handle lives process-locally in
  `dynamic/base.py::ActiveSession`, torn down on disconnect. Devices are
  subprocess/CLI-only (adb + pymobiledevice3, the `*_CMD` pattern); frida
  imported lazily behind the platform-client seam. Per-check preflight
  (never a raw exception); `DynamicError` hierarchy → global FastAPI
  exception handler (404 no-session/foreign-scan, 409 preflight-reject or
  already-active, 502 tool-unreachable). `MOBARK_CORELLIUM_BASE_URL`/
  `_API_KEY` config knobs land (empty = off); the Corellium client is M17.
  Build posture: **backend + fake devices** — real attach is an owner manual
  checkpoint. 911 backend tests green + ruff clean; frontend untouched.

- **Aug 27, 2026 — DONE: M12 (V2 dynamic) live hooks + event stream.**
  `dynamic/events.py` owns the FR-D10 feed: `DynamicEvent`
  `{ts, source, tag, platform, text, code}` (source ∈ hook|bypass|net|note),
  a bounded per-session ring buffer + subscriber fan-out on the
  `ActiveSession.feed` slot (ephemeral, torn down on disconnect; the
  `dynamic_events` DB table ships in M15). Transport is **SSE**, not
  WebSocket (owner, Aug 27): v1 has zero WS infra, so M12 reuses the chat
  `StreamingResponse` pattern — `GET /api/v1/dynamic/session/events/stream`
  (`: ping` keepalive, `_stream_events` module-level generator, ends on
  disconnect) + `GET`/`POST /api/v1/dynamic/session/events` HTTP fallback
  (catch-up snapshot + observation push, platform/ts stamped server-side) +
  `GET /api/v1/dynamic/session/scripts` (default-hook registry). **Real,
  runnable frida hook scripts authored but NOT executed** (fake posture;
  real exec = owner manual checkpoint): `dynamic/scripts/android/*.js`
  (pinning validators + root-detection) + `ios/*.js` (ATS/pinning +
  jailbreak + Keychain) — the M15 built-in-library seed. **FR-D11
  (static-finding → bypass-suggestion) REMOVED at owner direction** (cost
  tokens, low value; authoring stays LLM-driven M16 / manual M15). Full
  backend suite green (927 passed / 1 skipped / 13 deselected, +16) + ruff
  clean; frontend untouched.

- **Aug 28, 2026 — DONE: M13 (V2 dynamic) device mirroring.** FR-D6/D7/D8.
  Mirror is the codebase's FIRST WebSocket (binary H.264/JPEG frames don't
  fit the SSE event feed, which stays as-is). `dynamic/mirror.py` `MirrorRelay`
  = the event-feed analogue (bounded frame store + subscriber fan-out + live
  latency ping/pong + the honest `continuous|polled` fidelity flag for
  FR-D7), hung off `ActiveSession.mirror` (created at connect, torn down on
  disconnect). Per-platform frame sources: `android/mirror.py` (continuous
  scrcpy-protocol, `*_CMD`-guarded, clean DynamicError 502 on missing tool)
  + `ios/mirror.py` (polled `screenshotr`, `polled=True`). **Critical
  routing constraint (verified with a probe): a router-level
  `Depends(get_current_user)` is `Request`-typed and breaks WebSocket routes,
  so the mirror WS lives on a dedicated `mirror_router` included WITHOUT the
  auth list-dep and authenticates IN-HANDLER** (cookie → `user_from_token`
  → `require_scan_access` on the active session's scan_id; 4401 bad-session /
  4404 no-session-or-foreign, never a leak; auth-off parity passes).
  Guarded control API (sits under `get_current_user`): `GET /session/mirror`
  (state) · `POST /session/mirror/publish` (base64 frame, the fake-posture
  HTTP fallback) · `POST .../start` + `.../stop` (live flag). The bridge
  thread polls the send queue with `get_nowait`+sleep — a blocking
  `asyncio.to_thread(queue.get)` thread is uncancellable and hangs the event
  loop teardown (debugged via a hung TestClient). Config: `scrcpy_cmd`,
  `mirror_poll_interval_seconds`, `mirror_frame_bytes`. Full backend suite
  green (952 passed / 1 skipped / 13 deselected, +25) + ruff clean;
  frontend untouched — **the Mirror panel UI defers to M18** (sidebar is the
  M18 dashboard contract; owner approved backend-first at kickoff). Real
  on-device mirroring = owner manual checkpoint.
