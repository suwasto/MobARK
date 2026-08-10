# graphify
- **graphify** (`~/.claude/skills/graphify/SKILL.md`) - any input to knowledge graph. Trigger: `/graphify`
When the user types `/graphify`, use the installed graphify skill or instructions before doing anything else.


# MASA

Read docs/masa-prd.md, docs/masa-techstack.md, docs/masa-tasks.md
before doing anything.

Hard constraints: Apache-2.0 license (was MIT — relicensed Aug 3 2026,
copyright Anang Suwasto). GPL/LGPL tools (Semgrep, apktool,
jadx, ldid) — subprocess only, never imported. Local-first, no
network calls except opt-in web research.

## Status
M0 — completed (Aug 2, 2026). Repo skeleton (`backend/`, `frontend/`, `docker/`),
`docker-compose.yml` (app + worker + redis), FastAPI health endpoint,
SQLite schema + Alembic migrations for scans/findings, RQ + Redis wired and
tested with a dummy job, dependency/license audit (`docs/licenses.md`).
Validated end-to-end: `docker compose up` green, 7 unit + 2 integration tests
passing, committed as `80ccdde` on branch `main`.

M1 — COMPLETE (Aug 3, 2026). See `docs/progress/M1.md`.
Built & VALIDATED: `backend/app/analysis/` engine (jadx decompile, androguard
manifest/cert/netsec, gitleaks + semgrep subprocess wrappers with normalizers,
orchestrator with per-stage error policy); MASTG data vendored (292 tests @
commit d7fd7d45636ef9acbae89d0247e8dd748aa6918d, 46 android semgrep rules + 8
curated rules); `findings.mastg_test_id` column + migration 0002; RQ job
`run_android_scan`; CLI `python -m app.cli {run,scan,jobs}`; multi-stage
Dockerfile (JRE + jadx 1.5.6 + gitleaks 8.30.1 + semgrep 1.172.0 in its own venv).
ALL gates verified by running (Aug 3): CLI `run` on `docs/InsecureBankv2.apk` →
523 findings (16 androguard, 507 semgrep — 22 `scope: app`, 485
`third_party_library`; gitleaks 0), 0 warnings; image builds at 389 MB content
(within the 350–450 MB gate); migration at 0002 + RQ path proven (worker ran
scan 1 and scan 2 → done, 523 findings persisted in the compose volume DB);
`docker compose up` green, `/api/v1/health` ok; 27 unit + 6 integration tests
pass, ruff clean.
Fixed: API container crash-loop — the pip `semgrep` install upgraded starlette
to 1.3.1 (breaking fastapi 0.115.6's <0.42 pin). Fix: semgrep now lives in
`/opt/semgrep-venv` (symlinked onto PATH) so its starlette>=0.49 dep tree can't
clash with the app's. Earlier fixes preserved: enrichment relative-path bug,
test_mastg.py alias, ruff violations, signing-certificate asn1crypto API,
semgrep scope tagging.
Env notes: compose uses `masa_masa-data` volume (NOT `masa-data` — an empty
stray volume of that name is a leftover and can be removed). `masa-smoke-redis`
(host port 6379) is a leftover M0 container that host-side integration tests
use as their Redis. Host tools: jadx 1.5.6, gitleaks 8.30.1, semgrep 1.172.0
(Homebrew), java 17; backend venv at `backend/.venv` (Python 3.12).

M2 — iOS static core — planned (Aug 3 2026), not started. Plan in
docs/progress/M2.md; task list updated in docs/masa-tasks.md. Key research
notes: LIEF (v0.15+) has a first-class `code_signature` object but entitlements
still need plist carving + plistlib; `header.has(FLAGS.PIE)` for PIE;
`LC_ENCRYPTION_INFO` cryptid for FairPlay; stack canary via `___stack_chk_guard`
symbol. Sample IPA candidate: iBugBazaar (MASTG-APP-0030, payatu/iBugBazaar,
prebuilt IPA in releases); fallbacks DVIA-v2 (MASTG-APP-0024), iGoat-Swift
(MASTG-APP-0028).

M3 — COMPLETE (Aug 5, 2026). See `docs/progress/M3.md`.

M4 — Agent context layers (Layers 1-3) — **RAG/embedding DELETED from v1**
(owner decision Aug 6 2026, not deferred). CPU embedding of a 3MB APK took
5–15 min before chat was usable → replaced by three non-embedding layers.
Status: built + unit-tested (167 tests, ruff clean); live-model QA is MANUAL
(owner shut down Ollama during development — do not attempt live LLM tests;
mocked unit tests only). Plan/progress: `docs/progress/M4.md`.

Built: `agent/context.py` (Layer 1 — full findings set, precision-tagged
`[file/line]` vs `[binary-level presence only]`, platform whitelists,
**androguard never in iOS context**); `agent/tools.py` (Layer 2
`search_code(pattern, glob)` + `read_file(path, line_range)` — no platform
branching, traversal-guarded; Layer 3 `graph_query`/`graph_path`/
`graph_explain` wrappers); `agent/chat.py` (bounded ≤3-round tool loop,
context-only fallback, citations from file:line refs); `analysis/ios/symbols.py`
(the **import-table scanner** — named iOS source: CC_MD5/CC_SHA1/CC_DES/CCCrypt,
UIWebView, NSURLConnection cert-bypass selectors, ptrace/sysctl/syscall
anti-debug blocklist over Mach-O imports); iOS binary profile info findings
(exported symbols, linked dylibs, architectures, ARC, full entitlement set —
what was hidden in unpersisted result.meta); `resources/gitleaks_ios.toml`
(kSecAttrAccessibleAlways goes through Gitleaks, string-level not import-level);
`build_graph_scan` RQ job chained after run_scan (Android-only); API
`POST /scans/{id}/chat` (Layers 1-3) + `GET /scans/{id}/graph` (filesystem-
derived); CLI `graph build|query|path|explain` + `agent context|chat`.
Package `app/vector` renamed `app/graph` (no vector name remains); migration
0004 deleted (head = 0003; dev DBs at 0004 need `alembic downgrade 0003`);
chromadb + llama-index-core uninstalled.

**Validated Graphify CLI facts (0.9.32):** no `extract`/`export` subcommand —
headless build is `graphify update <dir> --no-cluster` (cwd = per-scan graph
dir); queries via `query|path|explain|affected --graph`; natural-language
`query` fails on code-only AST graphs → wrapper has a label/ID
substring-search fallback. Real numbers (InsecureBankv2): 46,177 nodes /
116,780 edges / 64 MB graph.json, zero LLM, ~1m17s. **InsecureBankv2 has no
cert-pinning code** — the working structural case is WebView/MyWebViewClient.java.
**iOS graph negative confirmed**: unpacked `.app` has 0 source-like files →
Graphify is Android-only in v1.

Remaining M4: manual QA with a real model (owner), stress (obfuscated +
large APK), go/no-go record, Docker image rebuild with new dep set (size
gate), M5 UI wiring after go/no-go.

**Follow-up (Aug 8, 2026 — graphify bug + Code maps tab):** (1) **M4 graph-build bug FIXED**: graphify 0.9.32 writes its output into the INPUT dir
(`<decompiled>/graphify-out/`), not the cwd — every chained build "succeeded"
(rc=0) while silently failing to produce a graph at `graph_path_for` and
polluting the decompiler tree with a 64 MB `graph.json`. `graphify.build` now
MOVES the input-dir `graphify-out/` into the per-scan graphs dir after a
successful run; `tree.py` excludes `graphify-out` from the decompiler walk
defensively. Live-verified in the container: `graph build 16` → 46,177 nodes /
116,780 edges, graph at `/data/graphs/16/`, decompiler tree clean.
(2) **Code maps tab (owner: "searchable explorer, auto-build, keep agent
preference")** — new dashboard tab between Decompiler and Report (Android
only; iOS shows the "Android-only" hint). The 64 MB `graph.json` never hits
the browser: `graphify.explorer_data()` compacts it once into a per-scan
`explorer.json` (public-shape node rows `id/label/file_type/file/line` +
`(source,target,relation)` links + degree map; module cache keyed by
path+mtime, bounded to the 4 most-recent graphs — cache evicts oldest) and
serves three endpoints: `GET /scans/{id}/graph/search?q=` (label-prefix >
label-substring > id-substring, `total` = pre-limit count), `GET
/scans/{id}/graph/hubs` (top-N by degree — the initial "Most connected"
view), `GET /scans/{id}/graph/node/{id}` (one node + in/out neighbors,
relation-tagged, deduped per direction, out-first sorted by neighbor degree,
capped 40; 404 unknown id). Shared `_require_graph` guard → 409 non-Android /
not-built. Frontend: `CodeMapsPanel.tsx` (debounced 300 ms search, hubs
initial view, detail pane with Outgoing/Incoming groups, per-row
Open-in-Decompiler jumps reusing `resolveTreePath`; requestId race guard on
node selection; `key={current.id}` remount per scan — review catch), `.codemap-*`
CSS + 760 px stack media query. Gates: **307 backend tests green + ruff
clean; tsc + vite build green.** Live-verified in compose on scan 16:
search `MyWebViewClient` → 5 hits with real files/lines, hub GoogleApiClient
degree 935 / 40 neighbors (28 out / 12 in), iOS scan 17 → clean 409, SPA
serves the new bundle, headless-Chrome DOM shows the full 6-tab bar with
Code maps between Decompiler and Report (chrome-devtools agent outage again
— DOM + code review covered the click-through).

M5 — **COMPLETE (Aug 8, 2026).** See `docs/progress/M5.md`.
Phases A–H + Phase I all green: the app image bundles the SPA
(`Dockerfile.app` frontend build stage → `/frontend/dist`) and `main.py`
serves index.html at `/` when dist exists; CLI-enqueued scan → worker → done
with SPA + assets + health served from FastAPI on :8000. Containerized e2e
re-verified after the Aug 8 follow-ups on BOTH platforms (Android
InsecureBankv2 + iOS iBugBazaar; see the Aug 8 follow-ups below). Loaded-state
browser checks passed; deep click-throughs partially blocked by the recurring
chrome-devtools outage (covered by code review + headless-Chrome DOM). One
post-completion owner checkpoint remains: manual model QA with a real model
(Ollama) — chat/explain/summary, not a blocker.

**Owner review follow-ups (Aug 7):** (1) **debuggable finding → critical**
(was high) — `analysis/manifest.py`. (2) **Overview score is now a SECURITY
score** (higher = better; low = red, high = green): security = 100 − risk;
`Scan.security_score` derived property (never stored), `ScanRead` exposes it,
summary prompt relabeled, `RiskGauge` → `SecurityGauge` with inverted ramp
+ labels. Verified in compose: InsecureBankv2 risk 40 → security 60,
debugable now critical (1C/4H/473M/2L/43I). (3) **Severity re-calibration (owner picks A+C, Aug 7; B declined)** —
Android curated: hostname-verifier + empty trust manager → **critical** via
`severity.py::SEMGREP_OVERRIDES`; WebView JS/file-access, hardcoded-key,
weak-cipher bumped to ERROR (→high). iOS: `setAllowsAnyHTTPSCertificate` →
critical, get-task-allow → medium (per-entitlement severities), empty
usage strings → low. MASTG vendored rules unchanged (B declined). Live
verified: debuggable critical, WebView-JS/hardcoded-key high, 1C/10H/467M/
2L/43I, risk 41 → security 59. 244 tests green. (4) **Scoring is now CVSS
4.0** (owner decision, same session): severity → representative CVSS 4.0
base score (critical 9.5 / high 8.0 / medium 5.5 / low 2.0 / info 0 — band
midpoints per the spec); overall **risk = round(10 × max(cvss))** — the
worst finding drives the score (owner chose max over mean). Securitygauge labels follow the CVSS 4.0 qualitative bands of the underlying risk (60
security → risk 40 → Medium, NOT High — owner complaint fixed) + a
`CVSS 4.0 · risk n/100 · band` caption; the arc color snaps to the band
(crimson ≤10 / amber 11–30 / olive 31–60 / moss 61–99 / emerald 100)
instead of a continuous ramp (owner follow-up, Aug 7). InsecureBankv2 (1 critical) now
scores risk 95 → **security 5**. (5) **Dashboard tab bar is sticky** —
Overview/Findings/Dependencies/Decompiler/Report stay visible while panel
content scrolls (`DashboardView`). (6) **Model pill dropdown gained a model
search box** (filters local + cloud groups, Escape clears first); the
"No models listed (is the server running?)" copy is now **local-only** —
cloud-opt backends say "No models listed — check the provider key in
Settings." (7) **Scan date accuracy fix**: SQLite drops tzinfo on
round-trip, so persisted timestamps serialized naive and browsers parsed
them as local time (hours off on non-UTC machines). `schemas.py` now
attaches UTC on serialization (`_utc_aware` on scan/finding `created_at`,
`checked_at`, `generated_at`) + `formatRelative` parses no-offset strings
as UTC as a belt-and-braces.
**Owner follow-up (Aug 8, 2026 — model-connection diagnostics):** probe +
agent chat were failing with a raw 500 / bare "Probe failed" for Ollama
model `ndavat/Nanbeige4.2-3B`. Root cause was environmental: host Ollama
0.30.6 predates the `nanbeige` (Looped Transformer) architecture in
llama.cpp — it needs Ollama v0.32.x+. App-side fixes so such failures
self-explain: `health._probe_completion` now returns `(ok, error)` and
`BackendHealth.error` carries the real upstream message (with an actionable
"upgrade Ollama" hint when the text says `unknown model architecture`);
BackendsTab renders `health.error` under the card; agent chat wraps
upstream LLM failures as `ChatUpstreamError` → **502** with the upstream
message (was an unhandled raw 500); `useChat` classifies 502 as
`'upstream'` with the detail in the bubble. 259 backend tests green, ruff
clean, tsc+vite build green.

**Owner review follow-ups (Aug 8, 2026):** (1) **Critical band REMOVED** —
findings vocabulary is now `high | medium | low | info` (`base.py::SEVERITIES`;
`risk.py::SEVERITY_CVSS` high 8.0 / medium 5.5 / low 2.0 / info 0 — max risk
is now 80, was 95). Producers of critical now emit high: debuggable manifest
finding, iOS `setAllowsAnyHTTPSCertificate` symbol rule, semgrep TLS-bypass
overrides, gitleaks direct-compromise rules. Migration **0005** rewrites
persisted `critical` → `high` AND recomputes every `done` scan's `risk_score`
under the new mapping (self-contained SQL; head is now 0005). Frontend: no
critical anywhere — stat boxes are High/Medium/Low/**Info**, `SecurityGauge`
bands re-mapped (risk 70–80 crimson worst → emerald 0; `Critical` band type
removed), tree dots/annotation labels/filter chips/agent greeting updated.
(2) **Top bar: single model pill → TWO searchable dropdowns** —
`components/ModelPicker.tsx` (replaces `ModelPill.tsx`): **Provider**
dropdown (every backend + `None (no AI)`), **Model** dropdown (served models
of the selected provider + `None`), both with search (Escape clears first).
**None linkage**: provider None → auto-clear all active models (model shows
None); model None → auto-clear the active provider. Picking a model PUTs
`{model, enabled:true}` + clears other enabled-with-model backends so
`pick_chat_backend` deterministically returns it. The **"Local-only" badge
is gone** (`TopBar` + `AppContext.localOnly` removed). (3) **Finding
suppression (per-finding + review toggle)**: `findings.suppressed` +
`suppressed_at` (migration 0005); `GET /scans/{id}/findings?include_suppressed=`
(default hides); `POST .../findings/{id}/suppress|unsuppress` (each recomputes
`Scan.risk_score`); suppressed findings excluded from risk score
(`compute_risk_score` skips `suppressed=True` via getattr — works for both
`FindingOut` and persisted `Finding`), AI summary, and agent Layer-1 context
(`agent/context.py`). Findings tab: per-row **Suppress/Restore** + **"Review
suppressed (n)"** toggle (dimmed rows); `useFindings` fetches with
`include_suppressed=true` once and splits active/suppressed client-side;
DashboardView re-fetches the scan after a toggle so the gauge updates.
(4) **"Suppressed (n)" Overview badge** — a clickable pill next to the stat
boxes showing the active scan's suppressed (false-positive) count; jumps to
the Findings review toggle; renders only when n > 0. (5) **UI polish (owner
review, Aug 8)**: gauge score moved INSIDE the SVG as a centered `<text>` +
`/100` tspan (no more arc overlap — was pulled up over the curve);
`.explain-btn` lost its stray `margin-top: 8px` so "AI explanation" and
"Suppress/Restore" sit inline on the same row. Gates: **256 backend tests
green + ruff clean; `tsc -b` + `vite build` green.**
**Containerized e2e re-verified after the Aug 8 changes — both platforms
(Aug 8):** both images rebuilt; migration 0005 applied to the persisted
volume (old scan rewritten: 1 critical → 11H/467M/2L/43I, risk 95 → 80 /
security 20). Fresh Android scan 16 (InsecureBankv2): **11H/467M/2L/43I,
zero critical**, risk 80 / security 20. Fresh iOS scan 17 (iBugBazaar):
**3M/1L/5I, zero critical** (get-task-allow medium), risk 55 / security 45.
Suppression lifecycle live on both: suppress-all-highs 80→55 → restore → 80;
iOS suppress-all-mediums 55→20 → restore one → 55; hidden by default /
visible via `include_suppressed`; `suppressed_at` stamped/cleared; agent
Layer-1 context excludes suppressed (scan 17 renders 7 findings, zero
leakage). Browser-verified (loadable chrome): gauge 45 inside the arc,
**"Suppressed (10)" badge** on scan 16 Overview, Findings tab "Findings
(513)" + "Review suppressed (10)", zero console errors. (Dev note: the
chrome-devtools agent outage recurred during the UI-polish click-through —
the polish fixes were verified via headless-Chrome DOM + code review.)
Note: `docker compose build app` does NOT rebuild the worker's image
(`masa-worker` is a separate tag) — always `docker compose build` or build
both services, then recreate, when analysis code changes.
Dashboard integration against the three mockups
(docs/masa-dashboard-{loaded,empty,progress}.html). Plan + architecture:
`docs/progress/M5.md`; granular checklist in docs/masa-tasks.md. Owner
decision: mockup design system is re-implemented in **Tailwind v4** (CSS-first
`@theme` tokens + `@fontsource/ibm-plex-*` — no CDN) rather than porting the
mockup CSS.

Phase A built + tested (238 tests, ruff clean): migration 0004
(`findings.explanation`, `scans.ai_summary`, `scans.stage`);
`analysis/risk.py::compute_risk_score` (originally severity-weighted mean,
**now CVSS 4.0 max aggregation** — see follow-up (4) above; computed in
`run_scan`, backfilled on GET); `model/selection.py::pick_chat_backend`
(shared by chat/explain/summary — `chat.py` delegates); `analysis/tree.py`
bounded file tree + guarded content reads (Android sources+resources, iOS
Payload/*.app); `agent/insights.py` explain_finding + summarize_scan (LLM,
cached on-row); endpoints: `POST /scans` (multipart upload, 413 over
`MASA_MAX_UPLOAD_MB`, enqueue-failure marks scan failed), `GET
/scans/{id}/findings` (severity-desc, ?severity/?limit/?offset, default
1000), `POST /scans/{id}/summary`, `POST
/scans/{id}/findings/{fid}/explain` (400 no model · 502 LLM failure),
`GET /scans/{id}/files` + `/files/content` (409 until analyzed); model
lifecycle `POST/DELETE /api/v1/model/backends` (+ `BackendStore.add/remove`,
local protected from delete); orchestrator `on_stage` callbacks → `Scan.stage`
writes in `run_scan`; FastAPI serves `frontend/dist` with SPA fallback.

Phase D built + browser-verified (loaded dashboard shell): `TargetBar`
(active-scan identity + SwitchScan dropdown — upload new APK/IPA, recent
scans with platform tags/dates, outside-click/Escape close, keyboard
options), also mounted on ProgressScreen; tab bar (Overview / Findings (n) /
Dependencies / Decompiler / Report) with placeholder panels for Phases
E–G/M7/M9; Overview tab from real data — `RiskGauge` (SVG arc, banded <25
low / 25–59 med / 60–84 high / ≥85 crit, stroke-dasharray), severity stat
boxes, AI summary block (auto-fetch `POST /scans/{id}/summary`; quiet
no-model 400 state, ok+Regenerate, error+Retry), Top findings (top 5
non-info, spine + sev-tag); `hooks/useFindings.ts` (severity counts, 1000-cap
v1) + `lib/format.ts` (formatRelative/platformLabel). Gate: `tsc -b && vite
build` + live check — InsecureBankv2 risk 40 / 0·5·473·2 / no-model summary /
Findings (523); switch to iBugBazaar.ipa and back verified; progress screen
RUNNING badge verified. Dev note: the 400 in the console is the designed
no-model summary contract (StrictMode double-fires it in dev).

Phase E built (Findings tab): `panels/FindingsPanel.tsx` — real findings
list + severity filter chips (All/Critical/High/Medium/Low/Info with
counts, client-side filter over the loaded set), expandable `FindingRow`
with lazy `POST /scans/{id}/findings/{fid}/explain` on first expand
(requestId race guard; client memo so re-expand is instant — backend also
caches in `findings.explanation`), ok+Regenerate / quiet no-model (400) /
error+Retry states; `.explain-btn` + `.ai-explain`/`.ai-tag` mockup
primitives in index.css; `findingLocation` extracted to `lib/findings.ts`
(shared with Overview top findings); Overview summary ok-box refactored
onto `.ai-explain`. Gate: `tsc -b && vite build` green; browser static
verification of the tab (All findings (523), chips 0/5/473/2/43,
severity-ordered rows). Dev note: browser-agent click-tooling (chrome-
devtools) was flaky during Phase E verification — chip/expand clickswere covered by code review + build rather than live clicks.

Phase F built (Decompiler tab): `panels/DecompilerPanel.tsx` + `code/`
(FileTree / CodeViewer / AnnotationRail). Tree from `GET /scans/{id}/files`
(lazy `<details>` expand, per-file severity dots from findings, app-code
`com/`-preferred auto-select that never stomps a manual choice); CodeViewer
from `GET /scans/{id}/files/content` — **highlight.js 11.11.1 (BSD-3-Clause,
core build + registered langs, tokens re-themed)**, numbered lines, flagged
lines (findings file_path+line → amber bar) click-to-scroll the rail note;
`lib/highlight.ts::splitHtmlLines` splits highlighted HTML per line with
span-carry (node-tested: line count + text fidelity exact; closing fragment
of multi-line tokens loses color — accepted trade-off). AnnotationRail =
findings for the open file by line, expandable AI explain via shared
`useExplain`/`ExplainBox` (extracted from FindingsPanel; 3rd reuse).
`useFileContent` hook. M8 placeholders: Smali toggle + Edit & recompile
disabled. Docs: licenses.md +frontend section (react/vite/tailwind/
fontsource/highlight.js). Bugs caught: React key warning in FileTree (fixed),
manual tree-click passed `node.name` as rootName (broken content path —
found by review, fixed). Browser verified: CryptoClass.java auto-selected,
10 annotations, flags, toolbar; agent click-tooling flaky formanual-click re-verification.

Phase G built (Agent dock chat): `hooks/useChat.ts` (messages + send,
requestId race guard; 400 no-model / 409 / 504 / network classified to
friendly copy); `components/agent/AgentDock.tsx` (mockup 1:1 — header steel
dot + "Agent · this scan", disabled 🌐 Web toggle (M7), collapse to 44px
rail via grid `1fr 340px` ⇄ `1fr 44px` in DashboardView; real welcome
message rebuilt per render so findings counts land after `useFindings`
loads; backtick→`<code>` spans; citations as **clickable file:line
`src-chip`s** jumping the Decompiler tab — `DashboardView.fileRequest` +
`openInDecompiler` (stable callbacks) → `DecompilerPanel` `requestFile`/
`onRequestConsumed` + `resolveTreePath` (exact → `<root>/<file>` → suffix
fallback, covers Android `sources/` + iOS `*.app` roots); error bubbles
with Retry, Enter-to-send (Shift+Enter newline, IME-safe), `.switch`
primitive added (Phase H reuses). Verified: tsc+build green; chat endpoint
returns the designed 400 (no chat model) in ~34ms; browser click-through
blocked by the recurring chrome-devtools outage (review-covered, like Phase
E).

**Decompiler follow-ups (Aug 6, owner review):** iOS decompiler no longer
shows the raw unzip — `tree.py` curates the `.app` walk to text-readable
files (hidden binary blobs collected into a collapsed **`Binary (Mach-O)`
(n) tree entry** — each listed inline with full path as inert dimmed rows
via `FileNode.binary`; `filtered_binaries` count kept in the API) and adds
a synthetic **`analysis/` root** generated from persisted lief/symbols
findings (`macho-profile.md` with
honest "not flagged" protection wording, `entitlements.plist` as JSON,
`exported-symbols.txt`, `insecure-imports.txt`); `_scan_findings` uses a
defensive SessionLocal (SQLAlchemyError → []) so a stale DB never 500s the
files endpoint. RiskGauge color is now a two-segment hue ramp green(0)→
orange(50)→red(100) instead of fixed amber. Decompiler panes are
IntelliJ-style resizable: pointer-capture Splitters, clamped widths
persisted to localStorage (double-click reset persists), `.decomp-layout`
columns via `--tree-w`/`--rail-w` CSS vars (≤900px still collapses to
tree+code). Gates: 240 backend tests + ruff clean, tsc+build green, iOS
tree/analysis docs verified live (iBugBazaar: 4 docs, 7 binaries hidden).

M6 — **COMPLETE (Aug 9, 2026).** See `docs/progress/M6.md`. App-oriented
tool set added to the M4 Layers 2/3 surface in `agent/tools.py`:
`read_manifest` (AndroidManifest.xml / Info.plist), `get_decompiled_class`
(Android-only, fqcn→sources path), `get_permissions` (uses-permission set /
usage strings), `run_secrets_scan` (on-demand gitleaks re-run wrapping
`analysis/gitleaks.py::scan_directory`, 30 s timeout + size guard),
`search_strings` (resource/string-file grep). Platform-aware schemas via
`schemas_for_platform` (iOS never sees `get_decompiled_class`); `ChatResponse`
gained `tool_mode: tools | context-only` + `tools_used` (Agent dock shows a
small "tools used" line); `max_tool_rounds` is now a settings knob
(`MASA_MAX_TOOL_ROUNDS`, default 3) with a per-request override on
`ChatRequest`. Soft-offer gating per owner decision (tools to any model;
known-good list Qwen2.5/2.5-coder, Llama 3.1+ documented in techstack as a
recommendation only). Gates: **339 backend tests green + ruff clean; tsc +
vite build green.** Real-model QA remains an owner checkpoint (Ollama off
during dev).

**M6 follow-up (Aug 9, 2026 — live tool steps + token streaming in the Agent
dock):** the dock now streams the agent's turn over SSE (`POST
/scans/{id}/chat/stream`, `agent/chat.py` gains a ``stream``/``on_event``
callback + `AgentEvent`/`ToolRun` records; `model/client.py` gains
`chat_stream`). Frames: `token` (live answer text, buffered 50 ms client-side)
· `tool_start`/`tool_end` (live steps: id/name/args → status/duration/preview/count)
· `answer` (canonical ChatResponse incl. `tool_runs` trace) · `error`
(kind+detail; pre-stream 400 no-model, 409 not-analyzed stay HTTP). Frontend:
`lib/sse.ts` StreamDecoder, `api.chatStream`, `useChat` pending-turn state
machine (ref-backed, abort keeps partial text/steps + "Stopped" note), dock
renders streaming text + caret + live step rows with expandable args/result
and clickable file:line chips (reuse `openInDecompiler`), then a collapsed
`Tools (n)` trace on the finished message; the M6 one-line tools-row was
replaced by the trace. `chat_stream` accumulates tool-call deltas
defensively (missing index/id → position; args concatenated per index) and
normalizes every provider to the OpenAI chunk shape; the tools-kwarg-rejected
fallback + loop-exhaustion plain chat both stream too. Gates: **350 backend
tests green (+11) + ruff clean; tsc + vite build green.** Containerized e2e
+ real-model QA remain owner checkpoints.

M8-M10 — not started, except the M8 kickoff plan (PLANNED Aug 10, 2026 —
see the M8 record at the end of this file; M7 is COMPLETE below).
**Post-M5 follow-up (Aug 8, 2026 — Gemini provider + curated model list):** (1) **Google Gemini** added to the BYOK provider set — `providers.py` entry (`gemini/` prefix, `GEMINI_API_KEY`, base `https://generativelanguage.googleapis.com/v1beta`, `models_path=None` → static curated list, matching Anthropic), `config.py` `gemini_base_url`/`gemini_api_key`, `backends.py` field maps, BYOKTab add-provider chip. Note: base is pinned to `v1beta` because MASA always passes `api_base` (litellm would otherwise self-select `v1alpha` for Gemini 3+ previews) — curated models are v1beta-compatible. (2) **Settings dialog model chips are now CURATED with a See-all reveal** (owner UX request): `ModelBackendRead` exposes `suggested_models` (provider table is source of truth); `BackendsTab` shows suggested ∩ served by default (first 6 served for local/custom, which have no curated list), the configured default is never hidden, and a dashed `▼ See all (N more)` chip reveals the full served list (collapses on fresh probes). BYOKTab provider order: OpenAI, Anthropic, Gemini, DeepSeek, OpenRouter, Custom.
**Owner follow-up (Aug 8, 2026 — BYOK seeding removed + custom key field):** (1) **BYOK backends are no longer seeded keyless** (`backends.py::_seed_backends`): a fresh store carries ONLY the local backends (`ollama`, `lm-studio`); BYOK providers seed only when a real key is configured via env/`Settings` (`MASA_OPENAI_API_KEY` etc.). Keyless cloud entries were unusable and only confused the Settings UI — cloud providers are now added exclusively via the BYOK menu (POST /backends requires the key; this is the only way in). Existing persisted stores keep whatever they had (the store file remains source of truth). Tests updated accordingly (seed = local-only, byok via POST). (2) **BYOK custom-endpoint form now includes an API key field** (`BYOKTab.tsx`, `needsApiKey` flag): base URL is required, key optional (some OpenAI-compatible endpoints are keyless). Gates: 281 backend tests green + ruff clean; tsc + vite build green.
**Owner follow-up (Aug 8, 2026 — Gemini 2.5 deprecation + progress dialog):** (1) **Gemini curated list moved to the Gemini 3 family** (`providers.py`): Google 404s the 2.5 line (`gemini-2.5-flash`/`2.5-pro`/`2.0-flash`) for NEW API keys — "no longer available to new users". Curated set is now `gemini-3.5-flash`, `gemini-3.6-flash`, `gemini-3.5-flash-lite`, `gemini-3.1-pro-preview` (all v1beta-served; the pinned `api_base` still wins over litellm's v1alpha self-selection). (2) **Probe walks the curated list** (`health.py::check_backend`): with no model configured, the Settings probe tries every suggestion and records the first that answers — a single stale entry can no longer mark the whole backend unreachable; a user-configured model is still probed exactly (broken choices fail loudly). (3) **Deprecation hint**: `model_arch_hint` (`client.py`) now also appends "no longer served to this account" guidance when the upstream text says a model is no longer available — same self-explaining surface as the Ollama arch hint, shared by Settings probe/chat/insights. (4) **Scan-in-progress is now a DIALOG, not a scrollable view** (owner report: the full view could push header/footer off-screen): `ProgressScreen` renders a `.progress-overlay` (absolute within `<main>`, top bar stays visible) + modal with the pipeline, dismissible via ×/Escape/backdrop-click (scan keeps running; `App.tsx` `progressDismissed` resets per active-scan id); the backdrop shows the last completed scan's dashboard (`DashboardView` `scanOverride` + `TargetBar` `scan` props, newest non-running scan via `backdropScan`) or the empty state on a fresh install; polling now runs while ANY scan is queued/running (`anyScanRunning`) so a dismissed background scan's completion always lands. Gates: **285 backend tests green + ruff clean; `tsc -b` + `vite build` green.** (Model IDs are per Aug-2026 availability research — re-verify if Google shifts the 3.x naming again.)
**Follow-up (same session) — Gemini models are now FETCHED LIVE, not hardcoded** (owner question "can't we fetch available models instead?"): Gemini has a real `models.list` (`GET /v1beta/models`) — it was skipped only because it isn't OpenAI-compatible. `Provider` gained `list_style` (`"openai"` | `"gemini"`); `health._list_gemini_models` does the `?key=` query auth, strips the `models/` prefix, filters to `generateContent`-capable base models (embeddings out, `tunedModels/` never in this endpoint), and on ANY failure/empty result falls back to `suggested_models` with source `"suggested"` (never `[]` — the probe surfaces connectivity). So provider deprecations can no longer hard-break the app: the Settings chips/dropdown/probe now reflect what Google actually serves, and the curated list is only the offline fallback. Frontend needed no changes (BackendsTab/ModelPicker already consume `health.models`). Gates: **184 model/agent/scan tests green + ruff clean** (full suite re-run below).
**Follow-up (same session) — Anthropic got the same live-first treatment** (owner request): Anthropic's `GET /v1/models` List Models endpoint is OpenAI-*shaped* (`{"data": [{"id": ...}]}`) but uses its own auth — `x-api-key` + `anthropic-version: 2023-06-01` headers, no Bearer. `providers.py` anthropic entry: `models_path="/v1/models"`, `list_style="anthropic"`; `health._list_anthropic_models` sends the anthropic headers (`limit=100`, one page covers the catalog), parses `data[].id`, and on any failure/empty/no-key falls back to `suggested_models` with source `"suggested"` (never `[]`). No provider carries `models_path=None` anymore; the curated lists for anthropic/gemini are pure offline fallbacks. Tests: anthropic live-parse (headers asserted, no Bearer), fallback-on-error, requires-key early return, probe-ok/failed/no-model-first-served/lightweight-live all moved to live semantics. Gates: **291 backend tests green + ruff clean** (frontend untouched).
**Follow-up (same session, verified live in compose) — no-model probe prefers curated ∩ live**: live probing revealed Google's `models.list` STILL lists deprecated IDs first (`gemini-2.5-flash` 404s on use for new keys), so a fresh BYOK key with no model configured would still show a bogus probe failure. `health.py::check_backend` now, when no model is configured, picks the first **curated ∩ live** entry (curated list = known-current seed) instead of the raw `models[0]`, and walks those small candidates — the deprecated raw-first entry is never probed. Live-verified in compose against the real key: gemini now `probe_model: gemini-3.5-flash`, `probe_ok: True` (was failing on 2.5-flash). Gates: **292 backend tests green + ruff clean.**
**Follow-up (same session) — BYOK per-provider toggle removed** (owner: "we already have active/inactive in Model backends"): `BYOKTab.tsx` cloud rows no longer carry an enable/disable switch (it duplicated the Model backends tab's toggle on the same `PUT {enabled}` path) — each row keeps a read-only Active/Inactive status + **Remove**. The master **Enable cloud fallback** batch toggle was ALSO removed on the next pass (owner decision) — BYOK is now pure add/remove; per-backend enable/disable lives entirely in the Model backends tab. `tsc -b` + `vite build` green.
**Follow-up (same session) — risk scoring is now WORST + COUNT, not pure max** (owner: "suppressing one or two highs doesn't move the score; only when ALL highs are gone" — this was the Aug 7 max-over-mean design, but the gauge felt like a switch). Owner approved: `risk = round(10×max_cvss)` plus ~1 point per extra finding at the TOP severity band (high), `int(0.9×(n−1)+0.5)`, capped at +9 so **risk ≤ 89** (CVSS 4.0 8.9 = top of the High band — the removed critical band is never re-introduced and the "CVSS 4.0 · risk n/100 · High" caption stays self-consistent). Bands below high keep their plain representative score (446 mediums = 55, same as 1 medium — the bonus is high-only by design). Live-verified sweep on scan 16: 11 highs = **89 → 88 → 87 → 86 → 85 → 85 → 84 → 83 → 82 → 81 → 80 → 55** as each high is suppressed (the 6↔7 flat step is expected rounding, pinned in tests; 10+ highs saturate at 89) — the first unsuppress jumps 55 → 80 because one high reintroduces the worst band, then +1 per extra. **Migration 0006** (`0006_worst_plus_count.py`, self-contained, mirrors `risk.py` exactly — same Python `int(0.9*(n-1)+0.5)` semantics) recomputes every `done` scan; applied to the volume DB (scan 18 → 89, scan 13 → 84 per its own high count, mediums unchanged). Stale LLM copy fixed: `insights.py` summary `security_score_note` now describes worst+count. Frontend needed no logic change — `SecurityGauge` bands (≥70 High/crimson) and caption already handle 81–89 (doc comment updated). Gates: **309 backend tests green + ruff clean; tsc + vite build green.**
**Follow-up (same session) — Agent dock chat UI (owner):** (1) **Send button disables when no model is connected** — `AgentDock` computes `modelConnected = backends.some(b => b.enabled && b.model)` from `useApp()` (the exact mirror of backend `pick_chat_backend` / ModelPicker's `active`), gates `submit()` and the button (`disabled={!draft.trim() || !modelConnected}`), and swaps the "⏎ to send" hint for an amber **"No model connected — pick one in the top bar or Settings"** (`.hint.warn`) + a tooltip on the disabled button. (2) **The "Thinking" bubble's Stop button was REMOVED** — the bubble now shows only the animated dots (the in-thread affordance comment in CSS updated). (3) **The input-row stop button (visible while sending) is now icon-only** — bare ■ with `aria-label`, no "Stop" text (`.stop-btn.stop-icon`, 34px square), matching mainstream AI-chat UIs. Live DOM-verified in compose with gemini enabled-but-model-empty: send renders `disabled` + tooltip, hint present, `.stop-icon`/`.hint.warn` in the served CSS. `tsc -b` + `vite build` green (no backend change; app image rebuilt).
M6.1 — **COMPLETE (Aug 9, 2026).** See `docs/progress/M6.1.md`.
Dev-only fake LLM (owner request: demo the dock's live steps + token
streaming with zero Ollama). `MASA_FAKE_MODEL=1` (`Settings.fake_model_enabled`)
seeds a dev-only `fake` provider/backend (`providers.py`, kind local, static
`demo` model) FIRST in the M3 store so `pick_chat_backend` resolves it
deterministically — chat/explain/summary all demo against it.
`model/client.py` `chat`/`chat_stream` short-circuit `provider_id == "fake"`
to `app/model/fake.py` (never litellm); `health._probe_completion`
short-circuits too (green Settings card). The script runs the REAL agent
loop + REAL tools: round 1 streams thinking text + two tool calls
(`search_code` pattern `WebView` split across two streamed deltas to
exercise `_accumulate_tool_call_deltas`, + `read_manifest`), round 2
composes the final answer from the REAL results (cites the first hit
`file:line` → clickable src-chip, else the manifest summary).
`BackendStore.read()` reconciles the fake entry with the knob
(idempotent, both directions) so flipping the env var converges existing
stores. **Live-verified (Aug 9)**: env-alias bug — pydantic-settings derives
env names from field names, so the documented `MASA_FAKE_MODEL=1` was
silently ignored (server ran knob-off); fixed via explicit
`validation_alias="MASA_FAKE_MODEL"` (raw alias IS the env name; the MASA_
prefix is not re-applied) + regression test. Browser e2e: sent "where is the
webview?" in the dock → thinking tokens streamed with caret, live
`search_code` (✓ 100 results) + `read_manifest` steps, answer cited real
`com/google/android/gms/internal/zzgf.java:115`, `Tools (2)` trace expanded,
zero console errors. Dev-DB caveat: stale host DB at the deleted vector-era
0004 stamp — re-stamp 0003 → upgrade head → re-stamp 0007. Gates: **373
backend tests green (+23) + ruff clean; frontend untouched (`tsc -b` +
`vite build` green).**

**Follow-up (same session) — the bonus went BAND-SYMMETRIC (owner approved):** `risk.py` now has `_BAND_RISK = {high: (80, 89, 0.9), medium: (55, 69, 0.9), low: (20, 39, 0.9)}` — the worst severity picks the band, base = `round(10×max_cvss)`, and each extra finding at that band adds `int(0.9×(n−1)+0.5)` capped at the band's CVSS 4.0 ceiling (high 89 · medium 69 · low 39 = the qualitative band tops 8.9/6.9/3.9 × 10). Clearing mediums now rewards progress too (16 mediums = 69 · 10 = 63 · 2 = 56 · 1 = 55), bands NEVER overlap (any high ≥ 80 > any no-high ≤ 69 > any low-only ≤ 39), and the caption "CVSS 4.0 · risk n/100 · band" stays literally true in every band (each cap IS the band ceiling — that was the discussion's key finding). **Saturation caveat (accepted)**: bulk bands sit at their ceiling — 446 mediums = 69 until the count drops below ~16, then the tail descends (progress shows via the severity-count stat boxes meanwhile). **Migration 0007** (`0007_band_symmetric_bonus.py`) re-scores every `done` scan (0006 test now upgrades to `0006` in isolation; new 0007 test: 3M → 57, 100L → 39, 11H → 89). Live-verified in compose: scan 16 (446M, no highs) 55 → **69**; scan 18 (11H) stays 89; scan 17 mediums descend 56 → 55 → 20 (low band) → restored 57 (it had one medium left suppressed from the Aug 8 e2e). Defensive `_BAND_RISK.get()` fallback keeps unknown-but-scored severities from crashing (review catch). Gates: **312 backend tests green + ruff clean; tsc + vite build green.**

M7 — **Agent web research (on-demand; COMPLETE Aug 9, 2026 — see
`docs/progress/M7.md`)**. Owner decisions at kickoff: (1) **agent-browser
DROPPED** — no browser automation in v1, JS-rendered pages degrade. (2)
**Deep-research / GPT Researcher pipeline DROPPED** (GPT Researcher's
Apache-2.0 license was verified — scope decision, not license): web research
is two on-demand agent tools, `web_search(query)` + `web_fetch(url)` (httpx
+ **trafilatura ≥1.8.0** — Apache-2.0 only at ≥1.8.0, earlier = GPLv3+),
gated by **per-scan opt-in** (`scans.web_research_enabled`, migration 0008,
default off), ChatGPT/Gemini-style: the model triggers search when a question
needs current/external info (CVEs, MASTG guidance, dep versions). (3)
**SearXNG = bundled, profile-gated** compose service (`profiles: [web]`,
unmodified upstream image, our own minimal settings.yml enables json
format). **AGPL boundary**: SearXNG is AGPL-3.0; MASA stays clean because it
runs as an unmodified separate container over HTTP JSON API only — never
imported/vendored/forked; AGPL §13 reaches modified copies of SearXNG
itself, not the calling app (`docs/licenses.md` row). (4) **Search provider
registry now, SearXNG only** — `search/providers.py` + `search/backends.py`
JSON store mirror the M3/M5 BYOK pattern; custom SearXNG-compatible
instances (base URL, no key) are the free-form BYOK analogue; Brave/Serper/
Mojeek are later rows. **Engine enablement is a Settings concern (owner
follow-up, same session):** each search backend carries an **Active/Inactive
toggle** in Settings → Search & research, **one Active at a time** (radio —
enabling one disables the others, mirroring `pick_chat_backend`
determinism); the store keeps `enabled` + `order` so a priority fallback
chain is a resolver-only change later. The Agent dock 🌐 toggle is the
**per-scan opt-in ONLY** (engine-agnostic privacy gate — never selects or
starts an engine) and is **disabled until an engine is Active** (greyed,
hint to Settings); web tools are offered only when BOTH the scan opt-in
(`scans.web_research_enabled`) AND an Active engine hold. **Ruled out as
future providers**: Google CSE (closing to new customers Jan 2027), Bing v7
(dead, HTTP 410), DuckDuckGo (no official API). M8–M10 unchanged.

**M7 built (Aug 9, 2026 — Phases A–D, mocked-test gates green):**
`app/search/` package — `providers.py` (SearXNG bundled + custom table),
`backends.py` (`SearchStore`: `search_backends.json` 0600, env-seeded
`MASA_SEARXNG_BASE_URL`, **`enable_only(id)`/`active()` radio** — one Active
at a time, enforced server-side on `upsert(enabled=True)` and `add()`;
`enable_only` delegates to upsert so the radio has ONE implementation),
`client.py` (SearXNG `GET /search?q=&format=json` →
`[{title,url,snippet,engine}]`; **`web_fetch` = streaming bounded httpx +
trafilatura extraction, SSRF-guarded** — http(s) only, private/reserved
hosts refused at the first hop AND every redirect hop, IPv4-mapped-IPv6
loopback refused, body read in chunks capped at `web_fetch_max_bytes`;
`check_backend` probe never raises — a misbehaving engine degrades to an
unreachable result, never a 500). API `GET/POST/DELETE /search/backends` +
`PUT …/{id}` (radio) + `POST …/{id}/test` (real query). Migration **0008**
(`scans.web_research_enabled`, default off) + `PUT /scans/{id}/web-research`.
Agent: `web_search`/`web_fetch` tools gated by **both** gates via
`web_tools_allowed(scan_id)` (scan opt-in AND `SearchStore.active()`),
`schemas_for_platform(platform, web_research_enabled=…)` filters the
schemas, handlers re-check defensively; system prompt gains a WEB RESEARCH
section only when allowed. Dev-only fake model (M6.1) gained a web-research
script (web_search → web_fetch → cited answer) so the flagship case demos
with zero Ollama. Frontend: Settings → **Search & research tab live**
(`SearchTab.tsx` — engine radio cards + base URL + Test probe + add/remove
custom, reusing BackendsTab/BYOKTab patterns — the per-scan opt-in lives
ONLY on the dock 🌐 toggle; a Settings copy was removed Aug 9);
Agent dock **🌐 Web toggle live** (per-scan opt-in only, disabled until an
engine is Active, green when on, "⏎ to send · 🌐 web on" hint); AppContext
`searchBackends` state + CRUD/probe/setWebResearch actions. Compose:
`searxng` under `profiles: [web]` (port 8888:8080, our
`docker/searxng/settings.yml` — json on, limiter off — mounted read-only at
/etc/searxng/settings.yml, `searxng-data` volume); `trafilatura>=1.8.0,<2.0`
in requirements.txt (the license boundary). Gates: **432 backend tests green
+ ruff clean; `tsc -b` + `vite build` green.** Remaining owner checkpoints:
containerized e2e with the profile started (upload → enable research → chat
streams a real search via compose SearXNG) + real-model QA.

**Follow-up (same session, Aug 9 — dock UX + compose SearXNG wiring, owner
review):** (1) **Agent dock minimum width raised 260 → 320 px** — at the old
min the header "Agent · this scan" overlapped the 🌐 Web toggle
(`DashboardView` `DOCK_MIN`); `.agent-header .title` also gained
`overflow: hidden` + `text-overflow: ellipsis` as a defensive clip at any
width. (2) **Dock drag-to-resize direction FIXED** — the real "extend/shrink"
complaint was the divider drag, not the button (owner confirmed: "extend
and shrink … using cursor … like in decompiler view"; the collapse button
glyphs were left at their original ⤡/⤢). The dock is the right-edge pane,
but its splitter ADDED the delta (`+ d`), so pulling the divider right GREW
the dock — the opposite of every other divider in the app (the decompiler
rail shrinks when dragged right via `railW - d`). Now `dockW - d`: drag
right narrows the dock, drag left extends it, matching the rail splitter. (3) **Settings per-scan opt-in section REMOVED** (`SearchTab.tsx`
`ScanOptInSection`) — redundant with the dock 🌐 toggle; the dock remains
the single per-scan control (`setWebResearch` / `PUT /scans/{id}/web-research`
unchanged). (4) **Compose app/worker now set
`MASA_SEARXNG_BASE_URL: http://searxng:8080`** — inside the compose network
the seeded `localhost:8888` pointed at the container itself (Connection
refused); the store seeds from the env on first read, an existing
`search_backends.json` keeps its own URL (edit in Settings → Search &
research). Start the engine with `docker compose --profile web up -d searxng`
(published to host `localhost:8888`). (5) **Web 🌐 toggle now also locks
without a chat model** — it was gated only on an Active engine; now
`webLocked = !activeEngine || !modelConnected` greys it and makes it
click-inert with a "No model connected — pick one in the top bar or
Settings" tooltip, mirroring the send-button gate (web research is
meaningless with no agent to run it).

**Containerized e2e RUN (Aug 9) — the M7 owner checkpoint, live in
compose with the fake model (Ollama off):** (1) **SearXNG crashed on boot —
`server.secret_key: The value has to be one of these types/values: str`.**
Our minimal `docker/searxng/settings.yml` lacked the `use_default_settings:
true` merge flag AND a secret_key; SearXNG 2026.8.4 schema-validation hard-
fails without them. Fixed in the file (fixed dev secret, localhost-only
engine) + validated in a throwaway container before recreating. (2) The
engine is reached live end-to-end: `POST /search/backends/searxng/test`
from the app → `reachable: true, result_count: 1` (app→`searxng:8080`
in-network). (3) The persisted store kept `localhost:8888` (file is source
of truth) — repointed via `PUT /search/backends/searxng {base_url:
http://searxng:8080}` (the documented Settings edit, done via API).
(4) Full chat e2e on scan 19 (InsecureBankv2, `MASA_FAKE_MODEL=1`):
`PUT /scans/19/web-research {enabled:true}` → `POST /scans/19/chat/stream`
"any known CVEs?" → streamed thinking tokens, live `web_search` tool step
**10 real results / 1.1s**, `web_fetch` attempt → **HTTP 403 from the top
hit (medium.com blocks the honest `MASA-agent/0.1` UA)** — degrades
cleanly. (5) **Fake web script FIXED** (regression-tested): it used to
re-fetch the SAME failed URL until the 3-round limit, so the final answer
lost its citation; now round 3 composes from the search results (cites the
top URL + "the top page blocked direct reading" note) — `_web_response`
never retries a failed fetch. Real-model QA remains an owner checkpoint.

**Follow-up (same session) — one-click engine start (owner request):**
Settings → Search & research now has a **▶ Start engine** button on the
bundled SearXNG card whenever the probe reports it unreachable — instead of
only the `docker compose --profile web up -d searxng` hint text. Backend:
`POST /search/backends/{id}/start` runs the FIXED compose argv (no shell /
no user input — not an injection surface) with the compose file discovered
upward from cwd (`_find_compose_file`), then polls the engine until it
answers (`_wait_for_engine`) and returns the fresh health. 400 for custom
instances; 502/504 carrying the manual command when Docker is missing /
timed out / compose failed. Frontend: `api.startSearchBackend` +
`AppContext.startSearchBackend` (merged in place like the probe) +
SearchTab button (bundled + `!health.reachable` only). Live-verified:
442 backend tests green (6 new) + ruff clean; tsc + vite build green;
endpoint in the app container (no Docker on its host) returns the clean
502 manual-command detail; host-side `docker compose -f … up -d searxng`
idempotent on the running engine. The Active toggle still never starts the
container — this button is the explicit start affordance.

**Follow-up (same session, Aug 9) — search provider registry expanded
(owner question: "what about duckduck, brave etc.? can it be simplified to
base URL + API key?")** — Settings → Search & research now offers four
providers instead of only SearXNG. The add-form is a **provider picker**
chip row (mirroring BYOKTab) whose fields adapt per provider: base URL
(pre-filled with the provider's default, optional when it has one) + API
key (required for keyed providers, hidden for SearXNG instances).
Providers: **custom** (SearXNG-compatible, base URL only), **brave**
(`api.search.brave.com`, `X-Subscription-Token` header, `GET
/res/v1/web/search`), **serper** (`google.serper.dev`, `X-API-KEY` header,
`POST /` JSON body — Google SERP), **mojeek** (`www.mojeek.com`, `q` +
`api_key` params, `fmt=json`). DuckDuckGo stays ruled out (no official
API); Google CSE (closing Jan 2027) and Bing v7 (HTTP 410) remain future-
rows only. `search/providers.py` now carries the keyed rows
(`key_required`/`default_base_url`/`query_style`/`parse_style`);
`client.py` dispatches by `query_style` (`searxng` | `brave` | `serper` |
`mojeek`) with per-style normalizers → the shared `[{title,url,snippet}]`
shape, plus a **key-rejected hint** (401/403 → "check the API key in
Settings") and a keyed-aware `check_backend` probe (skips the real query
when no key, reports `missing key`). `backends.py` env-seeds keyed engines
from `MASA_BRAVE_API_KEY` etc. but **disabled** (key presence alone never
activates an engine — the radio does); `upsert` accepts `api_key`;
`config.py` gains the key fields; `schemas.py` gains `has_api_key`,
`api_key` on create/upsert, and `GET /search/providers` (the picker's
source of truth). Frontend: `types.ts` `SearchProvider` + `api_key`
fields, `api.searchProviders()`, `SearchTab` provider-chip add-form with
a **key-set indicator** ("✓ key set" on a backend row) — `api_key` is
write-only in responses. Tests: provider invariants (every keyed row has a
default base URL + parse style), keyed normalizers (brave/serper/mojeek
parse fixtures), key-rejected hint, env-seed-disabled, API create-with-key
+ has_api_key + GET /providers. Gates: **457 backend tests green (+15) +
ruff clean; tsc + vite build green**; live in compose: `GET
/search/providers` serves all four rows with correct shapes.

**Follow-up (same session, Aug 9) — manual web-search testing + chat chip
overflow fix (owner):** (1) **The fake model now searches with the USER'S
OWN question text** — `fake.py::_web_query` picks the last user message
(≥4 chars, else the canned `InsecureBankv2 known vulnerabilities CVE`
fallback) as the round-1 `web_search` query, so a manual test types its own
search in the dock and the fake runs it verbatim (a real model would
paraphrase; the fake is a script). Live-verified in compose: question
"SQLite database CVEs 2026" → `web_search` args `{query: "SQLite database
CVEs 2026"}` → 10 results → `web_fetch` of the top hit (sqlite.org/cves.html,
read cleanly this time) → cited answer with the source URL. Manual test
recipe: fake model selected (MASA_FAKE_MODEL=1) + an Active engine in
Settings → Search & research + the dock 🌐 toggle on (per-scan opt-in) —
then just ask; the tool steps stream live and the `Tools (n)` trace shows
the real results. (2) **file:line citation chips could escape the chat
bubble** (long unbroken paths) — fixed three ways: `AgentDock`
`shortenPath` (middle-ellipsis keeping the filename:line tail + full path
in the chip tooltip), `.src-chip` `max-width:100%` + ellipsis floor (with
`.src-row` capped), and `.md code`/`.msg` `overflow-wrap: anywhere` so
inline paths in answers wrap instead of pushing the bubble out of the dock.
Gates: **459 backend tests green (+2 new) + ruff clean; tsc + vite build
green**; app image rebuilt and live.

M8 — **Edit & recompile (Android); PLANNED (Aug 10, 2026)** — kickoff spec
(`docs/m8-kickoff-spec.md`, interview record) + plan (`docs/progress/M8.md`,
phases A–E) written, no code yet; task list updated in docs/masa-tasks.md.
Three-round owner interview locked the decisions: (1) **apktool decode is
on-demand** — an RQ job triggered by the first Smali view / first edit
(cached per scan), never a scan-pipeline step; (2) **edits are diffs in the
DB** (new `edits` table: original + new content + unified diff per row),
**applied at rebuild** onto a fresh copy of the decoded tree — never silent
tree edits, revert-safe; (3) **Android only — iOS edit/ldid resign deferred
to v1.1**: verified research — an `ldid -S` re-signed IPA installs only on
jailbroken devices (AppSync Unified) or as handoff input for the user's own
Sideloadly/Apple-ID signing; stock iOS rejects it and the simulator won't
run it (wrong platform slice); iOS keeps the read-only bundle view;
(4) **toolchain bundled + size gate bumped** — apktool (pinned jar) +
Android build-tools zipalign/apksigner installed at build time (`keytool`
already ships in the JRE); owner approved growing past 450 MB;
(5) **agent surface = dock chat tool AND the mockup-faithful inline "Ask
agent to edit" bar**; `propose_smali_edit(file, instruction, new_content)`
stores a `proposed` edit + unified diff for human review, never
auto-applies; apply/reject/revert are human API calls, file-by-file for
multi-file proposals; (6) **full edit/build history per scan** — per-file
restore-original + `builds` table (status/stage/error/edits snapshot) with
re-download of any prior artifact; (7) **one install-scoped test keystore**
per MASA install (generated once into `data_dir`, `0600`, BYOK-key
precedent), reused for every rebuild; (8) **rebuild pipeline** = apply
edits → `apktool b` → `zipalign -f` → `apksigner sign` → `apksigner verify`
sanity gate; every stage fails loudly with a specific error, never a
silently broken APK; (9) **e2e is contract-style (no emulator)** — artifact
passes `apksigner verify`, signature fingerprint differs from the original
APK, filename carries `-resigned-test-`; real-device install = owner manual
checkpoint; (10) **persistent, un-dismissable "resigned test build" label**
— modal warning + filename + download header. Migration **0009**: `edits`,
`builds`, `scans.apktool_status`/`apktool_error`. masa-tasks.md updated:
iOS items moved to Deferred/v1.1, smali-decode task notes on-demand timing,
e2e item re-scoped to contract-style, M8 section now links the plan. Open
kickoff items (non-blocking): pin apktool + build-tools versions, choose the
awkward-APK fail-loudly test candidate, confirm the `propose_smali_edit`
contract.