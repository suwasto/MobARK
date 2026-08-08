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

M6-M10 — not started, except the M7 plan docs (updated Aug 7, 2026).
M7 — **Deep research + interactive browser automation planned; docs updated
(Aug 7, 2026)**: `docs/masa-{techstack,prd,tasks}.md` now include
**agent-browser** (vercel-labs, Apache-2.0 — native Rust CLI + CDP daemon
over Chrome/Chromium, no Playwright/Puppeteer/Node) as the agent's browser
capability: token-efficient accessibility-tree snapshots with element refs
(`@e12`, ~90%+ context savings vs raw HTML), `read` (markdown/llms.txt-
aware) replaces the hand-rolled `web_fetch`, `batch` for multi-step flows;
SearXNG still the search provider. Same per-scan opt-in + "leaves the
machine" boundary as web research; every browsing turn bounded (`--max-
output`, `--allowed-domains`, session teardown). Open deployment question:
Chrome for Testing (~150MB+) host-side like Ollama vs in-image. M6
(tool-calling surface), M8–M10 unchanged.