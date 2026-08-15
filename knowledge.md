# graphify
- **graphify** (`~/.claude/skills/graphify/SKILL.md`) - any input to knowledge graph. Trigger: `/graphify`
When the user types `/graphify`, use the installed graphify skill or instructions before doing anything else.


# MobARK

REBRAND (Aug 15, 2026): formerly MASA (Mobile Application Security
Assistant). The old name collided with Google's MASA (Mobile Application
Security Assessment) and the MASA defense alliance, so the project was
renamed MobARK (Mobile Application Reverse Kit) across code, docs, and
this log. The GitHub repo URL (github.com/suwasto/masa) is unchanged
until the repo itself is renamed; the logo artwork was retyped to the
new wordmark.

Read docs/mobark-prd.md, docs/mobark-techstack.md, docs/mobark-tasks.md
before doing anything.

NOTE (Aug 12, 2026): `docs/` is GITIGNORED/untracked (deliberate: ~44MB
of sample APKs/IPAs/icons/mockups don't belong in git). The files remain
on disk. READ them via explicit paths (read_files works regardless of
gitignore: knowledge.md/mobark-tasks.md name every relevant doc); SEARCH
them with the `--no-ignore` rg flag (the default code-search respects
.gitignore and will silently miss docs/).
M10 (Aug 14, 2026): the PUBLIC docs site lives in the TRACKED `site/` dir
(MkDocs + Material → GitHub Pages): curated, not synced from docs/ (which
stays ignored); see docs/progress/M10.md. When a task touches public docs,
editing site/ is the committed surface.

Hard constraints: Apache-2.0 license (was MIT, relicensed Aug 3 2026,
copyright Anang Suwasto). GPL/LGPL tools (Semgrep, apktool,
jadx, ldid): subprocess only, never imported. Local-first, no
network calls except opt-in web research.

## Status
M0: completed (Aug 2, 2026). Repo skeleton (`backend/`, `frontend/`, `docker/`),
`docker-compose.yml` (app + worker + redis), FastAPI health endpoint,
SQLite schema + Alembic migrations for scans/findings, RQ + Redis wired and
tested with a dummy job, dependency/license audit (`docs/licenses.md`).
Validated end-to-end: `docker compose up` green, 7 unit + 2 integration tests
passing, committed as `80ccdde` on branch `main`.

M1: COMPLETE (Aug 3, 2026). See `docs/progress/M1.md`.
Built & VALIDATED: `backend/app/analysis/` engine (jadx decompile, androguard
manifest/cert/netsec, gitleaks + semgrep subprocess wrappers with normalizers,
orchestrator with per-stage error policy); MASTG data vendored (292 tests @
commit d7fd7d45636ef9acbae89d0247e8dd748aa6918d, 46 android semgrep rules + 8
curated rules); `findings.mastg_test_id` column + migration 0002; RQ job
`run_android_scan`; CLI `python -m app.cli {run,scan,jobs}`; multi-stage
Dockerfile (JRE + jadx 1.5.6 + gitleaks 8.30.1 + semgrep 1.172.0 in its own venv).
ALL gates verified by running (Aug 3): CLI `run` on `docs/InsecureBankv2.apk` →
523 findings (16 androguard, 507 semgrep: 22 `scope: app`, 485
`third_party_library`; gitleaks 0), 0 warnings; image builds at 389 MB content
(within the 350–450 MB gate); migration at 0002 + RQ path proven (worker ran
scan 1 and scan 2 → done, 523 findings persisted in the compose volume DB);
`docker compose up` green, `/api/v1/health` ok; 27 unit + 6 integration tests
pass, ruff clean.
Fixed: API container crash-loop: the pip `semgrep` install upgraded starlette
to 1.3.1 (breaking fastapi 0.115.6's <0.42 pin). Fix: semgrep now lives in
`/opt/semgrep-venv` (symlinked onto PATH) so its starlette>=0.49 dep tree can't
clash with the app's. Earlier fixes preserved: enrichment relative-path bug,
test_mastg.py alias, ruff violations, signing-certificate asn1crypto API,
semgrep scope tagging.
Env notes: compose uses `mobark_mobark-data` volume (NOT `mobark-data`: an empty
stray volume of that name is a leftover and can be removed). `mobark-smoke-redis`
(host port 6379) is a leftover M0 container that host-side integration tests
use as their Redis. Host tools: jadx 1.5.6, gitleaks 8.30.1, semgrep 1.172.0
(Homebrew), java 17; backend venv at `backend/.venv` (Python 3.12).

M2: iOS static core, planned (Aug 3 2026), not started. Plan in
docs/progress/M2.md; task list updated in docs/mobark-tasks.md. Key research
notes: LIEF (v0.15+) has a first-class `code_signature` object but entitlements
still need plist carving + plistlib; `header.has(FLAGS.PIE)` for PIE;
`LC_ENCRYPTION_INFO` cryptid for FairPlay; stack canary via `___stack_chk_guard`
symbol. Sample IPA candidate: iBugBazaar (MASTG-APP-0030, payatu/iBugBazaar,
prebuilt IPA in releases); fallbacks DVIA-v2 (MASTG-APP-0024), iGoat-Swift
(MASTG-APP-0028).

M3: COMPLETE (Aug 5, 2026). See `docs/progress/M3.md`.

M4: Agent context layers (Layers 1-3), **RAG/embedding DELETED from v1**
(owner decision Aug 6 2026, not deferred). CPU embedding of a 3MB APK took
5–15 min before chat was usable → replaced by three non-embedding layers.
Status: built + unit-tested (167 tests, ruff clean); live-model QA is MANUAL
(owner shut down Ollama during development: do not attempt live LLM tests;
mocked unit tests only). Plan/progress: `docs/progress/M4.md`.

Built: `agent/context.py` (Layer 1: full findings set, precision-tagged
`[file/line]` vs `[binary-level presence only]`, platform whitelists,
**androguard never in iOS context**); `agent/tools.py` (Layer 2
`search_code(pattern, glob)` + `read_file(path, line_range)`: no platform
branching, traversal-guarded; Layer 3 `graph_query`/`graph_path`/
`graph_explain` wrappers); `agent/chat.py` (bounded ≤3-round tool loop,
context-only fallback, citations from file:line refs); `analysis/ios/symbols.py`
(the **import-table scanner**: named iOS source: CC_MD5/CC_SHA1/CC_DES/CCCrypt,
UIWebView, NSURLConnection cert-bypass selectors, ptrace/sysctl/syscall
anti-debug blocklist over Mach-O imports); iOS binary profile info findings
(exported symbols, linked dylibs, architectures, ARC, full entitlement set:
what was hidden in unpersisted result.meta); `resources/gitleaks_ios.toml`
(kSecAttrAccessibleAlways goes through Gitleaks, string-level not import-level);
`build_graph_scan` RQ job chained after run_scan (Android-only); API
`POST /scans/{id}/chat` (Layers 1-3) + `GET /scans/{id}/graph` (filesystem-
derived); CLI `graph build|query|path|explain` + `agent context|chat`.
Package `app/vector` renamed `app/graph` (no vector name remains); migration
0004 deleted (head = 0003; dev DBs at 0004 need `alembic downgrade 0003`);
chromadb + llama-index-core uninstalled.

**Validated Graphify CLI facts (0.9.32):** no `extract`/`export` subcommand:
headless build is `graphify update <dir> --no-cluster` (cwd = per-scan graph
dir); queries via `query|path|explain|affected --graph`; natural-language
`query` fails on code-only AST graphs → wrapper has a label/ID
substring-search fallback. Real numbers (InsecureBankv2): 46,177 nodes /
116,780 edges / 64 MB graph.json, zero LLM, ~1m17s. **InsecureBankv2 has no
cert-pinning code**: the working structural case is WebView/MyWebViewClient.java.
**iOS graph negative confirmed**: unpacked `.app` has 0 source-like files →
Graphify is Android-only in v1.

Remaining M4: manual QA with a real model (owner), stress (obfuscated +
large APK), go/no-go record, Docker image rebuild with new dep set (size
gate), M5 UI wiring after go/no-go.

**Follow-up (Aug 8, 2026: graphify bug + Code maps tab):** (1) **M4 graph-build bug FIXED**: graphify 0.9.32 writes its output into the INPUT dir
(`<decompiled>/graphify-out/`), not the cwd: every chained build "succeeded"
(rc=0) while silently failing to produce a graph at `graph_path_for` and
polluting the decompiler tree with a 64 MB `graph.json`. `graphify.build` now
MOVES the input-dir `graphify-out/` into the per-scan graphs dir after a
successful run; `tree.py` excludes `graphify-out` from the decompiler walk
defensively. Live-verified in the container: `graph build 16` → 46,177 nodes /
116,780 edges, graph at `/data/graphs/16/`, decompiler tree clean.
(2) **Code maps tab (owner: "searchable explorer, auto-build, keep agent
preference")**: new dashboard tab between Decompiler and Report (Android
only; iOS shows the "Android-only" hint). The 64 MB `graph.json` never hits
the browser: `graphify.explorer_data()` compacts it once into a per-scan
`explorer.json` (public-shape node rows `id/label/file_type/file/line` +
`(source,target,relation)` links + degree map; module cache keyed by
path+mtime, bounded to the 4 most-recent graphs: cache evicts oldest) and
serves three endpoints: `GET /scans/{id}/graph/search?q=` (label-prefix >
label-substring > id-substring, `total` = pre-limit count), `GET
/scans/{id}/graph/hubs` (top-N by degree: the initial "Most connected"
view), `GET /scans/{id}/graph/node/{id}` (one node + in/out neighbors,
relation-tagged, deduped per direction, out-first sorted by neighbor degree,
capped 40; 404 unknown id). Shared `_require_graph` guard → 409 non-Android /
not-built. Frontend: `CodeMapsPanel.tsx` (debounced 300 ms search, hubs
initial view, detail pane with Outgoing/Incoming groups, per-row
Open-in-Decompiler jumps reusing `resolveTreePath`; requestId race guard on
node selection; `key={current.id}` remount per scan: review catch), `.codemap-*`
CSS + 760 px stack media query. Gates: **307 backend tests green + ruff
clean; tsc + vite build green.** Live-verified in compose on scan 16:
search `MyWebViewClient` → 5 hits with real files/lines, hub GoogleApiClient
degree 935 / 40 neighbors (28 out / 12 in), iOS scan 17 → clean 409, SPA
serves the new bundle, headless-Chrome DOM shows the full 6-tab bar with
Code maps between Decompiler and Report (chrome-devtools agent outage again
: DOM + code review covered the click-through).

M5: **COMPLETE (Aug 8, 2026).** See `docs/progress/M5.md`.
Phases A–H + Phase I all green: the app image bundles the SPA
(`Dockerfile.app` frontend build stage → `/frontend/dist`) and `main.py`
serves index.html at `/` when dist exists; CLI-enqueued scan → worker → done
with SPA + assets + health served from FastAPI on :8000. Containerized e2e
re-verified after the Aug 8 follow-ups on BOTH platforms (Android
InsecureBankv2 + iOS iBugBazaar; see the Aug 8 follow-ups below). Loaded-state
browser checks passed; deep click-throughs partially blocked by the recurring
chrome-devtools outage (covered by code review + headless-Chrome DOM). One
post-completion owner checkpoint remains: manual model QA with a real model
(Ollama): chat/explain/summary, not a blocker.

**Owner review follow-ups (Aug 7):** (1) **debuggable finding → critical**
(was high): `analysis/manifest.py`. (2) **Overview score is now a SECURITY
score** (higher = better; low = red, high = green): security = 100 − risk;
`Scan.security_score` derived property (never stored), `ScanRead` exposes it,
summary prompt relabeled, `RiskGauge` → `SecurityGauge` with inverted ramp
+ labels. Verified in compose: InsecureBankv2 risk 40 → security 60,
debugable now critical (1C/4H/473M/2L/43I). (3) **Severity re-calibration (owner picks A+C, Aug 7; B declined)**:
Android curated: hostname-verifier + empty trust manager → **critical** via
`severity.py::SEMGREP_OVERRIDES`; WebView JS/file-access, hardcoded-key,
weak-cipher bumped to ERROR (→high). iOS: `setAllowsAnyHTTPSCertificate` →
critical, get-task-allow → medium (per-entitlement severities), empty
usage strings → low. MASTG vendored rules unchanged (B declined). Live
verified: debuggable critical, WebView-JS/hardcoded-key high, 1C/10H/467M/
2L/43I, risk 41 → security 59. 244 tests green. (4) **Scoring is now CVSS
4.0** (owner decision, same session): severity → representative CVSS 4.0
base score (critical 9.5 / high 8.0 / medium 5.5 / low 2.0 / info 0: band
midpoints per the spec); overall **risk = round(10 × max(cvss))**: the
worst finding drives the score (owner chose max over mean). Securitygauge labels follow the CVSS 4.0 qualitative bands of the underlying risk (60
security → risk 40 → Medium, NOT High: owner complaint fixed) + a
`CVSS 4.0 · risk n/100 · band` caption; the arc color snaps to the band
(crimson ≤10 / amber 11–30 / olive 31–60 / moss 61–99 / emerald 100)
instead of a continuous ramp (owner follow-up, Aug 7). InsecureBankv2 (1 critical) now
scores risk 95 → **security 5**. (5) **Dashboard tab bar is sticky**:
Overview/Findings/Dependencies/Decompiler/Report stay visible while panel
content scrolls (`DashboardView`). (6) **Model pill dropdown gained a model
search box** (filters local + cloud groups, Escape clears first); the
"No models listed (is the server running?)" copy is now **local-only**:
cloud-opt backends say "No models listed: check the provider key in
Settings." (7) **Scan date accuracy fix**: SQLite drops tzinfo on
round-trip, so persisted timestamps serialized naive and browsers parsed
them as local time (hours off on non-UTC machines). `schemas.py` now
attaches UTC on serialization (`_utc_aware` on scan/finding `created_at`,
`checked_at`, `generated_at`) + `formatRelative` parses no-offset strings
as UTC as a belt-and-braces.
**Owner follow-up (Aug 8, 2026: model-connection diagnostics):** probe +
agent chat were failing with a raw 500 / bare "Probe failed" for Ollama
model `ndavat/Nanbeige4.2-3B`. Root cause was environmental: host Ollama
0.30.6 predates the `nanbeige` (Looped Transformer) architecture in
llama.cpp: it needs Ollama v0.32.x+. App-side fixes so such failures
self-explain: `health._probe_completion` now returns `(ok, error)` and
`BackendHealth.error` carries the real upstream message (with an actionable
"upgrade Ollama" hint when the text says `unknown model architecture`);
BackendsTab renders `health.error` under the card; agent chat wraps
upstream LLM failures as `ChatUpstreamError` → **502** with the upstream
message (was an unhandled raw 500); `useChat` classifies 502 as
`'upstream'` with the detail in the bubble. 259 backend tests green, ruff
clean, tsc+vite build green.

**Owner review follow-ups (Aug 8, 2026):** (1) **Critical band REMOVED**:
findings vocabulary is now `high | medium | low | info` (`base.py::SEVERITIES`;
`risk.py::SEVERITY_CVSS` high 8.0 / medium 5.5 / low 2.0 / info 0: max risk
is now 80, was 95). Producers of critical now emit high: debuggable manifest
finding, iOS `setAllowsAnyHTTPSCertificate` symbol rule, semgrep TLS-bypass
overrides, gitleaks direct-compromise rules. Migration **0005** rewrites
persisted `critical` → `high` AND recomputes every `done` scan's `risk_score`
under the new mapping (self-contained SQL; head is now 0005). Frontend: no
critical anywhere: stat boxes are High/Medium/Low/**Info**, `SecurityGauge`
bands re-mapped (risk 70–80 crimson worst → emerald 0; `Critical` band type
removed), tree dots/annotation labels/filter chips/agent greeting updated.
(2) **Top bar: single model pill → TWO searchable dropdowns**:
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
(`compute_risk_score` skips `suppressed=True` via getattr: works for both
`FindingOut` and persisted `Finding`), AI summary, and agent Layer-1 context
(`agent/context.py`). Findings tab: per-row **Suppress/Restore** + **"Review
suppressed (n)"** toggle (dimmed rows); `useFindings` fetches with
`include_suppressed=true` once and splits active/suppressed client-side;
DashboardView re-fetches the scan after a toggle so the gauge updates.
(4) **"Suppressed (n)" Overview badge**: a clickable pill next to the stat
boxes showing the active scan's suppressed (false-positive) count; jumps to
the Findings review toggle; renders only when n > 0. (5) **UI polish (owner
review, Aug 8)**: gauge score moved INSIDE the SVG as a centered `<text>` +
`/100` tspan (no more arc overlap: was pulled up over the curve);
`.explain-btn` lost its stray `margin-top: 8px` so "AI explanation" and
"Suppress/Restore" sit inline on the same row. Gates: **256 backend tests
green + ruff clean; `tsc -b` + `vite build` green.**
**Containerized e2e re-verified after the Aug 8 changes: both platforms
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
chrome-devtools agent outage recurred during the UI-polish click-through:
the polish fixes were verified via headless-Chrome DOM + code review.)
Note: `docker compose build app` does NOT rebuild the worker's image
(`mobark-worker` is a separate tag): always `docker compose build` or build
both services, then recreate, when analysis code changes.
Dashboard integration against the three mockups
(docs/mobark-dashboard-{loaded,empty,progress}.html). Plan + architecture:
`docs/progress/M5.md`; granular checklist in docs/mobark-tasks.md. Owner
decision: mockup design system is re-implemented in **Tailwind v4** (CSS-first
`@theme` tokens + `@fontsource/ibm-plex-*`: no CDN) rather than porting the
mockup CSS.

Phase A built + tested (238 tests, ruff clean): migration 0004
(`findings.explanation`, `scans.ai_summary`, `scans.stage`);
`analysis/risk.py::compute_risk_score` (originally severity-weighted mean,
**now CVSS 4.0 max aggregation**: see follow-up (4) above; computed in
`run_scan`, backfilled on GET); `model/selection.py::pick_chat_backend`
(shared by chat/explain/summary: `chat.py` delegates); `analysis/tree.py`
bounded file tree + guarded content reads (Android sources+resources, iOS
Payload/*.app); `agent/insights.py` explain_finding + summarize_scan (LLM,
cached on-row); endpoints: `POST /scans` (multipart upload, 413 over
`MOBARK_MAX_UPLOAD_MB`, enqueue-failure marks scan failed), `GET
/scans/{id}/findings` (severity-desc, ?severity/?limit/?offset, default
1000), `POST /scans/{id}/summary`, `POST
/scans/{id}/findings/{fid}/explain` (400 no model · 502 LLM failure),
`GET /scans/{id}/files` + `/files/content` (409 until analyzed); model
lifecycle `POST/DELETE /api/v1/model/backends` (+ `BackendStore.add/remove`,
local protected from delete); orchestrator `on_stage` callbacks → `Scan.stage`
writes in `run_scan`; FastAPI serves `frontend/dist` with SPA fallback.

Phase D built + browser-verified (loaded dashboard shell): `TargetBar`
(active-scan identity + SwitchScan dropdown: upload new APK/IPA, recent
scans with platform tags/dates, outside-click/Escape close, keyboard
options), also mounted on ProgressScreen; tab bar (Overview / Findings (n) /
Dependencies / Decompiler / Report) with placeholder panels for Phases
E–G/M7/M9; Overview tab from real data: `RiskGauge` (SVG arc, banded <25
low / 25–59 med / 60–84 high / ≥85 crit, stroke-dasharray), severity stat
boxes, AI summary block (auto-fetch `POST /scans/{id}/summary`; quiet
no-model 400 state, ok+Regenerate, error+Retry), Top findings (top 5
non-info, spine + sev-tag); `hooks/useFindings.ts` (severity counts, 1000-cap
v1) + `lib/format.ts` (formatRelative/platformLabel). Gate: `tsc -b && vite
build` + live check: InsecureBankv2 risk 40 / 0·5·473·2 / no-model summary /
Findings (523); switch to iBugBazaar.ipa and back verified; progress screen
RUNNING badge verified. Dev note: the 400 in the console is the designed
no-model summary contract (StrictMode double-fires it in dev).

Phase E built (Findings tab): `panels/FindingsPanel.tsx`: real findings
list + severity filter chips (All/Critical/High/Medium/Low/Info with
counts, client-side filter over the loaded set), expandable `FindingRow`
with lazy `POST /scans/{id}/findings/{fid}/explain` on first expand
(requestId race guard; client memo so re-expand is instant: backend also
caches in `findings.explanation`), ok+Regenerate / quiet no-model (400) /
error+Retry states; `.explain-btn` + `.ai-explain`/`.ai-tag` mockup
primitives in index.css; `findingLocation` extracted to `lib/findings.ts`
(shared with Overview top findings); Overview summary ok-box refactored
onto `.ai-explain`. Gate: `tsc -b && vite build` green; browser static
verification of the tab (All findings (523), chips 0/5/473/2/43,
severity-ordered rows). Dev note: browser-agent click-tooling (chrome-
devtools) was flaky during Phase E verification: chip/expand clickswere covered by code review + build rather than live clicks.

Phase F built (Decompiler tab): `panels/DecompilerPanel.tsx` + `code/`
(FileTree / CodeViewer / AnnotationRail). Tree from `GET /scans/{id}/files`
(lazy `<details>` expand, per-file severity dots from findings, app-code
`com/`-preferred auto-select that never stomps a manual choice); CodeViewer
from `GET /scans/{id}/files/content`: **highlight.js 11.11.1 (BSD-3-Clause,
core build + registered langs, tokens re-themed)**, numbered lines, flagged
lines (findings file_path+line → amber bar) click-to-scroll the rail note;
`lib/highlight.ts::splitHtmlLines` splits highlighted HTML per line with
span-carry (node-tested: line count + text fidelity exact; closing fragment
of multi-line tokens loses color: accepted trade-off). AnnotationRail =
findings for the open file by line, expandable AI explain via shared
`useExplain`/`ExplainBox` (extracted from FindingsPanel; 3rd reuse).
`useFileContent` hook. M8 placeholders: Smali toggle + Edit & recompile
disabled. Docs: licenses.md +frontend section (react/vite/tailwind/
fontsource/highlight.js). Bugs caught: React key warning in FileTree (fixed),
manual tree-click passed `node.name` as rootName (broken content path:
found by review, fixed). Browser verified: CryptoClass.java auto-selected,
10 annotations, flags, toolbar; agent click-tooling flaky formanual-click re-verification.

Phase G built (Agent dock chat): `hooks/useChat.ts` (messages + send,
requestId race guard; 400 no-model / 409 / 504 / network classified to
friendly copy); `components/agent/AgentDock.tsx` (mockup 1:1: header steel
dot + "Agent · this scan", disabled 🌐 Web toggle (M7), collapse to 44px
rail via grid `1fr 340px` ⇄ `1fr 44px` in DashboardView; real welcome
message rebuilt per render so findings counts land after `useFindings`
loads; backtick→`<code>` spans; citations as **clickable file:line
`src-chip`s** jumping the Decompiler tab: `DashboardView.fileRequest` +
`openInDecompiler` (stable callbacks) → `DecompilerPanel` `requestFile`/
`onRequestConsumed` + `resolveTreePath` (exact → `<root>/<file>` → suffix
fallback, covers Android `sources/` + iOS `*.app` roots); error bubbles
with Retry, Enter-to-send (Shift+Enter newline, IME-safe), `.switch`
primitive added (Phase H reuses). Verified: tsc+build green; chat endpoint
returns the designed 400 (no chat model) in ~34ms; browser click-through
blocked by the recurring chrome-devtools outage (review-covered, like Phase
E).

**Decompiler follow-ups (Aug 6, owner review):** iOS decompiler no longer
shows the raw unzip: `tree.py` curates the `.app` walk to text-readable
files (hidden binary blobs collected into a collapsed **`Binary (Mach-O)`
(n) tree entry**: each listed inline with full path as inert dimmed rows
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

M6: **COMPLETE (Aug 9, 2026).** See `docs/progress/M6.md`. App-oriented
tool set added to the M4 Layers 2/3 surface in `agent/tools.py`:
`read_manifest` (AndroidManifest.xml / Info.plist), `get_decompiled_class`
(Android-only, fqcn→sources path), `get_permissions` (uses-permission set /
usage strings), `run_secrets_scan` (on-demand gitleaks re-run wrapping
`analysis/gitleaks.py::scan_directory`, 30 s timeout + size guard),
`search_strings` (resource/string-file grep). Platform-aware schemas via
`schemas_for_platform` (iOS never sees `get_decompiled_class`); `ChatResponse`
gained `tool_mode: tools | context-only` + `tools_used` (Agent dock shows a
small "tools used" line); `max_tool_rounds` is now a settings knob
(`MOBARK_MAX_TOOL_ROUNDS`, default 3) with a per-request override on
`ChatRequest`. Soft-offer gating per owner decision (tools to any model;
known-good list Qwen2.5/2.5-coder, Llama 3.1+ documented in techstack as a
recommendation only). Gates: **339 backend tests green + ruff clean; tsc +
vite build green.** Real-model QA remains an owner checkpoint (Ollama off
during dev).

**M6 follow-up (Aug 9, 2026: live tool steps + token streaming in the Agent
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

M8-M10: not started, except the M8 kickoff plan (PLANNED Aug 10, 2026,
see the M8 record at the end of this file; M7 is COMPLETE below).
**Post-M5 follow-up (Aug 8, 2026: Gemini provider + curated model list):** (1) **Google Gemini** added to the BYOK provider set, `providers.py` entry (`gemini/` prefix, `GEMINI_API_KEY`, base `https://generativelanguage.googleapis.com/v1beta`, `models_path=None` → static curated list, matching Anthropic), `config.py` `gemini_base_url`/`gemini_api_key`, `backends.py` field maps, BYOKTab add-provider chip. Note: base is pinned to `v1beta` because MobARK always passes `api_base` (litellm would otherwise self-select `v1alpha` for Gemini 3+ previews), curated models are v1beta-compatible. (2) **Settings dialog model chips are now CURATED with a See-all reveal** (owner UX request): `ModelBackendRead` exposes `suggested_models` (provider table is source of truth); `BackendsTab` shows suggested ∩ served by default (first 6 served for local/custom, which have no curated list), the configured default is never hidden, and a dashed `▼ See all (N more)` chip reveals the full served list (collapses on fresh probes). BYOKTab provider order: OpenAI, Anthropic, Gemini, DeepSeek, OpenRouter, Custom.
**Owner follow-up (Aug 8, 2026: BYOK seeding removed + custom key field):** (1) **BYOK backends are no longer seeded keyless** (`backends.py::_seed_backends`): a fresh store carries ONLY the local backends (`ollama`, `lm-studio`); BYOK providers seed only when a real key is configured via env/`Settings` (`MOBARK_OPENAI_API_KEY` etc.). Keyless cloud entries were unusable and only confused the Settings UI, cloud providers are now added exclusively via the BYOK menu (POST /backends requires the key; this is the only way in). Existing persisted stores keep whatever they had (the store file remains source of truth). Tests updated accordingly (seed = local-only, byok via POST). (2) **BYOK custom-endpoint form now includes an API key field** (`BYOKTab.tsx`, `needsApiKey` flag): base URL is required, key optional (some OpenAI-compatible endpoints are keyless). Gates: 281 backend tests green + ruff clean; tsc + vite build green.
**Owner follow-up (Aug 8, 2026: Gemini 2.5 deprecation + progress dialog):** (1) **Gemini curated list moved to the Gemini 3 family** (`providers.py`): Google 404s the 2.5 line (`gemini-2.5-flash`/`2.5-pro`/`2.0-flash`) for NEW API keys, "no longer available to new users". Curated set is now `gemini-3.5-flash`, `gemini-3.6-flash`, `gemini-3.5-flash-lite`, `gemini-3.1-pro-preview` (all v1beta-served; the pinned `api_base` still wins over litellm's v1alpha self-selection). (2) **Probe walks the curated list** (`health.py::check_backend`): with no model configured, the Settings probe tries every suggestion and records the first that answers, a single stale entry can no longer mark the whole backend unreachable; a user-configured model is still probed exactly (broken choices fail loudly). (3) **Deprecation hint**: `model_arch_hint` (`client.py`) now also appends "no longer served to this account" guidance when the upstream text says a model is no longer available, same self-explaining surface as the Ollama arch hint, shared by Settings probe/chat/insights. (4) **Scan-in-progress is now a DIALOG, not a scrollable view** (owner report: the full view could push header/footer off-screen): `ProgressScreen` renders a `.progress-overlay` (absolute within `<main>`, top bar stays visible) + modal with the pipeline, dismissible via ×/Escape/backdrop-click (scan keeps running; `App.tsx` `progressDismissed` resets per active-scan id); the backdrop shows the last completed scan's dashboard (`DashboardView` `scanOverride` + `TargetBar` `scan` props, newest non-running scan via `backdropScan`) or the empty state on a fresh install; polling now runs while ANY scan is queued/running (`anyScanRunning`) so a dismissed background scan's completion always lands. Gates: **285 backend tests green + ruff clean; `tsc -b` + `vite build` green.** (Model IDs are per Aug-2026 availability research, re-verify if Google shifts the 3.x naming again.)
**Follow-up (same session): Gemini models are now FETCHED LIVE, not hardcoded** (owner question "can't we fetch available models instead?"): Gemini has a real `models.list` (`GET /v1beta/models`), it was skipped only because it isn't OpenAI-compatible. `Provider` gained `list_style` (`"openai"` | `"gemini"`); `health._list_gemini_models` does the `?key=` query auth, strips the `models/` prefix, filters to `generateContent`-capable base models (embeddings out, `tunedModels/` never in this endpoint), and on ANY failure/empty result falls back to `suggested_models` with source `"suggested"` (never `[]`, the probe surfaces connectivity). So provider deprecations can no longer hard-break the app: the Settings chips/dropdown/probe now reflect what Google actually serves, and the curated list is only the offline fallback. Frontend needed no changes (BackendsTab/ModelPicker already consume `health.models`). Gates: **184 model/agent/scan tests green + ruff clean** (full suite re-run below).
**Follow-up (same session): Anthropic got the same live-first treatment** (owner request): Anthropic's `GET /v1/models` List Models endpoint is OpenAI-*shaped* (`{"data": [{"id": ...}]}`) but uses its own auth, `x-api-key` + `anthropic-version: 2023-06-01` headers, no Bearer. `providers.py` anthropic entry: `models_path="/v1/models"`, `list_style="anthropic"`; `health._list_anthropic_models` sends the anthropic headers (`limit=100`, one page covers the catalog), parses `data[].id`, and on any failure/empty/no-key falls back to `suggested_models` with source `"suggested"` (never `[]`). No provider carries `models_path=None` anymore; the curated lists for anthropic/gemini are pure offline fallbacks. Tests: anthropic live-parse (headers asserted, no Bearer), fallback-on-error, requires-key early return, probe-ok/failed/no-model-first-served/lightweight-live all moved to live semantics. Gates: **291 backend tests green + ruff clean** (frontend untouched).
**Follow-up (same session, verified live in compose): no-model probe prefers curated ∩ live**: live probing revealed Google's `models.list` STILL lists deprecated IDs first (`gemini-2.5-flash` 404s on use for new keys), so a fresh BYOK key with no model configured would still show a bogus probe failure. `health.py::check_backend` now, when no model is configured, picks the first **curated ∩ live** entry (curated list = known-current seed) instead of the raw `models[0]`, and walks those small candidates, the deprecated raw-first entry is never probed. Live-verified in compose against the real key: gemini now `probe_model: gemini-3.5-flash`, `probe_ok: True` (was failing on 2.5-flash). Gates: **292 backend tests green + ruff clean.**
**Follow-up (same session): BYOK per-provider toggle removed** (owner: "we already have active/inactive in Model backends"): `BYOKTab.tsx` cloud rows no longer carry an enable/disable switch (it duplicated the Model backends tab's toggle on the same `PUT {enabled}` path), each row keeps a read-only Active/Inactive status + **Remove**. The master **Enable cloud fallback** batch toggle was ALSO removed on the next pass (owner decision), BYOK is now pure add/remove; per-backend enable/disable lives entirely in the Model backends tab. `tsc -b` + `vite build` green.
**Follow-up (same session): risk scoring is now WORST + COUNT, not pure max** (owner: "suppressing one or two highs doesn't move the score; only when ALL highs are gone", this was the Aug 7 max-over-mean design, but the gauge felt like a switch). Owner approved: `risk = round(10×max_cvss)` plus ~1 point per extra finding at the TOP severity band (high), `int(0.9×(n−1)+0.5)`, capped at +9 so **risk ≤ 89** (CVSS 4.0 8.9 = top of the High band, the removed critical band is never re-introduced and the "CVSS 4.0 · risk n/100 · High" caption stays self-consistent). Bands below high keep their plain representative score (446 mediums = 55, same as 1 medium, the bonus is high-only by design). Live-verified sweep on scan 16: 11 highs = **89 → 88 → 87 → 86 → 85 → 85 → 84 → 83 → 82 → 81 → 80 → 55** as each high is suppressed (the 6↔7 flat step is expected rounding, pinned in tests; 10+ highs saturate at 89), the first unsuppress jumps 55 → 80 because one high reintroduces the worst band, then +1 per extra. **Migration 0006** (`0006_worst_plus_count.py`, self-contained, mirrors `risk.py` exactly, same Python `int(0.9*(n-1)+0.5)` semantics) recomputes every `done` scan; applied to the volume DB (scan 18 → 89, scan 13 → 84 per its own high count, mediums unchanged). Stale LLM copy fixed: `insights.py` summary `security_score_note` now describes worst+count. Frontend needed no logic change, `SecurityGauge` bands (≥70 High/crimson) and caption already handle 81–89 (doc comment updated). Gates: **309 backend tests green + ruff clean; tsc + vite build green.**
**Follow-up (same session): Agent dock chat UI (owner):** (1) **Send button disables when no model is connected**, `AgentDock` computes `modelConnected = backends.some(b => b.enabled && b.model)` from `useApp()` (the exact mirror of backend `pick_chat_backend` / ModelPicker's `active`), gates `submit()` and the button (`disabled={!draft.trim() || !modelConnected}`), and swaps the "⏎ to send" hint for an amber **"No model connected, pick one in the top bar or Settings"** (`.hint.warn`) + a tooltip on the disabled button. (2) **The "Thinking" bubble's Stop button was REMOVED**, the bubble now shows only the animated dots (the in-thread affordance comment in CSS updated). (3) **The input-row stop button (visible while sending) is now icon-only**, bare ■ with `aria-label`, no "Stop" text (`.stop-btn.stop-icon`, 34px square), matching mainstream AI-chat UIs. Live DOM-verified in compose with gemini enabled-but-model-empty: send renders `disabled` + tooltip, hint present, `.stop-icon`/`.hint.warn` in the served CSS. `tsc -b` + `vite build` green (no backend change; app image rebuilt).
M6.1: **COMPLETE (Aug 9, 2026).** See `docs/progress/M6.1.md`.
Dev-only fake LLM (owner request: demo the dock's live steps + token
streaming with zero Ollama). `MOBARK_FAKE_MODEL=1` (`Settings.fake_model_enabled`)
seeds a dev-only `fake` provider/backend (`providers.py`, kind local, static
`demo` model) FIRST in the M3 store so `pick_chat_backend` resolves it
deterministically: chat/explain/summary all demo against it.
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
stores. **Live-verified (Aug 9)**: env-alias bug: pydantic-settings derives
env names from field names, so the documented `MOBARK_FAKE_MODEL=1` was
silently ignored (server ran knob-off); fixed via explicit
`validation_alias="MOBARK_FAKE_MODEL"` (raw alias IS the env name; the MOBARK_
prefix is not re-applied) + regression test. Browser e2e: sent "where is the
webview?" in the dock → thinking tokens streamed with caret, live
`search_code` (✓ 100 results) + `read_manifest` steps, answer cited real
`com/google/android/gms/internal/zzgf.java:115`, `Tools (2)` trace expanded,
zero console errors. Dev-DB caveat: stale host DB at the deleted vector-era
0004 stamp: re-stamp 0003 → upgrade head → re-stamp 0007. Gates: **373
backend tests green (+23) + ruff clean; frontend untouched (`tsc -b` +
`vite build` green).**

**Follow-up (same session): the bonus went BAND-SYMMETRIC (owner approved):** `risk.py` now has `_BAND_RISK = {high: (80, 89, 0.9), medium: (55, 69, 0.9), low: (20, 39, 0.9)}`, the worst severity picks the band, base = `round(10×max_cvss)`, and each extra finding at that band adds `int(0.9×(n−1)+0.5)` capped at the band's CVSS 4.0 ceiling (high 89 · medium 69 · low 39 = the qualitative band tops 8.9/6.9/3.9 × 10). Clearing mediums now rewards progress too (16 mediums = 69 · 10 = 63 · 2 = 56 · 1 = 55), bands NEVER overlap (any high ≥ 80 > any no-high ≤ 69 > any low-only ≤ 39), and the caption "CVSS 4.0 · risk n/100 · band" stays literally true in every band (each cap IS the band ceiling, that was the discussion's key finding). **Saturation caveat (accepted)**: bulk bands sit at their ceiling, 446 mediums = 69 until the count drops below ~16, then the tail descends (progress shows via the severity-count stat boxes meanwhile). **Migration 0007** (`0007_band_symmetric_bonus.py`) re-scores every `done` scan (0006 test now upgrades to `0006` in isolation; new 0007 test: 3M → 57, 100L → 39, 11H → 89). Live-verified in compose: scan 16 (446M, no highs) 55 → **69**; scan 18 (11H) stays 89; scan 17 mediums descend 56 → 55 → 20 (low band) → restored 57 (it had one medium left suppressed from the Aug 8 e2e). Defensive `_BAND_RISK.get()` fallback keeps unknown-but-scored severities from crashing (review catch). Gates: **312 backend tests green + ruff clean; tsc + vite build green.**

M7: **Agent web research (on-demand; COMPLETE Aug 9, 2026, see
`docs/progress/M7.md`)**. Owner decisions at kickoff: (1) **agent-browser
DROPPED**: no browser automation in v1, JS-rendered pages degrade. (2)
**Deep-research / GPT Researcher pipeline DROPPED** (GPT Researcher's
Apache-2.0 license was verified: scope decision, not license): web research
is two on-demand agent tools, `web_search(query)` + `web_fetch(url)` (httpx
+ **trafilatura ≥1.8.0**: Apache-2.0 only at ≥1.8.0, earlier = GPLv3+),
gated by **per-scan opt-in** (`scans.web_research_enabled`, migration 0008,
default off), ChatGPT/Gemini-style: the model triggers search when a question
needs current/external info (CVEs, MASTG guidance, dep versions). (3)
**SearXNG = bundled, always-on** compose service: since Aug 14 it has NO
profile gate: a plain `docker compose up` starts it with the stack (before
that it was `profiles: [web]`, started on demand via `--profile web`; the
Settings ▶ Start engine button is now the recovery path for a stopped
container). Unmodified upstream image, our own minimal settings.yml enables
json format. **AGPL boundary**: SearXNG is AGPL-3.0; MobARK stays clean because it
runs as an unmodified separate container over HTTP JSON API only: never
imported/vendored/forked; AGPL §13 reaches modified copies of SearXNG
itself, not the calling app (`docs/licenses.md` row). (4) **Search provider
registry now, SearXNG only**: `search/providers.py` + `search/backends.py`
JSON store mirror the M3/M5 BYOK pattern; custom SearXNG-compatible
instances (base URL, no key) are the free-form BYOK analogue; Brave/Serper/
Mojeek are later rows. **Engine enablement is a Settings concern (owner
follow-up, same session):** each search backend carries an **Active/Inactive
toggle** in Settings → Search & research, **one Active at a time** (radio:
enabling one disables the others, mirroring `pick_chat_backend`
determinism); the store keeps `enabled` + `order` so a priority fallback
chain is a resolver-only change later. The Agent dock 🌐 toggle is the
**per-scan opt-in ONLY** (engine-agnostic privacy gate: never selects or
starts an engine) and is **disabled until an engine is Active** (greyed,
hint to Settings); web tools are offered only when BOTH the scan opt-in
(`scans.web_research_enabled`) AND an Active engine hold. **Ruled out as
future providers**: Google CSE (closing to new customers Jan 2027), Bing v7
(dead, HTTP 410), DuckDuckGo (no official API). M8–M10 unchanged.

**M7 built (Aug 9, 2026: Phases A–D, mocked-test gates green):**
`app/search/` package: `providers.py` (SearXNG bundled + custom table),
`backends.py` (`SearchStore`: `search_backends.json` 0600, env-seeded
`MOBARK_SEARXNG_BASE_URL`, **`enable_only(id)`/`active()` radio**: one Active
at a time, enforced server-side on `upsert(enabled=True)` and `add()`;
`enable_only` delegates to upsert so the radio has ONE implementation),
`client.py` (SearXNG `GET /search?q=&format=json` →
`[{title,url,snippet,engine}]`; **`web_fetch` = streaming bounded httpx +
trafilatura extraction, SSRF-guarded**: http(s) only, private/reserved
hosts refused at the first hop AND every redirect hop, IPv4-mapped-IPv6
loopback refused, body read in chunks capped at `web_fetch_max_bytes`;
`check_backend` probe never raises: a misbehaving engine degrades to an
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
(`SearchTab.tsx`: engine radio cards + base URL + Test probe + add/remove
custom, reusing BackendsTab/BYOKTab patterns: the per-scan opt-in lives
ONLY on the dock 🌐 toggle; a Settings copy was removed Aug 9);
Agent dock **🌐 Web toggle live** (per-scan opt-in only, disabled until an
engine is Active, green when on, "⏎ to send · 🌐 web on" hint); AppContext
`searchBackends` state + CRUD/probe/setWebResearch actions. Compose:
`searxng` always-on, no profile gate since Aug 14 (port 8888:8080, our
`docker/searxng/settings.yml`: json on, limiter off, mounted read-only at
/etc/searxng/settings.yml, `searxng-data` volume); `trafilatura>=1.8.0,<2.0`
in requirements.txt (the license boundary). Gates: **432 backend tests green
+ ruff clean; `tsc -b` + `vite build` green.** Remaining owner checkpoints:
containerized e2e (upload → enable research → chat streams a real search
via compose SearXNG) + real-model QA.

**Follow-up (same session, Aug 9: dock UX + compose SearXNG wiring, owner
review):** (1) **Agent dock minimum width raised 260 → 320 px**: at the old
min the header "Agent · this scan" overlapped the 🌐 Web toggle
(`DashboardView` `DOCK_MIN`); `.agent-header .title` also gained
`overflow: hidden` + `text-overflow: ellipsis` as a defensive clip at any
width. (2) **Dock drag-to-resize direction FIXED**: the real "extend/shrink"
complaint was the divider drag, not the button (owner confirmed: "extend
and shrink … using cursor … like in decompiler view"; the collapse button
glyphs were left at their original ⤡/⤢). The dock is the right-edge pane,
but its splitter ADDED the delta (`+ d`), so pulling the divider right GREW
the dock: the opposite of every other divider in the app (the decompiler
rail shrinks when dragged right via `railW - d`). Now `dockW - d`: drag
right narrows the dock, drag left extends it, matching the rail splitter. (3) **Settings per-scan opt-in section REMOVED** (`SearchTab.tsx`
`ScanOptInSection`): redundant with the dock 🌐 toggle; the dock remains
the single per-scan control (`setWebResearch` / `PUT /scans/{id}/web-research`
unchanged). (4) **Compose app/worker now set
`MOBARK_SEARXNG_BASE_URL: http://searxng:8080`**: inside the compose network
the seeded `localhost:8888` pointed at the container itself (Connection
refused); the store seeds from the env on first read, an existing
`search_backends.json` keeps its own URL (edit in Settings → Search &
research). The engine is always-on with the stack (no profile step since
Aug 14); a stopped container is restarted with `docker compose up -d
searxng` (published to host `localhost:8888`). (5) **Web 🌐 toggle now also
locks
without a chat model**: it was gated only on an Active engine; now
`webLocked = !activeEngine || !modelConnected` greys it and makes it
click-inert with a "No model connected: pick one in the top bar or
Settings" tooltip, mirroring the send-button gate (web research is
meaningless with no agent to run it).

**Containerized e2e RUN (Aug 9): the M7 owner checkpoint, live in
compose with the fake model (Ollama off):** (1) **SearXNG crashed on boot:
`server.secret_key: The value has to be one of these types/values: str`.**
Our minimal `docker/searxng/settings.yml` lacked the `use_default_settings:
true` merge flag AND a secret_key; SearXNG 2026.8.4 schema-validation hard-
fails without them. Fixed in the file (fixed dev secret, localhost-only
engine) + validated in a throwaway container before recreating. (2) The
engine is reached live end-to-end: `POST /search/backends/searxng/test`
from the app → `reachable: true, result_count: 1` (app→`searxng:8080`
in-network). (3) The persisted store kept `localhost:8888` (file is source
of truth): repointed via `PUT /search/backends/searxng {base_url:
http://searxng:8080}` (the documented Settings edit, done via API).
(4) Full chat e2e on scan 19 (InsecureBankv2, `MOBARK_FAKE_MODEL=1`):
`PUT /scans/19/web-research {enabled:true}` → `POST /scans/19/chat/stream`
"any known CVEs?" → streamed thinking tokens, live `web_search` tool step
**10 real results / 1.1s**, `web_fetch` attempt → **HTTP 403 from the top
hit (medium.com blocks the honest `MobARK-agent/0.1` UA)**: degrades
cleanly. (5) **Fake web script FIXED** (regression-tested): it used to
re-fetch the SAME failed URL until the 3-round limit, so the final answer
lost its citation; now round 3 composes from the search results (cites the
top URL + "the top page blocked direct reading" note): `_web_response`
never retries a failed fetch. Real-model QA remains an owner checkpoint.

**Follow-up (same session): one-click engine start (owner request):**
Settings → Search & research now has a **▶ Start engine** button on the
bundled SearXNG card whenever the probe reports it unreachable: instead of
only the `docker compose --profile web up -d searxng` hint text. Backend:
`POST /search/backends/{id}/start` runs the FIXED compose argv (no shell /
no user input: not an injection surface) with the compose file discovered
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
container: this button is the explicit start affordance.

**Follow-up (same session, Aug 9): search provider registry expanded
(owner question: "what about duckduck, brave etc.? can it be simplified to
base URL + API key?")**: Settings → Search & research now offers four
providers instead of only SearXNG. The add-form is a **provider picker**
chip row (mirroring BYOKTab) whose fields adapt per provider: base URL
(pre-filled with the provider's default, optional when it has one) + API
key (required for keyed providers, hidden for SearXNG instances).
Providers: **custom** (SearXNG-compatible, base URL only), **brave**
(`api.search.brave.com`, `X-Subscription-Token` header, `GET
/res/v1/web/search`), **serper** (`google.serper.dev`, `X-API-KEY` header,
`POST /` JSON body: Google SERP), **mojeek** (`www.mojeek.com`, `q` +
`api_key` params, `fmt=json`). DuckDuckGo stays ruled out (no official
API); Google CSE (closing Jan 2027) and Bing v7 (HTTP 410) remain future-
rows only. `search/providers.py` now carries the keyed rows
(`key_required`/`default_base_url`/`query_style`/`parse_style`);
`client.py` dispatches by `query_style` (`searxng` | `brave` | `serper` |
`mojeek`) with per-style normalizers → the shared `[{title,url,snippet}]`
shape, plus a **key-rejected hint** (401/403 → "check the API key in
Settings") and a keyed-aware `check_backend` probe (skips the real query
when no key, reports `missing key`). `backends.py` env-seeds keyed engines
from `MOBARK_BRAVE_API_KEY` etc. but **disabled** (key presence alone never
activates an engine: the radio does); `upsert` accepts `api_key`;
`config.py` gains the key fields; `schemas.py` gains `has_api_key`,
`api_key` on create/upsert, and `GET /search/providers` (the picker's
source of truth). Frontend: `types.ts` `SearchProvider` + `api_key`
fields, `api.searchProviders()`, `SearchTab` provider-chip add-form with
a **key-set indicator** ("✓ key set" on a backend row): `api_key` is
write-only in responses. Tests: provider invariants (every keyed row has a
default base URL + parse style), keyed normalizers (brave/serper/mojeek
parse fixtures), key-rejected hint, env-seed-disabled, API create-with-key
+ has_api_key + GET /providers. Gates: **457 backend tests green (+15) +
ruff clean; tsc + vite build green**; live in compose: `GET
/search/providers` serves all four rows with correct shapes.

**Follow-up (same session, Aug 9): manual web-search testing + chat chip
overflow fix (owner):** (1) **The fake model now searches with the USER'S
OWN question text**: `fake.py::_web_query` picks the last user message
(≥4 chars, else the canned `InsecureBankv2 known vulnerabilities CVE`
fallback) as the round-1 `web_search` query, so a manual test types its own
search in the dock and the fake runs it verbatim (a real model would
paraphrase; the fake is a script). Live-verified in compose: question
"SQLite database CVEs 2026" → `web_search` args `{query: "SQLite database
CVEs 2026"}` → 10 results → `web_fetch` of the top hit (sqlite.org/cves.html,
read cleanly this time) → cited answer with the source URL. Manual test
recipe: fake model selected (MOBARK_FAKE_MODEL=1) + an Active engine in
Settings → Search & research + the dock 🌐 toggle on (per-scan opt-in):
then just ask; the tool steps stream live and the `Tools (n)` trace shows
the real results. (2) **file:line citation chips could escape the chat
bubble** (long unbroken paths): fixed three ways: `AgentDock`
`shortenPath` (middle-ellipsis keeping the filename:line tail + full path
in the chip tooltip), `.src-chip` `max-width:100%` + ellipsis floor (with
`.src-row` capped), and `.md code`/`.msg` `overflow-wrap: anywhere` so
inline paths in answers wrap instead of pushing the bubble out of the dock.
Gates: **459 backend tests green (+2 new) + ruff clean; tsc + vite build
green**; app image rebuilt and live.

**Follow-up (Aug 10: guided SearXNG start + auto-detect, owner report):**
the ▶ Start engine button in Settings → Search & research could NEVER start
anything inside the app container (no Docker CLI/socket/compose file: the
endpoint 502s with the manual command by design). Owner chose **guided start
+ auto-detect** over mounting docker.sock (which would hand the container
that analyzes untrusted APKs host root: rejected). Frontend-only fix in
`SearchTab.tsx` + `.engine-guide` CSS: on the 502, `extractStartCommand`
parses the backticked command (anchored on `docker compose`: the
compose-failure format embeds the stderr tail BEFORE the command) and the
card switches to a guided panel: the exact host command in mono + a Copy
button (clipboard, transient "Copied ✓") + "◌ Detecting: checking every
4s…" status + the raw 502 note; a polling effect calls
`listSearchBackends()` every 4s (lightweight reachability) and on
`health.reachable` merges via `refreshSearchBackends` + a best-effort real
probe, flips to a green "✓ Engine is up" that auto-clears after 4s; 120s
cap → "Still unreachable: run the command + click Test" with Dismiss and
Stop waiting. Review catches fixed: the polling effect depends on the
STABLE `refreshSearchBackends`/`testSearchBackend` callbacks, not the whole
`actions` object: AppContext rebuilds it on any state change (e.g. App.tsx
polling scan progress while a scan runs), which would have restarted the
interval and reset the 120s cap indefinitely; `role="status" aria-live` on
the panel. Gates: tsc + vite build green (index-Dn58xM0n.js); live e2e in
compose: Settings → Search & research → Start engine → panel with the exact
command + Copy + Detecting + the 502 note → ran the SAME command on the host
(`docker compose --profile web up -d searxng`, restoring the engine that had
Exited 137 ~24h earlier) → auto-detect flipped to "Engine is up" within
~1 min → card dot online, Start row gone, Test → Probe OK (result_count 1),
zero console errors. (Note: a first e2e pass reported 2 fails that were MY
script's ambiguous `.backend-card` selector: the model-backends pane shares
the class; re-scoped to `.modal-pane.active` and all checks passed.)

M8: **Edit & recompile (Android); COMPLETE (Aug 10, 2026)**,
kickoff spec (`docs/m8-kickoff-spec.md`, interview record) + plan
(`docs/progress/M8.md`, phases A–E); Phases D–E not started. **Phase A
built**: apktool **3.0.3** (pinned jar + `java -jar` wrapper script at
`/opt/mobark-tools/apktool/`) + build-tools **35.0.0** zipalign/apksigner
(`/opt/mobark-tools/build-tools/`, flattened from the version folder so
apksigner keeps its `lib/`) bundled in `docker/Dockerfile.app` (open item 1
pinned; size gate measured at the Phase E container gate).
`analysis/apktool.py` (mirror of jadx.py: `decode()` = `apktool d -f -o
<work>/<scan>/apktool <apk>`, clean ApktoolError on timeout/non-zero/
exit-0-without-manifest; `is_ready(scan_id)` = filesystem-derived, the
`AndroidManifest.xml` presence rule: crash-safe). Migration **0009**:
`scans.apktool_status` (`not_started|queued|decoding|ready|failed`,
server_default not_started) + `scans.apktool_error` (Text): the column
tracks in-flight states, the tree is the truth for ready.
`workers/jobs.py::run_apktool_decode` (idempotent on is_ready, iOS returns
a clean Android-only error, failure → failed + apktool_error) +
`enqueue_apktool_decode`. API (scans.py): `POST /scans/{id}/smali` (202
enqueue; 409 not-analyzed / iOS / in-progress / already-ready: the
filesystem check runs FIRST so a stale column never re-decodes; `failed`
retries; enqueue failure → 500 + failed) + `GET /scans/{id}/smali-status`
(filesystem-derived ready) + `apktool_status`/`apktool_error` on ScanRead.
Frontend: Decompiler toolbar Smali chip **live**: not_started click →
POST + 2 s poll (in-chip `.smali-spin`); queued/decoding → busy;
failed → disabled + crimson title/`.hint-error` with the reason + a
`↻ Retry decode` button; ready → the toggle activates; chip hidden on
iOS (open items 5/6 per default).

**Phase B (edits model + Smali view, Aug 10)**: migration 0009 extended
with the **`edits` table** (id/scan_id FK/file_path apktool-root-relative/
original_content/new_content/unified_diff/source manual|agent/instruction/
status proposed|applied|rejected|reverted/build_id nullable→FK lands in
C/created_at/applied_at). `analysis/editable.py` = **can_edit** (smali*/
res/AndroidManifest.xml only; jadx sources + jadx-fallback smali + original/
+ unknown/ + all iOS read-only, server-enforced) + the path mapping
helpers (`MANIFEST_ROOT="AndroidManifest.xml"`: the synthetic single-file
tree root; tree path `AndroidManifest.xml/AndroidManifest.xml` ↔ edit path
`AndroidManifest.xml`). `analysis/edits.py` service: stdlib difflib
`make_unified_diff`, `newest_applied`/`effective_content` (newest applied
edit's new_content), `create_manual_edit` (created **applied**: baselines
on the EFFECTIVE content so same-file edits stack; rejects unchanged),
`apply/reject/revert` transitions (revert pops to the prior state).
Effective-content reads: `tree.read_tree_file(..., effective=True)`
overlays applied edits via its own SessionLocal (defensive); the on-disk
apktool tree is never mutated. `list_tree` appends the apktool roots once
`apktool.is_ready` (`smali`, `smali_classesN` via `apktool.smali_roots`,
`res`, manifest root). `analysis/smali_map.py` = Java⇄Smali mapping
(multidex first-found; jadx-fallback smali never maps back) behind `GET
/scans/{id}/files/smali-sibling`. API: `GET/POST /scans/{id}/edits` (201;
409 not-analyzed/Android-only/decode-not-ready; 400 non-editable/unchanged;
413 cap 200 KB; 404 missing baseline), `GET .../edits/{eid}/diff`, `POST
.../apply|reject|revert` (400 on wrong state). Frontend: `CodeEditor.tsx`
(plaintext, gutter lines translate with scroll, dirty, Ctrl/Cmd+S,
save-status) replaces CodeViewer for editable roots; the Java/Smali chips
jump the open file to its counterpart (`smaliSibling`); the tree refetches
when a decode turns ready. Gates: **524 backend tests green (+40) + ruff
clean; tsc + vite build green.** Docker image rebuild + size measurement
and the awkward-APK candidate (open item 2) remain for Phase E.

**Phase C (rebuild pipeline + resign, Aug 10)**: migration 0009 extended
with the **`builds` table** (id/scan_id FK/status queued|running|done|failed/
stage applying|rebuilding|zipping|signing|done/error Text/edits_json snapshot/
artifact_name/path/sha256/created_at/finished_at) + `edits.build_id` FK
(SET NULL; builds created before edits so the FK resolves).
`analysis/rebuild.py` = `build_apk` (fresh copy of the pristine decode →
`apply_edits` overlay: traversal-guarded, missing file fails loudly →
`apktool b` → `zipalign -f 4` **before** signing → `apksigner sign` →
`apksigner verify` gate: a signed-but-invalid APK is a failed build) with
`on_stage` callbacks (queued→applying→rebuilding→zipping→signing→done).
**Install-scoped test keystore** (decision 10): `ensure_keystore()`
generates `data_dir/mobark-test.jks` once (keytool from the bundled JRE,
alias `mobark-test`, RSA 2048, JKS) + a **random passphrase** in
`data_dir/mobark-test.jks.pass`: both 0600, BYOK precedent. Artifact naming:
`{stem}-resigned-test-{build_id}.apk` under `data_dir/artifacts/<scan_id>/`
(the label embedded in the filename, decision 9; minor format deviation
from the checklist's `-{scan_id}-b{n}`: build_id is unique per scan, same
contract); intermediates cleaned in `finally`; `cert_sha256()` parses the
verify digest for Phase E's fingerprint comparison.
`workers/jobs.py::run_rebuild(scan_id, build_id)` snapshots the applied
edit ids into `builds.edits_json` **at job start** (mid-build
apply/reject never mutates the tree), fails loudly with stage + stderr
reason, marks consumed edits' `build_id` only on success, allows zero-edit
(pristine) rebuilds (open item 4 = yes) + `enqueue_rebuild`. API (scans.py):
`POST /scans/{id}/rebuild` (202; 409 not-analyzed/Android-only/
decode-not-ready/**one-in-flight-per-scan**; 500 enqueue failure marks the
build failed) · `GET /scans/{id}/builds` (newest first) · `GET
/builds/{bid}` (modal poll target) · `GET /builds/{bid}/download`
(FileResponse, labeled Content-Disposition + `X-Resigned-Test-Build`
header, 409 not-done / 404 missing-on-disk). `BuildRead` exposes `edit_ids`
(parsed from edits_json via `validation_alias`: from_attributes maps by
the alias, not the field name). Frontend: the **Edit & recompile button is
live** (hidden on iOS: open item 6 default; disabled until decode-ready)
→ `RecompileModal.tsx` (620px, `.modal-overlay` pattern): persistent
un-dismissable amber test-build warning (decision 10), applied-edit count,
Recompile button (disabled while a build runs), live 5-dot stage pipeline
(2 s poll, settle-refresh both lists), done → labeled download + sha256,
failed → stage + specific error + ↻ Retry, plus the **Edits & builds
full-history panel** (decision 8): builds (status/stage/date/edits,
re-download any done artifact) + edits (per-applied "Restore original":
revert pops to the prior state). Reviewer fixes (same pass): dead `STAGES`
removed; keystore orphan recovery (keystore present but passfile missing →
unlink + regenerate) + `_write_0600` (no write-then-chmod window);
**stale-build reaping** in the trigger (queued >5 min / running >45 min →
failed "stale build" so the one-in-flight guard can't strand the scan after
a worker crash); `run_rebuild` refuses a build/scan id mismatch; the
**download endpoint constrains `artifact_path`** to the scan's artifact dir
(resolve + is_relative_to); apktool b in the pipeline is bound by the
rebuild step timeout (decode keeps its own default); streaming sha256;
modal close callback stabilized (useCallback: no re-subscribe churn).
Gates: **557 backend tests green (+33) + ruff clean; tsc + vite build
green.**

**Phase D (agent edit flow, Aug 10)**: `agent/tools.py` gained
`read_editable_file(path)` (reads the **current effective content**:
baseline + newest applied edit: of an editable apktool-root-relative path,
so proposals stack on what a rebuild would compile; containment check runs
BEFORE the editability check so traversal attempts get the `escapes` error)
and `propose_smali_edit(path, instruction, new_content)`: validates
editability + `MAX_EDIT_CHARS`, stores a **`proposed`** edit row + generated
unified diff via `edits.create_agent_proposal` (same stacking rule as
manual edits; **never auto-applies**: decision 7), returns `{edit_id,
file_path, instruction, status, unified_diff}` (diff capped at 2000 chars
for the model; full diff lives in the DB + review panel). Both gated by
`edit_tools_allowed(scan_id)` (Android AND filesystem-derived
`apktool.is_ready`: same derive-don't-trust-the-column rule as the Smali
chip) and filtered out of `schemas_for_platform` unless
`edit_tools_enabled=True`: the model never even *sees* them on iOS or an
undecoded scan (M7 web-tool precedent); handlers re-check both gates
defensively. `chat.py` appends an **M8 EDIT TOOLS** system-prompt section
only when they're offered (the review contract: a real model proposes,
never claims it applied anything; non-editable files are read-only).
`propose_smali_edit` reads the edit's columns BEFORE closing its session
(SQLAlchemy expire-on-commit → DetachedInstanceError otherwise) and
converts TreeError/FileNotFoundError to clean ToolErrors. **Fake-model
flagship demo** (`model/fake.py`): round 1 `read_editable_file` on the
bar's target, round 2 `propose_smali_edit` (manifest: toggles
`android:debuggable` true↔false / inserts `false` on `<application>` when
absent; smali: appends a `# MobARK demo edit - <instruction>` comment;
unsupported targets never guess an XML edit → honest fallback), round 3 a
cited answer with the stored proposal for review: a failed step composes an
honest answer instead of retrying (M7 precedent); the demo triggers only on
edit-y questions when edit tools are offered (the bar's `(Target editable
file: …)` hint always counts; non-edit questions keep the M6.1 main demo).
Frontend: the **✨ Ask agent to edit bar** (mockup 1:1: `.aeb-tag` + input +
Apply; visible when an editable file is open AND a chat model is connected,
mirroring the dock's no-model gate) sends the instruction with the open
file pre-set (appends the target hint), streams its own inline reply
(`useChat` per panel: token caret + live steps + Tools (n) trace) under
the bar, and **auto-opens `ProposalsModal`** when a turn lands a successful
`propose_smali_edit` (guarded per message id). `ProposalsModal` = the
**diff-review panel (D7)**: per-file cards with lazy-fetched git-style
colored unified diffs (`.pr-line.add/del/hunk/ctx`) and per-file
Apply/Reject; the toolbar **Review edits (n)** badge counts proposed rows;
applying bumps `editVersion` → an open editor remounts + refetches the
effective content so a manual save can never overwrite a just-applied agent
edit. Gates: **582 backend tests green (+25) + ruff clean; tsc + vite
build green.** Phase E (hardening + contract-style e2e) remains.

Three-round owner interview locked the decisions: (1) **apktool decode is
on-demand**: an RQ job triggered by the first Smali view / first edit
(cached per scan), never a scan-pipeline step; (2) **edits are diffs in the
DB** (new `edits` table: original + new content + unified diff per row),
**applied at rebuild** onto a fresh copy of the decoded tree: never silent
tree edits, revert-safe; (3) **Android only: iOS edit/ldid resign deferred
to v1.1**: verified research: an `ldid -S` re-signed IPA installs only on
jailbroken devices (AppSync Unified) or as handoff input for the user's own
Sideloadly/Apple-ID signing; stock iOS rejects it and the simulator won't
run it (wrong platform slice); iOS keeps the read-only bundle view;
(4) **toolchain bundled + size gate bumped**: apktool (pinned jar) +
Android build-tools zipalign/apksigner installed at build time (`keytool`
already ships in the JRE); owner approved growing past 450 MB;
(5) **agent surface = dock chat tool AND the mockup-faithful inline "Ask
agent to edit" bar**; `propose_smali_edit(file, instruction, new_content)`
stores a `proposed` edit + unified diff for human review, never
auto-applies; apply/reject/revert are human API calls, file-by-file for
multi-file proposals; (6) **full edit/build history per scan**: per-file
restore-original + `builds` table (status/stage/error/edits snapshot) with
re-download of any prior artifact; (7) **one install-scoped test keystore**
per MobARK install (generated once into `data_dir`, `0600`, BYOK-key
precedent), reused for every rebuild; (8) **rebuild pipeline** = apply
edits → `apktool b` → `zipalign -f` → `apksigner sign` → `apksigner verify`
sanity gate; every stage fails loudly with a specific error, never a
silently broken APK; (9) **e2e is contract-style (no emulator)**: artifact
passes `apksigner verify`, signature fingerprint differs from the original
APK, filename carries `-resigned-test-`; real-device install = owner manual
checkpoint; (10) **persistent, un-dismissable "resigned test build" label**
: modal warning + filename + download header. Migration **0009**: `edits`,
`builds`, `scans.apktool_status`/`apktool_error`. mobark-tasks.md updated:
iOS items moved to Deferred/v1.1, smali-decode task notes on-demand timing,
e2e item re-scoped to contract-style, M8 section now links the plan. Open
kickoff items (non-blocking): pin apktool + build-tools versions, choose the
awkward-APK fail-loudly test candidate, confirm the `propose_smali_edit`
contract.

**Phase E COMPLETE (Aug 10, 2026: hardening + contract-style e2e; M8 done):**
(1) **Awkward-APK fail-loudly (open item 2 resolved)**: candidate is a
**deterministic synthetic fixture** (`scripts/make_awkward_apk.py`: corrupt
`resources.arsc` + plain-text manifest in an APK-shaped ZIP). Real apktool
in the image fails the decode with the specific reason (`Unexpected chunk:
0x6702 (expected: RES_TABLE_TYPE)` from BinaryResourceParser);
`apktool_status=failed` + `apktool_error` carry it; no ready tree. The
REBUILD-side awkward case = an invalid-smali edit: build row `failed` at the
**`rebuilding`** stage with apktool's exact `Could not smali file` reason,
**no artifact**, download 409; `rebuild.py` now wraps the `ApktoolError`
from `apktool b` into the stage-tagged `RebuildError`. New unit tests:
service + job rebuilding-stage failure, awkward-decode fail-loudly chain,
and the **mid-build edit/rebuild race** (an edit applied after the job's
snapshot never reaches the build tree: `edits_json` immutable, late edit's
`build_id` stays None). (2) **Containerized contract-style e2e PASSED**: scan
20 InsecureBankv2 → real apktool 3.0.3 decode (ready in ~60s) → **manual
manifest edit** (debuggable off) + **agent-proposed edit** (fake model
streamed `read_editable_file` → `propose_smali_edit`; dup manifest
proposals rejected via the human API, smali `# MobARK demo edit` comment
applied) → `POST /rebuild` → done in ~10s → `InsecureBankv2-resigned-test-1.apk`:
**`apksigner verify` passes (CN=MobARK Test Signer) + `zipalign -c 4` passes +
fingerprint differs (`24d14ee1…` vs original `8092db81…`) + `-resigned-test-`
filename** + labeled download (`Content-Disposition` + `X-Resigned-Test-Build:
true`); build 1 `edits_json` = [1,6]; failed awkward build 2 stayed in
history (decision 8). (3) **iOS regression**: scan 22 iBugBazaar keeps the
read-only bundle tree (no smali/res/manifest roots); smali/edits/rebuild all
409 Android-only (decision-5 copy); toolbar hides the M8 affordances on iOS.
(4) **Build-tools pin fix (open item 1, found at the gate)**: Google now
serves `build-tools_r<v>_linux.zip` (underscore): `build-tools_r35.0.0-linux.zip`
404s and 35.0.0 was never published under the underscore scheme; Dockerfile
pinned **35.0.1** (`build-tools_r35.0.1_linux.zip`, verified against
repository2-3.xml) and both images rebuilt. Gates: **586 backend tests green
(+4) + ruff clean; tsc + vite build green**; image **3.47 GB content /
783 MB compressed** (bump approved). Browser DOM click-through blocked by the
recurring chrome-devtools outage (code review + the API-level e2e covered it,
per precedent). Owner post-completion checkpoints (not blockers): real-model
QA of the agent edit flow; optional manual install-and-run of a rebuilt APK.

**Follow-up (Aug 10: annotation-rail overflow fix, owner report):** the
Decompiler annotation rail's last note could overflow its bubble: long
unbroken finding-title tokens like `com.android.insecurebankv2.LoginActivity`
pushed past the `.note` border (no wrap rule). Fixed with the M7-precedent
`overflow-wrap: anywhere` on `.note` (index.css); verified headless-Chrome
against the exact built CSS (note scrollWidth == clientWidth, overflowPx 0)
+ the app image was rebuilt/recreated so the served bundle carries it.

**Follow-up (Aug 10: decompiler sticky title + annotation-rail minimize,
owner report):** (1) **Code title overlap fixed**: scrolled `.code-line`
rows (position:relative, DOM-after) could paint OVER the `.code-file-path`
title. `.code-file-path` is now `position: sticky; top: 0; z-index: 2` with
the opaque pane background (`#111417`) + border-bottom, so lines (and their
`.flagged::before` bars) scroll beneath a solid title. (2) **Annotation-rail
minimize**: `.rail-min-btn` (−) in the rail header collapses the rail:
`.decomp-layout.rail-min` swaps the splitter+rail for a slim 28px
`.annot-rail-collapsed` vertical restore strip (writing-mode label
"Annotations (n)"); state persisted as `mobark.decomp.railMin` (1/0) like the
splitter widths, restore returns to the saved rail width; `railMin`/`readFlag`
added to DecompilerPanel (AnnotationRail gained `onMinimize`); ≤900px hides
the strip too. Gates: tsc + vite build green (index-BPdWG6X4.js); reviewer
clean (non-blocking nit: flagged-line click while minimized sets the note id
silently: appears on re-expand); live headless-Chrome on :8000: after deep
scroll elementFromPoint at the title's center hits the title (no overlap),
minimize→strip→restore round-trip with `rail-min` class + localStorage
1→0, zero console errors; app image rebuilt/recreated.

**Follow-up (same session: the sticky title still showed code ABOVE it;
root cause was the pane's padding, not stacking):** empirically measured an
18 px band of `code-line`/`code-text` above the scrolled title. Cause:
`position: sticky` is constrained to the parent's **content-box top edge**:
`.code-pane`'s `padding: 18px 0` pushed that edge down, so the title could
never reach the pane's true top (the earlier elementFromPoint check only
probed the title's CENTER, missing the band above). Fix (index.css): the
18 px top spacer moved OUT of `.code-pane` (`padding: 0 0 18px`: bottom
padding kept) and INTO the sticky `.code-file-path` (`padding: 18px 18px
12px`) so the opaque bar covers the full strip; `.code-editor .code-file-path
{padding-top: 0}` keeps the Smali editor's flex header (non-sticky) flush.
Gates: tsc + vite build green (index-DnrDHuQm.css); reviewer clean; live
headless-Chrome: deep scroll gap = **0 px**, element at the title's top edge
is the title, at-rest first-line offset preserved (58 px, ~same as the old
54 px), editor header padding-top 0 / flush, zero console errors; app image
rebuilt/recreated.

**Follow-up (Aug 10: scan-switch view pinned to the first scan, owner
report):** switching scans from the TargetBar dropdown left the dashboard
showing the OLD scan until a manual browser refresh. Root cause: `DashboardView`'s
risk-backfill state (`scan`) pinned the derived `current = scan ?? scanOverride
?? activeScan`: once the backfill cache was non-null it shadowed the
selection forever, and the backfill effect was keyed on `current?.id`
(unchanged) so it never re-ran. Fix: `current` now derives from the
SELECTION (`selected = scanOverride ?? activeScan`) and only accepts the
cache when its id matches (`scan?.id === selected?.id ? scan : selected`);
the backfill effect keys on `selected?.id`, seeds the selection into the
cache first, and guards the async response with a functional id check (a
mid-flight switch can never land a stale backfill). Also keyed
`DecompilerPanel` per scan (`key={current.id}`, the AgentDock/CodeMapsPanel
precedent) so its M8 per-scan state: the ✨ ask-agent `useChat` thread
(which never sees scanId), the Smali decode status, and the edits list:
resets on switch while staying mounted across tab switches. Gates: **tsc +
vite build green**; **live-verified in headless Chrome against the running
stack via a CDP script (chrome-devtools agent outage again)**: two
consecutive dropdown switches (iBugBazaar.ipa → awkward.apk →
iBugBazaar.ipa) each updated the header + Findings count without a reload,
zero console errors. **App image rebuilt + container recreated** (`docker
compose build app && docker compose up -d app`; frontend-only change so the
worker image is untouched): now serves `index-DTGS7Orx.js` (was
`index-BlL6kSES.js`), health ok, and the same CDP scan-switch testre-run against the SERVED container on :8000 passes.

**Follow-up (same session): Code maps tab hidden on iOS (owner):** the
Code maps tab is Android-only in v1 (the graph builds the decompiled Java
tree; iOS has no source-like files and the backend 409s non-Android), so the
tab no longer appears on iOS scans at all: `DashboardView` filters the
`codemaps` entry from the tabs array when `current.platform === 'ios'` and
guards the panel render with the same condition (the CodeMapsPanel is never
mounted on iOS). A fallback effect resets `tab` to Overview when the active
tab is the hidden one (`tab==='codemaps' && platform==='ios'`: the user
switched scans while on Code maps), so the main area is never blank with no
active tab. Android scans keep the tab (platform null falls through to show,
mirroring the `platform == null || isAndroid` toolbar convention). Gates:
tsc + vite build green; app image rebuilt + container recreated (now serves
`index-DrTX3bwT.js`); **live-verified on :8000 via headless Chrome**: iOS
scan 22 tabs are Overview/Findings/Dependencies/Decompiler/Report (no Code
maps), Android scan 21 shows Code maps and it opens, switching back to iOS
while ON the Code maps tab lands on Overview, zero console errors.

**Follow-up (same session): Decompiler toolbar fully hidden on iOS (owner):**
the M8 toolbar already gated the Smali chip and Edit & recompile on
`platform == null || isAndroid`, but the Java chip rendered unconditionally:
iOS showed a lone meaningless "Java" chip. `DecompilerPanel` now wraps the
WHOLE `.decomp-toolbar` (Java/Smali view toggle + Smali decode chip +
Edit & recompile + Review edits) in `androidToolbar = platform == null ||
isAndroid`, so iOS renders none of it; the now-redundant inner gates were
removed (the wrap guarantees them; Retry decode keeps its own
`isAndroid && smaliFailed` so unknown-platform still shows nothing). The
view-hint fallback was split: Android/unknown keeps the Smali-chip guidance,
iOS gets the accurate "Read-only: iOS scans show the unpacked bundle" copy.
CSS check: `.view-hint` has no `margin-top`, so removing the toolbar leaves
no spacing gap. Gates: tsc + vite build green; app image rebuilt +
container recreated (serves `index-DQ3ol0Hg.js`); **live-verified on :8000
via headless Chrome**: iOS scan 22 Decompiler tab has NO toolbar (zero
chips, no Edit & recompile) + the iOS hint copy, Android scan 21 shows
Java/Smali chips + Edit & recompile (with the awkward.apk decode-failed
hint + Retry), zero console errors.

**Follow-up (same session): iOS Decompiler audit CLEAN (owner request,
no code change):** with the toolbar gone, the rest of the iOS Decompiler
tab was audited live on :8000 (scan 22 iBugBazaar) via headless Chrome at a
desktop viewport (the ≤900px responsive rule collapses the layout to
tree+code by design: the audit's first run at 800×600 mis-measured the
rail as 0, a harness artifact, not a bug). Results: full 5-column layout
intact (tree 140 / code 736 / rail 160 px); tree roots = `analysis` +
`vulnios_prod.app` (the .app bundle root is named after the real app dir
inside the IPA: NOT `iBugBazaar.app`); `Binary (Mach-O) (7)` group
present with 7 inert `aria-disabled` rows that all become visible on
expand; the 4 generated analysis docs all open with content (macho-profile.md
50 lines, entitlements.plist 5, exported-symbols.txt 21, insecure-imports.txt
15); annotation rail renders `Annotations (0)` with the honest empty-state
copy: correct, since all 9 iOS findings are binary-level (0 carry
file_path, by design), so no file can legitimately show notes; zero console
errors.

**Follow-up (same session): Decompiler tree now FILTERED by the
Java/Smali tab (owner decision Aug 10; question: "what is the use of the
java/smali tab if the tree shows both?").** The chips were previously a
per-file representation indicator + sibling jumper while the tree always
showed every root (jadx sources/resources + apktool smali/res/manifest
side by side). Now the tree follows the active view: `DecompilerPanel`
gains `isJavaRoot` (`sources`/`resources` = Java side) + a `visibleRoots`
memo that filters `files.roots` by `view`, **Android only** (iOS keeps the
full bundle tree: the toggle is hidden there): Java mode = the read-only
jadx analysis surface; Smali mode = the editable rebuild surface
(smali*/res/AndroidManifest.xml). Clicking the other chip is now a mode
switch that ALSO jumps to and selects the sibling (smaliSibling, both
directions); clicking a tree file keeps the matching mode; the
auto-select default is picked from the current view's roots; agent
citation clicks (requestFile) still resolve against the FULL tree then
switch the view to match the resolved file's side so it's never
invisible. Side effect: the jadx `resources` root now maps to the Java
view (was Smali): read-only, consistent with the split; the editable
apktool `res` root stays in Smali mode. Notes: findings dots/annotations
are jadx-path-based so Smali mode shows few dots (smali is the edit
surface: accepted). JSDoc gotcha caught by tsc: a block comment
containing `smali*/res` terminated the comment early (`*/` inside):
reworded to backticked names. Gates: tsc + vite build green; app image
rebuilt + container recreated (serves `index-Bl5b-HJG.js`); **live-verified
on :8000 via headless Chrome (scan 20, decode ready)**: Java mode roots
`[sources, resources]` vs API's full `[sources, resources, smali, res,
AndroidManifest.xml]`; Smali chip click → roots `[smali, res,
AndroidManifest.xml]` + open file jumped `CryptoClass.java →
CryptoClass.smali`; tree click stays in smali mode; Java chip back →
`AnimatorRes.smali → AnimatorRes.java` + roots `[sources, resources]`;
iOS roots stay `[analysis, vulnios_prod.app]`; zero console errors.

**Follow-up (Aug 10: smali-mode findings dots + rail):** the M8 note above
said "Smali mode shows few dots: accepted"; the owner then asked to map
semgrep/androguard findings onto their smali siblings so Smali mode shows
the analysis too. New endpoint `GET /scans/{id}/smali-mapping`
(`SmaliMappingResponse`): distinct finding file_paths → only `.java`/`.kt`
→ rebuild the `sources/` tree-path prefix → `smali_map.java_to_smali` →
`{mapping: {"sources/...": "smali/..."}, total}` (multidex first-found;
manifest/res findings never map; empty when undecoded; 409 iOS / not
analyzed; 404 unknown). **Contract gotcha caught against LIVE data**: finding
file_paths are ROOT-RELATIVE (`com/.../CryptoClass.java`), NOT
`sources/`-prefixed: the first route version filtered `startswith("sources/")`
and would have returned 0 mappings in production; fixed + tests assert the
real shape. Frontend `DecompilerPanel`: `smaliMap` state fetched when
`decodeReady && files?.platform === 'android'` (reset per scan,
best-effort {} on failure); `smaliAlias` memo strips the root prefixes to
root-relative pairs (declared ABOVE the auto-select effect: a TDZ error
caught by tsc); `findingsByFile`/`findingFiles` alias each jadx finding
onto its smali sibling (**line_number → null on the copies**: smali rail
notes carry no line anchor, only the file; severity dots copy the worst
rank); auto-select prefers dot-bearing smali files in smali mode. Gates:
592 backend tests green (+9 mapping tests) + ruff clean; tsc + vite build
green (`index-Bx3oqpvT.js`); app image rebuilt + recreated; API live-verified
(scan 20 → 237 mappings; iOS 409); **headless-Chrome live check on :8000**:
Java roots `[sources, resources]` → Smali chip → roots `[smali, res,
AndroidManifest.xml]`, active file jumped `CryptoClass.java →
CryptoClass.smali`, rail `Annotations (10)` with severity-only tags (no
`· line`), `CryptoClass.smali` row carries `fdot high`, click → 10 aliased
notes, back in Java mode the line anchors return (`High · line 26` …);
zero console errors. Harness notes: Node's global WebSocket (no `ws` dep);
poll for tree roots before clicking the chip (it's disabled until the
platform loads).

**Follow-up (same session: mapping extended beyond .java/.kt):** the
smali-mapping endpoint now also carries **identity entries** so res/
manifest findings dot in Smali mode too: `res/...` → ITSELF (the apktool
`res` root serves the same relative path as the jadx resources tree:
frontend strips the root prefix to `values/...` for the res-root node
paths) and `AndroidManifest.xml` → `AndroidManifest.xml/AndroidManifest.xml`
(the synthetic root's single file). Route now early-returns empty when
`apktool.is_ready` is false: the identity entries must not leak before
the decode exists (previously the empty came implicitly from
java_to_smali). Live scan 20: total 237 → 238 (1 manifest; zero res
findings on InsecureBankv2). Frontend `smaliAlias` gained an **identity
guard** (`javaRel === smaliRel` → skip): the manifest finding's file_path
`AndroidManifest.xml` ALREADY matches the manifest tree node path (dot +
rail worked without any alias), so aliasing would have doubled the 15
manifest findings to 30: live-verified `Annotations (15)`. No Java-mode
double-dot for res findings either: the jadx resources root serves
`res/...`-prefixed node paths (verified live: 808 nodes), so the aliased
`values/strings.xml` key matches no Java-mode node. Line numbers stay
dropped on res aliases (jadx vs apktool AXML decode could differ:
conservative). Gates: 592 backend tests green + ruff clean; tsc + vite
build green (`index-j7REreZI.js`); app image rebuilt + recreated;
headless-Chrome live check: Smali roots `[smali, res, AndroidManifest.xml]`,
manifest row `fdot high`, rail `Annotations (15)` (not 30), CryptoClass.smali
dot regression intact, zero console errors.

**Follow-up (same session: per-scan mapping CACHE):** repeated Decompiler
opens re-walked the filesystem per finding path (237 is_file() stats +
findings query every time); the mapping is immutable per scan (findings
immutable per scan id: re-runs create new scans; suppression never changes
finding paths; the decoded tree never mutates: edits are DB diffs), so it
is cached once per scan mirroring the graph explorer.json pattern. Moved the
compute out of the route into `smali_map.py`: `compute_mapping(scan, paths)`
(unchanged semantics: java/kt via java_to_smali, res→itself,
manifest→`editable.tree_path_from_edit_path`) + `cached_mapping`/
`store_mapping`. Module cache keyed by the absolute cache path
(`work/<scan>/smali_mapping.json`) holding `(tree_mtime, mapping)`, bounded
32 (evict oldest-inserted, same rule as `_EXPLORER_CACHE`); the persistent
file carries `{version, tree_mtime, mapping}` (shape-versioned + the decoded
manifest's mtime as the tree identity) written atomically (tmp+rename),
best-effort: any failure degrades to a recompute, never a wrong answer.
Route: `is_ready` gate → `cached_mapping` hit returns immediately (SKIPS the
findings DB query + filesystem walk) → else compute + store. Tests (+3 → 27
in the file): second-call served from cache (monkeypatched compute_mapping
counter stays 1), stale-tree-mtime file rebuilds + rewrites, torn-JSON file
rebuilds after clearing the module cache (fresh-process path), valid disk
file served without recompute (fresh-process hit), undecoded writes no file.
One reviewer-driven note: identity entries don't touch the filesystem, so
their validity assumes the tree exists (route gates is_ready first):
documented in compute_mapping. Gates: **595 backend tests green + ruff
clean**; app image rebuilt + recreated; live: first call computes (total
238) + `smali_mapping.json` written (28 KB, version 1 / 238 entries) inside
the container at `/data/work/20/`, second call cache-served, and the cache
file SURVIVES container recreation (volume) with the fresh process serving
it: the cross-restart win proven.

**Containerized e2e re-run (Aug 10, 2026: cache regression check, scan 23,
contract-style):** the full M8 flow on a FRESH scan with the mapping cache
live: no disturbance. Upload InsecureBankv2.apk → analyzed done in ~45s;
`POST /smali` → 202 → decode ready in ~50s (real apktool in the image);
smali-mapping 238 on both the compute + cached calls with
`/data/work/23/smali_mapping.json` (version 1 / 238 entries) written; **manual
manifest edit** (toggled `android:debuggable="true"` → `"false"`, `POST
/edits` 201, edit 11 applied); **agent edit flow** (app restarted with
`MOBARK_FAKE_MODEL=1` for the demo: fake backend seeded + enabled;
`POST /chat/stream` "remove the debuggable flag (Target editable file:
AndroidManifest.xml)" → 149 token frames + live `read_editable_file` →
`propose_smali_edit` steps + answer citing "edit #13 … nothing was applied
automatically" with the diff; proposals 12/13 both `proposed`, rejected via
the human API); **rebuild** (build 3: queued → applying → rebuilding → done
~10s, `edit_ids [11]`: exactly the APPLIED edit, rejected proposals
excluded, artifact `InsecureBankv2-resigned-test-3.apk`, sha256 present;
download 200 + `X-Resigned-Test-Build: true` + labeled Content-Disposition);
**artifact gates in-container**: `apksigner verify` → CN=MobARK Test Signer,
`zipalign -c 4` OK, cert SHA-256 `24d14ee1…` differs from the original's
`8092db81…` (identical values to the Phase E e2e: same test keystore);
**iOS regression**: scan 22 smali-mapping/edits/rebuild all 409 Android-only;
scan 20 mapping still cache-served (238). `MOBARK_FAKE_MODEL` restored to 0
(as-found) + health ok. Cache-safety notes: the cache file is a SIBLING of
`work/<scan>/apktool` so the rebuild's pristine-tree copy never includes it,
and the mapping endpoint is never on the edit/rebuild/chat path: the e2e
confirms the whole chain end-to-end.

**Follow-up (Aug 10: tree node cap removed + server cache):** owner
questioned why the decompiler says "truncated" and whether it's too heavy to
not truncate. Measured: scan 23's full tree is 11,510 nodes / ~1.7 MB
payload (smali 6,729, sources 3,192, resources 808, res 781, manifest 1):
fine for a local-first web app. Other decompiler tools (jadx-gui, Android
Studio APK Analyzer) show the full tree. Owner chose **remove truncation
entirely**. Changes in `backend/app/analysis/tree.py`:
`MAX_NODES_PER_ROOT = 1500` deleted; `list_tree` defaults to unbounded
(`max_nodes: int | None = None`); `MAX_DEPTH` raised 8→16 as symlink-cycle
guard only; module docstring updated. A new per-scan **server-side tree
cache** was added mirroring the smali-mapping cache pattern: identity =
root-name set + decoded manifest mtime; disk file at `work/<scan>/tree_cache.json`;
in-memory `_TREE_CACHE` bounded to 8 entries; atomic tmp+rename write;
`cached_list_tree` validates version+identity; any failure degrades to
recompute. `GET /scans/{id}/files` now calls `tree.cached_list_tree(scan)`.
Live-verified on scan 23: all roots `truncated: False`, payload 1.7 MB,
cache file written (1.7 MB), second call mtime unchanged (cache hit), iOS
unchanged. Tests: 47 scan + 67 edits/smali + 598 full suite green; ruff
clean. Deployed as `mobark-app` + `mobark-worker` rebuilds.

**Follow-up (same session: Java/Smali toggle dead-click fix, owner report):**
clicking **Java** on a smali file with no jadx counterpart did NOTHING:
`jumpToSibling` had `if (!sibling) return`, and the sibling API returns null
for res/manifest files and classes jadx didn't decompile (confirmed at code +
API level: `MyDBHandler.smali`, `AndroidManifest.xml`, `res/values/strings.xml`
→ null; the smali tree on scan 23 is truncated at 1505 nodes, so no-sibling
files like MyDBHandler aren't even in the tree payload). Fix in
`DecompilerPanel.tsx` (frontend only): on null sibling OR a transient lookup
error, `jumpToSibling` now STILL switches the view, restoring the target
side's **last-open file** (new `lastSideFile` useRef, recorded in `openFile`,
sibling jumps, and the citation resolver) or that side's default app-code
file when never opened (shared `findingPaths` useMemo: the same
app-code-with-findings logic the auto-open effect uses, extracted so the two
can't drift; selection cleared when the side is empty). Live-verified in
compose on scan 23 (12/12 checks): manifest (no sibling) → Java click moves
view, restores last java file `CryptoClass.java`, tree java-only; reverse
`resources/res/anim/abc_fade_in.xml` (no smali sibling) → Smali click moves
view, restores `CryptoClass.smali`; sibling jumps unchanged; zero console
errors. Deployed as `index-Cm89lR16.js`. Reviewer catches fixed: `findingPaths`
extraction, citation-resolver side recording, empty-side selection clear.

**Follow-up (Aug 11, 2026: dock chat is THE agent edit surface; the
Decompiler's ✨ Ask agent textfield removed, owner):** (1) **The inline
"Ask agent to edit" bar is GONE**: `DecompilerPanel` no longer renders the
`.agent-edit-bar` (tag + input + Apply) or its inline reply (`.aeb-reply`,
`EditStepList`); `editChat`/`editDraft`/`submitEditAsk` deleted; the `.aeb-*`
CSS removed. The edit conversation lives ENTIRELY in the Agent dock now:
the owner's flow: chat "disable password validation in authentication" →
the agent searches the code and proposes an edit. (2) **`find_smali_sibling`
agent tool added** (`agent/tools.py`, in `_M8_EDIT_TOOLS` so it's gated on
Android + decode-ready like the other edit tools): maps a jadx
`sources/.../*.java` path (what `search_code` returns) to its editable
apktool `smali*/...` sibling (multidex first-found via
`smali_map.java_to_smali`): the bridge between the Layer 2 search surface
and the M8 edit surface; clean errors for non-`sources/` paths and classes
apktool didn't decode. `_M8_EDIT_PROMPT` now walks the model through
search_code → find_smali_sibling → read_editable_file → propose_smali_edit.
(3) **Fake-model edit demo now SEARCHES FIRST** (`model/fake.py`): round 1
issues `search_code` (a content keyword from the USER'S OWN question:
"disable password validation in authentication" → `password`: the M7
user-query precedent) + `read_editable_file` together (the loop executes
all tool calls in a message; distinct stream indexes: the round-1 two-call
shape previously merged into one because both chunks carried `index: 0`),
round 2 `propose_smali_edit`, round 3 a cited answer naming the top search
hit (`file:line` → clickable chip) + the stored proposal. (4) **Proposals
review lifted to DashboardView**: one shared surface for the dock and the
Decompiler toolbar badge: `DashboardView` owns the per-scan `edits` list
(cleared + refetched on scan switch so the pill/badge never show the OLD
scan's count, and the review modal closes on switch: review catch),
`editVersion` (bumped on Apply/Reject → remounts an open CodeEditor),
`proposalsOpen` + the single `<ProposalsModal>` instance.
`DecompilerPanel` receives `proposedCount`/`editVersion`/`onOpenProposals`
props (toolbar Review edits (n) badge → shared modal). (5) **Agent dock**
gains a **Review edits (n) pill** (persistent, under the header) + **auto-
opens the shared review modal the moment a turn lands a successful
`propose_smali_edit`** (message-id guard, mirroring the old bar's
auto-open), an amber **✏️ edit hint** on Android scans where the smali
decode isn't ready yet ("open Decompiler → Smali to trigger it") so the
headline flow is discoverable, and a dock placeholder/welcome advertising
edit proposals. Gates: **603 backend tests green (30 in test_edit_tools:
5 new find_smali_sibling tests + updated fake-demo shapes) + ruff clean;
tsc + vite build green** (served `index-CDrS8u-v.js`). Reviewer catches
fixed: TDZ (refreshEdits referenced `current` before declaration: proposals
block moved after `const current`), stale pill count on scan switch,
modal persisting across scan switch, misleading welcome copy, and the
stream-index merge.

**Follow-up (Aug 11: @-mention files in the dock chat):** the dock now lets
the user **mention a file** (`@sources/com/foo/AuthManager.java`) so the
agent works on it directly. Frontend: typing `@` opens a **mention picker**
over the scan's decompiler tree (flattened lazily on the first `@`: the
full multi-MB tree is never fetched at mount; files only, iOS binaries
excluded), with Arrow/Enter/Tab/Escape keyboard nav; selecting inserts a
`@path` token at the caret. The draft's mentions render as a **removable
chip row** above the input (× strips the token; chip click opens the file in
the Decompiler), and sent user bubbles render mentions as **clickable
chips** (same `src-chip`, `UserBubble` splits the text around each token).
`useChat.send(question, mentionedFiles?)` stores them on the message (a
Retry re-sends them) and passes `mentioned_files` on the stream request.
Backend: `ChatRequest.mentioned_files` (validator trims blanks, caps 10,
512-char paths; Field max_length=50 is a transport bound only);
`chat.py::_load_mentioned_files` reads each path via the SAME guarded
`tree.read_tree_file` the viewer uses (traversal-guarded, binary refused,
plists decoded, **editable files carry the applied-edit overlay**: what a
rebuild would compile), capped 20k/file + 60k total, and renders a
**USER-MENTIONED FILES** system-prompt section so the model answers /
proposes edits about them with no search round; missing/unreadable paths
degrade to an inline `[could not load - …]` note, never a crash; deduped.
Both chat endpoints forward `mentioned_files`. **Fake-model demo is
mention-aware**: an editable mention (`@smali/…`, `@res/…`,
`@AndroidManifest.xml/AndroidManifest.xml`) becomes the edit target
(`_mention_to_edit_path` converts the tree path); a jadx `@sources/…`
mention drives the **search → find_smali_sibling → read sibling → propose
sibling** flow (the proposal targets the SIBLING, not the manifest
fallback: review catch); mention alone without edit keywords on a jadx
source is a question, not an edit. `_edit_instruction`/`_edit_search_pattern`
strip mentions so the proposal text + search keyword stay clean. CSS:
`.mention-pop/.mention-opt` (absolutely positioned above the input:
`.agent-input` gained `position: relative`), `.mention-chips/.mention-chip`
(removable), `.mention-chip-inline` (in-bubble). Review catches fixed: the
frontend mention regex now **requires a `/`** (every tree path is
`<root>/<rel>`: `@gmail.com` can no longer become a bogus chip) and
`_load_mentioned_files` dedups paths. Gates: **613 backend tests green +
ruff clean; tsc + vite build green** (`index-CTQnGGB5.js`).

**Follow-up (Aug 11: Dependencies tab IMPLEMENTED; it was a placeholder):**
the tab's placeholder copy said "Dependency CVE research ships in M7", but
M7's owner reframe made that research an agent web-search use case: the tab
itself was never built. Now it is a **local-first dependency inventory**
(nothing leaves the machine; no new persistence: everything derives on
demand from scan output). Backend: `analysis/dependencies.py` +
`GET /scans/{id}/dependencies`. **Android**: third-party Java/Kotlin package
groups from the jadx `sources` tree (`_group_key`: longest known-library
ancestor wins: `com.google.android.gms` groups separately from the generic
`com.google` bucket; `okhttp3`/`retrofit2` are their own groups; JDK
namespaces `java/javax/sun` are noise; the app's own package is excluded via
the manifest `package` attr), per-group non-suppressed semgrep finding
tallies (a finding-bearing group is listed even when the capped walk missed
its files), native `lib/<abi>/*.so` from the APK zip (grouped by name with
ABIs), runtime engine markers (Flutter/React Native/Unity/Cordova/Xamarin/
Capacitor via substring match on zip entries), app metadata (package +
min/target SDK from the jadx-decoded `AndroidManifest.xml`). **iOS**: linked
dylibs from the persisted LIEF "Linked dylibs (N)" info finding (system vs
third-party: `/usr/`, `/System/`, `/Library/`, `libswift` = system),
embedded `Frameworks/*.framework` + `.dylib`s, bundle id/version from
Info.plist. Known-library labels (`_KNOWN_ANDROID_LIBS`: AndroidX, GMS,
Firebase, Gson, OkHttp, Retrofit, RxJava, Glide, Jackson, …). Frontend:
`DependenciesPanel.tsx` (app-identity + runtime chips, per-kind sections,
sev-tag finding counts, "Check known CVEs" per dependency) wired into
DashboardView replacing the placeholder; the CVE button **pre-fills the
Agent dock draft** (new `presetDraft` prop, nonce-guarded, expands a
collapsed dock): the M7 web-research surface is the CVE lookup, per the
owner reframe; the panel explains the 🌐-toggle + Active-engine requirement.
Review catches fixed: dock preset reset on scan switch (AgentDock is keyed
per scan: a stale preset would pre-fill the next scan), CVE click expands a
collapsed dock. Live-verified in compose on scan 23 (InsecureBankv2):
Google Play services 2437 files/171 findings (3 high) · Android Support
Library 519/306 · com.google 22/8, app com.android.insecurebankv2
minSdk 15 targetSdk 22; iOS scan 22: 35 system dylibs + bundle
com.payatu.BugBazar v1.1; headless-Chrome click-through of the tab green,
zero console errors. Gates: **629 backend tests green (+16 new) + ruff
clean; tsc + vite build green**. mobark-tasks.md M5 placeholder line updated.

**Follow-up (same session: inventory CACHE):** repeated tab opens no longer
re-walk the sources tree + APK zip: `dependencies.py` gained a per-scan
cache (module, bounded 32, + a validated `dependencies_cache.json` beside
the scan's trees: the tree_cache.json / smali_mapping.json pattern:
versioned, atomic tmp+rename, best-effort). Identity = platform + sources/bundle
dir mtime + APK stat + a **findings fingerprint** (sha over the passed
non-suppressed `id:tool:severity` rows): so suppression toggles flip the
identity and recompute on the NEXT GET (lazy), and re-runs (new ids) too.
A vanished tree is a cache MISS, never stale-serving (the smali_map
`_tree_mtime` precedent: review catch). Live-verified in compose:
first GET writes the file, **app restart serves from disk with mtime
unchanged**, suppress→GET rewrites (mtime changes), restore→GET rewrites
back; unit tests cover hit/eviction-path, suppression invalidation, torn +
stale-identity files, fresh-process disk serve. Gates: **635 backend tests
green (+6 cache tests) + ruff clean; frontend untouched.**

**Follow-up (same session: suppression-fingerprint scope DECISION, no code):**
considered extending the findings-fingerprint pattern to the Code maps
`explorer.json` and the findings list endpoint. Verified both are
findings-independent: the explorer is pure graph data (node rows/links/degree,
zero findings references in graphify.explorer_data or CodeMapsPanel.tsx) with
its own disk+module+mtime-validated cache already; the findings endpoint is a
plain indexed SELECT with no cache and no computation to save (a fingerprint
cache there would be circular: the fingerprint IS the result set). Adding a
fingerprint to the explorer would force a needless 64 MB re-compaction on
every suppress toggle. **Owner decision (Aug 11): skip both: keep as-is.**
Suppression correctness is already handled across the board: risk recomputed,
`scans.ai_summary` invalidated, frontend refetches; `dependencies_cache.json`
remains the only findings-fingerprint cache.

**Verification (same session, live in compose on scan 23):** full
suppress→restore lifecycle re-checked end-to-end. Baseline risk 89/security 11,
523 findings (11 high). Suppressed finding 8317 (a `com.google.android.gms`
high): risk → 88/12 ✓, default findings 523→522 with 8317 hidden ✓,
`include_suppressed` shows it with `suppressed_at` stamped ✓, an injected
`ai_summary` value cleared to NULL ✓ (the stale-cache invalidation path
proven live), and the dependencies inventory recomputed on the next GET
(gms 171→170 findings, high 3→2) with the cache file rewritten ✓. Restored:
risk back to 89 ✓, findings back to 523 ✓, gms back to 171/3 ✓, cache
rewritten again ✓, `ai_summary` stays NULL (never stale) ✓, final state 0
suppressed (as-found, clean). Note: the deps-cache recompute is lazy (next
GET): a stat taken before the GET correctly shows an unchanged mtime; the
payload change is the definitive proof.

**Verification (same session, live in compose on scan 22: iOS):** the same
lifecycle against the dylib inventory. Baseline risk 57/security 43, 9
findings (3 medium; the dylib inventory's source is the info finding
`Linked dylibs (35)`: deliberately NOT suppressed). Suppressed finding 7881
(`CC_MD5`, medium): risk → 56 ✓ (band-symmetric 3→2 mediums, security 44),
default findings 9→8 with 7881 hidden ✓, `include_suppressed` shows it with
`suppressed_at` stamped ✓, injected `ai_summary` cleared to NULL ✓, deps
cache recomputed on the next GET (mtime changed, fingerprint flipped) while
the dylib inventory stayed **intact: 35 system / 0 third-party** ✓ (its
source finding untouched). Restored: risk back to 57/security 43 ✓, findings
back to 9 with 7881 visible ✓, `suppressed_at` cleared ✓, cache recomputed
back (mtime changed) ✓, `ai_summary` stays NULL ✓, final state **0
suppressed** (as-found, clean).

**Follow-up (Aug 11: dead search engines can't be activated; dock 🌐 needs a
LIVE engine, owner):** "if searxng is not live make it disable in setting;
agent dock web toggle also disable and unable to be clicked unless a search
provider is active." (1) **Backend** `GET /search/backends` now lightweight-
probes SearXNG-style engines (bundled + custom, `query_style == "searxng"`)
**even when INACTIVE**: the cheap base-URL HTTP check, so the Settings radio
can gate on reachability; keyed engines (brave/serper/mojeek) keep the
enabled-only rule (their honest check IS a real query that validates the key,
so they are never probed on the list route; cost note: a list blocks ≤3s per
dead searxng-style backend: fine at this scale, the UI poll is 4s).
(2) **Settings Active radio disabled** (`radioDisabled = !enabled &&
!engineLive`; engineLive = `health.reachable` for searxng-style,
`has_api_key` for keyed): dimmed `.switch.disabled` + click-inert +
tooltip ("Engine unreachable: start it (▶ Start engine), then activate" /
"No API key set: add a key to use this engine"). An ACTIVE engine stays
toggleable so it can be turned OFF even after going unreachable. Side
benefit: the ▶ Start engine button now also appears on an INACTIVE bundled
engine (its health is populated): start, then activate. (3) **Agent dock 🌐
toggle now needs a LIVE Active engine**: `liveEngine = some(enabled &&
health?.reachable)`, `webLocked = !modelConnected || (!liveEngine &&
!webResearch)`: a dead engine can't ENABLE web research, but an opt-in that
was already ON stays toggleable so the user can turn it OFF (review catch:
the fully-inert lock would have stranded the opt-in on while server-side
`web_tools_allowed`: enabled-only, still offered the tools); tooltip + input
hint explain ("⏎ to send · 🌐 off: no live search engine (Settings → Search
& research)"). Gates: **636 backend tests green + ruff clean; tsc + vite build
green.** Live-verified: disabled searxng still reports `health:
reachable=True status=ok` on the list (the radio gate's data), re-enabled
as-found; served bundle carries the new strings/CSS; headless-DOM shows the
dock toggle with the disabled class in the no-model state. No server-side
upsert enforcement (deliberate: the gate is the UI affordance; the store
stays offline and raw-API activations are out of scope).

**Follow-up (Aug 12, 2026: dead bundled engine reads Inactive + friendly
probe errors, owner report: "bundled searxng should be inactive and cannot
be switched when searxng is unreachable... enhance error message"):**
(1) **Frontend** `SearchTab.tsx` now derives `effectiveEnabled`: a
SearXNG-style engine (bundled/custom) reads as **Active ONLY while it
actually answers** (`backend.enabled && health.reachable`); an
enabled-but-dead engine now renders as **Inactive with a fully disabled
switch** (both ON and OFF directions: `radioDisabled = !engineLive`) so it
can't be switched at all until it comes up; the recovery path is ▶ Start
engine / Test, and the Inactive hint gains an "unreachable right now" note
when the stored flag was on. (2) **Backend** `client.py`: new
`_friendly_reason(exc)` translates raw transport exceptions into human
clauses (DNS "host name couldn't be resolved", refused, timeout, network
unreachable; unknown → truncated generic); `compose_hint(backend, exc=None)`
and the health-error call sites no longer append the raw `([Errno -2] Name
or service not known)` suffix: the Settings card shows the actionable hint
+ friendly reason. Start-endpoint failure messages unchanged (the
`extractStartCommand` parser's backticked-command contract is untouched).
Gates: **698 backend tests green (+2: DNS-friendly + health-friendly) +
ruff clean; tsc + vite build green**; live-verified with the bundled engine
stored-enabled but unreachable: card shows Inactive, switch disabled,
friendly error, ▶ Start engine present.

**Follow-up (Aug 11, 2026: Decompiler ONE-SCROLL annotation rail, owner
request: "make the codeview and the annotation one scroll not separate
scroll"):** the rail no longer has its own scrollbar: the code pane is
the single scroll SOURCE and the rail's notes are pinned to it. The grid,
splitters, rail-minimize, and responsive rules are untouched. Mechanics:
`AnnotationRail.tsx` positions every note ABSOLUTELY at its finding's line
offset (`(line-1)*lineHeight + compensation`; compensation = code-title
height − rail-head height, measured once the async content renders via a
rAF-retrying effect; lineHeight 0 on the smali editor path where notes have
no line anchors → stack-from-top), clusters overlapping cards below each
other (ResizeObserver re-clusters when an AI explanation expands a card,
`NOTE_GAP 10`), and the whole `.annot-rail-notes` column translates by the
code's scrollTop via a **`--rail-scroll` CSS var set DIRECTLY on the DOM**
(scrolling never re-renders the panel: the tree is huge). `DecompilerPanel`
owns the mirror: the scroller is the viewer's `.code-pane` or the smali
editor's `.editor-textarea`; native non-passive wheel forwarding (React's
onWheel is passive and can't preventDefault; deltaMode 1 → ×16, review
catch) so wheeling over the rail scrolls the code; the var write is skipped
while the rail is minimized; a flagged-line click scrolls the code so the
line-aligned note comes into view (de-keyed from the findings-array identity
via a ref: review catch). Review guards: the LAST clustered note is clamped
inside the code's reachable scroll range (a dense stack can't push a note
past the pane's bottom, unreachable), and the compensation math was
derivation-verified (note viewport y = headH + T_N − S; line viewport y =
titleH + (L−1)·LINE_H − S → T_N = (L−1)·LINE_H + (titleH − headH)).
Gates: tsc + vite build green; code review clean (4 fixes applied:
last-note clamp, deltaMode, rail-min skip, effect de-keying); app image
rebuilt + recreated (serves `index-DO9-1GYI.js`, matches local dist,
`rail-scroll` present in the bundle). **Live-verified in headless Chrome via
CDP at a DESKTOP viewport (1440×900)**: harness note: the default 800×600
headless viewport hits the documented ≤900px responsive rule that hides the
rail by design, so `display:none` made the first diagnostic read
`transform: none` (a hidden element has no box: a harness artifact, not a
bug). At 1440×900: rail `display:flex` + `overflow:hidden` (no own
scrollbar), notes `position:absolute` + transform rule applied
(`matrix(1,0,0,1,0,0)` at rest), scrolling the pane to 300 →
`--rail-scroll: -300px` and the note's viewport top moved **390 → 90
exactly −300px in lockstep with the code line** (one-scroll proven), zero
console errors.

**Follow-up (Aug 11: smali editor one-scroll alignment):** the smali
CodeEditor path previously fell back to stacked notes (aliases dropped
line anchors: jadx renumbers source lines, so statement-level mapping to
smali is impossible). Now the smali notes pin at **method granularity**: the
smali-mapping endpoint also returns **line anchors**: each finding's jadx
line maps to its containing method's `.method` line in the apktool smali
sibling (by name; constructors map to `<init>` via the jadx class simple
name; `static`/instance-initializer blocks never anchor: no method name).
Backend: `smali_map.py` `_jadx_methods` (brace-counted at CLASS-BODY depth,
multi-line throws handled, `new`-anonymous-class field inits + `;`-abstract
methods excluded, **single-line bodies `{ return x; }` captured**: review
catch, jadx emits compact one-line accessors) + `_smali_method_lines`
(`.method` name → line, first-found, `<init>`/`<clinit>` included);
`compute_anchors(scan, mapping, finding_lines)` groups by file (one read
per jadx/smali pair), never raises, unresolved lines get NO anchor (the
note stacks: pre-follow-up behaviour). Cache version bumped to **2**
(`smali_mapping.json` now stores `mapping` + `anchors`; stale v1 files
rebuild). Route queries distinct `(file_path, line_number)` and returns
`anchors` in `SmaliMappingResponse` on both cache-hit and compute paths.
Frontend: `DecompilerPanel` fetches anchors with the mapping, aliases each
smali finding's `line_number` to its anchor (`byLine[String(line)] ?? null`
: string keys on the wire, review catch) so notes pin at the editor's own
line numbers, and the measure effect now handles the EDITOR path: the
textarea's computed line-height (12.5px/1.9 → 23.75px) + `scrollHeight`
(the clamp bound), both re-measured per file. Gates: **640 backend tests
green (+1 regression) + ruff clean; tsc + vite build green** (`index-C-MKOpWW.js`),
app image rebuilt + recreated, health ok. **Live-verified in compose (scan
23, CryptoClass.smali, CDP at 1440×900)**: API: 238 mappings / **172
files with anchors**, 31/31 sampled anchors land EXACTLY on `.method`
lines in real apktool output (jadx 26-29 → smali#67 `.method public static
aes256decrypt`, jadx 34-37 → smali#120 `aes256encrypt`: the hardcoded-key
findings); browser: 10 notes with smali line tags (`High · line 67` …),
rail `overflow:hidden`, editor scroll 300 → `--rail-scroll: -300px` with
the note moving **exactly −300px in lockstep** (1942.39 → 1642.39), wheel
over the rail forwards to the editor (+120 → 420), and the first note's
inline top 1552.39px == `(67−1)×23.75 + (title 33.89 − rail-head 49)`
(1567.5 − 15.11): **pixel-exact, diff 0**. One-scroll now holds in BOTH
the viewer and the smali editor.

**Containerized M8 contract-style e2e RE-RUN (Aug 11, 2026: scan 24,
with the anchors feature live):** full flow on a fresh InsecureBankv2 scan
passed end-to-end: upload → analyzed done ~45s (risk 89) → `POST /smali`
202 → real apktool 3.0.3 decode ready ~45s → smali-mapping **238
mappings / 172 anchor files** (cache written at `/data/work/24/smali_mapping.json`, 42 KB, version 2 with anchors) → **manual manifest edit**
(`android:debuggable="true"`→`"false"`, edit 15 applied) → app restarted
with `MOBARK_FAKE_MODEL=1` → **agent edit flow** via `chat/stream` (153 token
frames + live `search_code` → `read_editable_file` → `propose_smali_edit`;
proposal stored as edit 16 `proposed`, answer cited "stored as edit #16 …
nothing was applied automatically" with the diff) → **edit 16 rejected via
the human API** (rejected; edit 15 stays applied) → `POST /rebuild` → build
5 **done ~10s** → `InsecureBankv2-resigned-test-5.apk` (sha256
`c8c2afba…`, **`edit_ids: [15]`: exactly the applied edit, rejected
proposal excluded**) → download 200 + `X-Resigned-Test-Build: true` +
`Content-Disposition: attachment; filename="InsecureBankv2-resigned-test-5.apk"`
→ **in-container artifact gates**: `apksigner verify` → **CN=MobARK Test
Signer**, `zipalign -c 4` OK, cert SHA-256 `24d14ee1…` **differs from the
original** `8092db81…` (identical values to the Phase E e2e: same test
keystore) → **iOS regression**: scan 22 iBugBazaar `POST /smali`,
`GET /smali-mapping`, `POST /edits`, `POST /rebuild` all **409 Android-only**
(decision-5 copy) → `MOBARK_FAKE_MODEL` restored to 0 (fake backend
reconciled away; 3 backends as-found), health ok. All M8 contract gates
hold with the anchors feature deployed.

**Follow-up (same session): @-mention feature e2e (API + browser):**
**API (scan 24, fake model):** (1) editable mention
`@smali/.../CryptoClass.smali` + edit question → streamed `search_code` →
`read_editable_file` on the mentioned path → `propose_smali_edit` on THAT
path (edit 17): the mention drives the target; (2) jadx mention
`@sources/.../CryptoClass.java` + edit question → `search_code` →
**`find_smali_sibling`** (maps the mention to
`smali/.../CryptoClass.smali`) → read sibling → **propose on the SIBLING**
(edit 18): the flagship search→map→read→propose flow driven by a mention;
(3) missing/duplicate mention (`DoesNotExist.java` x2) → clean stream,
never a crash (dedup + inline `[could not load]` degrade). **Browser (CDP,
1440×900):** typing `@` opens the `.mention-pop` picker (40 options, lazy
flatten), `@CryptoClass` filters to the java + smali pair, selection inserts
the `@path` token + removable `.mention-chip` row, send → the user bubble
renders the mention as a clickable `.mention-chip-inline`, and the agent
replies mention-aware (no search: the mentioned file content was attached;
"…I proposed an edit to `smali/.../CryptoClass…`"). **BUG FOUND + FIXED
(live-verified):** the mention chip's click called `onOpenFile` with the
FULL tree path (`smali/com/.../CryptoClass.smali`) but
`DecompilerPanel.resolveTreePath` only handled root-relative paths
(`com/...`: agent citations + graph nodes), the click silently fell back
to the auto-open default (`CryptoClass.java` in Java view) instead of
opening the mentioned smali. Fixed: the resolver now also splits off a
leading `<root>/` and matches that root's node directly (mention picker
paths), keeping the existing exact/`<root>/<file>`/suffix fallbacks for
citations: a smali mention now opens the smali file in Smali view
(live-verified: `openPath = smali/com/android/insecurebankv2/CryptoClass.smalieditable`).
Gates: **640 backend tests + ruff clean; tsc + vite build green
(`index-DcI4zIAg.js`)**, app image rebuilt/recreated; test proposals
rejected (review queue clean: only edit 15 applied as built);
`MOBARK_FAKE_MODEL` restored to 0, health ok.

**Follow-up (Aug 11, 2026: multi-mention verification, scan 24):** the
@-mention chip was re-tested with TWO files in ONE message (the single-
mention test above only covered one). Browser CDP, 13/13 checks green:
typing `@CryptoClass.smali` then `@LoginActivity.smali` → **both draft
chips in the row**; typing the SAME path a third time → **dedup holds**
(row stays at 2: `mentionedFrom` collapses); the × on the dup strips one
token while both distinct files remain; send → the **sent user bubble
renders BOTH inline mention chips**; clicking chip 0 opens
`LoginActivity.smali` and chip 1 opens `CryptoClass.smali` (data-driven
assertion: each chip opens ITS OWN file in the Smali editor, editable
badge attached): the Aug 11 `resolveTreePath` full-tree-path fix covers
multi-mention with no further code change; zero console errors. Backend
leg: `POST /chat/stream` with `mentioned_files` = the two smali paths
deduplicates (a duplicated path in the payload collapses:
`_load_mentioned_files` dict.fromkeys) and both files stream cleanly; the
browser run's fake-demo proposals landed on the **mentioned files**
(edit 24 CryptoClass.smali, 25–27 LoginActivity.smali) confirming the
mention-aware targeting end-to-end; all test proposals rejected (review
queue clean, only applied edit 15 remains). One test-harness lesson: the
basher default 30 s timeout kills the Chrome process group mid-run:
background CDP runs need an explicit `timeout_seconds` or file-logged
progress (`/tmp/mention_multi_out.log` pattern). Gates: **640 backend
tests + ruff clean**; app restored `MOBARK_FAKE_MODEL=0`, health 200.

**Follow-up (Aug 11, 2026: agent ends after plan-narration + thinking
clamp, owner report):** the owner tried the agent on a local model
(ollama/lm-studio) and got a turn that ended with pure plan narration
("Let's search for login-related files… Let's read LoginActivity.java…")
: no tool call, no rollup. Root cause in `chat.py`: the loop's
`if not tool_calls: final_text = content; break` accepted ANY content-only
response as the final answer, so a model that narrates intent instead of
emitting a tool call (a known weak-spot of local models) produced a plan
with no search ever running. Fixes: (1) **bounded narration nudge**:
`_NARRATION_INTENT_RE` (intent + action verbs: "let's search", "we need to
inspect", "i'll read", …), `_MAX_NARRATION_NUDGES=2`, `_NARRATION_NUDGE`
user message; when a round returns narration with NO tool call AND no
`file:line` citation (real answers that cite are never re-opened), the
loop records the assistant message, appends the nudge, and CONTINUES so
the model actually runs search_code → read → rolls up a grounded answer.
(2) **SYSTEM_PROMPT rule**: "NEVER describe an action you intend to take
instead of taking it… a plan like \"Let's search for X\" with no tool call
is not an answer." (3) **Stale final_text guard (review catch)**: a round
that emits narration WITH a tool call sets `final_text`; if later rounds
are nudged and the loop then exhausts, the stale narration used to win
(skipping the grounded fallback): the nudge branch now clears
`final_text=""` so exhaustion falls through to the plain-chat fallback.
(4) **Streaming thinking clamp** (owner: "max 4 lines, streamed like the
Freebuff CLI thinking display, not all shown"): `.stream-text` now
`-webkit-line-clamp: 4` + `overflow: hidden`: the live stream preview
stays at 4 lines while tokens keep arriving; the FULL answer still lands
in the finalized message when the turn completes (finalizeMessage uses
Markdown, not `.stream-text`), so nothing is lost. Fake-model demos are
unaffected: their thinking text ("Let me search the decompiled source…")
always ships WITH tool_calls in the same round, so `not tool_calls` never
fires the nudge: verified. Gates: **644 backend tests (+4: nudge-flow,
bounded-after-nudges, regex-wording, stale-final_text regression) + ruff
clean; tsc + vite build green** (`index-C0W6eqB6.js`); live browser check
on :8000: `.stream-text` computed lineClamp=4 + overflow=hidden while a
stream ran, short text unclipped, full 273-char final answer landed;
fake chat sanity (streaming tools + answer) green after the change;
app image rebuilt + recreated, `MOBARK_FAKE_MODEL=0`, health 200.

M9: Report generation; **COMPLETE (Aug 12, 2026), Phases A–E all done,
containerized contract-style e2e PASSED.** See
`docs/progress/M9.md`. Phase A (deterministic assembly):
`analysis/report.py`: `assemble_report(scan, findings, dependencies=…,
web_sources=…)` renders the body from persisted scan data ONLY (no LLM,
no subprocess); sections: header (app/platform/date/security
score + CVSS 4.0 band via `risk.py`), executive summary (cached
`ai_summary`, blank→explicit no-AI note: the body never 400s, decision
10), severity breakdown (risk.py source of truth), findings grouped by
severity with MASTG tags + cached explanations, Android smali-edit note /
iOS binary profile from the LIEF/symbols findings, dependencies payload,
and "External references" (M7 web sources). Aug 14: no "Resigned test
builds" section and no `builds` parameter: see item 10. Phase B: `POST /scans/{id}/report/regenerate`, re-runs
`insights.summarize_scan(regenerate=True)` (persisted to `ai_summary`) +
fills ONLY missing explanations (`explanations=true` default, cached ones
never re-spent), single all-or-nothing commit, M5 error contract. Phase C
(export): `GET /scans/{id}/report` (cached body) + `GET
/scans/{id}/report/export?format=md|pdf` (`{stem}-report.md|pdf`
attachments, sanitized stem). PDF = **reportlab platypus** (BSD-3-Clause,
decision 3 CORRECTED Aug 12) + **markdown==3.10.3** (BSD-3-Clause) over
the SAME body: `analysis/report_pdf.py`: md→HTML fragment
(python-markdown) parsed by a stdlib `html.parser` builder into
Paragraphs/ListFlowable/one-cell Tables (severity `[HIGH]`→colored chip
via `<font backColor>`, SecurityGauge palette mirrored server-side; page
numbers + brand footer via a canvas callback: working; DejaVu Sans TTF
`MOBARK_REPORT_FONT` default, Helvetica fallback when missing; `render_pdf`
bounded: fragment size cap + thread timeout, `%PDF`+size gate: silent
empty file is a 500, never a 200). **Why not xhtml2pdf: the Phase C
pip-licenses audit found xhtml2pdf 0.2.17 imports LGPL python-bidi +
LGPLv3 svglib (WeasyPrint's pyphen is LGPL/MPL too): posture violation,
owned decision to rewrite on reportlab; the xhtml2pdf/bidi/svglib/
pyhanko tree was uninstalled.** Body cached per scan (`report_cache.json`,
identity = platform/filename/risk/ai_summary + rich findings fingerprint +
web sources + deps hash): a suppress toggle / regenerate / web capture
recomputes (the `builds` inputs left the identity Aug 14 with the
Resigned test builds section: item 10). Deps: `requirements.txt`
reportlab+markdown pins, `requirements-dev.txt` pypdf (BSD-3-Clause, PDF
heading extraction in tests), Dockerfile `fonts-dejavu-core`. Gates: **681
backend tests green (+12 export tests) + ruff clean** (frontend untouched
this phase).

**Phase D (Report tab + Export button, frontend: done Aug 12):**
`panels/ReportPanel.tsx` renders the assembled markdown (react-markdown,
the dock's precedent) on an on-screen **paper card** (`.report-doc`)
echoing the exported PDF's branding (white paper, ink #14171a headings,
steel accent rule, tinted severity chips): the tab previews the artifact
being downloaded. Toolbar: **Export .md / Export PDF** download anchors
(`api.reportExportUrl`) + loading/error/retry. (The **Regenerate** button
: POST explicit cost opt-in with explanations note · no-model note ·
error+Retry: was REMOVED Aug 14: the report is deterministic and does
not depend on AI, so the AI-only regenerate affordance is gone; see item
10. The backend route stays.) `active` prop re-fetches on later tab activations
(the panel stays mounted once visited, so a suppress/restore on another
tab: which invalidates the server cache identity, must show up without
a scan remount; review catch). TopBar **Export report** is now a dropdown
(Markdown/.md + PDF/.pdf anchors, ModelPicker-style outside-click/Escape
close), disabled until a done scan; `App` passes the currently-visible
scan (progress backdrop's last completed scan, same `scanOverride ??
activeScan` selection DashboardView renders). Gates: **682 backend tests +
`tsc -b`/`vite build` green** (one TS catch: state field `generatedAt`, the
footer read `generated_at`).

**Phase E (hardening + containerized e2e: done Aug 12, PASSED):** open
item 2 IMPLEMENTED: `assemble_report` gained `suppressed_count` (the
route counts suppressed rows; cache identity rides along): a suppressed-
only scan reads as zero counts + the one-line "Suppressed findings: n
excluded (not scored, not listed below)" footnote instead of a clean bill
of health. Edge tests (+4): suppressed-only scan (unit), empty-scan API +
PDF export, suppressed-only API flow with unsuppress flip, iOS parity at
the API layer (body + both exports). `scripts/e2e_report.sh` (committed)
runs the real stack against the real samples: InsecureBankv2 (no-AI
default, MOBARK_FAKE_MODEL=0) → report sections + **no-AI fallback note**
(decision 10 live), md export = same cached body + `{stem}-report.md`
attachment, pdf = `%PDF` + extractable headings + working page numbers,
suppress toggle recomputes the body (decision 7) and flips the footnote;
iBugBazaar iOS parity (binary-profile body + PDF, no Android section
leak); restart with MOBARK_FAKE_MODEL=1 → `POST /report/regenerate` → the
fake summary + explanations land in the body and the fallback note is
gone. Run notes: first run hit two script bugs (bash `$(...)` strips
final newlines so the md-body cmp diverged: now both sides stripped;
post-restart regenerate raced app startup: now health-waited); the
incremental image build exceeded the 600s basher cap but completed (the
image was already tagged). Gates: **686 backend tests green (+4) + ruff
clean; `tsc -b` + `vite build` green; image 3.54 GB content / 759 MB
compressed** (M8: 3.47 / 783: the delta is reportlab + markdown +
fonts-dejavu-core, no new system libs). Remaining owner checkpoint (not a
blocker): the manual review pass: does the AI-drafted report read like
something a human pentester would ship? (M9.md Phase E, task-list item).
**Repo hygiene (same session): docs/ is now GITIGNORED/untracked** (~44MB
binaries: sample APK/IPA/icons/mockups, don't belong in git; the .md
milestone docs moved out of version control too by owner decision). Files
stay on disk; read via explicit paths; search with the `--no-ignore` rg
flag (this knowledge.md carries the note at the top).

**Manual-review follow-ups (Aug 12, 2026: owner review pass DONE):**
walked the REAL reports live (scan 30 Android, scan 31 iOS, scan 24 with
M8 builds, + the 60-page PDF) against the pentester's yardstick: verdict:
structurally ship-ready, but the Android body was drowned in third-party
noise (467 of 522 findings were `android/support`/`com/google/android/gms`
repeats) with no "what to fix first" section, and iOS listed dylibs three
times. Three follow-ups (in `analysis/report.py`, cache bumped to v2):
(1) **vendored-library roll-up**: findings inside bundled third-party
libraries (the Dependencies tab's new public `group_for_finding(finding,
app_package)` classification) collapse into per-library tallies in a
`### Third-party library findings (N)` subsection; app-owned rows stay
listed in full per severity; the severity breakdown still counts
EVERYTHING (it must match the risk score). Live: scan 30 went **237 KB →
19 KB**. **REMOVED Aug 14** (owner: "show every not suppressed finding,
not just medium x count"): every non-suppressed finding is listed
individually again; see item 10. (2) **Recommended priorities**: deterministic (no-LLM, decision
10) top-10 of app-owned findings by severity (info never a priority) with
file:line + MASTG tag + a static-only scope note. (3) **iOS dylib
de-dupe**: dylibs render ONCE: the binary profile is authoritative (cap
raised 20→60 for scan 31's 35 dylibs) and Dependencies points to it.
Review catch applied: unknown severities (e.g. `warning`) land in the
tally's explicit `other` bucket instead of silently vanishing. Gates: **689
backend tests green (+3) + ruff clean**.

**PDF redesign (Aug 12, 2026: second follow-up session):**
`analysis/report_pdf.py` was visually redesigned (fragment + reportlab
unchanged): the **DejaVu family** is now registered (regular/bold/oblique/
mono: the Phase C `_register_font()` only had the regular face, so
`<b>/<i>` were fake-bold); a **cover page** (`_cover_meta` parses the
assembled body's own header + breakdown lines: one body, two media, no
parallel assembly): deep-emerald brand band (MobARK wordmark, app, platform
chip), canvas-drawn **security gauge** (frontend SecurityGauge contract:
180° arc, discrete CVSS 4.0 band color, score/label/CVSS caption in the
bowl), four severity count boxes (the `.sev-tag` tint+foreground
contract), package/bundle + analyzed meta, suppressed-count note when
anything was excluded, static-only scope footnote; body pages get a
running emerald header + page-number footer, h2 emerald left bars, and
**severity-colored h3 headings** (High amber / Medium steel / Low moss /
Info gray / Third-party deep-emerald). Tests +4; live-verified in compose
on scan 30 (7 pages, high-risk crimson gauge, all four severity tints
pixel-probed in the raster). Gates: **693 backend tests green (+4) + ruff
clean**; image rebuilt.

**PDF follow-up 2 (owner direction, same session): real wordmark +
conventional severity palette:** the cover band now draws the ACTUAL MobARK
wordmark asset (`frontend/src/assets/mobark-wordmark.svg`, the same file the
TopBar renders) instead of plain text. `scripts/sync_wordmark.py` vendors
it into `backend/app/analysis/wordmark_data.py` (the M1 MASTG-vendoring
precedent: the app image only ships `backend/` + `frontend/dist`): vector
logo paths (M/L/H/V/Z subset; gradients flattened to midpoints) + the
white "MobARK" raster text cropped to the SVG's pattern-visible region
(computed from the pattern matrix), normalized to white glyphs +
downscaled 4x → 9.6 KB module (vs 460 KB raw). `report_pdf.py`
`_wordmark_path`/`_wordmark_art` (lock-guarded cache)/`_draw_wordmark`
draw the logo as a reportlab Drawing (y-flip, aspect-preserved) and
composite the raster with `mask='auto'`; ANY failure degrades to the text
wordmark (never a crash). Staleness guard: `wordmark_data.SVG_SHA256` is
tested against the live asset. Severity palette switched to conventional
**High red · Medium amber · Low green · Info slate** (`_SEVERITY_STYLES` +
`_SEV_TEXT`: chips, h3 headings, cover boxes), and a follow-up mirrored
it into the frontend overview (`.sev-tag` / `.spine` / `.fdot` now use
`--color-sev-red/amber(->amber var)/green/slate`), so the dashboard and
the export read consistently as a standard pentest deliverable. Tests +3 (vendored data +
staleness fingerprint, Drawing build, fallback) + updated color
assertions; live-verified in compose on scan 30 (vector logo facets +
white MobARK text on the band, red/amber/green/slate severity boxes). Gates:
**696 backend tests green (+3) + ruff clean**; image rebuilt.

**Follow-up (Aug 12, 2026: third session): MASTG v2 currency + smali decode UX + narrow testing.**

1. **MASTG v2 is CURRENT but the report cited deprecated v1 ids.** The
   vendored data is synced from OWASP/owasp-mastg @ `d7fd7d45` (2026-08-03)
  : MASTG v2. The v1-era test ids (MASTG-TEST-0001..0093) are ALL
   deprecated in v2 (superseded by atomic tests in the 0200+ range, e.g.
   MASTG-TEST-0222/-0326, which reference MASWE weakness ids). 92/292 of
   our mapped tests are deprecated (incl. MASTG-TEST-0007 the report cited
   and MASTG-TEST-0073 in the M5 test fixtures). Fix: `mastg.py` gained
   `active_test_ids_for_control` (excludes deprecated + placeholder); the
   backfill (`orchestrator._fill_mastg_test_ids`) only assigns live ids;
   the report's `_mastg_tag` drops deprecated ids from the findings tags
   AND the Recommended-priorities cites (the MASVS v2 control always
   renders) + a **Standards** provenance line in the header. NOTE: the v2
   atomic tests carry no MASVS-control linkage in our mapping yet (they
   reference MASWE; the control↔test edges live in the OWASP MAS
   checklist), so findings now cite the control without a MASTG tag until
   the checklist-linkage sync lands: which is also the prerequisite for
   the DEFERRED **MAS-checklist L1/L2/R assessment** (owner chose
   citations-only; recommended v1.1 work: vendor the checklist's
   MASVS-ID ↔ MASTG-TEST-ID ↔ L1/L2/R/P columns).
2. **Smali "takes forever" = no worker, not slow apktool.** The on-demand
   decode job sat QUEUED forever because the RQ `worker` service wasn't
   running (compose defines it; only `app redis` were up). Decode itself:
   ~4s for the 3.4 MB InsecureBankv2 sample (measured in-container).
   Fixes: **warm pre-decode** at scan completion (`apktool_predecode_enabled`
   default on; enqueue failure rolls back to `not_started`, warning-only)
   and a **stuck-queue guard**: `smali-status` reports `stalled` with a
   "start it with `docker compose up -d worker`" hint after
   `apktool_queue_stall_seconds` (legacy null-clock queued rows count too);
   the frontend chip renders `stalled` like `failed` with ↻ Retry.
   Migration **0010** adds `scans.apktool_queued_at`. OPERATIONAL RULE:
   decode/rebuild need the worker: run `docker compose up -d` (all
   services). Live-verified: stalled message worker-down; worker up → the
   stale queued job decoded → `ready`.
3. **No-AI executive summary (same session, owner: "the PDF report should
   not depend on AI - the user may or may not use a model").** The export
   never required a model (decision 10), but the no-AI summary rendered
   "_No AI summary yet - configure a chat model..._" - a visible AI
   dependency. `report.assemble_report` now falls back to a deterministic
   auto-summary (`_auto_summary`): "This automated static assessment of
   `<file>` (<platform>) found **N findings** (n high, n medium, ...),
   touching **M MASVS controls** (...)": pure persisted data, no model.
   A cached AI narrative still replaces it when present (enhancement, not
   requirement). Live-verified with scan 30's ai_summary nulled (markdown
   + PDF both complete, cover intact), then restored. +1 golden test.
4. **Testing convention (owner direction):** validate changed areas only:
   `pytest <changed test files>` + `ruff` on changed files + `npm run build`
   only when the frontend changed (full-suite runs are the exception).
   Narrow gates for this session: `test_smali_api.py` (+5: stall incl.
   legacy-null, trigger clock, warm pre-decode on/off), `test_mastg.py`
   (+2 active-lookup), `test_report.py` (+1 active-vs-deprecated cite),
   `test_ibugbazaar.py` (backfill now asserts live ids only),
   `test_migrations.py`, `test_report_export.py`, `test_scan_api_m5.py`,
   `test_worker.py`, `test_report_api.py`: **144 passed, ruff clean**;
   frontend tsc + vite green.
5. **Agent loop budget + sequential edit flow (Aug 13, owner report: "tool
   calling timeout too short… ends on read, doesn't continue to propose").**
   (a) **CLI-agent-like budget:** `settings.chat_timeout_seconds` 120→600
   (10 min, the whole-loop hard deadline) and `settings.max_tool_rounds`
   3→20 (the round ceiling that produced "I could not complete a grounded
   answer within the tool-call limit" mid-task); `ChatRequest.max_tool_rounds`
   schema cap 10→60. Loop-exhaustion tests pin `max_tool_rounds=3`
   explicitly (they asserted the old default's exact round count).
   (b) **"ends on read" nudge:** new `_EDIT_INTENT_RE` (change verbs:
   bypass/disable/remove/…) + `_EDIT_PROPOSE_NUDGE`: when a change request
   has run search/read tools but produced zero `propose_smali_edit` calls
   and then writes a content-only answer, the loop nudges (bounded ×2,
   mirroring the narration nudge) to propose or explicitly explain
   read-only. Gated on `edit_allowed` + intent (inherited from history so a
   bare "continue" follow-up keeps it). (c) **Sequential one-file-per-turn
   contract:** `_M8_EDIT_PROMPT` now says change requests MUST end in a
   proposal and multi-file requests are handled ONE FILE PER TURN:
   propose → human reviews (apply/reject) → "continue" → next propose.
   (d) **EDIT REVIEW STATE context:** `_load_edit_review_state` renders the
   scan's recent edits + verdicts (`proposed/applied/rejected` + instruction)
   into the system prompt when edit tools are ready, so a continue turn
   never re-proposes a resolved file.   (e) **Client-side thread → backend:**
   `ChatRequest.history` (`ChatHistoryTurn[]`, validated user/assistant,
   capped 12) + frontend sends the last 6 turns with every send
   (`useChat.buildHistory`: the backend never persisted chat); injected
   between system prompt and current question. (f) **Automatic
   continuation** (owner follow-up: "the continue should be automatic when
   user accept or edit the proposal"): DashboardView bumps a nonce the
   moment the review modal's pending count drops to 0 (an Apply/Reject in
   the modal is the only way that happens); AgentDock consumes each nonce
   exactly once (`seenContinueNonce` ref, so the follow-up turn that
   re-proposes can't double-fire) and auto-sends "continue…": the agent
   proposes the next file or declares the task complete, no button, no
   typing. Gates: **713 backend tests green** (+4 new: history injection,
   bad-role drop, review state, edit nudge fires / not for plain questions)
   + frontend tsc + vite build green.
6. **Multi-session agent chat (Aug 13, owner: "lets plan to add multiple chat
   session feature… add new session or delete previous session").** Decisions:
   server-side DB (survives reloads, full history reaches the model), auto-title
   from the first question + rename, per-scan scope (the dock is per-scan).
   Migration **0011**: `chat_sessions` (scan_id FK cascade, title, created/updated)
   + `chat_messages` (session_id FK cascade, role, content, tool_runs_json,
   position). Migration **0012**: `chat_messages.citations_json`: assistant
   turns persist their Citation-shaped chips (file/line/snippet) so a
   reloaded session's history re-renders the clickable source chips exactly
   like the live ChatResponse (owner follow-up: "persist citations with each
   session message"; `ChatMessageRead.citations` + `useChat.toChatMessage`
   maps them back; NULL on older rows renders without chips). Service `app/agent/sessions.py`: create/list (most-recently-used
   first)/rename/delete/add_message (auto-titles on first question; touch
   updated_at)/session_history/last_message/message_count. API: GET+POST
   `/scans/{id}/chat/sessions`, POST `…/{sid}/rename`, DELETE `…/{sid}`, GET
   `…/{sid}/messages` (tool_runs parsed back from JSON). `ChatRequest.session_id`
   → `/chat` + `/chat/stream` load the session's FULL persisted thread (fed to
   `answer_question` via the existing `history` param: the client's 6-turn
   window is now a no-session fallback) and persist the user turn at start (an
   interrupted turn still shows what was asked) + the assistant answer + tool
   trace at completion; stream route validates the session pre-headers (404)
   and the worker thread does its own DB work (`work_db = SessionLocal()`:
   SQLite + threads). `chat.py _MAX_HISTORY_TURNS` 8→20 (wider window for
   sessions). Frontend: `useChat` is session-aware: loads the per-scan list +
   most-recent session's thread on mount (creates NOTHING on browse; the first
   send creates on demand), `switchSession`/`newSession`/`deleteSession`/
   `renameSession`, and every send runs inside the active session (local
   message ids are NEGATIVE so they can never collide with server ids when a
   thread is loaded). Dock session bar under the strips: a trigger + custom
   dropdown (the model-picker pattern: outside-click + Escape close) listing
   sessions with inline rename (input in the row; Enter saves / Escape
   cancels) and a two-step inline delete confirm (first click arms
   "Delete?", second deletes) - NO browser prompt/confirm dialogs (owner
   follow-up); a pinned "＋ New session" row at the bottom; disabled while a
   turn runs. Auto-continue (item 5f) now guards on `last.id < 0`: only a
   LIVE proposal's review resumes the task; switching to an old session whose
   last turn proposed cannot trigger an unsolicited continuation. Gates: **721   backend tests green** (+8 sessions tests) + ruff clean + frontend tsc +
   vite build green.
7. **Finding triage + dock web toggle (Aug 13, owner: "add tools to batch
   suppress… too many instances of the MASVS-PLATFORM up-to-date-OS-version
   finding, I want to suppress all; when searxng is not reachable the dock
   web toggle should be disabled; when a finding is clicked jump to the
   code").** (a) **Batch suppress/restore by title:** `POST
   /scans/{id}/findings/suppress-batch` + `unsuppress-batch`
   (`BatchSuppressRequest {title, category?}`: the MASTG rules emit ONE
   finding per occurrence, so a check like the up-to-date-OS-version rule
   surfaces dozens of identical rows); toggles the whole title group, stamps
   /clears `suppressed_at`, recomputes risk ONCE (per-row toggles would
   recompute n times), idempotent (0-count no-op, never an error). The
   request is AND-composed (`title`/`category`/`severity`, ≥1 required: an
   empty match is a 422, never a "clear everything"; a typo'd severity is a
   400 like `list_findings`). Findings tab rows gain **"Suppress all (n)" /
   "Restore all (n)"**: shown only when the title group has >1 row (a lone
   finding would duplicate its own Suppress/Restore); counts are over the
   current active/review list and the match is title-only so the label
   always equals what actually toggles. The **severity group headers** gain
   the same band action: "Suppress all (n)" / "Restore all (n)" pins right
   in the colored header and bulk-clears a whole severity band (follow-up,
   owner: "bulk-clear a whole severity band at once"). **Undo toast:**
   `BatchSuppressResponse` now returns `finding_ids` (exactly which rows
   THIS call toggled) and the request accepts `finding_ids` as a criterion
   (≥1 criterion enforced: `[]` alone is a 422); after any band / title-
   group toggle a fixed bottom-center toast offers **Undo**, which flips
   back by those exact ids (`unsuppressFindingsByIds` /
   `suppressFindingsByIds`): a match-based restore would also flip earlier,
   separately-suppressed rows, so undo is precise. Auto-dismisses after 6s
   (failure keeps the toast, message becomes "Undo failed: …"); the toast
   is panel-level so it survives the findings refetch that follows every
   toggle.
   (b) **Finding click → code:** the row title (plus an explicit "View code
   ↗" button) jumps the Decompiler tab to the finding's file+line:
   DashboardView's `fileRequest` now carries `findingId`, the Decompiler
   resolves the tree path, sets `activeNoteId`, and the existing rail-note
   scroll effect lands the line once the content renders (codeMetrics dep).
   Findings without a `file_path` fall back to expanding the AI explanation.
   (c) **Dock 🌐 Web toggle locked when no live engine:** `webLocked` is now
   `!modelConnected || !liveEngine` (was `…|| (!liveEngine && !webResearch)`):
   the exact mirror of the Settings radio gate (SearchTab Aug 12), which
   disables a dead SearXNG-style engine's switch on AND off until it answers
   (recovery is ▶ Start engine / Test in Settings); `liveEngine` mirrors the
   keyed-engine gate too (`has_api_key`: the honest check is a real query,
   not a stale probe). The dock refreshes search-backend health whenever it
   opens so the lock reflects CURRENT reachability, not the boot snapshot.
   Gates: **734 backend tests green (+14 batch: title group, category
   narrowing, severity band, combined AND, idempotency, returned toggled
   ids, id-based undo restore, empty-ids 422, 409/400/422 contracts) + ruff
   clean; frontend tsc + vite build green.**
8. **Complete no-AI report + Markdown view in the Report tab (Aug 13,
   owner: "how does MobSF generate reports - they don't depend on AI but
   still have a complete report; I want a complete report not dependent on
   AI; also in the report tab display the md, it is better").** MobSF's
   answer (researched): a Django app whose static analyzers persist results
   to its DB, and the report is pure TEMPLATE rendering of those rows into
   HTML, converted to PDF via pdfkit/wkhtmltopdf: no LLM anywhere; our
   M9 `assemble_report` already had the same architecture (deterministic
   assembly from persisted scan data, `_auto_summary` exec-summary
   fallback). The remaining AI-dependent surface was the per-finding
   explanation (NULL without a model → findings rendered with no
   explanatory text). Fix: `_auto_explanation(finding)`: a deterministic
   paragraph (tool + severity + location + "mapped to MASVS control X and
   OWASP MASTG test Y (title from the vendored mapping)" + the static-only
   scope note) renders whenever `finding.explanation` is NULL; the cached AI
   text still replaces it when present. Body cache bumped v2→v3 (assembly
   changed).ReportPanel: the tab now defaults to the **Markdown source**
view (a scrollable/selectable `<pre>` of exactly what Export .md
downloads, + Copy markdown button) with a **Markdown ↔ PDF preview**
toggle; helper text updated ("no AI required - the cached AI commentary
replaces the factual fallbacks when a model has generated it"). (Aug 14:
the Markdown view now RENDERS the body via react-markdown instead of the
raw `<pre>` source: owner: "the report tab in markdown currently shows
raw markdown, fix it"; Copy markdown stays; see item 10.) Gates:
   **735 backend tests green (+1 no-AI explanation fallback) + ruff clean;
   frontend tsc + vite build green.**
   **Follow-up (same session, owner: "extend the deterministic explanation
   with the rule's description from the semgrep YAML rules"):** new
   `app/analysis/rule_meta.py`: `rule_description(check_id)` looks up the
   vendored rules' `metadata.summary` (62 rules carry one; the 8
   hand-curated MobARK rules don't: their folded `message` IS the finding
   title, so citing it would repeat the row, and they're skipped). The
   report's `_auto_explanation` reads `detail.check_id` (JSON-text or dict
   detail via a `_finding_detail` helper) for semgrep findings and cites
   it: "This semgrep check (mastg-android-sdk-version: "This rule scans for
   API that checks the version of the operating system") reported a …";
   tolerates namespaced/path-prefixed check ids via a trailing-id fallback.
   **Follow-up (same session, owner: "extend the deterministic explanation
   to gitleaks findings using their detail.rule_id and a vendored gitleaks
   rule description"):** gitleaks already persists `detail.rule_id` AND
   `detail.rule_description` (captured from gitleaks' JSON report at scan
   time - no new ruleset parsing needed); `_auto_explanation` cites both:
   "This gitleaks check (google-api-key: A Google API key was detected)
   reported a …". A gitleaks finding without a description (legacy row)
   just omits the rule clause - the title already names the rule.
   Gates: **740 backend tests green (+extended fallback test) + ruff
   clean** (frontend untouched).
   **Follow-up (same session, owner: "add the rule description to the
   Findings tab's no-AI ExplainBox fallback so the app matches the
   report"):** `_auto_explanation` + `_finding_detail` moved OUT of
   `report.py` into a shared `app/analysis/auto_explain.py`
   (`auto_explanation(finding)` - one source of truth for the report AND
   the explain surface). `insights.explain_finding` now catches
   `NoModelConfigured` and returns the deterministic paragraph marked
   `fallback: true` (never persisted as the cached AI row) instead of
   propagating a 400; `ExplainResponse.fallback: bool = False`;
   `ExplainBox` labels it "deterministic · no AI required (same text as
   the report)" and the Regenerate button reads "Regenerate with AI" -
   works on BOTH surfaces (Findings rows + the Decompiler annotation rail
   share ExplainBox/useExplain). The route's NoModelConfigured→400 catch
   stays as defense (the summary route still 400s). Gates: **740 backend
   tests green (no-model insights test now asserts the fallback) + ruff
   clean; frontend tsc + vite build green.**
9. **Semgrep rules license audit + GPL rewrite (Aug 13, owner: "check our
   semgrep - are we really using tools only or include its rule… it's rule
   licensed while mobsf only use tools and use java/kotlin rules; don't
   modify, just analyze" then "rewrite the two GPL-derived MASTG rules so
   the repo stays Apache-2.0-clean").** Audit verdict: we run the semgrep
   ENGINE (LGPL-2.1 CLI, subprocess-only) against ONLY our local vendored
   rule dirs (`--config app/analysis/rules/{mobark,mastg}`) - never the
   semgrep registry (`p/default`/`--config auto`/`r/…`), so Semgrep's own
   restrictive "Semgrep Rules License v1.0" never applies (that's the
   licensed-rule concern the owner remembered). Rules: 8 hand-curated in
   `mobark/` (Apache-2.0, project-owned) + 71 vendored verbatim from
   OWASP/owasp-mastg @ `d7fd7d45` (CC BY-SA 4.0, `License.md` at the ref;
   the `rules/` dir has no separate license file). Full-set audit (all 52
   files incl. the `.yaml`-extension ones, every metadata key + comment
   headers + URLs): the ONLY external-origin indicator beyond `summary`/
   `masvs`/`references` (Android doc links) is `original_source` on exactly
   TWO rules: both → **mindedsecurity/semgrep-rules-android-security,
   which is GPL-3.0** (verified its LICENSE). Those two MASTG rules are
   adapted derivatives of that repo's `rules/crypto/mstg-crypto-6.yaml`
   (MASTG split the single MSTG-CRYPTO-6 rule; 3/7 and 2/7 of its pattern
   atoms appear verbatim): GPL-3.0-derived content vendored into an
   Apache-2.0 repo = copyleft contamination against the project's hard
   constraint. **Fix (owner-approved): rewrote both rules from scratch**:
   same MASTG-CRYPTO-6 detection intent, ORIGINAL pattern expression: the
   GPL file's `pattern-inside: $M(...){ ... }` method-body wrapper is gone
   (matches anchor on the call sites themselves), `random-apis` now
   enumerates the `java.util.Random` API methods explicitly instead of a
   catch-all `$Y(...)`, `non-random-use` gained `getTimeInMillis()`;
   `original_source` dropped (no longer derived). The id/message/summary
   stay (MASTG CC BY-SA text, consistent with the other vendored files); a
   comment header records the rewrite. Verified with the REAL engine:
   `semgrep --validate` = 0 errors, and a smoke scan hit exactly the
   intended lines (time sources 5–7, weak RNG 9–11) and skipped the benign
   one. Gates: **740 backend tests green + ruff clean** (no test pinned the
   old patterns).
10. **Report surface rework (Aug 14, owner: "make the findings container
   not clickable: it already has a view code button; the regenerate
   button in the report tab is not necessary since it requests AI but our
   report does not depend on AI; the report tab in markdown currently
   shows raw markdown: fix it; in the pdf there is truncated text (the
   cover scope line); remove the green color at the start of each title
   like Executive summary; markdown and pdf should show every not
   suppressed finding, not only just medium x count; the report has no
   need for Resigned test builds").** Six changes:
   (a) **Findings row container is no longer clickable**: the title row
   is a plain div; only the "▸ AI explanation" (expand) and "View code ↗"
   (jump to the Decompiler) buttons are interactive (`FindingsPanel.tsx`;
   the old title-click also jumped, duplicating View code).
   (b) **Regenerate removed from the Report tab**: the report is
   deterministic (no AI dependency), so the AI-only Regenerate button and
   its status lines are gone from `ReportPanel.tsx`; the unused
   `api.regenerateReport` method + `ReportRegenerateResponse` type were
   deleted. The backend `POST /scans/{id}/report/regenerate` route and its
   tests stay (harmless; only the UI affordance was unwanted).
   (c) **Markdown tab renders instead of showing raw source**: the
   Markdown view now renders `body.markdown` through the existing
   react-markdown `Markdown` component (`.md` typography) inside a
   scrollable `.report-md-body` card; the raw-source `<pre>`
   (`.report-md-source`) is gone; Copy markdown still copies the raw body.
   (d) **PDF cover scope footnote wraps**: the cover's static-only scope
   line was ONE `drawCentredString`, overflowed the page width, and got
   CLIPPED at both edges (owner saw "…c analysis of the uploaded
   artifact…" with the start and end cut off). New
   `report_pdf._draw_wrapped_centered` word-wraps it into centered lines
   (verified: two lines, both < the 499pt text width).
   (e) **PDF h2 emerald LEFT BAR removed**: "remove the green color at
   the start of each title like Executive summary": the h2 TableStyle
   drops `LINEBEFORE` (the green underline `LINEBELOW` below the title
   stays; h3 severity headings unchanged).
   (f) **Every non-suppressed finding listed + no Resigned test builds**:
   `assemble_report` no longer partitions findings by library: the
   vendored per-library tally (`### Third-party library findings (N)`,
   "n medium" style counts) is GONE: every finding renders individually
   under its severity heading (`group_for_finding` import dropped; the
   Recommended-priorities intro no longer mentions the tally). The
   **"Resigned test builds" section is GONE too**: `builds` was removed
   from `assemble_report`/`cached_body`/`store_body`/`_cache_identity`,
   `_builds_fingerprint` deleted, and the route's `_assembled_report` no
   longer queries `Build` rows (the Recompile modal still owns that
   history). Body cache bumped v3→v4 (assembly changed). Tests: the
   vendored roll-up test was rewritten to assert every finding lists
   (`### High (2)`, `### Medium (1)`, `### Other (1)` …), the full-body
   test dropped its Build rows + section assertions, and the PDF export
   tests still pass with the new h2/cover rendering. Gates: **740 backend
   tests green + ruff clean; frontend `tsc -b` + `vite build` green**
   (report rendered-markdown styles in `index.css`).

M10: Open-source readiness (GitHub); **PLANNED (Aug 14, 2026), plan
finalized, not started.** See `docs/progress/M10.md`. Goal: publish the
repo on GitHub as a public OSS project. Owner decisions locked at kickoff:
(1) docs site = **MkDocs + Material → GitHub Pages** (`site/` dir,
tracked: `docs/` STAYS gitignored per the M9 decision, so the public
site carries its own curated pages; the internal milestone .md docs,
including M10.md itself, never reach GitHub); (2) **full CI + deploy**
(backend pytest+ruff, frontend build, Pages deploy via actions/deploy-pages,
plus dependabot); (3) **dependency licenses in a separate file**:
`docs/licenses.md` refresh + a public `site/docs/licenses.md` page;
README only links them (attribution); (4) demo media = **placeholders**
(screenshot + video; owner fills later); (5) **social-preview header**:
uses the owner's branded banner `docs/icons/mobark_icon_text_desc_whitetext.svg`
(960×263 white-text icon+text+desc) VENDORED into `site/assets/` (docs/ is
gitignored) and shown on a dark background: `site/assets/mobark-header.svg`
(dark rect baked in) for the README header + a dark-bg social-preview PNG
(~1280×640 via scripts/render_social_preview.sh, headless Chrome) for the
repo preview; (6) community files: CONTRIBUTING/CODE_OF_CONDUCT/
SECURITY/CHANGELOG + issue/PR templates; (7) Apache-2.0 stays, release
checklist (semver tag + first GitHub Release, optional GHCR). Six phases
A–F (repo polish+site skeleton · license attribution · community files ·
CI · Pages content · header/release). Open-source suggestions reviewed:
semver+releases, dependabot, SECURITY private reporting, good-first-issue
labels, GHCR image, optional SBOM/SPDX (v1.1). Out of scope: product
features (M11+), PyPI/npm publishing, SBOM/SPDX, automated docs/ → site/ sync.

M9.1: User authentication; **COMPLETE (Aug 14, 2026), Phases A–E all
done, containerized contract-style e2e PASSED.** See
`docs/progress/M9.1.md`. Owner decisions executed: (1) **per-user data
isolation**: ownership on `scans.user_id` (migration 0013, nullable +
app enforcement); findings/chats/edits/builds/smali/graphs/report caches
key off the scan row, so one `require_scan_access` check per scan-keyed
route isolates everything (404, not 403, for foreign scans: body
byte-identical to a nonexistent scan, no existence leak); threaded via
the `request_ctx.current_user_id` contextvar set by `get_current_user`
through ALL 35 `_get_scan_or_404` call sites (one choke point, no route
can forget it); `list_scans` own-only, `create_scan` attributes; (2)
**auth ON by default** (`MOBARK_AUTH_ENABLED=0` restores the open dev/CI
behavior: live-verified); (3) three methods, username/password (stdlib
`hashlib.scrypt`, `scrypt$n$r$p$salt$hex`, constant-time compare) + GitHub
OAuth (state) + Google OAuth (state + PKCE, `email_verified` gate), both
hand-rolled over the already-pinned httpx: **zero new runtime deps**, the
license audit gains no rows; (4) sessions = opaque `secrets.token_urlsafe`
tokens stored SHA-256-hashed in a `sessions` table (revocable on logout,
sliding 7-day expiry) behind an HttpOnly SameSite=Lax cookie; (5) first
registered user = admin + auto-claims legacy unowned scans (transactional,
idempotent): **Phase E hardening**: the read-then-write first-user check
is race-safe now via a partial UNIQUE index `users(is_admin) WHERE
is_admin` (migration 0014, ORM too): at most ONE admin row ever; the
register route catches the loser's IntegrityError and re-derives as a
non-admin (tested with a real threaded race); (6) per-user model/search
stores: root `model_backends.json`/`search_backends.json` stay as the
env-seeded SYSTEM layer, per-user overrides in `data/users/<uid>/…` (user
file = source of truth after first read; BYOK keys isolated per user; the
per-user `_write` must mkdir `path.parent`, not `data_dir`: bug fixed in
both stores); (7) health + auth routes stay open (compose healthcheck),
everything else behind `get_current_user` router dependencies;
Origin-check middleware on mutating routes (pure-ASGI, no SSE buffering;
no CSRF token in v1); worker untouched (jobs carry scan ids). OAuth config
= env only; login buttons render only when configured. CLI escape hatch:
`python -m app.cli auth reset-password <username>`. Frontend (Phase D):
LoginView (register/login toggle, OAuth buttons from `/auth/providers`,
`?error=` handling), `useAuth` boot (providers→me→`auth` state, auth-off
skips login), `onUnauthorized` 401 hook, TopBar user chip + logout,
activeScanId cleared on login/logout/401. Phase E: cookie-tampering tests,
auth-off parity suite, `scripts/e2e_auth.sh` PASSED against rebuilt images
(fresh volume, admin register, upload+scan, second-user 404 isolation,
claim visibility, OAuth per env, auth-off parity). Gates: **820 backend
tests green + ruff clean; `tsc -b` + `vite build` green; e2e_auth.sh
passed**. PRD's "single-user, no auth" v1 lines superseded (revised in
Phase E docs); deliberately-global items documented in M9.1.md audit
section (shared `mobark-test.jks` keystore, system store layer,
CLI-as-host-operator); M10 coordination: the public `site/` docs get an
auth page when M10 lands.

M9.1 follow-ups (post-completion, Aug 14, 2026):

- **`mobark:mobark` login test** (`test_auth_api.py::test_login_mobark_default_credentials`):
  `mobark` is only 4 chars, so it can't self-register (the register route's
  8-char minimum password: by design); the test seeds the account
  directly in the scratch DB via `hash_password("mobark")` (same as the
  conftest fixture) and proves the login round-trip: `POST /auth/login`
  mobark:mobark → 200 + session cookie → `/auth/me` returns the `mobark` user.
  `mobark` is a HOST-SEEDED/demo credential, not a self-registration path.
- **Settings moved into the profile dropdown** (TopBar): the standalone ⚙
  icon-btn is gone in auth-on mode: the user menu gains a **Settings**
  item above **Sign out** (the menu closes before opening the modal so the
  outside-click handler doesn't immediately re-close it). Auth-off parity
  mode has no user chip, so the ⚙ gear stays in the top bar there (the
  only way to reach Settings without a user). CSS: menu items default to
  body text; only **Sign out** stays red (danger). Gates: `tsc -b` +
  `vite build` green.
- **Vault: envelope encryption for BYOK/search keys at rest** (owner
  request, Aug 14): per-user API keys (`model_backends.json` /
  `search_backends.json` under `data/users/<uid>/`) are no longer plaintext
  0600: a random 32-byte master key wraps each key (AES-GCM, fresh nonce,
  `cryptography==44.0.0`: Apache-2.0, new license row), and the master
  key itself is wrapped in `key_wrap.json` by a scrypt KEK derived from the
  user's MobARK password (local users) or a dedicated vault passphrase
  (OAuth-only users: no password). The unwrapped MK never persists: at
  login it is re-wrapped under the raw session token into
  `sessions.vault_wrap` (migration 0015), and `get_current_user` recovers
  it per request into `request_ctx.current_master_key`; the chat worker
  thread gets it passed explicitly like `user_id`. Stores encrypt on write
  (`_protect_api_key`), decrypt at use (`resolved_api_key` in
  model/client, model/health, search/client), raise `VaultLockedError`
  (→400) on key-writes to a locked per-user vault, lazily migrate
  pre-vault plaintext files on first unlocked read, and the `*.tmp` write
  now creates 0600 from the start (no world-readable window). The SYSTEM
  store stays plaintext by design (owner env keys, CLI surface).
  OAuth-only sessions start vault-locked: `POST /auth/vault/unlock`
  (passphrase; first use creates the vault: a wrong passphrase 401s and
  never silently re-creates it) + `POST /auth/vault/reset` (forgot
  passphrase → destroy + clear keys); `/auth/me` carries `vault_locked`
  and Settings shows a passphrase form while locked. `cli auth
  reset-password` now destroys the vault + clears stored keys (keys are
  unrecoverable without the old password: printed loudly). Honest limit:
  the host operator can still extract keys from process memory at runtime;
  the guarantee is at rest (disk/backups/volume) + tenant isolation.
  Gates: 839 backend tests green (18 new vault tests) + ruff clean;
  `tsc -b` + `vite build` green.
- **Severity vocabulary + scoring reworked** (owner decision, Aug 15,
  2026): findings are now `high | warning | info` only (the Aug 8
  entry's `high | medium | low | info` is superseded in two steps: the
  low band was dropped and former low findings rewritten to **info**,
  then `medium` was renamed **warning**; migrations 0016 + 0017 with
  done-scan re-scores). Rationale: CVSS 4.0 qualitative scoring is for
  disclosed CVEs where a human analyst assesses attack requirements / user
  interaction: a static scanner can't honestly claim that context, so the
  CVSS 4.0 model was REPLACED by a plain **banded risk index** (the MobSF
  pattern): the worst finding picks the band (any high → base 70, otherwise
  warning → base 40), +1 per extra finding at that band, capped at the band
  ceiling (high 99 · warning 69); info never scores; `security = 100 − risk`.
  The gauge caption is now the honest "risk n/100 · band" (no CVSS claim),
  and the old unreachable 1–39 "low" risk band is gone (bands are High
  70–99 / Medium 40–69 / None 0). Emitters updated: external-storage
  permissions (`manifest.py`), aps-environment (`entitlements.py`), empty
  usage strings (`plist.py`), sysctl/syscall imports (`symbols.py`) emit
  `info`; the former medium producers (risky permissions, exported
  components, cleartext, get-task-allow, ATS, legacy crypto/UIWebView/
  ptrace symbol rules, stack-canary) emit `warning`. `risk.py` uses
  `SEVERITY_WEIGHT` (ordinal, ordering only) + `_BAND_RISK`; the report's
  recommended priorities are high + warning only; the PDF cover shows
  three severity boxes. Frontend: `Severity` type, filter chips, stat
  boxes, tree dots/rail labels, `DependenciesPanel` `warning_count`, and
  the CSS classes renamed (a legacy `low`/`medium` row still renders: the
  UI falls back to info/other defensively). Gates: 840 backend tests green
  + ruff clean; `tsc -b` + `vite build` green; containerized browser e2e
  verified the chips/gauge/PDF on a live scan.
- **Follow-up (same session): browser e2e caught + fixed two leftovers, and
  iOS was verified end-to-end too.** (1) The assembled report body still
  emitted "CVSS 4.0 · risk n/100" in the header, the risk-score line, and
  the scope note: exactly the dishonest provenance the banded model was
  meant to drop. All three now read `risk n/100 · band` / `Risk score:
  n/100` / a scope note explaining severity bands follow the banded risk
  index and are "not CVSS - a static scanner cannot honestly assess CVSS
  attack requirements or user interaction". Bonus find: `report_pdf.py`'s
  cover-meta regex already expected the NEW caption format, so the cover
  gauge had been silently showing "No security score" since the banded
  change: the report.py fix aligned them and the PDF cover now renders
  the real score. `_REPORT_CACHE_VERSION` bumped 4 → 5 (stale persisted
  bodies rebuild). (2) `requirements.txt` had drifted unbuildable:
  `androguard==4.1.4`'s metadata now requires `cryptography>=46.0.6`,
  conflicting with the M9.1 vault pin `==44.0.0` (the local venv held both,
  so tests passed while `docker compose build` could not resolve). Bumped
  the vault pin to `cryptography==46.0.7`: the vault only uses AESGCM
  (stable API), so no code change; comment records the drift. (3) iOS e2e
  (iBugBazaar.ipa, headless Chrome via CDP): 9 findings all in the new
  vocabulary (3 warning + 6 info, zero high: the High chip shows (0) and
  the High group header correctly disappears at zero); gauge caption
  `risk 42/100 · Medium` (the "Medium security" label is the risk-BAND
  name, a separate scale kept intentionally); report body + PDF cover carry
  `0 HIGH 3 WARNING 6 INFO` and the iOS binary profile section with no
  Android leakage. Both scans (Android 517 findings, iOS 9) passed 15/15
  and 14/14 CDP assertions against API-derived expected counts. Gates:
  840 backend tests green + ruff clean; frontend `tsc -b` + `vite build`
  green.

## M10: Open-source readiness (Aug 15, 2026)

**IN PROGRESS: Phases A–F implemented; owner-only steps remain.**
Docs: `docs/progress/M10.md` (plan + implementation record), the M10
section of `docs/mobark-tasks.md` (checkboxes ticked).

**Phase A: site + README.** Public docs site = tracked `site/` MkDocs
project (root `mkdocs.yml`, `docs_dir: site/docs`, `site_dir: _site`
gitignored, Material theme). Curated pages: index / quickstart /
features / architecture / auth / milestones / demo / licenses. **`docs/`
stays gitignored** (owner decision: internal milestone docs + sample
binaries never reach GitHub; the site is curated by hand). README
rewritten: dark-bg header banner (vendored brand SVG), badges (license
Python/Node/CI/docs), pitch, feature list, quick start with the **demo
users** (`admin`/`password123` first = admin, `alice`/`password123` =
regular user: documented for LOCAL installs, loudly marked demo-only),
config table, screenshot placeholders, docs/license links. Naming
collision check: "MobARK" collides with Google/ADA's Mobile App Security
Assessment program (accepted, flagged in M10.md).

**Phase B: licenses.** `docs/licenses.md` already current (Aug 14,
M9/M9.1 covered; `pip-licenses` verified no new rows). New
`site/docs/licenses.md` = public attribution page (permissive-only
posture, subprocess-only note for Semgrep LGPL + SearXNG AGPL).

**Phase C: community files.** `CONTRIBUTING.md` (dev setup, checks,
PR flow, local-first + Apache-2.0 + subprocess-only scope),
`CODE_OF_CONDUCT.md` (Contributor Covenant 2.1), `SECURITY.md`
(private reporting via GitHub advisories, local-first posture,
demo-credentials warning), `CHANGELOG.md` (Keep-a-Changelog,
Unreleased seeded, M0–M9.1 history). `.github/ISSUE_TEMPLATE/`
(bug_report.yml + feature_request.yml) + `PULL_REQUEST_TEMPLATE.md`.

**Phase D: CI.** `.github/workflows/backend.yml` (pytest + ruff, py3.11),
`frontend.yml` (npm ci + `npm run build` = tsc -b + vite),
`pages.yml` (mkdocs build → `actions/deploy-pages`, upload artifact from
`_site`), `dependabot.yml` (pip + npm weekly, grouped). CI badges in the
README (resolve after first run).

**Phase E: Pages content.** Auth page documents M9.1 (first-run admin,
OAuth env-only config, per-user isolation, vault, `MOBARK_AUTH_ENABLED=0`
parity, no-enumeration login). Demo page + README screenshots =
**placeholders** (PNG "OWNER: add" renders; owner fills later). Local
`mkdocs build` verified clean: mermaid diagram in the architecture
page renders (Material 9.7.7 handles `pre.mermaid` fences natively via
its own lazy-loaded script; verified through headless Chrome: the
theme renders into shadow DOM, so `--dump-dom` shows an empty div).

**Phase F: assets.** Vendored `docs/icons/mobark_icon_text_desc_whitetext.svg`
(1.6MB, embeds raster) into `site/assets/` + `mobark-icon.svg`; dark-bg
`site/assets/mobark-header.svg` (README header); 1280×640 social-preview
PNG via `scripts/render_social_preview.sh` (headless Chrome of
`site/assets/demo/social-preview.html`).

**Remaining (owner actions):** repo metadata in the GitHub UI
(description/topics/homepage → github.io), live Pages deploy
verification, demo media, semver release. Gates: `mkdocs build` clean,
backend pytest + ruff green, frontend tsc + vite build green.
