# MASA (Mobile Application Security Assistant) — Task List (v2, aligned to confirmed tech stack)

No fixed dates — sequenced by milestone dependency. Same milestone order as v1, tasks updated to reference actual tools. Feasibility notes are called out inline where a task was corrected from the original plan.

Stack reference: Python 3.11 + FastAPI · RQ + Redis · SQLite · **no vector store — the M4 RAG/embedding pipeline was deleted from v1 (owner decision); the agent layer is non-embedding: Layer 1 full findings context + Layer 2 search/read tools + Layer 3 Graphify graph** · jadx + androguard + Semgrep (Android) · LIEF + Mach-O import-table scanner + Gitleaks + Semgrep (iOS) · Gitleaks (secrets, both platforms) · apktool + apksigner/zipalign (Android recompile) · ldid (iOS resign) · LiteLLM (model/BYOK abstraction) · React + Vite + Tailwind · Ollama/LM Studio (host-run, not containerized) · SearXNG + GPT Researcher pattern (deep research) · agent-browser (CDP-driven browser automation, M7) · Docker Compose (3 services) · Apache-2.0 · Graphify (code-only, graph-based structure understanding)

**Library-first principle:** prefer an existing, maintained library over custom logic wherever one covers the need — the project ships Apache-2.0, so any GPL/LGPL-licensed tool (Semgrep, ldid, and the analysis CLIs) must be invoked as a subprocess, never imported as a library. See tech stack doc for the specific swaps and reasoning.

---

## M0 — Project scaffolding (new — not in v1 list)
- [x] Repo skeleton: `backend/` (FastAPI app + RQ worker), `frontend/` (React + Vite), `docker/`
- [x] `docker-compose.yml` starting with `app` + `redis` (searxng added in M7)
- [x] FastAPI base app with health-check endpoint
- [x] SQLite schema/migrations for scans + findings (e.g. via SQLModel or plain SQLAlchemy)
- [x] Redis + RQ worker wired up, test with a dummy job
- [x] Dependency/license audit pass: pin versions for Gitleaks, Semgrep, LiteLLM, LlamaIndex, GPT Researcher and record their licenses in the repo (informational — MASA is Apache-2.0, so GPL/LGPL tools stay subprocess-only; the audit records versions, licenses, and that posture)

## M1 — Android analysis core
> **Status: complete (Aug 3, 2026)** — see [docs/progress/M1.md](progress/M1.md).
- [x] Wrap jadx as a callable subprocess module (APK in → decompiled Java/Kotlin source tree out)
- [x] Bundle a JVM in the app Docker image for jadx — image builds, **389 MB content** (within the 350–450 MB gate)
- [x] Integrate androguard for manifest parsing (permissions, exported components, intent filters) — pure Python, no JVM needed for this part
- [x] Wrap **Gitleaks** as a subprocess module for secret/string scanning (replaces the originally-planned custom regex/entropy scanner — reusable as-is for M2)
- [x] Wrap **Semgrep**, running Java/Kotlin-oriented rulesets (community + OWASP-style) against jadx output for code-level findings (insecure WebView config, weak crypto, hardcoded trust managers, etc.) — replaces hand-writing these as one-off regex checks
- [x] Parse app signing certificate info (androguard supports this directly)
- [x] Parse network security config XML
- [x] Define structured findings JSON schema (title, severity, file/line, category) — needs a field for which tool produced each finding (androguard/Gitleaks/Semgrep), since they'll have different output shapes to normalize
- [x] Pull MASVS/MASTG tag mappings from the **official OWASP MASTG repo's mapping data**, vendored/cached locally, instead of hand-maintaining a lookup table
- [x] Validate end-to-end against a deliberately vulnerable test APK (`docs/InsecureBankv2.apk`) — 6 integration tests pass + containerized e2e verified (523 findings, same result on host and in compose)

## M2 — iOS static core
> **Status: complete (Aug 5, 2026)** — see
> [docs/progress/M2.md](progress/M2.md).

**Foundation (no LIEF yet):**
- [x] IPA unpack pipeline: `.ipa` → `Payload/*.app` via `zipfile` (pure Python), bundle id/name extraction, malformed-IPA rejection reusing M1's `ScanAborted` policy
- [x] Info.plist parsing via `plistlib` (binary + XML formats): ATS config (`NSAllowsArbitraryLoads`, per-domain exceptions), usage-description strings, `MinimumOSVersion`, background modes, bundle metadata
- [x] Platform autodetect in the CLI + orchestrator (`.apk` → android, `.ipa` → ios)

**Mach-O + entitlements (LIEF):**
- [x] Add `lief` to `requirements.txt` (Apache-2.0, manylinux wheels) + license-audit row
- [x] `ios/macho.py` via LIEF: PIE flag, stack canary (`___stack_chk_guard`), ARC indicator, FairPlay-encrypted check (`LC_ENCRYPTION_INFO` cryptid), exported symbols, linked dylibs, fat-arch slice info
- [x] `ios/entitlements.py`: carve the embedded code-signature blob via LIEF's `code_signature` object and parse with `plistlib` — no `codesign` dependency
- [x] Surface the entitlement-coverage limit in finding output (best-effort for ad-hoc/resigned IPAs; App Store FairPlay binaries are encrypted) — not just internal docs

**Findings + persistence (same schema as Android):**
- [x] `static_only: bool` on the findings schema (model + migration `0003` + `FindingRead`), set True on every iOS finding
- [x] Map iOS finding types to MASVS/MASTG using the already-vendored mapping (it includes iOS tests) — backfill `mastg_test_id` like M1
- [x] Reuse M1's Gitleaks wrapper against the `.app` tree (binary + resources) — ran clean on iBugBazaar (no hits); Linux coverage documented in M2 progress doc
- [x] `run_ios_scan` RQ job + CLI `run`/`scan` autodetect

**Validation:**
- [x] Unit tests: unpack / plist / entitlements / Mach-O (synthetic fixture or LIEF-built Mach-O)
- [x] Integration test against a pinned vulnerable sample IPA (**iBugBazaar**, `MASTG-APP-0030`, release artifact pinned + sha256) — **4/4 pass on host** (macOS); Linux confirmation via container e2e below
- [x] Rebuild image with `lief` + containerized e2e: enqueue an iOS scan through the compose worker → `done` with persisted findings (mirror M1)
- [x] Docs: `docs/licenses.md` (+lief), progress notes, this checklist

## M3 — Model backend abstraction
> **Status: COMPLETE (Aug 5, 2026)** — see
> [docs/progress/M3.md](progress/M3.md).
>
> Owner decisions at kickoff: BYOK keys plaintext in `data_dir` with `0600`
> perms (encryption-at-rest deferred to M5); curated BYOK set (OpenAI,
> Anthropic, DeepSeek, OpenRouter + custom); **no hard default chat model**
> (blank — the user picks from what the backend serves). Note: the
> "embeddings + ChromaDB deferred to M4" item was **removed from v1 entirely**
> at M4 kickoff (owner decision, Aug 6) — see the M4 section.

**Phase 1 — LiteLLM client + local backends:**
- [x] Add `litellm` (1.95.0) to `requirements.txt` (pinned) + `docs/licenses.md` row (MIT); `httpx` promoted to a direct runtime dep
- [x] `model/client.py`: thin `chat()` wrapper over `litellm.completion` with per-backend `api_base`/`api_key`/model-string mapping (dummy keys for local servers)
- [x] Local backend definitions: Ollama (`localhost:11434`, in-container `host.docker.internal:11434`) and LM Studio (`localhost:1234/v1`)
- [x] `model/health.py`: connectivity check (cheap `max_tokens=1` completion) + model listing; graceful "unreachable" result, never an exception

**Phase 2 — Config layer + API surface:**
- [x] `model/backends.py`: JSON-backed config store in `data_dir` (`model_backends.json`, perms `0600`), seeded from `MASA_*` env vars, runtime-editable
- [x] API routes (what M5's Settings modal will consume): `GET /model/backends` (with lightweight reachability) · `POST /model/backends/{id}/test` (full probe) · `GET /model/backends/{id}/models` · `PUT /model/backends/{id}` (runtime edits)

**Phase 3 — BYOK providers via LiteLLM:**
- [x] `model/providers.py`: provider table (OpenAI/Anthropic/DeepSeek/OpenRouter/custom — curated v1 set): env-var names, model-string prefixes, key-required vs. base-URL-only, OpenAI-compatible listing path + static fallback models, kept in one module
- [x] Keys never logged (`api_key` excluded from repr; API returns `has_api_key` only); store written `0600`; encryption-at-rest deferred to M5 (already an M5 task)

**Phase 4 — Embeddings + ChromaDB foundation — DEFERRED TO M4** (owner decision; items moved to M4 below)

**Phase 5 — Validation:**
- [x] Unit tests with `litellm`/`httpx` monkeypatched (no network) — **47 tests**: config store round-trip/perms/redaction, client mapping, health behavior, provider invariants, API surface
- [x] Integration tests gated on a real running Ollama (skipped when unreachable — `pytest -m integration`)
- [x] `docker-compose.yml`: `extra_hosts: ["host.docker.internal:host-gateway"]` on app + worker; `MASA_OLLAMA/LM_STUDIO_BASE_URL` → `host.docker.internal`; containerized check ran (host-gateway resolves; CLI health graceful with Ollama down)
- [x] CLI: `python -m app.cli model health [--backend ollama|lm-studio]` for UI-free verification
- [x] Docs: `docs/licenses.md` (+litellm, +httpx), this checklist, `docs/progress/M3.md` status flip
- [x] Hygiene: `.dockerignore` fixed — `backend/data` was leaking into the image (`data/` only matched the repo root); now `**/data`

## M4 — Agent context layers (Layers 1-3, no RAG)
> Plan + progress: [docs/progress/M4.md](progress/M4.md) — written Aug 5, 2026.
> **Owner decision (Aug 6, 2026): the RAG/embedding pipeline is DELETED from
> v1, not deferred.** Chunking (LlamaIndex CodeSplitter), ChromaDB storage, the
> embedding job, and the vector-retrieval chat endpoint were removed outright —
> CPU-only embedding of a 3MB APK took 5-15 min before chat was even usable.
> Replaced by three non-embedding layers. Status: **built + unit-tested (Aug 6,
> 2026)**; live-model QA is manual (Ollama off during development).

**Layer 1 — structured findings as direct agent context (all sources, full set):**
- [x] `agent/context.py`: normalizes every finding source into one agent-facing schema
      with a per-finding **precision tag** — `[file/line]` (semgrep, gitleaks,
      androguard manifest, Info.plist) vs `[binary-level presence only, no specific
      location]` (Mach-O protections/entitlements, import-table scanner). Platform
      tool whitelists: **androguard is Android-only and must never appear in an iOS
      context**; iOS = plist + lief + symbols + gitleaks + semgrep. Full findings set
      rendered (no subsetting; explicit `max_findings` escape hatch only)
- [x] iOS **binary profile** surfaced as info findings (was hidden in unpersisted
      `result.meta`): exported symbols, linked dylibs, architectures, ARC, full
      entitlement set — this is what answers "what entitlements does this app have"
- [x] **Import-table scanner** (`analysis/ios/symbols.py`, tool id `symbols`) — the
      explicitly-named replacement for vague "LIEF-derived findings": known-insecure
      API blocklist matched against Mach-O imports — CC_MD5/CC_SHA1/CC_DES/CCCrypt
      (legacy crypto), UIWebView, NSURLConnection cert-bypass selectors, ptrace/
      sysctl/syscall anti-debug. Binary-level precision by design; findings note
      what constant-level detail (ECB mode, PT_DENY_ATTACH) is NOT visible at the
      import table
- [x] iOS Gitleaks ruleset (`resources/gitleaks_ios.toml`) for the
      `kSecAttrAccessibleAlways` insecure-keychain string — **string-level, rides
      through Gitleaks, not the import-table scanner**
- [x] iOS semgrep stage added for completeness — **zero yield by design** (binary
      structure via LIEF, no decompiled Swift/ObjC source); the Layer 1 context
      builder flags it so the agent never leans on it

**Layer 2 — grep + file read as agent tools (no embeddings, both platforms):**
- [x] `agent/tools.py::search_code(pattern, glob)` — regex over the scan's
      decompiled/extracted tree (Android jadx tree; iOS unpacked bundle)
- [x] `agent/tools.py::read_file(path, line_range)` — traversal-guarded, binary
      plist decoded to text, binary files refused with a clear message
- [x] No platform branching inside the tools — only the tree-root resolver knows
      the platform; identical behavior both platforms

**Layer 3 — Graphify as agent tools (Android only):**
- [x] `graph_query`/`graph_path`/`graph_explain` tool wrappers over the graphify CLI
      (`app/graph/graphify.py`, renamed from `app/vector` — no "vector" name left)
- [x] `build_graph_scan` RQ job chained after `run_scan` (Android-only; iOS records
      `ios-no-source`); graph state is filesystem-derived, `GET /scans/{id}/graph`
- [x] CLI: `rag` group → `graph build|query|path|explain` + `agent context|chat`;
      `agent context` renders the exact Layer 1 context with zero LLM
- [x] Graphify CLI-surface corrections (validated 0.9.32): headless build is
      `update <dir> --no-cluster`; queries via `query|path|explain|affected --graph`;
      natural-language queries fail on code-only AST graphs → label/ID substring
      fallback in the wrapper
- [x] iOS graph negative confirmed (Aug 6): an unpacked `.app` tree has zero
      source-like files → Graphify is Android-only in v1

**Agent chat (mocked unit tests only — Ollama off during development):**
- [x] `agent/chat.py`: bounded tool-calling loop (≤3 rounds) over Layers 1-3, with
      the documented graceful fallback to context-only answers when the model
      doesn't emit tool calls; citations resolved from file:line refs in the answer
- [x] `POST /scans/{id}/chat` restored with Layers 1-3 semantics (same response
      shape as the deleted RAG endpoint, so M5's chat panel contract doesn't churn)
- [ ] Manual QA with a real model (owner, Ollama off during dev): "where is
      certificate pinning located" + 2-3 similar Android questions, one iOS
      entitlements question, multi-source answers (semgrep+androguard; symbols+
      gitleaks) with precision intact
- [ ] Stress: obfuscated + large APK — Layer 2/3 quality and findings-context size
- [ ] **Go/no-go checkpoint** — don't proceed to M5 UI wiring until the manual QA
      holds up

## M5 — Dashboard integration
> **Status: Phases A–H COMPLETE (Aug 7, 2026); Phase I not started.**
> Plan + architecture:
> [docs/progress/M5.md](progress/M5.md). Owner decision (Phase B): the primary
> accent is the MASA **brand emerald** from `docs/icons/masa_icon_only.svg`
> (replaces the mockup's blue `steel`); the top bar uses the `masa_icon_text_whitetext`
> wordmark as an image and the icon-only mark for the empty state.
> Owner decisions at kickoff: plan-only session first, then Phase A; the
> mockup design system is re-implemented in **Tailwind v4** (CSS-first
> `@theme` tokens — the v4 replacement for a `tailwind.config.js`).

**Backend surface (Phase A — COMPLETE, 238 tests green, ruff clean):**
- [x] Migration 0004: `findings.explanation` (AI-explain cache) · `scans.ai_summary` (overview cache) · `scans.stage` (progress screen stage string)
- [x] Risk score: `analysis/risk.py::compute_risk_score` (severity-weighted, documented formula), computed in `run_scan`, stored on `Scan.risk_score`, backfilled on GET for legacy scans
- [x] `POST /api/v1/scans` — multipart upload (`.apk`/`.ipa`, zip sanity check, `MASA_MAX_UPLOAD_MB` → 413), save + `Scan(queued)` + enqueue RQ job
- [x] `GET /api/v1/scans/{id}/findings` — severity-desc order, `?severity=` filter, `?limit/offset=` (default 1000)
- [x] `POST /api/v1/scans/{id}/summary` — AI overview via M3 chat model, cached in `scans.ai_summary`
- [x] `POST /api/v1/scans/{id}/findings/{fid}/explain` — FR-8 grounded explanation, cached in `findings.explanation`
- [x] `GET /api/v1/scans/{id}/files` + `GET /files/content` — bounded tree (depth 8 / 1500 nodes, `truncated` flag; Android `sources`+`resources` roots, iOS `Payload/*.app`), traversal-guarded reads reusing `agent/tools.py` (shared `is_text_file`/`resolve_tree_root`)
- [x] Model lifecycle: `POST /api/v1/model/backends` (create custom / activate BYOK) + `DELETE` (remove; local protected)
- [x] `Scan.stage` written at each `run_scan` pipeline stage via orchestrator `on_stage` callbacks (decompiling → analyzing → secrets → done)
- [x] Static serving: FastAPI mounts `frontend/dist` + SPA fallback for non-`/api` paths
- [x] Backend tests for all of the above (mocked LLM): 238 total (was 167) — risk, insights, upload/findings/explain/summary/files API, model lifecycle, migration 0004 up+down; ruff clean

**Frontend (Tailwind v4 re-implementation, Phases B–H):**
- [x] Design system: `@theme` tokens from the mockup palette (accent re-themed to the brand emerald) + IBM Plex via `@fontsource` (no CDN), `@tailwindcss/vite`
- [x] App shell + view machine (`empty | progress | loaded` from active-scan status, active scan id in localStorage), typed API client + types + AppContext (`state/AppContext.tsx`)
- [x] Empty state: dropzone (click + drag&drop) → `POST /scans`, setup checklist derived from real health + model state, local-only footnote, backend-unreachable retry
- [x] Progress screen: poll every 2.5 s while queued/running (shell `useScanPolling`), platform-aware pipeline stage list from `Scan.stage` (done ✓ / active ● pulse / pending), indeterminate bar, elapsed timer
- [x] Top bar: brand, real Local-only indicator, model pill dropdown (backends × served models, set default), + New scan, settings gear — **Phase H wired the pill + gear**
- [x] Target bar: active scan identity + "Open a different scan" dropdown (recent scans + upload) — also mounted on the progress screen (mockup-faithful)
- [x] Overview tab: risk gauge (SVG arc), severity counts, AI summary block, top findings — all from real data
- [x] Findings tab: real findings list, severity filter chips, expandable AI explanation per finding (explain endpoint, cached)
- [x] Decompiler tab (read-only in M5): file tree API, highlight.js code viewer with flagged lines, annotation rail from findings (+ per-line explain)
- [x] Decompiler follow-ups (Aug 6): **iOS no longer shows the raw unzipped bundle** — the app-bundle walk is curated to text-readable files, with the hidden binary blobs collected into a collapsed **`Binary (Mach-O)` (n) tree entry** (each listed inline with its full path, inert/dimmed rows — `FileNode.binary` flag; `filtered_binaries` count kept in the API) and a synthetic **`analysis/` root** is generated from the persisted binary-level findings: `macho-profile.md` (architectures, PIE/canary/ARC/FairPlay with honest "not flagged" phrasing, linked dylibs), `entitlements.plist` (full carved set as JSON), `exported-symbols.txt`, `insecure-imports.txt` (import-table scanner findings). **Panes are now resizable IntelliJ-style** (drag splitters between tree/code/rail, clamped, persisted to localStorage, double-click reset, narrow screens hide the rail as before). **Risk gauge color now tracks the 0–100 score** — continuous green(0)→orange(50)→red(100) hue ramp instead of a fixed amber
- [x] Agent chat panel (Phase G): wired to `POST /scans/{id}/chat` — collapsible right dock, real welcome message (findings counts), backtick-code rendering, citations as clickable file:line chips (jump the Decompiler tab to the file), graceful 400 no-model / 409 not-analyzed / 504 timeout / network error bubbles each with Retry, Enter-to-send (Shift+Enter newline, IME-safe), web-research toggle disabled until M7. Gate: `tsc -b && vite build` green; live check — dock renders against a real scan, chat returns the designed 400 (no chat model) in ~34ms; browser click-through blocked by the recurring chrome-devtools agent outage (covered by code review, same as Phase E)
- [x] Settings modal → Model Backends tab: backend cards, base URL edit, Test, served-model chips, set default model — **Phase H (Aug 7)**: `settings/BackendsTab.tsx`, live probes, per-card enable switch
- [x] Settings modal → BYOK tab: provider list, add key, custom endpoint, remove — **Phase H (Aug 7)**: `settings/BYOKTab.tsx` (master cloud toggle batches PUTs via `updateBackends`), masked-key honesty (we only ever get `has_api_key`)
- [x] "Local-only" indicator reflects real state — off the moment a BYOK provider is enabled, not decorative — **Phase H**: derivation in `AppContext.localOnly`, flips live after every Settings mutation (verified via API smoke test: custom create → DELETE, local PUT)
- [x] Placeholders (not built in M5): Dependencies tab (M7), Report tab + Export report (M9), Smali/edit/recompile (M8), web-research/browser toggle (M7) — **Phase H** also renders the Settings → "Search & research" tab as an M7 placeholder
- [x] Settings modal shell: `settings/SettingsModal.tsx` (Escape/overlay close, scroll lock, three tabs) + `ModelPill.tsx` (served models from `health.models`, set default, local/cloud groups) — Gate: `tsc -b && vite build` green; backend surface re-verified live via API (no Ollama — unreachable state is the designed no-model UX; live connection is an owner manual test)

**Owner review follow-ups (Aug 7, 2026):**
- [x] **debuggable → critical** — `Application is debuggable (android:debuggable=true)` was high; now critical (`analysis/manifest.py`, owner call: a production app shipping debuggable is a direct debugging/tampering exposure)
- [x] **Overview shows a SECURITY score, not a risk score** — higher is better, low = red / high = green. `risk.py` gains `compute_security_score`/`security_from_risk` (security = 100 − risk); `Scan.security_score` is a derived ORM property (never stored, cannot drift); `ScanRead` exposes it; the summary prompt speaks the security score with a "higher is better" note; `RiskGauge` renamed `SecurityGauge` with inverted hue ramp (red 0 → orange 50 → green 100) + labels (Low/Medium/High/Excellent security). Verified live in compose: InsecureBankv2 risk 40 → **security 60**, debuggable now critical (1C/4H/473M/2L/43I). 242 backend tests + ruff clean, tsc/build green
- [x] **Severity re-calibration (owner picks A + C, Aug 7; B declined)** — Android curated rules: hostname-verifier + empty-trust-manager → **critical** via `severity.py::SEMGREP_OVERRIDES` (semgrep can't express critical natively); WebView JS-enabled/file-access, hardcoded-key, weak-cipher rules bumped WARNING→ERROR (→ high) in `rules/masa/android-java.yml`. iOS: `setAllowsAnyHTTPSCertificate` → **critical**, `get-task-allow` → **medium** (per-entitlement severity map; aps-environment stays low), empty usage-description strings → **low**. MASTG vendored rules untouched (owner declined the override table for now). Verified live in compose (InsecureBankv2): debuggable critical, WebView-JS + hardcoded-key high, 1C/10H/467M/2L/43I, risk 41 → **security 59** (pre-CVSS formula). 244 backend tests + ruff clean
- [x] **CVSS 4.0 scoring + dashboard follow-ups (owner picks, Aug 7)** — (a) **Scoring is now CVSS 4.0**: each severity band maps to a representative CVSS 4.0 base score (critical 9.5 / high 8.0 / medium 5.5 / low 2.0 / info 0 — band midpoints), overall **risk = round(10 × max(cvss))** — the worst finding drives the score (`risk.py::SEVERITY_CVSS`; the old 10/7/4/1 weighted-mean formula is gone). (b) **Gauge labels follow the CVSS 4.0 qualitative bands of the underlying risk** — 60/100 security → risk 40 → **Medium**, not High (owner: "60 as high security should not be high"); caption shows `CVSS 4.0 · risk n/100 · band`. InsecureBankv2 (1 critical) → risk 95 → **security 5**. (c) **Sticky dashboard tab bar** — Overview/Findings/Dependencies/Decompiler/Report stay pinned while panel content scrolls (`DashboardView`). (d) **Model pill model-search box** (filters local + cloud groups, Escape clears first) + the "No models listed (is the server running?)" copy is now **local-only** — cloud-opt backends say "No models listed — check the provider key in Settings." (e) **Scan date accuracy**: SQLite drops tzinfo on round-trip → persisted timestamps serialized naive → browsers parsed them as local time (hours off on non-UTC machines); `schemas.py::_utc_aware` attaches UTC on serialization (`created_at`/`checked_at`/`generated_at`) + `formatRelative` treats no-offset strings as UTC. Gates: backend tests updated for the CVSS numbers, ruff clean, `tsc -b && vite build` green

**Owner review follow-ups (Aug 8, 2026 — severities, model picker, suppression):**
- [x] **Critical band removed** — findings vocabulary is now **high | medium | low | info** (`base.py::SEVERITIES`, `risk.py::SEVERITY_CVSS` — critical 9.5 gone; max risk is now 80 from high 8.0). Everything that produced critical maps to high: debuggable manifest finding, `setAllowsAnyHTTPSCertificate` iOS symbol rule, semgrep TLS-bypass overrides, gitleaks direct-compromise rules. Migration **0005** rewrites existing `critical` rows → `high` and recomputes every done scan's `risk_score` under the new mapping. Frontend: `types.ts` severity, stat boxes (High/Medium/Low/**Info**), filter chips, tree dots, annotation labels, Agent dock greeting ("N high-severity"), SecurityGauge bands (risk 70–80 crimson worst → emerald at 0). 256 backend tests green, ruff clean, tsc/build green
- [x] **Top-bar model selection → two searchable dropdowns** — the single model pill is now **Provider + Model** (`components/ModelPicker.tsx` replaces `ModelPill.tsx`): provider dropdown lists every backend (+ **None (no AI)**), model dropdown lists the selected provider's served models (+ **None**). Both have a search box (Escape clears first). **None linkage**: provider → None auto-clears every active model (model shows None); model → None auto-clears the active provider. Picking a model PUTs `{model, enabled:true}` and clears other enabled-with-model backends so `pick_chat_backend` deterministically returns it. The **"Local-only" badge is gone** (owner: remove it) — `TopBar` no longer renders it and `AppContext.localOnly` was removed with it
- [x] **Finding suppression (per-finding + review toggle)** — `findings.suppressed` + `findings.suppressed_at` (migration 0005); `GET /scans/{id}/findings` gains `include_suppressed` (default hides), new `POST .../suppress` + `.../unsuppress` (both recompute `Scan.risk_score`); suppressed findings are excluded from the risk score (`compute_risk_score` skips `suppressed=True`), the AI summary, and the agent Layer-1 context. Findings tab: per-row **Suppress / Restore** button + a **"Review suppressed (n)"** toggle that swaps in the suppressed queue (dimmed rows, restore in place); the Overview gauge re-fetches the scan after a toggle so the score updates. API + `useFindings` tests cover hide/show, idempotent suppress, risk recompute (high+low → 80 → suppress high → 20), 409 not-analyzed, summary exclusion
- [x] **"Suppressed (n)" badge on the Overview tab** — a clickable pill next to the severity stat boxes showing the active scan's suppressed (false-positive) count (jumps to the Findings review toggle; renders only when n > 0)
- [x] **UI polish (owner review, Aug 8)** — (a) the gauge score text moved INSIDE the SVG as a centered `<text>` + `/100` tspan so it can never overlap the arc curve; (b) `.explain-btn`'s stray `margin-top: 8px` removed so "AI explanation" and "Suppress/Restore" buttons sit inline on the same row

**Validation (Phase I — in progress Aug 8, 2026; M5 NOT complete per owner):**
- [x] `tsc -b && vite build` green; browser verification against a real scan — **loaded state browser-verified live (Aug 7)**: page load, top bar (brand + Local-only), target bar (InsecureBankv2.apk DONE), Overview risk gauge 40, Settings modal opens with its three tabs. (Empty + progress states were browser-checked in Phases C/D.) Deeper click-throughs (Findings-tab count, ModelPill dropdown, BYOK pane) were blocked by the recurring chrome-devtools agent outage — covered by code review + build, same as Phases E/G/H
- [x] Containerized e2e — **PASSED (Aug 7)**: `docker/Dockerfile.app` gained a **frontend build stage** (SPA dist bundled at `/frontend/dist`) and `main.py`'s root route now serves the SPA when dist exists (both were blockers for serving the dashboard from FastAPI); compose up → `app.cli scan` enqueued → worker ran → `done` (risk 40, 523 findings, severity-desc API verified) → SPA + `/assets` + `/api/v1/health` (redis+db ok) all served from FastAPI on :8000. `test_root` updated for the dual root contract (240 tests green, ruff clean)
- [x] Containerized e2e re-verified after the Aug 8 changes — **PASSED (Aug 8), both platforms**: both images rebuilt; migration 0005 applied to the persisted volume (old InsecureBankv2 scan rewritten: 1 critical → 11H/467M/2L/43I, risk 95 → **80 / security 20**). Fresh Android scan (InsecureBankv2, id 16): **11H/467M/2L/43I zero critical**, risk 80 / security 20. Fresh iOS scan (iBugBazaar, id 17): **3M/1L/5I zero critical**, risk 55 / security 45. Suppression lifecycle live on both platforms (Android risk 80→55→80 across suppress-all-highs/restore; iOS 55→20→55; `include_suppressed` hide/show; `suppressed_at` stamped/cleared; agent Layer-1 context excludes suppressed — 7 findings rendered, zero leakage). Browser-verified (loadable chrome): gauge 45 inside the arc, **"Suppressed (10)" badge** on scan 16 Overview, Findings "Review suppressed (10)" — zero console errors. Note: the run left suppression state in the volume (scan 16: 10 highs suppressed) — reset available on request. Backend suites green (**256 tests**), ruff clean, tsc/build green
- [ ] Manual QA with a real model (owner, Ollama off during dev): chat, per-finding explain, overview summary — **owner manual test, not done**
- [ ] Docs: `docs/progress/M5.md` status flip to COMPLETE, this checklist checked, knowledge.md updated — **deferred per owner (Aug 7): do NOT mark M5 complete yet**

## M6 — Agent tool-calling
- [ ] M4 already ships the Layer 1-3 tools (`search_code`, `read_file`, `graph_query`,
      `graph_path`, `graph_explain`) and the bounded tool loop. M6's remaining work:
      the M5-era tools (`read_manifest()`, `get_decompiled_class(name)`,
      `get_permissions()`, `run_secrets_scan()`) built on top of the analysis engine
- [ ] Implement the M6 tool surface using **LiteLLM's normalized function-calling
      interface** (already exercised by M4's chat loop)
- [ ] **Restrict tool-calling to a documented known-good model list** (Qwen2.5/2.5-coder, Llama 3.1+) — LiteLLM standardizes the API shape, but doesn't fix models that don't reliably follow structured tool-call output; that's still a model capability limit, not a library problem
- [ ] Graceful fallback: if the selected model doesn't support tool calls, degrade to
      a context-only answer (M4 Layers 1-3 already do this in `agent/chat.py`)
- [ ] Guard against runaway tool-call loops (max iterations, timeout) — M4's loop is
      bounded at ≤3 rounds; extend per tool semantics if needed
- [ ] Test agent on a multi-step question requiring 2+ tool calls
- [ ] Test the flagship structural-question case explicitly: "where is certificate
      pinning located" should resolve via graph traversal (Layer 3), not a
      findings-context round-trip — confirm this actually happens, don't just assume
      the agent picks the right tool

## M7 — Deep research / web browsing (+ interactive browser automation)
- [ ] Add `searxng` as a 3rd Docker Compose service, JSON output format enabled (so results are parseable, not just HTML)
- [ ] Adapt **GPT Researcher**'s search→fetch→summarize→synthesize pipeline, configured to use SearXNG as its retriever, rather than building that flow from scratch
- [ ] Wire the pluggable fallback chain (Brave/DuckDuckGo/Tavily/Serper/Google PSE via API key) through the same BYOK-style key storage pattern from M3/M5
- [ ] Expose `web_search(query)` (SearXNG) as an agent tool, added to the M6 tool-calling set
- [ ] **Browser capability via `agent-browser`** (vercel-labs, Apache-2.0 — native Rust CLI +
      CDP daemon, no Playwright/Puppeteer/Node): `npm install -g agent-browser` +
      `agent-browser install` (downloads Chrome for Testing); pin the version and add a
      `docs/licenses.md` row (Apache-2.0 — clean fit, no GPL/LGPL constraint, but still
      invoked as a subprocess like the other CLIs)
- [ ] Deployment decision: browser daemon + Chrome **host-side** like Ollama/LM Studio
      (keeps the app image lean — Chrome for Testing is ~150MB+) vs. in-image/extra
      container; document the choice here + in the tech stack doc
- [ ] Wrap browser agent tools: `browser_open` · `browser_read` (agent-friendly
      markdown/llms.txt extraction, no Chrome — replaces the hand-rolled `web_fetch`) ·
      `browser_snapshot` (accessibility tree → compact refs `@e1`, never raw HTML) ·
      `browser_click`/`fill`/`type` · `browser_screenshot` · `browser_batch`
      (multi-command single invocation, avoids per-command process startup)
- [ ] Token + safety discipline: agent consumes snapshot refs / `read` output only
      (~90%+ context savings vs raw HTML); bound every turn (`--max-output`,
      `--allowed-domains`, fixed snapshot scope, session close/teardown, max tool rounds)
- [ ] Confirm the pipeline stays **bounded** even using GPT Researcher's implementation
      (fixed source count, e.g. 5) — deliberately smaller in scope than its full
      autonomous-research feature set for v1
- [ ] Gate web research + browser automation behind the same explicit per-scan opt-in —
      never triggered silently by the agent
- [ ] Update the "Local-only" UI indicator to change state the moment web research/browser
      automation is enabled, and make the distinction clear in-copy: SearXNG and the
      browser both mean traffic leaves the machine, unlike local LLM inference
- [ ] Test the flagship use case: given a detected third-party library + version, agent
      researches whether it has known CVEs — search → read → snapshot/click through the
      advisory page → synthesize with source links
- [ ] Test a MASVS/MASTG reference lookup query end-to-end (a JS-rendered docs page
      exercises the browser path specifically)

## M8 — Edit & recompile
- [ ] Wire apktool's disassemble (baksmali) output into the file tree as the "Smali" view alongside jadx's "Java" view for the same file
- [ ] Restrict edit capability (manual or agent) to Smali + resource/manifest files only — Java view stays read-only in the actual implementation, not just the mockup
- [ ] Agent tool: `propose_smali_edit(file, instruction)` — returns a diff for the tester to review before it's applied, don't auto-apply silently
- [ ] Build the rebuild pipeline: apply accepted edits → apktool rebuild → zipalign → sign with an auto-generated local test keystore (`keytool` + `apksigner`)
- [ ] Pipeline must fail loudly with a specific error (not a silently broken APK) on rebuild failure — test against at least one APK known to be awkward for apktool (resource clashes, edge-case bytecode)
- [ ] Persistent, un-dismissable "resigned test build" label on every recompiled artifact — in the UI and embedded in the output filename
- [ ] iOS: Info.plist/entitlement/resource edit + resign via `ldid` — explicitly no compiled-logic editing path
- [ ] End-to-end test: agent-proposed SSL-pinning bypass edit → review diff → recompile → confirm the resulting APK actually installs and runs

## M9 — Report generation
- [ ] AI-assisted draft report generator: findings + chat insights → structured markdown
- [ ] Executive summary generation (aggregate risk narrative)
- [ ] MASVS/MASTG tags surfaced in report (from M1 lookup table)
- [ ] Markdown export
- [ ] PDF export (render markdown → PDF, e.g. via WeasyPrint)
- [ ] Manual review pass: does the AI-drafted report read like something a human pentester would ship?
- [ ] If web research (M7) was used during the engagement, cite those sources in the report distinctly from local-code-derived findings
- [ ] If a recompiled test build (M8) was produced, note it in the report distinctly from the original analyzed artifact

## M10 — Packaging & release
- [ ] Finalize `docker-compose.yml` (3 services: app, redis, searxng) — confirm truly single-command install on a clean machine
- [ ] README: setup, Ollama/LM Studio prerequisites (must be running on host before `docker-compose up`), hardware/model recommendations, screenshots
- [ ] Apache-2.0 license file
- [ ] Naming collision check ("MASA" vs existing GitHub/npm/PyPI projects)
- [ ] Strip remaining mockup placeholder branding/sample data
- [ ] Public GitHub repo, initial release tag
- [ ] Post-launch: monitor for the v1 success metric (stars/adoption), gather issue-tracker feedback for v1.1 scoping

---

## Deferred / v1.1 candidates (unchanged from v1, not blocking v1)
- [ ] MASVS/MASTG reference lookups through the agent layer (M7 web research covers
      current guidance; an embedded corpus was removed with the RAG pipeline)
- [ ] "Lite mode" model recommendation for low-spec hardware (Cookbook-style)
- [ ] Multi-user / auth / team features (would also mean revisiting SQLite → Postgres)
- [ ] Hosted cloud tier
- [ ] Dynamic analysis (Frida, jailbroken device workflows)
- [ ] Malware/repackaging diff against official store originals
- [ ] WebSocket-based real-time updates (only if polling proves genuinely insufficient in practice)
