# M8 — Edit & Recompile (Android): Kickoff Plan Spec

**Status:** DRAFT — interview complete (Aug 10, 2026), decisions locked, no code written yet.
**Spec owner:** Buffy (interviewer) · **Product owner:** Anang Suwasto.
**Milestone reference:** M8 in `docs/masa-tasks.md`, PRD §5.1 "Edit & recompile" + FR-9c…FR-9h, techstack "Edit & recompile" rows.
**Short name for this spec:** `m8-kickoff`.
**Milestone tracker:** [`docs/progress/M8.md`](progress/M8.md) — the phase-checklist conversion of this spec (A–E) with the task-list mapping.

---

## 1. Goal

M8 turns the Decompiler tab's placeholders into a working **edit → review → rebuild → resign** loop for **Android only**: a Smali view (apktool) alongside the read-only jadx Java view, manual and agent-proposed edits stored as reviewable diffs, and a "Recompile app" pipeline (apktool rebuild → zipalign → sign with an auto-generated local test keystore) that produces a clearly-labeled **resigned test build** APK the tester can download.

iOS edit/recompile is **deferred to v1.1** (owner decision, see §3 and §4).

---

## 2. What exists today (context the plan builds on)

- **Decompiler tab** (`frontend/src/components/panels/DecompilerPanel.tsx`) already renders the mockup toolbar: a Java/Smali `view-toggle` (Smali chip `disabled` with title "Smali view + edit/recompile land in M8") and an "Edit & recompile" button (`disabled`), plus a `.view-hint` box. Resizable IntelliJ-style panes, `FileTree` / `CodeViewer` / `AnnotationRail`.
- **File tree backend** (`backend/app/analysis/tree.py`): bounded walk (`MAX_DEPTH 8`, `MAX_NODES_PER_ROOT 1500`), Android roots `sources` (jadx) + `resources`; traversal-guarded content reads; `_LANGUAGES` map (note: **hljs has no smali grammar** — the comment already calls this out); iOS curated walk + synthetic `analysis` root (that platform machinery stays untouched/read-only).
- **Subprocess-wrapper pattern** to mirror: `analysis/jadx.py`, `analysis/gitleaks.py`, `analysis/semgrep.py` (bounded runs, `ToolError`-style clean errors, never raw `subprocess` in callers). GPL/LGPL tools are **subprocess-only, never imported** — apktool (Apache-2.0) and build-tools (Apache-2.0) are permissive, so they are still invoked as subprocesses by convention.
- **RQ jobs** (`workers/jobs.py`): `run_scan` → chained `build_graph_scan` precedent — a chained/post-hoc background job with filesystem-derived state is an established pattern.
- **Agent layer** (`agent/tools.py` + `chat.py`): `TOOL_SCHEMAS`, `schemas_for_platform` platform filter (`_ANDROID_ONLY_TOOLS`), M7 two-gate web pattern (`web_tools_allowed`), tool-loop with `tool_runs` traces + SSE streaming (`chat/stream`), dev-only fake model (`MASA_FAKE_MODEL=1`) that runs the REAL tool loop for demo/e2e.
- **Docker image** (`docker/Dockerfile.app`): eclipse-temurin:17 JRE already present → **`keytool` ships today** (licenses.md confirms). `apktool` + `zipalign`/`apksigner` are **planned for M8 Phase A, not yet installed**; `ldid` is **deferred to v1.1** (not an M8 item). Current image ~389MB content vs the 350–450MB gate.
- **Mockups** (`docs/masa-dashboard-{loaded,empty,progress}.html`) sketch the full intended UX: Java/Smali chips, `✎ Edit` + `✨ Ask agent to edit` buttons, view-hints ("Read-only — jadx output is for understanding code, not rebuilding it. Switch to **Smali**…" / "Editable — smali is what actually gets rebuilt into the APK…"), the recompile modal with the **resigned test build** warning and pipeline steps (Apply smali edits → Rebuild with apktool → Sign with test keystore → Download).
- **License posture**: `docs/licenses.md` updated at the M8 kickoff (Aug 10, 2026) — ldid (GPL-family, iOS resign) deferred to v1.1 with the iOS cut; apktool + build-tools rows land with Phase A.

---

## 3. Owner decisions (locked during the Aug 10 interview)

| # | Decision | Choice | Notes |
|---|---|---|---|
| D1 | When apktool disassembles | **On-demand, first Smali view** | A decode job runs when the user first switches to the Smali view (or starts an edit); UI shows a spinner + retry. Scan pipeline stays untouched (no per-scan time/disk cost). Decode is cached per scan. |
| D2 | Edit storage model | **Diffs in DB, applied at rebuild** | DB rows are the source of truth (original + new content + unified diff); the on-disk apktool tree stays the pristine baseline; the rebuild job overlays applied edits onto a fresh copy. Reproducible, revert-safe, attribution-friendly. |
| D3 | Platform scope | **Android only; iOS deferred to v1.1** | See D5. Architecture still leaves a clean seam for iOS later. |
| D4 | Tool provisioning | **Bundle all in the image; bump the size gate** | apktool jar + Android build-tools (zipalign/apksigner) installed at build time. Owner explicitly accepts the image growing past 450MB if needed. `keytool` already present via the JRE. |
| D5 | iOS edit/recompile | **Deferred to v1.1** | Rationale (owner + research): iOS *compiled-logic* editing was already a v1 non-goal; and even plist/entitlement editing + `ldid -S` resign produces an IPA that **only installs on jailbroken devices (AppSync Unified)** — stock iOS rejects it, and the simulator won't run it (wrong platform slice). The honest iOS deliverable would be a handoff artifact for the user's own Sideloadly/Apple-ID signing, which the owner judged not worth M8 scope. iOS keeps today's read-only bundle view. |
| D6 | Agent edit surface | **Dock chat tool AND inline "Ask agent to edit" bar** (mockup-faithful) | The new `propose_smali_edit` tool is offered in the dock chat; the decompiler toolbar also gets the mockup's inline bar that sends the instruction with the currently-open file pre-set. |
| D7 | Diff review | **Unified diff, file-by-file apply** | One agent proposal may touch several files; the review panel shows a unified diff per file with Apply/Reject per file. |
| D8 | Edit/build history | **Full history** | Per-file "Restore original", plus a per-scan "Edits & builds" list: every build row (status, timestamp, edits included), artifact re-download for any prior build. |
| D9 | Android e2e validation | **Contract-style only** | No emulator/device in the automated e2e. Assert pipeline success + artifact integrity: `apksigner verify` passes, zipalign correct, signature **fingerprint differs from the original APK**, filename carries the resigned label. "Installs and runs on a real device" is out of automated scope. |
| D10 | Test keystore lifecycle | **One keystore per MASA install** | Created on first rebuild in `data_dir`, reused for every scan/build (stable test signature; standard apktool practice). |

---

## 4. Scope

### In scope (M8 v1 — Android)

- On-demand **apktool decode** of an analyzed APK (RQ job + status), cached per scan; `smali/`, `smali_classes2…N/`, `res/`, decoded `AndroidManifest.xml` exposed through the file tree as **new editable roots**.
- **Java ⇄ Smali view toggle** in the Decompiler tab (mockup-faithful), mapping the open jadx `sources/…/*.java` file to its apktool `smali{,_classesN}/…/*.smali` sibling (multidex-aware search), and back.
- **Manual editing** of `smali*/**/*.smali`, `res/**` (decoded XML/values), and `AndroidManifest.xml` only. **Everything else stays read-only** (the entire jadx `sources` root, `original/`, `unknown/`, binaries). Enforced **server-side** (editability predicate), not just in the UI.
- **Agent tool `propose_smali_edit`** (Android-only, gated on decode-ready) → returns a stored **proposed** edit + unified diff for human review. Apply/Reject per file in the UI (D7). Agent proposals may span multiple files.
- **"Recompile app" pipeline** (RQ job): overlay applied edits on a fresh copy of the decoded tree → `apktool b` → `zipalign -f` → `apksigner sign` with the install-scoped test keystore (D10) → artifact saved under `data_dir/artifacts/<scan_id>/` with a **resigned-test-build label embedded in the filename**.
- **Fail-loudly rebuild** semantics: each stage maps to a specific error; a post-build sanity check (`apksigner verify`) catches silent breakage; no artifact is produced on failure. Tested against **at least one APK known to be awkward for apktool**.
- **Persistent, un-dismissable "resigned test build" warning**: in the recompile modal, on the artifact download, and in the filename (task-list requirement).
- **Full edit/build history** UI (D8): per-file revert + build list + re-download any prior artifact.
- **Docker image**: bundle apktool + zipalign + apksigner (D4); licenses.md + techstack + tasks + progress docs updated; image-size gate re-measured (bump approved).

### Out of scope / deferred (explicitly)

- **iOS edits + `ldid` resign** → v1.1 (D5). iOS bundle view stays read-only. `ldid` NOT installed (the licenses.md row stays "not yet installed").
- Editing the jadx **Java** view (one-way decompiler — the PRD's explicit non-goal; the mockup's read-only hint is now real).
- Multi-user/auth, dynamic instrumentation, install-and-run device e2e (D9).

---

## 5. Architecture

### 5.1 On-demand apktool decode

- New `backend/app/analysis/apktool.py` (mirrors `jadx.py`/`gitleaks.py`): wraps `java -jar apktool.jar d -f -o <work>/<scan>/apktool <apk>`; bounded timeout; parses rc + stderr into clean errors; no callers touch raw subprocess.
- **Trigger:** `POST /scans/{id}/smali` enqueues an RQ job (`run_apktool_decode`) — the only entry point. Status via `GET /scans/{id}/smali-status` (or a field on the scan read) reporting `not_started | queued | decoding | ready | failed{error}`.
- **State:** filesystem-derived like the graph (presence of `<work>/<scan>/apktool/AndroidManifest.xml` = ready) plus a status column for in-flight states (see §5.2).
- **Caching:** one decode per scan; no re-decode in v1.
- **Failure:** decode-failed → Smali chip disabled with the specific reason surfaced in the UI ("apktool could not decode this APK — <stderr excerpt>"), toggle-able retry.

### 5.2 Schema (migration 0009)

- `scans.apktool_status` — `not_started | queued | decoding | ready | failed` (+ optional `apktool_error` text column for the specific reason).
- **`edits`** table:
  - `id`, `scan_id` (FK), `file_path` (apktool-root-relative, e.g. `smali/com/app/AuthManager.smali`, `res/values/strings.xml`, `AndroidManifest.xml`), `original_content` (Text, full baseline), `new_content` (Text, full edited), `unified_diff` (Text, generated), `source` (`manual | agent`), `instruction` (nullable — the agent's natural-language ask, for attribution), `status` (`proposed | applied | rejected | reverted`), `build_id` (nullable FK — which build consumed it), `created_at`, `applied_at`.
  - **Stacking:** a second edit to the same file baselines on the *effective* content of the prior applied edit; reverting the newest pops to the previous state.
- **`builds`** table:
  - `id`, `scan_id` (FK), `status` (`queued | running | done | failed`), `stage` (`applying | rebuilding | zipping | signing | done`), `error` (Text), `edits_json` (list of applied edit ids at snapshot time), `artifact_name`, `artifact_path`, `artifact_sha256`, `created_at`, `finished_at`.
- One **rebuild at a time per scan** (409 on concurrent `POST /rebuild`); the build snapshots applied edits at job start so edits accepted mid-build never mutate the build tree.

### 5.3 Editability predicate + effective content

- `backend/app/analysis/editable.py` (or a method on the apktool module): `can_edit(scan, path)` — true only for paths under `smali*/`, `res/`, and the decoded `AndroidManifest.xml` (never under jadx `sources/` or the iOS bundle). Enforced in the edit-create API, the rebuild apply step, and (defensively) the agent tool.
- **Viewer content** (`GET /scans/{id}/files/content` or the smali view read): effective content = baseline file from the apktool tree with applied edits overlaid (the DB row's `new_content` for the newest applied edit on that path). Restore-original = mark `reverted`; viewer returns the baseline.
- Content-size cap on `new_content` (e.g. 200 KB) with a clean 413-style rejection.

### 5.4 Rebuild pipeline (`run_rebuild` RQ job)

Stages (each a bounded subprocess call, each failure → `builds.stage` + `builds.error` with the stderr excerpt, `status=failed`, **no artifact written**):

1. **Applying** — copy the decoded apktool tree to a per-build working dir; overlay all `applied` edits (write `new_content` over the copied paths).
2. **Rebuilding** — `apktool b <build-dir> -o <unsigned.apk>` (pin `--use-aapt2` as apktool's default; log warnings).
3. **Zipping** — `zipalign -f 4 <unsigned> <aligned.apk>` (**before** signing — v2+ schemes preserve alignment).
4. **Signing** — ensure the install-scoped keystore exists (`keytool -genkeypair -keystore <data_dir>/masa-test.jks -alias masa -keyalg RSA -keysize 2048 -validity 10000`, generated once, plaintext storepass in `data_dir` at `0600` per the BYOK-key precedent), then `apksigner sign --ks … --out <final.apk> <aligned.apk>` (v1/v2/v3 defaults).
5. **Sanity** — `apksigner verify --print-certs <final.apk>` must succeed, else `failed` (never a silently broken APK).
6. **Done** — record `artifact_name/path/sha256`; artifact named `{original}-resigned-test-{scan_id}-b{build_n}.apk`.

### 5.5 Agent tool `propose_smali_edit`

- **Schema:** `propose_smali_edit(file, instruction, new_content)` — `file` (apktool-relative, defaults to the currently-open file passed by the client), `instruction` (recorded for attribution), `new_content` (the full edited file, which the model composes after reading the current content via `read_file`). **Design checkpoint:** the `(file, instruction)` task-list signature with `new_content` added is a deliberate choice so the LLM produces byte-exact output the tool can diff; flagged for confirmation at Phase D kickoff.
- **Behavior:** validates Android platform + decode-ready + editable path + size cap → creates an `edits` row with `status=proposed` and a generated unified diff → returns `{edit_id, file, instruction, diff}`. Never auto-applies (PRD FR-9e: diff visible before kept).
- **Gating:** added to `_ANDROID_ONLY_TOOLS`; also gated on `apktool_status == ready` (else a clean "Smali not decoded yet — open the Smali view first" error). Offered in `schemas_for_platform` like `get_decompiled_class`.
- Apply/Reject/Revert are **API calls, not agent tools** — the human owns application (D7).
- Fake model (M6.1) gains an edit-demo script (read_file → propose_smali_edit → cited diff) so the flagship flow demos with zero Ollama, matching the M7 precedent.

### 5.6 API surface (all under `/api/v1`)

| Endpoint | Purpose |
|---|---|
| `POST /scans/{id}/smali` | Enqueue apktool decode (202; 409 if already decoding/ready) |
| `GET /scans/{id}/smali-status` | `{status, error}` (or folded into the scan read) |
| `GET /scans/{id}/edits` | All edit rows (file, source, status, instruction, timestamps) |
| `POST /scans/{id}/edits` | Create a **manual** edit `{file_path, content}` (editability + decode guards) |
| `GET /scans/{id}/edits/{eid}/diff` | Unified diff text |
| `POST /scans/{id}/edits/{eid}/apply` / `reject` / `revert` | State transitions (apply stamps `build_id` when consumed) |
| `POST /scans/{id}/rebuild` | Enqueue rebuild (409 while a build is running; 400 if decode not ready / no applied edits — TBD whether zero-edit rebuilds are allowed) |
| `GET /scans/{id}/builds` | Build history (status, stage, error, artifact, sha256) |
| `GET /scans/{id}/builds/{bid}/download` | Artifact download (`Content-Disposition` with the labeled name) |
| `GET /scans/{id}/files` | Existing endpoint gains the apktool roots once decoded |

### 5.7 Frontend

- **Decompiler tab** (DecompilerPanel):
  - Smali chip goes live: `not_started → click → POST /smali + poll smali-status` (spinner in-chip; `failed` → disabled with reason + retry).
  - Java→Smali path mapping for the open file (multidex-aware); smali→Java back.
  - **Edit mode** only for editable paths: read-only highlighted `CodeViewer` swaps to a plaintext editor (textarea + line numbers — no new editor dependency; hljs lacks smali anyway) with dirty indicator + Ctrl/Cmd+S → `POST /edits`; non-editable paths keep the mockup's read-only hint and disabled affordances.
  - **"Ask agent to edit" inline bar** (mockup-faithful): appears under the toolbar when an editable file is open + a chat model is connected; sends the instruction into the agent flow with `file` pre-set; the returned proposal opens the **diff review panel**.
  - **Diff review panel**: unified diff per file with Apply/Reject (multi-file proposals reviewed file-by-file, D7).
  - **"Edits & builds" section** (full history, D8): applied/reverted edits per file + build list with per-build stage/status/error + **re-download any prior artifact**.
  - **Recompile modal** (mockup-faithful): persistent resigned-test-build warning (never dismissable — the requirement), pipeline steps with live stage polling, done → Download, failed → specific error + log excerpt.
  - Resigned-build labeling: artifact filename + modal warning + download page header (a small "rebuilt" tag on the scan identity is optional polish).

### 5.8 Docker / tooling (Phase A)

- **apktool**: official release jar pinned (2.x latest at implementation time) + wrapper script; JRE already in the image.
- **zipalign + apksigner**: Android SDK build-tools direct download, pinned (≥30.0.0 for v3.1 signing), Apache-2.0 — add licenses.md rows (apktool Apache-2.0, build-tools Apache-2.0; keytool note already present).
- **ldid**: NOT installed (D5).
- Image size re-measured at gate; **bump past 450MB approved** (D4).

---

## 6. Edge cases & failure modes (design must handle)

1. **apktool decode failure** (some APKs can't decode — resource quirks): specific error, toggle disabled, retry.
2. **apktool rebuild failure / silent-warning builds**: stage-specific errors + `apksigner verify` sanity gate; the **awkward-APK test** pins at least one APK known to trip apktool (candidate at Phase E kickoff: an app with AAPT2-strict resources, low `minSdk` smali idioms, or resource-clash structures) — the fail-loudly requirement is a first-class test, not a wish.
3. **Multidex**: class → `smali`, `smali_classes2…N` search; duplicate relative paths resolved first-found (documented).
4. **jadx's own fallback `.smali`** files in `sources/` (when Java decompilation fails): remain read-only; only the **apktool** smali is editable — the UI must not confuse the two.
5. **Obfuscated apps**: smali is obfuscated; edits still apply (the point of the feature). No extra work, noted in docs.
6. **Edit staleness / rebuild races**: edits are DB rows; the build snapshots at start; concurrent `POST /rebuild` → 409.
7. **Same-file edit stacking**: baseline = prior effective content; revert pops to previous; diff regenerated.
8. **Oversized edits**: content cap with a clean error.
9. **Zero-edit rebuild**: allow (sanity check) or reject — decide at Phase C (default: allow, harmless).
10. **Artifact accumulation**: full history means disk growth — acceptable for v1; a configurable cap is a later knob.
11. **Keystore security**: plaintext storepass in `data_dir` `0600` (matches the BYOK plaintext-key precedent, documented honestly).

---

## 7. Validation plan

- **Unit tests (mocked subprocess, no network)**:
  - apktool wrapper: argv construction, rc/stderr → clean errors, timeout.
  - editability predicate (smali/res/manifest yes; jadx sources/iOS/no-scan no).
  - edit CRUD + unified-diff generation + stacking + revert + status transitions.
  - `propose_smali_edit`: platform gating, decode-ready gating, size cap, proposed-not-applied, diff shape; fake-model flagship (read → propose → diff → apply).
  - rebuild job: apply-overlay, stage order (**zipalign before apksigner** asserted), keystore reuse (generated once), naming, failure paths (each stage), `apksigner verify` sanity gate.
  - migration 0009 up/down.
  - API: decode trigger/status/409s, edits CRUD, rebuild enqueue/409, builds list/download filename.
- **Integration / containerized e2e** (contract-style, D9 — no emulator):
  - Decode **InsecureBankv2.apk** via the real apktool in the container → Smali roots present.
  - Manual edit (e.g. `AndroidManifest.xml` debuggable flag or a `strings.xml` value) + agent-proposed edit via the fake model → apply → rebuild → **`apksigner verify` passes, zipalign verified, signature fingerprint differs from the original APK**, filename carries `-resigned-test-`.
  - **Awkward-APK fail-loudly test**: rebuild fails with a specific stage error, no artifact, build row `failed`.
  - iOS scan: Smali/Edit/Recompile affordances absent/disabled (regression — bundle stays read-only).
- **Gates:** backend pytest + ruff; `tsc -b` + `vite build`; image rebuild + size measurement (bump recorded); browser DOM check of the live toggle/edit/recompile UI (chrome-devtools permitting — the recurring outage is covered by code review, per project precedent).
- **Docs:** `docs/progress/M8.md` plan+progress, tasks.md checklist, licenses.md rows, techstack edit rows, knowledge.md; **real-model agent QA** stays an owner post-completion checkpoint (consistent with M4–M7).

---

## 8. Phase breakdown

| Phase | Content |
|---|---|
| **A — Toolchain + decode** | Dockerfile (apktool, build-tools, wrapper scripts), licenses rows, `analysis/apktool.py` wrapper, migration 0009 (status columns), `run_apktool_decode` job, smali-status + trigger API, Smali chip live with spinner/retry/failed state. |
| **B — Edits model + Smali view** | `edits` table + CRUD + diff + revert + stacking, editability predicate, apktool roots in `list_tree`, effective-content reads, Java⇄Smali mapping (multidex), edit-mode textarea, read-only enforcement everywhere. |
| **C — Rebuild pipeline + UI** | `builds` table, `run_rebuild` job (apply → apktool b → zipalign → sign → verify), install-scoped keystore, artifact naming/labeling, download API, recompile modal (warning + live stages + download + error), "Edits & builds" full-history panel. |
| **D — Agent edit flow** | `propose_smali_edit` tool + gating (platform + decode-ready) + fake-model demo, diff review panel (file-by-file apply/reject), inline "Ask agent to edit" bar, multi-file proposal support. |
| **E — Hardening + e2e** | Awkward-APK fail-loudly test, concurrency/edge coverage, contract-style container e2e (D9), docs + tasks + knowledge.md updates, image size re-measurement. |

---

## 9. Open items to resolve at kickoff (non-blocking for the plan)

1. Pin exact **apktool** version and **build-tools** version (implementation-time).
2. Choose the **awkward APK** candidate for the fail-loudly test.
3. Confirm the `propose_smali_edit(file, instruction, new_content)` contract vs instruction-only (5.5 design checkpoint).
4. Whether zero-edit rebuilds are allowed (default: yes).
5. Whether the decode is triggered by the toggle click only, or also auto-starts when the Decompiler tab opens (default: toggle-click only, per D1).
6. Whether "Edit & recompile" appears on the Decompiler toolbar for iOS scans as a disabled/hidden affordance (default: hidden — iOS is out of scope, D5).
