# Product Requirements Document: MASA (Mobile Application Security Assistant)

**AI-native mobile security testing workbench**
Version 0.1 (Draft) · July 22, 2026

---

## 1. Summary

MASA is a self-hosted, open-source dashboard for mobile application security testing (Android + iOS) with a built-in AI copilot. It combines static analysis of APK/IPA files with a local-LLM-powered reasoning layer — inspired by Odysseus's pluggable model-backend pattern (Ollama, LM Studio, and OpenAI-compatible endpoints) — so a pentester can not only see raw findings but ask questions directly against the decompiled codebase and get grounded, cited answers.

Unlike MobSF, MASA's analysis engine is built from scratch, and the AI layer is a first-class citizen of the product rather than a bolt-on: the flagship capability is **chat-with-decompiled-code**, a RAG-backed conversational interface over the actual decompiled source of the app under test.

## 2. Problem Statement

Static analysis tools produce large volumes of findings but very little interpretation. Pentesters spend disproportionate time manually reading decompiled Java/Smali/Kotlin or Objective-C/Swift output to answer questions like "where else does this token get used?" or "is this finding actually exploitable here?" Existing tools (MobSF and similar) don't let a tester interrogate the codebase in natural language, and cloud AI tools are a non-starter for confidential client APKs. MASA closes that gap locally.

## 3. Goals & Success Metrics

| Goal | Metric (v1) |
|---|---|
| Ship a credible open-source alternative to closed/cloud AI-assisted mobile AppSec tooling | GitHub stars / adoption — primary success signal for v1 |
| Prove the chat-with-code concept works well enough to be genuinely useful, not a gimmick | Qualitative: testers can get a correct, source-grounded answer to an ad-hoc question in under 3 chat turns |
| Keep the tool fully local-first | Zero required network calls to third parties for a scan to complete end-to-end |

Out of scope for v1 success criteria: revenue, contributor count, enterprise adoption — these may become goals in later versions but are not what v1 is optimized for.

## 4. Target User

Primary persona: an independent or small-team mobile pentester / AppSec engineer who:
- Wants an open-source tool they can self-host and audit
- Values client confidentiality (local LLM inference, nothing leaves their machine)
- Is comfortable running Docker
- Wants to move faster through the "read decompiled code and figure out what matters" phase of an assessment

Secondary: security researchers and students who want a free, local platform to learn mobile AppSec against real or intentionally vulnerable apps.

## 5. Scope

### 5.1 In Scope (v1)

**Platforms analyzed:** Android (APK) and iOS (IPA), from day one.

**Android analysis:**
- Decompilation via jadx (Java/Kotlin readable source) and apktool (resources/manifest)
- Manifest parsing: permissions, exported components, intent filters
- String/secret scanning across decompiled output (see tech stack doc for tool choice)
- Certificate/signature inspection
- Network security config parsing
- Basic manifest-vs-behavior mismatch detection

**iOS analysis (static only — no jailbreak, no dynamic instrumentation in v1):**
- IPA unpacking, Info.plist and entitlements parsing
- Mach-O binary inspection (via otool/class-dump-equivalent tooling) for ATS config, binary protections (PIE, stack canary, ARC), and exported symbols
- String/secret scanning across binary and bundled resources
- Static-only is an explicit v1 constraint — no Frida/dynamic hooking, no jailbroken-device workflows

**AI integration layer:**
- Pluggable local model backend abstraction supporting Ollama and LM Studio (OpenAI-compatible `/v1/chat/completions` interface), matching the Odysseus pattern, so any locally-served model can be swapped in without code changes
- **Chat-with-decompiled-code (flagship feature):** RAG pipeline that chunks and embeds decompiled source per scan, retrieves relevant code on demand, and answers natural-language questions with citations back to file/line
- Per-finding "explain this" AI annotation (plain-language explanation + fix guidance)
- Tool-calling agent loop giving the LLM callable tools: read manifest, get decompiled class, search strings, get permissions, run secrets scan
- **Deep research / web browsing (Odysseus pattern):** self-hosted SearXNG as the default search backend, with an optional pluggable fallback chain (Brave, DuckDuckGo, Tavily, Serper, Google PSE) via API keys. Powers a multi-step research flow — search → fetch top sources → summarize each → synthesize — surfaced as an agent capability the tester can invoke for things like CVE lookups on a detected library version, checking current MASVS/MASTG guidance, or researching an unfamiliar SDK/endpoint found in the app. Off by default per scan; the agent should only browse when the tester enables it or explicitly asks a question that needs it.

**Edit & recompile:**
- **Android:** the decompiler view supports a Java (jadx, read-only) and a Smali (apktool, editable) view per file. Edits — made by hand or requested from the agent in natural language ("bypass this SSL pinning check for testing") — are applied at the smali level, since that's the only representation that can actually be rebuilt. Resource and manifest files (strings.xml, AndroidManifest.xml, network config) are directly editable without a smali detour. "Recompile app" runs the full pipeline: apply edits → rebuild with apktool → zipalign → sign with a locally generated test keystore → produce a downloadable APK.
- **iOS:** recompile scope is intentionally narrow — Info.plist, entitlements, and resource edits, resigned ad-hoc for sideload testing. Editing/recompiling actual binary logic is out of scope for v1 (see Non-Goals).
- Every rebuilt APK/IPA is clearly labeled as a **resigned test build** — different signature from the original, not intended for distribution or as an update to the original install. This is standard, well-established mobile pentest practice (the same approach objection/apktool-based workflows use for things like disabling SSL pinning or root detection during authorized testing), not a novel capability.

**Dashboard (per the earlier mockup, renamed to MASA):**
- Scan queue (upload, status tracking)
- Overview tab: risk score, severity breakdown, AI-generated scan summary
- Findings tab: full findings list with expandable AI explanations
- Decompiler tab: code viewer with AI margin annotations
- Report tab: AI-assisted draft report, exportable

**Deployment (v1):**
- Single local install via Docker Compose
- Single-user, no authentication/multi-tenancy required for v1
- No cloud-hosted tier in v1

**Licensing:**
- MIT (revised from the original AGPL-3.0 decision) — maximizes adoption and self-hosting for a single-user tool; the GPL/LGPL-licensed tools in the stack (Semgrep, ldid) are always invoked as subprocesses, never imported as libraries, which keeps the MIT license clean

### 5.2 Explicitly Out of Scope (v1)

- Multi-user accounts, roles, or team collaboration features
- Hosted/cloud-managed version
- Dynamic analysis / instrumentation (Frida hooks, jailbroken-device testing, runtime traffic interception)
- Automated exploit generation
- Malware/repackaging diffing against Play Store or App Store originals
- Cloud LLM integration as anything more than an optional, clearly-labeled opt-in (OpenRouter etc.) — local-first is the default and the headline positioning
- **iOS binary logic patching/recompilation.** Editing compiled Objective-C/Swift behavior and rebuilding it is not feasible without Xcode and the original project — iOS edit/recompile in v1 is resources/plist/entitlements only.
- **Editing jadx's Java view and expecting it to recompile.** There is no path from edited decompiled Java back to working bytecode — this is why the Smali view exists as a separate, explicitly-editable representation.

These are reasonable candidates for a v2+ roadmap but should not block v1 shipping.

## 6. Functional Requirements

### 6.1 Static Analysis Engine
- FR-1: System must accept APK or IPA upload and produce structured JSON findings without relying on MobSF.
- FR-2: System must decompile Android apps via jadx/apktool and expose per-class source to downstream consumers (findings UI, RAG pipeline).
- FR-3: System must statically unpack and parse IPA structure (Info.plist, entitlements, Mach-O headers) without requiring a jailbroken device.
- FR-4: Each finding must include: title, severity, file/line reference (where applicable), and a machine-readable category (mappable to MASVS/MASTG where relevant).

### 6.2 AI / RAG Layer
- FR-5: System must support at least two interchangeable local LLM backends (Ollama, LM Studio) via a single abstraction with no code change required to switch.
- FR-6: System must chunk and embed decompiled source per scan and store embeddings locally (e.g., Chroma/SQLite-VSS).
- FR-7: The chat interface must answer questions grounded in the actual scan's decompiled code and cite the specific file/class/line supporting its answer.
- FR-8: Each finding must support an on-demand "explain" action that produces a plain-language explanation plus a suggested fix.
- FR-9: The AI layer must be able to call defined tools (manifest reader, class fetcher, string search, permission lister, secrets scanner) rather than relying on one large unstructured prompt.
- FR-9a: The agent must support a bounded web research flow (search → fetch → summarize → synthesize) using a self-hosted SearXNG instance by default, with optional fallback to pluggable search providers if a key is configured.
- FR-9b: Web research must be an explicit, per-scan opt-in — not silently triggered — and the dashboard must indicate when a query is about to leave the local machine, consistent with the local-only indicator already in the UI.

### 6.3 Edit & Recompile
- FR-9c: The decompiler view must offer a Java (read-only) and Smali (editable) toggle for `.java`-sourced files; edits must only be possible in the Smali view.
- FR-9d: Resource/manifest/XML files must be directly editable without requiring a Smali detour.
- FR-9e: The agent must be able to apply a natural-language-requested edit to the currently open Smali or resource file, with the resulting diff visible to the tester before it's kept.
- FR-9f: "Recompile app" must run apply-edits → rebuild (apktool) → zipalign → sign-with-local-test-keystore as a visible pipeline, and produce a downloadable, resigned build.
- FR-9g: The UI must clearly label recompiled output as a resigned test build, distinct from the original app's signature, every time it's produced — not just in documentation.
- FR-9h: iOS recompile must be limited to Info.plist/entitlements/resource edits; the UI must not offer a Smali-equivalent "edit compiled logic" path for iOS in v1.

### 6.4 Dashboard
- FR-10: Dashboard must show scan status (queued/running/done) per uploaded app.
- FR-11: Overview tab must show an aggregate risk score and severity breakdown.
- FR-12: Findings tab must let a user expand any finding to view its AI explanation inline.
- FR-13: Decompiler tab must render decompiled source with AI-generated margin annotations tied to specific lines.
- FR-14: Report tab must generate a draft, exportable report (Markdown/PDF) combining findings and AI commentary.

### 6.4 Deployment
- FR-15: The full stack (backend, static analysis engine, vector store, dashboard) must run via a single `docker-compose up`.
- FR-16: No feature in v1 may require an internet-connected/cloud API call to function; cloud LLM backends are optional and off by default.

## 7. Non-Functional Requirements

- **Privacy/local-first:** No scan data, decompiled source, or chat content leaves the user's machine by default. This is a core value proposition, not an afterthought — it should be visible in the UI (e.g., the model-backend indicator already in the mockup). Web research is the one deliberate exception to this boundary: even self-hosted SearXNG ultimately proxies queries out to public search engines, so it isn't private in the same sense as local inference — it's opt-in per scan, and the UI should make that boundary honest rather than implying full offline operation once it's enabled.
- **Auditability:** As an open-source (MIT) project, code should be organized so the analysis engine and AI layer are inspectable and reasonably modular (not a monolith), inviting review and contribution even though v1 doesn't target contributor growth as a metric.
- **Performance:** RAG retrieval for chat should feel conversational — sub-few-second retrieval latency independent of LLM generation time, on typical consumer hardware (single consumer GPU or CPU-only fallback).
- **Portability:** Should run on Linux and macOS at minimum via Docker; Windows/Docker Desktop support is desirable but not blocking.

## 8. Proposed Architecture (recap)

```
Web Dashboard (MASA UI)
        |
Backend Orchestrator (FastAPI)
    |         |               |
Static     Model Backend   Tool/Agent Layer
Analysis   Abstraction      (manifest reader, class fetcher,
Engine     (Ollama /        string search, secrets scanner,
(jadx/     LM Studio,       permission lister)
apktool/   OpenAI-compat)
Mach-O
tooling)
    |
Vector store (Chroma/SQLite-VSS) — per-scan embeddings for RAG chat
```

## 9. Milestones (sequenced, not dated — no fixed timeline per project owner)

1. **M1 — Analysis core:** Android decompilation + findings pipeline producing structured JSON (no AI yet)
2. **M2 — iOS static core:** IPA unpacking + Mach-O/plist static findings pipeline
3. **M3 — Model backend abstraction:** Ollama + LM Studio client, swappable, tested against both
4. **M4 — RAG chat MVP:** embed one scan's decompiled source, working chat-with-code with citations — this is the flagship feature and should be validated hard before moving on
5. **M5 — Dashboard integration:** wire findings + chat + decompiler view into the UI from the mockup
6. **M6 — Tool-calling agent:** give the LLM callable tools instead of static prompts
7. **M7 — Deep research / web browsing:** self-hosted SearXNG + pluggable providers, search→fetch→summarize→synthesize flow, gated behind explicit opt-in
8. **M8 — Edit & recompile:** Smali edit view + apktool rebuild pipeline for Android, resource/plist/entitlement-only edit + resign for iOS
9. **M9 — Report generation:** AI-assisted draft report export
10. **M10 — Packaging:** Docker Compose single-command install, README, MIT license, public GitHub release

## 10. Risks & Open Questions

- **RAG quality on obfuscated code:** Heavily obfuscated/minified Android code (ProGuard/R8) may retrieve poorly or produce low-value answers — needs early testing against real-world obfuscated APKs, not just clean samples.
- **iOS static-only ceiling:** Some real vulnerability classes (runtime keychain misuse, SSL pinning behavior) are hard to confirm without dynamic testing — v1 should be honest in the UI about what static analysis can and can't confirm, to avoid false confidence.
- **Local hardware variance:** RAG + tool-calling agent loops can be slow on modest hardware; may need a "lite mode" recommendation (smaller model, reduced context) similar to Odysseus's Cookbook concept — worth considering for a near-term follow-up even if not v1.
- **Embedding model choice:** Needs a decision on a default local embedding model (e.g., nomic-embed-text via Ollama) — not yet specified, should be settled in M3/M4.
- **Web research scope creep:** Odysseus's deep research is a substantial subsystem (query enhancement, multi-provider fallback, ranking, source summarization). MASA should start with a narrower version — bounded number of sources, no autonomous multi-hour research loops — and only grow it if the CVE/library-lookup use case proves valuable in practice.
- **Recompile reliability:** apktool rebuilds don't always succeed cleanly on every APK (resource clashes, edge-case bytecode) — the pipeline needs to fail loudly and specifically rather than producing a silently broken APK. Worth budgeting time for this in M8 rather than assuming it "just works" once the happy path is wired up.
- **Recompile misuse potential:** the feature is standard, legitimate pentest tooling (same category as objection/apktool-based SSL-pinning or root-detection bypass workflows), but it's also the one feature in MASA that produces a modified, runnable artifact rather than just analysis. Worth being deliberate about the resigned-build warning staying visible and not something a user can silently disable.
- **Dependency-over-custom-code decision:** as of this revision, several previously "build from scratch" components (secret scanning, LLM client abstraction, RAG chunking, MASVS/MASTG mapping data) were replaced with existing maintained libraries (Gitleaks, Semgrep, LiteLLM, LlamaIndex, OWASP's own mapping data) — see the tech stack doc for the full list. This was a deliberate call. MASA ships MIT, so the GPL/LGPL-licensed tools among them (Semgrep, ldid) must always be invoked as subprocesses, never imported as libraries — the audit in docs/licenses.md records this posture. Worth revisiting at implementation time if any of these libraries turn out to be a worse fit in practice than on paper.
- **Naming collision check:** "MASA" should be checked against existing GitHub/npm/PyPI project names before public release.

## 11. Explicit Non-Goals (restated for clarity)

MASA v1 is **not**: a MobSF replacement with feature parity on day one, a multi-tenant SaaS product, a dynamic/runtime testing tool, or a cloud-AI product. It is a local-first, single-user, static-analysis-plus-RAG-chat tool whose main bet is that talking to your decompiled code is more valuable than another findings table.

---

*This PRD reflects decisions made in the initial scoping interview (July 22, 2026) and should be revisited once M4 (RAG chat MVP) is validated, since that's the feature the whole product's value proposition rests on.*
