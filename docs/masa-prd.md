# Product Requirements Document: MASA (Mobile Application Security Assistant)

**AI-native mobile security testing workbench**
Version 0.1 (Draft) · July 22, 2026

---

## 1. Summary

MASA is a self-hosted, open-source dashboard for mobile application security testing (Android + iOS) with a built-in AI copilot. It combines static analysis of APK/IPA files with a local-LLM-powered reasoning layer — inspired by Odysseus's pluggable model-backend pattern (Ollama, LM Studio, and OpenAI-compatible endpoints) — so a pentester can not only see raw findings but ask questions directly against the decompiled codebase and get grounded, cited answers.

Unlike MobSF, MASA's analysis engine is built from scratch, and the AI layer is a first-class citizen of the product rather than a bolt-on: the flagship capability is **chat-with-decompiled-code**, a grounded conversational interface over the app under test. **The M4 embedding/RAG pipeline was deleted from v1 (owner decision, Aug 6, 2026)** — CPU-only embedding of a 3MB APK took 5-15 minutes before chat was even usable. The agent layer is non-embedding: Layer 1 = the full precision-tagged findings set from every static source; Layer 2 = `search_code`/`read_file` tools over the decompiled/extracted tree; Layer 3 = Graphify graph traversal (Android). See the tech stack doc for the decision record.

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
- **Chat-with-decompiled-code (flagship feature):** grounded answers over the scan using three non-embedding layers — the full static-findings set (every source, precision-tagged), `search_code`/`read_file` tools over the decompiled/extracted tree, and (Android) Graphify graph traversal — with citations back to file/line. The RAG/embedding pipeline was removed from v1 (owner decision, Aug 6): see tech stack doc
- Per-finding "explain this" AI annotation (plain-language explanation + fix guidance)
- Tool-calling agent loop giving the LLM callable tools: read manifest, get decompiled class, search strings, get permissions, run secrets scan
- **On-demand agent web research (M7):** two agent tools in the existing tool loop — `web_search(query)` (self-hosted **SearXNG**, a profile-gated compose service; provider registry with custom SearXNG-compatible instances; Brave / Serper / Mojeek are later rows) and `web_fetch(url)` (httpx + **trafilatura ≥1.8.0** extraction — earlier versions are GPLv3+; static pages only — no browser in v1). ChatGPT/Gemini-style: the model triggers a search when a question needs current/external info (CVE lookups, MASTG guidance, dependency versions) and cites source URLs. Engines are configured in Settings — an **Active/Inactive toggle per backend, one Active at a time** — and web research itself is an explicit **per-scan opt-in** (Agent dock 🌐 toggle), which is disabled until an engine is Active. The deep-research pipeline and interactive browser automation were dropped from v1 (owner decision, Aug 9).
- **Graph-based code understanding (Graphify, Layer 3):** a deterministic
  call/import/inheritance graph is built from decompiled Android source using Graphify
  (tree-sitter AST parsing, code-only mode — no LLM, no API key, nothing leaves the
  machine). Structural questions ("where is certificate pinning located," "what calls
  this method") get answered by graph traversal — more precise than grep/findings
  context for that class of question. Android-only in v1 (iOS negative confirmed:
  unpacked `.app` bundles have no source-like files). The agent picks which tool fits
  the question — Layer 1 findings context, Layer 2 search/read, or Layer 3 graph.

**Edit & recompile:**
- **Android:** the decompiler view supports a Java (jadx, read-only) and a Smali (apktool, editable) view per file. Edits — made by hand or requested from the agent in natural language ("bypass this SSL pinning check for testing") — are applied at the smali level, since that's the only representation that can actually be rebuilt. Resource and manifest files (strings.xml, AndroidManifest.xml, network config) are directly editable without a smali detour. "Recompile app" runs the full pipeline: apply edits → rebuild with apktool → zipalign → sign with a locally generated test keystore → produce a downloadable APK.
- **iOS:** **deferred from v1 to v1.1 (owner decision, Aug 10, 2026).** The originally-planned narrow scope — Info.plist, entitlements, and resource edits, resigned ad-hoc via `ldid` for sideload testing (never compiled-logic editing, see Non-Goals) — remains the v1.1 target but is **not shipped in v1**. Research at the M8 kickoff confirmed an `ldid -S` re-signed IPA installs only on jailbroken devices (AppSync Unified) or as handoff input for the user's own Sideloadly/Apple-ID re-signing; stock iOS rejects it and the simulator won't run it (wrong platform slice). Shipping an artifact that needs a jailbroken device or external tooling to be useful was judged not worth v1 scope — iOS keeps today's read-only bundle view. Full decision record: `docs/progress/M8.md`.
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
- Apache-2.0 (revised from the original AGPL-3.0 decision) — maximizes adoption and self-hosting for a single-user tool; the GPL/LGPL-licensed tools in the stack (Semgrep, ldid) are always invoked as subprocesses, never imported as libraries, which keeps the Apache-2.0 license clean

### 5.2 Explicitly Out of Scope (v1)

- Multi-user accounts, roles, or team collaboration features
- Hosted/cloud-managed version
- Dynamic analysis / instrumentation (Frida hooks, jailbroken-device testing, runtime traffic interception)
- Automated exploit generation
- Malware/repackaging diffing against Play Store or App Store originals
- Cloud LLM integration as anything more than an optional, clearly-labeled opt-in (OpenRouter etc.) — local-first is the default and the headline positioning
- **iOS binary logic patching/recompilation.** Editing compiled Objective-C/Swift behavior and rebuilding it is not feasible without Xcode and the original project — a non-goal for both v1 and v1.1. Note: the *narrow* iOS edit path (Info.plist/entitlements/resource edits + `ldid` resign) is also **deferred to v1.1** (owner decision, Aug 10, 2026) — see the §5.1 Edit & recompile bullet and §10.
- **Editing jadx's Java view and expecting it to recompile.** There is no path from edited decompiled Java back to working bytecode — this is why the Smali view exists as a separate, explicitly-editable representation.

These are reasonable candidates for a v2+ roadmap but should not block v1 shipping.

## 6. Functional Requirements

### 6.1 Static Analysis Engine
- FR-1: System must accept APK or IPA upload and produce structured JSON findings without relying on MobSF.
- FR-2: System must decompile Android apps via jadx/apktool and expose per-class source to downstream consumers (findings UI, agent Layer 2/3 tools).
- FR-3: System must statically unpack and parse IPA structure (Info.plist, entitlements, Mach-O headers) without requiring a jailbroken device.
- FR-4: Each finding must include: title, severity, file/line reference (where applicable), and a machine-readable category (mappable to MASVS/MASTG where relevant).

### 6.2 AI / Agent Layer (non-embedding — Layers 1-3)
- FR-5: System must support at least two interchangeable local LLM backends (Ollama, LM Studio) via a single abstraction with no code change required to switch.
- FR-6: The agent must have access to the **full findings set from every static source**, normalized into one schema with a visible per-finding **precision tag** — `file/line` (Semgrep, Gitleaks, androguard manifest, Info.plist) vs `binary-level presence only, no specific location` (Mach-O protections/entitlements, import-table scanner). No embedding or vector store is used; this is a data lookup over the findings table. *(FR-6 originally required chunk-and-embed; the RAG pipeline was removed from v1 — owner decision, Aug 6.)*
- FR-6a: Layer 2 tools — `search_code(pattern, glob)` and `read_file(path, line_range)` — must work identically for Android and iOS as plain text operations over each platform's decompiled/extracted tree, with no platform-specific branching inside the tools.
- FR-7: The chat interface must answer questions grounded in the actual scan's data (findings context and/or tool results) and cite the specific file/class/line supporting its answer.
- FR-8: Each finding must support an on-demand "explain" action that produces a plain-language explanation plus a suggested fix.
- FR-9: The AI layer must be able to call defined tools (manifest reader, class fetcher, string search, permission lister, secrets scanner) rather than relying on one large unstructured prompt.
- FR-9a: The agent must support on-demand web tools — `web_search(query)` (against the single Active search engine configured in Settings) and `web_fetch(url)` (bounded httpx + trafilatura extraction) — in the existing tool loop, not a standalone deep-research pipeline.
- FR-9b: Web research must be an explicit, per-scan opt-in — not silently triggered — and the dashboard must indicate when a query is about to leave the local machine, consistent with the app's existing local-first framing. The per-scan opt-in control (Agent dock 🌐 toggle) must be **disabled until at least one search engine is Active** in Settings (mirroring the no-model-connected gate on chat).
- FR-9i: A code graph (calls/imports/inheritance) must be built from decompiled Android
  source via Graphify's code-only extraction mode, requiring no LLM call and no network
  access.
- FR-9j: The agent must have graph-query tools (query/path/explain) available alongside
  its Layer 1/2 tools, and choose between them based on question type rather than always
  defaulting to one.
- FR-9k: iOS graph support is not guaranteed — decompiled Objective-C/Swift pseudocode
  may not parse cleanly with tree-sitter's grammars, unlike Android's jadx-produced Java.
  Validate before assuming parity with Android; do not promise it in v1 documentation
  until confirmed.
- FR-9l: Search engines must be configured in Settings — an **Active/Inactive
  toggle per backend, one Active at a time** (enabling one disables the
  others); `web_search` runs against the single Active engine, and the web
  tools are offered only when BOTH the scan's opt-in (FR-9b) and an Active
  engine hold.


### 6.3 Edit & Recompile
- FR-9c: The decompiler view must offer a Java (read-only) and Smali (editable) toggle for `.java`-sourced files; edits must only be possible in the Smali view.
- FR-9d: Resource/manifest/XML files must be directly editable without requiring a Smali detour.
- FR-9e: The agent must be able to apply a natural-language-requested edit to the currently open Smali or resource file, with the resulting diff visible to the tester before it's kept.
- FR-9f: "Recompile app" must run apply-edits → rebuild (apktool) → zipalign → sign-with-local-test-keystore as a visible pipeline, and produce a downloadable, resigned build.
- FR-9g: The UI must clearly label recompiled output as a resigned test build, distinct from the original app's signature, every time it's produced — not just in documentation.
- FR-9h: iOS recompile must be limited to Info.plist/entitlements/resource edits; the UI must not offer a Smali-equivalent "edit compiled logic" path for iOS in v1. *(Deferred to v1.1 — owner decision, Aug 10, 2026: iOS edit/recompile is not shipped in v1/M8; this requirement binds the v1.1 iOS work.)*


### 6.4 Dashboard
- FR-10: Dashboard must show scan status (queued/running/done) per uploaded app.
- FR-11: Overview tab must show an aggregate risk score and severity breakdown.
- FR-12: Findings tab must let a user expand any finding to view its AI explanation inline.
- FR-13: Decompiler tab must render decompiled source with AI-generated margin annotations tied to specific lines.
- FR-14: Report tab must generate a draft, exportable report (Markdown/PDF) combining findings and AI commentary.

### 6.4 Deployment
- FR-15: The full stack (backend, static analysis engine, dashboard) must run via a single `docker-compose up`. *(No vector store exists — the RAG pipeline was removed from v1.)*
- FR-16: No feature in v1 may require an internet-connected/cloud API call to function; cloud LLM backends are optional and off by default.

## 7. Non-Functional Requirements

- **Privacy/local-first:** No scan data, decompiled source, or chat content leaves the user's machine by default. This is a core value proposition, not an afterthought — it should be visible in the UI (e.g., the model-backend indicator already in the mockup). Web research is the one deliberate exception to this boundary: even self-hosted SearXNG ultimately proxies queries out to public search engines, so it isn't private in the same sense as local inference — it's opt-in per scan, and the UI should make that boundary honest rather than implying full offline operation once it's enabled.
- **Auditability:** As an open-source (Apache-2.0) project, code should be organized so the analysis engine and AI layer are inspectable and reasonably modular (not a monolith), inviting review and contribution even though v1 doesn't target contributor growth as a metric.
- **Performance:** the agent layers are all non-embedding — findings-context assembly, grep/file reads, and graph traversal are sub-second data operations on typical consumer hardware (CPU-only included). No per-scan embedding index exists to slow first chat (the RAG pipeline was removed from v1 for exactly this reason).
- **Portability:** Should run on Linux and macOS at minimum via Docker; Windows/Docker Desktop support is desirable but not blocking.

## 8. Proposed Architecture (recap)

```
Web Dashboard (MASA UI)
        |
Backend Orchestrator (FastAPI)
    |         |               |
Static     Model Backend   Agent Layer (non-embedding)
Analysis   Abstraction    (Layer 1: full findings context —
Engine     (Ollama /      precision-tagged; Layer 2: search_code /
(jadx/     LM Studio,     read_file over the decompiled/extracted
apktool/   OpenAI-compat) tree; Layer 3: Graphify graph — Android;
LIEF)                     web_search/web_fetch via SearXNG — M7)
    |
(no vector store — the RAG/embedding pipeline was removed from v1)
```

## 9. Milestones (sequenced, not dated — no fixed timeline per project owner)

1. **M1 — Analysis core:** Android decompilation + findings pipeline producing structured JSON (no AI yet)
2. **M2 — iOS static core:** IPA unpacking + Mach-O/plist static findings pipeline
3. **M3 — Model backend abstraction:** Ollama + LM Studio client, swappable, tested against both
4. **M4 — Agent context layers (Layers 1-3):** full findings context + search/read tools + Graphify graph tools, with a bounded tool-calling chat — no embeddings (the RAG pipeline was removed from v1; see tech stack doc)
5. **M5 — Dashboard integration:** wire findings + chat + decompiler view into the UI from the mockup
6. **M6 — Tool-calling agent:** give the LLM callable tools instead of static prompts
7. **M7 — Agent web research (on-demand):** `web_search`/`web_fetch` agent tools, self-hosted SearXNG (profile-gated compose service; AGPL boundary — unmodified container, HTTP JSON API only), Settings search-engine registry with Active/Inactive toggles (one Active at a time), per-scan opt-in (dock toggle disabled until an engine is Active) — no deep-research pipeline, no browser automation in v1 (owner decision, Aug 9)
8. **M8 — Edit & recompile (Android):** Smali edit view + apktool rebuild pipeline + local-test-keystore resign for Android. iOS resource/plist/entitlement-only edit + `ldid` resign **deferred to v1.1** (owner decision, Aug 10, 2026 — an `ldid`-signed IPA only installs on jailbroken devices or as handoff input for the user's own re-signing)
9. **M9 — Report generation:** AI-assisted draft report export
10. **M10 — Packaging:** Docker Compose single-command install, README, Apache-2.0 license, public GitHub release

## 10. Risks & Open Questions

- **Agent answer quality on obfuscated code:** Heavily obfuscated/minified Android code (ProGuard/R8) degrades identifier labels — Layers 1-3 still work (findings carry semantic titles, grep matches patterns, and graph *structure* survives) but answers are weaker than on clean samples. Needs early testing against real-world obfuscated APKs.
- **iOS static-only ceiling:** Some real vulnerability classes (runtime keychain misuse, SSL pinning behavior) are hard to confirm without dynamic testing — v1 should be honest in the UI about what static analysis can and can't confirm, to avoid false confidence.
- **Local hardware variance:** tool-calling agent loops can be slow on modest hardware; may need a "lite mode" recommendation (smaller model, reduced context) similar to Odysseus's Cookbook concept — worth considering for a near-term follow-up even if not v1. (No longer includes an embedding step — that was the removed RAG pipeline.)
- **Findings-context size:** very large findings sets (500+ findings) make the Layer 1 context heavy for small-context models; the builder renders compactly and offers an explicit `max_findings` escape hatch, but a "lite mode" may need to trim or paginate context.
- **Web research scope creep:** the originally-planned deep-research subsystem (query enhancement, multi-provider fallback, ranking, source summarization) was dropped from v1 in favor of on-demand `web_search`/`web_fetch` tools (owner decision, Aug 9) — bounded results, one Active engine, no autonomous multi-hour research loops. Revisit only if the CVE/library-lookup use case proves it worthwhile.
- **SearXNG runtime + license boundary:** web research adds a second container (SearXNG, AGPL-3.0) beyond app+redis — profile-gated (`docker compose --profile web up -d searxng`) so the default install stays lean, and reached only over its HTTP JSON API as an unmodified image (never vendored/imported/forked — see `docs/licenses.md`). Queries leave the machine by design; the per-scan opt-in and the Active-engine setting gate that egress.
- **Recompile reliability:** apktool rebuilds don't always succeed cleanly on every APK (resource clashes, edge-case bytecode) — the pipeline needs to fail loudly and specifically rather than producing a silently broken APK. Worth budgeting time for this in M8 rather than assuming it "just works" once the happy path is wired up.
- **Recompile misuse potential:** the feature is standard, legitimate pentest tooling (same category as objection/apktool-based SSL-pinning or root-detection bypass workflows), but it's also the one feature in MASA that produces a modified, runnable artifact rather than just analysis. Worth being deliberate about the resigned-build warning staying visible and not something a user can silently disable.
- **iOS resign deferral (decision record, Aug 10, 2026):** iOS edit/recompile was cut from M8/v1. Verified research: an `ldid -S` fake-signed IPA is rejected by stock iOS (the signature must bind to a provisioning profile/Apple-issued cert), installs only on jailbroken devices via **AppSync Unified**, and won't run in the iOS Simulator (wrong platform slice — `PLATFORM_IOS` vs `PLATFORM_IOSSIMULATOR`; needs Mach-O patching that's out of scope). A user on a non-jailbroken device must re-sign with their own credentials — Sideloadly/AltStore with a free Apple ID (7-day expiry, 3-app limit, Developer Mode), or a paid $99/yr developer account with UDID registration — making MASA's iOS output a *handoff input* rather than an installable artifact. Revisit for v1.1 if the jailbreak-target / handoff workflow proves valuable for MASA's audience.
- **Dependency-over-custom-code decision:** several previously "build from scratch" components (secret scanning, LLM client abstraction, MASVS/MASTG mapping data) were replaced with existing maintained libraries (Gitleaks, Semgrep, LiteLLM, OWASP's own mapping data) — see the tech stack doc for the full list. (LlamaIndex/ChromaDB were adopted and then **removed from v1** with the RAG pipeline, owner decision Aug 6.) This was a deliberate call. MASA ships Apache-2.0, so the GPL/LGPL-licensed tools among them (Semgrep, ldid) must always be invoked as subprocesses, never imported as libraries — the audit in docs/licenses.md records this posture. Worth revisiting at implementation time if any of these libraries turn out to be a worse fit in practice than on paper.
- **Naming collision check:** "MASA" should be checked against existing GitHub/npm/PyPI project names before public release.
- **Graphify scope discipline:** Graphify is a large tool (PR triage, video/PDF
  ingestion, Neo4j export, Obsidian vaults, etc.). MASA should use exactly two
  capabilities — `extract --code-only` and `query`/`path`/`explain` — not adopt its
  full feature surface. Its published benchmark numbers (recall@10, QA accuracy vs.
  mem0/supermemory) are self-reported by the project, not independently verified —
  cite them as such if referenced anywhere, don't present them as settled fact.
- **Obfuscation and graph quality:** ProGuard/R8-obfuscated Android code degrades node
  *labels* (`a.b.c()`), but graph *structure* (who-calls-whom) survives — it doesn't
  depend on meaningful names. Worth validating at the same M4 go/no-go checkpoint
  already planned for agent-answer quality, not a separate concern.

## 11. Explicit Non-Goals (restated for clarity)

MASA v1 is **not**: a MobSF replacement with feature parity on day one, a multi-tenant SaaS product, a dynamic/runtime testing tool, or a cloud-AI product. It is a local-first, single-user, static-analysis-plus-agent-chat tool (non-embedding Layers 1-3) whose main bet is that talking to your decompiled code is more valuable than another findings table.

---

*This PRD reflects decisions made in the initial scoping interview (July 22, 2026) and was revised at M4 kickoff (Aug 6, 2026) when the RAG/embedding pipeline was removed from v1 in favor of non-embedding agent layers, and at the M8 kickoff (Aug 10, 2026) when iOS edit/recompile was deferred from v1/M8 to v1.1 (Android-only M8; see §5.1, §6.3 FR-9h, §9, §10). It should be revisited once M4's Layers 1-3 are validated, since the agent layer is the feature the whole product's value proposition rests on.*
