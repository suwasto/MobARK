# MASA (Mobile Application Security Assistant) — Task List (v2, aligned to confirmed tech stack)

No fixed dates — sequenced by milestone dependency. Same milestone order as v1, tasks updated to reference actual tools. Feasibility notes are called out inline where a task was corrected from the original plan.

Stack reference: Python 3.11 + FastAPI · RQ + Redis · SQLite · ChromaDB (embedded) + LlamaIndex CodeSplitter · jadx + androguard + Semgrep (Android) · LIEF (iOS) · Gitleaks (secrets, both platforms) · apktool + apksigner/zipalign (Android recompile) · ldid (iOS resign) · LiteLLM (model/BYOK abstraction) · React + Vite + Tailwind · Ollama/LM Studio (host-run, not containerized) · SearXNG + GPT Researcher pattern (deep research) · Docker Compose (3 services) · MIT

**Library-first principle:** prefer an existing, maintained library over custom logic wherever one covers the need — the project ships MIT, so any GPL/LGPL-licensed tool (Semgrep, ldid, and the analysis CLIs) must be invoked as a subprocess, never imported as a library. See tech stack doc for the specific swaps and reasoning.

---

## M0 — Project scaffolding (new — not in v1 list)
- [ ] Repo skeleton: `backend/` (FastAPI app + RQ worker), `frontend/` (React + Vite), `docker/`
- [ ] `docker-compose.yml` starting with `app` + `redis` (searxng added in M7)
- [ ] FastAPI base app with health-check endpoint
- [ ] SQLite schema/migrations for scans + findings (e.g. via SQLModel or plain SQLAlchemy)
- [ ] Redis + RQ worker wired up, test with a dummy job
- [ ] Dependency/license audit pass: pin versions for Gitleaks, Semgrep, LiteLLM, LlamaIndex, GPT Researcher and record their licenses in the repo (informational — MASA is MIT, so GPL/LGPL tools stay subprocess-only; the audit records versions, licenses, and that posture)

## M1 — Android analysis core
- [ ] Wrap jadx as a callable subprocess module (APK in → decompiled Java/Kotlin source tree out)
- [ ] Bundle a JVM in the app Docker image for jadx (confirm final image size is acceptable — expect +~200MB)
- [ ] Integrate androguard for manifest parsing (permissions, exported components, intent filters) — pure Python, no JVM needed for this part
- [ ] Wrap **Gitleaks** as a subprocess module for secret/string scanning (replaces the originally-planned custom regex/entropy scanner — reusable as-is for M2)
- [ ] Wrap **Semgrep**, running Java/Kotlin-oriented rulesets (community + OWASP-style) against jadx output for code-level findings (insecure WebView config, weak crypto, hardcoded trust managers, etc.) — replaces hand-writing these as one-off regex checks
- [ ] Parse app signing certificate info (androguard supports this directly)
- [ ] Parse network security config XML
- [ ] Define structured findings JSON schema (title, severity, file/line, category) — needs a field for which tool produced each finding (androguard/Gitleaks/Semgrep), since they'll have different output shapes to normalize
- [ ] Pull MASVS/MASTG tag mappings from the **official OWASP MASTG repo's mapping data**, vendored/cached locally, instead of hand-maintaining a lookup table
- [ ] Validate end-to-end against a deliberately vulnerable test APK

## M2 — iOS static core
- [ ] IPA unpack pipeline (.ipa → Payload/*.app), pure Python (zipfile)
- [ ] Parse Info.plist via Python's `plistlib` (usage strings, ATS config)
- [ ] Integrate **LIEF** for Mach-O binary inspection — PIE/stack canary/ARC flags, exported symbols, linked libraries
- [ ] Entitlement extraction via LIEF reading the embedded signature blob directly (no `codesign` dependency)
- [ ] **Document the entitlement-extraction coverage limit explicitly** (best-effort for ad-hoc/resigned IPAs — see tech stack doc) — surface this in the finding output itself, not just internal docs
- [ ] Reuse M1's Gitleaks wrapper against binary + bundled resources (same tool, different input surface)
- [ ] Map iOS finding types into the same findings JSON schema as Android
- [ ] "Static-only" flag on every iOS finding — already reflected in the mockup, now wire it to real data
- [ ] Validate against a sample IPA (e.g., an intentionally vulnerable iOS test app), confirm LIEF parses it correctly on Linux (not just macOS dev machine) before calling this done

## M3 — Model backend abstraction
- [ ] Integrate **LiteLLM** as the model client library (replaces building a custom OpenAI-compatible client class)
- [ ] Verify against Ollama (`localhost:11434/v1`) running on host, container reaching it via `host.docker.internal` or equivalent
- [ ] Verify against LM Studio (`localhost:1234/v1`) on host
- [ ] Config layer for switching base URL/model with no code change — backs the Settings modal's Model Backends tab
- [ ] Wire BYOK providers through LiteLLM's existing provider support (OpenAI/Anthropic/Gemini/DeepSeek/Mistral/Groq/xAI/OpenRouter/custom) — backs the Settings modal's BYOK tab; confirm which providers need a key vs. base-URL-only
- [ ] Decide default embedding model: **nomic-embed-text via Ollama**
- [ ] Connection health check surfaced in the UI (model-pill status dot, backend cards' "Test" button)

## M4 — RAG chat MVP (flagship feature — validate hard before proceeding)
- [ ] Integrate **LlamaIndex's `CodeSplitter`** (tree-sitter based) for chunking decompiled source — parses actual syntax boundaries instead of hand-testing per-class vs. per-method splitting
- [ ] Embed chunks into ChromaDB (embedded/persistent mode, file-backed — no separate service)
- [ ] Retrieval function: query → top-k relevant chunks
- [ ] Chat endpoint: user question + retrieved context → LLM → answer
- [ ] Citation formatting: answer must reference file/class/line, not just prose
- [ ] **Stress test against obfuscated/minified code** (ProGuard/R8) — named risk, don't skip
- [ ] Stress test against a large real-world APK for retrieval quality and latency
- [ ] Manual QA: correct grounded answer in ≤3 chat turns? (v1 success bar from PRD)
- [ ] **Go/no-go checkpoint** — don't proceed to M5 UI wiring until this holds up

## M5 — Dashboard integration
- [ ] Scaffold React + Vite app, port the mockup's design tokens into a Tailwind config (colors, IBM Plex fonts, spacing scale)
- [ ] Overview tab wired to real findings JSON (risk score calc, severity counts)
- [ ] Findings tab: expandable AI explanation per finding (calls M3's LiteLLM-backed model client)
- [ ] Decompiler tab: real decompiled source + AI margin annotations
- [ ] Agent chat panel wired to real M4 RAG endpoint (replace mock messages)
- [ ] Scan queue: real upload → RQ job → poll job status every 2-3s (no WebSocket needed for v1)
- [ ] Settings modal: Model Backends tab wired to real Ollama/LM Studio detection + model list
- [ ] Settings modal: BYOK tab wired to real key storage (local, encrypted at rest if feasible) and provider list
- [ ] "Local-only" indicator reflects real state — off the moment a BYOK provider is enabled, not decorative

## M6 — Agent tool-calling
- [ ] Define tool schema: `read_manifest()`, `get_decompiled_class(name)`, `search_strings(pattern)`, `get_permissions()`, `run_secrets_scan()`
- [ ] Implement using **LiteLLM's normalized function-calling interface** (replaces hand-parsing Ollama's native tool-call format directly)
- [ ] **Restrict tool-calling to a documented known-good model list** (Qwen2.5/2.5-coder, Llama 3.1+) — LiteLLM standardizes the API shape, but doesn't fix models that don't reliably follow structured tool-call output; that's still a model capability limit, not a library problem
- [ ] Graceful fallback: if the selected model doesn't support tool calls, degrade to plain RAG chat (M4) instead of failing
- [ ] Guard against runaway tool-call loops (max iterations, timeout)
- [ ] Test agent on a multi-step question requiring 2+ tool calls

## M7 — Deep research / web browsing
- [ ] Add `searxng` as a 3rd Docker Compose service, JSON output format enabled (so results are parseable, not just HTML)
- [ ] Adapt **GPT Researcher**'s search→fetch→summarize→synthesize pipeline, configured to use SearXNG as its retriever, rather than building that flow from scratch
- [ ] Wire the pluggable fallback chain (Brave/DuckDuckGo/Tavily/Serper/Google PSE via API key) through the same BYOK-style key storage pattern from M3/M5
- [ ] Expose `web_search(query)` and `web_fetch(url)` as agent tools, added to the M6 tool-calling set
- [ ] Confirm the pipeline stays **bounded** even using GPT Researcher's implementation (fixed source count, e.g. 5) — deliberately smaller in scope than its full autonomous-research feature set for v1
- [ ] Gate web research behind explicit per-scan opt-in — never triggered silently by the agent
- [ ] Update the "Local-only" UI indicator to change state the moment web research is enabled, and make the distinction clear in-copy: self-hosted SearXNG still means queries leave the machine, unlike local LLM inference
- [ ] Test the flagship use case: given a detected third-party library + version, agent researches whether it has known CVEs and summarizes findings with source links
- [ ] Test a MASVS/MASTG reference lookup query end-to-end

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
- [ ] MIT license file
- [ ] Naming collision check ("MASA" vs existing GitHub/npm/PyPI projects)
- [ ] Strip remaining mockup placeholder branding/sample data
- [ ] Public GitHub repo, initial release tag
- [ ] Post-launch: monitor for the v1 success metric (stars/adoption), gather issue-tracker feedback for v1.1 scoping

---

## Deferred / v1.1 candidates (unchanged from v1, not blocking v1)
- [ ] MASVS/MASTG as an embedded RAG corpus (reuse M4's ChromaDB instance once M4 is proven)
- [ ] "Lite mode" model recommendation for low-spec hardware (Cookbook-style)
- [ ] Multi-user / auth / team features (would also mean revisiting SQLite → Postgres)
- [ ] Hosted cloud tier
- [ ] Dynamic analysis (Frida, jailbroken device workflows)
- [ ] Malware/repackaging diff against official store originals
- [ ] WebSocket-based real-time updates (only if polling proves genuinely insufficient in practice)
