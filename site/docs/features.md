# Features

## Static analysis

- **Android (APK):** manifest inspection (permissions, exported
  components, debuggable flag, network security config, backup rules)
  via androguard · jadx decompilation · curated semgrep rules (the
  app's own rules + the vendored OWASP MASTG set) · gitleaks secrets
  scanning · dependency inventory (third-party packages, native
  `lib/*.so`, cross-platform runtime markers).
- **iOS (IPA):** bundle unpacking · Info.plist inspection · Mach-O
  analysis via LIEF (PIE, stack canary, ARC, FairPlay encryption,
  exported symbols, linked dylibs, architectures) · entitlement carving
  from the embedded code-signature blob · import-table scanner for
  insecure crypto, WebView, and anti-debug APIs.

## AI copilot

- Chat with the decompiled code through your local LLM (Ollama / LM
  Studio) or any BYOK provider (OpenAI, Anthropic, Gemini, DeepSeek,
  OpenRouter, custom).
- **Layers 1–3** (no embeddings): full findings context, code search /
  file-read tools, and per-scan code-graph query/path/explain tools.
- Tool-calling with **live step streaming** over SSE (token stream +
  tool start/end frames + a full trace), bounded tool loop, editable
  file reads, on-demand secrets re-scan, string/resource search.
- **Opt-in web research** (per-scan toggle): `web_search` +
  `web_fetch` through the bundled SearXNG, SSRF-guarded, with citation
  links back into the decompiled tree.
- Dev-only **fake LLM** (`MOBARK_FAKE_MODEL=1`) to demo the agent with
  zero Ollama.

## Edit & recompile (Android)

- On-demand apktool decode → smali tree.
- Agent can **propose edits** (and you can hand-edit smali) with diff
  review, then rebuild a **resigned test APK** (apksigner/zipalign).

## Reports

- Deterministic assembly (no model needed) with a **banded risk-index
  score** (`high | warning | info` severities: deliberately not CVSS,
  which needs a human analyst for disclosed CVEs) and per-finding
  explanations.
- Per-finding **suppression** with live re-scoring.
- Markdown + branded **PDF** export.

## Dashboard

- Overview (security gauge, severity stats, AI summary, top findings),
  Findings (filter/suppress/AI explain), Dependencies, Decompiler
  (file tree + code viewer + annotation rail), Code maps (searchable
  per-scan graph), Report: plus a progress dialog during scans and a
  searchable Provider/Model picker in the top bar.

## Multi-user auth

Username/password + GitHub/Google OAuth, per-user data isolation,
per-user encrypted key vault, sliding sessions. See
[Authentication](auth.md).
