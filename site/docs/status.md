# Status

## Shipped

- **Static analysis**: Android (manifest inspection via androguard,
  jadx decompilation, curated + vendored OWASP MASTG semgrep rules,
  gitleaks secrets scanning, dependency inventory) and iOS (bundle
  unpacking, Info.plist inspection, Mach-O analysis via LIEF: PIE,
  stack canary, ARC, FairPlay, dylibs, architectures: entitlement
  carving, import-table scanning).
- **AI Agent**: chat with the decompiled code through a local LLM
  (Ollama / LM Studio) or any BYOK provider; findings context, code
  search/read + code-graph tools, live tool/token streaming, opt-in
  web research through a bundled SearXNG.
- **Edit & recompile** (Android only): apktool decode, smali edits
  (agent proposals + manual), diff review, resigned test APK builds.
  iOS stays read-only: IPA rebuilds need an Apple Developer account
  and signing certificates, and edit support is very limited.
- **Reports**: deterministic Markdown/PDF with banded risk-index
  scoring (`high | warning | info`), per-finding suppression, AI (or
  no-model) explanations.
- **Dashboard**: security gauge, findings tab, decompiler, dependency
  inventory, code maps, report tab, agent dock.
- **Multi-user auth**: username/password + GitHub/Google OAuth,
  per-user data isolation, encrypted per-user key vault.
- **Dynamic analysis** (V2): live Frida hooks with a real-time event
  feed, device mirroring, network traffic capture with flagged-data
  detection, and script management (built-in, manual, agent-drafted
  behind a human approval gate) against a rooted Android device /
  emulator or a jailbroken iOS device (or an optional Corellium iOS
  backend).

## Roadmap

- v1.1 candidates: iOS edit & recompile (ldid resign), additional
  search-engine providers, WebSocket-based real-time updates. See the
  task list's "Deferred / v1.1 candidates" section.
