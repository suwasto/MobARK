# Status

## Shipped

- **Static analysis**: Android (manifest inspection via androguard,
  jadx decompilation, curated + vendored OWASP MASTG semgrep rules,
  gitleaks secrets scanning, dependency inventory) and iOS (bundle
  unpacking, Info.plist inspection, Mach-O analysis via LIEF: PIE,
  stack canary, ARC, FairPlay, dylibs, architectures: entitlement
  carving, import-table scanning).
- **AI copilot**: chat with the decompiled code through a local LLM
  (Ollama / LM Studio) or any BYOK provider; findings context, code
  search/read + code-graph tools, live tool/token streaming, opt-in
  web research through a bundled SearXNG.
- **Edit & recompile** (Android): apktool decode, smali edits (agent
  proposals + manual), diff review, resigned test APK builds.
- **Reports**: deterministic Markdown/PDF with banded risk-index
  scoring (`high | warning | info`, no CVSS claim), per-finding
  suppression, AI (or no-model) explanations.
- **Dashboard**: security gauge, findings tab, decompiler, dependency
  inventory, code maps, report tab, agent dock.
- **Multi-user auth**: username/password + GitHub/Google OAuth,
  per-user data isolation, encrypted per-user key vault.

## Roadmap

- **Dynamic analysis**: runtime/device testing (next up)
- iOS edit/recompile (ldid resign)
- Hosted tier
- Malware diffing
