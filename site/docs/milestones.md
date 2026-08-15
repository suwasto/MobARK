# Milestones

MASA is built milestone-driven. The internal trackers stay out of the
public repo (`docs/` is deliberately gitignored); this page is the
curated public history.

| Milestone | Shipped | What it delivered |
|---|---|---|
| **M0** | Aug 2, 2026 | Repo skeleton: FastAPI + RQ worker + React/Vite, docker-compose (app + worker + redis), SQLite + Alembic, health endpoint |
| **M1** | Aug 3, 2026 | Android static analysis: jadx decompile, androguard manifest/cert inspection, semgrep (curated + vendored MASTG rules), gitleaks secrets, orchestrator with per-stage error policy |
| **M2** | Aug 4, 2026 | iOS static core: LIEF Mach-O analysis (PIE, stack canary, ARC, FairPlay, dylibs, architectures), entitlements, Info.plist, import-table scanner |
| **M3** | Aug 5, 2026 | Model backends: Ollama/LM Studio + BYOK providers via LiteLLM, JSON-backed backend store, health/probe, model listing |
| **M4** | Aug 6, 2026 | Agent Layers 1–3: findings context, search/read tools, code-graph tools (Graphify), bounded tool loop, per-scan code graph + Code maps tab. *RAG/embeddings dropped from v1 by owner decision* |
| **M5** | Aug 8, 2026 | Dashboard: overview/security gauge (CVSS 4.0 risk), findings tab with AI explain, decompiler (file tree + code viewer + annotation rail), agent dock chat, upload flow, SPA served from FastAPI |
| **M6** | Aug 9, 2026 | App-oriented agent tools (manifest, class, permissions, secrets re-scan, string search) + live token/tool-step streaming over SSE; M6.1 dev-only fake LLM |
| **M7** | Aug 9, 2026 | Agent web research: `web_search`/`web_fetch` through a bundled always-on SearXNG (SSRF-guarded), per-scan opt-in, one-active search-engine radio in Settings |
| **M8** | Aug 10, 2026 | Edit & recompile (Android): apktool decode, smali edits (agent proposals + manual), diff review, resigned test APK builds |
| **M9** | Aug 12, 2026 | Reports: deterministic assembly, CVSS 4.0 risk scoring, per-finding suppression, Markdown + PDF export; chat sessions (M9 follow-up) |
| **M9.1** | Aug 14, 2026 | Auth + per-user isolation: register/login, GitHub/Google OAuth, sliding sessions, per-user encrypted key vault, structural scan ownership |
| **M10** | Aug 2026 | Open-source readiness: public docs site (this site), CI, community files, header assets — *in progress* |

## Deferred to v1.1

- Dynamic analysis
- iOS edit/recompile (ldid resign)
- Hosted tier
- Malware diffing
