# MobARK: Mobile Application Reverse Kit

MobARK is a **self-hosted, local-first dashboard** for mobile application
security testing (Android + iOS) with a built-in AI Agent. Static
analysis of APK/IPA files, chat-with-decompiled-code via a local LLM
(Ollama / LM Studio), and report generation: all without any scan data
leaving your machine.

<div class="grid cards" markdown>

-   :material-cellphone-lock: **Static analysis**

    Android (jadx / apktool / semgrep / gitleaks) and iOS (LIEF):
    manifests, decompiled sources, secrets, MASTG rule coverage, Mach-O
    binaries, entitlements.

-   :material-robot: **AI Agent**

    Chat with the decompiled code through a local LLM (Ollama / LM
    Studio or any BYOK provider), with tool-calling, live step
    streaming, and opt-in web research through a bundled SearXNG.

-   :material-file-document-edit: **Edit & recompile**

    On-demand smali decode, agent-proposed edits, and resigned test
    builds (Android) for validation workflows.

-   :material-file-chart-outline: **Reports**

    Deterministic Markdown / PDF reports with a banded risk-index
    score (`high | warning | info`, no CVSS claim), finding
    explanations, and per-finding suppression.

-   :material-account-lock: **Multi-user & isolated**

    Username/password + GitHub/Google OAuth, per-user data isolation,
    and per-user encrypted key storage (vault).

-   :material-home-lock: **Local-first**

    Nothing leaves your machine by default. The app, worker, Redis, and
    the search engine all run locally under `docker compose`.

</div>

## Quick tour

```bash
docker compose up --build
```

Open http://localhost:8000, register the first account (it becomes the
instance **admin**), upload an APK or IPA, and MobARK analyzes it locally.
See [Quickstart](quickstart.md) for the full walkthrough: including the
demo users you can create for a local install.

## Why local-first?

MobARK is designed for security work on artifacts you may not want to
upload anywhere: mobile app binaries, decompiled source, embedded
secrets. Every analysis stage runs on your machine: the LLM is your
local Ollama/LM Studio (or a BYOK cloud key you provide), and the only
outbound network traffic is the *opt-in* agent web research. The
project is Apache-2.0 and the compliance posture is documented in
[Third-party licenses](licenses.md).
