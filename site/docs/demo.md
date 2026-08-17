# Demo

## Screenshots

![Dashboard overview](assets/demo/dashboard.png)

![Agent dock with live tool steps and reasoning](assets/demo/agent-dock.png)

![Generated report](assets/demo/report.png)

## Video

A walkthrough of a real scan - upload, analysis, agent chat, and the
generated report:

<video controls src="../assets/demo/screen_record.mp4"></video>

## Try it yourself

The fastest demo is [the quickstart](quickstart.md): `docker compose up
--build`, register a first account (the **first registration becomes
the admin**: use any username, e.g. `admin`, with a password you choose
yourself), then upload an APK or IPA. With `MOBARK_FAKE_MODEL=1` the
agent dock demos its live steps and token streaming with zero Ollama.

Platform limits: both platforms get full static analysis and the AI
Agent, but **edit & recompile is Android-only** - iOS stays read-only
in v1 (IPA rebuilds need an Apple Developer account + signing
certificates, and edit support is very limited). See
[Features](features.md) for the parity table.
