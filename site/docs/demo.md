# Demo

> **OWNER: add real media.** The screenshots and video below are
> placeholders. Replace them with a capture of a real scan (the sample
> artifacts used in verification — e.g. InsecureBankv2.apk /
> iBugBazaar.ipa).

## Screenshots

!!! placeholder "Dashboard overview"

    **OWNER: add** — screenshot of the loaded dashboard (security gauge,
    severity stats, top findings, decompiler tree) at
    `site/assets/demo/dashboard.png`.

!!! placeholder "Agent dock"

    **OWNER: add** — screenshot of a chat with live tool steps /
    citations at `site/assets/demo/agent-dock.png`.

!!! placeholder "Report"

    **OWNER: add** — screenshot of a generated report (Markdown or PDF)
    at `site/assets/demo/report.png`.

## Video

!!! placeholder "Walkthrough video"

    **OWNER: add** — a short screen recording (upload → analysis →
    agent chat → report) at `site/assets/demo/demo.mp4` and link it here:

    ```html
    <video controls src="../assets/demo/demo.mp4"></video>
    ```

## Try it yourself

The fastest demo is [the quickstart](quickstart.md): `docker compose up
--build`, register `admin` / `password123`, upload an APK or IPA. With
`MASA_FAKE_MODEL=1` the agent dock demos its live steps and token
streaming with zero Ollama.
