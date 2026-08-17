# Releasing MobARK

MobARK publishes a ready-to-run image to Docker Hub
(`suwasto/mobark`) and docs to GitHub Pages. A release is a git tag
(`v0.1.0`); CI does the publishing — no local Docker Hub access is
needed.

## One-time setup (before the first release)

### 1. Docker Hub repository

Create a **public** repository named `mobark` under the `suwasto`
organization (or the account that owns the images):

<https://hub.docker.com/new/>

There is nothing else to configure in Docker Hub itself — the build
happens in GitHub Actions and pushes the finished image.

### 2. GitHub repository secrets

The publish workflow (`.github/workflows/docker.yml`) logs in with two
secrets. Add them at **Settings → Secrets and variables → Actions** on
the GitHub repo:

| Secret | Value |
|---|---|
| `DOCKERHUB_USERNAME` | `suwasto` (or whatever org/account owns the repo) |
| `DOCKERHUB_TOKEN` | Access token created at <https://hub.docker.com/settings/security> with **Read & Write** (and **Read** on public repos) permissions for the `mobark` repo |

### 3. GitHub Release permissions

Releases are created from the GitHub UI — no extra permissions needed.
The Pages docs site already deploys on `main` via
`.github/workflows/pages.yml`.

## Cutting a release (checklist)

1. **Bump the source version** in `backend/app/config.py`
   (`version: str = "0.1.0"` → the new version). This is the version
   local builds report and the default for compose (`MOBARK_VERSION`,
   `MOBARK_IMAGE_TAG`).
2. **Update `CHANGELOG.md`**: rename the `[Unreleased]` section to
   `[0.1.0] - YYYY-MM-DD` (Keep a Changelog format) and open a fresh
   `[Unreleased]` on top.
3. **Commit** the version bump + changelog on `main`.
4. **Tag and push** — this is what triggers the publish:

   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```

5. **Watch the `docker` workflow** on
   <https://github.com/suwasto/MobARK/actions> — it builds
   `linux/amd64` and pushes:

   - `suwasto/mobark:0.1.0`
   - `suwasto/mobark:latest`

6. **Create the GitHub Release** (optional but recommended): on
   <https://github.com/suwasto/MobARK/releases/new>, pick the `v0.1.0`
   tag and paste the `[0.1.0]` changelog section.
7. **Verify the published image**:

   ```bash
   docker pull suwasto/mobark:0.1.0
   docker run --rm suwasto/mobark:0.1.0 \
     python -c "import os; print(os.environ['MOBARK_VERSION'])"
   # -> 0.1.0
   ```

   Or after a `docker compose pull && docker compose up`:
   `curl http://localhost:8000/api/v1/health` reports the same version
   in its `version` field.

## Architecture note (v0.1.0)

Images are **`linux/amd64` only** for the first release. The bundled
analysis toolchain is x86_64-only: gitleaks publishes `linux_x64`
tarballs, and Google publishes Android build-tools (zipalign /
apksigner) only for Linux x86_64. Publishing `linux/arm64` requires
pinning arm64 sources for those tools first — tracked as future work,
not a v0.1.0 blocker. Hosts on arm64 (Apple Silicon Docker Desktop,
ARM servers) should run the amd64 image through emulation or build
from source (`docker compose up --build` — note the tool downloads in
`docker/Dockerfile.app` are also x86_64-pinned, so source builds on
arm64 hosts need the same tool-sourcing work).

## Rolling back

A bad release is never "unpublished" — Docker Hub keeps old tags. To
point installs at the previous good version, bump `MOBARK_IMAGE_TAG`
in the compose docs / `.env` to the last known-good tag and, if the
breakage warrants it, force-push `latest` by re-tagging the good
commit:

```bash
git tag -f v0.1.0 <good-commit>
git push -f origin v0.1.0
```

(Docker Hub does not auto-delete `latest` on tag force-push; update
`latest` manually in the Docker Hub repo UI if you need to.)
