# MobARK backend image — python:3.11 per the tech stack decision.
#
# M1 adds the Android analysis toolchain. The JVM is copied from an
# eclipse-temurin JRE stage (both images are glibc-based) rather than
# pulling a second full base image. jadx, gitleaks and semgrep are always
# invoked as subprocesses, never imported, per the Apache-2.0 license
# posture.
FROM eclipse-temurin:17-jre-jammy AS jre

# --- frontend build (M5 Phase I: bundle the SPA into the image so the app
# serves the dashboard from the same origin in production) ---
FROM node:22-alpine AS frontend
WORKDIR /build
COPY frontend/ ./
RUN npm install --no-audit --no-fund && npm run build

FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    JAVA_HOME=/opt/java/openjdk \
    PATH="/opt/java/openjdk/bin:${PATH}"

# Release version baked into the image (surfaces via /api/v1/health and the
# FastAPI /docs title). The publish workflow sets it from the git tag;
# local builds default to the source version.
ARG MOBARK_VERSION=0.3.0
ENV MOBARK_VERSION=${MOBARK_VERSION}

# --- JVM for jadx (build-time sanity check) ---
COPY --from=jre /opt/java/openjdk /opt/java/openjdk
RUN java -version 2>&1 | head -1

WORKDIR /app

COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# --- toolchain download deps ---
# fonts-dejavu-core (M9 Phase C): the DejaVu Sans TTF bundled for Unicode
# PDF text - /usr/share/fonts/truetype/dejavu/DejaVuSans.ttf, the
# MOBARK_REPORT_FONT default. Bitstream-Vera-licensed (permissive), no
# license-posture change (see docs/licenses.md).
RUN apt-get update && apt-get install -y --no-install-recommends \
        unzip curl ca-certificates fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/* \
    && test -f /usr/share/fonts/truetype/dejavu/DejaVuSans.ttf

# --- jadx (JVM CLI; ~33 MB zip) ---
# Note: unzip -d only creates a single level, so /opt/mobark-tools must
# exist before extraction.
ARG JADX_VERSION=1.5.6
RUN mkdir -p /opt/mobark-tools && \
    curl -fsSL -o /tmp/jadx.zip \
        "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" \
    && unzip -q /tmp/jadx.zip -d /opt/mobark-tools/jadx \
    && rm /tmp/jadx.zip \
    && /opt/mobark-tools/jadx/bin/jadx --version

# --- gitleaks (Go binary) ---
# Arch-aware: gitleaks publishes per-arch tarballs (linux_x64 / linux_arm64).
# TARGETARCH is BuildKit's automatic platform arg - amd64 on x86_64 hosts /
# CI runners, arm64 on Apple Silicon and ARM servers (the multi-arch release
# workflow builds both). The legacy builder sets no TARGETARCH, so the step
# falls back to uname -m (x86_64 / aarch64).
ARG GITLEAKS_VERSION=8.30.1
ARG TARGETARCH
RUN set -eux; \
    TARGETARCH="${TARGETARCH:-$(uname -m)}"; \
    case "${TARGETARCH}" in \
        amd64|x86_64) GITLEAKS_ARCH="linux_x64" ;; \
        arm64|aarch64) GITLEAKS_ARCH="linux_arm64" ;; \
        *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/gitleaks.tar.gz \
        "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${GITLEAKS_ARCH}.tar.gz" \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && rm /tmp/gitleaks.tar.gz \
    && gitleaks version

# --- semgrep (OSS CLI, subprocess-only) ---
# The PyPI package is `semgrep` (there is no `semgrep-oss` distribution);
# the CLI is always invoked with `--oss-only --metrics off` by the wrapper,
# so only OSS functionality is used. Requires Python >= 3.10.
#
# semgrep is installed into its OWN venv: its dependency tree requires
# starlette>=0.49.1, which conflicts with the FastAPI 0.115.x pin
# (starlette<0.42) in requirements.txt, so the two cannot share one
# site-packages without breaking each other. The venv keeps the app
# environment intact and exposes `semgrep` on PATH via a symlink.
ARG SEMGREP_VERSION=1.172.0
RUN python -m venv /opt/semgrep-venv \
    && /opt/semgrep-venv/bin/pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}" \
    && ln -sf /opt/semgrep-venv/bin/semgrep /usr/local/bin/semgrep \
    && semgrep --version

# --- apktool (M8 edit & recompile; Apache-2.0; JVM CLI) ---
# Pinned official release jar + a tiny wrapper script — the jar runs under
# the bundled JRE (already on PATH). The wrapper keeps the Python subprocess
# wrapper calling a single binary, same as jadx/gitleaks. apktool bundles
# its own aapt2, so no Android SDK is needed for `d`/`b`.
ARG APKTOOL_VERSION=3.0.3
RUN mkdir -p /opt/mobark-tools/apktool && \
    curl -fsSL -o /opt/mobark-tools/apktool/apktool.jar \
        "https://github.com/iBotPeaches/apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar" \
    && printf '#!/bin/sh\nexec java -jar "$(dirname "$0")/apktool.jar" "$@"\n' \
        > /opt/mobark-tools/apktool/apktool \
    && chmod +x /opt/mobark-tools/apktool/apktool \
    && /opt/mobark-tools/apktool/apktool --version >/dev/null 2>&1

# --- Android build-tools: zipalign + apksigner (M8 rebuild pipeline) ---
# amd64-only: Google publishes build-tools ONLY for Linux x86_64 (no arm64
# build exists). On arm64 the download is skipped - the backend's rebuild
# pipeline then fails loudly with a clear "not bundled on this architecture"
# message, so edit & recompile (apktool b + zipalign + apksigner) is
# amd64-only in v0.1.x while everything else runs natively.
#
# Pinned build-tools download (Apache-2.0). The zip extracts to a version
# folder (e.g. android-15/); its contents are flattened into
# /opt/mobark-tools/build-tools/ so the apksigner launcher keeps its lib/
# next to the script and the Python wrapper resolves a stable path.
# zipalign runs BEFORE signing (v2+ schemes preserve alignment).
#
# URL scheme note (Aug 10 2026, Phase E gate): Google publishes current
# archives under build-tools_r<version>_linux.zip (UNDERSCORE). The old
# hyphen form (build-tools_r35.0.0-linux.zip) now 404s — and 35.0.0 was
# never published under the underscore scheme — so the pin is 35.0.1
# (the first 35.x with a live underscore archive; verified against
# repository2-3.xml + HEAD).
ARG BUILD_TOOLS_VERSION=35.0.1
ARG TARGETARCH
RUN set -eux; \
    TARGETARCH="${TARGETARCH:-$(uname -m)}"; \
    if [ "${TARGETARCH}" = "amd64" ] || [ "${TARGETARCH}" = "x86_64" ]; then \
        curl -fsSL -o /tmp/build-tools.zip \
            "https://dl.google.com/android/repository/build-tools_r${BUILD_TOOLS_VERSION}_linux.zip" \
        && mkdir -p /opt/mobark-tools/build-tools \
        && unzip -q /tmp/build-tools.zip -d /tmp/build-tools \
        && cp -r /tmp/build-tools/*/* /opt/mobark-tools/build-tools/ \
        && rm -rf /tmp/build-tools /tmp/build-tools.zip \
        && test -x /opt/mobark-tools/build-tools/zipalign \
        && test -x /opt/mobark-tools/build-tools/apksigner \
        && /opt/mobark-tools/build-tools/apksigner --version >/dev/null 2>&1; \
    else \
        echo "Skipping Android build-tools (zipalign/apksigner) on ${TARGETARCH}: Google publishes Linux x86_64 only - edit & recompile is amd64-only"; \
    fi

COPY backend/ /app/

# The built SPA lands at /frontend/dist — config default `../frontend/dist`
# relative to WORKDIR /app — so main.py's conditional mount serves it.
COPY --from=frontend /build/dist /frontend/dist

ENV MOBARK_TOOLS_DIR=/opt/mobark-tools

EXPOSE 8000

# Compose overrides the command for the `worker` service.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
