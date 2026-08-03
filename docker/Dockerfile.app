# MASA backend image — python:3.11 per the tech stack decision.
#
# M1 adds the Android analysis toolchain. The JVM is copied from an
# eclipse-temurin JRE stage (both images are glibc-based) rather than
# pulling a second full base image. jadx, gitleaks and semgrep are always
# invoked as subprocesses, never imported, per the Apache-2.0 license
# posture.
FROM eclipse-temurin:17-jre-jammy AS jre

FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    JAVA_HOME=/opt/java/openjdk \
    PATH="/opt/java/openjdk/bin:${PATH}"

# --- JVM for jadx (build-time sanity check) ---
COPY --from=jre /opt/java/openjdk /opt/java/openjdk
RUN java -version 2>&1 | head -1

WORKDIR /app

COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# --- toolchain download deps ---
RUN apt-get update && apt-get install -y --no-install-recommends \
        unzip curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# --- jadx (JVM CLI; ~33 MB zip) ---
# Note: unzip -d only creates a single level, so /opt/masa-tools must
# exist before extraction.
ARG JADX_VERSION=1.5.6
RUN mkdir -p /opt/masa-tools && \
    curl -fsSL -o /tmp/jadx.zip \
        "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" \
    && unzip -q /tmp/jadx.zip -d /opt/masa-tools/jadx \
    && rm /tmp/jadx.zip \
    && /opt/masa-tools/jadx/bin/jadx --version

# --- gitleaks (Go binary) ---
ARG GITLEAKS_VERSION=8.30.1
RUN curl -fsSL -o /tmp/gitleaks.tar.gz \
        "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
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

COPY backend/ /app/

ENV MASA_TOOLS_DIR=/opt/masa-tools

EXPOSE 8000

# Compose overrides the command for the `worker` service.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
