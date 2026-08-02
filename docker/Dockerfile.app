# MASA backend image — python:3.11 per the tech stack decision.
# M1 will extend this image with a JVM (jadx) and the analysis CLIs
# (apktool, gitleaks, semgrep); those tools are always invoked as
# subprocesses, never imported, per the MIT license posture.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY backend/ /app/

EXPOSE 8000

# Compose overrides the command for the `worker` service.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
