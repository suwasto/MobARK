"""Connectivity checks + model listing for configured backends.

The contract of this module: ``check_backend`` NEVER raises — a broken or
unreachable backend yields a ``BackendHealth`` result the API/CLI can render
(red dot in M5) without crashing a request or a scan.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx
import litellm

from app.model.backends import ModelBackend
from app.model.providers import models_url

MODELS_TIMEOUT = 3.0
PROBE_TIMEOUT = 5.0


@dataclass
class BackendHealth:
    backend_id: str
    reachable: bool
    status: str = "unknown"  # "ok" | "unreachable" | "unknown"
    latency_ms: int | None = None
    models: list[str] = field(default_factory=list)
    model_source: str = "none"  # "live" | "suggested" | "unavailable" | "none"
    probe_model: str | None = None
    probe_ok: bool | None = None
    error: str | None = None
    checked_at: datetime = field(default_factory=lambda: datetime.now(UTC))


def list_models(
    backend: ModelBackend, timeout: float = MODELS_TIMEOUT
) -> tuple[list[str], str, str | None]:
    """List models served by a backend.

    Returns ``(models, source, error)`` where ``source`` is:
    - ``"live"`` — OpenAI-compatible ``GET {base_url}/models`` succeeded
    - ``"suggested"`` — provider has no live endpoint (Anthropic) → static list
    - ``"unavailable"`` — listing failed (server down, bad key, …) → ``[]``
    Never raises.
    """
    url = models_url(backend.provider, backend.base_url)
    if url is None:
        return list(backend.provider.suggested_models), "suggested", None
    headers = {}
    if backend.api_key and backend.kind != "local":
        # Local servers (Ollama/LM Studio) accept a dummy key but don't need
        # it on the listing call; don't send placeholder auth headers.
        headers["Authorization"] = f"Bearer {backend.api_key}"
    try:
        resp = httpx.get(url, headers=headers, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        models = [m.get("id") for m in data.get("data", []) if isinstance(m, dict) and m.get("id")]
        return models, "live", None
    except Exception as exc:
        return [], "unavailable", f"{type(exc).__name__}: {exc}"


def _probe_completion(backend: ModelBackend, model: str, timeout: float = PROBE_TIMEOUT) -> bool:
    """Cheap ``max_tokens=1`` completion as the runtime usability probe."""
    try:
        litellm.completion(
            model=f"{backend.provider.model_prefix}{model}",
            messages=[{"role": "user", "content": "ping"}],
            api_base=backend.base_url or None,
            api_key=backend.api_key or None,
            max_tokens=1,
            timeout=timeout,
        )
        return True
    except Exception:
        return False


def check_backend(backend: ModelBackend, *, probe: bool = True) -> BackendHealth:
    """Reachability + model listing (and an optional completion probe).

    ``probe=False`` (used by the lightweight ``GET /backends``) skips the
    completion round-trip so listing a few backends stays fast.
    """
    start = time.monotonic()
    models, source, list_error = list_models(backend)
    latency_ms = int((time.monotonic() - start) * 1000)

    probe_model = backend.model or (models[0] if models else None)
    probe_ok: bool | None = None
    error: str | None = None

    if source == "live":
        reachable, status = True, "ok"
        if probe and probe_model:
            probe_ok = _probe_completion(backend, probe_model)
            if probe_ok is False:
                error = f"model probe failed for {probe_model!r}"
    elif source == "unavailable":
        # The listing call itself failed — connection-level trouble; probing
        # would just burn time against a server that isn't answering.
        reachable, status = False, "unreachable"
        error = list_error or "model listing failed (is the server running?)"
    else:  # "suggested": provider has no live endpoint (Anthropic, custom)
        if probe_model is None:
            reachable, status = False, "unknown"
            error = "cannot verify: no model configured"
        elif not probe:
            reachable, status = False, "unknown"
            error = "no live listing endpoint; run the full test (POST /test) to verify"
        else:
            probe_ok = _probe_completion(backend, probe_model)
            reachable = bool(probe_ok)
            status = "ok" if probe_ok else "unreachable"
            error = None if probe_ok else "completion probe failed (key, model, or connectivity)"

    return BackendHealth(
        backend_id=backend.id,
        reachable=reachable,
        status=status,
        latency_ms=latency_ms,
        models=models,
        model_source=source,
        probe_model=probe_model,
        probe_ok=probe_ok,
        error=error,
    )
