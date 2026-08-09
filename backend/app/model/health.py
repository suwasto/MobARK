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
from app.model.client import model_arch_hint
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


def _list_gemini_models(
    backend: ModelBackend, url: str, timeout: float
) -> tuple[list[str], str, str | None]:
    """Gemini's ``models.list`` — live model discovery, not a hardcoded list.

    Request/auth are NOT OpenAI-compatible: the key goes in the query string
    (``?key=``) and the response is ``{"models": [{"name": "models/..."}]}``
    with the ``models/`` prefix stripped and entries filtered to those that
    support ``generateContent`` (embeddings etc. are not chat models; tuned
    models live under ``tunedModels/`` in a separate endpoint).

    On ANY failure (bad key, network, 4xx) or an empty result, falls back to
    the provider's curated list with source ``"suggested"`` — the backend
    stays usable and the completion probe surfaces connectivity issues — so
    a Google-side deprecation or outage never hard-breaks the app.
    """
    # models.list is paginated (nextPageToken) but the default page size
    # covers every current model — revisit only if Google ever grows the
    # catalog past it.
    fallback = list(backend.provider.suggested_models)
    params = {"key": backend.api_key} if backend.api_key else {}
    try:
        resp = httpx.get(url, params=params, timeout=timeout)
        resp.raise_for_status()
        models: list[str] = []
        for entry in resp.json().get("models", []):
            if not isinstance(entry, dict):
                continue
            name = entry.get("name") or ""
            if not name.startswith("models/"):
                continue
            methods = entry.get("supportedGenerationMethods") or []
            if "generateContent" not in methods:
                continue
            models.append(name[len("models/") :])
        if models:
            return models, "live", None
        return fallback, "suggested", None
    except Exception as exc:
        return fallback, "suggested", f"{type(exc).__name__}: {exc}"


def _list_anthropic_models(
    backend: ModelBackend, url: str, timeout: float
) -> tuple[list[str], str, str | None]:
    """Anthropic's ``List Models`` — live model discovery like Gemini.

    Anthropic ships an OpenAI-*shaped* response (``{"data": [{"id": ...}]}``)
    but with its own auth: ``x-api-key`` + ``anthropic-version`` headers (no
    Bearer). The catalog fits one page at ``limit=100`` (default is 20), so
    pagination is skipped. On any failure (bad key, offline) or an empty
    result, falls back to the curated list with source ``"suggested"`` —
    never ``[]``.
    """
    fallback = list(backend.provider.suggested_models)
    if not backend.api_key:
        return fallback, "suggested", "anthropic listing requires an API key"
    headers = {
        "x-api-key": backend.api_key,
        "anthropic-version": "2023-06-01",
    }
    try:
        resp = httpx.get(url, headers=headers, params={"limit": 100}, timeout=timeout)
        resp.raise_for_status()
        models = [
            m.get("id")
            for m in resp.json().get("data", [])
            if isinstance(m, dict) and m.get("id")
        ]
        if models:
            return models, "live", None
        return fallback, "suggested", None
    except Exception as exc:
        return fallback, "suggested", f"{type(exc).__name__}: {exc}"


def list_models(
    backend: ModelBackend, timeout: float = MODELS_TIMEOUT
) -> tuple[list[str], str, str | None]:
    """List models served by a backend.

    Returns ``(models, source, error)`` where ``source`` is:
    - ``"live"`` — a live listing succeeded (OpenAI-compatible ``GET
      {base_url}/models``, Anthropic's ``List Models``, or Gemini's
      ``GET /v1beta/models``)
    - ``"suggested"`` — a live fetch failed or returned empty → static
      curated fallback (providers that carry one never degrade to ``[]``;
      the completion probe surfaces connectivity)
    - ``"unavailable"`` — listing failed with no fallback → ``[]``
    Never raises.
    """
    url = models_url(backend.provider, backend.base_url)
    if url is None:
        return list(backend.provider.suggested_models), "suggested", None
    if backend.provider.list_style == "gemini":
        return _list_gemini_models(backend, url, timeout)
    if backend.provider.list_style == "anthropic":
        return _list_anthropic_models(backend, url, timeout)
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


def _probe_error(exc: Exception) -> str:
    """Human-readable probe failure, with an actionable hint when the model
    server rejected the model's own architecture (e.g. an old Ollama build
    against a newer model)."""
    return model_arch_hint(f"{type(exc).__name__}: {exc}")


def _probe_completion(
    backend: ModelBackend, model: str, timeout: float = PROBE_TIMEOUT
) -> tuple[bool, str | None]:
    """Cheap ``max_tokens=1`` completion as the runtime usability probe.

    Returns ``(ok, error)`` — on failure the error carries the upstream
    message so the Settings probe shows *why* it failed (model not loadable,
    bad key, …) instead of a bare false. The dev-only fake backend (M6
    follow-up) always probes ok — it never contacts a server.
    """
    from app.model.fake import is_fake

    if is_fake(backend):
        return True, None
    try:
        completion_kwargs: dict = {
            "model": f"{backend.provider.model_prefix}{model}",
            "messages": [{"role": "user", "content": "ping"}],
            "api_base": backend.base_url or None,
            "api_key": backend.api_key or None,
            "max_tokens": 1,
            "timeout": timeout,
        }
        if backend.provider_id == "ollama":
            # Same reasoning-disable as client.chat — a thinking model would
            # burn the 5s probe on a <think> block instead of answering.
            completion_kwargs["extra_body"] = {"think": False}
        litellm.completion(**completion_kwargs)
        return True, None
    except Exception as exc:
        return False, _probe_error(exc)


def check_backend(backend: ModelBackend, *, probe: bool = True) -> BackendHealth:
    """Reachability + model listing (and an optional completion probe).

    ``probe=False`` (used by the lightweight ``GET /backends``) skips the
    completion round-trip so listing a few backends stays fast.
    """
    start = time.monotonic()
    models, source, list_error = list_models(backend)
    latency_ms = int((time.monotonic() - start) * 1000)

    # A configured model is probed exactly. Without one, prefer the provider's
    # curated ∩ live entries — Google's models.list still lists deprecated IDs
    # (gemini-2.5-flash 404s on use for new keys), so the raw first entry is a
    # bad default; the curated list is the known-current seed.
    if backend.model:
        probe_model = backend.model
    elif models:
        probe_model = next(
            (m for m in backend.provider.suggested_models if m in models), models[0]
        )
    else:
        probe_model = None
    probe_ok: bool | None = None
    error: str | None = None

    if source == "live":
        reachable, status = True, "ok"
        if probe and probe_model:
            if backend.model:
                # User-picked model: probe exactly, fail loudly on a broken choice.
                probe_ok, probe_err = _probe_completion(backend, probe_model)
            else:
                # No model configured: walk the curated ∩ live candidates
                # (small, known-current) so a deprecated entry at the top of
                # the live list can't make the whole backend look broken.
                candidates = [
                    m for m in backend.provider.suggested_models if m in models
                ] or [probe_model]
                probe_ok = None
                probe_err: str | None = None
                for cand in candidates:
                    probe_ok, probe_err = _probe_completion(backend, cand)
                    if probe_ok:
                        probe_model = cand
                        break
            if probe_ok is False:
                error = f"model probe failed for {probe_model!r}: {probe_err}"
    elif source == "unavailable":
        # The listing call itself failed — connection-level trouble; probing
        # would just burn time against a server that isn't answering.
        reachable, status = False, "unreachable"
        # Neutral phrasing on purpose: for cloud BYOK backends there is no
        # local server to run — "is the server running?" only fits local ones
        # (owner review, Aug 7).
        error = list_error or "model listing failed"
    else:  # "suggested": provider has no live endpoint (Anthropic) or a live
        # fetch fell back to the curated list (Gemini listing failure).
        if probe_model is None:
            reachable, status = False, "unknown"
            error = "cannot verify: no model configured"
        elif not probe:
            reachable, status = False, "unknown"
            # With a fallback error we know the endpoint EXISTS but the fetch
            # failed (bad key, offline) — don't tell the user it doesn't.
            error = (
                f"live model listing failed: {list_error}; "
                "run the full test (POST /test) to verify"
                if list_error
                else "no live listing endpoint; run the full test (POST /test) to verify"
            )
        else:
            # With a configured model, probe exactly that one. Without one
            # (the common Gemini/Anthropic case), walk the curated list so a
            # single deprecation (Google 404s retired model IDs for new keys)
            # can't mark the whole backend unreachable — the first model that
            # answers is recorded as the probe target.
            candidates = [probe_model] if backend.model else models
            probe_ok = None
            probe_err: str | None = None
            for cand in candidates:
                probe_ok, probe_err = _probe_completion(backend, cand)
                if probe_ok:
                    probe_model = cand
                    break
            reachable = bool(probe_ok)
            status = "ok" if probe_ok else "unreachable"
            error = (
                None
                if probe_ok
                else f"completion probe failed (key, model, or connectivity): {probe_err}"
            )

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
