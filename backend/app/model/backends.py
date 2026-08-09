"""Model backend config store — env-seeded, runtime-editable JSON in data_dir.

Owner decisions (Aug 5, 2026):
- Keys are stored plaintext in ``model_backends.json`` with ``0600`` perms;
  encryption-at-rest is deferred to M5 (already an M5 checklist item).
- No hard default chat model: ``model`` seeds blank; the user picks one from
  what the backend actually serves (``MASA_DEFAULT_CHAT_MODEL`` can seed it).
- Keys are never logged: ``api_key`` is excluded from the dataclass repr and
  never returned by the API (only ``has_api_key``).
"""
from __future__ import annotations

import dataclasses
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from app.config import Settings, settings
from app.model.providers import PROVIDERS, Provider

CONFIG_FILENAME = "model_backends.json"
CONFIG_MODE = 0o600

# Settings field per provider: seeded base URL / API key.
_BASE_URL_FIELD = {
    "ollama": "ollama_base_url",
    "lm-studio": "lm_studio_base_url",
    "openai": "openai_base_url",
    "anthropic": "anthropic_base_url",
    "deepseek": "deepseek_base_url",
    "openrouter": "openrouter_base_url",
    "gemini": "gemini_base_url",
}
_API_KEY_FIELD = {
    "openai": "openai_api_key",
    "anthropic": "anthropic_api_key",
    "deepseek": "deepseek_api_key",
    "openrouter": "openrouter_api_key",
    "gemini": "gemini_api_key",
}


@dataclass
class ModelBackend:
    id: str
    provider_id: str
    name: str
    kind: str  # "local" | "byok" | "custom"
    base_url: str
    model: str = ""  # configured chat model; blank = pick from served models
    api_key: str | None = field(default=None, repr=False)
    enabled: bool = True

    @property
    def provider(self) -> Provider:
        return PROVIDERS[self.provider_id]

    @property
    def local(self) -> bool:
        """True only for local inference backends — the "Local-only" indicator
        (M5) must flip off the moment a BYOK/custom backend is enabled."""
        return self.kind == "local"

    def has_api_key(self) -> bool:
        return bool(self.api_key)


def _fake_backend(cfg: Settings) -> ModelBackend:
    """The dev-only fake backend (M6 follow-up) — the one construction site
    shared by seeding and read-time reconciliation so the two can't drift."""
    from app.model.fake import FAKE_MODEL

    return ModelBackend(
        id="fake",
        provider_id="fake",
        name="Fake (dev demo)",
        kind="local",
        base_url="",
        model=FAKE_MODEL,
        api_key="fake",
    )


def _seed_backends(cfg: Settings) -> list[ModelBackend]:
    """Build the initial backend list from the provider table + env/`Settings`.

    Local backends are always seeded (they need no key). BYOK backends are
    seeded ONLY when an API key is configured via env/`Settings` — a keyless
    cloud entry is unusable and only confuses the Settings UI (owner
    decision, Aug 8 2026): add cloud providers with a key via the BYOK menu
    (POST /api/v1/model/backends) instead.

    The dev-only ``fake`` backend (M6 follow-up) is seeded ONLY when
    ``cfg.fake_model_enabled`` (MASA_FAKE_MODEL=1) — it must never appear in
    a real deployment. It is inserted FIRST so ``pick_chat_backend`` resolves
    it deterministically: with the knob on, chat/explain/summary all demo
    against the fake without touching a real model.
    """
    seeded: list[ModelBackend] = []
    if cfg.fake_model_enabled:
        seeded.append(_fake_backend(cfg))
    for provider_id, provider in PROVIDERS.items():
        if provider.kind == "custom":
            # Custom backends are user-created via the API, not seeded.
            continue
        if provider_id == "fake":
            # Dev-only: seeded above, gated by the MASA_FAKE_MODEL knob.
            continue
        base_url = getattr(cfg, _BASE_URL_FIELD.get(provider_id, ""), "") or (
            provider.default_base_url
        )
        if provider.kind == "local":
            api_key = provider.dummy_key
        else:
            api_key = getattr(cfg, _API_KEY_FIELD.get(provider_id, ""), "") or None
            if api_key is None:
                # No real key configured — don't seed an unusable cloud
                # entry. It appears only when added via the BYOK menu.
                continue
        seeded.append(
            ModelBackend(
                id=provider_id,
                provider_id=provider_id,
                name=provider.name,
                kind=provider.kind,
                base_url=base_url,
                model=cfg.default_chat_model or "",
                api_key=api_key,
            )
        )
    return seeded


class BackendStore:
    """JSON-backed store of configured backends.

    First read seeds the file from the provider table + ``Settings``; every
    later read honors the file as the source of truth (runtime edits stick).
    """

    def __init__(self, data_dir: Path, settings_obj: Settings | None = None):
        self.data_dir = Path(data_dir)
        self.path = self.data_dir / CONFIG_FILENAME
        self._settings = settings_obj or settings

    # ---- read / seed -----------------------------------------------------

    def read(self) -> list[ModelBackend]:
        if not self.path.is_file():
            backends = _seed_backends(self._settings)
            self._write(backends)
            return backends
        try:
            raw = json.loads(self.path.read_text())
        except (json.JSONDecodeError, OSError):
            # Corrupt/illegible store: reseed rather than crash a request.
            backends = _seed_backends(self._settings)
            self._write(backends)
            return backends
        backends: list[ModelBackend] = []
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            try:
                backend = ModelBackend(**{k: v for k, v in entry.items() if k in _backend_fields()})
            except (TypeError, ValueError):
                continue  # drop entries that no longer parse
            if backend.provider_id not in PROVIDERS:
                continue  # drop entries for providers we no longer know
            backends.append(backend)
        backends = self._reconcile_fake(backends)
        return backends

    def get(self, backend_id: str) -> ModelBackend | None:
        return next((b for b in self.read() if b.id == backend_id), None)

    # ---- write / upsert --------------------------------------------------

    def upsert(
        self,
        backend_id: str,
        *,
        base_url: str | None = None,
        model: str | None = None,
        api_key: str | None = None,
        enabled: bool | None = None,
    ) -> ModelBackend:
        """Update one backend's config and persist. An empty ``api_key`` clears
        the stored key. Raises KeyError for unknown ids."""
        backends = self.read()
        backend = next((b for b in backends if b.id == backend_id), None)
        if backend is None:
            raise KeyError(f"unknown backend {backend_id!r}")
        if base_url is not None:
            backend.base_url = base_url
        if model is not None:
            backend.model = model
        if api_key is not None:
            backend.api_key = api_key or None
        if enabled is not None:
            backend.enabled = enabled
        self._write(backends)
        return backend

    def add(self, backend: ModelBackend) -> None:
        """Append a new backend (custom / re-activated BYOK) and persist.

        Raises ValueError when the id already exists — the API maps it to
        409 so the caller can switch to PUT/upsert semantics.
        """
        backends = self.read()
        if any(b.id == backend.id for b in backends):
            raise ValueError(f"backend {backend.id!r} already exists")
        backends.append(backend)
        self._write(backends)

    def remove(self, backend_id: str) -> bool:
        """Remove a backend entirely; returns False when unknown.

        A later POST can re-add it (BYOK) — the store file, not the seed
        table, is the source of truth after first read.
        """
        backends = self.read()
        remaining = [b for b in backends if b.id != backend_id]
        if len(remaining) == len(backends):
            return False
        self._write(remaining)
        return True

    def _write(self, backends: list[ModelBackend]) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        payload = json.dumps([dataclasses.asdict(b) for b in backends], indent=2) + "\n"
        tmp = self.path.with_name(f"{self.path.name}.tmp")
        tmp.write_text(payload)
        os.chmod(tmp, CONFIG_MODE)
        tmp.replace(self.path)
        # The chmod above lands on the temp inode; re-assert on the final path.
        try:
            os.chmod(self.path, CONFIG_MODE)
        except OSError:
            pass

    def _reconcile_fake(self, backends: list[ModelBackend]) -> list[ModelBackend]:
        """Keep the dev-only fake backend in lockstep with the config knob.

        The store file is the source of truth after first read, so flipping
        MASA_FAKE_MODEL later must still take effect: the knob ON adds a
        missing fake entry, the knob OFF removes a stale one — each case
        persists the reconciled list (idempotent, so a converged store never
        rewrites itself).
        """
        has_fake = any(b.id == "fake" for b in backends)
        if self._settings.fake_model_enabled and not has_fake:
            backends.insert(0, _fake_backend(self._settings))
            self._write(backends)
        elif not self._settings.fake_model_enabled and has_fake:
            backends = [b for b in backends if b.id != "fake"]
            self._write(backends)
        return backends


def _backend_fields() -> set[str]:
    return {f.name for f in dataclasses.fields(ModelBackend)}


def get_store() -> BackendStore:
    """Store over the app's data dir — used by API routes and the CLI."""
    return BackendStore(settings.data_dir, settings)
