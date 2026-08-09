"""M7 search backend config store — env-seeded, runtime-editable JSON.

Mirrors ``model/backends.py`` (M3) in shape and semantics:
``search_backends.json`` in data_dir with ``0600`` perms, env-seeded from
``MASA_SEARXNG_BASE_URL``, runtime-editable.

**One Active engine (radio)** — owner decision, Aug 9: exactly one search
backend may be Active at a time. ``enable_only`` persists that invariant
server-side so no client (UI or raw API) can ever leave two engines Active —
the same determinism ``pick_chat_backend`` gives the model layer. ``active()``
is the single enabled backend (``None`` when all are off); the agent's web
tools are gated on it. ``order`` is reserved for a future priority fallback
chain (SearXNG down → Brave) — a resolver-only change, no migration.
"""
from __future__ import annotations

import dataclasses
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from app.config import Settings, settings
from app.search.providers import SEARCH_PROVIDERS, SearchProvider

CONFIG_FILENAME = "search_backends.json"
CONFIG_MODE = 0o600

_SEARXNG_URL_FIELD = "searxng_base_url"
# Settings field per KEYED provider: the env var that seeds its API key
# (MASA_BRAVE_API_KEY etc. — pydantic-settings derives the names from the
# field names). Keyed providers seed only when a real key is set; the
# Settings form is the runtime path.
_KEYED_KEY_FIELD = {
    "brave": "brave_api_key",
    "serper": "serper_api_key",
    "mojeek": "mojeek_api_key",
}


@dataclass
class SearchBackend:
    id: str
    provider_id: str
    name: str
    kind: str  # "bundled" | "custom"
    base_url: str
    # Active/Inactive (the radio): exactly one backend enabled at a time.
    enabled: bool = True
    # Reserved for a future priority fallback chain — unused in v1.
    order: int = 0
    # Future keyed engines (Brave/Serper/Mojeek). Never returned by the API
    # (only ``has_api_key``), same honesty rule as model backends.
    api_key: str | None = field(default=None, repr=False)

    @property
    def provider(self) -> SearchProvider:
        return SEARCH_PROVIDERS[self.provider_id]

    def has_api_key(self) -> bool:
        return bool(self.api_key)


def _seed_backends(cfg: Settings) -> list[SearchBackend]:
    """The initial store: the bundled SearXNG backend, seeded **enabled**
    (mirroring local model backends — it is the bundled default; the user can
    turn it off), plus any KEYED provider (Brave/Serper/Mojeek) whose API key
    is set via env/Settings — seeded **disabled** so the radio keeps the
    bundled engine Active by default (mirroring the model BYOK rule: no
    unusable keyless entry is ever seeded; the Settings form is the runtime
    path). Custom instances are never seeded — user-created via the API,
    exactly like model ``custom`` backends."""
    seeded = [
        SearchBackend(
            id="searxng",
            provider_id="searxng",
            name=SEARCH_PROVIDERS["searxng"].name,
            kind=SEARCH_PROVIDERS["searxng"].kind,
            base_url=getattr(cfg, _SEARXNG_URL_FIELD, "")
            or SEARCH_PROVIDERS["searxng"].default_base_url,
            enabled=True,
        )
    ]
    for provider_id, provider in SEARCH_PROVIDERS.items():
        if provider.kind != "keyed":
            continue
        api_key = getattr(cfg, _KEYED_KEY_FIELD.get(provider_id, ""), "") or None
        if api_key is None:
            continue  # no real key configured — add via the Settings form
        seeded.append(
            SearchBackend(
                id=provider_id,
                provider_id=provider_id,
                name=provider.name,
                kind=provider.kind,
                base_url=provider.default_base_url,
                enabled=False,  # radio: the bundled engine stays Active
                api_key=api_key,
            )
        )
    return seeded


class SearchStore:
    """JSON-backed store of configured search backends.

    First read seeds the file from the provider table + ``Settings``; every
    later read honors the file as the source of truth (runtime edits stick).
    """

    def __init__(self, data_dir: Path, settings_obj: Settings | None = None):
        self.data_dir = Path(data_dir)
        self.path = self.data_dir / CONFIG_FILENAME
        self._settings = settings_obj or settings

    # ---- read / seed -----------------------------------------------------

    def read(self) -> list[SearchBackend]:
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
        backends: list[SearchBackend] = []
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            try:
                backend = SearchBackend(
                    **{k: v for k, v in entry.items() if k in _backend_fields()}
                )
            except (TypeError, ValueError):
                continue  # drop entries that no longer parse
            if backend.provider_id not in SEARCH_PROVIDERS:
                continue  # drop entries for providers we no longer know
            backends.append(backend)
        return backends

    def get(self, backend_id: str) -> SearchBackend | None:
        return next((b for b in self.read() if b.id == backend_id), None)

    # ---- radio semantics ---------------------------------------------------

    def active(self) -> SearchBackend | None:
        """The one enabled backend — the engine the agent searches with
        (``None`` when all backends are off)."""
        return next((b for b in self.read() if b.enabled), None)

    def enable_only(self, backend_id: str) -> SearchBackend:
        """Enable exactly ``backend_id`` and disable every other backend —
        the radio invariant, persisted. Raises KeyError for unknown ids.

        Delegates to ``upsert(enabled=True)`` so the radio has ONE
        implementation (the Settings toggle, the raw API PUT, and this
        primitive can never drift).
        """
        return self.upsert(backend_id, enabled=True)

    # ---- write / upsert --------------------------------------------------

    def upsert(
        self,
        backend_id: str,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        enabled: bool | None = None,
    ) -> SearchBackend:
        """Update one backend and persist. ``enabled=True`` goes through the
        radio semantics (``enable_only``) so two backends can never both be
        Active; ``enabled=False`` only turns this one off. An empty
        ``api_key`` clears the stored key. Raises KeyError for unknown ids."""
        backends = self.read()
        backend = next((b for b in backends if b.id == backend_id), None)
        if backend is None:
            raise KeyError(f"unknown search backend {backend_id!r}")
        if base_url is not None:
            backend.base_url = base_url
        if api_key is not None:
            backend.api_key = api_key or None
        if enabled is not None:
            if enabled:
                for b in backends:
                    b.enabled = b.id == backend_id
            else:
                backend.enabled = False
        self._write(backends)
        return backend

    def add(self, backend: SearchBackend) -> None:
        """Append a new backend and persist. The radio invariant holds on add
        too: a newly-added enabled backend disables everything else.

        Raises ValueError when the id already exists — the API maps it to
        409 so the caller can switch to PUT/upsert semantics.
        """
        backends = self.read()
        if any(b.id == backend.id for b in backends):
            raise ValueError(f"search backend {backend.id!r} already exists")
        if backend.enabled:
            for b in backends:
                b.enabled = False
        backends.append(backend)
        self._write(backends)

    def remove(self, backend_id: str) -> bool:
        """Remove a backend entirely; returns False when unknown.

        The bundled ``searxng`` entry is deletable (the store file, not the
        seed table, is the source of truth after first read).
        """
        backends = self.read()
        remaining = [b for b in backends if b.id != backend_id]
        if len(remaining) == len(backends):
            return False
        self._write(remaining)
        return True

    def _write(self, backends: list[SearchBackend]) -> None:
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


def _backend_fields() -> set[str]:
    return {f.name for f in dataclasses.fields(SearchBackend)}


def get_search_store() -> SearchStore:
    """Store over the app's data dir — used by API routes, the agent tools,
    and chat gating."""
    return SearchStore(settings.data_dir, settings)
