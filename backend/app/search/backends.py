"""M7 search backend config store - env-seeded, runtime-editable JSON.

Mirrors ``model/backends.py`` (M3) in shape and semantics:
``search_backends.json`` in data_dir with ``0600`` perms, env-seeded from
``MOBARK_SEARXNG_BASE_URL``, runtime-editable.

**One Active engine (radio)** - owner decision, Aug 9: exactly one search
backend may be Active at a time. ``enable_only`` persists that invariant
server-side so no client (UI or raw API) can ever leave two engines Active -
the same determinism ``pick_chat_backend`` gives the model layer. ``active()``
is the single enabled backend (``None`` when all are off); the agent's web
tools are gated on it. ``order`` is reserved for a future priority fallback
chain (SearXNG down → Brave) - a resolver-only change, no migration.
"""
from __future__ import annotations

import dataclasses
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from app.auth import vault
from app.config import Settings, settings
from app.request_ctx import current_master_key, current_user_id
from app.search.providers import SEARCH_PROVIDERS, SearchProvider

CONFIG_FILENAME = "search_backends.json"
CONFIG_MODE = 0o600
# Per-user stores live under data_dir/users/<uid>/ (M9.1 decision 3) -
# mirrors model/backends.py::USER_STORE_DIR.
USER_STORE_DIR = "users"

_SEARXNG_URL_FIELD = "searxng_base_url"
# Settings field per KEYED provider: the env var that seeds its API key
# (MOBARK_BRAVE_API_KEY etc. - pydantic-settings derives the names from the
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
    # Reserved for a future priority fallback chain - unused in v1.
    order: int = 0
    # Future keyed engines (Brave/Serper/Mojeek). Never returned by the API
    # (only ``has_api_key``), same honesty rule as model backends.
    api_key: str | None = field(default=None, repr=False)

    @property
    def provider(self) -> SearchProvider:
        return SEARCH_PROVIDERS[self.provider_id]

    def has_api_key(self) -> bool:
        return bool(self.api_key)

    def resolved_api_key(self) -> str | None:
        """The plaintext key for outbound requests. A vault blob is
        decrypted with the session's master key (``request_ctx``); a
        plaintext value (SYSTEM store - owner env keys, auth-off mode)
        passes through untouched. None when the vault is locked - the key
        exists at rest but is not usable in this context."""
        value = self.api_key
        if not value:
            return None
        if vault.is_vault_blob(value):
            mk = current_master_key.get()
            if mk is None:
                return None
            return vault.unwrap_secret(mk, value)
        return value


def _seed_backends(cfg: Settings) -> list[SearchBackend]:
    """The initial store: the bundled SearXNG backend, seeded **enabled**
    (mirroring local model backends - it is the bundled default; the user can
    turn it off), plus any KEYED provider (Brave/Serper/Mojeek) whose API key
    is set via env/Settings - seeded **disabled** so the radio keeps the
    bundled engine Active by default (mirroring the model BYOK rule: no
    unusable keyless entry is ever seeded; the Settings form is the runtime
    path). Custom instances are never seeded - user-created via the API,
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
            continue  # no real key configured - add via the Settings form
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

    M9.1 (Phase C): an optional ``user_id`` scopes the store to
    ``data_dir/users/<uid>/search_backends.json``, seeded on first read from
    the SYSTEM layer (the root file's current contents, else a fresh env
    seed) - the user file then becomes that user's source of truth. The
    one-Active radio and per-user keys are thereby isolated per user.
    """

    def __init__(
        self,
        data_dir: Path,
        settings_obj: Settings | None = None,
        user_id: int | None = None,
    ):
        self.data_dir = Path(data_dir)
        self.user_id = user_id
        if user_id is not None:
            self.path = (
                self.data_dir / USER_STORE_DIR / str(user_id) / CONFIG_FILENAME
            )
        else:
            self.path = self.data_dir / CONFIG_FILENAME
        self._settings = settings_obj or settings

    # ---- read / seed -----------------------------------------------------

    def _seed_source(self) -> list[SearchBackend]:
        """The initial list for a store with no file yet. For a USER store
        this is the SYSTEM layer's current contents (inherit the machine
        config); for the system store itself, a fresh env seed."""
        if self.user_id is not None:
            system_path = self.data_dir / CONFIG_FILENAME
            if system_path.is_file():
                return SearchStore(self.data_dir, self._settings).read()
        return _seed_backends(self._settings)

    def read(self) -> list[SearchBackend]:
        if not self.path.is_file():
            backends = self._seed_source()
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
        # Lazy migration: a per-user store still holding plaintext keys is
        # encrypted in place now that the vault is unlocked (the rewrite
        # replaces the old plaintext bytes entirely).
        if (
            self.user_id is not None
            and current_master_key.get() is not None
            and any(
                b.api_key and not vault.is_vault_blob(b.api_key) for b in backends
            )
        ):
            self._write(backends)
        return backends

    def get(self, backend_id: str) -> SearchBackend | None:
        return next((b for b in self.read() if b.id == backend_id), None)

    # ---- radio semantics ---------------------------------------------------

    def active(self) -> SearchBackend | None:
        """The one enabled backend - the engine the agent searches with
        (``None`` when all backends are off)."""
        return next((b for b in self.read() if b.enabled), None)

    def enable_only(self, backend_id: str) -> SearchBackend:
        """Enable exactly ``backend_id`` and disable every other backend -
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
            if api_key:
                self._require_unlocked()
                backend.api_key = self._protect_api_key(api_key)
            else:
                backend.api_key = None
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

        Raises ValueError when the id already exists - the API maps it to
        409 so the caller can switch to PUT/upsert semantics.
        """
        backends = self.read()
        if any(b.id == backend.id for b in backends):
            raise ValueError(f"search backend {backend.id!r} already exists")
        if backend.api_key:
            self._require_unlocked()
            backend.api_key = self._protect_api_key(backend.api_key)
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

    # ---- M9.1 vault: at-rest protection -----------------------------------
    # Identical to model/backends.py: per-user stores encrypt api_key values
    # under the session's master key; the SYSTEM store stays plaintext by
    # design (owner env keys). ``resolved_api_key`` decrypts at use.

    def _protect_api_key(self, value: str | None) -> str | None:
        """Encrypt one key for at-rest storage. Already-encrypted blobs pass
        through; without a master key (vault locked) the value passes
        through and the KEY-WRITE paths raise ``VaultLockedError``."""
        if value is None or self.user_id is None:
            return value
        if vault.is_vault_blob(value):
            return value
        mk = current_master_key.get()
        if mk is None:
            return value
        return vault.wrap_secret(mk, value)

    def _require_unlocked(self) -> None:
        """A key-write to a per-user store must never land plaintext at
        rest: the vault has to be unlocked in this request."""
        if self.user_id is None:
            return
        if current_master_key.get() is None:
            raise vault.VaultLockedError(
                "your vault is locked - unlock it (or set a vault passphrase) "
                "before storing API keys"
            )

    def clear_api_keys(self) -> None:
        """Drop every stored api_key (vault-destroy path - undecryptable
        blobs must not linger behind ``has_api_key``)."""
        backends = self.read()
        for b in backends:
            b.api_key = None
        self._write(backends)

    def _write(self, backends: list[SearchBackend]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Protect each key for at rest (shallow copies - never mutate the
        # caller's in-memory backends).
        rows = [
            dataclasses.asdict(dataclasses.replace(b, api_key=self._protect_api_key(b.api_key)))
            for b in backends
        ]
        payload = json.dumps(rows, indent=2) + "\n"
        # Create the temp file 0600 from the start - no world-readable
        # write-then-chmod window.
        tmp = self.path.with_name(f"{self.path.name}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, CONFIG_MODE)
        with os.fdopen(fd, "w") as f:
            f.write(payload)
        tmp.replace(self.path)
        # The chmod above lands on the temp inode; re-assert on the final path.
        try:
            os.chmod(self.path, CONFIG_MODE)
        except OSError:
            pass


def _backend_fields() -> set[str]:
    return {f.name for f in dataclasses.fields(SearchBackend)}


def get_search_store(user_id: int | None = None) -> SearchStore:
    """Store over the app's data dir. ``user_id`` None falls back to the
    request-scoped current user (``request_ctx.current_user_id``) - so the
    API routes and the agent's web-tool gating resolve the CALLER's store -
    and None from there too means the SYSTEM store (CLI, auth-off mode,
    agent-level code outside a request)."""
    if user_id is None:
        user_id = current_user_id.get()
    if user_id is not None:
        return SearchStore(settings.data_dir, settings, user_id=user_id)
    return SearchStore(settings.data_dir, settings)
