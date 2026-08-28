"""M17 Corellium config store - per-user base URL + API key, env-seeded.

Mirrors ``model/backends.py`` / ``search/backends.py`` (M3/M7) in shape and
semantics: ``corellium.json`` under ``data_dir`` (0600), env-seeded from
``MOBARK_CORELLIUM_BASE_URL`` / ``MOBARK_CORELLIUM_API_KEY``, runtime-editable,
per-user isolated (``data_dir/users/<uid>/corellium.json``) exactly like the
model/search stores (M9.1 decision 3).

Corellium is the **opt-in, off-by-default paid third-party iOS backend** the
PRD's FR-D5a + self-hosted posture carve out: empty config = the option hides
entirely (no iOS device path surfaces it, the Settings UI omits it, discovery
never shows a Corellium instance). It stays plainly separate from the default
self-hosted pymobiledevice3 path - a configured Corellium key is never
silently used, only when the tester picks a Corellium instance as the attach
device.

``api_key`` follows the model/search at-rest rule: encrypted (AES-GCM vault
blob) in a per-user store, plaintext only in the SYSTEM store (owner env
keys) / auth-off mode. Never returned by the API - only ``has_api_key``.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from app.auth import vault
from app.config import Settings, settings
from app.request_ctx import current_master_key, current_user_id

CONFIG_FILENAME = "corellium.json"
CONFIG_MODE = 0o600
# Per-user stores live under data_dir/users/<uid>/ (M9.1 decision 3).
USER_STORE_DIR = "users"

# Settings field names the seed reads (the env vars MOBARK_CORELLIUM_*).
_BASE_URL_FIELD = "corellium_base_url"
_API_KEY_FIELD = "corellium_api_key"


@dataclass
class CorelliumConfig:
    """One configured Corellium backend (there is at most one - it is an
    alternative iOS device backend, not a multi-endpoint store)."""

    base_url: str = ""
    api_key: str | None = field(default=None, repr=False)
    enabled: bool = True

    def has_api_key(self) -> bool:
        return bool(self.api_key)

    def configured(self) -> bool:
        """True only when the pair is actually usable: a base URL AND a
        plaintext-resolvable API key. The PRD FR-D5-1: Corellium must be off
        by default and require explicit setup - a base URL alone (no key)
        configures nothing."""
        return bool(self.base_url and self.resolved_api_key())

    def resolved_api_key(self) -> str | None:
        """The plaintext key for outbound requests. A vault blob is decrypted
        with the session's master key (``request_ctx``); a plaintext value
        (SYSTEM store - owner env keys, auth-off mode) passes through
        untouched. None when the vault is locked in this context."""
        value = self.api_key
        if not value:
            return None
        if vault.is_vault_blob(value):
            mk = current_master_key.get()
            if mk is None:
                return None
            return vault.unwrap_secret(mk, value)
        return value


def _seed_config(cfg: Settings) -> CorelliumConfig:
    """The initial config from env/Settings. Both ``MOBARK_CORELLIUM_BASE_URL``
    and ``MOBARK_CORELLIUM_API_KEY`` must be set for a usable seed - a bare
    base URL with no key is unusable and only confuses (owner convention, the
    BYOK rule: never seed an unusable entry)."""
    base_url = (getattr(cfg, _BASE_URL_FIELD, "") or "").strip()
    api_key = (getattr(cfg, _API_KEY_FIELD, "") or "").strip() or None
    if not base_url or api_key is None:
        return CorelliumConfig(base_url="", api_key=None, enabled=False)
    return CorelliumConfig(base_url=base_url, api_key=api_key, enabled=True)


class CorelliumStore:
    """JSON-backed store of the single Corellium config.

    First read seeds the file from env/``Settings``; every later read honors
    the file as the source of truth (runtime edits stick). An optional
    ``user_id`` scopes the store to ``data_dir/users/<uid>/corellium.json``,
    seeded on first read from the SYSTEM layer (the root file's current
    contents, else a fresh env seed) - the user file then becomes that user's
    source of truth, isolating a per-tester Corellium key exactly like the
    model/search BYOK keys (M9.1 decision 3)."""

    def __init__(
        self,
        data_dir: Path,
        settings_obj: Settings | None = None,
        user_id: int | None = None,
    ):
        self.data_dir = Path(data_dir)
        self.user_id = user_id
        if user_id is not None:
            self.path = self.data_dir / USER_STORE_DIR / str(user_id) / CONFIG_FILENAME
        else:
            self.path = self.data_dir / CONFIG_FILENAME
        self._settings = settings_obj or settings

    # ---- read / seed -----------------------------------------------------

    def _seed_source(self) -> CorelliumConfig:
        """The initial config for a store with no file yet. For a USER store
        this is the SYSTEM layer's current contents (inherit the machine
        config); for the system store itself, a fresh env seed."""
        if self.user_id is not None:
            system_path = self.data_dir / CONFIG_FILENAME
            if system_path.is_file():
                return CorelliumStore(self.data_dir, self._settings).read()
        return _seed_config(self._settings)

    def read(self) -> CorelliumConfig:
        if not self.path.is_file():
            cfg = self._seed_source()
            self._write(cfg)
            return cfg
        try:
            raw = json.loads(self.path.read_text())
        except (json.JSONDecodeError, OSError):
            cfg = _seed_config(self._settings)
            self._write(cfg)
            return cfg
        if not isinstance(raw, dict):
            cfg = _seed_config(self._settings)
            self._write(cfg)
            return cfg
        cfg = CorelliumConfig(
            base_url=str(raw.get("base_url") or ""),
            api_key=raw.get("api_key"),
            enabled=bool(raw.get("enabled", True)),
        )
        # Lazy migration: a per-user store still holding a plaintext key is
        # encrypted in place now that the vault is unlocked.
        if (
            self.user_id is not None
            and current_master_key.get() is not None
            and cfg.api_key
            and not vault.is_vault_blob(cfg.api_key)
        ):
            self._write(cfg)
        return cfg

    # ---- write -----------------------------------------------------------

    def upsert(
        self,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        enabled: bool | None = None,
    ) -> CorelliumConfig:
        """Update the config and persist. An empty ``api_key`` clears the
        stored key. An empty ``base_url`` clears the whole config (making it
        unconfigured again)."""
        cfg = self.read()
        if base_url is not None:
            cfg.base_url = (base_url or "").strip()
        if api_key is not None:
            if api_key:
                self._require_unlocked()
                cfg.api_key = self._protect_api_key(api_key)
            else:
                cfg.api_key = None
        if enabled is not None:
            cfg.enabled = enabled
        self._write(cfg)
        return cfg

    def clear(self) -> None:
        """Drop the whole config - the unconfigured/off-by-default state."""
        self._write(CorelliumConfig(base_url="", api_key=None, enabled=False))

    def configured(self) -> bool:
        return self.read().configured()

    # ---- M9.1 vault: at-rest protection -----------------------------------
    # Identical to model/backends.py / search/backends.py: a per-user store
    # encrypts api_key under the session's master key; the SYSTEM store stays
    # plaintext by design (owner env keys). ``resolved_api_key`` decrypts at
    # use.

    def _protect_api_key(self, value: str | None) -> str | None:
        if value is None or self.user_id is None:
            return value
        if vault.is_vault_blob(value):
            return value
        mk = current_master_key.get()
        if mk is None:
            return value
        return vault.wrap_secret(mk, value)

    def _require_unlocked(self) -> None:
        """A key-write to a per-user store must never land plaintext at rest."""
        if self.user_id is None:
            return
        if current_master_key.get() is None:
            raise vault.VaultLockedError(
                "your vault is locked - unlock it (or set a vault passphrase) "
                "before storing the Corellium API key"
            )

    def _write(self, cfg: CorelliumConfig) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(
            {
                "base_url": cfg.base_url,
                "api_key": self._protect_api_key(cfg.api_key),
                "enabled": cfg.enabled,
            },
            indent=2,
        ) + "\n"
        tmp = self.path.with_name(f"{self.path.name}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, CONFIG_MODE)
        with os.fdopen(fd, "w") as f:
            f.write(payload)
        tmp.replace(self.path)
        try:
            os.chmod(self.path, CONFIG_MODE)
        except OSError:
            pass


def get_corellium_store(user_id: int | None = None) -> CorelliumStore:
    """Store over the app's data dir. ``user_id`` None falls back to the
    request-scoped current user (``request_ctx.current_user_id``) - so the API
    routes and the iOS device backend resolve the CALLER's store - and None
    from there too means the SYSTEM store (CLI, auth-off mode)."""
    if user_id is None:
        user_id = current_user_id.get()
    if user_id is not None:
        return CorelliumStore(settings.data_dir, settings, user_id=user_id)
    return CorelliumStore(settings.data_dir, settings)