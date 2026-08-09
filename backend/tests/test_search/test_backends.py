"""M7 SearchStore — env seeding, 0600 perms, and the one-Active radio.

The radio (owner decision, Aug 9) is the module's core contract: exactly one
search backend may be Active at a time, enforced server-side by
``enable_only`` (and on ``add``), so a raw API client can never leave two
engines Active — mirroring ``pick_chat_backend`` determinism.
"""

import json
import os

import pytest

from app.config import Settings
from app.search.backends import SearchBackend, SearchStore


def _settings(**overrides) -> Settings:
    return Settings(**{"data_dir": ".", **overrides})


def test_seed_creates_bundled_searxng_enabled(tmp_path):
    """A fresh store carries the bundled SearXNG backend, seeded ACTIVE (the
    bundled default) — the user can turn it off; no custom instances seed."""
    store = SearchStore(tmp_path, settings_obj=_settings())
    backends = store.read()
    assert [b.id for b in backends] == ["searxng"]
    assert backends[0].kind == "bundled"
    assert backends[0].enabled is True
    assert store.active() is not None and store.active().id == "searxng"
    assert store.path.is_file()


def test_seed_respects_searxng_base_url_env(tmp_path, monkeypatch):
    monkeypatch.setenv("MASA_SEARXNG_BASE_URL", "http://searxng.local:8080")
    store = SearchStore(tmp_path, settings_obj=Settings())
    assert store.read()[0].base_url == "http://searxng.local:8080"


def test_store_file_permissions_0600(tmp_path):
    store = SearchStore(tmp_path, settings_obj=_settings())
    store.read()
    perms = os.stat(store.path).st_mode & 0o777
    assert perms == 0o600


def test_corrupt_store_reseeds(tmp_path):
    store = SearchStore(tmp_path, settings_obj=_settings())
    store.read()
    store.path.write_text("{not json")
    backends = store.read()
    assert [b.id for b in backends] == ["searxng"]
    assert json.loads(store.path.read_text()), "store must be rewritten as valid JSON"


def test_unknown_entries_dropped_on_read(tmp_path):
    store = SearchStore(tmp_path, settings_obj=_settings())
    store.read()
    data = json.loads(store.path.read_text())
    data.append(
        {"id": "yandex", "provider_id": "yandex", "name": "Old", "kind": "custom", "base_url": "x"}
    )
    store.path.write_text(json.dumps(data))
    assert {b.id for b in store.read()} == {"searxng"}


def test_store_honors_existing_file_over_env(tmp_path, monkeypatch):
    store = SearchStore(tmp_path, settings_obj=_settings())
    store.read()
    store.upsert("searxng", base_url="http://192.168.1.20:8888")
    monkeypatch.setenv("MASA_SEARXNG_BASE_URL", "http://other:8888")
    reloaded = SearchStore(tmp_path, settings_obj=Settings()).read()
    assert reloaded[0].base_url == "http://192.168.1.20:8888"


# ---- radio semantics ---------------------------------------------------------


def test_enable_only_disables_all_others(tmp_path):
    store = SearchStore(tmp_path, settings_obj=_settings())
    store.read()
    store.add(
        SearchBackend(
            id="custom",
            provider_id="custom",
            name="Custom SearXNG",
            kind="custom",
            base_url="http://searxng.example:8080",
        )
    )
    store.enable_only("searxng")
    enabled = [b for b in store.read() if b.enabled]
    assert [b.id for b in enabled] == ["searxng"]


def test_active_none_when_all_off(tmp_path):
    store = SearchStore(tmp_path, settings_obj=_settings())
    store.read()
    store.upsert("searxng", enabled=False)
    assert store.active() is None


def test_two_direct_enables_leave_one_active(tmp_path):
    """The API contract: two PUT {enabled:true} calls leave exactly one
    Active — the radio is enforced by the store, not the UI."""
    store = SearchStore(tmp_path, settings_obj=_settings())
    store.read()
    store.add(
        SearchBackend(
            id="custom",
            provider_id="custom",
            name="Custom SearXNG",
            kind="custom",
            base_url="http://searxng.example:8080",
        )
    )
    store.upsert("searxng", enabled=True)  # enables searxng, disables custom
    assert store.active().id == "searxng"
    store.upsert("custom", enabled=True)  # enables custom, disables searxng
    assert store.active().id == "custom"
    enabled = [b for b in store.read() if b.enabled]
    assert len(enabled) == 1


def test_add_of_enabled_backend_turns_others_off(tmp_path):
    store = SearchStore(tmp_path, settings_obj=_settings())
    store.read()
    store.add(
        SearchBackend(
            id="custom",
            provider_id="custom",
            name="Custom SearXNG",
            kind="custom",
            base_url="http://searxng.example:8080",
        )
    )
    # The freshly-added custom instance is enabled — the bundled searxng is off.
    assert store.active().id == "custom"


def test_upsert_disabled_keeps_others_untouched(tmp_path):
    store = SearchStore(tmp_path, settings_obj=_settings())
    store.read()
    store.upsert("searxng", enabled=False)
    assert store.active() is None


def test_upsert_base_url_persists(tmp_path):
    store = SearchStore(tmp_path, settings_obj=_settings())
    store.read()
    store.upsert("searxng", base_url="http://localhost:9000")
    assert store.get("searxng").base_url == "http://localhost:9000"


def test_unknown_backend_upsert_and_enable_only_raise(tmp_path):
    store = SearchStore(tmp_path, settings_obj=_settings())
    store.read()
    with pytest.raises(KeyError, match="unknown search backend"):
        store.upsert("nope", enabled=True)
    with pytest.raises(KeyError, match="unknown search backend"):
        store.enable_only("nope")


def test_remove_returns_false_for_unknown(tmp_path):
    store = SearchStore(tmp_path, settings_obj=_settings())
    store.read()
    assert store.remove("nope") is False
    assert store.remove("searxng") is True
    assert store.get("searxng") is None
    assert store.active() is None


def test_add_duplicate_id_raises(tmp_path):
    store = SearchStore(tmp_path, settings_obj=_settings())
    store.read()
    with pytest.raises(ValueError, match="already exists"):
        store.add(
            SearchBackend(
                id="searxng",
                provider_id="searxng",
                name="SearXNG",
                kind="bundled",
                base_url="http://localhost:8888",
            )
        )


def test_repr_never_leaks_api_key():
    b = SearchBackend(
        id="brave",
        provider_id="brave",
        name="Brave",
        kind="custom",
        base_url="https://api.brave.com",
        api_key="bsk-secret",
    )
    assert "bsk-secret" not in repr(b)


# ---- keyed provider seeding (Brave/Serper/Mojeek) -----------------------------


def test_keyed_providers_seed_only_with_env_key(tmp_path, monkeypatch):
    """Mirror of the model BYOK rule: a keyed search provider seeds only when
    a real API key is configured via env (MASA_BRAVE_API_KEY etc.) — no
    unusable keyless entry is ever created. Seeded DISABLED so the radio
    keeps the bundled engine Active by default."""
    monkeypatch.delenv("MASA_BRAVE_API_KEY", raising=False)
    plain = SearchStore(tmp_path / "plain", settings_obj=Settings()).read()
    assert [b.id for b in plain] == ["searxng"]

    monkeypatch.setenv("MASA_BRAVE_API_KEY", "bsk-env-secret")
    keyed = SearchStore(tmp_path / "keyed", settings_obj=Settings()).read()
    ids = [b.id for b in keyed]
    assert ids == ["searxng", "brave"]
    brave = keyed[1]
    assert brave.kind == "keyed"
    assert brave.api_key == "bsk-env-secret"
    assert brave.enabled is False  # bundled stays Active (radio)
    assert brave.base_url == "https://api.search.brave.com"


def test_upsert_api_key_sets_and_clears(tmp_path):
    store = SearchStore(tmp_path, settings_obj=_settings())
    store.read()
    store.upsert("searxng", api_key="x")
    assert store.get("searxng").api_key == "x"
    store.upsert("searxng", api_key="")
    assert store.get("searxng").has_api_key() is False
