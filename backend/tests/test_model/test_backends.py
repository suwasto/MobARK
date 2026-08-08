"""Config store: env seeding, runtime upsert, 0600 perms, key redaction."""

import json
import os

import pytest

from app.config import Settings
from app.model.backends import BackendStore, ModelBackend


def _settings(**overrides) -> Settings:
    return Settings(**{"data_dir": ".", **overrides})


def test_seed_creates_file_with_local_backends_only(tmp_path, monkeypatch):
    """BYOK backends are no longer seeded keyless (owner decision, Aug 8
    2026) — an unusable cloud entry only confuses Settings. Fresh installs
    get local backends; cloud providers are added via the BYOK menu."""
    # Deterministic: a dev machine may have MASA_*_API_KEY exported.
    for key in ("OPENAI", "ANTHROPIC", "DEEPSEEK", "OPENROUTER", "GEMINI"):
        monkeypatch.delenv(f"MASA_{key}_API_KEY", raising=False)
    store = BackendStore(tmp_path, settings_obj=_settings())
    backends = store.read()
    ids = {b.id for b in backends}
    assert {"ollama", "lm-studio"} == ids
    assert "custom" not in ids, "custom backends are user-created, not seeded"
    assert store.path.is_file()


def test_seed_byok_backends_when_key_configured(tmp_path, monkeypatch):
    """BYOK backends seed only when a real key is configured (env/settings)."""
    monkeypatch.setenv("MASA_OPENAI_API_KEY", "sk-secret-123")
    by_id = {b.id: b for b in BackendStore(tmp_path, settings_obj=Settings()).read()}
    assert "openai" in by_id
    assert by_id["openai"].api_key == "sk-secret-123"
    assert "anthropic" not in by_id, "unkeyed BYOK must not seed"


def test_seed_local_backends_have_dummy_keys(tmp_path):
    by_id = {b.id: b for b in BackendStore(tmp_path, settings_obj=_settings()).read()}
    assert by_id["ollama"].api_key == "ollama"
    assert by_id["lm-studio"].api_key == "lm-studio"


def test_seed_respects_env_overrides(tmp_path, monkeypatch):
    monkeypatch.setenv("MASA_OLLAMA_BASE_URL", "http://host.docker.internal:11434")
    monkeypatch.setenv("MASA_OPENAI_API_KEY", "sk-secret-123")
    backends = {b.id: b for b in BackendStore(tmp_path, settings_obj=Settings()).read()}
    assert backends["ollama"].base_url == "http://host.docker.internal:11434"
    assert backends["openai"].api_key == "sk-secret-123"
    assert backends["openai"].has_api_key() is True


def test_seed_blank_model_by_default(tmp_path):
    assert all(b.model == "" for b in BackendStore(tmp_path, settings_obj=_settings()).read())


def test_default_chat_model_env_seeds_model(tmp_path, monkeypatch):
    monkeypatch.setenv("MASA_DEFAULT_CHAT_MODEL", "qwen2.5-coder")
    backends = BackendStore(tmp_path, settings_obj=Settings()).read()
    assert all(b.model == "qwen2.5-coder" for b in backends)


def test_store_honors_existing_file_over_env(tmp_path, monkeypatch):
    store = BackendStore(tmp_path, settings_obj=_settings())
    store.read()  # seed
    store.upsert("ollama", base_url="http://192.168.1.50:11434")
    monkeypatch.setenv("MASA_OLLAMA_BASE_URL", "http://other:11434")
    reloaded = {b.id: b for b in BackendStore(tmp_path, settings_obj=Settings()).read()}
    assert reloaded["ollama"].base_url == "http://192.168.1.50:11434"


def test_upsert_persists_and_clears_key(tmp_path):
    store = BackendStore(tmp_path, settings_obj=_settings())
    store.read()  # seed (local backends only — unkeyed BYOK no longer seeds)
    # Add a BYOK backend the way the app does (store.add, keyed) — owner
    # decision Aug 8 2026: keyless BYOK entries are never seeded/created.
    store.add(
        ModelBackend(
            id="openai",
            provider_id="openai",
            name="OpenAI",
            kind="byok",
            base_url="https://api.openai.com/v1",
            api_key="sk-seed",
        )
    )
    b = store.upsert(
        "openai", base_url="https://custom.example/v1", model="gpt-4o", api_key="sk-abc"
    )
    assert (b.base_url, b.model, b.api_key) == ("https://custom.example/v1", "gpt-4o", "sk-abc")

    reloaded = {x.id: x for x in BackendStore(tmp_path, settings_obj=_settings()).read()}
    assert reloaded["openai"].base_url == "https://custom.example/v1"
    assert reloaded["openai"].api_key == "sk-abc"

    store.upsert("openai", api_key="")  # empty clears the key
    assert {x.id: x for x in store.read()}["openai"].api_key is None


def test_unknown_backend_upsert_raises(tmp_path):
    store = BackendStore(tmp_path, settings_obj=_settings())
    store.read()
    with pytest.raises(KeyError, match="unknown backend"):
        store.upsert("nope")


def test_store_file_permissions_0600(tmp_path):
    store = BackendStore(tmp_path, settings_obj=_settings())
    store.read()
    perms = os.stat(store.path).st_mode & 0o777
    assert perms == 0o600


def test_api_key_redacted_from_repr():
    b = ModelBackend(
        id="openai",
        provider_id="openai",
        name="OpenAI",
        kind="byok",
        base_url="https://api.openai.com/v1",
        api_key="sk-leak-me",
    )
    assert "sk-leak-me" not in repr(b)


def test_corrupt_store_reseeds(tmp_path):
    store = BackendStore(tmp_path, settings_obj=_settings())
    store.read()
    store.path.write_text("{not json")
    backends = store.read()
    assert backends, "corrupt store must reseed rather than return nothing"
    assert json.loads(store.path.read_text()), "store must be rewritten as valid JSON"


def test_unknown_entries_dropped_on_read(tmp_path):
    store = BackendStore(tmp_path, settings_obj=_settings())
    store.read()
    data = json.loads(store.path.read_text())
    data.append(
        {"id": "phoenix", "provider_id": "phoenix", "name": "Old", "kind": "byok", "base_url": "x"}
    )
    store.path.write_text(json.dumps(data))
    ids = {b.id for b in store.read()}
    assert "phoenix" not in ids
