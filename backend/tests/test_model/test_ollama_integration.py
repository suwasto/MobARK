"""M3 integration: real Ollama on the host (skipped when not running).

Run with:  pytest -m integration
Requires ``ollama serve`` on the host with at least one model pulled
(``ollama pull qwen2.5-coder`` recommended). Mirrors the M2 deselected-by-
default pattern — every test self-skips when localhost:11434 is unreachable.
"""

import httpx
import pytest

pytestmark = pytest.mark.integration

OLLAMA_MODELS_URL = "http://localhost:11434/v1/models"


@pytest.fixture(scope="module")
def ollama_reachable() -> bool:
    try:
        return httpx.get(OLLAMA_MODELS_URL, timeout=2).status_code == 200
    except Exception:
        return False


@pytest.fixture(scope="module")
def ollama_backend():
    from app.config import Settings
    from app.model.backends import BackendStore

    cfg = Settings()
    store = BackendStore(cfg.data_dir, settings_obj=cfg)
    return next(b for b in store.read() if b.id == "ollama")


def test_ollama_models_listing_live(ollama_reachable, ollama_backend):
    if not ollama_reachable:
        pytest.skip("Ollama not running on localhost:11434 — start it with `ollama serve`")
    from app.model.health import list_models

    models, source, error = list_models(ollama_backend)
    assert source == "live", f"expected live listing, got {source!r}: {error}"


def test_ollama_health_reachable(ollama_reachable, ollama_backend):
    if not ollama_reachable:
        pytest.skip("Ollama not running on localhost:11434 — start it with `ollama serve`")
    from app.model.health import check_backend

    h = check_backend(ollama_backend)
    assert h.reachable is True, h.error
    assert h.status == "ok"
    assert h.model_source == "live"


def test_ollama_probe_never_raises(ollama_reachable, ollama_backend):
    """With no model configured the probe is skipped; with a pulled model it
    must report ok/failed cleanly — either way it never raises."""
    if not ollama_reachable:
        pytest.skip("Ollama not running on localhost:11434 — start it with `ollama serve`")
    from app.model.health import check_backend

    h = check_backend(ollama_backend, probe=True)
    assert h.probe_ok in (True, False, None)
    if h.probe_ok is False:
        assert h.error, "a failed probe must carry an explanation"
