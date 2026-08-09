"""M7 provider table invariants — the audit surface for search engines."""

from app.search.providers import SEARCH_PROVIDERS


def test_engine_set_matches_v1_plus_keyed_rows():
    """Bundled SearXNG + custom SearXNG-compatible instance + the keyed
    Brave/Serper/Mojeek rows (Aug 9 owner follow-up). More providers are just
    a table row + a client branch — no other code changes."""
    assert set(SEARCH_PROVIDERS) == {"searxng", "custom", "brave", "serper", "mojeek"}


def test_bundled_searxng_needs_no_key_or_base_url():
    p = SEARCH_PROVIDERS["searxng"]
    assert p.kind == "bundled"
    assert p.key_required is False
    assert p.base_url_required is False
    assert p.default_base_url == "http://localhost:8888"


def test_custom_instance_requires_base_url_no_key():
    p = SEARCH_PROVIDERS["custom"]
    assert p.kind == "custom"
    assert p.base_url_required is True
    assert p.key_required is False
    assert p.query_style == "searxng"


def test_keyed_providers_require_key_and_have_defaults():
    """Each keyed row: key required, env var named, a default base URL, and
    its own query style dispatching the client branch."""
    expected = {
        "brave": ("Brave Search", "MASA_BRAVE_API_KEY", "https://api.search.brave.com", "brave"),
        "serper": (
            "Serper (Google SERP)",
            "MASA_SERPER_API_KEY",
            "https://google.serper.dev",
            "serper",
        ),
        "mojeek": ("Mojeek", "MASA_MOJEK_API_KEY", "https://www.mojeek.com", "mojeek"),
    }
    for pid, (name, env, base, style) in expected.items():
        p = SEARCH_PROVIDERS[pid]
        assert p.kind == "keyed"
        assert p.name == name
        assert p.key_required is True
        assert p.key_env_var == env
        assert p.base_url_required is False  # defaults are overridable, not required
        assert p.default_base_url == base
        assert p.query_style == style
