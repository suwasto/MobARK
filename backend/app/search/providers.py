"""M7 search provider table - single source of truth for web-search engines.

Mirrors ``model/providers.py`` (M3): one auditable place for each engine's
base-URL posture, key requirement, and query style. v1 shipped SearXNG only
(the bundled compose service + user-added custom SearXNG-compatible
instances); Aug 9 owner follow-up adds the documented **keyed** rows -
Brave, Serper, Mojeek - added via the same Settings form (base URL where
required + API key), each with a small query/parse branch in
``app/search/client.py`` (no universal search-API protocol exists, so every
engine needs its own client - the table's ``query_style`` dispatches it).
Ruled out as future providers (owner decision, Aug 9): Google CSE (closing
to new customers Jan 2027), Bing v7 (dead, HTTP 410), DuckDuckGo (no
official API - its HTML endpoint is unstable and keyless, the opposite of
this add-form).
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SearchProvider:
    id: str
    name: str
    kind: str  # "bundled" | "custom" | "keyed"
    base_url_required: bool
    key_required: bool
    key_env_var: str | None  # env var that seeds the API key (None: no key)
    default_base_url: str
    # Dispatches the query + normalize branch in ``app/search/client.py``:
    #   "searxng" - GET {base}/search?q=…&format=json -> results[]
    #   "brave"   - GET {base}/res/v1/web/search, X-Subscription-Token -> web.results[]
    #   "serper"  - POST {base}/search, X-API-KEY, JSON {"q": …} -> organic[]
    #   "mojeek"  - GET {base}/search?q=…&api_key=…&fmt=json -> response.results[]
    query_style: str = "searxng"


SEARCH_PROVIDERS: dict[str, SearchProvider] = {
    p.id: p
    for p in [
        SearchProvider(
            id="searxng",
            name="SearXNG",
            kind="bundled",
            base_url_required=False,
            key_required=False,
            key_env_var=None,
            # Profile-gated compose service (``docker compose --profile web
            # up -d searxng``) - see docker-compose.yml.
            default_base_url="http://localhost:8888",
        ),
        SearchProvider(
            id="custom",
            name="Custom SearXNG instance",
            kind="custom",
            base_url_required=True,
            key_required=False,
            key_env_var=None,
            default_base_url="",
        ),
        SearchProvider(
            id="brave",
            name="Brave Search",
            kind="keyed",
            base_url_required=False,
            key_required=True,
            key_env_var="MASA_BRAVE_API_KEY",
            default_base_url="https://api.search.brave.com",
            query_style="brave",
        ),
        SearchProvider(
            id="serper",
            name="Serper (Google SERP)",
            kind="keyed",
            base_url_required=False,
            key_required=True,
            key_env_var="MASA_SERPER_API_KEY",
            default_base_url="https://google.serper.dev",
            query_style="serper",
        ),
        SearchProvider(
            id="mojeek",
            name="Mojeek",
            kind="keyed",
            base_url_required=False,
            key_required=True,
            key_env_var="MASA_MOJEK_API_KEY",
            default_base_url="https://www.mojeek.com",
            query_style="mojeek",
        ),
    ]
}
