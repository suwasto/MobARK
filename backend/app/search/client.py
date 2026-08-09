"""M7 search client — engine queries (dispatch by ``query_style``) + bounded
web_fetch extraction.

``query`` talks to the single Active engine and normalizes every provider's
response to ``[{title, url, snippet, engine}]`` — the model cites source URLs
from it. There is no universal search-API protocol, so each ``query_style``
has its own small request + parse branch (see ``app/search/providers.py``):

  searxng — GET {base}/search?q=…&format=json      -> results[]
  brave   — GET {base}/res/v1/web/search            -> web.results[]
            (X-Subscription-Token header, count param)
  serper  — POST {base}/search (X-API-KEY, JSON     -> organic[]
            body {"q": …})
  mojeek  — GET {base}/search?q=…&api_key=…&fmt=json-> response.results[]
            (desc field, not description)

``web_fetch`` is the agent's page reader: a bounded httpx GET + **trafilatura
(>=1.8.0 — Apache-2.0; earlier versions were GPLv3+)** article extraction.
SSRF-guarded: http(s) scheme only, private/reserved hosts refused at the
first hop AND on every redirect hop — the agent must never read the user's
local network (this is the one deliberate egress in MASA).

``check_backend`` powers the Settings probe: the lightweight pass accepts any
2xx from the base URL (SearXNG) — keyed engines have no meaningful root
endpoint, so their honest health check IS a real query (also validates the
key); the full test runs a real search query and reports the normalized
result count.
"""
from __future__ import annotations

import ipaddress
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx
from trafilatura import extract

from app.config import settings
from app.search.backends import SearchBackend

_MAX_RESULTS = 10
_MAX_REDIRECTS = 5
# Extracted text cap for the model (the article is bounded before extraction
# too, via web_fetch_max_bytes — this is the model-facing trim).
_WEB_FETCH_MAX_CHARS = 8000
_LIGHTWEIGHT_TIMEOUT = 3.0

_PRIVATE_NETS = tuple(
    ipaddress.ip_network(net)
    for net in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "100.64.0.0/10",
        "0.0.0.0/8",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)
_RESERVED_HOSTS = {"localhost", "localhost.localdomain", "metadata.google.internal"}

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


class SearchError(RuntimeError):
    """A web tool failed cleanly — surfaced to the model as an error result."""


def compose_hint(backend: SearchBackend) -> str:
    """Actionable first-use hint for an unreachable engine — the self-
    explaining posture shared with the Ollama arch hint (M6)."""
    if backend.kind == "bundled":
        return (
            f"SearXNG is unreachable at {backend.base_url} — start the search "
            "service: `docker compose --profile web up -d searxng`"
        )
    return f"search engine is unreachable at {backend.base_url}"


def _keyed_hint(backend: SearchBackend, exc: Exception) -> str:
    """Self-explaining failure message for a keyed engine: a 401/403 is a
    rejected key (the most common first-use failure) — the bundled engine
    keeps its compose hint (``compose_hint``)."""
    if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code in (401, 403):
        return (
            f"{backend.name} rejected the API key (HTTP {exc.response.status_code}) — "
            "check the key in Settings → Search & research"
        )
    return f"search engine is unreachable at {backend.base_url}"


def _require_key(backend: SearchBackend) -> None:
    if not backend.has_api_key():
        raise SearchError(
            f"{backend.name} has no API key configured — add it in Settings → "
            "Search & research"
        )


def _normalize(
    rows: list[dict],
    *,
    url_field: str = "url",
    snippet_field: str = "description",
    engine_name: str,
    engine_field: str | None = None,
    limit: int,
) -> list[dict]:
    """Shared row normalizer: ``{title, url, snippet, engine}``, top ``limit``
    (every provider returns results best-first). ``engine_field`` reads the
    engine name from each row (SearXNG reports the actual engine per result);
    otherwise ``engine_name`` is fixed (keyed providers don't report one)."""
    out: list[dict] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        engine = (r.get(engine_field) or "") if engine_field else engine_name
        out.append(
            {
                "title": r.get("title") or "",
                "url": r.get(url_field) or "",
                "snippet": r.get(snippet_field) or "",
                "engine": engine,
            }
        )
        if len(out) >= limit:
            break
    return out


def _query_searxng(
    backend: SearchBackend, q: str, *, timeout: float, limit: int
) -> list[dict]:
    url = f"{backend.base_url.rstrip('/')}/search"
    try:
        resp = httpx.get(url, params={"q": q, "format": "json"}, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
    except httpx.HTTPError as exc:
        raise SearchError(f"{compose_hint(backend)} ({exc})") from exc
    except ValueError as exc:
        raise SearchError(
            f"search engine returned non-JSON at {backend.base_url}: {exc}"
        ) from exc
    if not isinstance(data, dict):
        # Well-formed JSON that isn't the expected object (e.g. a bare array)
        # must fail as a SearchError, not an AttributeError deep in the tool
        # (review catch: it used to 500 the Settings probe).
        raise SearchError(
            f"search engine returned an unexpected JSON shape at {backend.base_url}"
        )
    return _normalize(
        data.get("results", []) or [],
        snippet_field="content",
        engine_name=backend.id,
        engine_field="engine",  # SearXNG reports the real engine per result
        limit=limit,
    )


def _query_brave(
    backend: SearchBackend, q: str, *, timeout: float, limit: int
) -> list[dict]:
    """Brave Search API: GET /res/v1/web/search with the key in the
    ``X-Subscription-Token`` header (a query-param key gets 401 — see
    docs). ``count`` maxes at 20."""
    _require_key(backend)
    url = f"{backend.base_url.rstrip('/')}/res/v1/web/search"
    headers = {"X-Subscription-Token": backend.api_key, "Accept": "application/json"}
    try:
        resp = httpx.get(
            url,
            headers=headers,
            params={"q": q, "count": min(limit, 20)},
            timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()
    except httpx.HTTPError as exc:
        raise SearchError(f"{_keyed_hint(backend, exc)} ({exc})") from exc
    except ValueError as exc:
        raise SearchError(
            f"{backend.name} returned non-JSON at {backend.base_url}: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise SearchError(
            f"{backend.name} returned an unexpected JSON shape at {backend.base_url}"
        )
    return _normalize(
        (data.get("web") or {}).get("results", []) or [],
        engine_name="brave",
        limit=limit,
    )


def _query_serper(
    backend: SearchBackend, q: str, *, timeout: float, limit: int
) -> list[dict]:
    """Serper (Google SERP): POST {base}/search with the key in the
    ``X-API-KEY`` header and a JSON body — GET with query params gets 400."""
    _require_key(backend)
    url = f"{backend.base_url.rstrip('/')}/search"
    headers = {"X-API-KEY": backend.api_key, "Content-Type": "application/json"}
    try:
        resp = httpx.post(
            url,
            headers=headers,
            json={"q": q, "num": min(limit, 100)},
            timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()
    except httpx.HTTPError as exc:
        raise SearchError(f"{_keyed_hint(backend, exc)} ({exc})") from exc
    except ValueError as exc:
        raise SearchError(
            f"{backend.name} returned non-JSON at {backend.base_url}: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise SearchError(
            f"{backend.name} returned an unexpected JSON shape at {backend.base_url}"
        )
    return _normalize(
        data.get("organic", []) or [],
        url_field="link",
        snippet_field="snippet",
        engine_name="serper",
        limit=limit,
    )


def _query_mojeek(
    backend: SearchBackend, q: str, *, timeout: float, limit: int
) -> list[dict]:
    """Mojeek: GET /search with the key as a query param and ``fmt=json``
    (default is XML without it). Snippet field is ``desc``; ``t`` maxes at 20."""
    _require_key(backend)
    url = f"{backend.base_url.rstrip('/')}/search"
    params = {"api_key": backend.api_key, "q": q, "fmt": "json", "t": min(limit, 20)}
    try:
        resp = httpx.get(url, params=params, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
    except httpx.HTTPError as exc:
        raise SearchError(f"{_keyed_hint(backend, exc)} ({exc})") from exc
    except ValueError as exc:
        raise SearchError(
            f"{backend.name} returned non-JSON at {backend.base_url}: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise SearchError(
            f"{backend.name} returned an unexpected JSON shape at {backend.base_url}"
        )
    return _normalize(
        (data.get("response") or {}).get("results", []) or [],
        snippet_field="desc",
        engine_name="mojeek",
        limit=limit,
    )


_STYLE_QUERIES = {
    "searxng": _query_searxng,
    "brave": _query_brave,
    "serper": _query_serper,
    "mojeek": _query_mojeek,
}


def query(
    backend: SearchBackend,
    q: str,
    *,
    timeout: float | None = None,
    limit: int = _MAX_RESULTS,
) -> list[dict]:
    """Search via the backend's engine (dispatched by ``query_style``).

    Returns ``[{title, url, snippet, engine}]``, top ``limit`` results (every
    provider returns results best-first). Raises :class:`SearchError` — with
    a compose hint for the bundled engine, an API-key hint for a 401/403
    from a keyed engine — when the engine is unreachable or the response is
    unparseable.
    """
    if not q.strip():
        raise SearchError("empty search query")
    timeout = timeout or float(settings.web_search_timeout_seconds)
    branch = _STYLE_QUERIES.get(backend.provider.query_style)
    if branch is None:
        raise SearchError(
            f"unsupported query style {backend.provider.query_style!r} for {backend.name}"
        )
    return branch(backend, q, timeout=timeout, limit=limit)


# ---- web_fetch (bounded + SSRF-guarded) ------------------------------------


def _validate_target_url(url: str) -> str:
    """Scheme + host guard for ``web_fetch`` (SSRF): http(s) only, no private
    or reserved hosts. Called on the initial URL and on every redirect hop."""
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError as exc:
        raise SearchError(f"invalid URL {url!r}: {exc}") from exc
    if parsed.scheme not in ("http", "https"):
        raise SearchError(f"web_fetch only supports http(s) URLs, got {parsed.scheme!r}")
    host = (parsed.hostname or "").lower()
    if not host:
        raise SearchError(f"URL has no host: {url!r}")
    if host in _RESERVED_HOSTS or host.endswith(".local") or host.endswith(".internal"):
        raise SearchError(f"refusing to fetch a local/reserved host: {host!r}")
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return url  # hostname — DNS rebinding is out of scope for a local tool
    # IPv4-mapped IPv6 (e.g. ``::ffff:127.0.0.1``) connects to the mapped
    # IPv4 — test THAT against the private nets too, or loopback slips
    # through the IPv6 net list (review catch).
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if any(addr in net for net in _PRIVATE_NETS):
        raise SearchError(f"refusing to fetch a private-network address: {host!r}")
    return url


def _extract_title(html: bytes) -> str:
    m = _TITLE_RE.search(html.decode("utf-8", errors="replace"))
    if not m:
        return ""
    return " ".join(m.group(1).split())[:200]


def web_fetch(
    url: str,
    *,
    timeout: float | None = None,
    max_bytes: int | None = None,
) -> dict:
    """Fetch one page (bounded) and extract agent-friendly article text.

    Returns ``{"url", "title", "text"}`` — the URL is the final post-redirect
    location so the model cites the page it actually read. Static pages only
    in v1 (no browser — JS-rendered pages degrade to their raw HTML; the
    extraction fails cleanly when nothing readable remains).
    """
    timeout = timeout or float(settings.web_fetch_timeout_seconds)
    max_bytes = max_bytes or settings.web_fetch_max_bytes
    current = url
    with httpx.Client(follow_redirects=False, timeout=timeout) as client:
        for _hop in range(_MAX_REDIRECTS + 1):
            current = _validate_target_url(current)
            try:
                # Streaming read: the size cap bounds memory TOO — the body is
                # consumed in chunks and truncated at max_bytes, so a huge page
                # never materializes fully in RAM (review catch; the old
                # ``resp.content[:max_bytes]`` buffered the whole body first).
                with client.stream(
                    "GET", current, headers={"User-Agent": "MASA-agent/0.1"}
                ) as resp:
                    if resp.status_code in (301, 302, 303, 307, 308):
                        location = resp.headers.get("location")
                        if not location:
                            raise SearchError(
                                f"redirect without a Location header from {current}"
                            )
                        current = urllib.parse.urljoin(current, location)
                        continue
                    if resp.status_code != 200:
                        raise SearchError(
                            f"web_fetch got HTTP {resp.status_code} from {current}"
                        )
                    chunks: list[bytes] = []
                    total = 0
                    for chunk in resp.iter_bytes():
                        chunks.append(chunk)
                        total += len(chunk)
                        if total >= max_bytes:
                            break
                    html = b"".join(chunks)[:max_bytes]
                break
            except httpx.HTTPError as exc:
                raise SearchError(f"web_fetch failed for {current}: {exc}") from exc
        else:
            raise SearchError(f"too many redirects fetching {url}")
    try:
        text = extract(html, include_comments=False, include_tables=False)
    except Exception as exc:  # noqa: BLE001 - extraction must degrade cleanly
        raise SearchError(f"could not extract text from {current}: {exc}") from exc
    if not text:
        raise SearchError(
            f"no readable text extracted from {current} — the page may be "
            "JS-rendered (v1 has no browser automation)"
        )
    return {"url": current, "title": _extract_title(html), "text": text[:_WEB_FETCH_MAX_CHARS]}


# ---- health / probe ---------------------------------------------------------


@dataclass
class SearchHealth:
    backend_id: str
    reachable: bool
    status: str = "unknown"  # "ok" | "unreachable" | "unknown"
    latency_ms: int | None = None
    error: str | None = None
    checked_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    # Full-probe extras: how many normalized results a real query returned.
    result_count: int | None = None
    sample_title: str | None = None


def check_backend(backend: SearchBackend, *, probe: bool = False) -> SearchHealth:
    """Reachability of a search backend. Never raises.

    Lightweight (``probe=False``, used by ``GET /search/backends``): accept
    any 2xx from the base URL — the cheap list pass. Full test
    (``probe=True``, ``POST /search/backends/{id}/test``): run a real search
    query and report the normalized result count — the honest check that the
    JSON format is actually enabled on the instance.
    """
    start = time.monotonic()
    latency = lambda: int((time.monotonic() - start) * 1000)  # noqa: E731
    if probe or backend.provider.query_style != "searxng":
        # Full test (or ANY keyed engine — no meaningful root endpoint
        # exists, so a real query IS the honest health check; it also
        # validates the key, surfacing "rejected the API key" cleanly).
        try:
            rows = query(backend, "MASA connectivity probe", limit=1)
        except Exception as exc:  # noqa: BLE001 - the probe NEVER raises (the
            # model-health contract); an unexpected engine response (bad JSON
            # shape, parser hiccup) must degrade to a readable failure, not a
            # 500 on POST /search/backends/{id}/test.
            return SearchHealth(
                backend_id=backend.id,
                reachable=False,
                status="unreachable",
                latency_ms=latency(),
                error=str(exc),
            )
        return SearchHealth(
            backend_id=backend.id,
            reachable=True,
            status="ok",
            latency_ms=latency(),
            result_count=len(rows),
            sample_title=rows[0]["title"] if rows else None,
        )
    try:
        resp = httpx.get(backend.base_url.rstrip("/") + "/", timeout=_LIGHTWEIGHT_TIMEOUT)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        return SearchHealth(
            backend_id=backend.id,
            reachable=False,
            status="unreachable",
            latency_ms=latency(),
            error=f"{compose_hint(backend)} ({exc})",
        )
    return SearchHealth(
        backend_id=backend.id,
        reachable=True,
        status="ok",
        latency_ms=latency(),
    )
