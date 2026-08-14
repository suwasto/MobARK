"""M7 search client - query normalization, bounded SSRF-guarded web_fetch,
and the health probe. Network is monkeypatched (httpx) / mocked (trafilatura);
the flagship e2e lives in test_agent/test_web_research.py."""

import httpx
import pytest

from app.search import client as search_client
from app.search.backends import SearchBackend
from app.search.client import SearchError, check_backend, query, web_fetch

_SEARXNG = SearchBackend(
    id="searxng",
    provider_id="searxng",
    name="SearXNG",
    kind="bundled",
    base_url="http://localhost:8888",
)


def _keyed_backend(pid: str, base_url: str, api_key: str | None = "sk-test"):
    return SearchBackend(
        id=pid,
        provider_id=pid,
        name=pid.title(),
        kind="keyed",
        base_url=base_url,
        api_key=api_key,
    )


_BRAVE = _keyed_backend("brave", "https://api.search.brave.com")
_SERPER = _keyed_backend("serper", "https://google.serper.dev")
_MOJEEK = _keyed_backend("mojeek", "https://www.mojeek.com")


class _FakeResp:
    def __init__(self, status_code=200, json_data=None, content=b"", headers=None):
        self.status_code = status_code
        self._json = json_data
        self.content = content
        self.headers = headers or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPError(f"HTTP {self.status_code}")

    def json(self):
        return self._json

    def iter_bytes(self):
        yield self.content


class _BoomJSONResp(_FakeResp):
    """A response whose body is not JSON - ``.json()`` raises like httpx."""

    def json(self):
        raise ValueError("body is not valid JSON")


def _searxng_payload(results):
    return {"results": results}


def test_query_normalizes_searxng_json(monkeypatch):
    monkeypatch.setattr(
        search_client.httpx,
        "get",
        lambda url, params=None, timeout=None: _FakeResp(
            json_data=_searxng_payload(
                [
                    {
                        "title": "CVE-2024-0001",
                        "url": "https://nvd.nist.gov/vuln/CVE-2024-0001",
                        "content": "A description",
                        "engine": "google",
                    },
                    {
                        "title": "no-url result",
                        "url": "",
                        "content": "",
                        "engine": "duckduckgo",
                    },
                    {
                        "title": "third",
                        "url": "https://x.example",
                        "content": "c",
                        "engine": "bing",
                    },
                ]
            )
        ),
    )
    rows = query(_SEARXNG, "CVE-2024-0001")
    assert rows[0] == {
        "title": "CVE-2024-0001",
        "url": "https://nvd.nist.gov/vuln/CVE-2024-0001",
        "snippet": "A description",
        "engine": "google",
    }
    assert len(rows) == 3
    # request shape: GET {base}/search?q=…&format=json
    captured = {}

    def spy_get(url, params=None, timeout=None):
        captured["url"] = url
        captured["params"] = params
        return _FakeResp(json_data=_searxng_payload([]))

    monkeypatch.setattr(search_client.httpx, "get", spy_get)
    query(_SEARXNG, "hello world")
    assert captured["url"] == "http://localhost:8888/search"
    assert captured["params"] == {"q": "hello world", "format": "json"}


def test_query_bounded_to_limit(monkeypatch):
    monkeypatch.setattr(
        search_client.httpx,
        "get",
        lambda url, params=None, timeout=None: _FakeResp(
            json_data=_searxng_payload(
                [{"title": f"r{i}", "url": f"https://x.example/{i}"} for i in range(20)]
            )
        ),
    )
    assert len(query(_SEARXNG, "x", limit=5)) == 5


def test_query_unreachable_raises_compose_hint(monkeypatch):
    def boom(url, params=None, timeout=None):
        raise httpx.HTTPError("connection refused")

    monkeypatch.setattr(search_client.httpx, "get", boom)
    with pytest.raises(SearchError) as ei:
        query(_SEARXNG, "x")
    # The hint carries the actionable compose command AND a friendly reason -
    # never the raw exception text (owner report, Aug 12).
    assert "docker compose up -d searxng" in str(ei.value)
    assert "connection was refused" in str(ei.value)
    assert "[Errno" not in str(ei.value)


def test_query_unreachable_dns_error_is_friendly(monkeypatch):
    """A DNS failure (the common container-not-running case) reads as a
    friendly host-resolution clause, not the raw ``[Errno -2] Name or
    service not known`` (owner report, Aug 12)."""
    def boom(url, params=None, timeout=None):
        raise httpx.ConnectError("[Errno -2] Name or service not known")

    monkeypatch.setattr(search_client.httpx, "get", boom)
    with pytest.raises(SearchError) as ei:
        query(_SEARXNG, "x")
    msg = str(ei.value)
    assert "host name couldn't be resolved" in msg
    assert "docker compose up -d searxng" in msg
    assert "[Errno" not in msg


def test_query_non_json_raises(monkeypatch):
    monkeypatch.setattr(
        search_client.httpx,
        "get",
        lambda url, params=None, timeout=None: _BoomJSONResp(),
    )
    with pytest.raises(SearchError, match="non-JSON"):
        query(_SEARXNG, "x")


def test_query_empty_query_raises(monkeypatch):
    with pytest.raises(SearchError, match="empty"):
        query(_SEARXNG, "   ")


def test_query_rejects_non_dict_json(monkeypatch):
    """Well-formed JSON that isn't an object (e.g. a bare array) fails as a
    SearchError, not an AttributeError (review catch: it used to 500 the
    Settings probe on a misbehaving engine)."""
    monkeypatch.setattr(
        search_client.httpx,
        "get",
        lambda url, params=None, timeout=None: _FakeResp(json_data=[1, 2, 3]),
    )
    with pytest.raises(SearchError, match="unexpected JSON shape"):
        query(_SEARXNG, "x")


# ---- keyed engines (Brave/Serper/Mojeek) -------------------------------------


def test_query_brave_normalizes_and_auths(monkeypatch):
    captured = {}

    def fake_get(url, headers=None, params=None, timeout=None):
        captured["url"] = url
        captured["headers"] = headers
        captured["params"] = params
        return _FakeResp(
            json_data={
                "web": {
                    "results": [
                        {"title": "CVE-2024-0001", "url": "https://nvd.nist.gov/1",
                         "description": "Brave snippet"},
                        {"title": "second", "url": "https://x.example/2",
                         "description": "d"},
                    ]
                }
            }
        )

    monkeypatch.setattr(search_client.httpx, "get", fake_get)
    rows = query(_BRAVE, "CVE-2024-0001")
    assert rows[0] == {
        "title": "CVE-2024-0001",
        "url": "https://nvd.nist.gov/1",
        "snippet": "Brave snippet",
        "engine": "brave",
    }
    assert len(rows) == 2
    # Request shape: GET /res/v1/web/search, key in the header, count param.
    assert captured["url"] == "https://api.search.brave.com/res/v1/web/search"
    assert captured["headers"]["X-Subscription-Token"] == "sk-test"
    assert captured["params"] == {"q": "CVE-2024-0001", "count": 10}


def test_query_serper_normalizes_and_posts(monkeypatch):
    captured = {}

    def fake_post(url, headers=None, json=None, timeout=None):
        captured["url"] = url
        captured["headers"] = headers
        captured["json"] = json
        return _FakeResp(
            json_data={
                "organic": [
                    {"title": "Serper hit", "link": "https://example.com/x",
                     "snippet": "s"},
                ]
            }
        )

    monkeypatch.setattr(search_client.httpx, "post", fake_post)
    rows = query(_SERPER, "hello")
    assert rows[0] == {
        "title": "Serper hit",
        "url": "https://example.com/x",
        "snippet": "s",
        "engine": "serper",
    }
    # Request shape: POST /search with the key header + a JSON body (query
    # params get 400 from Serper).
    assert captured["url"] == "https://google.serper.dev/search"
    assert captured["headers"]["X-API-KEY"] == "sk-test"
    assert captured["json"] == {"q": "hello", "num": 10}


def test_query_mojeek_normalizes_with_key_param(monkeypatch):
    captured = {}

    def fake_get(url, params=None, timeout=None):
        captured["url"] = url
        captured["params"] = params
        return _FakeResp(
            json_data={
                "response": {
                    "results": [
                        {"title": "Mojeek hit", "url": "https://mojeek.example/x",
                         "desc": "d"},
                    ]
                }
            }
        )

    monkeypatch.setattr(search_client.httpx, "get", fake_get)
    rows = query(_MOJEEK, "hello")
    assert rows[0] == {
        "title": "Mojeek hit",
        "url": "https://mojeek.example/x",
        "snippet": "d",
        "engine": "mojeek",
    }
    # Request shape: GET /search with api_key + fmt=json (default is XML).
    assert captured["url"] == "https://www.mojeek.com/search"
    assert captured["params"] == {
        "api_key": "sk-test",
        "q": "hello",
        "fmt": "json",
        "t": 10,
    }


def test_keyed_without_key_raises_cleanly(monkeypatch):
    no_key = _keyed_backend("brave", "https://api.search.brave.com", api_key=None)
    with pytest.raises(SearchError, match="no API key configured"):
        query(no_key, "x")


def test_keyed_401_surfaces_rejected_key_hint(monkeypatch):
    """A 401/403 from a keyed engine is a rejected key - the most common
    first-use failure - surfaced as a self-explaining hint, not a raw error."""

    class _AuthFakeResp(_FakeResp):
        def raise_for_status(self):
            req = httpx.Request("GET", "https://api.search.brave.com/res/v1/web/search")
            raise httpx.HTTPStatusError(
                "Client error '401 Unauthorized'",
                request=req,
                response=httpx.Response(401, request=req),
            )

    monkeypatch.setattr(
        search_client.httpx,
        "get",
        lambda url, headers=None, params=None, timeout=None: _AuthFakeResp(),
    )
    with pytest.raises(SearchError, match="rejected the API key"):
        query(_BRAVE, "x")


def test_keyed_lightweight_probe_runs_real_query(monkeypatch):
    """Keyed engines have no meaningful root endpoint - the lightweight probe
    IS a real query (also validates the key)."""
    monkeypatch.setattr(
        search_client.httpx,
        "get",
        lambda url, headers=None, params=None, timeout=None: _FakeResp(
            json_data={"web": {"results": [{"title": "hit", "url": "https://x",
                                              "description": "d"}]}}
        ),
    )
    h = check_backend(_BRAVE, probe=False)
    assert h.reachable is True
    assert h.status == "ok"


def test_keyed_probe_failure_never_raises(monkeypatch):
    def boom(url, headers=None, params=None, timeout=None):
        raise httpx.HTTPError("conn refused")

    monkeypatch.setattr(search_client.httpx, "get", boom)
    h = check_backend(_BRAVE, probe=False)
    assert h.reachable is False
    assert "unreachable" in h.status


# ---- web_fetch: SSRF guard + extraction --------------------------------------


class _FakeStream:
    """Context-manager wrapper so the fake exposes httpx's ``stream()`` shape."""

    def __init__(self, resp):
        self._resp = resp

    def __enter__(self):
        return self._resp

    def __exit__(self, *exc):
        return False


class _FakeClient:
    def __init__(self, responses):
        self._responses = list(responses)
        self.requests = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get(self, url, headers=None):
        self.requests.append(url)
        return self._responses.pop(0)

    def stream(self, method, url, headers=None):
        self.requests.append(url)
        return _FakeStream(self._responses.pop(0))


def _page_resp(body=b"<html><title>T</title><body><p>Hello article.</p></body></html>"):
    return _FakeResp(status_code=200, content=body)


def test_web_fetch_extracts_and_returns_final_url(monkeypatch):
    monkeypatch.setattr(
        search_client.httpx, "Client", lambda **kw: _FakeClient([_page_resp()])
    )
    monkeypatch.setattr(search_client, "extract", lambda html, **kw: "Hello article.")
    page = web_fetch("https://example.com/advisory")
    assert page["url"] == "https://example.com/advisory"
    assert page["title"] == "T"
    assert page["text"] == "Hello article."


def test_web_fetch_follows_redirect_with_guard(monkeypatch):
    """Redirects are followed manually, validating EVERY hop - a redirect to
    a private host is refused even when the initial URL is public."""
    monkeypatch.setattr(
        search_client.httpx,
        "Client",
        lambda **kw: _FakeClient(
            [
                _FakeResp(status_code=301, headers={"location": "http://127.0.0.1/secret"}),
                _page_resp(),
            ]
        ),
    )
    with pytest.raises(SearchError, match="private-network"):
        web_fetch("https://example.com/redirect")


def test_web_fetch_refuses_private_hosts():
    for url in (
        "http://127.0.0.1/admin",
        "http://10.0.0.5/x",
        "http://192.168.1.1/x",
        "http://172.16.0.1/x",
        "http://169.254.169.254/latest/meta-data",
        "http://localhost/x",
        "http://[::1]/x",
    ):
        with pytest.raises(SearchError):
            web_fetch(url)


def test_web_fetch_refuses_ipv4_mapped_ipv6_loopback():
    """IPv4-mapped IPv6 (``::ffff:127.0.0.1``) connects to loopback - the
    guard must refuse it (review catch: it slipped past the IPv6 net list)."""
    for url in ("http://[::ffff:127.0.0.1]/", "http://[::ffff:7f00:1]/"):
        with pytest.raises(SearchError, match="private-network"):
            web_fetch(url)


def test_web_fetch_refuses_non_http_schemes():
    for url in ("file:///etc/passwd", "ftp://example.com/x", "gopher://x"):
        with pytest.raises(SearchError, match="http\\(s\\)"):
            web_fetch(url)


def test_web_fetch_no_readable_text_fails_cleanly(monkeypatch):
    monkeypatch.setattr(
        search_client.httpx, "Client", lambda **kw: _FakeClient([_page_resp(b"<html></html>")])
    )
    monkeypatch.setattr(search_client, "extract", lambda html, **kw: None)
    with pytest.raises(SearchError, match="JS-rendered"):
        web_fetch("https://example.com/spa")


def test_web_fetch_too_many_redirects(monkeypatch):
    chain = [
        _FakeResp(status_code=301, headers={"location": f"https://example.com/{i}"})
        for i in range(8)
    ]
    monkeypatch.setattr(search_client.httpx, "Client", lambda **kw: _FakeClient(chain))
    with pytest.raises(SearchError, match="too many redirects"):
        web_fetch("https://example.com/start")


# ---- health probe ------------------------------------------------------------


def test_check_backend_lightweight_reachable(monkeypatch):
    monkeypatch.setattr(
        search_client.httpx,
        "get",
        lambda url, timeout=None: _FakeResp(status_code=200),
    )
    h = check_backend(_SEARXNG, probe=False)
    assert h.reachable is True and h.status == "ok"
    assert h.error is None


def test_check_backend_lightweight_unreachable_has_hint(monkeypatch):
    def boom(url, timeout=None):
        raise httpx.HTTPError("conn refused")

    monkeypatch.setattr(search_client.httpx, "get", boom)
    h = check_backend(_SEARXNG, probe=False)
    assert h.reachable is False and h.status == "unreachable"
    assert "docker compose up -d searxng" in (h.error or "")
    assert "[Errno" not in (h.error or "")


def test_check_backend_lightweight_error_is_user_friendly(monkeypatch):
    """The health card error carries the actionable hint plus a human reason
    for the failure - never the raw socket error suffix (owner report)."""
    def boom(url, timeout=None):
        raise httpx.ConnectError("[Errno -2] Name or service not known")

    monkeypatch.setattr(search_client.httpx, "get", boom)
    h = check_backend(_SEARXNG, probe=False)
    assert h.reachable is False
    assert "host name couldn't be resolved" in (h.error or "")
    assert "docker compose up -d searxng" in (h.error or "")
    assert "[Errno" not in (h.error or "")


def test_check_backend_full_probe_runs_real_query(monkeypatch):
    monkeypatch.setattr(
        search_client.httpx,
        "get",
        lambda url, params=None, timeout=None: _FakeResp(
            json_data=_searxng_payload(
                [{"title": "top hit", "url": "https://nvd.nist.gov/x", "content": "c"}]
            )
        ),
    )
    h = check_backend(_SEARXNG, probe=True)
    assert h.reachable is True
    assert h.result_count == 1
    assert h.sample_title == "top hit"


def test_check_backend_full_probe_failure(monkeypatch):
    def boom(url, params=None, timeout=None):
        raise httpx.HTTPError("conn refused")

    monkeypatch.setattr(search_client.httpx, "get", boom)
    h = check_backend(_SEARXNG, probe=True)
    assert h.reachable is False
    assert "unreachable" in h.status


def test_check_backend_probe_never_raises_on_bad_engine(monkeypatch):
    """The probe contract: an engine that returns a bizarre response degrades
    to an unreachable result, never a raised exception (which would 500 the
    POST /search/backends/{id}/test endpoint - review catch)."""

    class _Weird:
        def raise_for_status(self):
            pass

        def json(self):
            return [1, 2, 3]

    monkeypatch.setattr(
        search_client.httpx, "get", lambda url, params=None, timeout=None: _Weird()
    )
    h = check_backend(_SEARXNG, probe=True)
    assert h.reachable is False
    assert h.status == "unreachable"
    assert "unexpected JSON shape" in (h.error or "")
