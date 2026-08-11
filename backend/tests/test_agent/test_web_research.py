"""M7 web research - the two-gate gating + the flagship CVE case, mocked.

No network, no real LLM (Ollama off): the search client is httpx-mocked and
extraction is trafilatura-mocked; the agent loop runs against the dev-only
fake backend (M6.1), which scripts the web_search -> web_fetch -> cited
answer flow through the REAL tool handlers.
"""

import json
from types import SimpleNamespace

import pytest

from app.agent import chat as chat_mod
from app.agent.chat import answer_question
from app.agent.tools import execute_tool
from app.config import Settings
from app.models import Finding, Scan
from app.search.backends import SearchStore

WEB_TOOL_NAMES = {"web_search", "web_fetch"}


@pytest.fixture()
def env(monkeypatch, db_session_factory, tmp_path):
    """A done Android scan with web research OPTED IN + the decompiled tree."""
    monkeypatch.setattr("app.config.settings.data_dir", tmp_path)
    monkeypatch.setattr("app.db.SessionLocal", db_session_factory)
    with db_session_factory() as session:
        scan = Scan(
            filename="app.apk",
            platform="android",
            status="done",
            web_research_enabled=True,
        )
        session.add(scan)
        session.commit()
        scan_id = scan.id
        session.add(
            Finding(
                scan_id=scan_id,
                tool="semgrep",
                title="WebView with JavaScript enabled",
                severity="medium",
                file_path="com/app/W.java",
                line_number=42,
                category="MASVS-PLATFORM-2",
            )
        )
        session.commit()
    root = tmp_path / "work" / str(scan_id) / "decompiled" / "sources"
    (root / "com/app").mkdir(parents=True)
    (root / "com/app/W.java").write_text("public class W {}\n")
    return scan_id


def _msg(content, tool_calls=None):
    return SimpleNamespace(content=content, tool_calls=tool_calls)


def _resp(message):
    return SimpleNamespace(choices=[SimpleNamespace(message=message)])


def _tool_call(call_id, name, arguments):
    return SimpleNamespace(id=call_id, function=SimpleNamespace(name=name, arguments=arguments))


def _web_tool_names(tools):
    return {t["function"]["name"] for t in tools}


def _fake_backend():
    from app.model.backends import ModelBackend

    return ModelBackend(
        id="fake", provider_id="fake", name="Fake (dev demo)", kind="local",
        base_url="", model="demo", api_key="fake",
    )


# ---- the two gates ------------------------------------------------------------


def test_web_tools_offered_when_both_gates_hold(env, monkeypatch):
    """Opt-in ON + Active engine (fresh store seeds searxng enabled) -> the
    web schemas are offered AND the system prompt tells the model when to use
    them."""
    scan_id = env
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    captured = {}

    def fake_chat(backend, messages, **kwargs):
        captured["messages"] = messages
        captured["tools"] = kwargs.get("tools")
        return _resp(_msg("ok"))

    monkeypatch.setattr(chat_mod, "client_chat", fake_chat)
    answer_question(scan_id, "does this library have known CVEs?")
    names = _web_tool_names(captured["tools"])
    assert WEB_TOOL_NAMES <= names
    assert "WEB RESEARCH IS ENABLED" in captured["messages"][0]["content"]


def test_web_tools_hidden_when_scan_optin_off(monkeypatch, db_session_factory, tmp_path):
    """Gate 1 off (the default): the model never even sees the web schemas,
    and the prompt carries no web instructions."""
    monkeypatch.setattr("app.config.settings.data_dir", tmp_path)
    monkeypatch.setattr("app.db.SessionLocal", db_session_factory)
    with db_session_factory() as session:
        scan = Scan(filename="app.apk", platform="android", status="done")
        session.add(scan)
        session.commit()
        scan_id = scan.id
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    captured = {}

    def fake_chat(backend, messages, **kwargs):
        captured["messages"] = messages
        captured["tools"] = kwargs.get("tools")
        return _resp(_msg("ok"))

    monkeypatch.setattr(chat_mod, "client_chat", fake_chat)
    answer_question(scan_id, "does this library have known CVEs?")
    names = _web_tool_names(captured["tools"])
    assert WEB_TOOL_NAMES.isdisjoint(names)
    assert "WEB RESEARCH" not in captured["messages"][0]["content"]


def test_web_tools_hidden_when_no_active_engine(env, monkeypatch):
    """Gate 2 off: opt-in on but every engine Inactive (Settings radio all
    off) - no web schemas, no prompt section."""
    scan_id = env
    # The env fixture pointed settings.data_dir at tmp_path; write the store
    # file there with the bundled engine disabled so SearchStore.active() is
    # None when the chat's gating check reads it.
    import app.config

    store = SearchStore(app.config.settings.data_dir, settings_obj=Settings())
    store.upsert("searxng", enabled=False)
    assert store.active() is None

    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    captured = {}

    def fake_chat(backend, messages, **kwargs):
        captured["messages"] = messages
        captured["tools"] = kwargs.get("tools")
        return _resp(_msg("ok"))

    monkeypatch.setattr(chat_mod, "client_chat", fake_chat)
    answer_question(scan_id, "does this library have known CVEs?")
    names = _web_tool_names(captured["tools"])
    assert WEB_TOOL_NAMES.isdisjoint(names)
    assert "WEB RESEARCH" not in captured["messages"][0]["content"]


def test_web_tools_offered_on_ios_when_gates_hold(monkeypatch, db_session_factory, tmp_path):
    """iOS gets the web tools too (they are platform-agnostic) - while still
    never seeing the Android-only class tool."""
    monkeypatch.setattr("app.config.settings.data_dir", tmp_path)
    monkeypatch.setattr("app.db.SessionLocal", db_session_factory)
    with db_session_factory() as session:
        scan = Scan(
            filename="app.ipa", platform="ios", status="done", web_research_enabled=True
        )
        session.add(scan)
        session.commit()
        scan_id = scan.id
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: object())
    captured = {}

    def fake_chat(backend, messages, **kwargs):
        captured["tools"] = kwargs.get("tools")
        return _resp(_msg("ok"))

    monkeypatch.setattr(chat_mod, "client_chat", fake_chat)
    answer_question(scan_id, "does this library have known CVEs?")
    names = _web_tool_names(captured["tools"])
    assert WEB_TOOL_NAMES <= names
    assert "get_decompiled_class" not in names


def test_execute_web_tool_denied_without_optin(monkeypatch, db_session_factory, tmp_path):
    """Defense in depth: even a raw execute_tool call (bypassing the schema
    gate) refuses web egress on a non-opted-in scan."""
    monkeypatch.setattr("app.config.settings.data_dir", tmp_path)
    monkeypatch.setattr("app.db.SessionLocal", db_session_factory)
    with db_session_factory() as session:
        scan = Scan(filename="app.apk", platform="android", status="done")
        session.add(scan)
        session.commit()
        scan_id = scan.id
    result = json.loads(execute_tool(scan_id, "web_search", {"query": "x"}))
    assert "error" in result
    assert "not enabled" in result["error"]
    result = json.loads(execute_tool(scan_id, "web_fetch", {"url": "https://example.com"}))
    assert "error" in result


# ---- flagship: "does library X have known CVEs?" ------------------------------

# Network fakes (same shapes as the client unit tests).


class _FakeResp:
    def __init__(self, status_code=200, json_data=None, content=b"", headers=None):
        self.status_code = status_code
        self._json = json_data
        self.content = content
        self.headers = headers or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._json

    def iter_bytes(self):
        yield self.content


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

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get(self, url, headers=None):
        return self._responses.pop(0)

    def stream(self, method, url, headers=None):
        return _FakeStream(self._responses.pop(0))


def test_flagship_cve_research_cites_source_url(env, monkeypatch):
    """The full M7 flagship: opt-in scan + fake model -> real web_search
    (mocked engine JSON) -> real web_fetch (mocked page) -> answer citing the
    source URL; tools_used/tool_runs reflect both web tools."""
    scan_id = env

    # The engine: fresh store seeds bundled searxng Active (gate 2 holds).
    # The search client: a fixture SearXNG JSON payload.
    from app.search import client as search_client

    def fake_get(url, params=None, timeout=None):
        return _FakeResp(
            json_data={
                "results": [
                    {
                        "title": "CVE-2024-1234: InsecureBankv2 hardcoded credentials",
                        "url": "https://nvd.nist.gov/vuln/CVE-2024-1234",
                        "content": "InsecureBankv2 ships hardcoded credentials.",
                        "engine": "google",
                    }
                ]
            }
        )

    monkeypatch.setattr(search_client.httpx, "get", fake_get)

    def fake_client(**kw):
        return _FakeClient(
            [
                _FakeResp(
                    status_code=200,
                    content=b"<html><title>CVE advisory</title><body>"
                    b"<p>InsecureBankv2 exposes hardcoded credentials.</p></body></html>",
                )
            ]
        )

    monkeypatch.setattr(search_client.httpx, "Client", fake_client)
    monkeypatch.setattr(
        search_client, "extract", lambda html, **kw: "InsecureBankv2 exposes hardcoded credentials."
    )

    monkeypatch.setattr(chat_mod, "_pick_chat_backend", _fake_backend)
    result = answer_question(scan_id, "does InsecureBankv2 have known CVEs?")

    assert result.tool_mode == "tools"
    assert set(result.tools_used) == {"web_search", "web_fetch"}
    assert len(result.tool_runs) == 2
    names = [r.name for r in result.tool_runs]
    assert names == ["web_search", "web_fetch"]
    assert all(r.status == "ok" for r in result.tool_runs)
    assert result.tool_runs[0].count == 1  # one normalized search result
    # The answer cites the fetched source URL.
    assert "https://nvd.nist.gov/vuln/CVE-2024-1234" in result.answer
    assert "hardcoded credentials" in result.answer


def test_flagship_streaming_emits_web_steps(env, monkeypatch):
    """The streaming path of the same flagship: live token + tool_start/end
    events for the web tools, then the cited answer."""
    scan_id = env
    from app.search import client as search_client

    def fake_get(url, params=None, timeout=None):
        return _FakeResp(
            json_data={
                "results": [
                    {
                        "title": "OWASP MASTG",
                        "url": "https://mas.owasp.org/MASTG/",
                        "content": "The mobile app security testing guide.",
                        "engine": "google",
                    }
                ]
            }
        )

    monkeypatch.setattr(search_client.httpx, "get", fake_get)

    def fake_client(**kw):
        return _FakeClient(
            [
                _FakeResp(
                    status_code=200,
                    content=b"<html><title>MASTG</title><body><p>Guidance here.</p></body></html>",
                )
            ]
        )

    monkeypatch.setattr(search_client.httpx, "Client", fake_client)
    monkeypatch.setattr(search_client, "extract", lambda html, **kw: "Guidance here.")
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", _fake_backend)

    events: list[chat_mod.AgentEvent] = []
    result = answer_question(
        scan_id, "what does the MASTG say about WebView bridges?",
        stream=True, on_event=events.append,
    )
    kinds = [e.kind for e in events]
    assert "tool_start" in kinds and "tool_end" in kinds
    starts = [e for e in events if e.kind == "tool_start"]
    assert [e.payload["name"] for e in starts] == ["web_search", "web_fetch"]
    assert "https://mas.owasp.org/MASTG/" in result.answer
    assert len(result.tool_runs) == 2
