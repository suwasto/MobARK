"""Dev-only fake LLM tests (M6 follow-up) — no network, no Ollama.

The fake is the deterministic stand-in for a real model: seeded by the
MASA_FAKE_MODEL knob, short-circuited in model/client.py, and scripted in
app/model/fake.py. These tests pin the script's shapes (chunk stream,
buffered response, composed answer) and the store seeding/reconcile logic.
"""
from __future__ import annotations

import json

import pytest

import app.config
import app.model.client as client_mod
from app.agent.chat import _stream_round
from app.model.backends import BackendStore, ModelBackend, _seed_backends
from app.model.fake import FAKE_MODEL, fake_chat_response, fake_stream_chunks
from app.model.health import _probe_completion
from app.model.providers import PROVIDERS
from app.models import Finding, Scan


def _fake_backend() -> ModelBackend:
    return ModelBackend(
        id="fake",
        provider_id="fake",
        name="Fake (dev demo)",
        kind="local",
        base_url="",
        model=FAKE_MODEL,
        api_key="fake",
    )


def _tool_results(messages):
    """The tool-role contents the fake should compose its answer from."""
    return [m["content"] for m in messages if m.get("role") == "tool"]


# ---- config knob env mapping (live-verified Aug 9) ---------------------------


def test_fake_knob_reads_documented_env_var(monkeypatch):
    """Regression: pydantic-settings derives env names from FIELD names, so
    ``fake_model_enabled`` would silently become MASA_FAKE_MODEL_ENABLED —
    the documented knob MASA_FAKE_MODEL needs the explicit alias. The
    live demo run exposed this: the server ignored MASA_FAKE_MODEL=1."""
    from app.config import Settings

    monkeypatch.setenv("MASA_FAKE_MODEL", "1")
    assert Settings().fake_model_enabled is True
    monkeypatch.setenv("MASA_FAKE_MODEL", "0")
    assert Settings().fake_model_enabled is False
    monkeypatch.delenv("MASA_FAKE_MODEL")
    assert Settings().fake_model_enabled is False


# ---- provider table + store seeding ------------------------------------------


def test_fake_provider_in_table():
    provider = PROVIDERS["fake"]
    assert provider.kind == "local"
    assert provider.suggested_models == ("demo",)
    assert provider.models_path is None  # no live listing — static "demo"


def test_seed_omits_fake_by_default(monkeypatch):
    monkeypatch.setattr(app.config.settings, "fake_model_enabled", False)
    seeded = _seed_backends(app.config.settings)
    assert all(b.id != "fake" for b in seeded)


def test_seed_includes_fake_when_knob_on(monkeypatch):
    monkeypatch.setattr(app.config.settings, "fake_model_enabled", True)
    seeded = _seed_backends(app.config.settings)
    assert seeded[0].id == "fake"  # inserted first -> pick_chat_backend hits it
    assert seeded[0].provider_id == "fake"
    assert seeded[0].model == "demo"
    assert seeded[0].enabled


def test_store_reconciles_fake_into_existing_store(monkeypatch, tmp_path):
    """Flipping the knob on an existing store adds the fake (the file is the
    source of truth after first read, so read() must converge the entry)."""
    store = BackendStore(tmp_path, app.config.settings)
    # A store seeded with the knob OFF carries only the real local backends.
    assert [b.id for b in store.read()] == ["ollama", "lm-studio"]
    monkeypatch.setattr(app.config.settings, "fake_model_enabled", True)
    assert store.get("fake") is not None
    assert store.get("fake").model == "demo"
    assert store.get("fake").enabled
    # The reconcile is idempotent — a converged store doesn't rewrite itself.
    assert [b.id for b in store.read()] == ["fake", "ollama", "lm-studio"]


def test_store_reconciles_fake_out_when_knob_off(monkeypatch, tmp_path):
    monkeypatch.setattr(app.config.settings, "fake_model_enabled", True)
    store = BackendStore(tmp_path, app.config.settings)
    assert store.get("fake") is not None
    monkeypatch.setattr(app.config.settings, "fake_model_enabled", False)
    assert store.get("fake") is None


# ---- buffered response script ------------------------------------------------


def test_fake_chat_plain_answer_without_tools():
    response = fake_chat_response([{"role": "user", "content": "hi"}], tools=None)
    content = response.choices[0].message.content
    assert "MASA_FAKE_MODEL" in content
    assert not getattr(response.choices[0].message, "tool_calls", None)


def test_fake_chat_round1_thinking_plus_two_tool_calls():
    messages = [{"role": "user", "content": "where is the webview?"}]
    response = fake_chat_response(messages, tools=[{"type": "function"}])
    message = response.choices[0].message
    assert "search the decompiled source" in message.content
    calls = message.tool_calls
    assert [c.function.name for c in calls] == ["search_code", "read_manifest"]
    assert json.loads(calls[0].function.arguments) == {"pattern": "WebView"}
    assert json.loads(calls[1].function.arguments) == {}


def test_fake_chat_round2_composes_answer_from_real_hits():
    messages = [
        {"role": "user", "content": "where is the webview?"},
        {"role": "tool", "tool_call_id": "call_search",
         "content": json.dumps([{"file": "com/app/W.java", "line": 42,
                                 "snippet": "public class W extends WebViewClient"}]),
        },
        {"role": "tool", "tool_call_id": "call_manifest",
         "content": json.dumps({"package": "com.example.app"})},
    ]
    response = fake_chat_response(messages, tools=[{"type": "function"}])
    content = response.choices[0].message.content
    assert "com/app/W.java:42" in content
    assert "MASA_FAKE_MODEL" in content
    assert not getattr(response.choices[0].message, "tool_calls", None)


def test_fake_chat_round2_tool_error_never_mistaken_for_manifest():
    """A failed read_manifest ({"error": ...}) must not render as "the
    manifest summary is available" — error dicts are skipped (review catch)."""
    messages = [
        {"role": "tool", "tool_call_id": "c1", "content": "[]"},
        {"role": "tool", "tool_call_id": "c2",
         "content": json.dumps({"error": "AndroidManifest.xml not found"})},
    ]
    response = fake_chat_response(messages, tools=[{"type": "function"}])
    content = response.choices[0].message.content
    assert "AndroidManifest.xml not found" not in content
    assert "manifest summary is available" not in content


def test_fake_chat_round2_no_hits_falls_back_to_manifest():
    messages = [
        {"role": "user", "content": "where is the webview?"},
        {"role": "tool", "tool_call_id": "call_search", "content": "[]"},
        {"role": "tool", "tool_call_id": "call_manifest",
         "content": json.dumps({"bundle_identifier": "com.example.ios"})},
    ]
    response = fake_chat_response(messages, tools=[{"type": "function"}])
    content = response.choices[0].message.content
    assert "com.example.ios" in content


# ---- streaming chunk script --------------------------------------------------


def test_fake_stream_round1_tokens_then_tool_deltas():
    messages = [{"role": "user", "content": "where is the webview?"}]
    chunks = list(fake_stream_chunks(messages, tools=[{"type": "function"}]))
    contents = [c.choices[0].delta.content for c in chunks if c.choices[0].delta.content]
    assert "search the decompiled source" in "".join(contents)
    tool_chunks = [c.choices[0].delta.tool_calls for c in chunks if c.choices[0].delta.tool_calls]
    assert len(tool_chunks) == 3
    # search_code arguments arrive split across two deltas (index 0)
    assert tool_chunks[0][0]["index"] == 0
    assert tool_chunks[1][0]["function"]["arguments"] == 'iew"}'
    merged = tool_chunks[0][0]["function"]["arguments"] + tool_chunks[1][0]["function"]["arguments"]
    assert json.loads(merged) == {"pattern": "WebView"}


def test_fake_stream_round2_only_answer_tokens():
    messages = [
        {"role": "user", "content": "where is the webview?"},
        {"role": "tool", "tool_call_id": "call_search",
         "content": json.dumps([{"file": "com/app/W.java", "line": 42,
                                 "snippet": "public class W extends WebViewClient"}]),
        },
        {"role": "tool", "tool_call_id": "call_manifest", "content": "{}"},
    ]
    chunks = list(fake_stream_chunks(messages, tools=[{"type": "function"}]))
    assert all(c.choices[0].delta.tool_calls is None for c in chunks)
    answer = "".join(c.choices[0].delta.content for c in chunks)
    assert "com/app/W.java:42" in answer
    assert "MASA_FAKE_MODEL" in answer


def test_fake_stream_plain_without_tools():
    chunks = list(fake_stream_chunks([{"role": "user", "content": "hi"}], tools=None))
    assert all(c.choices[0].delta.tool_calls is None for c in chunks)
    text = "".join(c.choices[0].delta.content for c in chunks)
    assert "MASA_FAKE_MODEL" in text


def test_fake_stream_rounds_flow_through_real_accumulator():
    """The fake's chunks must be consumable by the REAL _stream_round — the
    exact integration a demo turn runs (thinking text + normalized tool calls)."""
    messages = [{"role": "user", "content": "where is the webview?"}]
    tokens: list[str] = []

    class Backend:
        provider_id = "fake"

    response = _stream_round(
        Backend(),
        messages,
        temperature=0.2,
        timeout=60.0,
        tools=[{"type": "function"}],
        on_token=tokens.append,
    )
    message = response.choices[0].message
    assert "search the decompiled source" in "".join(tokens)
    assert [tc.function.name for tc in message.tool_calls] == ["search_code", "read_manifest"]
    assert json.loads(message.tool_calls[0].function.arguments) == {"pattern": "WebView"}


# ---- M7 web-research demo script ---------------------------------------------


def _web_tools():
    """The tool schemas a web-enabled scan's chat offers the model."""
    return [
        {"type": "function", "function": {"name": "web_search"}},
        {"type": "function", "function": {"name": "web_fetch"}},
    ]


def test_fake_web_round1_issues_search_when_no_results():
    response = fake_chat_response(
        [{"role": "user", "content": "any CVEs?"}], tools=_web_tools()
    )
    message = response.choices[0].message
    assert [c.function.name for c in message.tool_calls] == ["web_search"]


def test_fake_web_round1_uses_the_users_question_as_the_query():
    """A manual web-search test types its OWN query — the fake's round-1
    web_search must run the user's actual question text (a real model would
    paraphrase it; the fake is a script and searches verbatim). The canned
    query is only the fallback for empty/short questions."""
    response = fake_chat_response(
        [{"role": "user", "content": "SQLite database CVE 2026"}], tools=_web_tools()
    )
    message = response.choices[0].message
    assert [c.function.name for c in message.tool_calls] == ["web_search"]
    assert json.loads(message.tool_calls[0].function.arguments) == {
        "query": "SQLite database CVE 2026"
    }


def test_fake_web_round1_short_question_falls_back_to_canned_query():
    response = fake_chat_response([{"role": "user", "content": "hi"}], tools=_web_tools())
    message = response.choices[0].message
    assert json.loads(message.tool_calls[0].function.arguments)["query"] == (
        "InsecureBankv2 known vulnerabilities CVE"
    )


def test_fake_web_round2_fetches_top_result_once():
    messages = [
        {"role": "user", "content": "any CVEs?"},
        {"role": "tool", "tool_call_id": "call_search",
         "content": json.dumps([{"title": "T", "url": "https://example.com/cve",
                                 "snippet": "s"}])},
    ]
    response = fake_chat_response(messages, tools=_web_tools())
    message = response.choices[0].message
    assert [c.function.name for c in message.tool_calls] == ["web_fetch"]
    assert json.loads(message.tool_calls[0].function.arguments) == {
        "url": "https://example.com/cve"
    }


def test_fake_web_round3_failed_fetch_never_retried_cites_results():
    """Regression (containerized e2e, Aug 9): a 403'd page (e.g. medium.com
    blocking the honest MASA UA) must NOT be re-fetched — the next response
    composes the answer from the search results, citing the top URL, so the
    demo always lands a citation within the default 3 tool rounds instead of
    looping on the same failed fetch until the round limit."""
    messages = [
        {"role": "user", "content": "any CVEs?"},
        {"role": "tool", "tool_call_id": "call_search",
         "content": json.dumps([{"title": "T", "url": "https://example.com/cve",
                                 "snippet": "s"}])},
        {"role": "tool", "tool_call_id": "call_fetch",
         "content": json.dumps({"error": "web_fetch got HTTP 403 from "
                                        "https://example.com/cve"})},
    ]
    response = fake_chat_response(messages, tools=_web_tools())
    message = response.choices[0].message
    assert not getattr(message, "tool_calls", None)  # no re-fetch of the same URL
    content = message.content
    assert "https://example.com/cve" in content
    assert "blocked direct reading" in content


def test_fake_web_round3_successful_page_is_cited():
    messages = [
        {"role": "user", "content": "any CVEs?"},
        {"role": "tool", "tool_call_id": "call_search",
         "content": json.dumps([{"title": "T", "url": "https://example.com/cve",
                                 "snippet": "s"}])},
        {"role": "tool", "tool_call_id": "call_fetch",
         "content": json.dumps({"url": "https://example.com/cve",
                                 "title": "CVE-2024-0001",
                                 "text": "A vulnerability..."})},
    ]
    response = fake_chat_response(messages, tools=_web_tools())
    message = response.choices[0].message
    assert not getattr(message, "tool_calls", None)
    assert "CVE-2024-0001" in message.content
    assert "https://example.com/cve" in message.content


# ---- client + health short-circuits ------------------------------------------


def test_client_chat_short_circuits_fake(monkeypatch):
    calls = {"n": 0}

    def boom(*args, **kwargs):
        calls["n"] += 1
        raise AssertionError("litellm must never see the fake backend")

    monkeypatch.setattr(client_mod.litellm, "completion", boom)
    response = client_mod.chat(_fake_backend(), [{"role": "user", "content": "hi"}])
    assert "MASA_FAKE_MODEL" in response.choices[0].message.content
    assert calls["n"] == 0


def test_client_chat_stream_short_circuits_fake(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("litellm must never see the fake backend")

    monkeypatch.setattr(client_mod.litellm, "completion", boom)
    chunks = list(
        client_mod.chat_stream(_fake_backend(), [{"role": "user", "content": "hi"}])
    )
    assert chunks
    assert chunks[0].choices[0].delta.content


def test_health_probe_fake_always_ok():
    ok, error = _probe_completion(_fake_backend(), "demo")
    assert ok is True
    assert error is None


@pytest.mark.parametrize("line", [None, 42])
def test_fake_answer_handles_missing_line(line):
    """The composed citation tolerates a hit without a line number."""
    result = json.dumps([{"file": "com/app/W.java", "line": line, "snippet": "x"}])
    response = fake_chat_response(
        [{"role": "tool", "tool_call_id": "c", "content": result}],
        tools=[{"type": "function"}],
    )
    content = response.choices[0].message.content
    assert "com/app/W.java" in content


# ---- the demo itself: real agent loop + real tools + fake model -------------


@pytest.fixture()
def demo_scan(monkeypatch, db_session_factory, tmp_path):
    """A done Android scan with a real tree: W.java (WebView on line 42) +
    an AndroidManifest.xml so BOTH fake tool calls execute for real."""
    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    monkeypatch.setattr("app.db.SessionLocal", db_session_factory)
    with db_session_factory() as session:
        scan = Scan(filename="app.apk", platform="android", status="done")
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
            )
        )
        session.commit()
    root = tmp_path / "work" / str(scan_id) / "decompiled"
    (root / "sources/com/app").mkdir(parents=True)
    lines = [f"// {i}" for i in range(1, 42)]
    lines.append("public class W extends WebViewClient {")
    lines.append("  void m() {}")
    lines.append("}")
    (root / "sources/com/app/W.java").write_text("\n".join(lines) + "\n")
    (root / "resources").mkdir(parents=True)
    (root / "resources/AndroidManifest.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.example.demo">\n'
        "  <uses-sdk android:minSdkVersion=\"21\"/>\n"
        "</manifest>\n"
    )
    return scan_id


def test_fake_backend_runs_real_agent_loop(demo_scan, monkeypatch):
    """THE demo: the fake model + real loop + real tools, streamed. The dock
    sees thinking tokens, two live tool steps with real results, then a
    composed answer citing the real hit (com/app/W.java:42)."""
    from app.agent import chat as chat_mod
    from app.agent.chat import answer_question

    scan_id = demo_scan
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: _fake_backend())
    events: list[chat_mod.AgentEvent] = []

    result = answer_question(
        scan_id, "where is the webview?", stream=True, on_event=events.append
    )

    kinds = [e.kind for e in events]
    assert kinds[0] == "token"  # thinking aloud streams first
    assert "tool_start" in kinds and "tool_end" in kinds
    starts = [e for e in events if e.kind == "tool_start"]
    assert [s.payload["name"] for s in starts] == ["search_code", "read_manifest"]
    ends = [e for e in events if e.kind == "tool_end"]
    assert all(e.payload["status"] == "ok" for e in ends)
    search_end = next(e for e in ends if e.payload["name"] == "search_code")
    assert search_end.payload["count"] == 1  # W.java:42 — a REAL hit

    # The answer cites the real first hit -> clickable src-chip in the dock.
    assert "com/app/W.java:42" in result.answer
    assert any(c.file == "com/app/W.java" and c.line == 42 for c in result.citations)
    assert result.tool_mode == "tools"
    assert len(result.tool_runs) == 2
    assert [r.name for r in result.tool_runs] == ["search_code", "read_manifest"]
    assert all(r.status == "ok" for r in result.tool_runs)


def test_fake_backend_buffered_path_same_script(demo_scan, monkeypatch):
    """The buffered (non-streaming) /chat path with the fake runs the same
    script — thinking + two tools + composed answer."""
    from app.agent import chat as chat_mod
    from app.agent.chat import answer_question

    scan_id = demo_scan
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: _fake_backend())
    result = answer_question(scan_id, "where is the webview?")
    assert "com/app/W.java:42" in result.answer
    assert result.tool_mode == "tools"
    assert [r.name for r in result.tool_runs] == ["search_code", "read_manifest"]
