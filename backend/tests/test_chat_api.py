"""API tests — POST /scans/{id}/chat + GET /scans/{id}/graph (M4 Layers 1-3).

The old RAG chat API tests were deleted with the pipeline; these cover the
non-embedding replacement. answer_question is monkeypatched — no LLM.
"""
from __future__ import annotations

import json

from app.agent.chat import AgentResult, ChatNotConfigured, Citation
from app.models import Scan


def _add_scan(db_session_factory, *, platform="android", status="done"):
    with db_session_factory() as session:
        scan = Scan(filename="app.apk", platform=platform, status=status)
        session.add(scan)
        session.commit()
        return scan.id


# ---- chat endpoint ------------------------------------------------------------


def test_chat_unknown_scan_404(client):
    r = client.post("/api/v1/scans/999999/chat", json={"question": "hi"})
    assert r.status_code == 404


def test_chat_not_analyzed_409(client, db_session_factory):
    scan_id = _add_scan(db_session_factory, status="queued")
    r = client.post(f"/api/v1/scans/{scan_id}/chat", json={"question": "hi"})
    assert r.status_code == 409
    assert "not analyzed" in r.json()["detail"]


def test_chat_no_model_configured_400(client, db_session_factory, monkeypatch):
    scan_id = _add_scan(db_session_factory)
    from app.api.routes import scans as routes

    def boom(*args, **kwargs):
        raise ChatNotConfigured("no chat model configured — pick a backend + model in Settings")

    monkeypatch.setattr(routes, "answer_question", boom)
    r = client.post(f"/api/v1/scans/{scan_id}/chat", json={"question": "hi"})
    assert r.status_code == 400
    assert "no chat model configured" in r.json()["detail"]


def test_chat_success_with_citations(client, db_session_factory, monkeypatch):
    scan_id = _add_scan(db_session_factory)
    from app.api.routes import scans as routes

    def fake_answer(scan_id, question, **kwargs):
        return AgentResult(
            answer="The WebView client is defined in com/app/W.java:42.",
            citations=[Citation(file="com/app/W.java", line=42, snippet="public class W")],
            sources=["com/app/W.java"],
            tools_used=["graph_query", "read_file"],
        )

    monkeypatch.setattr(routes, "answer_question", fake_answer)
    r = client.post(f"/api/v1/scans/{scan_id}/chat", json={"question": "where is the webview"})
    assert r.status_code == 200
    body = r.json()
    assert "com/app/W.java:42" in body["answer"]
    assert body["citations"][0]["file"] == "com/app/W.java"
    assert body["citations"][0]["line"] == 42
    assert body["sources"] == ["com/app/W.java"]


def test_chat_timeout_forwarded_and_504(client, db_session_factory, monkeypatch):
    from app.agent.chat import AgentTimeout
    from app.api.routes import scans as routes

    captured = {}

    def fake_answer(scan_id, question, **kwargs):
        captured.update(kwargs)
        return AgentResult(
            answer="ok", citations=[], sources=[], tools_used=[]
        )

    monkeypatch.setattr(routes, "answer_question", fake_answer)
    scan_id = _add_scan(db_session_factory)

    # 1) per-request timeout_seconds is forwarded to the agent loop
    r = client.post(
        f"/api/v1/scans/{scan_id}/chat", json={"question": "hi", "timeout_seconds": 5}
    )
    assert r.status_code == 200
    assert captured["timeout"] == 5

    # 2) a hung LLM call (AgentTimeout) maps to 504, not a stuck worker
    def slow(*args, **kwargs):
        raise AgentTimeout("agent chat for scan 1 exceeded its 120s budget")

    monkeypatch.setattr(routes, "answer_question", slow)
    r = client.post(f"/api/v1/scans/{scan_id}/chat", json={"question": "hi"})
    assert r.status_code == 504
    assert "budget" in r.json()["detail"]


def test_chat_upstream_llm_failure_502(client, db_session_factory, monkeypatch):
    """An upstream LLM failure (e.g. Ollama can't load the model's
    architecture) maps to 502 with the upstream message — not a raw 500."""
    from app.agent.chat import ChatUpstreamError
    from app.api.routes import scans as routes

    def boom(*args, **kwargs):
        raise ChatUpstreamError(
            "LLM call failed: litellm.APIConnectionError: OllamaException - "
            "unknown model architecture: 'nanbeige'"
        )

    monkeypatch.setattr(routes, "answer_question", boom)
    scan_id = _add_scan(db_session_factory)
    r = client.post(f"/api/v1/scans/{scan_id}/chat", json={"question": "hi"})
    assert r.status_code == 502
    assert "unknown model architecture" in r.json()["detail"]


def test_chat_validation_empty_question_422(client, db_session_factory):
    scan_id = _add_scan(db_session_factory)
    r = client.post(f"/api/v1/scans/{scan_id}/chat", json={"question": ""})
    assert r.status_code == 422


# ---- chat cancel (Stop button) ------------------------------------------------


def test_chat_cancel_calls_request_cancel(client, db_session_factory, monkeypatch):
    """The Stop button's endpoint sets the in-process cancel flag (which the
    agent loop polls between rounds) — verified against the real handler."""
    from app.api.routes import scans as routes

    called = {"scan_id": None}

    def fake_cancel(scan_id):
        called["scan_id"] = scan_id

    monkeypatch.setattr(routes, "request_cancel", fake_cancel)
    scan_id = _add_scan(db_session_factory)
    r = client.post(f"/api/v1/scans/{scan_id}/chat/cancel")
    assert r.status_code == 200
    assert r.json() == {"cancelled": True}
    assert called["scan_id"] == scan_id


def test_chat_cancel_is_noop_without_in_flight_chat(client, db_session_factory):
    """Cancelling when nothing is running is a clean 200 no-op — the flag
    only exists while a request is in flight (request_cancel on a missing
    event must never raise)."""
    scan_id = _add_scan(db_session_factory)
    r = client.post(f"/api/v1/scans/{scan_id}/chat/cancel")
    assert r.status_code == 200
    assert r.json() == {"cancelled": True}


def test_chat_cancel_unknown_scan_404(client):
    r = client.post("/api/v1/scans/999999/chat/cancel")
    assert r.status_code == 404


def test_chat_interrupted_409(client, db_session_factory, monkeypatch):
    """A cancelled chat (Stop button -> ChatInterrupted) maps to 409 — never
    a fake 200 answer."""
    from app.agent.chat import ChatInterrupted
    from app.api.routes import scans as routes

    def boom(*args, **kwargs):
        raise ChatInterrupted("agent chat for scan 1 was interrupted by the user")

    monkeypatch.setattr(routes, "answer_question", boom)
    scan_id = _add_scan(db_session_factory)
    r = client.post(f"/api/v1/scans/{scan_id}/chat", json={"question": "hi"})
    assert r.status_code == 409
    assert "interrupted" in r.json()["detail"]


# ---- graph state endpoint -----------------------------------------------------


def test_graph_state_android_built(client, db_session_factory, monkeypatch, tmp_path):
    scan_id = _add_scan(db_session_factory)
    import app.config

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    p = tmp_path / "graphs" / str(scan_id) / "graphify-out" / "graph.json"
    p.parent.mkdir(parents=True)
    p.write_text(
        json.dumps(
            {"nodes": [{"id": "a"}] * 3, "links": [{"source": "a", "target": "b"}] * 2}
        )
    )

    r = client.get(f"/api/v1/scans/{scan_id}/graph")
    assert r.status_code == 200
    body = r.json()
    assert body["built"] is True
    assert body["nodes"] == 3
    assert body["edges"] == 2
    assert body["graph_path"] == f"graphs/{scan_id}/graphify-out/graph.json"


def test_graph_state_android_not_built(client, db_session_factory, monkeypatch, tmp_path):
    scan_id = _add_scan(db_session_factory)
    import app.config

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    r = client.get(f"/api/v1/scans/{scan_id}/graph")
    assert r.status_code == 200
    body = r.json()
    assert body["built"] is False
    assert "not built yet" in body["reason"]


def test_graph_state_ios_is_android_only(client, db_session_factory, monkeypatch, tmp_path):
    scan_id = _add_scan(db_session_factory, platform="ios")
    import app.config

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    r = client.get(f"/api/v1/scans/{scan_id}/graph")
    assert r.status_code == 200
    body = r.json()
    assert body["built"] is False
    assert "Android-only" in body["reason"]


def test_graph_state_missing_scan_404(client):
    assert client.get("/api/v1/scans/999999/graph").status_code == 404


# ---- Code maps explorer endpoints (search / hubs / node detail) ---------------


def _write_graph_file(tmp_path, scan_id, nodes, links):
    p = tmp_path / "graphs" / str(scan_id) / "graphify-out" / "graph.json"
    p.parent.mkdir(parents=True)
    p.write_text(json.dumps({"nodes": nodes, "links": links}))
    return p


def _graph_nodes():
    return [
        {
            "id": "n_wv",
            "label": "MyWebViewClient",
            "file_type": "class",
            "source_file": "com/app/MyWebViewClient.java",
            "source_location": "L42",
        },
        {
            "id": "n_act",
            "label": "LoginActivity",
            "file_type": "class",
            "source_file": "com/app/LoginActivity.java",
            "source_location": "L7",
        },
        {
            "id": "n_net",
            "label": "NetworkConfig",
            "file_type": "class",
            "source_file": "com/app/NetworkConfig.java",
            "source_location": "L1",
        },
    ]


def _graph_links():
    return [
        {"source": "n_act", "target": "n_wv", "relation": "calls"},
        {"source": "n_wv", "target": "n_net", "relation": "imports"},
    ]


def test_graph_search_happy(client, db_session_factory, monkeypatch, tmp_path):
    scan_id = _add_scan(db_session_factory)
    import app.config

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    _write_graph_file(tmp_path, scan_id, _graph_nodes(), _graph_links())

    r = client.get(f"/api/v1/scans/{scan_id}/graph/search", params={"q": "webview"})
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 1
    node = body["nodes"][0]
    assert node["label"] == "MyWebViewClient"
    assert node["file_type"] == "class"
    assert node["file"] == "com/app/MyWebViewClient.java"
    assert node["line"] == 42


def test_graph_search_empty_query_returns_empty(client, db_session_factory, monkeypatch, tmp_path):
    scan_id = _add_scan(db_session_factory)
    import app.config

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    _write_graph_file(tmp_path, scan_id, _graph_nodes(), _graph_links())
    r = client.get(f"/api/v1/scans/{scan_id}/graph/search", params={"q": "  "})
    assert r.status_code == 200
    assert r.json() == {"query": "  ", "total": 0, "nodes": []}


def test_graph_search_ios_409(client, db_session_factory, monkeypatch, tmp_path):
    scan_id = _add_scan(db_session_factory, platform="ios")
    import app.config

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    r = client.get(f"/api/v1/scans/{scan_id}/graph/search", params={"q": "x"})
    assert r.status_code == 409
    assert "Android-only" in r.json()["detail"]


def test_graph_search_not_built_409(client, db_session_factory, monkeypatch, tmp_path):
    scan_id = _add_scan(db_session_factory)
    import app.config

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    r = client.get(f"/api/v1/scans/{scan_id}/graph/search", params={"q": "x"})
    assert r.status_code == 409
    assert "not built yet" in r.json()["detail"]


def test_graph_search_unknown_scan_404(client):
    r = client.get("/api/v1/scans/999999/graph/search", params={"q": "x"})
    assert r.status_code == 404


def test_graph_hubs_and_node_detail(client, db_session_factory, monkeypatch, tmp_path):
    scan_id = _add_scan(db_session_factory)
    import app.config

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    _write_graph_file(tmp_path, scan_id, _graph_nodes(), _graph_links())

    r = client.get(f"/api/v1/scans/{scan_id}/graph/hubs")
    assert r.status_code == 200
    hubs = r.json()["hubs"]
    assert hubs[0]["node"]["id"] == "n_wv"  # linked both ways -> degree 2
    assert hubs[0]["degree"] == 2

    r = client.get(f"/api/v1/scans/{scan_id}/graph/node/n_wv")
    assert r.status_code == 200
    body = r.json()
    assert body["node"]["id"] == "n_wv"
    assert body["degree"] == 2
    out = [n for n in body["neighbors"] if n["direction"] == "out"]
    inn = [n for n in body["neighbors"] if n["direction"] == "in"]
    assert [n["node"]["id"] for n in out] == ["n_net"]
    assert [n["node"]["id"] for n in inn] == ["n_act"]
    assert out[0]["relation"] == "imports"
    assert inn[0]["relation"] == "calls"


def test_graph_node_unknown_404(client, db_session_factory, monkeypatch, tmp_path):
    scan_id = _add_scan(db_session_factory)
    import app.config

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    _write_graph_file(tmp_path, scan_id, _graph_nodes(), _graph_links())
    r = client.get(f"/api/v1/scans/{scan_id}/graph/node/zzz")
    assert r.status_code == 404
    assert "not found" in r.json()["detail"]
