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


def test_chat_validation_empty_question_422(client, db_session_factory):
    scan_id = _add_scan(db_session_factory)
    r = client.post(f"/api/v1/scans/{scan_id}/chat", json={"question": ""})
    assert r.status_code == 422


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
