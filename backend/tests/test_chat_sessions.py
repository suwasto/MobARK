"""M9 follow-up: multi-session agent chat - sessions CRUD + turn persistence.

Covers the chat_sessions/chat_messages surface: create/list/rename/delete,
per-scan ownership (404s), and the /chat + /chat/stream routes persisting
the user + assistant turns (auto-title from the first question, tool trace
on the assistant turn). answer_question is monkeypatched - no LLM.
"""
from __future__ import annotations

import json

from app.agent.chat import AgentResult, Citation, ToolRun
from app.models import Scan
from tests.conftest import authed_user_id


def _add_scan(db_session_factory, *, platform="android", status="done"):
    with db_session_factory() as session:
        scan = Scan(
            filename="app.apk", platform=platform, status=status,
            user_id=authed_user_id(db_session_factory),
        )
        session.add(scan)
        session.commit()
        return scan.id


def _parse_sse(text: str) -> list[dict]:
    """Parse an SSE body into ``[{event, data}]`` (data JSON-decoded);
    comments (``: keepalive``) and empty blocks are skipped."""
    events = []
    for block in text.strip().split("\n\n"):
        if not block or block.startswith(":"):
            continue
        event = None
        data_lines = []
        for line in block.splitlines():
            if line.startswith("event:"):
                event = line[len("event:") :].strip()
            elif line.startswith("data:"):
                data_lines.append(line[len("data:") :].strip())
        if event and data_lines:
            events.append({"event": event, "data": json.loads("\n".join(data_lines))})
    return events


def _fake_answer(scan_id, question, **kwargs):
    return AgentResult(
        answer="The root check lives in com/app/W.java:42.",
        citations=[Citation(file="com/app/W.java", line=42, snippet="public class W")],
        sources=["com/app/W.java"],
        tools_used=["search_code"],
        tool_runs=[
            ToolRun(
                id="c1",
                name="search_code",
                args={"pattern": "class W"},
                status="ok",
                duration_ms=5,
            )
        ],
    )


# ---- sessions CRUD ------------------------------------------------------------


def test_sessions_crud_flow(client, db_session_factory):
    scan_id = _add_scan(db_session_factory)
    base = f"/api/v1/scans/{scan_id}/chat/sessions"

    # Empty list first.
    assert client.get(base).json() == []

    # Create -> placeholder title, zero messages.
    r = client.post(base)
    assert r.status_code == 200
    s = r.json()
    assert s["scan_id"] == scan_id
    assert s["title"] == "New chat"
    assert s["message_count"] == 0
    assert s["last_content"] is None
    sid = s["id"]

    # List shows the new session (most recently used first).
    assert [x["id"] for x in client.get(base).json()] == [sid]

    # Rename.
    r = client.post(f"{base}/{sid}/rename", json={"title": "Root check hunt"})
    assert r.status_code == 200
    assert r.json()["title"] == "Root check hunt"

    # Messages empty.
    assert client.get(f"{base}/{sid}/messages").json() == []

    # Delete -> gone everywhere.
    assert client.delete(f"{base}/{sid}").json() == {"deleted": True}
    assert client.get(base).json() == []
    assert client.get(f"{base}/{sid}/messages").status_code == 404
    assert client.post(f"{base}/{sid}/rename", json={"title": "x"}).status_code == 404


def test_sessions_scoped_to_scan(client, db_session_factory):
    scan_a = _add_scan(db_session_factory)
    scan_b = _add_scan(db_session_factory)
    base_a = f"/api/v1/scans/{scan_a}/chat/sessions"
    base_b = f"/api/v1/scans/{scan_b}/chat/sessions"
    sid = client.post(base_a).json()["id"]

    # Scan B cannot see or touch scan A's session.
    assert client.get(base_b).json() == []
    assert client.get(f"{base_b}/{sid}/messages").status_code == 404
    assert client.post(f"{base_b}/{sid}/rename", json={"title": "x"}).status_code == 404
    assert client.delete(f"{base_b}/{sid}").status_code == 404


def test_sessions_unknown_scan_404(client):
    assert client.post("/api/v1/scans/999999/chat/sessions").status_code == 404
    assert client.get("/api/v1/scans/999999/chat/sessions").status_code == 404


# ---- turn persistence ---------------------------------------------------------


def test_buffered_chat_persists_turn(client, db_session_factory, monkeypatch):
    scan_id = _add_scan(db_session_factory)
    from app.api.routes import scans as routes

    monkeypatch.setattr(routes, "answer_question", _fake_answer)
    base = f"/api/v1/scans/{scan_id}/chat/sessions"
    sid = client.post(base).json()["id"]

    r = client.post(
        f"/api/v1/scans/{scan_id}/chat",
        json={"question": "bypass the root check", "session_id": sid},
    )
    assert r.status_code == 200

    msgs = client.get(f"{base}/{sid}/messages").json()
    assert [m["role"] for m in msgs] == ["user", "assistant"]
    assert msgs[0]["content"] == "bypass the root check"
    assert msgs[1]["content"] == "The root check lives in com/app/W.java:42."
    assert msgs[1]["tool_runs"][0]["name"] == "search_code"
    assert msgs[1]["tool_runs"][0]["status"] == "ok"
    # Citations persist with the assistant turn - reloaded history keeps the
    # clickable source chips.
    assert msgs[1]["citations"] == [
        {"file": "com/app/W.java", "line": 42, "snippet": "public class W"}
    ]

    # Auto-title from the first question + list preview reflects the turn.
    lst = client.get(base).json()
    assert lst[0]["title"] == "bypass the root check"
    assert lst[0]["message_count"] == 2
    assert lst[0]["last_content"] == msgs[1]["content"]


def test_buffered_chat_second_turn_stacks_history(client, db_session_factory, monkeypatch):
    """A second turn in the same session sees the first turn in history (the
    model gets the persisted thread, not just the client's window)."""
    scan_id = _add_scan(db_session_factory)
    from app.api.routes import scans as routes

    captured = {}

    def fake_answer(scan_id, question, **kwargs):
        captured["history"] = kwargs.get("history")
        return AgentResult(
            answer="done", citations=[], sources=[], tools_used=[]
        )

    monkeypatch.setattr(routes, "answer_question", fake_answer)
    base = f"/api/v1/scans/{scan_id}/chat/sessions"
    sid = client.post(base).json()["id"]

    client.post(
        f"/api/v1/scans/{scan_id}/chat",
        json={"question": "bypass the root check", "session_id": sid},
    )
    # Second turn: history carries turn 1 (the current question is separate).
    r = client.post(
        f"/api/v1/scans/{scan_id}/chat",
        json={"question": "continue", "session_id": sid},
    )
    assert r.status_code == 200
    assert captured["history"] == [
        {"role": "user", "content": "bypass the root check"},
        # the first turn's assistant answer (this test's fake returns "done")
        {"role": "assistant", "content": "done"},
    ]


def test_stream_chat_persists_turn(client, db_session_factory, monkeypatch):
    scan_id = _add_scan(db_session_factory)
    from app.api.routes import scans as routes

    monkeypatch.setattr(routes, "answer_question", _fake_answer)
    monkeypatch.setattr(routes, "check_configured", lambda: None)  # hermetic
    # The worker thread opens its own SessionLocal - point it at the scratch
    # DB so the persisted turns land where the test reads them.
    monkeypatch.setattr("app.db.SessionLocal", db_session_factory)
    base = f"/api/v1/scans/{scan_id}/chat/sessions"
    sid = client.post(base).json()["id"]

    r = client.post(
        f"/api/v1/scans/{scan_id}/chat/stream",
        json={"question": "where is the root check", "session_id": sid},
    )
    assert r.status_code == 200
    kinds = [e["event"] for e in _parse_sse(r.text)]
    assert "answer" in kinds

    msgs = client.get(f"{base}/{sid}/messages").json()
    assert [m["role"] for m in msgs] == ["user", "assistant"]
    assert msgs[0]["content"] == "where is the root check"
    assert msgs[1]["content"] == "The root check lives in com/app/W.java:42."
    assert msgs[1]["citations"][0]["file"] == "com/app/W.java"
    assert msgs[1]["citations"][0]["line"] == 42


def test_chat_session_id_wrong_scan_404(client, db_session_factory, monkeypatch):
    scan_a = _add_scan(db_session_factory)
    scan_b = _add_scan(db_session_factory)
    from app.api.routes import scans as routes

    monkeypatch.setattr(routes, "answer_question", _fake_answer)
    # The stream route 400s on a missing model BEFORE the session check -
    # make the config check hermetic so the 404 path is what's exercised.
    monkeypatch.setattr(routes, "check_configured", lambda: None)
    sid = client.post(f"/api/v1/scans/{scan_a}/chat/sessions").json()["id"]

    r = client.post(
        f"/api/v1/scans/{scan_b}/chat", json={"question": "hi", "session_id": sid}
    )
    assert r.status_code == 404

    r = client.post(
        f"/api/v1/scans/{scan_b}/chat/stream", json={"question": "hi", "session_id": sid}
    )
    assert r.status_code == 404


def test_chat_unknown_session_404(client, db_session_factory, monkeypatch):
    scan_id = _add_scan(db_session_factory)
    r = client.post(
        f"/api/v1/scans/{scan_id}/chat", json={"question": "hi", "session_id": 999999}
    )
    assert r.status_code == 404
