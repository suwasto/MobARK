"""M9 follow-up: multi-session agent chat persistence.

The dock's thread now lives in the DB (``chat_sessions`` + ``chat_messages``)
instead of the client-only 6-turn window: create/list/rename/delete sessions,
append turns, and load a session's history for the model. The chat layer
stays stateless - the routes load the session history here and pass it to
``answer_question`` as ``history``, then persist the finished turn back here.
"""

from __future__ import annotations

import json

from sqlalchemy import func, select

from app.models import ChatMessage, ChatSession, utcnow

# Sessions are auto-titled from the first question's first line; the
# placeholder survives until the first user turn (or a manual rename).
_PLACEHOLDER_TITLE = "New chat"
_TITLE_MAX = 60
# Same per-turn cap the client history used - bounded rows, bounded prompts.
_MESSAGE_CHAR_CAP = 4000


def _auto_title(question: str) -> str:
    first_line = (question or "").strip().splitlines()[0] if question else ""
    first_line = " ".join(first_line.split())
    if not first_line:
        return _PLACEHOLDER_TITLE
    if len(first_line) > _TITLE_MAX:
        return first_line[:_TITLE_MAX - 1].rstrip() + "…"
    return first_line


def create_session(db, scan_id: int, *, title: str | None = None) -> ChatSession:
    """A fresh (empty) session for a scan, titled ``New chat`` until the
    first question arrives (or a manual rename)."""
    session = ChatSession(scan_id=scan_id, title=(title or _PLACEHOLDER_TITLE)[:120])
    db.add(session)
    db.commit()
    db.refresh(session)
    return session


def list_sessions(db, scan_id: int) -> list[ChatSession]:
    """All sessions for a scan, most recently used first."""
    return list(
        db.scalars(
            select(ChatSession)
            .where(ChatSession.scan_id == scan_id)
            .order_by(ChatSession.updated_at.desc(), ChatSession.id.desc())
        )
    )


def get_session(db, session_id: int, scan_id: int | None = None) -> ChatSession | None:
    """One session, optionally scoped to a scan (route-level ownership check)."""
    stmt = select(ChatSession).where(ChatSession.id == session_id)
    if scan_id is not None:
        stmt = stmt.where(ChatSession.scan_id == scan_id)
    return db.scalars(stmt).first()


def rename_session(db, session: ChatSession, title: str) -> ChatSession:
    session.title = (title or "").strip()[:120] or _PLACEHOLDER_TITLE
    session.updated_at = utcnow()
    db.commit()
    db.refresh(session)
    return session


def delete_session(db, session: ChatSession) -> None:
    """Hard delete - messages cascade (ondelete CASCADE + delete-orphan)."""
    db.delete(session)
    db.commit()


def add_message(
    db,
    session: ChatSession,
    *,
    role: str,
    content: str,
    tool_runs: list[dict] | None = None,
    citations: list[dict] | None = None,
) -> ChatMessage:
    """Append one turn (``position`` = next in-session index). The first
    user question auto-titles the session; a manual rename wins. Touches
    ``updated_at`` so the list's most-recently-used sort stays honest.
    ``tool_runs`` / ``citations`` (Citation-shaped dicts) persist on the
    assistant turn so reloaded history re-renders steps + source chips."""
    if role == "user" and session.title == _PLACEHOLDER_TITLE:
        session.title = _auto_title(content)
    session.updated_at = utcnow()
    count = db.scalar(
        select(func.count(ChatMessage.id)).where(ChatMessage.session_id == session.id)
    )
    msg = ChatMessage(
        session_id=session.id,
        role=role,
        content=content[:_MESSAGE_CHAR_CAP],
        tool_runs_json=json.dumps(tool_runs) if tool_runs else None,
        citations_json=json.dumps(citations) if citations else None,
        position=count or 0,
    )
    db.add(msg)
    db.commit()
    db.refresh(msg)
    return msg


def session_history(db, session_id: int) -> list[ChatMessage]:
    """The session's turns in conversation order (model input order)."""
    return list(
        db.scalars(
            select(ChatMessage)
            .where(ChatMessage.session_id == session_id)
            .order_by(ChatMessage.position, ChatMessage.id)
        )
    )


def last_message(db, session_id: int) -> ChatMessage | None:
    """The newest turn - the session list's preview."""
    return db.scalars(
        select(ChatMessage)
        .where(ChatMessage.session_id == session_id)
        .order_by(ChatMessage.position.desc(), ChatMessage.id.desc())
        .limit(1)
    ).first()


def message_count(db, session_id: int) -> int:
    return (
        db.scalar(
            select(func.count(ChatMessage.id)).where(ChatMessage.session_id == session_id)
        )
        or 0
    )
