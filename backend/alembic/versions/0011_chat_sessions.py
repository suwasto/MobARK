"""M9 follow-up: multi-session agent chat - chat_sessions + chat_messages

Revision ID: 0011
Revises: 0010
Create Date: 2026-08-13

The agent dock's chat thread used to live client-side only (the backend
never persisted chat; the frontend re-sent the last 6 turns as ``history``).
Sessions move the thread to the DB: ``chat_sessions`` is one thread per
scan (auto-titled from the first question, renameable), ``chat_messages``
is the ordered turns (user/assistant) with the assistant's tool-run trace.
Deleting a session cascades its messages.

No backfill: no chat rows existed before this migration.
"""
import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "chat_sessions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "scan_id",
            sa.Integer(),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("title", sa.String(length=120), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_chat_sessions_scan_id", "chat_sessions", ["scan_id"])

    op.create_table(
        "chat_messages",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "session_id",
            sa.Integer(),
            sa.ForeignKey("chat_sessions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # user | assistant
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        # JSON list of ToolRun-shaped dicts (assistant turns only)
        sa.Column("tool_runs_json", sa.Text(), nullable=True),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_chat_messages_session_id", "chat_messages", ["session_id"])


def downgrade() -> None:
    op.drop_index("ix_chat_messages_session_id", table_name="chat_messages")
    op.drop_table("chat_messages")
    op.drop_index("ix_chat_sessions_scan_id", table_name="chat_sessions")
    op.drop_table("chat_sessions")
