"""M9 follow-up: persist assistant citations - chat_messages.citations_json

Revision ID: 0012
Revises: 0011
Create Date: 2026-08-13

Assistant turns already persist their content + tool-run trace; the citation
chips (file/line/snippet) were NOT stored, so a reloaded session's history
lost them. ``citations_json`` holds the Citation-shaped list for assistant
turns; NULL on older rows renders history without chips (no backfill).
"""
import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "chat_messages",
        sa.Column("citations_json", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("chat_messages", "citations_json")
