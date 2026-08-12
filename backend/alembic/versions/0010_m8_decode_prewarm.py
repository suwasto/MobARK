"""M8 follow-up (Aug 12): apktool pre-decode warm-up + stuck-queue guard

Revision ID: 0010
Revises: 0009
Create Date: 2026-08-12

Adds ``scans.apktool_queued_at`` - the enqueue clock for the stall guard.
With the worker running, Android scans now pre-decode in the background the
moment analysis lands; a ``queued`` state older than
``MASA_APKTOOL_QUEUE_STALL_SECONDS`` (60s) means no RQ worker is consuming
the queue, and smali-status reports ``stalled`` with a start-the-worker hint
instead of spinning forever. Existing rows default to NULL (nothing was
pre-enqueued; the on-demand trigger sets it on the next decode).
"""
import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("apktool_queued_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("scans", "apktool_queued_at")
