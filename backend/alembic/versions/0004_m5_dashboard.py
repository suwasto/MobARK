"""M5: dashboard columns - findings.explanation, scans.ai_summary, scans.stage

Revision ID: 0004
Revises: 0003
Create Date: 2026-08-06

All three are nullable caches/state for the M5 dashboard:
- ``findings.explanation`` - cached AI explanation (POST .../explain)
- ``scans.ai_summary`` - cached AI overview summary (POST .../summary)
- ``scans.stage`` - human-readable pipeline stage for the progress screen

"""
import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("explanation", sa.Text(), nullable=True))
    op.add_column("scans", sa.Column("ai_summary", sa.Text(), nullable=True))
    op.add_column("scans", sa.Column("stage", sa.String(length=32), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "stage")
    op.drop_column("scans", "ai_summary")
    op.drop_column("findings", "explanation")
