"""M1: add mastg_test_id to findings + index on tool

Revision ID: 0002
Revises: 0001
Create Date: 2026-08-03

"""
import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("mastg_test_id", sa.String(length=64), nullable=True),
    )
    op.create_index("ix_findings_tool", "findings", ["tool"])


def downgrade() -> None:
    op.drop_index("ix_findings_tool", table_name="findings")
    op.drop_column("findings", "mastg_test_id")
