"""M2: add static_only to findings

Revision ID: 0003
Revises: 0002
Create Date: 2026-08-04

"""
import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column(
            "static_only",
            sa.Boolean(),
            nullable=False,
            # All existing findings are static-only; the dashboard filters on
            # this flag, so backfill with the server default on the way up.
            server_default=sa.text("1"),
        ),
    )


def downgrade() -> None:
    op.drop_column("findings", "static_only")
