"""M16 (V2): dynamic_scripts.status - the agent-draft approval gate

Revision ID: 0020
Revises: 0019
Create Date: 2026-08-28

FR-D19 (agent-authored scripts must be explicitly approved before save/run):
adds a ``status`` column (``proposed`` | ``ready``) to ``dynamic_scripts``.
An AGENT-authored draft (``origin=agent``) is created ``proposed`` and only
becomes ``ready`` after the tester approves it (the M16 approve endpoint);
built-in and manual scripts are always ``ready`` (their default).

This is distinct from the RUNNING state, which deliberately stays
process-local in the ScriptRunner (never a DB column). Existing rows (all
built-in/manual at this point) are backfilled ``ready`` via the server
default - no data migration needed.
"""
import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "dynamic_scripts",
        sa.Column(
            "status",
            sa.String(length=16),
            nullable=False,
            server_default="ready",
        ),
    )


def downgrade() -> None:
    op.drop_column("dynamic_scripts", "status")
