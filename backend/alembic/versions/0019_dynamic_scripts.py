"""M15 (V2): dynamic_scripts - the per-scan frida script library

Revision ID: 0019
Revises: 0018
Create Date: 2026-08-28

V2's FR-D15/D16/D17: a per-scan library of frida scripts. ``origin``
(builtin|manual|agent) distinguishes the built-in seed (from the M12 default
hooks), manual scripts (authored in-dashboard), and agent-authored scripts
(M16). ``code`` keeps the stable M12 default-hook id so a built-in's
event-feed linkage survives the move into the DB (null for a manual script).
Rows are scoped to a scan (scan_id FK, CASCADE) and tagged by platform.

The RUNNING state is NOT persisted here - it lives process-locally in the
ScriptRunner on the ActiveSession (like the feed/mirror/traffic), torn down
on disconnect; this table is the durable definition the UI lists.

No backfill: dynamic analysis is new in V2, no rows existed before.
"""
import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "dynamic_scripts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "scan_id",
            sa.Integer(),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        # android | ios
        sa.Column("platform", sa.String(length=16), nullable=False),
        # builtin | manual | agent
        sa.Column("origin", sa.String(length=16), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        # stable M12 default-hook id for built-ins (event-feed code); null
        # for a manual script.
        sa.Column("code", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_dynamic_scripts_scan_id", "dynamic_scripts", ["scan_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_dynamic_scripts_scan_id", table_name="dynamic_scripts")
    op.drop_table("dynamic_scripts")
