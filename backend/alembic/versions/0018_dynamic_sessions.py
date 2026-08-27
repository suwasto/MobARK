"""M11 (V2): dynamic_sessions - the persisted Frida device/session lifecycle

Revision ID: 0018
Revises: 0017
Create Date: 2026-08-27

V2 adds dynamic analysis (Frida runtime testing). ``dynamic_sessions`` is
the DURABLE lifecycle of one runtime session - one scan on one device at a
time (FR-D5). The LIVE handles (frida session, mirror stream) stay in the
process-local registry (app/dynamic/base.py), never in the DB; this table is
the record the UI reads (state + per-platform identity metadata from FR-D3).

No backfill: dynamic analysis is new in V2, no rows existed before.
"""
import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "dynamic_sessions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "scan_id",
            sa.Integer(),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # android | ios
        sa.Column("platform", sa.String(length=16), nullable=False),
        # disconnected | preflight | attached | error
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("device_id", sa.String(length=128), nullable=True),
        sa.Column("device_name", sa.String(length=256), nullable=True),
        # adb | ssh | corellium
        sa.Column("connection_type", sa.String(length=16), nullable=True),
        sa.Column("frida_version", sa.String(length=64), nullable=True),
        sa.Column("target_pid", sa.Integer(), nullable=True),
        # Android: whether the attached process runs as root.
        sa.Column("root_status", sa.Boolean(), nullable=True),
        # iOS-only: the jailbreak method (checkra1n/palera1n/...).
        sa.Column("jailbreak_method", sa.String(length=64), nullable=True),
        sa.Column("corellium_enabled", sa.Boolean(), nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_dynamic_sessions_scan_id", "dynamic_sessions", ["scan_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_dynamic_sessions_scan_id", table_name="dynamic_sessions")
    op.drop_table("dynamic_sessions")
