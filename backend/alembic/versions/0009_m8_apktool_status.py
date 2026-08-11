"""M8: on-demand apktool decode state on scans + edits + builds

Revision ID: 0009
Revises: 0008
Create Date: 2026-08-10

Owner decisions (Aug 10, 2026): apktool decode is **on-demand** — an RQ job
triggered by the first Smali view / first edit, cached per scan, never a
scan-pipeline step. ``scans.apktool_status`` tracks in-flight states
(``not_started | queued | decoding | ready | failed``); ``ready`` is also
filesystem-derived (``<work>/<scan>/apktool/AndroidManifest.xml`` exists),
and ``scans.apktool_error`` carries the specific decode failure for the UI.

Phase B adds the **``edits`` table** — the DB-diff source of truth for M8
edit/recompile: full-file rows (original + new + generated unified diff),
never silent writes to the on-disk apktool tree. Phase C adds the
**``builds`` table** (full rebuild history; the pipeline snapshots the
applied edits at job start) and the ``edits.build_id`` FK to it.

Existing scans default to ``apktool_status=not_started`` (nothing decodes
until explicitly triggered); no edits or builds exist to migrate.
"""
import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column(
            "apktool_status",
            sa.String(length=16),
            nullable=False,
            server_default="not_started",
        ),
    )
    op.add_column("scans", sa.Column("apktool_error", sa.Text(), nullable=True))

    # ---- Phase C: builds (created before edits so the edits FK resolves) ----
    op.create_table(
        "builds",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "scan_id",
            sa.Integer(),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # queued | running | done | failed
        sa.Column("status", sa.String(length=16), nullable=False),
        # applying | rebuilding | zipping | signing | done
        sa.Column("stage", sa.String(length=32), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        # JSON list of applied edit ids at snapshot time
        sa.Column("edits_json", sa.Text(), nullable=True),
        sa.Column("artifact_name", sa.String(length=512), nullable=True),
        sa.Column("artifact_path", sa.String(length=1024), nullable=True),
        sa.Column("artifact_sha256", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_builds_scan_id", "builds", ["scan_id"])

    # ---- Phase B: edits (build_id now FKs to builds) ----
    op.create_table(
        "edits",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "scan_id",
            sa.Integer(),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("file_path", sa.String(length=1024), nullable=False),
        sa.Column("original_content", sa.Text(), nullable=False),
        sa.Column("new_content", sa.Text(), nullable=False),
        sa.Column("unified_diff", sa.Text(), nullable=False),
        # manual | agent (agent proposals land in Phase D)
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("instruction", sa.Text(), nullable=True),
        # proposed | applied | rejected | reverted
        sa.Column("status", sa.String(length=16), nullable=False),
        # the consuming build (SET NULL when a build row goes away)
        sa.Column(
            "build_id",
            sa.Integer(),
            sa.ForeignKey("builds.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_edits_scan_id", "edits", ["scan_id"])


def downgrade() -> None:
    op.drop_index("ix_edits_scan_id", table_name="edits")
    op.drop_table("edits")
    op.drop_index("ix_builds_scan_id", table_name="builds")
    op.drop_table("builds")
    op.drop_column("scans", "apktool_error")
    op.drop_column("scans", "apktool_status")
