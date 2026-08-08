"""M5: finding suppression + no-critical severity vocabulary

Revision ID: 0005
Revises: 0004
Create Date: 2026-08-08

Owner decisions (Aug 8, 2026):
- **Finding suppression** — per-finding false-positive suppression with a
  review toggle. ``findings.suppressed`` (False = visible) + ``suppressed_at``
  (when it was suppressed). Suppressed findings are excluded from the risk
  score (``risk.py::compute_risk_score`` skips ``suppressed=True`` rows), the
  AI summary, and the agent context.
- **No critical band** — the findings vocabulary is now
  ``high | medium | low | info``. Existing ``critical`` rows are rewritten to
  ``high`` (the new top), and every ``done`` scan's ``risk_score`` is
  recomputed under the post-critical CVSS 4.0 mapping (high 8.0 · medium 5.5
  · low 2.0 · info 0; risk = round(10 × max(cvss))). The old mapping's
  critical 9.5 → risk 95 scores collapse to the new high 8.0 → 80.

"""
import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

# New CVSS 4.0 representative base scores (band midpoints), * 10 — the
# migration is self-contained (no app imports) so it can't drift from the
# mapping that existed at migration time.
_SEVERITY_RISK = {
    "high": 80,
    "medium": 55,
    "low": 20,
    "info": 0,
}


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("suppressed", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "findings",
        sa.Column("suppressed_at", sa.DateTime(timezone=True), nullable=True),
    )

    # Data rewrite: the critical band no longer exists — high is the top.
    op.execute("UPDATE findings SET severity = 'high' WHERE severity = 'critical'")

    # Recompute every done scan's risk score under the new mapping. SQLite
    # CASE/MAX over the persisted severities; nothing is suppressed yet (the
    # column just landed with server_default false).
    conn = op.get_bind()
    scans = conn.execute(sa.text("SELECT id FROM scans WHERE status = 'done'")).fetchall()
    for (scan_id,) in scans:
        rows = conn.execute(
            sa.text(
                "SELECT severity FROM findings WHERE scan_id = :sid",
            ),
            {"sid": scan_id},
        ).fetchall()
        risk = max((_SEVERITY_RISK.get(sev, 0) for (sev,) in rows), default=0)
        conn.execute(
            sa.text("UPDATE scans SET risk_score = :risk WHERE id = :sid"),
            {"risk": risk, "sid": scan_id},
        )


def downgrade() -> None:
    # The critical->high rewrite and risk recompute are NOT reversed — a
    # downgrade cannot distinguish rows that were originally critical from
    # ones that were already high (no marker is kept). Column drops only.
    op.drop_column("findings", "suppressed_at")
    op.drop_column("findings", "suppressed")
