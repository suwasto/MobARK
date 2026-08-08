"""M5: risk recompute under the worst + count scoring model

Revision ID: 0006
Revises: 0005
Create Date: 2026-08-08

Owner follow-up (Aug 8, 2026): the risk score is now **worst + breadth**,
not pure max. ``risk.py::compute_risk_score`` scores ``round(10 ×
max_cvss)`` plus ~1 point per extra finding at the TOP severity band
(high), capped at +9 so risk never crosses 89 — CVSS 4.0 8.9 is the top of
the High band, so the removed critical band is never re-introduced. Below
high, bands keep their plain representative score (446 mediums = 55, same
as 1 medium). Rationale: suppressing/fixing a few of many highs should
visibly move the gauge (11 highs = 89 · 9 = 87 · 1 = 80 · none = 55) while
any high keeps the scan in the High band.

This migration re-scores every ``done`` scan under the new model so
persisted rows don't drift from the live code (the same recompute pass
migration 0005 did for the critical->high mapping). Self-contained — no
app imports, so it can't drift from the mapping at migration time. The
formula mirrors ``risk.py`` exactly (round-half-up on the 0.9 slope).
"""
import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None

# Severity band -> representative risk (CVSS 4.0 midpoint * 10).
_SEVERITY_RISK = {
    "high": 80,
    "medium": 55,
    "low": 20,
    "info": 0,
}
# Worst + breadth constants — MUST match risk.py::compute_risk_score.
_HIGH_COUNT_BONUS_CAP = 9
_HIGH_COUNT_BONUS_PER_EXTRA = 0.9


def _recompute_risk(rows) -> int:
    """``(severity, suppressed)`` rows -> risk under the worst+count model."""
    active = [sev for sev, suppressed in rows if not suppressed]
    high_count = active.count("high")
    if high_count:
        bonus = min(
            _HIGH_COUNT_BONUS_CAP,
            int(_HIGH_COUNT_BONUS_PER_EXTRA * (high_count - 1) + 0.5),
        )
        return min(89, 80 + bonus)
    return max((_SEVERITY_RISK.get(sev, 0) for sev in active), default=0)


def upgrade() -> None:
    conn = op.get_bind()
    scans = conn.execute(
        sa.text("SELECT id FROM scans WHERE status = 'done'")
    ).fetchall()
    for (scan_id,) in scans:
        rows = conn.execute(
            sa.text(
                "SELECT severity, suppressed FROM findings WHERE scan_id = :sid",
            ),
            {"sid": scan_id},
        ).fetchall()
        conn.execute(
            sa.text("UPDATE scans SET risk_score = :risk WHERE id = :sid"),
            {"risk": _recompute_risk(rows), "sid": scan_id},
        )


def downgrade() -> None:
    # Data-only migration: the previous max-only values were overwritten and
    # are not recoverable (same policy as 0005's rewrite) — nothing to undo.
    pass
