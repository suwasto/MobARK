"""M9.2: rename the medium band to warning + banded risk-index re-score

Revision ID: 0017
Revises: 0016
Create Date: 2026-08-15

Owner decisions (Aug 15, 2026):
- The findings severity vocabulary is now ``high | warning | info`` - the
  ``medium`` band is renamed ``warning`` (existing rows rewritten).
- The CVSS 4.0-based risk model is REPLACED by the plain banded risk index
  (a static scanner cannot honestly assess CVSS attack requirements / user
  interaction - the MobSF pattern is a severity heuristic): risk = the worst
  finding's band base (any high -> 70, otherwise warning -> 40) plus ~1
  point per extra finding at that band, capped at the band ceiling (high 99
  · warning 69); info never scores. Every ``done`` scan's ``risk_score`` is
  recomputed under the new model (a lone high collapses 80 -> 70, a lone
  medium 55 -> 40, 2 highs + 1 medium 81 -> 71).

Self-contained - no app imports - and mirrors ``risk.py`` exactly
(round-half-up on the bonus slope).
"""
import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None

# Band -> (base risk, ceiling risk, bonus slope) - MUST match risk.py's
# _BAND_RISK. Bands never overlap: any high >= 70 > any warning <= 69.
_BAND_RISK = {
    "high": (70, 99, 1.0),
    "warning": (40, 69, 1.0),
}


def _recompute_risk(rows) -> int:
    """``(severity, suppressed)`` rows -> risk under the banded model."""
    scored = [
        sev
        for sev, suppressed in rows
        if not suppressed and sev in _BAND_RISK
    ]
    if not scored:
        return 0
    worst_sev = "high" if "high" in scored else "warning"
    base, ceiling, per_extra = _BAND_RISK[worst_sev]
    extra = scored.count(worst_sev) - 1
    bonus = min(ceiling - base, int(per_extra * max(0, extra) + 0.5))
    return base + bonus


def upgrade() -> None:
    # Data rewrite: the medium band is renamed warning.
    op.execute("UPDATE findings SET severity = 'warning' WHERE severity = 'medium'")

    # Recompute every done scan's risk score under the banded model (a
    # medium-only scan's score collapses 55 -> 40; a lone high 80 -> 70).
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
    # Data-only migration: the medium->warning rewrite and risk recompute are
    # NOT reversed (a downgrade cannot distinguish rows that were originally
    # medium from ones that were always warning) - same policy as 0005/0006.
    pass
