"""M9.2: drop the 'low' severity band - findings vocabulary is high | medium | info

Revision ID: 0016
Revises: 0015
Create Date: 2026-08-15

Owner decision (Aug 15, 2026): the findings severity vocabulary drops the
``low`` band - findings are now ``high | medium | info``. Existing ``low``
rows are rewritten to ``info`` (owner direction: minor findings become
informational notes - they stop driving the risk score), and every ``done``
scan's ``risk_score`` is recomputed under the post-low CVSS 4.0 mapping
(high 8.0 · medium 5.5 · info 0; risk = the worst finding's band base plus
the band-symmetric breadth bonus, capped at the band ceiling - high 89 ·
medium 69). Suppressed rows stay excluded from the recompute, exactly like
the live ``risk.py``.

Self-contained - no app imports - and mirrors ``risk.py`` exactly
(round-half-up on the 0.9 slope).
"""
import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None

# Severity band -> representative CVSS base score (matches risk.py - the low
# band is gone, only high and medium drive the score).
_SEVERITY_CVSS = {
    "high": 8.0,
    "medium": 5.5,
}
# Band -> (base risk, ceiling risk, bonus slope) - MUST match risk.py's
# _BAND_RISK. Ceilings are the CVSS 4.0 qualitative band tops × 10.
_BAND_RISK = {
    "high": (80, 89, 0.9),
    "medium": (55, 69, 0.9),
}


def _recompute_risk(rows) -> int:
    """``(severity, suppressed)`` rows -> risk under the band-symmetric model."""
    scored = [
        (sev, _SEVERITY_CVSS.get(sev, 0.0))
        for sev, suppressed in rows
        if not suppressed
    ]
    scored = [(sev, cvss) for sev, cvss in scored if cvss > 0]
    if not scored:
        return 0
    worst_sev, worst_cvss = max(scored, key=lambda pair: pair[1])
    base, ceiling, per_extra = _BAND_RISK[worst_sev]
    extra = sum(1 for _, cvss in scored if cvss == worst_cvss) - 1
    bonus = min(ceiling - base, int(per_extra * max(0, extra) + 0.5))
    return base + bonus


def upgrade() -> None:
    # Data rewrite: the low band no longer exists - low findings are now
    # informational notes.
    op.execute("UPDATE findings SET severity = 'info' WHERE severity = 'low'")

    # Recompute every done scan's risk score under the post-low mapping (a
    # low-only scan's score collapses to 0 - nothing above info drives it).
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
    # Data-only migration: the low->info rewrite and risk recompute are NOT
    # reversed (a downgrade cannot distinguish rows that were originally low
    # from ones that were always info) - same policy as 0005/0006/0007.
    pass
