"""M5: risk recompute under the band-symmetric worst + count model

Revision ID: 0007
Revises: 0006
Create Date: 2026-08-08

Owner follow-up (Aug 8, 2026): the risk score's breadth bonus now applies
to EVERY severity band, not just high. ``risk.py::compute_risk_score``
scores ``round(10 × max_cvss)`` for the worst finding's band, plus ~1 point
per extra finding at that band, capped at the band's CVSS 4.0 ceiling
(high 89 · medium 69 · low 39 - the qualitative band tops 8.9/6.9/3.9 × 10).
So clearing mediums now also rewards progress (16 mediums = 69 · 10 = 63 ·
2 = 56 · 1 = 55) while bands never overlap: any high ≥ 80 > any no-high
≤ 69 > any low-only ≤ 39, and the gauge caption "CVSS 4.0 · risk n/100 ·
band" stays literally true (each cap IS the band ceiling). Bulk bands
saturate at their ceiling (446 mediums = 69 until the count drops below
~16 - visible progress returns in the tail).

This migration re-scores every ``done`` scan under the extended model
(same recompute pass as 0006). Self-contained - no app imports - and
mirrors ``risk.py`` exactly (round-half-up on the 0.9 slope).
"""
import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

# Severity band -> representative CVSS base score (matches risk.py).
_SEVERITY_CVSS = {
    "high": 8.0,
    "medium": 5.5,
    "low": 2.0,
}
# Band -> (base risk, ceiling risk, bonus slope) - MUST match risk.py's
# _BAND_RISK. Ceilings are the CVSS 4.0 qualitative band tops × 10.
_BAND_RISK = {
    "high": (80, 89, 0.9),
    "medium": (55, 69, 0.9),
    "low": (20, 39, 0.9),
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
    # Data-only migration: prior values were overwritten and are not
    # recoverable (same policy as 0005/0006) - nothing to undo.
    pass
