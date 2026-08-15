"""M5 risk/security score unit tests - banded risk index, worst+count, edges.

Formula (Aug 15, 2026 - the CVSS 4.0 model was replaced by the banded risk
index): the worst finding picks the band - any high sets the High band
(base 70), otherwise warnings set the Warning band (base 40) - and each
extra finding at that band adds ~1 point, capped at the band ceiling (high
99 · warning 69). Info findings never score; unknown severities are
ignored. Owner decisions: max-not-mean Aug 7; worst+count + band-symmetric
Aug 8; low band dropped Aug 15 (former low findings are informational);
medium renamed warning + CVSS dropped Aug 15. security = 100 - risk
(higher is better). Suppressed findings are skipped entirely; bands never
overlap (any high ≥ 70 > any warning ≤ 69 > info-only 0).
"""
import types

from app.analysis.base import FindingOut
from app.analysis.risk import (
    SEVERITY_WEIGHT,
    compute_risk_score,
    compute_security_score,
    security_from_risk,
)


def _f(severity: str) -> FindingOut:
    return FindingOut(tool="test", title=f"{severity} finding", severity=severity)


def _suppressed(severity: str) -> FindingOut:
    """A FindingOut-shaped row with the persisted ``suppressed`` flag set."""
    return types.SimpleNamespace(severity=severity, suppressed=True)


def test_weights_are_ordered_high_first():
    # Display order contract for the findings list.
    assert list(SEVERITY_WEIGHT) == ["high", "warning", "info"]


def test_severity_weights_are_ordinal():
    # Ordinal weights for ordering: high > warning > info (info = 0 - a
    # note never drives the posture). Not the score itself.
    assert SEVERITY_WEIGHT["high"] == 3
    assert SEVERITY_WEIGHT["warning"] == 2
    assert SEVERITY_WEIGHT["info"] == 0
    assert "critical" not in SEVERITY_WEIGHT
    assert "low" not in SEVERITY_WEIGHT
    assert "medium" not in SEVERITY_WEIGHT


def test_empty_scan_scores_zero():
    assert compute_risk_score([]) == 0


def test_info_only_scores_zero():
    assert compute_risk_score([_f("info"), _f("info")]) == 0


def test_single_high_is_seventy():
    # The High band base - any high sets the worst band.
    assert compute_risk_score([_f("high")]) == 70


def test_legacy_low_severity_is_unscored():
    # The low band is gone (Aug 15, 2026) - a persisted legacy row is ignored
    # exactly like any unknown severity (never a crash), so a low-only scan
    # reads 0. Use a stub: FindingOut now rejects "low" outright.
    legacy = types.SimpleNamespace(severity="low")
    assert compute_risk_score([legacy]) == 0


def test_worst_finding_drives_the_score():
    # Worst-first aggregation (owner decision): a single high among many
    # warnings still reads 70 - the worst finding governs the posture.
    findings = (
        [_f("high")]
        + [_f("warning")] * 5
        + [_f("info")] * 40
    )
    assert compute_risk_score(findings) == 70


def test_high_count_adds_breadth_bonus():
    # Worst + count (owner decision, Aug 8): each extra high adds ~1 point,
    # capped so risk never crosses 99.
    assert compute_risk_score([_f("high")]) == 70
    assert compute_risk_score([_f("high"), _f("high")]) == 71
    assert compute_risk_score([_f("high")] * 5) == 74
    assert compute_risk_score([_f("high")] * 9) == 78
    assert compute_risk_score([_f("high")] * 30) == 99  # ceiling
    assert compute_risk_score([_f("high")] * 100) == 99  # capped


def test_warning_band_breadth_bonus():
    # Band-symmetric (owner decision, Aug 8): warnings get the same breadth
    # bonus as highs, capped at the Warning band ceiling 69.
    assert compute_risk_score([_f("warning")]) == 40
    assert compute_risk_score([_f("warning")] * 2) == 41
    assert compute_risk_score([_f("warning")] * 5) == 44
    assert compute_risk_score([_f("warning")] * 10) == 49
    assert compute_risk_score([_f("warning")] * 30) == 69  # ceiling
    assert compute_risk_score([_f("warning")] * 446) == 69  # saturated


def test_bands_never_overlap():
    # Worst-first ordering is preserved with no band overlap: any high ≥ 70
    # > any warning ≤ 69, and info-only scans read 0.
    assert compute_risk_score([_f("high")]) == 70
    assert compute_risk_score([_f("warning")] * 446) == 69
    assert compute_risk_score([_f("info")] * 100) == 0


def test_unknown_severity_is_ignored_not_crashed():
    # FindingOut validates severities, so use a stub for the unknown value.
    banana = types.SimpleNamespace(severity="banana")
    assert compute_risk_score([_f("high"), banana]) == 70
    assert compute_risk_score([banana]) == 0


def test_suppressed_findings_are_excluded():
    # A suppressed worst finding must not drive the posture (Aug 8).
    assert compute_risk_score([_suppressed("high")]) == 0
    assert compute_risk_score([_suppressed("high"), _f("info")]) == 0
    # Plain FindingOut (analysis layer) has no suppressed attribute - getattr
    # keeps both call sites working.
    assert compute_risk_score([_f("high")]) == 70


def test_works_with_persisted_finding_objects(db_session_factory):
    from app.models import Finding, Scan

    with db_session_factory() as session:
        scan = Scan(filename="a.apk", status="done")
        session.add(scan)
        session.commit()
        session.add_all(
            [
                Finding(scan_id=scan.id, tool="t", title="x", severity="high"),
                Finding(scan_id=scan.id, tool="t", title="y", severity="info"),
                Finding(
                    scan_id=scan.id,
                    tool="t",
                    title="z",
                    severity="high",
                    suppressed=True,
                ),
            ]
        )
        session.commit()
        findings = list(session.query(Finding).all())
    # high -> High band base 70 (info unscored; suppressed skipped)
    assert compute_risk_score(findings) == 70


# ---- security score (public-facing; higher is better) -----------------------


def test_security_score_is_inverse_of_risk():
    assert compute_security_score([]) == 100  # no findings -> no risk
    assert compute_security_score([_f("info")]) == 100
    assert compute_security_score([_f("high")]) == 30
    assert compute_security_score([_f("warning")]) == 60
    # 2 highs -> worst+count risk 71 -> security 29
    findings = (
        [_f("high")] * 2
        + [_f("warning")] * 5
        + [_f("info")]
    )
    assert compute_risk_score(findings) == 71
    assert compute_security_score(findings) == 29


def test_security_from_risk_passthrough():
    assert security_from_risk(None) is None
    assert security_from_risk(40) == 60
    assert security_from_risk(100) == 0
    assert security_from_risk(0) == 100
