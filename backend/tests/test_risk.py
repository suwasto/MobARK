"""M5 risk/security score unit tests - CVSS 4.0 mapping, worst+count, edges.

Formula (docs/progress/M5.md): each severity band maps to a representative
CVSS 4.0 base score (high 8.0, medium 5.5, low 2.0, info 0 - the critical
band was removed Aug 8); risk = round(10 * max(cvss)) driven by the worst
finding, plus ~1 point per extra finding at the worst severity band, capped
at the band's CVSS 4.0 ceiling (high 89 · medium 69 · low 39 - the band
 tops 8.9/6.9/3.9 × 10). Owner decisions: max-not-mean Aug 7; "worst +
count" then band-symmetric Aug 8. security = 100 - risk (higher is
better). Suppressed findings are skipped entirely; bands never overlap
(any high ≥ 80 > any no-high ≤ 69 > any low-only ≤ 39).
"""
import types

from app.analysis.base import FindingOut
from app.analysis.risk import (
    SEVERITY_CVSS,
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
    assert list(SEVERITY_CVSS) == ["high", "medium", "low", "info"]


def test_cvss_base_scores_follow_qualitative_bands():
    # CVSS 4.0 qualitative bands: high 7.0-8.9, medium 4.0-6.9, low 0.1-3.9,
    # none 0. We use the band midpoints.
    assert SEVERITY_CVSS["high"] == 8.0
    assert SEVERITY_CVSS["medium"] == 5.5
    assert SEVERITY_CVSS["low"] == 2.0
    assert SEVERITY_CVSS["info"] == 0.0
    assert "critical" not in SEVERITY_CVSS


def test_empty_scan_scores_zero():
    assert compute_risk_score([]) == 0


def test_info_only_scores_zero():
    assert compute_risk_score([_f("info"), _f("info")]) == 0


def test_single_high_is_eighty():
    # CVSS 8.0 (high band midpoint) * 10 -> 80/100 risk.
    assert compute_risk_score([_f("high")]) == 80


def test_single_low_is_twenty():
    assert compute_risk_score([_f("low")]) == 20


def test_worst_finding_drives_the_score():
    # Max aggregation (owner decision): a single high among many lower
    # findings still reads 80 - the worst finding governs the posture.
    findings = (
        [_f("high")]
        + [_f("medium")] * 5
        + [_f("low")] * 40
    )
    assert compute_risk_score(findings) == 80


def test_high_count_adds_breadth_bonus():
    # Worst + count (owner decision, Aug 8): each extra high adds ~1 point,
    # capped at +9 so risk never crosses 89 (CVSS 4.0 8.9 = High band top).
    # Note: the 0.9 slope's rounding makes 6 and 7 highs both read 85 - the
    # flat step is expected (int(0.9*5+0.5) == int(0.9*6+0.5) == 5), not a bug.
    assert compute_risk_score([_f("high")]) == 80
    assert compute_risk_score([_f("high"), _f("high")]) == 81
    assert compute_risk_score([_f("high")] * 5) == 84
    assert compute_risk_score([_f("high")] * 9) == 87
    assert compute_risk_score([_f("high")] * 11) == 89
    assert compute_risk_score([_f("high")] * 12) == 89  # capped at +9


def test_medium_band_breadth_bonus():
    # Band-symmetric (owner decision, Aug 8): mediums get the same breadth
    # bonus as highs, capped at the Medium band ceiling 69 (CVSS 6.9).
    assert compute_risk_score([_f("medium")]) == 55
    assert compute_risk_score([_f("medium")] * 2) == 56
    assert compute_risk_score([_f("medium")] * 5) == 59
    assert compute_risk_score([_f("medium")] * 10) == 63
    assert compute_risk_score([_f("medium")] * 16) == 69  # ceiling
    assert compute_risk_score([_f("medium")] * 446) == 69  # saturated


def test_low_band_breadth_bonus():
    assert compute_risk_score([_f("low")]) == 20
    assert compute_risk_score([_f("low")] * 2) == 21
    assert compute_risk_score([_f("low")] * 22) == 39  # ceiling (CVSS 3.9)
    assert compute_risk_score([_f("low")] * 100) == 39


def test_bands_never_overlap():
    # Worst-first ordering is preserved with no band overlap: any high ≥ 80
    # > any no-high ≤ 69 > any low-only ≤ 39.
    assert compute_risk_score([_f("high")]) == 80
    assert compute_risk_score([_f("medium")] * 446) == 69
    assert compute_risk_score([_f("low")] * 100) == 39


def test_unknown_severity_is_ignored_not_crashed():
    # FindingOut validates severities, so use a stub for the unknown value.
    banana = types.SimpleNamespace(severity="banana")
    assert compute_risk_score([_f("high"), banana]) == 80
    assert compute_risk_score([banana]) == 0


def test_suppressed_findings_are_excluded():
    # A suppressed worst finding must not drive the posture (Aug 8).
    assert compute_risk_score([_suppressed("high")]) == 0
    assert compute_risk_score([_suppressed("high"), _f("low")]) == 20
    # Plain FindingOut (analysis layer) has no suppressed attribute - getattr
    # keeps both call sites working.
    assert compute_risk_score([_f("high")]) == 80


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
    # high -> CVSS 8.0 -> 80/100 risk (info unscored; suppressed skipped)
    assert compute_risk_score(findings) == 80


# ---- security score (public-facing; higher is better) -----------------------


def test_security_score_is_inverse_of_risk():
    assert compute_security_score([]) == 100  # no findings -> no risk
    assert compute_security_score([_f("info")]) == 100
    assert compute_security_score([_f("high")]) == 20
    assert compute_security_score([_f("low")]) == 80
    # 2 highs -> worst+count risk 81 -> security 19
    findings = (
        [_f("high")] * 2
        + [_f("medium")] * 5
        + [_f("low")]
    )
    assert compute_risk_score(findings) == 81
    assert compute_security_score(findings) == 19


def test_security_from_risk_passthrough():
    assert security_from_risk(None) is None
    assert security_from_risk(40) == 60
    assert security_from_risk(100) == 0
    assert security_from_risk(0) == 100
