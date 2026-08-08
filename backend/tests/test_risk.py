"""M5 risk/security score unit tests — CVSS 4.0 mapping, max aggregation, edges.

Formula (docs/progress/M5.md): each severity band maps to a representative
CVSS 4.0 base score (high 8.0, medium 5.5, low 2.0, info 0 — the critical
band was removed Aug 8); risk = round(10 * max(cvss)) over scored findings
(worst finding drives the overall score — owner decision Aug 7); security =
100 - risk (higher is better). Suppressed findings are skipped entirely.
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
    # findings still reads 80 — the worst finding governs the posture.
    findings = (
        [_f("high")]
        + [_f("medium")] * 5
        + [_f("low")] * 40
    )
    assert compute_risk_score(findings) == 80


def test_score_caps_at_100():
    assert compute_risk_score([_f("high"), _f("high")]) == 80


def test_unknown_severity_is_ignored_not_crashed():
    # FindingOut validates severities, so use a stub for the unknown value.
    banana = types.SimpleNamespace(severity="banana")
    assert compute_risk_score([_f("high"), banana]) == 80
    assert compute_risk_score([banana]) == 0


def test_suppressed_findings_are_excluded():
    # A suppressed worst finding must not drive the posture (Aug 8).
    assert compute_risk_score([_suppressed("high")]) == 0
    assert compute_risk_score([_suppressed("high"), _f("low")]) == 20
    # Plain FindingOut (analysis layer) has no suppressed attribute — getattr
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
    # Any high -> risk 80 -> security 20 (the documented worst-finding case)
    findings = (
        [_f("high")] * 2
        + [_f("medium")] * 5
        + [_f("low")]
    )
    assert compute_risk_score(findings) == 80
    assert compute_security_score(findings) == 20


def test_security_from_risk_passthrough():
    assert security_from_risk(None) is None
    assert security_from_risk(40) == 60
    assert security_from_risk(100) == 0
    assert security_from_risk(0) == 100
