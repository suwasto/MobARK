"""M5 risk score unit tests — deterministic weights, caps, edge cases.

Formula (docs/progress/M5.md): weights critical=10, high=7, medium=4, low=1,
info=0; score = min(100, round(100 * raw / (10 * n))) over scored findings.
"""
from app.analysis.base import FindingOut
from app.analysis.risk import SEVERITY_WEIGHTS, compute_risk_score


def _f(severity: str) -> FindingOut:
    return FindingOut(tool="test", title=f"{severity} finding", severity=severity)


def test_weights_are_ordered_critical_first():
    # Display order contract for the findings list.
    assert list(SEVERITY_WEIGHTS) == ["critical", "high", "medium", "low", "info"]


def test_empty_scan_scores_zero():
    assert compute_risk_score([]) == 0


def test_info_only_scores_zero():
    assert compute_risk_score([_f("info"), _f("info")]) == 0


def test_single_critical_is_max():
    assert compute_risk_score([_f("critical")]) == 100


def test_single_low_is_ten():
    assert compute_risk_score([_f("low")]) == 10


def test_mixed_weights_match_documented_formula():
    # 2C 4H 5M 1L -> raw = 20+28+20+1 = 69, n = 12 -> round(100*69/120) = 58
    findings = (
        [_f("critical")] * 2
        + [_f("high")] * 4
        + [_f("medium")] * 5
        + [_f("low")]
    )
    assert compute_risk_score(findings) == 58


def test_score_caps_at_100():
    assert compute_risk_score([_f("critical"), _f("critical")]) == 100


def test_unknown_severity_is_ignored_not_crashed():
    import types

    # FindingOut validates severities, so use a stub for the unknown value.
    banana = types.SimpleNamespace(severity="banana")
    assert compute_risk_score([_f("critical"), banana]) == 100
    assert compute_risk_score([banana]) == 0


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
            ]
        )
        session.commit()
        findings = list(session.query(Finding).all())
    # high + info -> raw 7, n 1 -> 70
    assert compute_risk_score(findings) == 70
