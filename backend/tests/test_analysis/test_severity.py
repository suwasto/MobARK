from app.analysis.base import FindingOut
from app.analysis.severity import SEMGREP_SEVERITY, gitleaks_severity


def test_semgrep_severity_map():
    assert SEMGREP_SEVERITY["ERROR"] == "high"
    assert SEMGREP_SEVERITY["WARNING"] == "medium"
    assert SEMGREP_SEVERITY["INFO"] == "info"


def test_gitleaks_default_severity_is_high():
    assert gitleaks_severity("some-unknown-rule") == "high"


def test_gitleaks_override_rules():
    assert gitleaks_severity("aws-access-token") == "critical"
    assert gitleaks_severity("private-key") == "critical"
    assert gitleaks_severity("github-pat") == "critical"


def test_finding_rejects_invalid_severity():
    import pytest

    with pytest.raises(ValueError):
        FindingOut(tool="gitleaks", title="x", severity="catastrophic")
