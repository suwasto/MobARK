from app.analysis.base import FindingOut
from app.analysis.severity import (
    SEMGREP_SEVERITY,
    gitleaks_severity,
    semgrep_severity,
)


def test_semgrep_severity_map():
    assert SEMGREP_SEVERITY["ERROR"] == "high"
    assert SEMGREP_SEVERITY["WARNING"] == "warning"
    assert SEMGREP_SEVERITY["INFO"] == "info"


def test_semgrep_curated_overrides_are_high():
    # Owner calibration (Aug 7): complete TLS verification bypasses were
    # critical; after the critical band was removed (Aug 8) they are high -
    # the top severity.
    assert semgrep_severity("masa-android-all-hostname-verifier", "ERROR") == "high"
    assert semgrep_severity("masa-android-insecure-trust-manager", "ERROR") == "high"
    # Non-overridden rules keep the native mapping.
    assert semgrep_severity("masa-android-webview-javascript-enabled", "ERROR") == "high"
    assert semgrep_severity("some-mastg-rule", "WARNING") == "warning"
    assert semgrep_severity("unknown", "NONSENSE") == "info"


def test_gitleaks_default_severity_is_high():
    assert gitleaks_severity("some-unknown-rule") == "high"


def test_gitleaks_override_rules_are_high():
    # Direct-compromise rules: top severity (critical band removed Aug 8).
    assert gitleaks_severity("aws-access-token") == "high"
    assert gitleaks_severity("private-key") == "high"
    assert gitleaks_severity("github-pat") == "high"


def test_finding_rejects_invalid_severity():
    import pytest

    with pytest.raises(ValueError):
        FindingOut(tool="gitleaks", title="x", severity="catastrophic")
    # The removed bands are now invalid too.
    with pytest.raises(ValueError):
        FindingOut(tool="gitleaks", title="x", severity="critical")
    with pytest.raises(ValueError):
        FindingOut(tool="gitleaks", title="x", severity="medium")
