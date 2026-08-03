import json
from pathlib import Path

from app.analysis.gitleaks import normalize_report as normalize_gitleaks
from app.analysis.semgrep import normalize_report as normalize_semgrep


def _write(tmp_path: Path, payload) -> Path:
    p = tmp_path / "report.json"
    p.write_text(json.dumps(payload))
    return p


def test_gitleaks_normalizer_maps_fields(tmp_path):
    report = _write(
        tmp_path,
        [
            {
                "RuleID": "aws-access-token",
                "Description": "AWS Access Token",
                "StartLine": 12,
                "EndLine": 12,
                "Secret": "AKIA...",
                "Match": "key=AKIA...",
                "Entropy": 4.2,
                "File": "/work/decompiled/sources/com/example/Config.java",
                "Tags": ["key", "AWS"],
                "Fingerprint": "abc:file:rule:12",
            }
        ],
    )
    findings = normalize_gitleaks(report, Path("/work/decompiled"))
    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "gitleaks"
    assert f.severity == "critical"  # override table
    assert f.file_path == "sources/com/example/Config.java"  # root-stripped
    assert f.line_number == 12
    assert f.detail["rule_id"] == "aws-access-token"
    assert f.detail["secret"] == "AKIA..."


def test_gitleaks_empty_report_yields_no_findings(tmp_path):
    report = _write(tmp_path, [])
    assert normalize_gitleaks(report, Path("/work")) == []


def test_semgrep_normalizer_maps_fields_and_category(tmp_path):
    report = _write(
        tmp_path,
        {
            "results": [
                {
                    "check_id": "masa-android-webview-javascript-enabled",
                    "path": "/work/decompiled/sources/a/b/Web.java",
                    "start": {"line": 42, "col": 1},
                    "end": {"line": 42, "col": 20},
                    "extra": {
                        "severity": "WARNING",
                        "message": "[MASVS-PLATFORM-3] WebView has JavaScript enabled.",
                        "metadata": {"cwe": ["CWE-79"]},
                    },
                },
                {
                    "check_id": "masa-android-insecure-trust-manager",
                    "path": "/work/decompiled/sources/a/b/Tls.java",
                    "start": {"line": 7},
                    "extra": {"severity": "ERROR", "message": "[MASVS-NETWORK-3] Bad TLS."},
                },
            ],
            "errors": [],
            "paths": {},
        }
    )
    findings = normalize_semgrep(report, Path("/work/decompiled"))
    assert len(findings) == 2

    f = findings[0]
    assert f.tool == "semgrep"
    assert f.severity == "medium"  # WARNING
    assert f.category == "MASVS-PLATFORM-3"  # parsed from message
    assert f.file_path == "sources/a/b/Web.java"
    assert f.line_number == 42
    assert f.detail["check_id"] == "masa-android-webview-javascript-enabled"

    assert findings[1].severity == "high"  # ERROR
    assert findings[1].category == "MASVS-NETWORK-3"


def test_semgrep_unknown_severity_falls_back_to_info(tmp_path):
    report = _write(
        tmp_path,
        {"results": [{"check_id": "x", "path": "/w/a.java", "start": {},
                      "extra": {"severity": "NONSENSE", "message": "m"}}]},
    )
    findings = normalize_semgrep(report, Path("/w"))
    assert findings[0].severity == "info"


def test_semgrep_tags_app_vs_third_party_library_scope(tmp_path):
    report = _write(
        tmp_path,
        {
            "results": [
                {
                    "check_id": "r1",
                    "path": "/work/decompiled/sources/com/example/app/Secret.java",
                    "start": {"line": 1},
                    "extra": {"severity": "ERROR", "message": "m"},
                },
                {
                    "check_id": "r2",
                    "path": "/work/decompiled/sources/android/support/v4/Widget.java",
                    "start": {"line": 2},
                    "extra": {"severity": "WARNING", "message": "m"},
                },
            ],
            "errors": [],
        }
    )
    findings = normalize_semgrep(report, Path("/work/decompiled"), app_package="com.example.app")
    assert findings[0].detail["scope"] == "app"
    assert findings[0].detail["in_app_package"] is True
    assert findings[1].detail["scope"] == "third_party_library"
    assert findings[1].detail["in_app_package"] is False


def test_semgrep_no_scope_keys_when_package_unknown(tmp_path):
    report = _write(
        tmp_path,
        {"results": [{"check_id": "x", "path": "/w/a.java", "start": {},
                      "extra": {"severity": "INFO", "message": "m"}}]},
    )
    findings = normalize_semgrep(report, Path("/w"))
    assert "scope" not in findings[0].detail
    assert "in_app_package" not in findings[0].detail
