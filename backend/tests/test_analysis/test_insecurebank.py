"""M1 integration tests against the real, deliberately-vulnerable sample.

Requires jadx, gitleaks and semgrep on PATH (or MASA_*_CMD overrides) and
androguard installed. Run with:  pytest -m integration
"""
from pathlib import Path

import pytest

from app.analysis import jadx, manifest
from app.analysis.base import SEVERITIES
from app.analysis.orchestrator import ScanAborted, run_android_analysis

pytestmark = pytest.mark.integration

APK = Path(__file__).resolve().parents[3] / "docs" / "InsecureBankv2.apk"


@pytest.fixture(scope="module")
def apk() -> Path:
    if not APK.is_file():
        pytest.skip(f"sample APK not present at {APK}")
    return APK


def test_jadx_decompiles_sample(apk, tmp_path_factory):
    out = tmp_path_factory.mktemp("decomp") / "out"
    jadx.decompile(apk, out)
    sources = out / "sources"
    assert sources.is_dir(), "jadx should produce a sources/ tree"
    java_files = list(sources.rglob("*.java"))
    assert len(java_files) > 10, "expected a real Java tree, got very little"


def test_manifest_analysis_on_sample(apk):
    result = manifest.analyze(apk)
    assert result.errors == []
    titles = [f.title for f in result.findings]
    # InsecureBankv2 ships allowBackup=true and debuggable=true.
    assert any("allowBackup" in t for t in titles), f"missing allowBackup finding: {titles}"
    assert any("debuggable" in t for t in titles), f"missing debuggable finding: {titles}"
    assert all(f.severity in SEVERITIES for f in result.findings)
    certs = [f for f in result.findings if f.title.startswith("Signing certificate")]
    assert certs, "expected at least one signing certificate finding"
    assert certs[0].detail.get("sha256_fingerprint")


def test_full_pipeline_on_sample(apk, tmp_path_factory):
    work = tmp_path_factory.mktemp("scan")
    result = run_android_analysis(apk, work)
    assert result.platform == "android"
    assert result.findings, "expected findings from the vulnerable sample"
    assert all(f.severity in SEVERITIES for f in result.findings)

    by_tool = {}
    for f in result.findings:
        by_tool.setdefault(f.tool, []).append(f)
    assert by_tool.get("androguard"), "androguard/manifest stage produced no findings"
    assert by_tool.get("semgrep"), "semgrep stage produced no findings"

    # Categories should be MASVS v2 controls where the mapping applies.
    categorized = [f for f in result.findings if f.category]
    assert categorized, "expected at least some MASVS-categorized findings"


def test_corrupt_apk_fails_preflight(tmp_path):
    bad = tmp_path / "corrupt.apk"
    bad.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 512)  # not a zip at all
    with pytest.raises(ScanAborted):
        run_android_analysis(bad, tmp_path / "work")
