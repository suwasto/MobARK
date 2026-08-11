"""M2 integration tests against the real, deliberately-vulnerable sample.

Requires ``lief`` installed and the pinned sample IPA present at
``docs/iBugBazaar.ipa`` (see docs/progress/M2.md for the pinned release +
sha256). Run with:  pytest -m integration
"""
import hashlib
from pathlib import Path

import pytest

from app.analysis.base import SEVERITIES
from app.analysis.ios.ipa import IpaError
from app.analysis.orchestrator import ScanAborted, run_ios_analysis

pytestmark = pytest.mark.integration

IPA = Path(__file__).resolve().parents[3] / "docs" / "iBugBazaar.ipa"
IPA_SHA256 = "0d8f588d3cdf312db8052cc24e70a41501e558631d5b9fcc3a12bf7a50f3e8b9"


@pytest.fixture(scope="module")
def ipa() -> Path:
    if not IPA.is_file():
        pytest.skip(f"sample IPA not present at {IPA}")
    return IPA


def test_ipa_is_pinned_artifact(ipa):
    digest = hashlib.sha256(ipa.read_bytes()).hexdigest()
    assert digest == IPA_SHA256, (
        f"sample IPA sha256 mismatch: got {digest}, expected {IPA_SHA256} - "
        "the vendored iBugBazaar artifact changed; update the pin in this test "
        "and docs/progress/M2.md"
    )


def test_full_ios_pipeline_on_sample(ipa, tmp_path_factory):
    work = tmp_path_factory.mktemp("ios-scan")
    result = run_ios_analysis(ipa, work)
    assert result.platform == "ios"
    assert result.app_root is not None and result.app_root.is_dir()
    assert result.findings, "expected findings from the vulnerable sample"
    assert all(f.severity in SEVERITIES for f in result.findings)
    assert all(f.static_only is True for f in result.findings)

    # MASTG backfill ran for iOS findings (the vendored mapping has iOS tests).
    backfilled = [f for f in result.findings if f.category and f.mastg_test_id]
    assert backfilled, "expected MASTG test ids backfilled for iOS findings"

    meta = result.meta
    assert meta.get("bundle_identifier") == "com.payatu.BugBazar"
    assert meta.get("architectures"), "expected Mach-O arch info"
    # iBugBazaar is signed ad-hoc for testing and ships get-task-allow.
    assert meta.get("entitlements", {}).get("get-task-allow") is True


def test_ios_pipeline_rejects_non_ipa(tmp_path):
    bad = tmp_path / "not-an.ipa"
    bad.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 512)
    with pytest.raises(ScanAborted, match="IPA unpack failed"):
        run_ios_analysis(bad, tmp_path / "work")


def test_ipa_extract_rejects_zip_without_payload(tmp_path):
    import zipfile

    f = tmp_path / "no-payload.ipa"
    with zipfile.ZipFile(f, "w") as zf:
        zf.writestr("README.txt", b"not an app")
    with pytest.raises(IpaError, match="no Payload"):
        from app.analysis.ios.ipa import extract

        extract(f, tmp_path / "out")
