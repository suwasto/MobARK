import zipfile

import pytest

from app.analysis.manifest import ManifestError
from app.analysis.orchestrator import ScanAborted, _preflight_apk


def test_preflight_rejects_non_zip(tmp_path):
    f = tmp_path / "not-an.apk"
    f.write_bytes(b"this is not a zip archive at all" * 10)
    with pytest.raises(ScanAborted, match="not a valid ZIP"):
        _preflight_apk(f)


def test_preflight_rejects_zip_without_manifest(tmp_path):
    f = tmp_path / "no-manifest.apk"
    with zipfile.ZipFile(f, "w") as zf:
        zf.writestr("classes.dex", b"\x00" * 8)
    with pytest.raises(ScanAborted, match="missing AndroidManifest.xml"):
        _preflight_apk(f)


def test_preflight_accepts_well_formed_zip(tmp_path):
    f = tmp_path / "ok.apk"
    with zipfile.ZipFile(f, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest/>")
        zf.writestr("classes.dex", b"\x00" * 8)
    assert _preflight_apk(f) is None


def test_preflight_rejects_missing_file(tmp_path):
    with pytest.raises(ScanAborted, match="APK not found"):
        _preflight_apk(tmp_path / "missing.apk")


def test_manifest_analyze_raises_on_garbage(tmp_path):
    f = tmp_path / "garbage.apk"
    f.write_bytes(b"\x00" * 1024)
    with pytest.raises(ManifestError):
        from app.analysis.manifest import analyze

        analyze(f)
