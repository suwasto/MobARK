import plistlib
import zipfile
from pathlib import Path

import pytest

from app.analysis.ios.ipa import IpaError, extract, find_app_dir


def _make_ipa(tmp_path: Path, with_plist: bool = True, corrupt: bool = False) -> Path:
    ipa_path = tmp_path / "app.ipa"
    with zipfile.ZipFile(ipa_path, "w") as zf:
        if corrupt:
            zf.writestr("Payload/Broken.app/", b"")
        else:
            zf.writestr("Payload/MyApp.app/AppBinary", b"\x00" * 16)
            zf.writestr("Payload/MyApp.app/Resources/info.txt", b"hello")
            if with_plist:
                plist = {
                    "CFBundleIdentifier": "com.example.MyApp",
                    "CFBundleName": "MyApp",
                    "CFBundleDisplayName": "My App",
                    "CFBundleShortVersionString": "1.2.3",
                }
                zf.writestr(
                    "Payload/MyApp.app/Info.plist",
                    plistlib.dumps(plist, fmt=plistlib.FMT_BINARY),
                )
    return ipa_path


def test_find_app_dir_locates_payload_app(tmp_path):
    ipa = _make_ipa(tmp_path)
    with zipfile.ZipFile(ipa) as zf:
        assert find_app_dir(zf) == "MyApp.app"


def test_find_app_dir_rejects_archive_without_payload(tmp_path):
    ipa = tmp_path / "empty.ipa"
    with zipfile.ZipFile(ipa, "w") as zf:
        zf.writestr("README.txt", b"not an app")
    with pytest.raises(IpaError, match="no Payload/.*\\.app"):
        with zipfile.ZipFile(ipa) as zf:
            find_app_dir(zf)


def test_extract_returns_bundle_metadata(tmp_path):
    ipa = _make_ipa(tmp_path)
    dest = tmp_path / "out"
    bundle = extract(ipa, dest)

    assert bundle.app_dir_name == "MyApp.app"
    assert bundle.bundle_identifier == "com.example.MyApp"
    assert bundle.bundle_name == "MyApp"
    assert bundle.display_name == "My App"
    assert bundle.version == "1.2.3"

    app_root = dest / "Payload" / "MyApp.app"
    assert (app_root / "AppBinary").is_file()
    assert (app_root / "Resources" / "info.txt").is_file()


def test_extract_rejects_missing_info_plist(tmp_path):
    ipa = _make_ipa(tmp_path, with_plist=False)
    with pytest.raises(IpaError, match="missing Info.plist"):
        extract(ipa, tmp_path / "out")


def test_extract_rejects_non_zip(tmp_path):
    f = tmp_path / "fake.ipa"
    f.write_bytes(b"this is not a zip" * 10)
    with pytest.raises(IpaError, match="not a valid ZIP"):
        extract(f, tmp_path / "out")


def test_extract_rejects_corrupt_zip(tmp_path, monkeypatch):
    # A zip that fails to read its central directory mid-extract must
    # surface as the "corrupt archive" IpaError, not a raw traceback.
    ipa = _make_ipa(tmp_path)

    def flaky_namelist(self):
        raise zipfile.BadZipFile("central directory is corrupt")

    monkeypatch.setattr(zipfile.ZipFile, "namelist", flaky_namelist)
    with pytest.raises(IpaError, match="corrupt archive"):
        extract(ipa, tmp_path / "out")


def test_extract_rejects_encrypted_archive(tmp_path, monkeypatch):
    # Encrypted zip members raise RuntimeError from extractall, which must
    # surface as a clean IpaError, not a raw traceback.
    ipa = _make_ipa(tmp_path)

    def encrypted_extractall(self, path):
        raise RuntimeError("password required for extraction")

    monkeypatch.setattr(zipfile.ZipFile, "extractall", encrypted_extractall)
    with pytest.raises(IpaError, match="encrypted"):
        extract(ipa, tmp_path / "out")


def test_extract_rejects_oversized_archive(tmp_path, monkeypatch):
    # A decompression-bomb IPA (huge declared member sizes) must be rejected
    # before any extraction happens.
    ipa = _make_ipa(tmp_path)
    monkeypatch.setattr(
        "app.analysis.ios.ipa.MAX_UNPACKED_BYTES", 16, raising=False
    )
    with pytest.raises(IpaError, match="too large to unpack"):
        extract(ipa, tmp_path / "out")


def test_extract_missing_file_raises(tmp_path):
    with pytest.raises(IpaError, match="IPA not found"):
        extract(tmp_path / "nope.ipa", tmp_path / "out")
