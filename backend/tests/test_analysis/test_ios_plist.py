import plistlib
from pathlib import Path

import pytest

from app.analysis.base import TOOL_PLIST
from app.analysis.ios.plist import PlistError, analyze_info_plist, load_info_plist


def _write_plist(tmp_path: Path, plist: dict, fmt=plistlib.FMT_XML) -> Path:
    p = tmp_path / "Info.plist"
    p.write_bytes(plistlib.dumps(plist, fmt=fmt))
    return p


def test_load_info_plist_binary_and_xml(tmp_path):
    for fmt in (plistlib.FMT_BINARY, plistlib.FMT_XML):
        p = _write_plist(tmp_path, {"CFBundleIdentifier": "com.example.app"}, fmt=fmt)
        assert load_info_plist(p)["CFBundleIdentifier"] == "com.example.app"


def test_load_info_plist_rejects_garbage(tmp_path):
    p = tmp_path / "Info.plist"
    p.write_bytes(b"\x00\x01\x02 not a plist")
    with pytest.raises(PlistError):
        load_info_plist(p)


def test_ats_arbitrary_loads_is_high(tmp_path):
    p = _write_plist(
        tmp_path,
        {"NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True}},
    )
    result = analyze_info_plist(p)
    ats = [f for f in result.findings if f.category == "MASVS-NETWORK-1"]
    assert any(f.title.startswith("ATS allows arbitrary loads") for f in ats)
    assert ats[0].tool == TOOL_PLIST
    assert ats[0].severity == "high"


def test_ats_web_content_is_medium(tmp_path):
    p = _write_plist(
        tmp_path,
        {"NSAppTransportSecurity": {"NSAllowsArbitraryLoadsInWebContent": True}},
    )
    result = analyze_info_plist(p)
    assert any(
        f.title.startswith("ATS disabled in web content") for f in result.findings
    )


def test_ats_per_domain_exceptions(tmp_path):
    p = _write_plist(
        tmp_path,
        {
            "NSAppTransportSecurity": {
                "NSExceptionDomains": {
                    "http.example.com": {"NSExceptionAllowsInsecureHTTPLoads": True},
                    "old.example.com": {"NSExceptionMinimumTLSVersion": "TLSv1.0"},
                    "ok.example.com": {"NSExceptionAllowsInsecureHTTPLoads": False},
                }
            }
        },
    )
    result = analyze_info_plist(p)
    ats = [f for f in result.findings if "per-domain exceptions" in f.title]
    assert len(ats) == 1
    assert set(ats[0].detail["domains"]) == {"http.example.com", "old.example.com"}


def test_no_ats_findings_when_ats_absent(tmp_path):
    p = _write_plist(tmp_path, {"CFBundleName": "App"})
    result = analyze_info_plist(p)
    assert not [f for f in result.findings if f.category == "MASVS-NETWORK-1"]


def test_empty_usage_string_flagged(tmp_path):
    p = _write_plist(
        tmp_path,
        {
            "NSCameraUsageDescription": "",
            "NSLocationWhenInUseUsageDescription": "Needed for maps",
        },
    )
    result = analyze_info_plist(p)
    flagged = [f for f in result.findings if f.category == "MASVS-PLATFORM-2"]
    assert len(flagged) == 1
    assert "NSCameraUsageDescription" in flagged[0].detail["keys"]


def test_metadata_captured_in_meta(tmp_path):
    p = _write_plist(
        tmp_path,
        {
            "CFBundleIdentifier": "com.example.app",
            "MinimumOSVersion": "14.0",
            "UIBackgroundModes": ["location", "audio"],
        },
    )
    result = analyze_info_plist(p)
    assert result.meta["bundle_identifier"] == "com.example.app"
    assert result.meta["minimum_os_version"] == "14.0"
    assert result.meta["background_modes"] == ["location", "audio"]
