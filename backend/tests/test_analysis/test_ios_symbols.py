"""Import-table scanner tests - pure matcher, no LIEF binary needed.

M4 Layer 1 iOS source #2: known-insecure API blocklist matched against the
Mach-O import table. The matcher is a pure function; the LIEF read is thin.
"""
from __future__ import annotations

from app.analysis.base import TOOL_SYMBOLS
from app.analysis.ios.symbols import analyze_app_binary, match_imports


def test_match_legacy_crypto():
    findings = match_imports(["_CC_MD5", "_CC_SHA1", "_CC_DES", "_CCCrypt"])
    assert findings, "expected blocklist hits"
    assert all(f.tool == TOOL_SYMBOLS for f in findings)
    assert all(f.category == "MASVS-CRYPTO-2" for f in findings)
    titles = {f.title for f in findings}
    assert any("MD5" in t for t in titles)
    assert any("SHA-1" in t for t in titles)
    assert any("DES" in t for t in titles)


def test_match_uiwebview_via_objc_class_reference():
    """UIWebView is usually a class reference, not an import - the scanner
    accepts extra ObjC metadata names for that case."""
    findings = match_imports([], extra_names=["UIWebView"])
    assert any("UIWebView" in f.title for f in findings)
    assert findings[0].category == "MASVS-PLATFORM-2"


def test_match_anti_debug_symbols():
    findings = match_imports(["_ptrace", "_sysctl", "_syscall"])
    assert all(f.category == "MASVS-RESILIENCE-2" for f in findings)
    assert any("ptrace" in f.title for f in findings)
    assert any("sysctl" in f.title for f in findings)


def test_underscore_prefix_normalized():
    # "_ptrace" and "ptrace" are the same symbol - one finding, not two.
    assert len(match_imports(["_ptrace", "ptrace"])) == 1


def test_exact_match_wins_over_substring():
    # CCCryptorCreate must hit its own rule, not the broader CCCrypt one.
    findings = match_imports(["_CCCryptorCreate"])
    assert len(findings) == 1
    assert "CCCryptorCreate" in findings[0].title
    assert "CCCrypt imported" not in findings[0].title


def test_no_matches_for_benign_imports():
    assert (
        match_imports(["_objc_msgSend", "_malloc", "CFStringCreateWithFormat", "_memcpy"])
        == []
    )


def test_detail_carries_symbol_and_note():
    findings = match_imports(["_CC_MD5"])
    assert findings[0].detail["symbol"] == "_CC_MD5"
    assert "note" in findings[0].detail


def test_analyze_app_binary_without_executable_is_error_not_crash(tmp_path):
    result = analyze_app_binary(tmp_path)
    assert result.errors  # "no main executable"
    assert result.findings == []
