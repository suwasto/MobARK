"""Layer 1 context tests - precision derivation, platform tool whitelists,
full-set rendering. No LLM, no embeddings, no network.
"""
from __future__ import annotations

from app.agent.context import (
    PRECISION_BINARY,
    PRECISION_FILE_LINE,
    build_findings_context,
    derive_precision,
)
from app.models import Finding, Scan


def _add_scan(db_session_factory, *, platform="android", status="done"):
    with db_session_factory() as session:
        scan = Scan(filename="app.apk", platform=platform, status=status)
        session.add(scan)
        session.commit()
        return scan.id


def _add_findings(db_session_factory, scan_id, rows):
    with db_session_factory() as session:
        for tool, title, sev, file_, line, cat in rows:
            session.add(
                Finding(
                    scan_id=scan_id,
                    tool=tool,
                    title=title,
                    severity=sev,
                    file_path=file_,
                    line_number=line,
                    category=cat,
                )
            )
        session.commit()


def _context(db_session_factory, scan_id):
    with db_session_factory() as session:
        scan = session.get(Scan, scan_id)
        return build_findings_context(session, scan)


def test_precision_derivation_per_tool():
    # Layer 1 requirement: every source tagged with its precision level.
    assert derive_precision("semgrep") == PRECISION_FILE_LINE
    assert derive_precision("gitleaks") == PRECISION_FILE_LINE
    assert derive_precision("androguard") == PRECISION_FILE_LINE
    assert derive_precision("plist") == PRECISION_FILE_LINE
    assert derive_precision("lief") == PRECISION_BINARY
    assert derive_precision("symbols") == PRECISION_BINARY
    assert derive_precision("unknown-tool") == PRECISION_BINARY  # safe default


def test_android_context_excludes_ios_tools(db_session_factory):
    scan_id = _add_scan(db_session_factory, platform="android")
    _add_findings(
        db_session_factory,
        scan_id,
        [
            (
                "androguard",
                "Exported activity",
                "high",
                "AndroidManifest.xml",
                None,
                "MASVS-PLATFORM-1",
            ),
            ("semgrep", "WebView JS enabled", "warning", "com/app/W.java", 42, "MASVS-PLATFORM-2"),
            ("lief", "PIE disabled", "high", None, None, "MASVS-CODE-4"),  # iOS-only tool
        ],
    )
    c = _context(db_session_factory, scan_id)
    assert {e.tool for e in c.entries} == {"androguard", "semgrep"}
    assert "PIE disabled" not in c.rendered


def test_ios_context_excludes_androguard_and_tags_precision(db_session_factory):
    scan_id = _add_scan(db_session_factory, platform="ios")
    _add_findings(
        db_session_factory,
        scan_id,
        [
            ("androguard", "Manifest leak", "high", "AndroidManifest.xml", None, None),
            (
                "symbols",
                "Legacy MD5 hashing imported (CC_MD5)",
                "warning",
                None,
                None,
                "MASVS-CRYPTO-2",
            ),
            ("gitleaks", "Hardcoded secret", "high", "Test.app/Binary", 5, None),
            ("plist", "ATS arbitrary loads", "high", "Info.plist", None, "MASVS-NETWORK-1"),
            ("semgrep", "stray finding", "info", "x.swift", 1, None),
        ],
    )
    c = _context(db_session_factory, scan_id)
    tools = {e.tool for e in c.entries}
    assert "androguard" not in tools  # must never appear in the iOS path
    assert tools == {"symbols", "gitleaks", "plist", "semgrep"}

    by_tool = {e.tool: e for e in c.entries}
    assert by_tool["symbols"].precision == PRECISION_BINARY
    assert by_tool["gitleaks"].precision == PRECISION_FILE_LINE
    assert by_tool["plist"].precision == PRECISION_FILE_LINE

    rendered = c.rendered
    assert "[file/line]" in rendered
    assert "[binary-level presence only" in rendered
    assert "import-table scanner" in rendered  # tool labeled, not "LIEF-derived"


def test_ios_context_notes_semgrep_zero_yield_when_empty(db_session_factory):
    scan_id = _add_scan(db_session_factory, platform="ios")
    _add_findings(
        db_session_factory,
        scan_id,
        [("gitleaks", "Hardcoded secret", "high", "Test.app/Binary", 5, None)],
    )
    c = _context(db_session_factory, scan_id)
    assert "zero findings by design on iOS" in c.rendered


def test_full_findings_set_never_subsetted(db_session_factory):
    scan_id = _add_scan(db_session_factory, platform="android")
    _add_findings(
        db_session_factory,
        scan_id,
        [("gitleaks", f"secret {i}", "high", f"f{i}.java", i, None) for i in range(50)],
    )
    c = _context(db_session_factory, scan_id)
    assert c.count == 50
    assert all(f"secret {i}" in c.rendered for i in (0, 25, 49))  # nothing dropped


def test_max_findings_is_explicit_escape_hatch_only(db_session_factory):
    scan_id = _add_scan(db_session_factory, platform="android")
    _add_findings(
        db_session_factory,
        scan_id,
        [("gitleaks", f"secret {i}", "high", f"f{i}.java", i, None) for i in range(10)],
    )
    with db_session_factory() as session:
        scan = session.get(Scan, scan_id)
        capped = build_findings_context(session, scan, max_findings=3)
    assert capped.count == 3


def test_known_file_defaults_for_manifest_and_plist(db_session_factory):
    # plist/androguard stages don't set a per-finding file_path - Layer 1 must
    # still name the file (Info.plist / AndroidManifest.xml), it's part of the
    # precision contract.
    android_scan = _add_scan(db_session_factory, platform="android")
    _add_findings(
        db_session_factory,
        android_scan,
        [("androguard", "Backup enabled", "warning", None, None, None)],
    )
    c = _context(db_session_factory, android_scan)
    assert "AndroidManifest.xml" in c.rendered

    ios_scan = _add_scan(db_session_factory, platform="ios")
    _add_findings(
        db_session_factory,
        ios_scan,
        [("plist", "ATS arbitrary loads", "high", None, None, "MASVS-NETWORK-1")],
    )
    c = _context(db_session_factory, ios_scan)
    assert "Info.plist" in c.rendered


def test_rendered_entries_carry_location_and_mastg_id(db_session_factory):
    scan_id = _add_scan(db_session_factory, platform="android")
    _add_findings(
        db_session_factory,
        scan_id,
        [
            ("semgrep", "WebView JS enabled", "warning", "com/app/W.java", 42, "MASVS-PLATFORM-2"),
            ("androguard", "Backup enabled", "warning", "AndroidManifest.xml", None, None),
        ],
    )
    c = _context(db_session_factory, scan_id)
    assert "com/app/W.java:42" in c.rendered
    assert "AndroidManifest.xml" in c.rendered
