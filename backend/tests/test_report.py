"""M9 report assembly - Phase A unit tests.

The assembly is a pure function of persisted scan data (no LLM, no I/O):
``report.assemble_report(scan, findings, ...)`` renders the markdown body
from ORM rows + optional derived payloads. These tests build real rows via
the scratch-SQLite fixture (the dependencies/edits test convention) and
assert on the rendered body - no model, no filesystem.
"""
from __future__ import annotations

import json

from app.analysis import report
from app.analysis.risk import security_from_risk
from app.models import Finding, Scan

# ---- band helpers -----------------------------------------------------------


def test_risk_band_matches_security_gauge_boundaries():
    assert report.risk_band(80) == "high"
    assert report.risk_band(70) == "high"
    assert report.risk_band(69) == "medium"
    assert report.risk_band(40) == "medium"
    assert report.risk_band(39) == "low"
    assert report.risk_band(1) == "low"
    assert report.risk_band(0) == "none"
    assert report.risk_band(None) == "none"
    assert report.risk_band(90) == "high"  # defensive - beyond the cap


def test_security_label_mirrors_gauge():
    assert report.security_label(80) == "Low security"
    assert report.security_label(55) == "Medium security"
    assert report.security_label(20) == "High security"
    assert report.security_label(0) == "Excellent security"


# ---- Android golden body ----------------------------------------------------


def _make_scan(
    db_session_factory,
    *,
    platform="android",
    risk_score=80,
    ai_summary="Apps ships with an insecure WebView surface.",
):
    with db_session_factory() as db:
        scan = Scan(
            filename="app.apk" if platform == "android" else "app.ipa",
            platform=platform,
            status="done",
            risk_score=risk_score,
            ai_summary=ai_summary,
        )
        db.add(scan)
        db.commit()
        return db.get(Scan, scan.id)


def _add_findings(db_session_factory, scan_id, rows):
    with db_session_factory() as db:
        for row in rows:
            db.add(Finding(scan_id=scan_id, **row))
        db.commit()


def _findings(db_session_factory, scan_id):
    with db_session_factory() as session:
        return list(session.query(Finding).filter(Finding.scan_id == scan_id).all())


def test_no_ai_finding_explanation_fallback(db_session_factory):
    """A finding WITHOUT a cached AI explanation still renders a complete
    deterministic paragraph (Aug 13 follow-up: the report must not depend on
    a model - the MobSF pattern): tool + severity + location + the
    MASVS/MASTG mapping from persisted data + the vendored mapping, closed
    with the static-only scope note. The cached AI explanation replaces it
    when a model has generated one (the golden-body test above asserts the
    AI text renders instead)."""
    scan = _make_scan(db_session_factory, ai_summary=None)
    _add_findings(
        db_session_factory,
        scan.id,
        [
            {
                "title": "WebView has JavaScript enabled",
                "severity": "high",
                "file_path": "com/foo/WebView.java",
                "line_number": 12,
                "category": "MASVS-PLATFORM",
                "mastg_test_id": "MASTG-TEST-0222",
                "tool": "semgrep",
            },
            {
                "title": "Hardcoded credential",
                "severity": "medium",
                "file_path": "com/foo/ApiKeys.java",
                "line_number": 7,
                "tool": "gitleaks",
            },
            {
                "title": "Up-to-date OS version check",
                "severity": "low",
                "file_path": "com/foo/MainActivity.java",
                "line_number": 20,
                "category": "MASVS-PLATFORM",
                "tool": "semgrep",
                "detail": json.dumps({"check_id": "mastg-android-sdk-version"}),
            },
            {
                "title": "Hardcoded secret detected: google-api-key",
                "severity": "high",
                "file_path": "com/foo/Config.java",
                "line_number": 30,
                "tool": "gitleaks",
                "detail": json.dumps(
                    {
                        "rule_id": "google-api-key",
                        "rule_description": "A Google API key was detected",
                    }
                ),
            },
        ],
    )
    body = report.assemble_report(scan, _findings(db_session_factory, scan.id))

    # No-AI executive summary fallback (the report is complete, not a
    # "configure a model" note)
    assert "found **4 findings**" in body
    # Deterministic per-finding explanation: what, where, the mapping, scope
    assert (
        "This semgrep check reported a high-severity condition at "
        "`com/foo/WebView.java:12`" in body
    )
    assert "mapped to MASVS control MASVS-PLATFORM" in body
    assert "OWASP MASTG test MASTG-TEST-0222 (Position Independent Code (PIC) Not Enabled)" in body
    assert "Static-only finding" in body
    # A finding with no MASTG mapping still gets the factual fallback
    assert "This gitleaks check reported a medium-severity condition" in body
    # The vendored RULE description (metadata.summary) enriches the
    # explanation - distinct from the title, cited with the rule id.
    assert (
        "This semgrep check (mastg-android-sdk-version: "
        "This rule scans for API that checks the version of the operating "
        "system) reported a low-severity condition"
    ) in body
    # Gitleaks: the persisted rule description + rule id name WHAT leaked.
    assert (
        "This gitleaks check (google-api-key: A Google API key was detected) "
        "reported a high-severity condition"
    ) in body
    # No AI placeholders anywhere
    assert "No AI" not in body
    assert "configure a chat model" not in body


def test_android_report_full_body(tmp_path, monkeypatch, db_session_factory):
    scan = _make_scan(db_session_factory, risk_score=80)
    _add_findings(
        db_session_factory,
        scan.id,
        [
            {
                "title": "Insecure WebView configuration",
                "severity": "high",
                "file_path": "com/foo/WebViewActivity.java",
                "line_number": 42,
                "category": "MASVS-CODE",
                "mastg_test_id": "MASTG-TEST-0073",
                "tool": "semgrep",
                "explanation": "WebView loads untrusted content.",
            },
            {
                "title": "Hardcoded credential",
                "severity": "medium",
                "file_path": "com/foo/ApiKeys.java",
                "line_number": 7,
                "tool": "gitleaks",
            },
            {
                "title": "Insecure WebView configuration (suppressed)",
                "severity": "high",
                "file_path": "com/foo/Other.java",
                "tool": "semgrep",
                "suppressed": True,
            },
        ],
    )
    body = report.assemble_report(
        scan,
        _findings(db_session_factory, scan.id),
        dependencies={
            "platform": "android",
            "app": {"package": "com.foo"},
            "runtime_markers": ["Flutter"],
            "dependencies": [
                {
                    "name": "okhttp3",
                    "kind": "package",
                    "finding_count": 1,
                    "high_count": 1,
                    "evidence": "1 source file",
                }
            ],
        },
        web_sources=["https://nvd.nist.gov/vuln/detail/CVE-2026-0001"],
        # The fixture has 3 findings, 1 suppressed (the route computes this
        # from the DB; the unit test states it explicitly).
        suppressed_count=1,
    )

    # Header + score band
    assert "# MASA security report" in body
    assert "**App:** app.apk (android)" in body
    assert "risk 80/100 · High" in body
    assert security_from_risk(80) == 20
    assert "20/100 - Low security" in body
    assert "**Package:** com.foo" in body

    # Executive summary from the cached row
    assert "## Executive summary" in body
    assert "insecure WebView surface" in body

    # Severity breakdown counts the NON-suppressed set
    assert "**high:** 1" in body
    assert "**medium:** 1" in body
    assert "**low:** 0" in body

    # Findings grouped by severity - suppressed one never appears (only its
    # count does, via the open-item-2 footnote - "one line, no detail").
    assert "### High (1)" in body
    assert "### Medium (1)" in body
    # Recommended priorities (manual-review follow-up): the app-owned high
    # ranks first, info rows are never priorities, scope note present.
    assert "## Recommended priorities" in body
    assert "1. **[HIGH] Insecure WebView configuration**" in body
    assert "_Scope: automated static analysis" in body
    assert "Insecure WebView configuration" in body
    assert "com/foo/WebViewActivity.java:42" in body
    # Aug 12 follow-up: MASTG-TEST-0073 is DEPRECATED in MASTG v2 - the
    # report must never cite it as current (the MASVS control still renders).
    assert "MASTG-TEST-0073" not in body
    assert "MASVS-CODE" in body
    # The standards-provenance line names the vendored MASTG v2 ref + date.
    assert "**Standards:**" in body
    assert "deprecated v1 test ids are not cited" in body
    assert "WebView loads untrusted content." in body
    assert "Insecure WebView configuration (suppressed)" not in body
    assert "**Suppressed findings:** 1 excluded (not scored, not listed below)" in body

    # Android surface note
    assert "## Android surface" in body
    assert "editable as smali" in body

    # Dependencies section from the passed payload
    assert "## Dependencies" in body
    assert "**okhttp3** (package)" in body
    assert "1 finding (1 high)" in body
    assert "**Runtime:** Flutter" in body

    # Aug 14 follow-up: NO Resigned test builds section - the report is the
    # static assessment of the uploaded artifact, not the M8 rebuild pipeline
    # (the Recompile modal owns that history).
    assert "## Resigned test builds" not in body
    assert "resigned-test" not in body

    # External references (M7 web sources) cited distinctly
    assert "## External references" in body
    assert "https://nvd.nist.gov/vuln/detail/CVE-2026-0001" in body


def test_report_cites_active_mastg_test_never_deprecated(
    tmp_path, monkeypatch, db_session_factory
):
    """Aug 12 follow-up: a CURRENT v2 atomic test id is cited; a deprecated
    v1 id on the same scan is never rendered as a tag."""
    scan = _make_scan(db_session_factory)
    _add_findings(
        db_session_factory,
        scan.id,
        [
            {
                "title": "Current test",
                "severity": "high",
                "file_path": "com/foo/A.java",
                "line_number": 1,
                "category": "MASVS-AUTH-2",
                "mastg_test_id": "MASTG-TEST-0326",  # active v2 atomic
                "tool": "semgrep",
            },
            {
                "title": "Retired test",
                "severity": "medium",
                "file_path": "com/foo/B.java",
                "line_number": 2,
                "category": "MASVS-PLATFORM-1",
                "mastg_test_id": "MASTG-TEST-0007",  # deprecated v1
                "tool": "semgrep",
            },
        ],
    )
    body = report.assemble_report(scan, _findings(db_session_factory, scan.id))
    assert "MASTG-TEST-0326" in body
    assert "MASTG-TEST-0007" not in body
    assert "MASVS-PLATFORM-1" in body  # the control is always cited


def test_android_empty_scan_blank_ai_fallback(tmp_path, monkeypatch, db_session_factory):
    scan = _make_scan(db_session_factory, risk_score=None, ai_summary=None)

    body = report.assemble_report(scan, [])

    assert "not yet scored" in body
    # No-AI path (Aug 12 follow-up): the export never depends on AI - the
    # executive summary is a deterministic roll-up, not a placeholder.
    assert "No AI summary yet" not in body
    assert "automated static assessment" in body
    assert "found **no findings**" in body  # summary-specific phrasing
    assert "**high:** 0" in body
    assert "_No findings for this scan._" in body
    assert "## Android surface" in body
    # No dependencies / builds / web sections when nothing was passed
    assert "## Dependencies" not in body
    assert "## Resigned test builds" not in body
    assert "## External references" not in body
    # No suppression footnote when nothing was excluded
    assert "Suppressed findings" not in body
    # No priorities when there is nothing to fix
    assert "## Recommended priorities" not in body


def test_no_ai_summary_is_deterministic_rollup(
    tmp_path, monkeypatch, db_session_factory
):
    """Aug 12 follow-up: with no chat model (ai_summary blank), the executive
    summary is assembled from persisted data - counts + MASVS controls - so
    the PDF/markdown export is complete without AI. The AI narrative is a
    bonus when a model has run, never a requirement."""
    scan = _make_scan(db_session_factory, risk_score=80, ai_summary=None)
    _add_findings(
        db_session_factory,
        scan.id,
        [
            {
                "title": "Exported activity",
                "severity": "high",
                "file_path": "AndroidManifest.xml",
                "category": "MASVS-PLATFORM-1",
                "tool": "semgrep",
            },
            {
                "title": "Weak cipher",
                "severity": "medium",
                "file_path": "com/foo/Crypto.java",
                "line_number": 3,
                "category": "MASVS-CRYPTO-2",
                "tool": "semgrep",
            },
            {
                "title": "Logging",
                "severity": "info",
                "file_path": "com/foo/Log.java",
                "category": "MASVS-CODE-2",
                "tool": "semgrep",
            },
        ],
    )
    body = report.assemble_report(scan, _findings(db_session_factory, scan.id))
    assert "No AI summary yet" not in body
    assert "automated static assessment" in body
    assert "**3 findings**" in body
    assert "1 high, 1 medium, 1 info" in body
    assert "3 MASVS controls" in body
    assert "MASVS-PLATFORM-1" in body
    # The AI path is untouched: a cached summary still wins.
    scan_with_ai = _make_scan(db_session_factory, risk_score=80)
    _add_findings(
        db_session_factory, scan_with_ai.id,
        [{"title": "X", "severity": "low", "tool": "semgrep"}],
    )
    ai_body = report.assemble_report(
        scan_with_ai, _findings(db_session_factory, scan_with_ai.id)
    )
    assert "Apps ships with an insecure WebView surface." in ai_body
    assert "automated static assessment" not in ai_body


def test_android_lists_every_finding_including_vendored(
    tmp_path, monkeypatch, db_session_factory
):
    """Aug 14 owner follow-up: the report shows EVERY non-suppressed
    finding - findings inside bundled third-party libraries (the Dependencies
    tab's grouping) are listed individually too, never a per-library tally
    ("not only just 'medium x count'"). The severity breakdown counts
    everything (it must match the risk score)."""
    scan = _make_scan(db_session_factory, risk_score=80)
    _add_findings(
        db_session_factory,
        scan.id,
        [
            {
                "title": "Insecure WebView configuration",
                "severity": "high",
                "file_path": "com/foo/WebViewActivity.java",
                "line_number": 42,
                "tool": "semgrep",
            },
            {
                "title": "Support library repeat",
                "severity": "medium",
                "file_path": "android/support/v4/app/ActivityCompat.java",
                "line_number": 66,
                "tool": "semgrep",
            },
            {
                "title": "GMS SDK finding",
                "severity": "high",
                "file_path": "com/google/android/gms/internal/zzar.java",
                "line_number": 56,
                "tool": "semgrep",
            },
            {
                "title": "GMS odd-severity row",
                "severity": "warning",
                "file_path": "com/google/android/gms/internal/zzbk.java",
                "line_number": 9,
                "tool": "semgrep",
            },
        ],
    )
    body = report.assemble_report(
        scan,
        _findings(db_session_factory, scan.id),
        dependencies={
            "platform": "android",
            "app": {"package": "com.foo"},
            "dependencies": [
                {
                    "name": "com.google.android.gms",
                    "label": "Google Play services",
                    "kind": "package",
                },
                {
                    "name": "android.support",
                    "label": "Android Support Library",
                    "kind": "package",
                },
            ],
        },
    )

    # Breakdown counts everything (matches the risk score) - the warning
    # severity lands in the report's explicit "other" bucket, never vanishes.
    assert "**high:** 2" in body
    assert "**medium:** 1" in body
    assert "**other:** 1" in body

    # EVERY finding is listed individually, grouped by severity - app-owned
    # and vendored alike. No "- app-owned" suffix, no per-library tally.
    assert "### High (2)" in body
    assert "### Medium (1)" in body
    assert "### Other (1)" in body
    assert "Insecure WebView configuration" in body
    assert "com/foo/WebViewActivity.java:42" in body
    assert "Support library repeat" in body
    assert "android/support/v4/app/ActivityCompat.java:66" in body
    assert "GMS SDK finding" in body
    assert "GMS odd-severity row" in body
    assert "Third-party library findings" not in body
    assert "app-owned" not in body

    # Priorities rank by severity (high first) across the whole set.
    assert "## Recommended priorities" in body
    assert "1. **[HIGH] Insecure WebView configuration**" in body
    assert "2. **[HIGH] GMS SDK finding**" in body


def test_priorities_rank_by_severity_and_exclude_info(
    tmp_path, monkeypatch, db_session_factory
):
    """Manual-review follow-up: the Recommended priorities list orders
    app-owned findings high -> low (info rows are never "priorities" - the
    detail section still lists them) and caps at 10."""
    scan = _make_scan(db_session_factory, risk_score=80)
    _add_findings(
        db_session_factory,
        scan.id,
        [
            {
                "title": "Low-severity note",
                "severity": "low",
                "file_path": "com/foo/Low.java",
                "line_number": 1,
                "tool": "gitleaks",
            },
            {
                "title": "Medium-severity issue",
                "severity": "medium",
                "file_path": "com/foo/Med.java",
                "line_number": 2,
                "tool": "semgrep",
            },
            {
                "title": "High-severity issue",
                "severity": "high",
                "file_path": "com/foo/High.java",
                "line_number": 3,
                "tool": "semgrep",
            },
            {
                "title": "Info row",
                "severity": "info",
                "file_path": "com/foo/Info.java",
                "line_number": 4,
                "tool": "lief",
            },
        ],
    )
    body = report.assemble_report(
        scan,
        _findings(db_session_factory, scan.id),
        dependencies={"platform": "android", "app": {"package": "com.foo"}},
    )

    # High first, then medium, then low - info never a priority. Slice the
    # priorities section on its own heading (not the whole body) so a future
    # section reorder can't silently change what this asserts.
    priorities_section = body.split("## Findings")[0]
    high = priorities_section.index("1. **[HIGH] High-severity issue**")
    med = priorities_section.index("2. **[MEDIUM] Medium-severity issue**")
    low = priorities_section.index("3. **[LOW] Low-severity note**")
    assert high < med < low
    assert "[INFO] Info row" not in priorities_section
    assert "Info row" in body  # still in the detail section


def test_ios_dylib_dedupe_in_dependencies(tmp_path, monkeypatch, db_session_factory):
    """Manual-review follow-up: linked dylibs render ONCE - the iOS binary
    profile is the authoritative list, and the Dependencies section points
    there instead of re-listing every dylib (a 35-row repeat is not
    something a pentester would ship). Frameworks still render."""
    scan = _make_scan(db_session_factory, platform="ios", risk_score=55)
    _add_findings(
        db_session_factory,
        scan.id,
        [
            {
                "title": "Linked dylibs (2)",
                "severity": "info",
                "tool": "lief",
                "detail": json.dumps(
                    {
                        "dylibs": [
                            "/usr/lib/libSystem.B.dylib",
                            "@rpath/Alamofire.framework/Alamofire",
                        ]
                    }
                ),
            },
        ],
    )
    body = report.assemble_report(
        scan,
        _findings(db_session_factory, scan.id),
        dependencies={
            "platform": "ios",
            "app": {"bundle_id": "com.northbank.mobile"},
            "dependencies": [
                {"name": "/usr/lib/libSystem.B.dylib", "kind": "dylib"},
                {
                    "name": "@rpath/Alamofire.framework/Alamofire",
                    "kind": "dylib",
                },
                {"name": "Alamofire", "kind": "framework"},
            ],
        },
    )

    # The profile lists the dylibs once (authoritative).
    assert "**Linked dylibs:**" in body
    assert "@rpath/Alamofire.framework/Alamofire" in body
    # The Dependencies section points to the profile instead of re-listing.
    assert "**Linked dylibs (2):** listed in the iOS binary profile above" in body
    assert "(dylib) - Mach-O linked dylib" not in body
    # Frameworks are NOT part of the profile - they still render.
    assert "**Alamofire** (framework)" in body


def test_suppressed_only_scan_footnote(db_session_factory):
    """Phase E edge: a scan whose findings are ALL suppressed must not read
    as a clean bill of health - the breakdown shows zero counts and the
    open-item-2 footnote names how many findings were excluded ("one line,
    no detail" - the rows stay reviewable in the Findings tab)."""
    scan = _make_scan(db_session_factory, risk_score=0)
    _add_findings(
        db_session_factory,
        scan.id,
        [
            {"title": "False positive A", "severity": "high", "tool": "semgrep"},
            {"title": "False positive B", "severity": "medium", "tool": "gitleaks"},
        ],
    )
    with db_session_factory() as db:
        for f in db.query(Finding).filter(Finding.scan_id == scan.id).all():
            f.suppressed = True
        db.commit()

    body = report.assemble_report(scan, [], suppressed_count=2)

    # Everything scored is zero - but the footnote explains WHY.
    assert "**high:** 0" in body
    assert "**medium:** 0" in body
    assert "_No findings for this scan._" in body
    assert "**Suppressed findings:** 2 excluded (not scored, not listed below)" in body
    assert "False positive A" not in body
    assert "False positive B" not in body
    # The score line still renders (a suppressed-only scan scores zero).
    assert "**Security score:** 100/100 - Excellent security" in body


# ---- iOS binary profile -----------------------------------------------------


def test_ios_report_binary_profile(tmp_path, monkeypatch, db_session_factory):
    scan = _make_scan(db_session_factory, platform="ios", risk_score=55)
    _add_findings(
        db_session_factory,
        scan.id,
        [
            {
                "title": "Binary slices",
                "severity": "info",
                "tool": "lief",
                "detail": json.dumps({"architectures": ["arm64", "arm64e"]}),
            },
            {
                "title": "Position-independent executable (PIE) disabled",
                "severity": "high",
                "tool": "lief",
            },
            {
                "title": "Linked dylibs (2)",
                "severity": "info",
                "tool": "lief",
                "detail": json.dumps(
                    {
                        "dylibs": [
                            "/usr/lib/libSystem.B.dylib",
                            "@rpath/Alamofire.framework/Alamofire",
                        ]
                    }
                ),
            },
            {
                "title": "Entitlements granted (2)",
                "severity": "info",
                "tool": "lief",
                "detail": json.dumps(
                    {"entitlements": {"get-task-allow": True, "aps-environment": "dev"}}
                ),
            },
            {
                "title": "Exported symbols (500)",
                "severity": "info",
                "tool": "lief",
                "detail": json.dumps({"count": 500, "sample": ["_foo", "_bar"]}),
            },
            {
                "title": "Legacy crypto import",
                "severity": "high",
                "tool": "symbols",
                "detail": json.dumps({"symbol": "CC_MD5", "note": "legacy digest"}),
            },
        ],
    )
    body = report.assemble_report(
        scan,
        _findings(db_session_factory, scan.id),
        dependencies={
            "platform": "ios",
            "app": {"bundle_id": "com.northbank.mobile"},
            "dependencies": [
                {"name": "Alamofire", "kind": "framework"},
            ],
        },
    )

    assert "**App:** app.ipa (ios)" in body
    assert "risk 55/100 · Medium" in body
    assert "**Bundle id:** com.northbank.mobile" in body

    # Binary profile from the persisted LIEF/symbols findings
    assert "## iOS binary profile" in body
    assert "**Architectures:** arm64, arm64e" in body
    assert "PIE disabled" in body
    assert "Linked dylibs" in body
    assert "Alamofire.framework/Alamofire" in body
    assert "get-task-allow" in body
    assert "Exported symbols" in body
    assert "Import-table finding [HIGH]: Legacy crypto import" in body
    assert "CC_MD5" in body

    # No Android-only section on iOS
    assert "## Android surface" not in body

    # Dependencies payload renders too
    assert "**Alamofire** (framework)" in body


def test_ios_no_binary_profile_falls_back(tmp_path, monkeypatch, db_session_factory):
    scan = _make_scan(db_session_factory, platform="ios", risk_score=20)
    _add_findings(
        db_session_factory,
        scan.id,
        [{"title": "Some other finding", "severity": "low", "tool": "gitleaks"}],
    )
    body = report.assemble_report(scan, _findings(db_session_factory, scan.id))
    assert "## iOS binary profile" in body
    assert "No binary-profile findings recorded" in body


def test_unknown_severity_lands_in_other_bucket(
    tmp_path, monkeypatch, db_session_factory
):
    """A severity outside the vocabulary must not silently vanish from the
    report - it lands in an explicit "Other" bucket (the findings tab still
    returns such rows; risk.py ignores them for scoring by design)."""
    scan = _make_scan(db_session_factory, risk_score=0)
    _add_findings(
        db_session_factory,
        scan.id,
        [
            {"title": "Odd severity row", "severity": "warning", "tool": "custom"},
            {"title": "Normal low", "severity": "low", "tool": "gitleaks"},
        ],
    )
    body = report.assemble_report(scan, _findings(db_session_factory, scan.id))
    assert "**other:** 1" in body
    assert "### Other (1)" in body
    assert "Odd severity row" in body
    assert "### Low (1)" in body


def test_report_reuses_risk_module_not_reimplemented():
    """The header band/label must be derived from risk.py - a future change
    to the scoring model must flow into the report automatically."""
    import inspect

    source = inspect.getsource(report)
    assert "security_from_risk" in source  # the report derives, never stores
