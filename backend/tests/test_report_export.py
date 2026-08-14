"""M9 Phase C - report export: GET /report + /report/export (md | pdf).

The assembled body is served cache-first (decision 7); export streams the
same body as Markdown or renders it through reportlab platypus to a branded
PDF (decision 3 as corrected Aug 12 - xhtml2pdf's LGPL transitive tree was
rejected; reportlab is BSD-3-Clause). The PDF tests are headless and
hermetic: no browser, no network - reportlab renders in-process on a thread
with the Helvetica font fallback (the DejaVu TTF only exists in the image),
and pypdf extracts the section headings from the rendered bytes. No model
is involved anywhere - the body assembly never 400s on a missing model
(decision 10).
"""
from __future__ import annotations

import io
from pathlib import Path

from app.analysis import report, report_pdf
from app.models import Finding, Scan
from tests.conftest import authed_user_id

# ---- helpers ----------------------------------------------------------------


def _add_scan(db_session_factory, *, filename="app.apk", status="done"):
    with db_session_factory() as session:
        scan = Scan(
            filename=filename, platform="android", status=status,
            user_id=authed_user_id(db_session_factory),
        )
        session.add(scan)
        session.commit()
        return scan.id


def _add_finding(db_session_factory, scan_id, *, title="Insecure WebView", sev="high"):
    with db_session_factory() as session:
        session.add(
            Finding(
                scan_id=scan_id,
                tool="semgrep",
                title=title,
                severity=sev,
                file_path="com/foo/WebView.java",
                line_number=42,
            )
        )
        session.commit()


# ---- GET /scans/{id}/report -------------------------------------------------


def test_get_report_returns_assembled_body(
    client, db_session_factory, monkeypatch, tmp_path
):
    import app.config

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    scan_id = _add_scan(db_session_factory)
    _add_finding(db_session_factory, scan_id)

    r = client.get(f"/api/v1/scans/{scan_id}/report")
    assert r.status_code == 200
    body = r.json()
    assert "# MASA security report" in body["markdown"]
    assert "## Executive summary" in body["markdown"]
    # The body renders with NO model configured - never a 400 (decision 10),
    # and the summary is a deterministic roll-up, not an AI placeholder
    # (Aug 12 follow-up: the export must not depend on AI).
    assert "No AI summary yet" not in body["markdown"]
    assert "automated static assessment" in body["markdown"]
    assert "Insecure WebView" in body["markdown"]
    assert body["generated_at"]


def test_get_report_empty_scan_and_pdf_exports(
    client, db_session_factory, monkeypatch, tmp_path
):
    """Phase E edge: a done scan with ZERO findings - the body reads as
    empty (never a crash) and the PDF export renders it too."""
    import app.config

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    scan_id = _add_scan(db_session_factory)

    r = client.get(f"/api/v1/scans/{scan_id}/report")
    assert r.status_code == 200
    body = r.json()["markdown"]
    assert "_No findings for this scan._" in body
    assert "**high:** 0" in body
    # Zero suppressed -> no footnote line
    assert "Suppressed findings" not in body

    from pypdf import PdfReader

    r = client.get(f"/api/v1/scans/{scan_id}/report/export", params={"format": "pdf"})
    assert r.status_code == 200
    assert r.content.startswith(b"%PDF")
    text = " ".join(
        (page.extract_text() or "") for page in PdfReader(io.BytesIO(r.content)).pages
    )
    assert "MASA security report" in " ".join(text.split())


def test_get_report_suppressed_only_footnote(
    client, db_session_factory, monkeypatch, tmp_path
):
    """Phase E edge: a scan with ALL findings suppressed - the body shows
    zero counts + the one-line footnote, and an unsuppress flips both (the
    cache identity recomputes - decision 7)."""
    import app.config

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    scan_id = _add_scan(db_session_factory)
    _add_finding(db_session_factory, scan_id, title="FP one")
    _add_finding(db_session_factory, scan_id, title="FP two", sev="low")

    with db_session_factory() as session:
        for f in session.query(Finding).filter(Finding.scan_id == scan_id).all():
            f.suppressed = True
        session.commit()

    r = client.get(f"/api/v1/scans/{scan_id}/report")
    body = r.json()["markdown"]
    assert "_No findings for this scan._" in body
    assert "**Suppressed findings:** 2 excluded (not scored, not listed below)" in body
    assert "FP one" not in body

    # Restore one -> footnote drops to 1, the finding returns (recomputed).
    with db_session_factory() as session:
        f = session.query(Finding).filter(Finding.scan_id == scan_id).first()
        f.suppressed = False
        session.commit()
    body = client.get(f"/api/v1/scans/{scan_id}/report").json()["markdown"]
    assert "**Suppressed findings:** 1 excluded (not scored, not listed below)" in body
    assert "FP one" in body


def test_ios_report_api_parity(client, db_session_factory, monkeypatch, tmp_path):
    """Phase E edge: iOS parity at the API layer - the binary-profile body
    and BOTH exports (md + pdf) work for an iOS scan."""
    import json as _json

    from pypdf import PdfReader

    import app.config

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    with db_session_factory() as session:
        scan = Scan(
            filename="app.ipa", platform="ios", status="done", risk_score=55,
            user_id=authed_user_id(db_session_factory),
        )
        session.add(scan)
        session.commit()
        scan_id = scan.id
        session.add_all(
            [
                Finding(
                    scan_id=scan_id,
                    tool="lief",
                    title="Binary slices",
                    severity="info",
                    detail=_json.dumps({"architectures": ["arm64"]}),
                ),
                Finding(
                    scan_id=scan_id,
                    tool="lief",
                    title="Position-independent executable (PIE) disabled",
                    severity="high",
                ),
            ]
        )
        session.commit()

    r = client.get(f"/api/v1/scans/{scan_id}/report")
    assert r.status_code == 200
    body = r.json()["markdown"]
    assert "**App:** app.ipa (ios)" in body
    assert "## iOS binary profile" in body
    assert "**Architectures:** arm64" in body
    assert "## Android surface" not in body

    md = client.get(
        f"/api/v1/scans/{scan_id}/report/export", params={"format": "md"}
    )
    assert md.status_code == 200
    assert md.text == body  # one body, two media

    pdf = client.get(
        f"/api/v1/scans/{scan_id}/report/export", params={"format": "pdf"}
    )
    assert pdf.status_code == 200
    assert pdf.content.startswith(b"%PDF")
    text = " ".join(
        (page.extract_text() or "") for page in PdfReader(io.BytesIO(pdf.content)).pages
    )
    assert "iOS binary profile" in " ".join(text.split())


def test_get_report_guards(client, db_session_factory):
    assert client.get("/api/v1/scans/999999/report").status_code == 404
    scan_id = _add_scan(db_session_factory, status="queued")
    r = client.get(f"/api/v1/scans/{scan_id}/report")
    assert r.status_code == 409
    assert "not analyzed" in r.json()["detail"]


# ---- export: markdown -------------------------------------------------------


def test_export_markdown_matches_report_body(
    client, db_session_factory, monkeypatch, tmp_path
):
    import app.config

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    scan_id = _add_scan(db_session_factory)
    _add_finding(db_session_factory, scan_id)

    report_body = client.get(f"/api/v1/scans/{scan_id}/report").json()["markdown"]
    r = client.get(f"/api/v1/scans/{scan_id}/report/export", params={"format": "md"})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/markdown")
    assert "attachment" in r.headers["content-disposition"]
    assert "app-report.md" in r.headers["content-disposition"]
    # The export streams the SAME cached body (cache-first, decision 7).
    assert r.text == report_body


def test_export_markdown_sanitizes_attachment_stem(client, db_session_factory):
    scan_id = _add_scan(db_session_factory, filename="North Bank APK (v1)!.apk")
    r = client.get(f"/api/v1/scans/{scan_id}/report/export", params={"format": "md"})
    assert r.status_code == 200
    # A hostile filename can never smuggle quotes into the header.
    # Both the sanitization and the quote-safety land in one assertion:
    # the filename is exactly the sanitized stem, wrapped in its own quotes.
    assert 'filename="North-Bank-APK-v1-report.md"' in r.headers["content-disposition"]


# ---- export: pdf ------------------------------------------------------------


def test_export_pdf_magic_and_section_headings(
    client, db_session_factory, monkeypatch, tmp_path
):
    from pypdf import PdfReader

    import app.config

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    scan_id = _add_scan(db_session_factory, filename="app.apk")
    _add_finding(db_session_factory, scan_id, title="Insecure WebView")

    r = client.get(f"/api/v1/scans/{scan_id}/report/export", params={"format": "pdf"})
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert "app-report.pdf" in r.headers["content-disposition"]
    pdf = r.content
    assert pdf.startswith(b"%PDF")  # magic - never a silent empty file
    assert len(pdf) > 1000  # non-trivial size

    # Section-heading extraction gate (contract-style e2e, headless):
    reader = PdfReader(io.BytesIO(pdf))
    text = "\n".join(page.extract_text() or "" for page in reader.pages)
    text = " ".join(text.split())  # normalize extraction whitespace
    assert "MASA security report" in text
    assert "Executive summary" in text
    assert "Insecure WebView" in text
    assert "WebView.java:42" in text
    # Page numbers work on the reportlab footer (the xhtml2pdf margin-box
    # limitation that motivated the rewrite).
    assert "page 1" in text


def test_export_pdf_inline_disposition(
    client, db_session_factory, monkeypatch, tmp_path
):
    """M9 follow-up: the Report tab's live PDF preview needs an INLINE
    disposition - an iframe pointing at the export route would otherwise
    trigger the attachment download instead of rendering. The download
    anchors keep the attachment default (asserted by the sibling tests)."""
    import app.config

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    scan_id = _add_scan(db_session_factory, filename="app.apk")
    _add_finding(db_session_factory, scan_id, title="Insecure WebView")

    r = client.get(
        f"/api/v1/scans/{scan_id}/report/export",
        params={"format": "pdf", "inline": "1"},
    )
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.headers["content-disposition"].startswith("inline;")
    assert "app-report.pdf" in r.headers["content-disposition"]
    assert r.content.startswith(b"%PDF")
    # This scan has NO ai_summary - the PDF must render the deterministic
    # no-AI executive summary (the export never depends on a model).
    from pypdf import PdfReader

    text = " ".join(
        (page.extract_text() or "") for page in PdfReader(io.BytesIO(r.content)).pages
    )
    assert "automated static assessment" in " ".join(text.split())

    # The md export honors the flag too (same route, harmless parity).
    r = client.get(
        f"/api/v1/scans/{scan_id}/report/export",
        params={"format": "md", "inline": "1"},
    )
    assert r.headers["content-disposition"].startswith("inline;")


def test_export_pdf_render_failure_is_500(
    client, db_session_factory, monkeypatch, tmp_path
):
    import app.config
    from app.api.routes import scans as routes

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    scan_id = _add_scan(db_session_factory)

    def boom(body, *, stem):
        raise report_pdf.ReportPdfError("PDF render failed: engine down")

    monkeypatch.setattr(routes.report_pdf, "render_pdf", boom)
    r = client.get(f"/api/v1/scans/{scan_id}/report/export", params={"format": "pdf"})
    assert r.status_code == 500
    assert "engine down" in r.json()["detail"]


def test_export_guards(client, db_session_factory):
    assert (
        client.get("/api/v1/scans/999999/report/export", params={"format": "md"}).status_code
        == 404
    )
    scan_id = _add_scan(db_session_factory, status="queued")
    r = client.get(f"/api/v1/scans/{scan_id}/report/export", params={"format": "md"})
    assert r.status_code == 409
    # unknown format -> clean 400 (the project's manual-validation style)
    scan_id = _add_scan(db_session_factory)
    r = client.get(f"/api/v1/scans/{scan_id}/report/export", params={"format": "docx"})
    assert r.status_code == 400
    assert "unknown export format" in r.json()["detail"]


# ---- render_pdf bounds (the Phase C contract) -------------------------------


def test_render_pdf_rejects_invalid_output(monkeypatch):
    monkeypatch.setattr(
        report_pdf, "_render_bounded", lambda fragment, stem, meta=None: b""
    )
    try:
        report_pdf.render_pdf("# MASA security report", stem="app")
    except report_pdf.ReportPdfError as exc:
        assert "invalid or empty" in str(exc)
    else:  # pragma: no cover - the gate must raise
        raise AssertionError("empty render must raise, never return silently")


def test_render_pdf_size_cap(monkeypatch):
    import app.config

    monkeypatch.setattr(app.config.settings, "report_pdf_max_html_bytes", 32)
    try:
        report_pdf.render_pdf("# MASA security report" * 20, stem="app")
    except report_pdf.ReportPdfError as exc:
        assert "too large" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("oversized render must raise")


# ---- markdown -> flowables (the reportlab template) -------------------------


def test_severity_chips_and_flowables():
    fragment = report_pdf.markdown_fragment(
        "## Findings\n\n- **[HIGH] Insecure WebView** - `com/foo/WebView.java:42`\n"
    )
    assert "<strong>[HIGH]" in fragment

    chipped = report_pdf._severity_chips(fragment)
    # The chip is a colored reportlab markup tag; the title stays bold after.
    # High is RED (the conventional severity palette - owner direction);
    # medium inherits the old high's amber; low is green.
    assert 'backColor="#fbe9e8"' in chipped
    assert 'color="#b3261e"' in chipped
    assert "<b>Insecure WebView</b>" in chipped
    assert "[HIGH]" not in chipped  # the bracket is fully replaced

    low = report_pdf._severity_chips(
        report_pdf.markdown_fragment(
            "## Findings\n\n- **[LOW] Hardcoded key** - `com/foo/Keys.java:9`\n"
        )
    )
    assert 'backColor="#e7f3ec"' in low
    assert 'color="#1e7a46"' in low
    assert "<b>Hardcoded key</b>" in low

    flowables = report_pdf._flowables_for(fragment, width=500)
    assert flowables  # headings/lists render to at least one flowable


def test_chip_separates_severity_from_title():
    """The chip and the title keep their space in the RENDERED text - the
    ``_text`` whitespace handling must not glue them (review catch)."""
    from pypdf import PdfReader

    fragment = report_pdf.markdown_fragment(
        "## Findings\n\n- **[HIGH] Insecure WebView** - `com/foo/WebView.java:42`\n"
    )
    pdf = report_pdf._build_doc(fragment, stem="app")
    text = " ".join(
        (page.extract_text() or "") for page in PdfReader(io.BytesIO(pdf)).pages
    )
    assert "HIGH Insecure WebView" in " ".join(text.split())


def test_font_registration_falls_back_to_helvetica(tmp_path, monkeypatch):
    import app.config

    # Missing font file -> Helvetica (never a crash).
    monkeypatch.setattr(
        app.config.settings, "report_font_path", tmp_path / "no-such.ttf"
    )
    assert report_pdf._register_font() == "Helvetica"
    # A corrupt font file -> Helvetica too (register raises, caught).
    fake = tmp_path / "broken.ttf"
    fake.write_bytes(b"definitely not a ttf")
    monkeypatch.setattr(app.config.settings, "report_font_path", fake)
    assert report_pdf._register_font() == "Helvetica"
    # The DejaVu "MasaReport" family branch is exercised in the image (Phase
    # E containerized e2e) - no real TTF is available on the host.


def test_wordmark_data_is_vendored_and_render_ready():
    """The wordmark module (scripts/sync_wordmark.py output) carries the
    vector logo paths + a decodable raster - the PDF cover draws the REAL
    MASA brand, not a text approximation."""
    import base64 as _b64
    import io as _io
    import re

    from PIL import Image

    from app.analysis import wordmark_data

    assert wordmark_data.VIEWBOX_W > 0 and wordmark_data.VIEWBOX_H > 0
    assert len(wordmark_data.PATHS) >= 10  # the logo's facets survive
    # Staleness guard: the vendored data must match the live SVG - edit the
    # asset and re-run scripts/sync_wordmark.py (the MASTG sync precedent).
    import hashlib

    svg = (
        Path(__file__).resolve().parents[2]
        / "frontend"
        / "src"
        / "assets"
        / "masa-wordmark.svg"
    )
    assert svg.is_file(), "wordmark SVG missing"
    live_sha = hashlib.sha256(svg.read_bytes()).hexdigest()
    assert wordmark_data.SVG_SHA256 == live_sha, (
        "wordmark_data.py is stale - re-run scripts/sync_wordmark.py"
    )
    for d, fill in wordmark_data.PATHS:
        assert d and fill.startswith("#") and len(fill) == 7
        assert set(re.findall(r"[A-Za-z]", d)) <= set("MLHVZ")
    r = wordmark_data.RASTER
    assert r["w"] > 0 and r["h"] > 0
    img = Image.open(_io.BytesIO(_b64.b64decode(r["png_b64"])))
    assert img.format == "PNG"


def test_wordmark_drawing_builds_and_paths_parse():
    """The vendored paths parse into reportlab Paths (the M/L/H/V/Z
    subset) and the Drawing assembles - the cover's vector logo mark."""
    art, scale = report_pdf._wordmark_art(height=50)
    assert art.width > 0 and art.height == 50
    # The drawing keeps the SVG's aspect: width = height * (W / H).
    expected_w = 50 * report_pdf.wordmark_data.VIEWBOX_W / report_pdf.wordmark_data.VIEWBOX_H
    assert abs(art.width - expected_w) < 1e-9
    assert abs(scale - 50 / report_pdf.wordmark_data.VIEWBOX_H) < 1e-9
    # Every vendored path parses into a reportlab Path in the group.
    assert len(art.contents) == 1  # the logo Group
    group = art.contents[0]
    assert len(group.contents) == len(report_pdf.wordmark_data.PATHS)


def test_wordmark_failure_falls_back_to_text(monkeypatch, capsys):
    """A bad vendored raster never crashes the cover - the text wordmark
    takes over (the never-a-crash degradation contract)."""

    def _boom(*args, **kwargs):
        raise ValueError("corrupt raster")

    monkeypatch.setattr(report_pdf, "_draw_wordmark", _boom)
    body = (
        "# MASA security report\n\n"
        "- **App:** app.apk (android)\n\n"
        "- **Security score:** 50/100 - Medium security (CVSS 4.0 · risk "
        "50/100 · Medium)\n\n"
        "## Severity breakdown\n\n- **high:** 1\n"
    )
    pdf = report_pdf.render_pdf(body, stem="app")
    assert pdf.startswith(b"%PDF")
    from pypdf import PdfReader

    text = " ".join(
        (page.extract_text() or "") for page in PdfReader(io.BytesIO(pdf)).pages
    )
    assert "MASA SECURITY ASSESSMENT" in text  # the text fallback


def test_cover_meta_parses_header_and_breakdown():
    """The cover derives its facts from the assembled body's own header +
    severity breakdown lines (one body, two media - no parallel assembly)."""
    meta = report_pdf._cover_meta(
        "# MASA security report\n\n"
        "- **App:** InsecureBankv2.apk (android)\n"
        "- **Analyzed:** 2026-08-12 12:36 UTC\n"
        "- **Security score:** 12/100 - Low security (CVSS 4.0 · risk "
        "88/100 · High)\n"
        "- **Package:** com.android.insecurebankv2\n\n"
        "## Severity breakdown\n\n"
        "- **high:** 10\n- **medium:** 467\n- **low:** 2\n- **info:** 43\n"
        "- **Suppressed findings:** 1 excluded\n"
    )
    assert meta["app"] == "InsecureBankv2.apk"
    assert meta["platform"] == "android"
    assert meta["analyzed"] == "2026-08-12 12:36 UTC"
    assert meta["score"] == 12
    assert meta["risk"] == 88
    assert meta["band"] == "High"
    assert meta["identity"] == "com.android.insecurebankv2"
    assert meta["counts"] == {"high": 10, "medium": 467, "low": 2, "info": 43}
    assert meta["suppressed"] == 1


def test_cover_meta_tolerates_missing_facts():
    """A truncated / no-AI / unscoreable body still yields a clean cover - no
    field is required (the gauge shows "-" when there is no score)."""
    meta = report_pdf._cover_meta("# MASA security report\n\nNo findings.\n")
    assert meta["app"] is None
    assert meta["score"] is None
    assert meta["counts"] == {}
    assert meta["suppressed"] == 0
    # iOS identity (bundle id) parses into the same "identity" field.
    ios = report_pdf._cover_meta(
        "- **App:** app.ipa (ios)\n- **Bundle id:** com.northbank.mobile\n"
    )
    assert ios["platform"] == "ios"
    assert ios["identity"] == "com.northbank.mobile"


def test_cover_page_renders_brand_and_gauge():
    """The redesigned cover is a real page: brand band, app identity, the
    security gauge, severity boxes, and the scope footer all render (and
    their text is extractable - the contract-style gate stays headless)."""
    from pypdf import PdfReader

    body = (
        "# MASA security report\n\n"
        "- **App:** InsecureBankv2.apk (android)\n"
        "- **Analyzed:** 2026-08-12 12:36 UTC\n"
        "- **Security score:** 12/100 - Low security (CVSS 4.0 · risk "
        "88/100 · High)\n"
        "- **Package:** com.android.insecurebankv2\n\n"
        "## Executive summary\n\nCached summary.\n\n"
        "## Severity breakdown\n\n"
        "- **high:** 10\n- **medium:** 467\n- **low:** 2\n- **info:** 43\n\n"
        "## Findings\n\n- **[HIGH] Insecure WebView** - `com/foo/WebView.java:42`\n"
    )
    pdf = report_pdf.render_pdf(body, stem="InsecureBankv2")
    reader = PdfReader(io.BytesIO(pdf))
    assert len(reader.pages) >= 2  # cover + at least one body page
    text = " ".join((page.extract_text() or "") for page in reader.pages)
    text = " ".join(text.split())
    # The brand band draws the REAL wordmark: the raster "MASA" text is
    # embedded as an image on page 1 (vector logo paths are not extractable
    # text - the image presence IS the contract gate here).
    page1_images = list(reader.pages[0].images)
    assert len(page1_images) == 1
    assert page1_images[0].name.endswith(".png")
    # Cover identity
    assert "InsecureBankv2.apk" in text
    assert "ANDROID" in text
    assert "com.android.insecurebankv2" in text
    # Gauge facts + severity boxes
    assert "12" in text
    assert "CVSS 4.0 · risk 88/100" in text
    assert "HIGH" in text
    assert "MEDIUM" in text
    # Body still renders on page 2+
    assert "Executive summary" in text
    assert "Insecure WebView" in text
    assert "page 1" in text


def test_h3_headings_are_severity_colored():
    """The Findings section's h3 group headings render with a severity left
    bar + color (High red / Third-party deep-emerald) - the
    scan-at-a-glance improvement. Asserted on the rendered Paragraph style,
    not pixels."""
    fragment = report_pdf.markdown_fragment(
        "### High (7) - app-owned\n\n### Third-party library findings (485)\n"
    )
    flowables = report_pdf._flowables_for(fragment, width=500)
    tables = [f for f in flowables if f.__class__.__name__ == "Table"]
    assert len(tables) == 2
    from reportlab.lib.colors import HexColor

    colors = [
        table._cellvalues[0][0].style.textColor for table in tables
    ]
    # High heading -> RED chip foreground; Third-party -> deep emerald.
    assert colors[0] == HexColor("#b3261e")
    assert colors[1] == HexColor("#017452")

    green = report_pdf._flowables_for(
        report_pdf.markdown_fragment("### Low (2) - app-owned\n"), width=500
    )
    gtables = [f for f in green if f.__class__.__name__ == "Table"]
    assert gtables
    assert gtables[0]._cellvalues[0][0].style.textColor == HexColor("#1e7a46")


# ---- cache-first assembly (decision 7) --------------------------------------


def test_report_cache_recomputes_on_input_change(
    client, db_session_factory, monkeypatch, tmp_path
):
    import app.config

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    scan_id = _add_scan(db_session_factory)
    _add_finding(db_session_factory, scan_id, title="First title")

    first = client.get(f"/api/v1/scans/{scan_id}/report").json()["markdown"]
    assert "First title" in first
    assert report.report_cache_path(scan_id).is_file()  # body was cached

    # A regenerate-style change (new ai_summary) must recompute, not serve
    # the stale cached body.
    with db_session_factory() as session:
        scan = session.get(Scan, scan_id)
        scan.ai_summary = "Fresh executive summary."
        session.commit()
    second = client.get(f"/api/v1/scans/{scan_id}/report").json()["markdown"]
    assert "Fresh executive summary." in second

    # A suppress toggle changes the findings set -> recompute too.
    with db_session_factory() as session:
        finding = session.query(Finding).filter(Finding.scan_id == scan_id).first()
        finding.suppressed = True
        session.commit()
    third = client.get(f"/api/v1/scans/{scan_id}/report").json()["markdown"]
    assert "First title" not in third
