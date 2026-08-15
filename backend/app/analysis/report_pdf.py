"""M9 report export - branded PDF via reportlab platypus (BSD-3-Clause).

Phase C of M9 (docs/progress/M9.md): the report exports as Markdown (the
assembled body itself) and as a branded PDF. The PDF path renders the SAME
assembled markdown body - python-markdown (BSD-3-Clause) converts it to a
constrained HTML fragment (headings / single-level lists / blockquotes /
code / bold / italic), and **reportlab platypus** (BSD-3-Clause) lays that
fragment out directly (Paragraphs, ListFlowable, one-cell Tables for the
blockquote rule and the severity h3 left bars). One body, two media -
never a parallel assembly.

WHY reportlab and not xhtml2pdf (owner decision, Aug 12 2026 follow-up):
the Phase C audit (the project's own ``pip-licenses`` check) found
xhtml2pdf 0.2.17's transitive tree IMPORTS **LGPL python-bidi** (eagerly,
for RTL text shaping) and **LGPLv3 svglib** (lazy, for SVG images) - a
violation of MASA's hard posture that all imported libraries are permissive
(MIT/Apache-2.0/BSD). WeasyPrint's tree has the same problem (pyphen is
LGPL/MPL). reportlab is BSD-3-Clause, was already a transitive, and
rendering the constrained fragment directly (instead of through a full HTML
engine) keeps the branded design, makes **page numbers actually work** (a
footer callback - xhtml2pdf's @page margin boxes couldn't), and drops the
LGPL pair + the PAdES (pyHanko) bloat entirely. Severity chips are colored
boxes with the conventional severity palette (High red · Medium amber ·
Info slate - owner direction, deliberately distinct from the frontend
dashboard's brand palette; see below), mono ``file:line``, DejaVu
Sans TTF family for Unicode text (``MASA_REPORT_FONT`` + its
-Bold/-Oblique/-Mono siblings; Helvetica fallback when missing - never a
crash).LAYOUT (redesigned Aug 12, 2026 - the manual-review follow-up):
- **Cover page**: a deep-emerald brand band (the REAL MASA wordmark
  rendered from the SVG asset - ``scripts/sync_wordmark.py`` vendors
  ``frontend/src/assets/masa-wordmark.svg`` into ``wordmark_data.py``:
  vector logo paths + the white raster "MASA" text, cropped to the SVG's
  pattern-visible region; the same file the TopBar renders; app filename +
  platform chip), a canvas-drawn **security gauge** (the frontend
  SecurityGauge's discrete CVSS 4.0 band colors), the three severity count
  boxes, package/bundle + analyzed-date meta, and a scope/disclaimer
  footer. The cover derives its facts by parsing the assembled body's own
  header + breakdown lines (machine-generated, stable vocabulary) - one
  body, two media, no parallel assembly.
- **Body pages**: a running header (emerald rule + report identity) and the
  page-number footer; h1/h2 section headings are PLAIN dark text (the green
  underline rule was removed Aug 14 - "remove it for cleaner report"), and
  **h3 headings are severity-colored** (High red / Medium amber / Info
  slate / Third-party deep-emerald) with an emerald left bar so the
  Findings section scans at a glance.
- The DejaVu **family** is registered (regular/bold/oblique/mono), so the
  fragment's ``<b>/<i>`` render with real weights instead of fake-bold.

SEVERITY PALETTE (owner direction, Aug 12 2026 - the PDF follow-up): the
report uses the conventional severity colors - **High red · Warning amber ·
Info slate** (the low band was dropped and medium renamed warning Aug 15,
2026) - which is deliberately NOT the frontend dashboard palette
(amber/steel/moss/gray); the exported artifact reads like a
standard pentest deliverable while the app keeps its brand palette.

Bounded render (the Phase C contract): the HTML fragment is size-capped
(``MASA_REPORT_PDF_MAX_HTML_BYTES``) and the render runs under a hard
deadline (``MASA_REPORT_PDF_TIMEOUT_SECONDS``) on a worker thread - a stuck
engine can never block the API worker forever. Output is sanity-gated:
``%PDF`` magic + a non-trivial size - a silent empty file is a hard error,
never a 200.
"""
from __future__ import annotations

import base64
import io
import math
import re
import threading
from functools import partial
from html.parser import HTMLParser
from pathlib import Path

import markdown as md

from app.analysis import wordmark_data
from app.config import settings

# reportlab is imported lazily inside the render path - the markdown export
# never pays for the PDF engine's import.

# Severity chip palette - OWNER-DIRECTED conventional severity colors
# (Aug 12, 2026 PDF follow-up): High red · Warning amber · Info slate (the
# low band was dropped and medium renamed warning Aug 15, 2026).
# Deliberately distinct from the frontend dashboard palette
# (amber/steel/moss/gray) so the exported report reads like a standard
# pentest deliverable. Tinted background + dark text (the .sev-tag
# contract), high-contrast pairs chosen for print.
_SEVERITY_STYLES = {
    "high": ("#fbe9e8", "#b3261e"),
    "warning": ("#f9ead7", "#a85f14"),
    "info": ("#eceef0", "#5f6b76"),
    "other": ("#f1f1ef", "#6c747a"),
}

# Brand accents (the SecurityGauge / dock palette).
_ACCENT = "#23cf92"
_ACCENT_DEEP = "#017452"
_HEADING = "#14171a"
_BODY = "#1b2025"
_MUTED = "#6c747a"
_BQ_BG = "#f4fbf8"
_CODE_BG = "#f4f4f2"

# The frontend SecurityGauge's discrete arc colors (risk-index band of the
# underlying RISK): high risk = crimson · medium = amber · none = bright
# emerald (the banded model only produces 0, 40-69 or 70-99, so the old
# 1-39 low band is unreachable and gone). Used by the cover gauge so the
# PDF and the dashboard never disagree about the posture.
_GAUGE_BAND = {
    "High": "#c1554a",
    "Medium": "#d98e3e",
    "None": "#1ed394",
}
_GAUGE_LABEL = {
    "High": "Low security",
    "Medium": "Medium security",
    "None": "Excellent security",
}

# h3 heading colors (the Findings section's severity groups) - the chip
# foregrounds (High red · Warning amber · Info slate), plus a deep emerald
# for the third-party roll-up heading.
_SEV_TEXT = {
    "high": "#b3261e",
    "warning": "#a85f14",
    "info": "#5f6b76",
    "other": "#6c747a",
    "third": "#017452",
}
_H3_SEV_RE = re.compile(r"^(High|Warning|Info|Other)\b")
_THIRD_PARTY_RE = re.compile(r"^Third[- ]party\b", re.IGNORECASE)

# The assembled body emits findings as ``- **[HIGH] Title**``; after
# markdown->HTML that is ``<li><strong>[HIGH] Title</strong></li>``. Swap the
# leading bracket (and the space after it) for a real colored chip (the
# plan's "severity chips as colored boxes") while the rest of the title
# stays bold. The ``<font backColor=...>`` tag is passed straight through to
# reportlab's Paragraph markup by the fragment parser. Matches only the
# body's exact shape - iOS "Import-table finding [HIGH]" stays plain text.
_CHIP_RE = re.compile(r"<strong>\[(HIGH|WARNING|INFO|OTHER)\] ?")


def markdown_fragment(body: str) -> str:
    """The assembled body as an HTML fragment (python-markdown, BSD-3-Clause).

    The body is machine-generated with a fixed vocabulary (headings, bullet
    lists, blockquotes, inline code/bold/italic) - plain ``markdown()`` with
    no extensions is exactly its subset.
    """
    return md.markdown(body)


def _severity_chips(fragment: str) -> str:
    def _chip(match: re.Match) -> str:
        sev = match.group(1).lower()
        bg, fg = _SEVERITY_STYLES[sev]
        return (
            f'<font backColor="{bg}" color="{fg}"><b>{match.group(1)}</b></font> <b>'
        )

    # The chip regex consumes the matching ``<strong>`` opener; normalize the
    # remaining ``<strong>/</strong>`` (other bold spans) to reportlab's
    # ``<b>`` form so the fragment is consistent for the paragraph parser.
    return _CHIP_RE.sub(_chip, fragment).replace("<strong>", "<b>").replace(
        "</strong>", "</b>"
    )


class ReportPdfError(Exception):
    """A bounded render failed (timeout, size cap, invalid output, engine
    error) - the export route maps this to a 500 with the human reason.
    Never a silent empty file."""


# ---- font -------------------------------------------------------------------
# The bundled DejaVu Sans family (fonts-dejavu-core in the image) registered
# once per process: regular + Bold + Oblique + the Mono face, so the
# fragment's ``<b>/<i>/<code>`` render with real variants. Helvetica (and
# its built-in family) when the files are missing or unreadable - the
# ASCII/Latin-1 subset of the body still renders, never a crash.
_FONT_NAME: str | None = None
_BOLD_NAME: str | None = None
_MONO_NAME: str | None = None
_FONT_LOCK = threading.Lock()


def _register_font() -> str:
    """Register ``MASA_REPORT_FONT`` + its sibling variants and return the
    regular family name, or \"Helvetica\" when the file is missing/unreadable
    (never raises). Also registers the bold/italic/mono siblings and the
    family mapping so ``<b>/<i>`` get real glyphs."""
    global _FONT_NAME, _BOLD_NAME, _MONO_NAME
    path = Path(settings.report_font_path)
    if not path.is_file():
        _FONT_NAME = _BOLD_NAME = _MONO_NAME = None
        return "Helvetica"
    try:
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont

        pdfmetrics.registerFont(TTFont("MasaReport", str(path)))
        _FONT_NAME = "MasaReport"
        # DejaVu Sans ships -Bold/-Oblique/-BoldOblique beside the regular
        # file; register whatever exists so Paragraph <b>/<i> are real.
        family = {"normal": "MasaReport", "bold": "MasaReport",
                  "italic": "MasaReport", "boldItalic": "MasaReport"}
        for suffix, name, key in (
            ("-Bold", "MasaReport-Bold", "bold"),
            ("-Oblique", "MasaReport-Oblique", "italic"),
            ("-BoldOblique", "MasaReport-BoldOblique", "boldItalic"),
        ):
            variant = path.with_name(path.stem + suffix + path.suffix)
            if variant.is_file():
                try:
                    pdfmetrics.registerFont(TTFont(name, str(variant)))
                    family[key] = name
                except Exception:  # noqa: BLE001 - a bad variant degrades
                    pass
        pdfmetrics.registerFontFamily("MasaReport", **family)
        _BOLD_NAME = family["bold"] if family["bold"] != "MasaReport" else None
        # Mono face for file:line / code spans (DejaVuSansMono alongside).
        mono = path.with_name("DejaVuSansMono.ttf")
        if mono.is_file():
            try:
                pdfmetrics.registerFont(TTFont("MasaMono", str(mono)))
                _MONO_NAME = "MasaMono"
            except Exception:  # noqa: BLE001
                pass
        return _FONT_NAME
    except Exception:  # noqa: BLE001 - a bad font degrades to Helvetica
        _FONT_NAME = _BOLD_NAME = _MONO_NAME = None
        return "Helvetica"


def _font_name() -> str:
    global _FONT_NAME
    if _FONT_NAME is None:
        with _FONT_LOCK:
            if _FONT_NAME is None:
                _FONT_NAME = _register_font()
    return _FONT_NAME


def _bold_name() -> str:
    """The registered bold variant (the regular face when no bold sibling
    exists, Helvetica-Bold only when fully on the fallback) - never mix a
    base-14 face into a DejaVu document (review catch)."""
    _font_name()  # ensure registration ran
    return _BOLD_NAME or _FONT_NAME or "Helvetica-Bold"


def _mono_name() -> str:
    _font_name()
    return _MONO_NAME or "Courier"


# ---- fragment -> reportlab flowables ----------------------------------------


def _rl_escape(text: str) -> str:
    """Escape text for reportlab's Paragraph markup (only &, <, > matter)."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _font_tag(attrs: list[tuple[str, str | None]]) -> str:
    """Pass a ``<font ...>`` tag (the injected severity chips) through to
    reportlab markup verbatim: ``<font backColor=... color=...>``."""
    parts = []
    for key, value in attrs:
        if value is not None:
            parts.append(f'{key}="{value}"')
    return f"<font {' '.join(parts)}>"


class _FlowableBuilder(HTMLParser):
    """Constrained md->HTML fragment -> reportlab flowables.

    The fragment is python-markdown's output for the report body - a fixed
    vocabulary: h1/h2/h3, single-level ul>li, p, blockquote, and the inline
    strong/em/code plus the injected chip ``<font>`` tags. Any unknown tag
    is skipped defensively (its text still flows) - the body never emits
    one, but a finding title containing markup must not crash the render.
    """

    _INLINE_OPEN = {"strong": "<b>", "em": "<i>", "b": "<b>"}
    _INLINE_CLOSE = {"strong": "</b>", "em": "</i>", "b": "</b>"}

    def __init__(self, width: float):
        super().__init__(convert_charrefs=True)
        self.width = width
        self.flowables: list = []
        self._inline: list[str] = []
        self._stack: list[str] = []
        self._mode: str | None = None  # block context: h1|h2|h3|p|li|bq
        self._list_items: list[str] = []
        self._bq_text: list[str] = []

    # ---- helpers -----------------------------------------------------------

    def _text(self, data: str) -> None:
        collapsed = re.sub(r"\s+", " ", data)
        if not collapsed:
            return
        # Drop LEADING pretty-print whitespace only (buffer empty); a space
        # BETWEEN inline tags is meaningful - the severity chips sit on
        # ``</font> <b>Title</b>``, and dropping that space would render
        # "HIGHInsecure WebView" (review catch). Ends are stripped at emit.
        if collapsed == " " and not self._inline and not self._bq_text:
            return
        if self._mode == "bq":
            self._bq_text.append(_rl_escape(collapsed))
        else:
            self._inline.append(_rl_escape(collapsed))

    def _inline_markup(self) -> str:
        return "".join(self._inline).strip()

    def _emit_paragraph(self, markup: str, style_name: str = "body") -> None:
        if not markup:
            return
        from reportlab.platypus import Paragraph

        self.flowables.append(Paragraph(markup, _styles()[style_name]))

    def _emit_heading(self, level: int) -> None:
        markup = self._inline_markup()
        self._inline.clear()
        self._stack.clear()
        if not markup:
            return
        from reportlab.lib.colors import HexColor
        from reportlab.platypus import Paragraph, Table, TableStyle

        if level == 3:
            # Severity-colored h3: High amber / Warning steel / Info gray /
            # Third-party deep-emerald (manual-review follow-up) - the
            # Findings section's severity groups scan at a glance.
            sev = None
            m = _H3_SEV_RE.match(markup)
            if m:
                sev = m.group(1).lower()
            elif _THIRD_PARTY_RE.match(markup):
                sev = "third"
            color = _SEV_TEXT.get(sev or "", _ACCENT_DEEP)
            style = _styles()["h3"].clone(f"h3-{sev or 'plain'}")
            style.textColor = HexColor(color)
            box = Table(
                [[Paragraph(markup, style)]],
                colWidths=[self.width],
                style=TableStyle(
                    [
                        ("LINEBEFORE", (0, 0), (-1, -1), 3, HexColor(color)),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                        ("TOPPADDING", (0, 0), (-1, -1), 0),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                    ]
                ),
            )
            # Owner report (Aug 14): the severity group heading was glued to
            # the first finding below - the heading is a Table, and TableStyle
            # has NO SPACEAFTER command in reportlab 4.x (silently ignored),
            # so the breathing room is set on the flowable itself (the frame
            # reads ``flowable.spaceAfter``).
            box.spaceAfter = 8
            self.flowables.append(box)
            return

        # h1/h2: PLAIN headings - no underline, no left bar (owner follow-up,
        # Aug 14: "that green underline always have no gap with the text
        # below it, maybe remove it for cleaner report"). A plain Paragraph
        # carries the section spacing natively via the style's
        # spaceBefore/spaceAfter - the old Table wrapper existed only to draw
        # the green rule, and a Table's own spacing needs the flowable-attr
        # hack (the frame reads ``flowable.spaceBefore/After``; TableStyle
        # has no such commands in reportlab 4.x).
        self.flowables.append(Paragraph(markup, _styles()[f"h{level}"]))

    def _emit_list(self) -> None:
        if not self._list_items:
            return
        from reportlab.lib.colors import HexColor
        from reportlab.platypus import ListFlowable, ListItem, Paragraph

        items = [
            ListItem(Paragraph(markup, _styles()["body"]), leftIndent=10)
            for markup in self._list_items
        ]
        self.flowables.append(
            ListFlowable(
                items,
                bulletType="bullet",
                start="\u2022",
                bulletFontName=_font_name(),
                bulletFontSize=9.5,
                bulletColor=HexColor(_ACCENT_DEEP),
                leftIndent=6,
            )
        )
        self._list_items.clear()

    def _emit_blockquote(self) -> None:
        markup = "".join(self._bq_text).strip()
        self._bq_text.clear()
        if not markup:
            return
        from reportlab.lib.colors import HexColor
        from reportlab.platypus import Paragraph, Table, TableStyle

        inner = Paragraph(markup, _styles()["quote"])
        box = Table(
            [[inner]],
            colWidths=[self.width],
            style=TableStyle(
                [
                    ("LINEBEFORE", (0, 0), (-1, -1), 3, HexColor(_ACCENT)),
                    ("BACKGROUND", (0, 0), (-1, -1), HexColor(_BQ_BG)),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            ),
        )
        # Owner report (Aug 14): a finding's explanation sat GLUED to the
        # finding bullet above and the next finding below - the blockquote is
        # a Table (own spacing, not the paragraph's), so the breathing room
        # rides on the flowable itself (the frame reads spaceBefore/After;
        # TableStyle has no such commands in reportlab 4.x). 8pt above (from
        # the finding bullet) and 12pt below (to the next finding / section)
        # keep the explanation clearly separated from what follows.
        box.spaceBefore = 8
        box.spaceAfter = 12
        self.flowables.append(box)

    # ---- HTMLParser hooks --------------------------------------------------

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in ("h1", "h2", "h3"):
            self._mode = tag
            self._inline.clear()
            self._stack.clear()
        elif tag == "li":
            self._mode = "li"
            self._inline.clear()
            self._stack.clear()
        elif tag == "ul" or tag == "ol":
            self._list_items = []
        elif tag == "blockquote":
            self._mode = "bq"
            self._bq_text = []
        elif tag == "p":
            if self._mode != "bq":
                self._mode = "p"
                self._inline.clear()
                self._stack.clear()
        elif tag == "font":
            self._stack.append("font")
            self._inline.append(_font_tag(attrs))
        elif tag == "code":
            # Mono face decided at render time (DejaVu Sans Mono in the
            # image, Courier fallback) - not a static class map.
            self._stack.append(tag)
            self._inline.append(f'<font name="{_mono_name()}">')
        elif tag in self._INLINE_OPEN:
            self._stack.append(tag)
            self._inline.append(self._INLINE_OPEN[tag])
        # unknown tags: skip, text still flows

    def handle_endtag(self, tag: str) -> None:
        if tag in ("h1", "h2", "h3"):
            self._emit_heading(int(tag[1]))
            self._mode = None
        elif tag == "li":
            self._list_items.append(self._inline_markup())
            self._inline.clear()
            self._stack.clear()
            self._mode = None
        elif tag in ("ul", "ol"):
            self._emit_list()
        elif tag == "blockquote":
            self._emit_blockquote()
            self._mode = None
        elif tag == "p":
            if self._mode == "p":
                self._emit_paragraph(self._inline_markup())
                self._inline.clear()
                self._stack.clear()
                self._mode = None
        elif tag == "font":
            if "font" in self._stack:
                self._stack.remove("font")
                self._inline.append("</font>")
        elif tag == "code":
            if "code" in self._stack:
                self._stack.remove("code")
                self._inline.append("</font>")
        elif tag in self._INLINE_CLOSE:
            if tag in self._stack:
                self._stack.remove(tag)
                self._inline.append(self._INLINE_CLOSE[tag])
        # unknown closing tags are ignored

    def handle_data(self, data: str) -> None:
        self._text(data)


def _styles() -> dict[str, object]:
    """Paragraph styles - built per render so the font family is current."""
    from reportlab.lib.colors import HexColor
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.styles import ParagraphStyle

    font = _font_name()
    # AIRY LINE SPACING (owner report: "the space between lines is too small,
    # text almost touches the line above/below"): DejaVu Sans draws tall
    # ascenders/descenders, so the old 1.42x body leading read as cramped.
    # Every face now leads at >= 1.6x with real paragraph breathing room.
    return {
        "h1": ParagraphStyle(
            "h1", fontName=font, fontSize=19, leading=24, textColor=HexColor(_HEADING),
            spaceBefore=0, spaceAfter=10, alignment=TA_LEFT,
        ),
        # h2 spaceAfter 10: the underline rule is GONE (Aug 14 follow-up -
        # "remove it for cleaner report"), so the heading's own after-space
        # is what separates it from the section body.
        "h2": ParagraphStyle(
            "h2", fontName=font, fontSize=12.5, leading=17.5, textColor=HexColor(_HEADING),
            spaceBefore=18, spaceAfter=10, alignment=TA_LEFT,
        ),
        "h3": ParagraphStyle(
            "h3", fontName=font, fontSize=10.5, leading=15.5, textColor=HexColor(_ACCENT_DEEP),
            spaceBefore=12, spaceAfter=5, alignment=TA_LEFT,
        ),
        "body": ParagraphStyle(
            "body", fontName=font, fontSize=9.5, leading=16, textColor=HexColor(_BODY),
            spaceBefore=1.5, spaceAfter=4, alignment=TA_LEFT,
        ),
        "quote": ParagraphStyle(
            "quote", fontName=font, fontSize=9, leading=14.5, textColor=HexColor("#3d444a"),
            spaceBefore=0, spaceAfter=0, alignment=TA_LEFT,
        ),
    }


def _flowables_for(fragment: str, width: float) -> list:
    """The severity-chipped fragment -> the report's flowable list."""
    builder = _FlowableBuilder(width)
    builder.feed(_severity_chips(fragment))
    builder.close()
    return builder.flowables


# ---- wordmark -------------------------------------------------------------
# The real MASA wordmark is vendored from frontend/src/assets/masa-wordmark.svg
# by scripts/sync_wordmark.py into wordmark_data.py (the M1 MASTG-vendoring
# precedent - the app image only ships backend/ + frontend/dist, so the SVG
# is parsed ONCE at sync time into a render-ready module). The vector logo
# paths use only the M/L/H/V/Z subset (no curves); the white "MASA" raster
# text is a small RGBA PNG composited onto the emerald band with mask='auto'.
# Rendering is best-effort: ANY failure (bad vendored data, reportlab issue)
# degrades to the plain text wordmark - never a crash.
_WM_TOKEN = re.compile(r"[MLHVZ]|-?\d*\.?\d+")


def _wordmark_path(d: str, scale: float):
    """Parse a vendored ``d`` (M/L/H/V/Z subset) into a reportlab Path,
    scaled and flipped to PDF y-up coordinates."""
    from reportlab.graphics.shapes import Path

    p = Path()
    tokens = _WM_TOKEN.findall(d)
    cmd = None
    x = y = 0.0
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok.isalpha():
            cmd = tok
            if cmd == "Z":
                p.closePath()
            i += 1
            continue
        num = float(tok)
        if cmd == "M":
            x, y = num, float(tokens[i + 1])
            i += 2
            p.moveTo(x * scale, (wordmark_data.VIEWBOX_H - y) * scale)
        elif cmd == "L":
            x, y = num, float(tokens[i + 1])
            i += 2
            p.lineTo(x * scale, (wordmark_data.VIEWBOX_H - y) * scale)
        elif cmd == "H":
            x = num
            i += 1
            p.lineTo(x * scale, (wordmark_data.VIEWBOX_H - y) * scale)
        elif cmd == "V":
            y = num
            i += 1
            p.lineTo(x * scale, (wordmark_data.VIEWBOX_H - y) * scale)
    return p


_WORDMARK_ART: tuple | None = None  # (drawing, scale) built lazily, shared
_WORDMARK_LOCK = threading.Lock()


def _wordmark_art(height: float) -> tuple[object, float]:
    """The vector logo mark as a reportlab Drawing sized to ``height`` pt.
    Cached (lock-guarded like ``_FONT_LOCK``) - the art is identical on
    every cover."""
    global _WORDMARK_ART
    if _WORDMARK_ART and abs(_WORDMARK_ART[1] * wordmark_data.VIEWBOX_H - height) < 0.1:
        return _WORDMARK_ART
    with _WORDMARK_LOCK:
        if _WORDMARK_ART and abs(_WORDMARK_ART[1] * wordmark_data.VIEWBOX_H - height) < 0.1:
            return _WORDMARK_ART
        from reportlab.graphics.shapes import Drawing, Group
        from reportlab.lib.colors import HexColor

        scale = height / wordmark_data.VIEWBOX_H
        drawing = Drawing(
            wordmark_data.VIEWBOX_W * scale, wordmark_data.VIEWBOX_H * scale
        )
        group = Group()
        for d, fill in wordmark_data.PATHS:
            p = _wordmark_path(d, scale)
            p.fillColor = HexColor(fill)
            p.strokeColor = None
            p.strokeWidth = 0
            group.add(p)
        drawing.add(group)
        _WORDMARK_ART = (drawing, scale)
        return _WORDMARK_ART


def _draw_wordmark(canvas, cx: float, top: float, height: float) -> None:
    """Draw the real MASA wordmark on the band: vector logo paths + the
    white "MASA" raster text, centered on ``cx`` with its top at ``top``.
    Raises on any failure - the cover falls back to the text wordmark."""
    from reportlab.graphics import renderPDF
    from reportlab.lib.utils import ImageReader

    art, scale = _wordmark_art(height)
    x0 = cx - wordmark_data.VIEWBOX_W * scale / 2
    y0 = top - wordmark_data.VIEWBOX_H * scale
    renderPDF.draw(art, canvas, x0, y0)
    r = wordmark_data.RASTER
    img = ImageReader(io.BytesIO(base64.b64decode(r["png_b64"])))
    canvas.drawImage(
        img,
        x0 + r["x"] * scale,
        y0 + (wordmark_data.VIEWBOX_H - r["y"] - r["h"]) * scale,
        r["w"] * scale,
        r["h"] * scale,
        mask="auto",
        preserveAspectRatio=False,
    )


# ---- cover page --------------------------------------------------------------
# The cover facts are parsed from the assembled body's own header + severity
# breakdown lines (machine-generated, stable vocabulary) - the report never
# assembles a parallel structure for the PDF (one body, two media).
_COVER_RE = {
    "app": re.compile(r"^\- \*\*App:\*\* (.+?) \((\w+)\)\s*$", re.M),
    "analyzed": re.compile(r"^\- \*\*Analyzed:\*\* (.+)\s*$", re.M),
    "score": re.compile(
        r"^\- \*\*Security score:\*\* (\d+)/100 - (.+?) \(risk "
        r"(\d+)/100 · (\w+)\)\s*$",
        re.M,
    ),
    "package": re.compile(r"^\- \*\*Package:\*\* (\S+)\s*$", re.M),
    "bundle": re.compile(r"^\- \*\*Bundle id:\*\* (\S+)\s*$", re.M),
    "suppressed": re.compile(r"^\- \*\*Suppressed findings:\*\* (\d+)", re.M),
}
_COUNT_RE = re.compile(r"^\- \*\*(high|warning|info):\*\* (\d+)\s*$", re.M)


def _cover_meta(body: str) -> dict:
    """Cover facts parsed from the assembled body - best-effort: every field
    is optional, so a truncated/no-AI/odd body still renders a clean cover
    with whatever it carries (gauge shows \"-\" when unscoreable)."""
    meta: dict = {
        "app": None, "platform": None, "analyzed": None,
        "score": None, "risk": None, "band": None, "label": None,
        "identity": None, "counts": {}, "suppressed": 0,
    }
    m = _COVER_RE["app"].search(body)
    if m:
        meta["app"], meta["platform"] = m.group(1).strip(), m.group(2).lower()
    m = _COVER_RE["analyzed"].search(body)
    if m:
        meta["analyzed"] = m.group(1).strip()
    m = _COVER_RE["score"].search(body)
    if m:
        meta["score"] = int(m.group(1))
        meta["label"] = m.group(2).strip()
        meta["risk"] = int(m.group(3))
        meta["band"] = m.group(4).capitalize()
    m = _COVER_RE["package"].search(body) or _COVER_RE["bundle"].search(body)
    if m:
        meta["identity"] = m.group(1).strip()
    for m in _COUNT_RE.finditer(body):
        meta["counts"][m.group(1)] = int(m.group(2))
    m = _COVER_RE["suppressed"].search(body)
    if m:
        meta["suppressed"] = int(m.group(1))
    return meta


def _draw_gauge(canvas, cx: float, cy: float, r: float, score, risk) -> None:
    """A 180° security arc (the frontend SecurityGauge contract): track +
    band-colored fill proportional to the score, score text in the bowl."""
    from reportlab.lib.colors import HexColor

    clamped = 0 if score is None else max(0, min(100, score))
    risk = 100 - clamped if risk is None else risk
    band = "High" if risk >= 70 else "Medium" if risk >= 40 else "None"
    color = _GAUGE_BAND[band]

    def _stroke(frac: float, stroke: str, width: float) -> None:
        if frac <= 0:
            return
        pts = []
        for i in range(81):
            # 0° (3 o'clock) -> 180° (9 o'clock) over the top (12 o'clock).
            ang = math.pi * (1 - frac * i / 80)
            pts.append((cx + r * math.cos(ang), cy + r * math.sin(ang)))
        canvas.saveState()
        canvas.setStrokeColor(HexColor(stroke))
        canvas.setLineWidth(width)
        canvas.setLineCap(1)  # round caps, like the SVG strokeLinecap
        p = canvas.beginPath()
        p.moveTo(*pts[0])
        for x, y in pts[1:]:
            p.lineTo(x, y)
        canvas.drawPath(p, stroke=1, fill=0)
        canvas.restoreState()

    _stroke(1.0, "#e8e6df", 12)  # track (bone)
    _stroke(clamped / 100, color, 12)  # score fill
    # Score centered in the bowl - below the curve, inside the arc.
    canvas.saveState()
    canvas.setFont(_bold_name(), 30)
    canvas.setFillColor(HexColor(color))
    canvas.drawCentredString(cx, cy - 2, str(score) if score is not None else "-")
    canvas.setFont(_font_name(), 11)
    canvas.setFillColor(HexColor(_MUTED))
    canvas.drawCentredString(cx, cy - 26, "/100")
    canvas.setFont(_font_name(), 9.5)
    canvas.setFillColor(HexColor(color))
    canvas.drawCentredString(
        cx, cy - 46,
        _GAUGE_LABEL[band] if score is not None else "No security score",
    )
    if score is not None:
        canvas.setFont(_font_name(), 8)
        canvas.setFillColor(HexColor(_MUTED))
        canvas.drawCentredString(cx, cy - 62, f"risk {risk}/100 · {band}")
    canvas.restoreState()


def _draw_wrapped_centered(canvas, text: str, cx: float, top: float,
                           font: str, size: float, *, max_width: float,
                           leading: float) -> None:
    """Draw ``text`` as centered wrapped lines starting at ``top`` (each
    line ``leading`` pt below the previous). Word-wrap at ``max_width`` -
    the report cover's scope footnote is too long for one line and a bare
    ``drawCentredString`` would clip at both page edges (Aug 14 owner
    report). Returns nothing; the caller owns the font/color state.
    """
    lines: list[str] = []
    current = ""
    for word in text.split():
        trial = (current + " " + word).strip()
        if not current or canvas.stringWidth(trial, font, size) <= max_width:
            current = trial
        else:
            lines.append(current)
            current = word
    if current:
        lines.append(current)
    y = top
    for line in lines:
        canvas.drawCentredString(cx, y, line)
        y -= leading


def _draw_chip(canvas, x: float, y: float, w: float, h: float, label: str,
               count: int, bg: str, fg: str) -> None:
    """A severity summary box on the cover (count + label on a tint)."""
    from reportlab.lib.colors import HexColor

    canvas.saveState()
    canvas.setFillColor(HexColor(bg))
    canvas.roundRect(x, y, w, h, 6, stroke=0, fill=1)
    canvas.setFillColor(HexColor(fg))
    canvas.setFont(_bold_name(), 22)
    canvas.drawCentredString(x + w / 2, y + h - 30, str(count))
    canvas.setFont(_font_name(), 8)
    canvas.drawCentredString(x + w / 2, y + 10, label.upper())
    canvas.restoreState()


def _cover_canvas(meta: dict, canvas, doc) -> None:
    """The brand cover page - drawn on the first page canvas (absolute page
    coords). Band, title, gauge, severity boxes, meta row, footer."""
    from reportlab.lib.colors import HexColor

    W, H = doc.pagesize
    stem = meta.get("stem") or "security report"
    # ---- brand band --------------------------------------------------------
    canvas.saveState()
    canvas.setFillColor(HexColor(_ACCENT_DEEP))
    canvas.rect(0, H - 172, W, 172, stroke=0, fill=1)
    canvas.setFillColor(HexColor(_ACCENT))
    canvas.rect(0, H - 176, W, 4, stroke=0, fill=1)
    canvas.setFillColor(HexColor("#ffffff"))
    canvas.setFont(_bold_name(), 11)
    try:
        # The REAL MASA wordmark (SVG-derived vector logo + white raster
        # text) - a vendored-data/reportlab failure degrades to the plain
        # text wordmark, never a crash.
        _draw_wordmark(canvas, W / 2, H - 34, 50)
    except Exception:  # noqa: BLE001 - bad vendored data degrades to text
        canvas.drawCentredString(W / 2, H - 50, "MASA SECURITY ASSESSMENT")
    app = meta.get("app") or stem
    if len(app) > 40:
        app = app[:38] + "…"  # long stems stay inside the band
    canvas.setFont(_font_name(), 26)
    canvas.drawCentredString(W / 2, H - 114, app)
    platform = (meta.get("platform") or "").upper()
    if platform:
        # The platform chip sits BELOW the app title with a real gap (owner
        # report: the title was nearly touching the chip).
        canvas.setFont(_bold_name(), 8.5)
        canvas.setFillColor(HexColor(_ACCENT_DEEP))
        canvas.roundRect(W / 2 - 34, H - 152, 68, 18, 4, stroke=0, fill=1)
        canvas.setFillColor(HexColor("#ffffff"))
        canvas.drawCentredString(W / 2, H - 144, platform)
    canvas.setFont(_font_name(), 9)
    canvas.setFillColor(HexColor("#d8f5ea"))
    canvas.drawCentredString(W / 2, H - 166, "Automated static security assessment")
    canvas.restoreState()

    # ---- gauge --------------------------------------------------------------
    _draw_gauge(canvas, W / 2, H - 400, 84, meta.get("score"), meta.get("risk"))

    # ---- severity boxes ------------------------------------------------------
    counts = meta.get("counts") or {}
    labels = ("high", "warning", "info")
    box_w, gap = 118, 14
    total_w = len(labels) * box_w + (len(labels) - 1) * gap
    x0 = (W - total_w) / 2
    for i, sev in enumerate(labels):
        bg, fg = _SEVERITY_STYLES[sev]
        _draw_chip(
            canvas, x0 + i * (box_w + gap), H - 530, box_w, 58,
            sev, counts.get(sev, 0), bg, fg,
        )

    # ---- meta row + suppressed note ------------------------------------------
    canvas.saveState()
    canvas.setFont(_font_name(), 9.5)
    canvas.setFillColor(HexColor(_MUTED))
    identity = meta.get("identity")
    analyzed = meta.get("analyzed")
    parts = [
        p
        for p in (identity and f"ID: {identity}", analyzed and f"Analyzed: {analyzed}")
        if p
    ]
    canvas.drawCentredString(W / 2, H - 570, " · ".join(parts))
    if meta.get("suppressed"):
        canvas.setFont(_font_name(), 8.5)
        canvas.setFillColor(HexColor("#a85f14"))
        canvas.drawCentredString(
            W / 2, H - 592,
            f"{meta['suppressed']} finding(s) suppressed as false positives - "
            "excluded from scoring and the body above",
        )
    # Scope footnote - the honest static-only boundary, on the cover too.
    # Wrapped into centered lines: a single drawCentredString would overflow
    # the page width and get CLIPPED at both edges (owner report, Aug 14:
    # the cover showed "...c analysis of the uploaded artifact ..." with the
    # start and end cut off).
    canvas.setFont(_font_name(), 8)
    canvas.setFillColor(HexColor(_MUTED))
    _draw_wrapped_centered(
        canvas,
        "Scope: automated static analysis of the uploaded artifact (manifest, "
        "decompiled code, secrets scan, dependency inventory, binary profile). "
        "No dynamic, device, or emulator testing was performed.",
        W / 2,
        96,
        _font_name(),
        8,
        max_width=W - 2 * doc.leftMargin,
        leading=11,
    )
    canvas.restoreState()

    # ---- cover footer --------------------------------------------------------
    canvas.saveState()
    canvas.setFont(_font_name(), 7.5)
    canvas.setFillColor(HexColor(_MUTED))
    canvas.drawString(doc.leftMargin, 0.8 * 72, "MASA security report — Confidential")
    canvas.drawRightString(W - doc.rightMargin, 0.8 * 72, "page 1")
    canvas.restoreState()


# ---- running header + footer for body pages ----------------------------------


def _body_page(canvas, doc) -> None:
    """Body pages: a thin emerald running header (report identity) above the
    existing brand + page-number footer. The cover has its own frame."""
    from reportlab.lib.colors import HexColor

    W, H = doc.pagesize
    canvas.saveState()
    # Running header rule
    canvas.setStrokeColor(HexColor(_ACCENT))
    canvas.setLineWidth(1.2)
    canvas.line(
        doc.leftMargin,
        H - doc.topMargin + 14,
        W - doc.rightMargin,
        H - doc.topMargin + 14,
    )
    canvas.setFont(_font_name(), 7.5)
    canvas.setFillColor(HexColor(_MUTED))
    canvas.drawString(doc.leftMargin, H - doc.topMargin + 4, "MASA security report")
    canvas.restoreState()
    # Footer: brand left, page number right (reportlab handles page numbers -
    # xhtml2pdf's @page margin boxes could not).
    canvas.saveState()
    canvas.setFont(_font_name(), 7.5)
    canvas.setFillColor(HexColor(_MUTED))
    canvas.drawString(doc.leftMargin, 0.8 * 72, "MASA security report")
    canvas.drawRightString(
        W - doc.rightMargin, 0.8 * 72, f"page {doc.page}"
    )
    canvas.restoreState()


# ---- bounded render ---------------------------------------------------------


def _build_doc(fragment: str, stem: str, meta: dict | None = None) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import cm
    from reportlab.platypus import PageBreak, SimpleDocTemplate

    left = right = 1.7 * cm
    top, bottom = 1.9 * cm, 2.1 * cm
    width = A4[0] - left - right
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=left,
        rightMargin=right,
        topMargin=top,
        bottomMargin=bottom,
        title=f"MASA security report - {stem}",
        author="MASA",
    )
    meta = dict(meta or {})
    meta["stem"] = stem
    story: list = []
    # The cover is drawn on page 1 via the canvas callback; the body starts
    # on page 2 (the report content itself never changes - one body, two
    # media; the cover is presentation only).
    story.append(PageBreak())
    story.extend(_flowables_for(fragment, width))
    doc.build(
        story,
        onFirstPage=partial(_cover_canvas, meta),
        onLaterPages=_body_page,
    )
    return buf.getvalue()


def _render_bounded(fragment: str, stem: str, meta: dict | None = None) -> bytes:
    """Render under ``MASA_REPORT_PDF_TIMEOUT_SECONDS`` - a hung or erroring
    engine surfaces as ReportPdfError, never a hang or an empty success."""
    holder: dict[str, object] = {}

    def _run() -> None:
        try:
            holder["data"] = _build_doc(fragment, stem, meta)
        except Exception as exc:  # noqa: BLE001 - surfaced as ReportPdfError
            holder["exc"] = exc

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    thread.join(settings.report_pdf_timeout_seconds)
    if thread.is_alive():
        # The daemon thread is abandoned mid-render (bounded by the size cap
        # on its input) - documented tradeoff: it consumes CPU until its own
        # end, and a later render could interleave with it. Single-user
        # local tool; the alternative (killing the thread) is not possible
        # in Python.
        raise ReportPdfError(
            f"PDF render exceeded the {settings.report_pdf_timeout_seconds}s "
            "timeout - try the markdown export"
        )
    if "exc" in holder:
        raise ReportPdfError(f"PDF render failed: {holder['exc']}")
    return holder.get("data", b"")


def render_pdf(body: str, *, stem: str) -> bytes:
    """Render the assembled body to branded PDF bytes.

    Bounds (the Phase C contract): the HTML fragment handed to the renderer
    is size-capped (``MASA_REPORT_PDF_MAX_HTML_BYTES``) and the render runs
    under a hard deadline; the output is sanity-gated (``%PDF`` magic +
    non-trivial size) - a silent empty file is a ReportPdfError, never a
    silent 200.
    """
    fragment = markdown_fragment(body)
    size = len(fragment.encode("utf-8"))
    if size > settings.report_pdf_max_html_bytes:
        raise ReportPdfError(
            f"report body is too large to render as PDF ({size} bytes HTML "
            f"> the {settings.report_pdf_max_html_bytes} cap) - use the "
            "markdown export"
        )
    _font_name()  # register the bundled TTF family (or Helvetica) first
    meta = _cover_meta(body)
    data = _render_bounded(fragment, stem, meta)
    if not data.startswith(b"%PDF") or len(data) < 512:
        raise ReportPdfError(
            "PDF render produced an invalid or empty document - use the "
            "markdown export"
        )
    return data
