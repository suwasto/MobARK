"""M14 (V2) FR-D13 flagged-data detection - in-process, deterministic.

The M14 task line's "reuse the v1 secrets scanner (gitleaks)" was overridden
at kickoff by the owner: gitleaks is LIMITED TO STATIC ANALYSIS. Traffic
flagging is a NEW IN-PROCESS detector (no subprocess, no rule-file coupling)
that flags plaintext credentials, bearer tokens, and PII-shaped values in
captured request/response bodies.

Design:
- Deterministic regex + Luhn matchers; per sub-category FIRST hit only, so a
  single body produces a bounded, ordered flag list.
- Bodies are scanned then DROPPED by the caller - a traffic row carries only
  the boolean ``flagged`` + bounded ``flags[]`` snippets (never the raw
  body). Data-minimizing by construction.
- Never raises: an undecodable binary body, an oversized body, or malformed
  input scans to no flags, never a crash. Bodies over ``traffic_flag_body_bytes``
  are scanned up to the cap.
"""
from __future__ import annotations

import re
from typing import Any

# A credential key/value pair - ``"password": "s3cr3t"``, ``api_key=...``,
# ``client_secret = ...``. The value class is deliberately tight (no quotes,
# no separators) so the match ends cleanly at the closing quote / delimiter.
_CREDENTIAL_RE = re.compile(
    r"""(?ix)
    (?:password|passwd|pwd|secret|api[_-]?key|apikey|client[_-]?secret|
        private[_-]?key|auth[_-]?token|access[_-]?token|refresh[_-]?token|
        session[_-]?token|bearer[_-]?token|consumer[_-]?key)
    \s*["']?\s*[:=]\s*["']?
    (?P<value>[A-Za-z0-9_\-./+]{4,128})
    ["']?
    """
)

# ``Authorization: Bearer <token>`` - require a token long enough that a
# real credential is present, not a stub.
_BEARER_RE = re.compile(r"(?i)\bbearer\s+([A-Za-z0-9\-_.~]{20,})")

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# US Social Security Number (conservative - the exact 3-2-4 grouping).
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

# Phone numbers: an E.164-style +prefix form, or a 10-digit grouped form
# (3-3-4). Conservative - no bare 10-digit runs, no leading-9 misreads.
_PHONE_RE = re.compile(
    r"(?<!\d)(?:\+\d[\d\s().-]{6,15}\d|\b\d{3}[-. ]\d{3}[-. ]\d{4}\b)(?!\d)"
)

# Credit-card candidates: 13-19 digits, optionally space/dash grouped. The
# Luhn check in :func:`_luhn` rejects look-alikes.
_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def _luhn(digits: str) -> bool:
    """The Luhn checksum - the arithmetic that tells a real card number from
    a look-alike digit run."""
    total = 0
    double = False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if double:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        double = not double
    return total % 10 == 0


def _snippet(text: str, start: int, end: int, limit: int) -> str:
    return text[start : min(end, start + limit)]


def detect(
    body: Any = None,
    *,
    body_cap: int | None = None,
    snippet_chars: int | None = None,
) -> list[dict[str, Any]]:
    """Scan one request/response body for flagged data (FR-D13).

    Returns a bounded, ordered list of ``{category, label, snippet}`` hits -
    at most one per sub-category (credential / bearer / email / ssn / phone /
    credit_card). Never raises; a None/undecodable/oversized body scans to
    ``[]``. Snippets are truncated to ``snippet_chars``; bodies are scanned
    only up to ``body_cap`` bytes.
    """
    from app.config import settings

    if body_cap is None:
        body_cap = settings.traffic_flag_body_bytes
    if snippet_chars is None:
        snippet_chars = settings.traffic_flag_snippet_chars
    if body is None:
        return []
    if isinstance(body, bytes | bytearray):
        body = bytes(body).decode("utf-8", "replace")
    text = str(body)
    if len(text) > body_cap:
        text = text[:body_cap]

    hits: list[dict[str, Any]] = []

    m = _CREDENTIAL_RE.search(text)
    if m:
        start, end = m.span("value")
        hits.append(
            {
                "category": "credential",
                "label": "credentials",
                "snippet": _snippet(text, start, end, snippet_chars),
            }
        )

    m = _BEARER_RE.search(text)
    if m:
        hits.append(
            {
                "category": "bearer",
                "label": "bearer_token",
                "snippet": _snippet(text, m.start(1), m.end(1), snippet_chars),
            }
        )

    m = _EMAIL_RE.search(text)
    if m:
        hits.append(
            {
                "category": "pii",
                "label": "email",
                "snippet": _snippet(text, m.start(), m.end(), snippet_chars),
            }
        )

    m = _SSN_RE.search(text)
    if m:
        hits.append(
            {
                "category": "pii",
                "label": "ssn",
                "snippet": _snippet(text, m.start(), m.end(), snippet_chars),
            }
        )

    m = _PHONE_RE.search(text)
    if m:
        hits.append(
            {
                "category": "pii",
                "label": "phone",
                "snippet": _snippet(text, m.start(), m.end(), snippet_chars),
            }
        )

    for m in _CARD_RE.finditer(text):
        digits = re.sub(r"[^0-9]", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn(digits):
            hits.append(
                {
                    "category": "pii",
                    "label": "credit_card",
                    "snippet": _snippet(text, m.start(), m.end(), snippet_chars),
                }
            )
            break

    return hits