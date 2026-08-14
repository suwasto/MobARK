"""Deterministic per-finding explanations (no-AI path).

The same ``auto_explanation`` powers the report's finding rows
(``report._finding_lines``) AND the explain surface's no-model fallback
(``insights.explain_finding``) - one source of truth so the app matches the
report. A plain factual sentence built ONLY from persisted data, the vendored
MASTG mapping, and the vendored rule metadata (never an LLM call, never a
"configure a model" note): what the tool reported, the rule's own description
when one is available, where, and which MASVS control / MASTG test it maps to,
closed with the static-only scope note.
"""
from __future__ import annotations

import json

from app.analysis import mastg
from app.analysis.rule_meta import rule_description


def _finding_detail(finding) -> dict:
    """The persisted ``detail`` column is JSON text on the ORM row (the API
    schema parses it); handle both shapes - same contract as
    ``dependencies._detail_dict``."""
    d = getattr(finding, "detail", None)
    if isinstance(d, dict):
        return d
    if isinstance(d, str) and d:
        try:
            parsed = json.loads(d)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def auto_explanation(finding) -> str:
    """Deterministic explanation of one finding for the no-AI path.

    Cites the rule's own description when one is available: semgrep findings
    are looked up by ``detail.check_id`` in the vendored rule metadata
    (``rule_meta``); gitleaks findings carry ``detail.rule_description``
    (persisted at scan time) alongside ``detail.rule_id``.
    """
    sev = (finding.severity or "info").lower()
    tool = getattr(finding, "tool", None) or "static analysis"
    rule_desc = None
    if tool in ("semgrep", "gitleaks"):
        detail = _finding_detail(finding)
        if tool == "semgrep":
            check_id = detail.get("check_id")
            desc = rule_description(check_id)
            if desc:
                rule_desc = f"{check_id}: {desc}"
        else:
            rule_id = detail.get("rule_id")
            desc = detail.get("rule_description")
            if rule_id and desc:
                rule_desc = f"{rule_id}: {desc}"
    text = f"This {tool} check"
    if rule_desc:
        text += f" ({rule_desc})"
    text += f" reported a {sev}-severity condition"
    loc = []
    if getattr(finding, "file_path", None):
        loc_text = finding.file_path
        if getattr(finding, "line_number", None):
            loc_text += f":{finding.line_number}"
        loc.append(f"`{loc_text}`")
    if loc:
        text += " at " + ", ".join(loc)
    mappings = []
    if getattr(finding, "category", None):
        mappings.append(f"MASVS control {finding.category}")
    test_id = getattr(finding, "mastg_test_id", None)
    info = mastg.mastg_test(test_id) if test_id else None
    # Same currency rule as the tags: a deprecated v1 id is never cited as
    # current - the control mapping above still renders.
    if info and info.get("status") != "deprecated" and info.get("title"):
        mappings.append(f"OWASP MASTG test {test_id} ({info['title']})")
    if mappings:
        text += ", mapped to " + " and ".join(mappings)
    text += (
        ". Static-only finding - flagged from the artifact's code/binary "
        "structure, not confirmed at runtime."
    )
    return text
