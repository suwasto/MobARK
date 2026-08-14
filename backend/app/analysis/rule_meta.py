"""Vendored semgrep rule metadata for deterministic report explanations.

The rule YAMLs under ``app/analysis/rules/{masa,mastg}/*.yml`` carry
per-rule metadata: the rule ``id`` (what semgrep's ``check_id`` reports - a
finding's ``detail.check_id``) and, on most rules, ``metadata.summary`` - a
one-line description DISTINCT from the finding title. The report's no-AI
per-finding explanation cites this summary so a finding reads richer without
a chat model.

Rules without a summary (the 8 hand-curated MASA rules) are skipped: their
``message`` is a folded one-liner that IS the finding title already - citing
it again would just repeat the row. Loaded once, lazily, and cached - same
vendored-data pattern as ``mastg.py``; scan-time analysis never touches the
network.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

RULES_DIR = Path(__file__).parent / "rules"


@lru_cache(maxsize=1)
def rule_descriptions() -> dict[str, str]:
    """``{rule id -> one-line description}`` from the rules' ``metadata.summary``.

    Best-effort: an unreadable file is skipped, a rule without a summary is
    omitted, last rule wins on a duplicate id - never a crash.
    """
    out: dict[str, str] = {}
    for sub in ("masa", "mastg"):
        d = RULES_DIR / sub
        if not d.is_dir():
            continue
        for path in sorted(d.glob("*.yml")):
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8"))
            except (OSError, yaml.YAMLError):
                continue
            if not isinstance(data, dict):
                continue
            for rule in data.get("rules") or []:
                if not isinstance(rule, dict) or not rule.get("id"):
                    continue
                metadata = rule.get("metadata")
                summary = metadata.get("summary") if isinstance(metadata, dict) else None
                if summary:
                    out[str(rule["id"])] = _collapse(str(summary))
    return out


def _collapse(text: str) -> str:
    """One line: collapse embedded newlines/whitespace (the explanation is a
    single block-quote paragraph in the report)."""
    return " ".join(text.split())


def rule_description(check_id: str | None) -> str | None:
    """The vendored summary for a semgrep ``check_id``, or None when the rule
    is unknown (or carries no summary). Tolerates semgrep's occasional
    ``<path>:<id>`` / namespaced ``rules.<id>`` check ids via a trailing-id
    fallback so a lookup never misses on formatting drift."""
    if not check_id:
        return None
    desc = rule_descriptions().get(check_id)
    if desc is not None:
        return desc
    tail = check_id.rsplit(":", 1)[-1].rsplit(".", 1)[-1]
    if tail != check_id:
        return rule_descriptions().get(tail)
    return None
