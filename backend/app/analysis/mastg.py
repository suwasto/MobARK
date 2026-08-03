"""Vendored OWASP MASTG mapping loader.

The mapping data (``app/analysis/resources/mastg_mapping.json``) is
generated from the OWASP MASTG repo's per-test YAML front matter by
``scripts/sync_mastg.py`` and committed to the repo, so scan-time analysis
never touches the network. Records ``source_ref`` / ``source_date`` inside
the JSON so stale data is auditable.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

RESOURCES_DIR = Path(__file__).parent / "resources"
MAPPING_PATH = RESOURCES_DIR / "mastg_mapping.json"


@lru_cache(maxsize=1)
def load_mapping() -> dict:
    """Return {test_id: {platform, title, masvs_v2_id, masvs_v1_id, status}}."""
    if not MAPPING_PATH.is_file():
        return {}
    try:
        data = json.loads(MAPPING_PATH.read_text())
    except json.JSONDecodeError:
        return {}
    tests = data.get("tests") if isinstance(data, dict) else None
    return tests if isinstance(tests, dict) else {}


def mastg_test(test_id: str) -> dict | None:
    return load_mapping().get(test_id)


@lru_cache(maxsize=1)
def _control_index() -> dict[str, list[str]]:
    """control id -> list of android test ids (for reverse lookups)."""
    index: dict[str, list[str]] = {}
    for test_id, info in load_mapping().items():
        if not isinstance(info, dict):
            continue
        if info.get("platform") and info["platform"] != "android":
            continue
        controls = info.get("masvs_v2_id") or []
        if isinstance(controls, str):
            controls = [controls]
        for control in controls:
            index.setdefault(control, []).append(test_id)
    return index


def test_ids_for_control(control: str) -> list[str]:
    """Android MASTG test ids mapped to a MASVS v2 control, if any."""
    return _control_index().get(control, [])


def source_metadata() -> dict:
    """Upstream ref/date recorded when the mapping was generated."""
    if not MAPPING_PATH.is_file():
        return {}
    try:
        data = json.loads(MAPPING_PATH.read_text())
    except json.JSONDecodeError:
        return {}
    return {
        k: data.get(k)
        for k in ("source_ref", "source_date", "generated_at")
        if data.get(k) is not None
    }
