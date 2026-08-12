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
def _control_index() -> dict[tuple[str, str], list[str]]:
    """(platform, control id) -> list of test ids (for reverse lookups)."""
    index: dict[tuple[str, str], list[str]] = {}
    for test_id, info in load_mapping().items():
        if not isinstance(info, dict):
            continue
        platform = info.get("platform")
        if platform not in ("android", "ios"):
            continue
        controls = info.get("masvs_v2_id") or []
        if isinstance(controls, str):
            controls = [controls]
        for control in controls:
            index.setdefault((platform, control), []).append(test_id)
    return index


def test_ids_for_control(control: str, platform: str = "android") -> list[str]:
    """MASTG test ids (for ``platform``) mapped to a MASVS v2 control."""
    return _control_index().get((platform, control), [])


def active_test_ids_for_control(control: str, platform: str = "android") -> list[str]:
    """CURRENT (non-deprecated) MASTG v2 test ids for a MASVS v2 control.

    The v1-era ids (``MASTG-TEST-0001..0093``) are all DEPRECATED in MASTG
    v2 (superseded by the atomic tests in the 0200+ range) - citing one as
    current would mislead a pentester. Findings carry the MASVS control
    regardless; this drives the backfill so new scans only ever cite live
    ids (owner follow-up, Aug 12: "the report cites MASTG-TEST-0007 which
    is deprecated").
    """
    return [
        test_id
        for test_id in test_ids_for_control(control, platform)
        # ``deprecated`` = the retired v1-era ids; ``placeholder`` = a
        # not-yet-written atomic slot. Neither is a citable current test.
        if (mastg_test(test_id) or {}).get("status") not in ("deprecated", "placeholder")
    ]


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
