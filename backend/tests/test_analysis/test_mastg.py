from app.analysis.mastg import (
    active_test_ids_for_control,
    load_mapping,
    mastg_test,
    source_metadata,
)
from app.analysis.mastg import (
    test_ids_for_control as reverse_lookup,
)


def test_mapping_loaded_and_nonempty():
    mapping = load_mapping()
    assert isinstance(mapping, dict)
    assert len(mapping) > 100  # full MASTG catalog is ~290 tests


def test_mapping_records_pinned_source_ref():
    meta = source_metadata()
    assert meta.get("source_ref"), "mapping must record the pinned upstream commit"
    assert len(meta["source_ref"]) == 40  # a git SHA
    assert meta.get("source_date")


def test_mastg_test_lookup():
    backup = mastg_test("MASTG-TEST-0009")
    assert backup is not None
    assert "MASVS-STORAGE-2" in backup["masvs_v2_id"]
    assert backup["platform"] == "android"


def test_reverse_lookup_control_to_test():
    tests = reverse_lookup("MASVS-RESILIENCE-4")
    assert tests, "debuggable control should resolve to tests"
    assert "MASTG-TEST-0039" in tests


def test_unknown_lookups_are_empty():
    assert mastg_test("MASTG-TEST-9999") is None
    assert reverse_lookup("MASVS-NOPE-1") == []


def test_active_lookup_never_cites_deprecated_v1_ids():
    """Aug 12 follow-up: MASTG-TEST-0007 (the report's offender) and every
    other v1-era id are deprecated in MASTG v2 - the active set must never
    contain them."""
    ids = active_test_ids_for_control("MASVS-PLATFORM-1", platform="android")
    assert "MASTG-TEST-0007" not in ids
    for test_id in ids:
        info = mastg_test(test_id)
        assert info is not None and info.get("status") != "deprecated"


def test_active_lookup_empty_when_only_deprecated_mapped():
    """Every id mapped to MASVS-PLATFORM-1 (android) is a retired v1 id - the
    active set is empty until the checklist-linkage sync adds v2 atomics, and
    the backfill simply omits the tag (the MASVS control still renders)."""
    assert active_test_ids_for_control("MASVS-PLATFORM-1", platform="android") == []
