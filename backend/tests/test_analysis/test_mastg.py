from app.analysis.mastg import (
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
