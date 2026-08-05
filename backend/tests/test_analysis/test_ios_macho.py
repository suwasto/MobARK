"""Unit tests for ``ios/macho.py``.

LIEF 1.0 no longer offers ``Binary.create``, so the fixture strategy is:

- a hand-rolled minimal 64-bit Mach-O header (parses cleanly with LIEF);
- in-memory mutation via LIEF's API (``header.flags``, ``add_local_symbol``)
  to exercise each check without needing a full compiled binary.
"""
import plistlib
from pathlib import Path

import lief
import pytest

from app.analysis.base import TOOL_LIEF
from app.analysis.ios.macho import MachoError, _analyze_binary, _load_binaries


def _write_minimal_macho(path: Path, flags: int = 0) -> None:
    """A valid 64-bit Mach-O header with no load commands."""
    import struct

    header = struct.pack(
        "<IIIIIIII",
        0xFEEDFACF,  # MH_MAGIC_64
        0x0100000C,  # CPU_TYPE_ARM64
        0,           # cpusubtype
        2,           # MH_EXECUTE
        0,           # ncmds
        0,           # sizeofcmds
        flags,
        0,           # reserved
    )
    path.write_bytes(header)


def _make_app_bundle(tmp_path: Path, exe_bytes: bytes) -> Path:
    """A minimal ``Payload/Test.app`` bundle with an Info.plist + executable."""
    app_root = tmp_path / "Payload" / "Test.app"
    app_root.mkdir(parents=True)
    plistlib.dump(
        {"CFBundleExecutable": "Test", "CFBundleIdentifier": "com.example.Test"},
        (app_root / "Info.plist").open("wb"),
    )
    (app_root / "Test").write_bytes(exe_bytes)
    return app_root


def test_load_binaries_parses_minimal_macho(tmp_path):
    f = tmp_path / "mini"
    _write_minimal_macho(f)
    binaries = _load_binaries(f)
    assert len(binaries) == 1
    assert isinstance(binaries[0], lief.MachO.Binary)


def test_load_binaries_rejects_non_macho(tmp_path):
    f = tmp_path / "not-macho"
    f.write_bytes(b"this is not a mach-o binary at all")
    with pytest.raises(MachoError):
        _load_binaries(f)


def test_pie_missing_is_finding(tmp_path):
    f = tmp_path / "mini"
    _write_minimal_macho(f, flags=0)  # no PIE flag
    binary = _load_binaries(f)[0]
    from app.analysis.base import StageResult

    result = StageResult()
    _analyze_binary(binary, result)
    pie = [x for x in result.findings if x.category == "MASVS-CODE-4" and "PIE" in x.title]
    assert len(pie) == 1
    assert pie[0].severity == "high"
    assert pie[0].tool == TOOL_LIEF


def test_pie_present_no_finding(tmp_path):
    f = tmp_path / "mini"
    _write_minimal_macho(f, flags=int(lief.MachO.Header.FLAGS.PIE))
    binary = _load_binaries(f)[0]
    from app.analysis.base import StageResult

    result = StageResult()
    _analyze_binary(binary, result)
    assert not [x for x in result.findings if "PIE" in x.title]


def test_stack_canary_detected_via_symbol(tmp_path):
    f = tmp_path / "mini"
    _write_minimal_macho(f)
    binary = _load_binaries(f)[0]
    binary.add_local_symbol(0, "___stack_chk_guard")
    from app.analysis.base import StageResult

    result = StageResult()
    _analyze_binary(binary, result)
    assert not [x for x in result.findings if "Stack canary" in x.title]


def test_stack_canary_missing_is_finding(tmp_path):
    f = tmp_path / "mini"
    _write_minimal_macho(f)
    binary = _load_binaries(f)[0]  # no symbols at all
    from app.analysis.base import StageResult

    result = StageResult()
    _analyze_binary(binary, result)
    canary = [x for x in result.findings if "Stack canary" in x.title]
    assert len(canary) == 1
    assert canary[0].severity == "medium"


def test_arc_indicator_from_objc_symbols(tmp_path):
    f = tmp_path / "mini"
    _write_minimal_macho(f)
    binary = _load_binaries(f)[0]
    binary.add_local_symbol(0, "objc_retainAutorelease")
    from app.analysis.base import StageResult

    result = StageResult()
    _analyze_binary(binary, result)
    assert result.meta["arc"] is True
    assert "objc_retainAutorelease" in result.meta["arc_evidence"]


def test_analyze_app_binary_end_to_end(tmp_path):
    f = tmp_path / "exe"
    _write_minimal_macho(f, flags=int(lief.MachO.Header.FLAGS.PIE))
    app_root = _make_app_bundle(tmp_path, f.read_bytes())

    from app.analysis.ios.macho import analyze_app_binary

    result = analyze_app_binary(app_root)
    assert result.meta["main_executable"] == "Test"
    assert "CPU_TYPE.ARM64" in result.meta["architectures"][0]
    # PIE is set -> no PIE finding; canary absent -> exactly one finding.
    assert not [x for x in result.findings if "PIE" in x.title]
    assert len([x for x in result.findings if "Stack canary" in x.title]) == 1
