"""M8 Phase A: apktool wrapper unit tests (subprocess mocked, no network)."""
from __future__ import annotations

from pathlib import Path

import pytest

from app.analysis import apktool
from app.analysis.subprocess import RunResult


def _make_apk(tmp_path: Path) -> Path:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04fake-apk")
    return apk


def test_decode_argv_and_timeout(monkeypatch, tmp_path):
    """The exact apktool argv (d -f -o <out> <apk>) and the explicit timeout
    win over the settings default."""
    monkeypatch.setattr(
        apktool, "apktool_binary", lambda: "/opt/masa-tools/apktool/apktool"
    )
    captured = {}

    def fake_run(cmd, timeout):
        captured["cmd"] = cmd
        captured["timeout"] = timeout
        (Path(cmd[4]) / "AndroidManifest.xml").write_text("<manifest/>")
        return RunResult(0, "", "")

    monkeypatch.setattr(apktool, "run_tool", fake_run)
    apk = _make_apk(tmp_path)
    out = tmp_path / "out"
    apktool.decode(apk, out, timeout=42)
    assert captured["cmd"] == [
        "/opt/masa-tools/apktool/apktool",
        "d",
        "-f",
        "-o",
        str(out),
        str(apk),
    ]
    assert captured["timeout"] == 42


def test_decode_defaults_timeout_to_settings(monkeypatch, tmp_path):
    monkeypatch.setattr(
        apktool, "apktool_binary", lambda: "apktool"
    )
    monkeypatch.setattr(apktool.settings, "apktool_timeout_seconds", 900)
    captured = {}

    def fake_run(cmd, timeout):
        captured["timeout"] = timeout
        (Path(cmd[4]) / "AndroidManifest.xml").write_text("<manifest/>")
        return RunResult(0, "", "")

    monkeypatch.setattr(apktool, "run_tool", fake_run)
    apktool.decode(_make_apk(tmp_path), tmp_path / "out")
    assert captured["timeout"] == 900


def test_decode_nonzero_exit_maps_to_clean_error(monkeypatch, tmp_path):
    monkeypatch.setattr(apktool, "apktool_binary", lambda: "apktool")

    def fake_run(cmd, timeout):
        return RunResult(1, "", "Exception in thread \"main\"\nresource clash")

    monkeypatch.setattr(apktool, "run_tool", fake_run)
    with pytest.raises(apktool.ApktoolError, match="resource clash"):
        apktool.decode(_make_apk(tmp_path), tmp_path / "out")


def test_decode_timeout_maps_to_clean_error(monkeypatch, tmp_path):
    monkeypatch.setattr(apktool, "apktool_binary", lambda: "apktool")
    monkeypatch.setattr(
        apktool,
        "run_tool",
        lambda cmd, timeout: RunResult(-1, "", "", timed_out=True),
    )
    with pytest.raises(apktool.ApktoolError, match="timed out after 1200s"):
        apktool.decode(_make_apk(tmp_path), tmp_path / "out")


def test_decode_exit_zero_without_manifest_fails(monkeypatch, tmp_path):
    """apktool exiting 0 while producing nothing must fail loudly — a silent
    success would leave the Smali view pointing at a broken tree."""
    monkeypatch.setattr(apktool, "apktool_binary", lambda: "apktool")
    monkeypatch.setattr(
        apktool, "run_tool", lambda cmd, timeout: RunResult(0, "", "")
    )
    with pytest.raises(apktool.ApktoolError, match="no AndroidManifest.xml"):
        apktool.decode(_make_apk(tmp_path), tmp_path / "out")


def test_missing_binary_raises(monkeypatch):
    monkeypatch.setattr(apktool, "resolve_binary", lambda *a, **k: None)
    with pytest.raises(apktool.ApktoolError, match="not found"):
        apktool.apktool_binary()


def test_build_argv_and_success(monkeypatch, tmp_path):
    """apktool b runs the exact argv (b <tree> -o <out>) and creates the
    output directory for the APK."""
    monkeypatch.setattr(apktool, "apktool_binary", lambda: "apktool")
    captured = {}

    def fake_run(cmd, timeout):
        captured["cmd"] = cmd
        captured["timeout"] = timeout
        Path(cmd[-1]).write_bytes(b"PK\x03\x04")
        return RunResult(0, "", "")

    monkeypatch.setattr(apktool, "run_tool", fake_run)
    tree_dir = tmp_path / "decoded"
    out = tmp_path / "out" / "app-resigned-test-1.apk"
    apktool.build(tree_dir, out, timeout=42)
    assert captured["cmd"] == ["apktool", "b", str(tree_dir), "-o", str(out)]
    assert captured["timeout"] == 42


def test_build_failure_and_no_output_fail_loudly(monkeypatch, tmp_path):
    """A non-zero apktool b exit (and a silent 0-exit without output) both
    fail loudly with the stderr reason — never a silent broken APK."""
    monkeypatch.setattr(apktool, "apktool_binary", lambda: "apktool")
    monkeypatch.setattr(
        apktool,
        "run_tool",
        lambda cmd, timeout: RunResult(1, "", "resource not found"),
    )
    with pytest.raises(apktool.ApktoolError, match="resource not found"):
        apktool.build(tmp_path / "tree", tmp_path / "out.apk")

    monkeypatch.setattr(
        apktool, "run_tool", lambda cmd, timeout: RunResult(0, "", "")
    )
    with pytest.raises(apktool.ApktoolError, match="no APK output"):
        apktool.build(tmp_path / "tree", tmp_path / "out.apk")


def test_decoded_root_and_is_ready(monkeypatch, tmp_path):
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    root = apktool.decoded_root(7)
    assert root == tmp_path / "work" / "7" / "apktool"
    assert apktool.is_ready(7) is False
    root.mkdir(parents=True)
    (root / "AndroidManifest.xml").write_text("<manifest/>")
    assert apktool.is_ready(7) is True
