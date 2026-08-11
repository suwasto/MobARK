"""iOS Gitleaks custom-ruleset tests (M4 Layer 1 - string-level checks).

kSecAttrAccessibleAlways is a string in the binary's __cstring, not a symbol
import - it rides through Gitleaks via the iOS ruleset, never the import-table
scanner.
"""
from __future__ import annotations

import tomllib

from app.analysis import gitleaks
from app.analysis.orchestrator import _IOS_GITLEAKS_CONFIG


def test_ios_config_file_exists_and_parses():
    assert _IOS_GITLEAKS_CONFIG.is_file()
    data = tomllib.loads(_IOS_GITLEAKS_CONFIG.read_text())
    rules = data["rules"]
    ids = {r["id"] for r in rules}
    assert "ios-insecure-keychain-accessibility" in ids
    rule = next(r for r in rules if r["id"] == "ios-insecure-keychain-accessibility")
    assert "kSecAttrAccessibleAlways" in rule["regex"]
    assert rule["entropy"] == 0  # fixed string - no entropy gate


def test_scan_directory_passes_config_flag(monkeypatch, tmp_path):
    captured: dict = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["timeout"] = kwargs.get("timeout")
        captured["cwd"] = kwargs.get("cwd")
        return type("R", (), {"returncode": 0, "timed_out": False, "stderr": ""})()

    monkeypatch.setattr(gitleaks, "run_tool", fake_run)
    monkeypatch.setattr(gitleaks, "gitleaks_binary", lambda: "gitleaks")

    target = tmp_path / "app"
    target.mkdir()
    cfg = tmp_path / "ios.toml"
    cfg.write_text("title = 'x'\n")

    gitleaks.scan_directory(target, tmp_path / "g.json", config=cfg)

    cmd = captured["cmd"]
    assert "--config" in cmd
    assert str(cfg.resolve()) in cmd
    assert cmd[0] == "gitleaks"
    assert "dir" in cmd


def test_scan_directory_without_config_has_no_flag(monkeypatch, tmp_path):
    captured: dict = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return type("R", (), {"returncode": 0, "timed_out": False, "stderr": ""})()

    monkeypatch.setattr(gitleaks, "run_tool", fake_run)
    monkeypatch.setattr(gitleaks, "gitleaks_binary", lambda: "gitleaks")
    target = tmp_path / "app"
    target.mkdir()
    gitleaks.scan_directory(target, tmp_path / "g.json")
    assert "--config" not in captured["cmd"]
