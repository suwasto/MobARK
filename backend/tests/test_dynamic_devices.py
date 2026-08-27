"""M11 (V2) device discovery/preflight parsing tests.

adb / pymobiledevice3 are CLI tools invoked as subprocesses; these tests
monkeypatch the subprocess seam (``run_tool`` / ``resolve_binary`` /
socket) with canned output to exercise the parsers + per-check boolean
mapping with no real device or CLI installed - the fake-device posture.
"""
from __future__ import annotations

import pytest

from app.analysis.subprocess import RunResult


def _fake_run(returncode, stdout="", stderr=""):
    return RunResult(returncode, stdout, stderr)


# ---------------------------------------------------------------------------
# Android (adb)
# ---------------------------------------------------------------------------


def _patch_adb(monkeypatch, run_side_effect):
    import app.dynamic.android.devices as m

    monkeypatch.setattr(m, "resolve_binary", lambda name, env: "/usr/bin/adb")
    monkeypatch.setattr(m, "run_tool", run_side_effect)
    return m


def test_android_list_parses_devices(monkeypatch):
    out = (
        "List of devices attached\n"
        "emulator-5554\tdevice\tproduct:sdk_gphone64_x86_64 model:pixel_6\n"
        "ZYX123\tdevice\tmodel:oneplus product:oneplus9\n"
    )
    m = _patch_adb(monkeypatch, lambda *a, **k: _fake_run(0, out))
    devs = m.list_devices()
    assert len(devs) == 2
    assert devs[0]["id"] == "emulator-5554"
    assert devs[0]["model"] == "pixel_6"
    assert devs[1]["product"] == "oneplus9"


def test_android_list_skips_offline_and_blank(monkeypatch):
    out = (
        "List of devices attached\n"
        "emulator-5554\toffline\n"
        "phone\tunauthorized\n"
        "\n"
    )
    _patch_adb(monkeypatch, lambda *a, **k: _fake_run(0, out))
    import app.dynamic.android.devices as m

    assert m.list_devices() == []


def test_android_preflight_all_checks(monkeypatch):
    import app.dynamic.android.devices as m

    def run(cmd, **kw):
        if "get-state" in cmd:
            return _fake_run(0, "device\n")
        if "frida-server" in cmd:
            return _fake_run(0, "/data/local/tmp/frida-server\n")
        if "pm" in cmd:
            return _fake_run(0, "package:/data/app/.../base.apk\n")
        return _fake_run(0)

    _patch_adb(monkeypatch, run)
    checks = m.preflight("emulator-5554", "com.example.app")
    assert checks == {
        "adb_ok": True,
        "device_present": True,
        "frida_server_reachable": True,
        "target_installed": True,
    }


def test_android_preflight_device_absent(monkeypatch):
    import app.dynamic.android.devices as m

    def run(cmd, **kw):
        if "get-state" in cmd:
            return _fake_run(0, "offline\n")
        return _fake_run(0)

    _patch_adb(monkeypatch, run)
    checks = m.preflight("emulator-5554", "com.example.app")
    assert checks["adb_ok"] is True
    assert checks["device_present"] is False
    assert checks["frida_server_reachable"] is False
    assert checks["target_installed"] is False


def test_android_preflight_missing_adb_no_raise(monkeypatch):
    import app.dynamic.android.devices as m

    def missing(name, env):
        return None

    monkeypatch.setattr(m, "resolve_binary", missing)
    checks = m.preflight("emulator-5554", "com.example.app")
    assert checks == {
        "adb_ok": False,
        "device_present": False,
        "frida_server_reachable": False,
        "target_installed": False,
    }


def test_android_list_missing_adb_raises(monkeypatch):
    import app.dynamic.android.devices as m
    from app.dynamic.base import DeviceError

    monkeypatch.setattr(m, "resolve_binary", lambda n, e: None)
    with pytest.raises(DeviceError):
        m.list_devices()


# ---------------------------------------------------------------------------
# iOS (pymobiledevice3)
# ---------------------------------------------------------------------------


def _patch_ios(monkeypatch, run_side_effect):
    import app.dynamic.ios.devices as m

    monkeypatch.setattr(m, "resolve_binary", lambda name, env: "pymobiledevice3")
    monkeypatch.setattr(m, "run_tool", run_side_effect)
    return m


def test_ios_udids_json_parse(monkeypatch):
    out = (
        '[{"udid":"AAAA-UUID","name":"iPhone of Tester",'
        '"ios_version":"17.5"}]'
    )
    m2 = _patch_ios(monkeypatch, lambda *a, **k: _fake_run(0, out))
    assert m2.list_devices() == [
        {"id": "AAAA-UUID", "name": "iPhone of Tester", "model": None, "detail": "iOS 17.5"}
    ]


def test_ios_empty_list_clean(monkeypatch):
    _patch_ios(monkeypatch, lambda *a, **k: _fake_run(0, ""))
    import app.dynamic.ios.devices as m

    assert m.list_devices() == []


def test_ios_preflight_booleans(monkeypatch):
    import app.dynamic.ios.devices as m

    monkeypatch.setattr(m, "resolve_binary", lambda name, env: "pymobiledevice3")
    monkeypatch.setattr(
        m,
        "list_devices",
        lambda: [{"id": "UDID1", "name": "iPhone", "model": None, "detail": None}],
    )
    monkeypatch.setattr(m, "_frida_server_reachable", lambda: True)
    monkeypatch.setattr(m, "_target_installed", lambda d, t: True)
    checks = m.preflight("UDID1", "com.example.app")
    assert checks == {
        "device_reachable": True,
        "frida_server_reachable": True,
        "jailbreak_detected": True,
        "target_installed": True,
    }


def test_ios_preflight_device_absent(monkeypatch):
    import app.dynamic.ios.devices as m

    monkeypatch.setattr(m, "resolve_binary", lambda name, env: "pymobiledevice3")
    monkeypatch.setattr(m, "list_devices", lambda: [])
    checks = m.preflight("NOPE", "com.example.app")
    assert checks["device_reachable"] is False
    assert checks["target_installed"] is False
    assert checks["frida_server_reachable"] is False