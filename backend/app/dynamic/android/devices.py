"""M11 (V2) Android device discovery + pre-flight (via adb, subprocess-only).

adb is a permissive CLI invoked strictly as a subprocess (never imported),
following the M1 jadx/gitleaks ``*_CMD`` pattern. ``list_devices`` and
``preflight`` are the FR-D1/FR-D2 surface; ``preflight`` NEVER raises for a
failed check - it returns per-check booleans (the "returns per-check
booleans, never raw exceptions" requirement), so the UI can render each
prerequisite individually.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.analysis.subprocess import resolve_binary, run_tool
from app.config import settings
from app.dynamic.base import DeviceError


def _adb() -> list[str]:
    binary = resolve_binary("adb", "adb_cmd")
    if not binary:
        raise DeviceError(
            502,
            "adb is not available - install Android platform-tools or set "
            "MOBARK_ADB_CMD (a rooted device/emulator with frida-server is "
            "required for Android dynamic analysis)",
        )
    return [binary]


@dataclass
class Device:
    """One Android device/emulator from ``adb devices -l``."""

    id: str
    name: str
    model: str | None = None
    product: str | None = None


def list_devices() -> list[dict]:
    """``adb devices -l`` -> normalized devices. Empty list = no devices
    (clean response, not an error). Raises DeviceError only when adb itself
    is missing or errored."""
    cmd = _adb() + ["devices", "-l"]
    result = run_tool(cmd, timeout=settings.dynamic_op_timeout_seconds)
    if result.timed_out:
        raise DeviceError(504, "adb devices timed out")
    devices: list[dict] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("List of devices") or line.startswith("*"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        serial, state = parts[0], parts[1]
        if state != "device":
            # offline / unauthorized / unknown - skip, not an error
            continue
        kv: dict[str, str] = {}
        for tok in parts[2:]:
            if ":" in tok:
                k, _, v = tok.partition(":")
                kv[k] = v
        devices.append(
            {
                "id": serial,
                "name": serial,
                "model": kv.get("model"),
                "product": kv.get("product"),
            }
        )
    return devices


def _device_present(device_id: str) -> bool:
    """``adb -s <id> get-state`` == ``device``."""
    cmd = _adb() + ["-s", device_id, "get-state"]
    result = run_tool(cmd, timeout=settings.dynamic_op_timeout_seconds)
    return result.returncode == 0 and result.stdout.strip() == "device"


def _frida_server_reachable(device_id: str) -> bool:
    """frida-server binary present in the device's tmp dir (a "reachable"
    proxy - the binary's presence is what the attach path depends on; a real
    frida enumeration happens at attach time)."""
    cmd = _adb() + [
        "-s",
        device_id,
        "shell",
        "ls /data/local/tmp/frida-server",
    ]
    result = run_tool(cmd, timeout=settings.dynamic_op_timeout_seconds)
    return result.returncode == 0


def _target_installed(device_id: str, target_app: str) -> bool:
    """``adb -s <id> shell pm path <package>`` exit 0 = installed."""
    cmd = _adb() + ["-s", device_id, "shell", "pm", "path", target_app]
    result = run_tool(cmd, timeout=settings.dynamic_op_timeout_seconds)
    return result.returncode == 0


def preflight(device_id: str, target_app: str) -> dict:
    """Per-check booleans for the Android connect gate. Never raises for a
    failed check; the ONLY raise is a missing adb (no device path at all)."""
    checks = {
        "adb_ok": False,
        "device_present": False,
        "frida_server_reachable": False,
        "target_installed": False,
    }
    try:
        _adb()
    except DeviceError:
        return checks
    checks["adb_ok"] = True
    if not _device_present(device_id):
        return checks
    checks["device_present"] = True
    checks["frida_server_reachable"] = _frida_server_reachable(device_id)
    checks["target_installed"] = _target_installed(device_id, target_app)
    return checks
