"""M11 (V2) iOS device discovery + pre-flight (via pymobiledevice3/usbmuxd).

pymobiledevice3 is a permissive CLI invoked strictly as a subprocess (never
imported), following the ``*_CMD`` pattern. ``list_devices`` and
``preflight`` mirror the Android module: preflight NEVER raises for a failed
check - it returns per-check booleans so the UI renders each prerequisite
individually (FR-D1). An empty iOS device list is a clean response, not an
error.
"""
from __future__ import annotations

import json
import socket

from app.analysis.subprocess import resolve_binary, run_tool
from app.config import settings
from app.dynamic.base import DeviceError


def _pmd3() -> list[str]:
    binary = resolve_binary("pymobiledevice3", "pymobiledevice3_cmd")
    if not binary:
        raise DeviceError(
            502,
            "pymobiledevice3 is not available - install it (or set "
            "MOBARK_PYMOBILEDEVICE3_CMD); a jailbroken iOS device is required "
            "for iOS dynamic analysis",
        )
    return [binary]


def _udids_from_list(text: str) -> dict[str, dict]:
    """Tolerantly parse ``pymobiledevice3 usbmux list`` output into
    {udid: {name, ios_version}}. Accepts either a JSON array (default CLI
    format) or a plain line-per-UDID fallback."""
    udids: dict[str, dict] = {}
    text = text.strip()
    if not text:
        return udids
    try:
        data = json.loads(text)
        rows = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        rows = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            udid = line.split()[0]
            udids[udid] = {"name": udid, "ios_version": None}
        return udids
    for row in rows:
        if not isinstance(row, dict):
            continue
        udid = (
            row.get("udid")
            or row.get("serial")
            or row.get("serial_number")
            or row.get("UniqueDeviceID")
        )
        if not udid:
            continue
        udids[str(udid)] = {
            "name": row.get("name") or str(udid),
            "ios_version": row.get("ios_version") or row.get("ProductVersion"),
        }
    return udids


def list_devices() -> list[dict]:
    """pymobiledevice3 usbmux list -> normalized devices. Empty = no iOS
    devices (clean). Raises DeviceError only when pmd3 itself is missing."""
    cmd = _pmd3() + ["usbmux", "list"]
    result = run_tool(cmd, timeout=settings.dynamic_op_timeout_seconds)
    if result.timed_out:
        raise DeviceError(504, "pymobiledevice3 usbmux list timed out")
    return [
        {
            "id": udid,
            "name": meta["name"],
            "model": None,
            "detail": meta["ios_version"] and f"iOS {meta['ios_version']}" or None,
        }
        for udid, meta in _udids_from_list(result.stdout).items()
    ]


def _device_present(device_id: str) -> bool:
    return device_id in {d["id"] for d in list_devices()}


def _frida_server_reachable() -> bool:
    """TCP reachability of the frida-server-over-SSH endpoint (the ssh port
    on the configured host). frida-server over SSH implies ssh reachability;
    the tunnel/remote-device setup is a deployment concern documented at
    attach."""
    host, port = settings.frida_ssh_host, settings.frida_ssh_port
    try:
        with socket.create_connection(
            (host, port), timeout=settings.dynamic_op_timeout_seconds
        ):
            return True
    except OSError:
        return False


def _target_installed(device_id: str, target_app: str) -> bool:
    """pymobiledevice3 apps list -> does any bundle id match the target?
    Tolerant: a JSON parse failure or an empty result reads as not-installed,
    never a crash."""
    cmd = _pmd3() + ["apps", "list"]
    result = run_tool(cmd, timeout=settings.dynamic_op_timeout_seconds)
    if result.returncode != 0:
        return False
    text = result.stdout
    if target_app in text:
        return True
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return False
    apps = data if isinstance(data, list) else list(data.values())
    for app in apps:
        if isinstance(app, dict) and (
            app.get("CFBundleIdentifier") == target_app
            or app.get("bundle_id") == target_app
        ):
            return True
    return False


def preflight(device_id: str, target_app: str) -> dict:
    """Per-check booleans for the iOS connect gate. Never raises for a failed
    check; the ONLY raise is a missing pymobiledevice3 (no device path at
    all). ``jailbreak_detected`` is a best-effort proxy - a reachable
    frida-server over SSH is taken to imply jailbreak tooling is present."""
    checks = {
        "device_reachable": False,
        "frida_server_reachable": False,
        "jailbreak_detected": False,
        "target_installed": False,
    }
    try:
        _pmd3()
    except DeviceError:
        return checks
    if not _device_present(device_id):
        return checks
    checks["device_reachable"] = True
    checks["frida_server_reachable"] = _frida_server_reachable()
    checks["jailbreak_detected"] = checks["frida_server_reachable"]
    checks["target_installed"] = _target_installed(device_id, target_app)
    return checks
