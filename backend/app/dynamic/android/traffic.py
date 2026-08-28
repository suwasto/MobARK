"""M14 (V2) Android traffic-capture source (mitmdump + device-settings proxy).

Android captures decrypted traffic once the pinning bypass is active: the
device routes through mitmdump (subprocess, never imported - the ``*_CMD``
pattern), the CA is trusted via DEVICE SETTINGS (``adb shell settings put
global http_proxy`` - the device-settings path, NOT the iOS config profile),
and each flow is published into the session's ``TrafficLog`` as
``{method, path, status}`` (FR-D12).

Real capture against a rooted device/emulator is an owner manual checkpoint;
this module owns the ``*_CMD``-guarded resolution, the proxy-set command
shape, and a synthetic generator for the fake posture, so the full traffic
surface runs with zero mitmdump.
"""
from __future__ import annotations

from app.analysis.subprocess import resolve_binary, run_tool
from app.config import settings
from app.dynamic.android.devices import _adb
from app.dynamic.base import DeviceError


def _mitmdump() -> list[str]:
    binary = resolve_binary("mitmdump", "mitmproxy_cmd")
    if not binary:
        raise DeviceError(
            502,
            "mitmdump is not available - install mitmproxy (or set "
            "MOBARK_MITMPROXY_CMD); Android traffic capture needs it",
        )
    return [binary]


def _proxy_cmd(device_id: str, port: int) -> list[str]:
    """The device-settings command that points the device's HTTP(S) traffic
    at mitmdump (the CA is trusted via device settings, not a profile)."""
    return _adb() + [
        "-s",
        device_id,
        "shell",
        "settings",
        "put",
        "global",
        "http_proxy",
        f"127.0.0.1:{port}",
    ]


class AndroidTrafficSource:
    """Real-shaped Android capture source (mitmdump + device-settings CA).

    ``check`` resolves the tool (a clean DeviceError(502) when mitmdump is
    missing, never a crash); ``set_device_proxy`` issues the adb http_proxy
    command; ``capture_loop`` publishes flows to the TrafficLog. On a real
    device this is owner-manual; the fake posture drives it via the HTTP
    fallback / synthetic producer.
    """

    def __init__(self, device_id: str = "") -> None:
        self._device_id = device_id
        self._binary: list[str] | None = None

    def check(self) -> None:
        """Resolve + verify mitmdump is present; a clean DeviceError(502)
        when it is missing."""
        if self._binary is None:
            self._binary = _mitmdump()
        return None

    def set_device_proxy(self) -> None:
        """Point the device's HTTP(S) traffic at mitmdump via device
        settings. Real capture is owner-manual; this issues the adb command
        and fails loudly (502) when adb rejects it."""
        cmd = _proxy_cmd(self._device_id, settings.mitmproxy_listen_port)
        result = run_tool(cmd, timeout=settings.dynamic_op_timeout_seconds)
        if result.returncode != 0:
            tail = (result.stderr or result.stdout or "").strip().splitlines()
            raise DeviceError(
                502,
                "adb http_proxy set failed: "
                + (tail[-1] if tail else "unknown error"),
            )

    def capture_loop(self, publish) -> None:
        """Publish flows to the TrafficLog. Real mitmdump flow-dump parsing
        is owner-manual; here it drives the synthetic producer so the log/API
        surface is testable with zero mitmdump."""
        self.check()
        for seq in range(1, 1000):
            publish(
                method="GET",
                path=f"/synthetic/{seq}",
                host="example.com",
                status=200,
                size_bytes=128,
            )


def make_source(device_id: str | None = None) -> AndroidTrafficSource:
    return AndroidTrafficSource(device_id or "")