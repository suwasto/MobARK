"""M11 (V2) Android Frida attach/detach.

frida-python (MIT) is imported ONLY inside the function bodies - never at
module load - so fake-device test doubles swap the whole backend out without
touching frida. Real attach: ensure the target app is installed (install from
the scan artifact when available, else a clear error), reach the device's
frida-server, attach by package name, and capture the FR-D3 identity
(frida_version, target_pid, root_status).
"""
from __future__ import annotations

import re
from typing import Any

from app.analysis.subprocess import run_tool
from app.config import settings
from app.dynamic.android.devices import _adb, _target_installed
from app.dynamic.base import DeviceError


def _install_if_missing(
    device_id: str, target_app: str, artifact_path: str | None
) -> None:
    """Install the target app if it isn't already on the device. When the
    scan has an uploaded APK artifact, install from it (``adb install -r``);
    otherwise raise a clear, self-explaining error."""
    if _target_installed(device_id, target_app):
        return
    if not artifact_path:
        raise DeviceError(
            409,
            f"target app {target_app!r} is not installed on {device_id} and "
            "no APK artifact is available to install it - install the app on "
            "the device first (auto-install from the scan artifact is wired "
            "when an APK is present)",
        )
    cmd = _adb() + ["-s", device_id, "install", "-r", artifact_path]
    result = run_tool(cmd, timeout=settings.dynamic_op_timeout_seconds)
    if result.returncode != 0:
        tail = (result.stderr or result.stdout or "").strip().splitlines()
        raise DeviceError(
            502,
            "adb install failed: "
            + (tail[-1] if tail else "unknown error"),
        )


def _root_status(device_id: str) -> bool:
    """``adb -s <id> shell id -u`` == ``0`` (rooted process)."""
    cmd = _adb() + ["-s", device_id, "shell", "id", "-u"]
    result = run_tool(cmd, timeout=settings.dynamic_op_timeout_seconds)
    return result.returncode == 0 and result.stdout.strip() == "0"


class AndroidAttach:
    """Owns the LIVE frida session for one Android connect; ``detach`` tears
    it down so nothing leaks into the next session."""

    def __init__(self) -> None:
        self._device: Any = None
        self._session: Any = None

    def attach(
        self,
        device_id: str,
        target_app: str,
        artifact_path: str | None = None,
    ) -> dict:
        _install_if_missing(device_id, target_app, artifact_path)
        import frida  # lazy - never imported at module load

        if not _target_installed(device_id, target_app):
            raise DeviceError(
                409, f"target app {target_app!r} is not installed on {device_id}"
            )
        try:
            self._device = frida.get_device(device_id, timeout=10)
        except frida.InvalidArgumentError as exc:
            # The device id may be a serial frida doesn't know - fall back to
            # the USB device (the common rooted-phone/emulator case).
            try:
                self._device = frida.get_usb_device(timeout=10)
            except Exception as exc2:
                raise DeviceError(
                    502,
                    "cannot reach frida-server on the device - is frida-server "
                    "running (via adb)? " + _reason(exc2),
                ) from exc
        try:
            self._session = self._device.attach(target_app)
        except Exception as exc:
            raise DeviceError(
                502,
                f"frida attach to {target_app!r} failed: " + _reason(exc),
            ) from exc
        try:
            import frida as _frida

            frida_version = getattr(_frida, "__version__", "unknown")
        except Exception:
            frida_version = "unknown"
        return {
            "connection_type": "adb",
            "frida_version": frida_version,
            "target_pid": int(self._session.pid),
            "root_status": _root_status(device_id),
        }

    def detach(self) -> None:
        if self._session is not None:
            try:
                self._session.detach()
            except Exception:
                pass
            self._session = None
        self._device = None


def _reason(exc: Exception) -> str:
    text = str(exc)
    # Trim frida's noisy "[Errno ...] /usr/lib/..." traces to the head clause.
    return re.sub(r"\s+", " ", text).strip()[:300] or "unknown error"
