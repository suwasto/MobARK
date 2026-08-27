"""M11 (V2) iOS Frida attach/detach (frida-server over SSH).

frida-python (MIT) imported lazily, never at module load. Real attach reaches
frida-server over the network (``add_remote_device``) - the operator is
expected to have frida-server running on the jailbroken device and reachable
over SSH (the ssh tunnel setup is a deployment concern; preflight's
``frida_server_reachable`` is the same endpoint's TCP probe). connection_type
is ``ssh``.
"""
from __future__ import annotations

import re
from typing import Any

from app.config import settings
from app.dynamic.base import DeviceError


class IosAttach:
    """Owns the LIVE frida session for one iOS connect; ``detach`` tears it
    down so nothing leaks into the next session."""

    def __init__(self) -> None:
        self._device: Any = None
        self._session: Any = None

    def attach(self, device_id: str, target_app: str) -> dict:
        import frida  # lazy - never imported at module load

        host, port = settings.frida_ssh_host, settings.frida_ssh_port
        try:
            mgr = frida.get_device_manager()
            self._device = mgr.add_remote_device(f"{host}:{port}")
        except Exception as exc:
            raise DeviceError(
                502,
                "cannot reach frida-server over SSH on "
                f"{host}:{port}: {_reason(exc)}",
            ) from exc
        try:
            self._session = self._device.attach(target_app)
        except Exception as exc:
            raise DeviceError(
                502,
                f"frida attach to {target_app!r} over SSH failed: "
                + _reason(exc),
            ) from exc
        try:
            import frida as _frida

            frida_version = getattr(_frida, "__version__", "unknown")
        except Exception:
            frida_version = "unknown"
        return {
            "connection_type": "ssh",
            "frida_version": frida_version,
            "target_pid": int(self._session.pid),
            # jailbreak method isn't reliably discoverable programmatically;
            # surfaced as None for the UI to leave to the tester's knowledge.
            "jailbreak_method": None,
            "device_id": device_id,
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
    return re.sub(r"\s+", " ", text).strip()[:300] or "unknown error"
