"""M11 (V2) platform backend factory - the one seam the router + tests use.

``get_backend(platform)`` returns the platform's device backend. Tests swap
this factory (monkeypatch ``app.dynamic.client.get_backend``) for a fake
backend - the fake-device build posture - so the full HTTP surface + session
lifecycle run with zero adb/frida/pymobiledevice3. Each backend wraps the
platform modules (android/*, ios/*), which import frida/pymobiledevice3
lazily inside function bodies.
"""
from __future__ import annotations

from app.dynamic.android import attach as android_attach
from app.dynamic.android import devices as android_devices
from app.dynamic.base import DynamicError
from app.dynamic.ios import attach as ios_attach
from app.dynamic.ios import devices as ios_devices


class PlatformBackend:
    """Common contract: discovery, preflight, attach, disconnect."""

    platform: str = ""

    def list_devices(self) -> list[dict]:
        raise NotImplementedError

    def preflight(self, device_id: str, target_app: str) -> dict:
        raise NotImplementedError

    def attach(
        self, device_id: str, target_app: str, artifact_path: str | None = None
    ) -> dict:
        raise NotImplementedError

    def disconnect(self) -> None:
        raise NotImplementedError


class AndroidBackend(PlatformBackend):
    platform = "android"

    def __init__(self) -> None:
        self._handle: android_attach.AndroidAttach | None = None

    def list_devices(self) -> list[dict]:
        return android_devices.list_devices()

    def preflight(self, device_id: str, target_app: str) -> dict:
        return android_devices.preflight(device_id, target_app)

    def attach(self, device_id: str, target_app: str, artifact_path=None) -> dict:
        handle = android_attach.AndroidAttach()
        meta = handle.attach(device_id, target_app, artifact_path)
        self._handle = handle
        return meta

    def disconnect(self) -> None:
        if self._handle is not None:
            self._handle.detach()
            self._handle = None


class IosBackend(PlatformBackend):
    platform = "ios"

    def __init__(self) -> None:
        self._handle: ios_attach.IosAttach | None = None

    def list_devices(self) -> list[dict]:
        return ios_devices.list_devices()

    def preflight(self, device_id: str, target_app: str) -> dict:
        return ios_devices.preflight(device_id, target_app)

    def attach(self, device_id: str, target_app: str, artifact_path=None) -> dict:
        handle = ios_attach.IosAttach()
        meta = handle.attach(device_id, target_app)
        self._handle = handle
        return meta

    def disconnect(self) -> None:
        if self._handle is not None:
            self._handle.detach()
            self._handle = None


def get_backend(platform: str) -> PlatformBackend:
    if platform == "android":
        return AndroidBackend()
    if platform == "ios":
        return IosBackend()
    raise DynamicError(400, f"unknown platform {platform!r} (expected android|ios)")


# Re-exported for callers that want the registry without importing base twice.
__all__: list[str] = ["get_backend", "PlatformBackend"]
