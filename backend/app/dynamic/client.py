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
from app.dynamic.ios.corellium import attach as corellium_attach
from app.dynamic.ios.corellium import client as corellium_client
from app.dynamic.ios.corellium import config as corellium_config
from app.dynamic.ios.corellium import devices as corellium_devices


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
    """iOS device backend: the physical jailbroken path (pymobiledevice3 +
    frida-over-SSH) AND, when Corellium is configured (M17, FR-D5a opt-in),
    the virtual-instance path. Discovery merges both; preflight/attach route
    by device-id prefix (``corellium:`` vs a physical UDID). A configured
    Corellium key is never silently used - only when the tester picks a
    Corellium instance as the attach device."""

    platform = "ios"

    def __init__(self) -> None:
        self._handle: ios_attach.IosAttach | None = None
        self._core_handle: corellium_attach.CorelliumAttach | None = None

    def list_devices(self) -> list[dict]:
        physical: list[dict] = []
        physical_unavailable = False
        try:
            physical = ios_devices.list_devices()
        except DynamicError:
            # pymobiledevice3 absent/unreachable: fall through and still list
            # Corellium instances when configured (a Corellium-only tester has
            # no physical device path). The 502 surfaces only when there is
            # NOTHING to list instead.
            physical = []
            physical_unavailable = True
        core: list[dict] = []
        store = corellium_config.get_corellium_store()
        if store.configured():
            try:
                core = corellium_devices.list_devices()
            except DynamicError:
                core = []
        if not physical and not core:
            # An EMPTY clean physical list (pmd3 ok, zero devices) is a clean
            # response (the M11 empty-is-clean convention) - only a missing
            # tool (physical_unavailable) with nothing configured re-raises,
            # so a completely broken iOS path stays honest, never a silent 200.
            if physical_unavailable:
                raise DynamicError(
                    502,
                    "no iOS devices available - no physical device "
                    "(pymobiledevice3 unreachable) and no Corellium instances "
                    "configured",
                )
        return physical + core

    def preflight(self, device_id: str, target_app: str) -> dict:
        if corellium_devices.is_corellium_device(device_id):
            return corellium_devices.preflight(device_id, target_app)
        return ios_devices.preflight(device_id, target_app)

    def attach(self, device_id: str, target_app: str, artifact_path=None) -> dict:
        if corellium_devices.is_corellium_device(device_id):
            handle = corellium_attach.CorelliumAttach()
            cfg = corellium_config.get_corellium_store().read()
            key = cfg.resolved_api_key()
            client = corellium_client.CorelliumClient(cfg.base_url, key)
            meta = handle.attach(device_id, target_app, client)
            self._core_handle = handle
            return meta
        handle = ios_attach.IosAttach()
        meta = handle.attach(device_id, target_app)
        self._handle = handle
        return meta

    def disconnect(self) -> None:
        if self._handle is not None:
            self._handle.detach()
            self._handle = None
        if self._core_handle is not None:
            self._core_handle.detach()
            self._core_handle = None


def get_backend(platform: str) -> PlatformBackend:
    if platform == "android":
        return AndroidBackend()
    if platform == "ios":
        return IosBackend()
    raise DynamicError(400, f"unknown platform {platform!r} (expected android|ios)")


# Re-exported for callers that want the registry without importing base twice.
__all__: list[str] = ["get_backend", "PlatformBackend"]
