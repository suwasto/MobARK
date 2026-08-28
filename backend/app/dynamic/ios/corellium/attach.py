"""M17 Corellium-backed iOS attach (real frida attach = owner checkpoint).

The durable ``connection_type=corellium`` / ``corellium_enabled=True`` identity
is written on connect. Real frida injection against a Corellium instance goes
through the Corellium agent (``runFrida`` / the instance's frida console) -
that live interaction is the owner manual checkpoint, same fake-posture rule
as every other V2 device path. ``attach`` resolves + validates the instance
(real API call) and returns the FR-D3 meta; ``detach`` tears nothing live down
(there is no held session until the checkpoint is exercised).
"""
from __future__ import annotations

from app.dynamic.base import DynamicError
from app.dynamic.ios.corellium.client import CorelliumClient, CorelliumError
from app.dynamic.ios.corellium.devices import instance_id_of, is_corellium_device


class CorelliumAttach:
    """Owns the (fake-posture) Corellium attach for one connect; ``detach``
    clears the handle so nothing leaks into the next session."""

    def __init__(self) -> None:
        self._instance_id: str | None = None

    def attach(self, device_id: str, target_app: str, client: CorelliumClient) -> dict:
        if not is_corellium_device(device_id):
            raise DynamicError(
                400,
                f"device {device_id!r} is not a Corellium instance "
                f"(expected a 'corellium:'-prefixed device id)",
            )
        instance_id = instance_id_of(device_id)
        try:
            state = client.instance_state(instance_id)
        except CorelliumError as exc:
            raise DynamicError(exc.status, exc.message) from exc
        if state != "on":
            raise DynamicError(
                502,
                f"Corellium instance {instance_id!r} is not running "
                f"(state={state}) - start it before attaching",
            )
        self._instance_id = instance_id
        return {
            "connection_type": "corellium",
            "corellium_enabled": True,
            "frida_version": "corellium-agent",  # surfaced honestly: the real
            # version comes from the agent at the owner manual checkpoint.
            "target_pid": None,
            "jailbreak_method": "corellium",
            "device_id": device_id,
        }

    def detach(self) -> None:
        self._instance_id = None