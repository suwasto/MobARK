"""M17 Corellium-backed iOS device discovery + pre-flight.

Corellium instances are virtual iOS devices the tester picks as the attach
target (FR-D5a opt-in). ``list_devices`` surfaces every instance the
configured API key can see; ``preflight`` returns the SAME per-check boolean
shape as the physical iOS path (FR-D1), so the connect gate + UI render each
prerequisite individually, never a crash. An empty instance list is a clean
response (no virtual devices), not an error.

The real frida agent interaction (verifying a bundle is actually installed,
attaching frida) is the owner manual checkpoint - ``target_installed`` is a
best-effort True while the instance is running, documented as such.
"""
from __future__ import annotations

from app.dynamic.base import DynamicError
from app.dynamic.ios.corellium.client import CorelliumClient, CorelliumError
from app.dynamic.ios.corellium.config import get_corellium_store

# Device-id prefix that routes a Corellium instance through the iOS backend
# (a UDID never starts with this, so physical vs virtual can't collide).
PREFIX = "corellium:"


def device_id(instance_id: str) -> str:
    return f"{PREFIX}{instance_id}"


def instance_id_of(device_id: str) -> str:
    return device_id[len(PREFIX) :]


def is_corellium_device(device_id: str) -> bool:
    return device_id.startswith(PREFIX)


def _client() -> CorelliumClient:
    """The configured Corellium client, or a clean 400 when not configured
    (the store has no usable base URL + key pair - FR-D5a off-by-default)."""
    cfg = get_corellium_store().read()
    key = cfg.resolved_api_key()
    if not cfg.base_url or not key:
        raise DynamicError(
            400,
            "Corellium is not configured - set a base URL + API key "
            "(Settings, or MOBARK_CORELLIUM_BASE_URL/MOBARK_CORELLIUM_API_KEY) "
            "before listing virtual iOS devices",
        )
    return CorelliumClient(cfg.base_url, key)


def list_devices() -> list[dict]:
    """Every Corellium instance the API key can see, as iOS devices. Empty =
    no virtual devices (clean). A missing/bad config or an unreachable API
    surfaces a clean 502/400, never a crash."""
    client = _client()
    try:
        instances = client.instances()
    except CorelliumError as exc:
        raise DynamicError(exc.status, exc.message) from exc
    return [
        {
            "id": device_id(inst["id"]),
            "name": inst["name"],
            "model": inst["model"],
            "detail": _detail(inst),
        }
        for inst in instances
    ]


def _detail(inst: dict) -> str | None:
    parts = ["Corellium"]
    if inst.get("os"):
        parts.append(f"iOS {inst['os']}")
    if inst.get("state"):
        parts.append(inst["state"])
    return " · ".join(parts)


def preflight(device_id: str, target_app: str) -> dict:
    """Per-check booleans for a Corellium instance (the same FR-D1 gate shape
    as the physical iOS path). Never raises for a failed check - the ONLY
    raise is a missing config (no Corellium path at all)."""
    checks = {
        "device_reachable": False,
        "frida_server_reachable": False,
        "jailbreak_detected": False,
        "target_installed": False,
    }
    if not is_corellium_device(device_id):
        return checks
    try:
        client = _client()
        state = client.instance_state(instance_id_of(device_id))
    except (CorelliumError, DynamicError):
        return checks
    checks["device_reachable"] = state in ("on", "creating")
    # A running Corellium iOS instance is jailbroken by default (the
    # `patches: jailbroken` create default) and exposes frida through its
    # agent - so frida reachability == the instance is on.
    checks["frida_server_reachable"] = state == "on"
    checks["jailbreak_detected"] = state == "on"
    # Best-effort: verifying the bundle via the real agent (appList) is the
    # owner manual checkpoint; a running instance is reported as able to
    # install/have it until real attach happens.
    checks["target_installed"] = state == "on"
    return checks