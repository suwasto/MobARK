"""M17 Corellium HTTP client (opt-in, off-by-default paid iOS backend).

A small httpx client over Corellium's REST API (the documented surface:
projects -> instances; instance states on/off/creating/deleting). The real
frida agent interaction (``appList``/``runFrida`` - WebSocket agent) is NOT
implemented here: that is the owner manual checkpoint (real attach = a
tester operating the Corellium UI/agent), same fake-posture rule as every
other V2 device path.

The base URL is NOT SSRF-guarded, and deliberately so (mirrors the model
backends' local-Ollama handling): Corellium's docs explicitly support ONSITE /
private-network appliances, so a tester may legitimately point at
``https://192.168.x.x``. It is user-configured, never attacker-supplied, and
the whole feature is opt-in + off by default (FR-D5a).

Errors: every failure maps to ``CorelliumError`` (a ``DynamicError`` carrying
a 502 + human message) so the router surfaces a clean response, never a raw
500. Auth: ``Authorization: Bearer <api_key>`` - Corellium's API-token auth.
"""
from __future__ import annotations

import re
from typing import Any

import httpx

from app.config import settings
from app.dynamic.base import DynamicError


class CorelliumError(DynamicError):
    """The Corellium API failed cleanly (unreachable, bad key, API error)."""


class CorelliumClient:
    """One Corellium endpoint. ``base_url`` is the Corellium root (e.g.
    ``https://app.corellium.com``); ``api_key`` is a Corellium API token."""

    def __init__(self, base_url: str, api_key: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self._timeout = float(settings.dynamic_op_timeout_seconds)

    # ---- low-level -------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
        }

    def _get(self, path: str, **params: Any) -> Any:
        url = f"{self.base_url}{path}"
        try:
            resp = httpx.get(
                url,
                headers=self._headers(),
                params=params or None,
                timeout=self._timeout,
            )
        except httpx.HTTPError as exc:
            raise CorelliumError(
                502,
                f"cannot reach Corellium at {self.base_url}: {_reason(exc)}",
            ) from exc
        if resp.status_code == 401 or resp.status_code == 403:
            raise CorelliumError(
                502,
                "Corellium rejected the API key (401/403) - check "
                "MOBARK_CORELLIUM_API_KEY / the Settings config",
            )
        if resp.status_code >= 400:
            raise CorelliumError(
                502,
                f"Corellium API error {resp.status_code} on {path}",
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise CorelliumError(
                502,
                f"Corellium returned non-JSON on {path}",
            ) from exc

    # ---- projects / instances --------------------------------------------

    def projects(self) -> list[dict]:
        """Every project the API key can see (``GET /v1/projects``)."""
        data = self._get("/v1/projects")
        return data if isinstance(data, list) else []

    def instances(self) -> list[dict]:
        """Every instance across all projects, normalized to
        ``{id, name, model, os, state}`` (``GET /v1/projects/{id}/instances``
        per project). An empty list is a clean response - no virtual devices
        - never an error."""
        rows: list[dict] = []
        for project in self.projects():
            pid = project.get("id")
            if not pid:
                continue
            data = self._get(f"/v1/projects/{pid}/instances")
            for inst in data if isinstance(data, list) else []:
                if not isinstance(inst, dict) or not inst.get("id"):
                    continue
                rows.append(
                    {
                        "id": str(inst["id"]),
                        "name": inst.get("name") or str(inst["id"]),
                        "model": inst.get("flavor"),
                        "os": inst.get("os"),
                        "state": inst.get("state", "unknown"),
                    }
                )
        return rows

    def instance_state(self, instance_id: str) -> str:
        """The instance's lifecycle state (on|off|creating|deleting|unknown)."""
        for inst in self.instances():
            if inst["id"] == instance_id:
                return inst["state"]
        raise CorelliumError(
            502,
            f"Corellium instance {instance_id!r} not found on this API key",
        )

    def reachable(self) -> bool:
        """A lightweight reachability probe: any 2xx from the projects list
        (also validates the API key). Never raises - returns False."""
        try:
            self._get("/v1/projects")
            return True
        except CorelliumError:
            return False


def _reason(exc: Exception) -> str:
    text = str(exc)
    return re.sub(r"\s+", " ", text).strip()[:300] or "unknown error"