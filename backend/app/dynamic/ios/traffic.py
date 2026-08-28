"""M14 (V2) iOS traffic-capture source (mitmdump + config-profile CA trust).

iOS captures decrypted traffic once the ATS/pinning bypass is active AND
mitmproxy's CA is trusted via an installed CONFIGURATION PROFILE (FR-D14a) -
alongside the Frida-based bypass, unlike Android's device-settings path.
Each flow is published into the session's ``TrafficLog`` as
``{method, path, status}`` (FR-D12).

Real capture against a jailbroken device is an owner manual checkpoint; this
module owns the ``*_CMD``-guarded resolution, the FR-D14a CA-trust surface
(``ca_trusted`` / ``ca_profile_path``), and a synthetic generator for the
fake posture, so the full traffic surface runs with zero mitmdump.
"""
from __future__ import annotations

from app.analysis.subprocess import resolve_binary
from app.dynamic.base import DeviceError


def _mitmdump() -> list[str]:
    binary = resolve_binary("mitmdump", "mitmproxy_cmd")
    if not binary:
        raise DeviceError(
            502,
            "mitmdump is not available - install mitmproxy (or set "
            "MOBARK_MITMPROXY_CMD); iOS traffic capture needs it",
        )
    return [binary]


class IosTrafficSource:
    """Real-shaped iOS capture source (mitmdump + config-profile CA trust).

    ``check`` resolves the tool (a clean DeviceError(502) when mitmdump is
    missing); ``ca_trusted`` reports whether the mitmproxy CA config profile
    is installed + trusted on the device (FR-D14a - False until the tester
    completes the profile step); ``ca_profile_path`` locates the
    ``.mobileconfig`` artifact to serve to the tester; ``capture_loop``
    publishes flows to the TrafficLog. On a real device this is owner-manual;
    the fake posture drives it via the HTTP fallback / synthetic producer.
    """

    def __init__(self) -> None:
        self._binary: list[str] | None = None

    def check(self) -> None:
        """Resolve + verify mitmdump is present; a clean DeviceError(502)
        when it is missing."""
        if self._binary is None:
            self._binary = _mitmdump()
        return None

    def ca_trusted(self) -> bool:
        """Has the mitmproxy CA config profile been installed + trusted on
        the device? FR-D14a: the traffic panel must show 'trust not
        installed' until this is True. Real device check is owner-manual;
        the fake posture reports False (not installed)."""
        return False

    def ca_profile_path(self) -> str | None:
        """Path to the mitmproxy CA config profile (``.mobileconfig``) for
        the tester to install on the device. Fake posture: absent (None)
        until the real CA artifact exists - ``ca-status`` then reports
        ``profile_available=False`` and ``ca-profile`` 404s cleanly."""
        return None

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


def make_source() -> IosTrafficSource:
    return IosTrafficSource()