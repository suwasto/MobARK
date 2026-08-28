"""M13 (V2) Android device-mirror frame source (continuous scrcpy relay).

Android is a CONTINUOUS stream (FR-D7): the device screen is relayed
scrcpy-protocol-style and each frame is pushed to the session's
``MirrorRelay`` with ``polled=False``. The transport here is the adb-tunnel
that carries H.264-ish NAL frames (the same adb path M11 uses); real
encoding/demux is an owner manual checkpoint - this module owns the 
``*_CMD``-guarded tool resolution + the fake/synthetic source the test
posture drives, so the full relay surface runs with zero device.
"""
from __future__ import annotations

from app.analysis.subprocess import resolve_binary
from app.dynamic.base import DeviceError

# Real H.264 NAL frames are decoded + demuxed on the owner-manual path; the
# synthetic generator emits plausible-shaped blobs for the fake posture.
CODEC = "h264"


def _scrcpy() -> list[str]:
    binary = resolve_binary("scrcpy", "scrcpy_cmd")
    if not binary:
        raise DeviceError(
            502,
            "scrcpy is not available - install scrcpy (or set MOBARK_SCRCPY_CMD); "
            "Android device mirroring needs it",
        )
    return [binary]


def synthetic_frame(seq: int) -> bytes:
    """A deterministic, plausible H.264-ish blob (fake posture). Real frames
    come from the scrcpy/adb stream at runtime."""
    header = b"\x00\x00\x00\x01\x67\x42\xc0"  # NAL SPS-ish prefix
    return header + seq.to_bytes(4, "big") + b"\x00" * 64


class AndroidSource:
    """Real-shaped continuous mirror source (FR-D7 ``continuous=True``).

    Resolution + missing-tool handling live here; on-device capture is an
    owner manual checkpoint. In the fake posture ``publish_loop`` is driven
    by :func:`synthetic_source` (or the HTTP publish fallback).
    """

    continuous = True
    codec = CODEC
    poll_interval_seconds: int | None = None  # continuous - no poll cadence

    def __init__(self) -> None:
        self._binary: str | None = None

    def check(self) -> None:
        """Resolve + verify the tool is present (never a crash - a clean
        DynamicError(502) when scrcpy is missing)."""
        if self._binary is None:
            self._binary = _scrcpy()
        return None

    def publish_loop(self, publish) -> None:
        """Yield frames to the relay. Real capture is owner-manual; the
        contract is: resolve the tool, then stream frames via ``publish``."""
        self.check()
        for seq in range(1, 1000):
            publish(synthetic_frame(seq), codec=self.codec, polled=False)


def make_source() -> AndroidSource:
    return AndroidSource()