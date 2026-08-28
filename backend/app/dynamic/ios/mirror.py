"""M13 (V2) iOS device-mirror frame source (polled screenshotr relay).

iOS is POLLED, not a continuous stream (FR-D7): frames come from the
``screenshotr`` screen-capture service at ``mirror_poll_interval_seconds``
and each is handed to the session's ``MirrorRelay`` with ``polled=True``, so
the UI can honestly say "polled frames - not a continuous stream". The
capture goes through pymobiledevice3 (the ``*_CMD`` subprocess pattern M11
uses); this build keeps the resolution + shape-guarded shell + a synthetic
generator for the fake posture.
"""
from __future__ import annotations

from app.config import settings

CODEC = "jpeg"


def _screenshot_cmd() -> list[str]:
    import app.dynamic.ios.devices as dev

    base = dev._pmd3()  # noqa: SLF001 - the shared pmd3 resolution
    return base + ["screenshot"]


def synthetic_frame(seq: int) -> bytes:
    """A plausible JPEG-shaped blob for the fake posture. Real frames come
    from ``pymobiledevice3 screenshot`` at runtime."""
    # JPEG SOI marker + length-padded payload (not a real image - fake).
    return b"\xff\xd8\xff\xe0" + seq.to_bytes(4, "big") + b"\x00" * 128


class ScreenshotrSource:
    """Real-placed polled mirror source (``continuous=False``).

    Polls ``screenshotr`` at ``settings.mirror_poll_interval_seconds``;
    missing pymobiledevice3 is a clean DeviceError (502), never a crash. On
    the actual device this is owner-manual; the fake posture drives it with
    :func:`synthetic_frame` / the HTTP publish fallback.
    """

    continuous = False
    polled = True
    codec = CODEC

    def __init__(self) -> None:
        self._poll_interval = settings.mirror_poll_interval_seconds
        self._cmd: list[str] | None = None

    @property
    def poll_interval_seconds(self) -> int:
        return self._poll_interval

    def check(self) -> None:
        """Resolve + verify the capture tool is present; a clean
        DeviceError(502) when pymobiledevice3 is missing."""
        if self._cmd is None:
            self._cmd = _screenshot_cmd()
        return None

    def publish_loop(self, publish) -> None:
        """Poll: capture a frame and push it to the relay, sleeping the poll
        interval between captures. Real path is owner-manual; here it just
        drives the synthetic producer so the relay/WS surface is testable."""
        self.check()
        for seq in range(1, 1000):
            publish(synthetic_frame(seq), codec=self.codec, polled=True)
            # Real: time.sleep(self._poll_interval) before the next capture.


def make_source() -> ScreenshotrSource:
    return ScreenshotrSource()