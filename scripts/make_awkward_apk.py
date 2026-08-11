#!/usr/bin/env python3
"""Craft the M8 Phase E awkward-APK fixture.

An APK-shaped ZIP that gets PAST upload but trips apktool mid-decode: the
``AndroidManifest.xml`` is plain TEXT (apktool expects binary AXML) and
``resources.arsc`` is garbage (no valid resource table). This is the
deterministic stand-in for the real-world "resource clash / edge-case
bytecode" APKs apktool chokes on - used by the containerized contract-style
e2e to verify the fail-loudly DECODE contract with the REAL apktool binary
(host unit tests mock the subprocess boundary; see test_smali_api.py).
**Keep in sync with the ``_craft_awkward_apk`` helper in test_smali_api.py**
(the host test replicates the same ZIP contents).

Usage: python scripts/make_awkward_apk.py <out.apk>
"""
from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path


def craft(path: str | Path) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        # A text manifest is NOT the binary AXML apktool's parser expects.
        z.writestr("AndroidManifest.xml", '<?xml version="1.0"?><manifest/>\n')
        # A corrupt resource table - aapt2/apktool fail loading it.
        z.writestr("resources.arsc", b"\x02garbage-not-a-resource-table" + b"\x00" * 64)
        z.writestr("classes.dex", b"dex\n035\x00garbage")
    Path(path).write_bytes(buf.getvalue())


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: make_awkward_apk.py <out.apk>")
    craft(sys.argv[1])
    print(f"awkward APK written to {sys.argv[1]}")
