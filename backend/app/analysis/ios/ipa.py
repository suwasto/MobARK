"""IPA unpack pipeline: ``.ipa`` -> ``Payload/*.app`` tree.

Pure ``zipfile`` — no external tooling. Mirrors M1's preflight policy:
malformed archives abort the scan with a specific ``ScanAborted`` reason.
"""
from __future__ import annotations

import plistlib
import zipfile
from dataclasses import dataclass
from pathlib import Path


class IpaError(Exception):
    """A malformed/unusable IPA archive."""


# Guard against decompression bombs: cap total uncompressed size.
MAX_UNPACKED_BYTES = 2 * 1024 * 1024 * 1024  # 2 GiB


def _check_unpacked_size(archive: zipfile.ZipFile) -> None:
    """Reject archives whose members would decompress beyond the cap."""
    total = sum((info.file_size or 0) for info in archive.infolist())
    if total > MAX_UNPACKED_BYTES:
        raise IpaError(
            f"archive too large to unpack ({total / (1024**3):.1f} GiB "
            f"> {MAX_UNPACKED_BYTES / (1024**3):.0f} GiB)"
        )


@dataclass
class IpaBundle:
    """Top-level metadata about the app bundle extracted from an IPA."""

    app_dir_name: str  # e.g. "InsecureBank.app" (relative to Payload/)
    bundle_identifier: str | None
    bundle_name: str | None  # CFBundleName
    display_name: str | None  # CFBundleDisplayName
    version: str | None  # CFBundleShortVersionString


def find_app_dir(archive: zipfile.ZipFile) -> str:
    """Locate the ``Payload/*.app`` directory entry inside an IPA.

    :raises IpaError: if the archive has no usable ``Payload`` directory.
    """
    try:
        names = archive.namelist()
    except zipfile.BadZipFile as exc:
        raise IpaError(f"corrupt archive: {exc}") from exc

    candidates: list[str] = []
    for name in names:
        parts = name.split("/")
        if len(parts) >= 2 and parts[0] == "Payload" and parts[1].endswith(".app"):
            candidates.append(parts[1])
    if not candidates:
        raise IpaError(
            "no Payload/*.app directory found — not a valid iOS IPA"
        )
    return candidates[0]


def extract(ipa_path: Path, dest_dir: Path) -> IpaBundle:
    """Extract the app bundle from an IPA into ``dest_dir``.

    Extracts the whole archive (Payload/ tree) so downstream stages can scan
    the bundle resources. Returns the bundle metadata parsed from its
    Info.plist.

    :raises IpaError: on malformed/non-zip input or a missing Info.plist.
    """
    if not ipa_path.is_file():
        raise IpaError(f"IPA not found: {ipa_path}")
    if not zipfile.is_zipfile(ipa_path):
        raise IpaError("not a valid ZIP archive")

    dest_dir.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(ipa_path) as archive:
            app_dir_name = find_app_dir(archive)
            _check_unpacked_size(archive)
            archive.extractall(dest_dir)
    except RuntimeError as exc:
        # Encrypted zip members raise RuntimeError on read, not BadZipFile.
        raise IpaError("encrypted IPA archives are not supported") from exc
    except (zipfile.BadZipFile, OSError) as exc:
        raise IpaError(f"corrupt archive: {exc}") from exc

    app_root = dest_dir / "Payload" / app_dir_name
    info_plist_path = app_root / "Info.plist"
    if not info_plist_path.is_file():
        raise IpaError(f"app bundle missing Info.plist: {info_plist_path}")

    metadata: dict = {}
    try:
        with info_plist_path.open("rb") as fh:
            metadata = plistlib.load(fh)
    except (plistlib.InvalidFileException, OSError) as exc:
        raise IpaError(f"cannot parse Info.plist: {exc}") from exc

    return IpaBundle(
        app_dir_name=app_dir_name,
        bundle_identifier=metadata.get("CFBundleIdentifier"),
        bundle_name=metadata.get("CFBundleName"),
        display_name=metadata.get("CFBundleDisplayName"),
        version=metadata.get("CFBundleShortVersionString"),
    )
