"""Entitlement extraction from the embedded code-signature blob (no ``codesign``).

LIEF exposes the embedded signature as ``code_signature``; we carve the
entitlements out of the signature blob ourselves.

The embedded signature is a ``0xfade0cc0`` **superblob** whose index entries
are ``(slot, offset)`` pairs - slot numbers, not magic values:

- slot ``5`` (``CSSLOT_ENTITLEMENTS``) - the entitlements as a *plain* plist
  (XML or binary) under a ``0xfade7171`` blob header. This is the common case
  for ad-hoc / Xcode-signed builds and is the primary carve path.
- slot ``7`` (``CSSLOT_DER_ENTITLEMENTS``) - the entitlements as a
  DER-encoded plist under a ``0xfade7172`` header (best-effort).
- slot ``0x10000`` (``CSSLOT_CMS_SIGNATURE``) - a ``0xfade0b01`` blob wrapper
  around CMS SignedData, where entitlements may appear only as signed
  attribute OID ``1.2.840.113635.100.9.1``. We parse the CMS with a small
  BER walker (handles the indefinite-length encoding Apple uses) and take
  the first attribute value that loads as a plist.

This is deliberately best-effort for ad-hoc/resigned IPAs and *partial* for
FairPlay-encrypted App Store binaries - both are surfaced as findings, not
just docs lines.
"""
from __future__ import annotations

import plistlib
import struct
from pathlib import Path

from app.analysis.base import TOOL_LIEF, FindingOut, StageResult
from app.analysis.ios import macho

# Superblob / sub-blob magic values (Apple's codesign.h).
CSMAGIC_SUPERBLOB = 0xFADE0CC0
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
CSMAGIC_DER_ENTITLEMENTS = 0xFADE7172
CSMAGIC_BLOBWRAPPER = 0xFADE0B01

# Superblob index slot numbers.
CSSLOT_ENTITLEMENTS = 0x00000005
CSSLOT_DER_ENTITLEMENTS = 0x00000007
CSSLOT_CMS_SIGNATURE = 0x00010000

ENTITLEMENTS_OID = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x63, 0x64, 0x09, 0x01])

# Entitlements whose presence is worth a finding (shipping-app hygiene).
# Value is ``(label, severity)`` - per-entitlement calibration (owner
# review, Aug 7): get-task-allow is a debugger-attach exposure on a
# shipping app (medium); aps-environment is routine, stays low.
NOTABLE_ENTITLEMENTS = {
    "get-task-allow": ("debugger attachment allowed (get-task-allow)", "medium"),
    "com.apple.security.get-task-allow": (
        "debugger attachment allowed (get-task-allow)",
        "medium",
    ),
    "aps-environment": ("push notifications environment", "low"),
}


def _signature_blob(binary, exe_path: Path) -> bytes | None:
    """Fetch the embedded code-signature blob bytes for one slice.

    LIEF exposes ``code_signature.data`` (often just the blob header) plus
    ``data_offset``/``data_size`` pointing at the full blob inside the file -
    read the file slice when that is available, falling back to ``.data``.
    """
    cs = binary.code_signature
    if cs is None:
        return None
    if cs.data_size and cs.data_size > len(cs.data) and cs.data_offset:
        try:
            with exe_path.open("rb") as fh:
                fh.seek(cs.data_offset)
                blob = fh.read(cs.data_size)
            if len(blob) == cs.data_size:
                return blob
        except OSError:
            pass
    return bytes(cs.data)


def analyze_app_binary(app_root: Path) -> StageResult:
    """Extract entitlements from the app's main executable signature blob."""
    result = StageResult()
    exe_path = macho._find_main_executable(app_root)
    if exe_path is None:
        result.errors.append("no main executable - entitlement stage skipped")
        return result

    try:
        binaries = macho._load_binaries(exe_path)
    except macho.MachoError as exc:
        result.errors.append(str(exc))
        return result

    # Entitlements are per-slice; merge the set across slices (first wins).
    merged: dict = {}
    sources: set[str] = set()
    for binary in binaries:
        if not binary.has_code_signature or binary.code_signature is None:
            continue
        blob = _signature_blob(binary, exe_path)
        entitlements = carve_entitlements(blob)
        if entitlements is None:
            continue
        merged.update(entitlements)
        sources.add("signature-blob")

    result.meta["entitlements"] = merged
    result.meta["entitlements_source"] = sorted(sources)

    for ent in sorted(merged):
        if ent in NOTABLE_ENTITLEMENTS:
            label, severity = NOTABLE_ENTITLEMENTS[ent]
            result.findings.append(
                FindingOut(
                    tool=TOOL_LIEF,
                    title=f"Notable entitlement granted: {label}",
                    severity=severity,
                    category="MASVS-PLATFORM-1",
                    detail={"entitlement": ent},
                )
            )

    # M4 Layer 1: the full entitlement set is agent context (answer source for
    # "what entitlements does this app have") - not just the notable ones.
    if merged:
        result.findings.append(
            FindingOut(
                tool=TOOL_LIEF,
                title=f"Entitlements granted ({len(merged)})",
                severity="info",
                category="MASVS-PLATFORM-1",
                detail={"entitlements": {k: v for k, v in sorted(merged.items())}},
            )
        )

    if not sources:
        result.meta["entitlements_carved"] = False
        result.findings.append(
            FindingOut(
                tool=TOOL_LIEF,
                title="Entitlements not extractable - code-signature coverage is best-effort",
                severity="info",
                category="MASVS-PLATFORM-1",
                detail={
                    "note": "No entitlement blob found in the embedded signature. "
                    "Ad-hoc/resigned IPAs may use unusual signature layouts; "
                    "App Store FairPlay binaries are encrypted.",
                },
            )
        )
    return result


def carve_entitlements(sig_data: bytes) -> dict | None:
    """Return the entitlements dict from an embedded signature blob, or None.

    The superblob index entries are ``(slot, offset)`` pairs relative to the
    start of the superblob; the sub-blob at each offset carries its own magic
    header. Slots 5/7 (entitlements) and 0x10000 (CMS signature) are probed.
    """
    if len(sig_data) < 12:
        return None
    magic, _length, count = struct.unpack_from(">III", sig_data, 0)
    if magic != CSMAGIC_SUPERBLOB:
        return None

    for i in range(count):
        off = 12 + i * 8
        if off + 8 > len(sig_data):
            break
        slot, blob_offset = struct.unpack_from(">II", sig_data, off)
        if slot == CSSLOT_ENTITLEMENTS:
            ent = _parse_entitlements_blob(
                sig_data, blob_offset, CSMAGIC_EMBEDDED_ENTITLEMENTS
            )
            if ent is not None:
                return ent
        elif slot == CSSLOT_DER_ENTITLEMENTS:
            ent = _parse_entitlements_blob(
                sig_data, blob_offset, CSMAGIC_DER_ENTITLEMENTS
            )
            if ent is not None:
                return ent
        elif slot == CSSLOT_CMS_SIGNATURE:
            ent = _parse_cms(sig_data, blob_offset)
            if ent is not None:
                return ent
    return None


def _parse_entitlements_blob(data: bytes, offset: int, blob_magic: int) -> dict | None:
    """A superblob entitlements sub-blob: magic, length, then a plain plist."""
    if offset + 8 > len(data):
        return None
    magic, length = struct.unpack_from(">II", data, offset)
    if magic != blob_magic or length < 8:
        return None
    payload = data[offset + 8 : min(offset + length, len(data))]
    try:
        return plistlib.loads(payload)
    except plistlib.InvalidFileException:
        return None


def _parse_cms(data: bytes, offset: int) -> dict | None:
    """Walk the CMS blob wrapper for the entitlements attribute OID.

    The CMS slot is a ``0xfade0b01`` blob wrapper whose content is CMS
    SignedData (often BER with indefinite-length segments). We walk it with
    the tolerant ``_find_oid_values`` and try each OCTET STRING value under
    the entitlements OID as a plist.
    """
    if offset + 8 > len(data):
        return None
    magic, length = struct.unpack_from(">II", data, offset)
    if magic != CSMAGIC_BLOBWRAPPER or length < 8:
        return None
    cms = data[offset + 8 : min(offset + length, len(data))]
    hits = _find_oid_values(cms, ENTITLEMENTS_OID)
    for hit in hits:
        try:
            return plistlib.loads(hit)
        except plistlib.InvalidFileException:
            continue
    return None


def _read_tlv(data: bytes, offset: int) -> tuple[int, int, int | None, bool] | None:
    """Return (tag, value_offset, length, indefinite) at ``offset``.

    ``length`` is None when the value uses BER indefinite-length encoding
    (Apple's CMS does); use ``_tlv_end`` to resolve such a value's span.
    """
    if offset + 2 > len(data):
        return None
    tag = data[offset]
    length_byte = data[offset + 1]
    if length_byte == 0x80:
        return tag, offset + 2, None, True
    if length_byte < 0x80:
        length = length_byte
        header = 2
    else:
        num_bytes = length_byte & 0x7F
        if num_bytes == 0 or num_bytes > 4 or offset + 2 + num_bytes > len(data):
            return None
        length = int.from_bytes(data[offset + 2 : offset + 2 + num_bytes], "big")
        header = 2 + num_bytes
    if offset + header + length > len(data):
        return None
    return tag, offset + header, length, False


def _find_eoc(data: bytes, start: int) -> int | None:
    """Offset of the end-of-contents marker (00 00) closing an indefinite value."""
    i = start
    while i + 1 < len(data):
        if data[i] == 0x00 and data[i + 1] == 0x00:
            return i
        end = _tlv_end(data, i)
        if end is None or end <= i:
            i += 1
        else:
            i = end
    return None


def _tlv_end(data: bytes, offset: int) -> int | None:
    """Offset just past the TLV at ``offset`` (where the next sibling starts)."""
    tlv = _read_tlv(data, offset)
    if tlv is None:
        return None
    _tag, voff, length, indefinite = tlv
    if not indefinite:
        return voff + length
    eoc = _find_eoc(data, voff)
    return eoc + 2 if eoc is not None else None


def _find_oid_values(data: bytes, oid: bytes) -> list[bytes]:
    """Return the content bytes of OCTET STRINGs directly under the OID.

    Walks every SEQUENCE; when the next TLV is the target OID, the TLV after
    it is the SET of values, and we take each child OCTET STRING's content.
    Handles BER indefinite-length nesting via ``_tlv_end``.
    """
    hits: list[bytes] = []

    def walk(start: int, end: int) -> None:
        i = start
        while i < end:
            tlv = _read_tlv(data, i)
            if tlv is None:
                return
            tag, voff, _vlen, _indefinite = tlv
            tlv_end = _tlv_end(data, i)
            if tlv_end is None:
                return
            if tag == 0x30:  # SEQUENCE
                inner_end = min(tlv_end, end)
                j = voff
                inner = _read_tlv(data, j)
                if (
                    inner is not None
                    and inner[0] == 0x06  # OBJECT IDENTIFIER
                    and data[inner[1] : inner[1] + inner[2]] == oid
                ):
                    set_tlv = _read_tlv(data, inner[1] + inner[2])
                    if set_tlv is not None and set_tlv[0] == 0x31:  # SET OF
                        set_end = _tlv_end(data, inner[1] + inner[2])
                        if set_end is not None:
                            k = set_tlv[1]
                            while k < set_end:
                                value_tlv = _read_tlv(data, k)
                                if value_tlv is None:
                                    break
                                if value_tlv[0] == 0x04:  # OCTET STRING
                                    hits.append(
                                        data[value_tlv[1] : value_tlv[1] + value_tlv[2]]
                                    )
                                value_end = _tlv_end(data, k)
                                if value_end is None:
                                    break
                                k = value_end
                    walk(inner[1] + inner[2], inner_end)
                else:
                    walk(voff, inner_end)
                i = tlv_end
            else:
                i = tlv_end

    walk(0, len(data))
    return hits
