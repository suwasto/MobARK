"""Unit tests for ``ios/entitlements.py`` signature-blob carving.

Builds synthetic embedded-signature superblobs by hand (struct) so the carve
logic is tested against the real on-disk layout (slot-number index entries +
``0xfade7171`` / ``0xfade0b01`` blob magics).
"""
import plistlib
import struct

from app.analysis.ios.entitlements import (
    CSMAGIC_BLOBWRAPPER,
    CSMAGIC_EMBEDDED_ENTITLEMENTS,
    CSMAGIC_SUPERBLOB,
    CSSLOT_CMS_SIGNATURE,
    CSSLOT_ENTITLEMENTS,
    carve_entitlements,
)


def _superblob(*slots: tuple[int, bytes]) -> bytes:
    """Pack a superblob from (slot, blob) pairs with correct index offsets."""
    body = b"".join(blob for _slot, blob in slots)
    offsets: list[tuple[int, int]] = []
    off = 12 + 8 * len(slots)
    for slot, blob in slots:
        offsets.append((slot, off))
        off += len(blob)
    index = b"".join(struct.pack(">II", slot, o) for slot, o in offsets)
    body_len = 12 + 8 * len(slots) + len(body)
    return struct.pack(">III", CSMAGIC_SUPERBLOB, body_len, len(slots)) + index + body


def _entitlements_blob(ent: dict, magic: int = CSMAGIC_EMBEDDED_ENTITLEMENTS) -> bytes:
    payload = plistlib.dumps(ent, fmt=plistlib.FMT_BINARY)
    return struct.pack(">II", magic, 8 + len(payload)) + payload


def test_carve_from_entitlements_slot():
    blob = _superblob((CSSLOT_ENTITLEMENTS, _entitlements_blob({"get-task-allow": True})))
    assert carve_entitlements(blob) == {"get-task-allow": True}


def test_carve_from_der_entitlements_slot():
    blob = _superblob(
        (CSSLOT_ENTITLEMENTS, _entitlements_blob({"a": "b"})),
        # DER slot: same blob shape, different magic, DER payload (ASCII plist works too)
        (0x7, _entitlements_blob({"der": "yes"}, magic=0xFADE7172)),
    )
    # First slot wins.
    assert carve_entitlements(blob) == {"a": "b"}


def test_carve_prefers_entitlements_slot_over_cms():
    ent_blob = _entitlements_blob({"get-task-allow": True})
    cms_blob = _cms_wrapper(b"")
    blob = _superblob((CSSLOT_CMS_SIGNATURE, cms_blob), (CSSLOT_ENTITLEMENTS, ent_blob))
    assert carve_entitlements(blob) == {"get-task-allow": True}


def test_carve_rejects_non_superblob():
    assert carve_entitlements(b"\x00" * 64) is None
    assert carve_entitlements(b"") is None
    assert carve_entitlements(struct.pack(">III", 0xDEADBEEF, 16, 0)) is None


def test_carve_none_when_no_entitlements_slots():
    # A superblob with only a code-directory slot (0) carries no entitlements.
    cd = struct.pack(">II", 0xFADE0C02, 8)
    blob = _superblob((0, cd))
    assert carve_entitlements(blob) is None


def test_carve_from_cms_signed_attributes():
    """Entitlements inside CMS signed attributes (OID 1.2.840.113635.100.9.1)."""
    from app.analysis.ios.entitlements import ENTITLEMENTS_OID

    ent = plistlib.dumps({"aps-environment": "development"}, fmt=plistlib.FMT_BINARY)

    # DER: SEQUENCE { OID, SET OF { OCTET STRING { plist } } }
    oid_tlv = b"\x06\x09" + ENTITLEMENTS_OID
    octet_tlv = b"\x04" + bytes([len(ent)]) + ent
    set_tlv = b"\x31" + bytes([len(octet_tlv)]) + octet_tlv
    seq_inner = oid_tlv + set_tlv
    seq_tlv = b"\x30" + bytes([len(seq_inner)]) + seq_inner

    blob = _superblob((CSSLOT_CMS_SIGNATURE, _cms_wrapper(seq_tlv)))
    assert carve_entitlements(blob) == {"aps-environment": "development"}


def test_carve_from_cms_with_indefinite_length_ber():
    """Apple CMS uses BER indefinite-length SEQUENCEs — the walker must cope."""
    from app.analysis.ios.entitlements import ENTITLEMENTS_OID

    ent = plistlib.dumps({"key": "value"}, fmt=plistlib.FMT_BINARY)
    oid_tlv = b"\x06\x09" + ENTITLEMENTS_OID
    octet_tlv = b"\x04" + bytes([len(ent)]) + ent
    set_tlv = b"\x31" + bytes([len(octet_tlv)]) + octet_tlv
    # 0x80 = indefinite length; EOC marker terminates.
    seq_tlv = b"\x30\x80" + oid_tlv + set_tlv + b"\x00\x00"

    blob = _superblob((CSSLOT_CMS_SIGNATURE, _cms_wrapper(seq_tlv)))
    assert carve_entitlements(blob) == {"key": "value"}


def _cms_wrapper(der: bytes) -> bytes:
    """A ``0xfade0b01`` blob wrapper around CMS content."""
    return struct.pack(">II", CSMAGIC_BLOBWRAPPER, 8 + len(der)) + der
