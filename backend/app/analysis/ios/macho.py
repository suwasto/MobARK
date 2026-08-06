"""Mach-O static analysis via LIEF (Apache-2.0, manylinux wheels).

Coverage:
- PIE flag (``header.has(FLAGS.PIE)``)
- Stack canary (``___stack_chk_guard`` symbol)
- ARC indicator (ObjC runtime retain/release symbols)
- FairPlay encryption (``LC_ENCRYPTION_INFO`` crypt_id)
- Exported symbols + linked dylibs + fat-arch slices (go to ``meta``/detail)
"""
from __future__ import annotations

from pathlib import Path

import lief

from app.analysis.base import TOOL_LIEF, FindingOut, StageResult

# ObjC runtime symbols whose presence indicates ARC-compiled code.
ARC_RUNTIME_SYMBOLS = (
    "objc_retainAutorelease",
    "objc_retainAutoreleasedReturnValue",
    "objc_retain",
    "objc_release",
    "objc_storeStrong",
    "objc_autoreleaseReturnValue",
)

CANARY_SYMBOL = "___stack_chk_guard"

# Symbol prefixes that are noise in exported-symbol lists.
NOISE_PREFIXES = ("_OBJC_", "_swift_", "l_", "___cxx_", ".objc_", "_block_")


class MachoError(Exception):
    pass


def _load_binaries(path: Path) -> list:
    """Parse ``path`` and return a list of MachO binaries (all slices).

    :raises MachoError: if the file is not a parseable Mach-O.
    """
    try:
        parsed = lief.MachO.parse(str(path))
    except (lief.bad_file, lief.parsing_error, lief.exception, OSError) as exc:
        raise MachoError(f"LIEF failed to parse Mach-O: {exc}") from exc
    if parsed is None:
        raise MachoError(f"not a Mach-O file: {path}")
    if isinstance(parsed, lief.MachO.FatBinary):
        # Index the FatBinary rather than list()-ing it: LIEF 1.0's
        # iterator binding returns Binary handles whose .header access
        # segfaults, while __getitem__ keeps the parent reference alive.
        return [parsed[i] for i in range(len(parsed))]
    return [parsed]


def analyze_app_binary(app_root: Path) -> StageResult:
    """Analyze the main executable inside an app bundle.

    The main executable is ``Payload/*.app/<Name>`` (CFBundleExecutable),
    falling back to the first plain-file entry at the bundle root.
    """
    result = StageResult()
    exe_path = _find_main_executable(app_root)
    if exe_path is None:
        result.errors.append(
            "no main executable found in app bundle — Mach-O stage skipped"
        )
        return result
    result.meta["main_executable"] = str(exe_path.relative_to(app_root))

    try:
        binaries = _load_binaries(exe_path)
    except MachoError as exc:
        result.errors.append(str(exc))
        return result

    archs: list[str] = []
    for binary in binaries:
        arch = str(binary.header.cpu_type) + ("_64" if binary.header.is_64bit else "")
        archs.append(arch)
        _analyze_binary(binary, result)
    result.meta["architectures"] = archs
    # M4 Layer 1: surface the binary profile as info findings so the agent's
    # findings context can see it (result.meta is not persisted anywhere).
    _emit_profile_findings(result, archs)
    return result


def _find_main_executable(app_root: Path) -> Path | None:
    """CFBundleExecutable from Info.plist, else the first file at bundle root."""
    from app.analysis.ios import plist as plist_mod

    info_path = app_root / "Info.plist"
    if info_path.is_file():
        try:
            info = plist_mod.load_info_plist(info_path)
            exe_name = info.get("CFBundleExecutable")
            if exe_name:
                candidate = app_root / exe_name
                if candidate.is_file():
                    return candidate
        except plist_mod.PlistError:
            pass
    for child in sorted(app_root.iterdir()):
        if child.is_file():
            return child
    return None


def _analyze_binary(binary, result: StageResult) -> None:
    """Emit findings for one Mach-O slice."""
    syms = {s.name for s in binary.symbols}

    # --- PIE ---
    if not binary.header.has(lief.MachO.Header.FLAGS.PIE):
        result.findings.append(
            FindingOut(
                tool=TOOL_LIEF,
                title="Position-independent executable (PIE) disabled",
                severity="high",
                category="MASVS-CODE-4",
                detail={"arch": str(binary.header.cpu_type)},
            )
        )

    # --- Stack canary ---
    if CANARY_SYMBOL not in syms:
        result.findings.append(
            FindingOut(
                tool=TOOL_LIEF,
                title="Stack canary missing (___stack_chk_guard not found)",
                severity="medium",
                category="MASVS-CODE-4",
                detail={"arch": str(binary.header.cpu_type)},
            )
        )

    # --- ARC indicator (best-effort) ---
    arc_symbols = sorted(s for s in syms if any(t in s for t in ARC_RUNTIME_SYMBOLS))
    if arc_symbols:
        result.meta["arc"] = True
        result.meta["arc_evidence"] = arc_symbols[:10]
    else:
        result.meta["arc"] = False

    # --- FairPlay encryption ---
    if binary.has_encryption_info and binary.encryption_info is not None:
        crypt_id = binary.encryption_info.crypt_id
        if crypt_id != 0:
            result.meta["fairplay"] = True
            result.findings.append(
                FindingOut(
                    tool=TOOL_LIEF,
                    title="FairPlay-encrypted binary (crypt_id != 0) — static coverage limited",
                    severity="info",
                    category="MASVS-CODE-4",
                    detail={
                        "crypt_id": crypt_id,
                        "crypt_offset": binary.encryption_info.crypt_offset,
                        "note": "App Store binaries are encrypted; symbol/entitlement "
                        "extraction is partial for this slice.",
                    },
                )
            )
        else:
            result.meta["fairplay"] = False

    # --- Exported symbols ---
    exported = [
        s.name
        for s in binary.exported_symbols
        if s.name and not s.name.startswith(NOISE_PREFIXES)
    ]
    result.meta["exported_symbol_count"] = len(exported)
    result.meta.setdefault("exported_symbols_sample", exported[:20])

    # --- Linked dylibs ---
    libs = [lib.name for lib in binary.libraries if lib.name]
    result.meta["linked_dylibs"] = sorted(set(result.meta.get("linked_dylibs", [])) | set(libs))


def is_macho(path: Path) -> bool:
    """Cheap probe: does LIEF consider this file a Mach-O?"""
    try:
        _load_binaries(path)
        return True
    except MachoError:
        return False


def _emit_profile_findings(result: StageResult, archs: list[str]) -> None:
    """Info findings describing the binary itself (architectures, linked
    dylibs, exported symbols, ARC) — binary-level context for the agent.
    Only emitted when the data is non-empty so quiet binaries stay quiet.
    """
    if archs:
        result.findings.append(
            FindingOut(
                tool=TOOL_LIEF,
                title=f"Binary slices: {', '.join(archs)}",
                severity="info",
                detail={"architectures": archs},
            )
        )
    dylibs = result.meta.get("linked_dylibs") or []
    if dylibs:
        result.findings.append(
            FindingOut(
                tool=TOOL_LIEF,
                title=f"Linked dylibs ({len(dylibs)})",
                severity="info",
                detail={"count": len(dylibs), "dylibs": dylibs[:50]},
            )
        )
    count = result.meta.get("exported_symbol_count") or 0
    if count:
        sample = result.meta.get("exported_symbols_sample") or []
        result.findings.append(
            FindingOut(
                tool=TOOL_LIEF,
                title=f"Exported symbols ({count})",
                severity="info",
                detail={"count": count, "sample": sample[:50]},
            )
        )
    if result.meta.get("arc") is True:
        evidence = result.meta.get("arc_evidence") or []
        result.findings.append(
            FindingOut(
                tool=TOOL_LIEF,
                title="ARC enabled (ObjC runtime symbols present)",
                severity="info",
                detail={"evidence": evidence[:10]},
            )
        )
