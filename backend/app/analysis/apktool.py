"""apktool (dis)assembly wrapper (APK -> decoded smali/res/AndroidManifest tree).

M8 edit & recompile, Android only. apktool is a JVM CLI tool (Apache-2.0),
invoked strictly as a subprocess - never imported, per the project license
posture. ``decode()`` produces apktool's ``-o`` layout: ``<out>/`` with
``AndroidManifest.xml``, ``smali{,classesN}/``, ``res/``, ``apktool.yml``.

Decode is **on-demand** (owner decision, Aug 10 2026): the RQ job runs only
when the user first opens the Smali view / starts an edit, then caches per
scan. The decoded tree stays the pristine baseline for the whole M8 edit
model - edits are DB diffs applied at rebuild, never silent tree writes.
"""
from __future__ import annotations

from pathlib import Path

from app.analysis.subprocess import resolve_binary, run_tool, tail
from app.config import settings


class ApktoolError(Exception):
    """Decode failed (bad APK, missing tool, timeout, empty output)."""


def apktool_binary() -> str:
    """The apktool launcher: a *_CMD override, the vendored wrapper script
    (container: /opt/masa-tools/apktool/apktool -> java -jar apktool.jar),
    or apktool on PATH (host dev)."""
    bin_path = resolve_binary("apktool", "apktool_cmd", tools_subdir="apktool/apktool")
    if bin_path is None:
        raise ApktoolError(
            "apktool not found on PATH (install it or set MASA_APKTOOL_CMD)"
        )
    return bin_path


def decoded_root(scan_id: int) -> Path:
    """Absolute path of a scan's on-demand apktool decode output."""
    return settings.data_dir / "work" / str(scan_id) / "apktool"


def is_ready(scan_id: int) -> bool:
    """Filesystem-derived decode state: the apktool output tree is ready when
    its decoded AndroidManifest.xml exists (the same derive-don't-trust-the-
    column rule the graph uses)."""
    return (decoded_root(scan_id) / "AndroidManifest.xml").is_file()


def smali_roots(scan_id: int) -> list[tuple[str, Path]]:
    """``(name, absolute_path)`` of the decoded smali roots, in apktool order:
    ``smali`` first, then ``smali_classes2..N`` (multidex, first-found wins).
    Empty when the scan is not decoded. Shared by the file tree (Phase B) and
    the Java⇄Smali mapper."""
    if not is_ready(scan_id):
        return []
    root = decoded_root(scan_id)
    out: list[tuple[str, Path]] = []
    direct = root / "smali"
    if direct.is_dir():
        out.append(("smali", direct))
    for d in sorted(root.glob("smali_classes*")):
        if d.is_dir():
            out.append((d.name, d))
    return out


def build(tree_dir: Path, out_apk: Path, timeout: int | None = None) -> None:
    """Assemble a decoded tree back into an APK (``apktool b -o``).

    Operates on a *copy* of the pristine decoded tree (the rebuild pipeline
    overlays the applied edits onto that copy first - the on-disk baseline
    never mutates). Raises :class:`ApktoolError` with a specific reason on
    timeout / non-zero exit / silent 0-exit without an output file.
    """
    out_apk.parent.mkdir(parents=True, exist_ok=True)
    cmd = [apktool_binary(), "b", str(tree_dir), "-o", str(out_apk)]
    timeout = timeout or settings.apktool_timeout_seconds
    result = run_tool(cmd, timeout=timeout)
    if result.timed_out:
        raise ApktoolError(f"apktool b timed out after {timeout}s")
    if result.returncode != 0:
        raise ApktoolError(
            f"apktool b exited {result.returncode}: {tail(result.stderr) or tail(result.stdout)}"
        )
    if not out_apk.is_file():
        raise ApktoolError("apktool b exited 0 but produced no APK output")


def decode(apk_path: Path, out_dir: Path, timeout: int | None = None) -> None:
    """Disassemble ``apk_path`` into ``out_dir`` (``apktool d -f -o``).

    Raises :class:`ApktoolError` with a specific reason on any failure -
    timeout, non-zero exit (bad APK / missing aapt2), or a silent 0-exit
    that produced no manifest. Callers (the RQ job) map the error to
    ``scans.apktool_status=failed`` + ``apktool_error``.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [apktool_binary(), "d", "-f", "-o", str(out_dir), str(apk_path)]
    timeout = timeout or settings.apktool_timeout_seconds
    result = run_tool(cmd, timeout=timeout)
    if result.timed_out:
        raise ApktoolError(f"apktool timed out after {timeout}s")
    if result.returncode != 0:
        raise ApktoolError(
            f"apktool exited {result.returncode}: {tail(result.stderr) or tail(result.stdout)}"
        )
    if not (out_dir / "AndroidManifest.xml").is_file():
        raise ApktoolError("apktool exited 0 but produced no AndroidManifest.xml")
