"""Full M1 Android analysis pipeline with a per-stage error policy.

Stage policy:
- **required** (preflight, jadx decompile, androguard manifest): any failure
  fails the scan with a specific error.
- **enrichment** (semgrep, gitleaks): failures are recorded as warnings and
  the scan still completes, since they're layered on top of the required
  stages.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

from app.analysis import gitleaks, jadx, manifest, semgrep
from app.analysis.base import FindingOut, ScanResult
from app.analysis.mastg import test_ids_for_control
from app.config import settings


class ScanAborted(RuntimeError):
    """A required stage failed; the scan cannot produce results."""


def run_android_analysis(apk_path: Path, work_dir: Path) -> ScanResult:
    """Analyze an APK, returning normalized findings plus diagnostics.

    :param apk_path: path to the APK file
    :param work_dir: scratch directory for decompiled output and tool reports
    :raises ScanAborted: on preflight/decompile/manifest failure
    """
    apk_path = Path(apk_path)
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    result = ScanResult(platform="android")

    _preflight(apk_path)

    decompiled = work_dir / "decompiled"
    reports = work_dir / "reports"
    reports.mkdir(parents=True, exist_ok=True)

    # --- required: decompile ---
    try:
        jadx.decompile(apk_path, decompiled, timeout=settings.jadx_timeout_seconds)
    except jadx.JadxError as exc:
        raise ScanAborted(f"decompilation failed: {exc}") from exc
    result.decompiled_root = decompiled

    # --- required: manifest / certificate ---
    try:
        manifest_result = manifest.analyze(apk_path)
    except manifest.ManifestError as exc:
        raise ScanAborted(f"manifest analysis failed: {exc}") from exc
    result.findings.extend(manifest_result.findings)
    result.warnings.extend(manifest_result.errors + manifest_result.warnings)

    source_root = decompiled / "sources" if (decompiled / "sources").is_dir() else decompiled

    # --- enrichment: code pattern analysis ---
    sg = semgrep.scan_source_tree(
        source_root,
        reports / "semgrep.json",
        app_package=manifest_result.app_package,
    )
    result.findings.extend(sg.findings)
    result.warnings.extend(sg.errors + sg.warnings)

    # --- enrichment: secret scanning ---
    gl = gitleaks.scan_directory(decompiled, reports / "gitleaks.json")
    result.findings.extend(gl.findings)
    result.warnings.extend(gl.errors + gl.warnings)

    _fill_mastg_test_ids(result.findings)
    return result


def _preflight(apk_path: Path) -> None:
    """Cheap structural checks; raise ScanAborted with a specific reason."""
    if not apk_path.is_file():
        raise ScanAborted(f"APK not found: {apk_path}")
    if not zipfile.is_zipfile(apk_path):
        raise ScanAborted("not a valid ZIP archive")
    try:
        with zipfile.ZipFile(apk_path) as zf:
            names = set(zf.namelist())
    except (zipfile.BadZipFile, OSError) as exc:
        raise ScanAborted(f"corrupt archive: {exc}") from exc
    if "AndroidManifest.xml" not in names:
        raise ScanAborted("missing AndroidManifest.xml — not an Android APK")


def _fill_mastg_test_ids(findings: list[FindingOut]) -> None:
    """Backfill mastg_test_id from the vendored mapping where a control is set."""
    for f in findings:
        if f.category and not f.mastg_test_id:
            ids = test_ids_for_control(f.category)
            if ids:
                f.mastg_test_id = ids[0]
