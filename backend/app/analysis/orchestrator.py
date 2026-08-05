"""M1 Android + M2 iOS analysis pipelines with a per-stage error policy.

Stage policy:
- **required** (preflight, decompile/manifest, unpack/plist, Mach-O): any
  failure fails the scan with a specific error.
- **best-effort** (entitlements): extraction is inherently limited for
  ad-hoc/resigned and FairPlay-encrypted binaries; limits are surfaced as
  an info finding, not a scan failure.
- **enrichment** (semgrep, gitleaks): failures are recorded as warnings and
  the scan still completes, since they're layered on top of the required
  stages.

Platform dispatch is by file extension: ``.apk`` -> android, ``.ipa`` -> ios.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

from app.analysis import gitleaks, jadx, manifest, semgrep
from app.analysis.base import FindingOut, ScanResult
from app.analysis.ios import entitlements, ipa, macho, plist
from app.analysis.mastg import test_ids_for_control
from app.config import settings


class ScanAborted(RuntimeError):
    """A required stage failed; the scan cannot produce results."""


def run_analysis(artifact_path: Path, work_dir: Path) -> ScanResult:
    """Dispatch to the platform pipeline based on the artifact extension."""
    suffix = Path(artifact_path).suffix.lower()
    if suffix == ".apk":
        return run_android_analysis(artifact_path, work_dir)
    if suffix == ".ipa":
        return run_ios_analysis(artifact_path, work_dir)
    raise ScanAborted(f"unsupported artifact type {suffix!r} (expected .apk or .ipa)")


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

    _preflight_apk(apk_path)

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

    _fill_mastg_test_ids(result.findings, platform="android")
    return result


def run_ios_analysis(ipa_path: Path, work_dir: Path) -> ScanResult:
    """Analyze an IPA, returning normalized findings plus diagnostics.

    Stages: unpack (required) -> Info.plist (required) -> Mach-O (required)
    -> entitlements (best-effort) -> gitleaks (enrichment).

    :param ipa_path: path to the IPA file
    :param work_dir: scratch directory for the unpacked bundle and reports
    :raises ScanAborted: on any required-stage failure
    """
    ipa_path = Path(ipa_path)
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    result = ScanResult(platform="ios")

    # --- required: unpack ---
    bundle_root = work_dir / "bundle"
    try:
        bundle = ipa.extract(ipa_path, bundle_root)
    except ipa.IpaError as exc:
        raise ScanAborted(f"IPA unpack failed: {exc}") from exc
    app_root = bundle_root / "Payload" / bundle.app_dir_name
    result.app_root = app_root

    # --- required: Info.plist ---
    info_plist_path = app_root / "Info.plist"
    try:
        plist_result = plist.analyze_info_plist(info_plist_path)
    except plist.PlistError as exc:
        raise ScanAborted(f"Info.plist analysis failed: {exc}") from exc
    result.findings.extend(plist_result.findings)
    result.warnings.extend(plist_result.errors + plist_result.warnings)
    result.meta.update(plist_result.meta)

    # --- required: Mach-O ---
    macho_result = macho.analyze_app_binary(app_root)
    result.findings.extend(macho_result.findings)
    result.meta.update(macho_result.meta)
    if macho_result.errors:
        # Binary inspection is the core of the iOS pipeline; a failed parse
        # means the scan cannot produce meaningful results.
        raise ScanAborted(f"Mach-O analysis failed: {macho_result.errors[0]}")
    result.warnings.extend(macho_result.warnings)

    # --- best-effort: entitlements (extraction limits are a finding) ---
    entitlements_result = entitlements.analyze_app_binary(app_root)
    result.findings.extend(entitlements_result.findings)
    result.warnings.extend(entitlements_result.errors + entitlements_result.warnings)
    result.meta.update(entitlements_result.meta)

    # --- enrichment: secret scanning over the bundle tree ---
    reports = work_dir / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    gl = gitleaks.scan_directory(app_root, reports / "gitleaks.json")
    result.findings.extend(gl.findings)
    result.warnings.extend(gl.errors + gl.warnings)

    _fill_mastg_test_ids(result.findings, platform="ios")
    return result


def _preflight_apk(apk_path: Path) -> None:
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


def _fill_mastg_test_ids(findings: list[FindingOut], platform: str) -> None:
    """Backfill mastg_test_id from the vendored mapping where a control is set."""
    for f in findings:
        if f.category and not f.mastg_test_id:
            ids = test_ids_for_control(f.category, platform=platform)
            if ids:
                f.mastg_test_id = ids[0]
