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
from collections.abc import Callable
from pathlib import Path

from app.analysis import gitleaks, jadx, manifest, semgrep
from app.analysis.base import FindingOut, ScanResult
from app.analysis.ios import entitlements, ipa, macho, plist, symbols
from app.analysis.mastg import test_ids_for_control
from app.config import settings

# M4 Layer 1: iOS string-level rules (kSecAttrAccessibleAlways) ride through
# Gitleaks as a custom ruleset — the import-table scanner cannot see strings.
_IOS_GITLEAKS_CONFIG = Path(__file__).parent / "resources" / "gitleaks_ios.toml"


class ScanAborted(RuntimeError):
    """A required stage failed; the scan cannot produce results."""


def run_analysis(
    artifact_path: Path,
    work_dir: Path,
    on_stage: Callable[[str], None] | None = None,
) -> ScanResult:
    """Dispatch to the platform pipeline based on the artifact extension.

    ``on_stage`` (optional, M5 progress screen) is invoked with a
    human-readable stage string at each pipeline boundary — the RQ job
    persists it to ``Scan.stage`` so the dashboard shows real progress.
    """
    suffix = Path(artifact_path).suffix.lower()
    if suffix == ".apk":
        return run_android_analysis(artifact_path, work_dir, on_stage=on_stage)
    if suffix == ".ipa":
        return run_ios_analysis(artifact_path, work_dir, on_stage=on_stage)
    raise ScanAborted(f"unsupported artifact type {suffix!r} (expected .apk or .ipa)")


def run_android_analysis(
    apk_path: Path,
    work_dir: Path,
    on_stage: Callable[[str], None] | None = None,
) -> ScanResult:
    """Analyze an APK, returning normalized findings plus diagnostics.

    :param apk_path: path to the APK file
    :param work_dir: scratch directory for decompiled output and tool reports
    :param on_stage: optional progress callback (M5 Scan.stage)
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
    if on_stage:
        on_stage("decompiling")
    try:
        jadx.decompile(apk_path, decompiled, timeout=settings.jadx_timeout_seconds)
    except jadx.JadxError as exc:
        raise ScanAborted(f"decompilation failed: {exc}") from exc
    result.decompiled_root = decompiled

    # --- required: manifest / certificate ---
    if on_stage:
        on_stage("analyzing")
    try:
        manifest_result = manifest.analyze(apk_path)
    except manifest.ManifestError as exc:
        raise ScanAborted(f"manifest analysis failed: {exc}") from exc
    result.findings.extend(manifest_result.findings)
    result.warnings.extend(manifest_result.errors + manifest_result.warnings)

    source_root = decompiled / "sources" if (decompiled / "sources").is_dir() else decompiled

    # --- enrichment: code pattern analysis ---
    if on_stage:
        on_stage("code analysis")
    sg = semgrep.scan_source_tree(
        source_root,
        reports / "semgrep.json",
        app_package=manifest_result.app_package,
    )
    result.findings.extend(sg.findings)
    result.warnings.extend(sg.errors + sg.warnings)

    # --- enrichment: secret scanning ---
    if on_stage:
        on_stage("secrets")
    gl = gitleaks.scan_directory(decompiled, reports / "gitleaks.json")
    result.findings.extend(gl.findings)
    result.warnings.extend(gl.errors + gl.warnings)

    _fill_mastg_test_ids(result.findings, platform="android")
    return result


def run_ios_analysis(
    ipa_path: Path,
    work_dir: Path,
    on_stage: Callable[[str], None] | None = None,
) -> ScanResult:
    """Analyze an IPA, returning normalized findings plus diagnostics.

    Stages: unpack (required) -> Info.plist (required) -> Mach-O (required)
    -> entitlements (best-effort) -> symbols -> gitleaks (enrichment).

    :param ipa_path: path to the IPA file
    :param work_dir: scratch directory for the unpacked bundle and reports
    :param on_stage: optional progress callback (M5 Scan.stage)
    :raises ScanAborted: on any required-stage failure
    """
    ipa_path = Path(ipa_path)
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    result = ScanResult(platform="ios")

    # --- required: unpack ---
    if on_stage:
        on_stage("unpacking")
    bundle_root = work_dir / "bundle"
    try:
        bundle = ipa.extract(ipa_path, bundle_root)
    except ipa.IpaError as exc:
        raise ScanAborted(f"IPA unpack failed: {exc}") from exc
    app_root = bundle_root / "Payload" / bundle.app_dir_name
    result.app_root = app_root

    # --- required: Info.plist + Mach-O ---
    if on_stage:
        on_stage("analyzing")
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
    if on_stage:
        on_stage("entitlements")
    entitlements_result = entitlements.analyze_app_binary(app_root)
    result.findings.extend(entitlements_result.findings)
    result.warnings.extend(entitlements_result.errors + entitlements_result.warnings)
    result.meta.update(entitlements_result.meta)

    reports = work_dir / "reports"
    reports.mkdir(parents=True, exist_ok=True)

    # --- enrichment: import-table scanner (known-insecure API blocklist) ---
    # M4 Layer 1 iOS source #2 — named explicitly; this is the "symbol /
    # import-table scanning" stage, not a vague "LIEF-derived" catch-all.
    if on_stage:
        on_stage("symbols")
    symbols_result = symbols.analyze_app_binary(app_root)
    result.findings.extend(symbols_result.findings)
    result.warnings.extend(symbols_result.errors + symbols_result.warnings)
    result.meta.update(symbols_result.meta)

    # --- enrichment: secret + string scanning over the bundle tree ---
    # iOS uses the custom ruleset (kSecAttrAccessibleAlways) — string-level,
    # not import-table-level.
    if on_stage:
        on_stage("secrets")
    gl = gitleaks.scan_directory(
        app_root,
        reports / "gitleaks.json",
        config=_IOS_GITLEAKS_CONFIG if _IOS_GITLEAKS_CONFIG.is_file() else None,
    )
    result.findings.extend(gl.findings)
    result.warnings.extend(gl.errors + gl.warnings)

    # --- enrichment: semgrep, for completeness (zero yield by design) ---
    # iOS is binary structure via LIEF, not decompiled Swift/ObjC source, so
    # semgrep finds no parseable source. Kept as an honest stage: the Layer 1
    # context builder flags it as zero-yield so the agent never leans on it.
    sg = semgrep.scan_source_tree(app_root, reports / "semgrep-ios.json")
    result.findings.extend(sg.findings)
    result.warnings.extend(sg.errors + sg.warnings)
    result.meta["semgrep_ios_findings"] = len(sg.findings)

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
