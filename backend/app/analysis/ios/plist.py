"""Info.plist static analysis (binary + XML via ``plistlib``).

Findings:
- ATS config (``NSAppTransportSecurity``): arbitrary loads, in-web-content,
  broad exception domains — MASVS-NETWORK-1/2.
- Empty usage-description strings for sensitive APIs the app declares
  (best-effort, informational — missing keys can't be detected statically).
- Bundle metadata (MinimumOSVersion, background modes, identifiers) goes into
  ``meta``, not findings.
"""
from __future__ import annotations

import plistlib
from pathlib import Path

from app.analysis.base import TOOL_PLIST, FindingOut, StageResult

# Sensitive APIs that require a purpose string in Info.plist when used.
USAGE_KEYS = {
    "NSCameraUsageDescription": "camera",
    "NSMicrophoneUsageDescription": "microphone",
    "NSPhotoLibraryUsageDescription": "photo library",
    "NSLocationWhenInUseUsageDescription": "location (in use)",
    "NSLocationAlwaysUsageDescription": "location (always)",
    "NSLocationAlwaysAndWhenInUseUsageDescription": "location (always + in use)",
    "NSContactsUsageDescription": "contacts",
    "NSCalendarsUsageDescription": "calendar",
    "NSBluetoothAlwaysUsageDescription": "bluetooth",
    "NSHealthShareUsageDescription": "health data (share)",
    "NSHealthUpdateUsageDescription": "health data (update)",
    "NSUserTrackingUsageDescription": "user tracking (ATT)",
    "NSFaceIDUsageDescription": "Face ID",
    "NSMotionUsageDescription": "motion sensors",
}

SENSITIVE_API_KEYS = set(USAGE_KEYS) | {
    # APIs that imply a purpose string should exist for them.
    "NSAppleMusicUsageDescription",
    "NFCReaderUsageDescription",
    "NSRemindersUsageDescription",
    "NSSiriUsageDescription",
    "NSSpeechRecognitionUsageDescription",
}


class PlistError(Exception):
    pass


def load_info_plist(path: Path) -> dict:
    """Parse an Info.plist in either binary or XML form."""
    try:
        with path.open("rb") as fh:
            return plistlib.load(fh)
    except (plistlib.InvalidFileException, OSError) as exc:
        raise PlistError(f"cannot parse Info.plist: {exc}") from exc


def analyze_info_plist(path: Path) -> StageResult:
    """Analyze an app bundle's Info.plist, returning findings + metadata.

    Metadata (bundle identifiers, MinimumOSVersion, background modes, ...)
    is stashed on ``result.meta`` for the orchestrator/report.
    """
    result = StageResult()
    plist = load_info_plist(path)

    result.meta["bundle_identifier"] = plist.get("CFBundleIdentifier")
    result.meta["bundle_name"] = plist.get("CFBundleName")
    result.meta["bundle_display_name"] = plist.get("CFBundleDisplayName")
    result.meta["bundle_version"] = plist.get("CFBundleShortVersionString")
    result.meta["minimum_os_version"] = plist.get("MinimumOSVersion")
    background_modes = plist.get("UIBackgroundModes") or []
    result.meta["background_modes"] = background_modes
    result.meta["ats"] = plist.get("NSAppTransportSecurity")

    _analyze_ats(plist, result)
    _analyze_usage_strings(plist, result)
    return result


def _analyze_ats(plist: dict, result: StageResult) -> None:
    ats = plist.get("NSAppTransportSecurity") or {}
    if not isinstance(ats, dict):
        return
    if ats.get("NSAllowsArbitraryLoads") is True:
        result.findings.append(
            FindingOut(
                tool=TOOL_PLIST,
                title="ATS allows arbitrary loads (NSAllowsArbitraryLoads=true)",
                severity="high",
                category="MASVS-NETWORK-1",
                detail={"key": "NSAllowsArbitraryLoads"},
            )
        )
    if ats.get("NSAllowsArbitraryLoadsInWebContent") is True:
        result.findings.append(
            FindingOut(
                tool=TOOL_PLIST,
                title="ATS disabled in web content (NSAllowsArbitraryLoadsInWebContent=true)",
                severity="medium",
                category="MASVS-NETWORK-1",
                detail={"key": "NSAllowsArbitraryLoadsInWebContent"},
            )
        )
    exceptions = ats.get("NSExceptionDomains") or {}
    if isinstance(exceptions, dict):
        lax = [
            domain
            for domain, cfg in exceptions.items()
            if isinstance(cfg, dict)
            and (
                cfg.get("NSExceptionAllowsInsecureHTTPLoads") is True
                or cfg.get("NSExceptionMinimumTLSVersion")
                in ("TLSv1.0", "TLSv1.1", "TLS 1.0", "TLS 1.1")
                or cfg.get("NSIncludesSubdomains") is True
            )
        ]
        if lax:
            result.findings.append(
                FindingOut(
                    tool=TOOL_PLIST,
                    title=(
                        "ATS per-domain exceptions allow insecure HTTP: "
                        f"{', '.join(sorted(lax)[:5])}"
                    ),
                    severity="medium",
                    category="MASVS-NETWORK-1",
                    detail={
                        "key": "NSExceptionDomains",
                        "domains": sorted(lax),
                    },
                )
            )


def _analyze_usage_strings(plist: dict, result: StageResult) -> None:
    declared = {
        key: value
        for key, value in plist.items()
        if key in SENSITIVE_API_KEYS
    }
    # If the app declares any sensitive API key, the presence of the
    # corresponding usage description is checked; a key that exists but is
    # empty is flagged. We can't detect *usage* of APIs statically here, so
    # this is informational only.
    missing = [
        key for key, value in declared.items() if not value
    ]
    if missing:
        result.findings.append(
            FindingOut(
                tool=TOOL_PLIST,
                title="Empty usage-description strings for sensitive APIs",
                # Owner calibration (Aug 7): a privacy/transparency issue, not
                # a direct security control — low, not medium.
                severity="low",
                category="MASVS-PLATFORM-2",
                detail={
                    "keys": {
                        key: USAGE_KEYS.get(key, key) for key in missing
                    }
                },
            )
        )
    if declared and not missing:
        result.meta["usage_descriptions"] = list(declared)
