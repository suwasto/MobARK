"""AndroidManifest.xml + certificate + network-security-config analysis.

Backed by androguard, imported lazily so unit tests that don't exercise
manifest analysis don't need it installed. Emits normalized findings for:

- requested permissions (curated risky set)
- exported components with intent filters
- ``allowBackup`` / ``debuggable`` / cleartext flags
- network security config
- signing certificate metadata

Categories reference MASVS v2 control ids; ``mastg_test_id`` is filled from
the vendored MASTG mapping via a control -> test reverse lookup.
"""
from __future__ import annotations

from pathlib import Path

from app.analysis.base import FindingOut, StageResult

ANDROID_NS = "http://schemas.android.com/apk/res/android"


class ManifestError(Exception):
    """APK could not be parsed for manifest analysis."""


# Curated risky/dangerous permissions worth flagging when requested.
RISKY_PERMISSIONS = {
    "android.permission.READ_SMS": ("SMS is readable by the app", "high"),
    "android.permission.SEND_SMS": ("The app can send SMS messages", "high"),
    "android.permission.RECEIVE_SMS": ("The app can receive SMS messages", "high"),
    "android.permission.RECORD_AUDIO": ("The app can record audio", "warning"),
    "android.permission.CAMERA": ("The app can access the camera", "warning"),
    "android.permission.READ_CONTACTS": ("The app can read contacts", "warning"),
    "android.permission.ACCESS_FINE_LOCATION": ("The app can access fine location", "warning"),
    "android.permission.READ_CALL_LOG": ("The app can read the call log", "high"),
    "android.permission.READ_PHONE_STATE": ("The app can read phone state", "warning"),
    "android.permission.REQUEST_INSTALL_PACKAGES": (
        "The app can request installing packages",
        "high",
    ),
    "android.permission.QUERY_ALL_PACKAGES": (
        "The app can enumerate installed packages",
        "warning",
    ),
    "android.permission.WRITE_EXTERNAL_STORAGE": ("The app can write external storage", "info"),
    "android.permission.READ_EXTERNAL_STORAGE": ("The app can read external storage", "info"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": (
        "Accessibility service binding (screen-reader level access)",
        "high",
    ),
}


def analyze(apk_path: Path) -> StageResult:
    """Run manifest/certificate/netsec checks on an APK.

    Raises :class:`ManifestError` when the APK cannot be parsed.
    """
    try:
        from androguard.core.apk import APK
    except ImportError as exc:  # pragma: no cover
        raise ManifestError("androguard is not installed") from exc

    try:
        apk = APK(str(apk_path))
    except Exception as exc:
        raise ManifestError(f"failed to parse APK with androguard: {exc}") from exc

    result = StageResult()
    try:
        result.app_package = apk.get_package() or None
    except Exception:
        result.app_package = None
    manifest_el = _manifest_element(apk, result)
    if manifest_el is not None:
        app_el = _application_element(manifest_el)
        if app_el is not None:
            result.extend(_application_checks(app_el))
        result.extend(_exported_components(manifest_el))
        result.extend(_network_security_config(apk, manifest_el, result))
    result.extend(_permission_findings(apk))
    result.extend(_certificate_findings(apk))
    return result


def _manifest_element(apk, result: StageResult):
    """Return the parsed manifest root element, or None (diagnostics recorded)."""
    try:
        xml = apk.get_android_manifest_xml()
    except Exception as exc:
        result.errors.append(f"failed to parse AndroidManifest.xml: {exc}")
        return None
    if xml is None:
        result.errors.append("AndroidManifest.xml is empty")
        return None
    # Defensive: some androguard versions return raw XML text.
    if isinstance(xml, str | bytes):
        from lxml import etree

        try:
            xml = etree.fromstring(xml)
        except Exception as exc:
            result.errors.append(f"failed to parse AndroidManifest.xml text: {exc}")
            return None
    return xml


def _attr(elem, name: str) -> str | None:
    value = elem.get(f"{{{ANDROID_NS}}}{name}")
    return value if value is not None else None


def _application_element(manifest_el):
    for child in manifest_el:
        if _local(child) == "application":
            return child
    return None


def _local(elem) -> str:
    tag = elem.tag
    if isinstance(tag, str) and "}" in tag:
        return tag.rsplit("}", 1)[1]
    return str(tag)


def _application_checks(app_el) -> StageResult:
    result = StageResult()
    allow_backup = _attr(app_el, "allowBackup")
    if allow_backup == "true":
        result.findings.append(
            FindingOut(
                tool="androguard",
                title="Application data can be backed up (android:allowBackup=true)",
                severity="warning",
                file_path="AndroidManifest.xml",
                category="MASVS-STORAGE-2",
            )
        )
    debuggable = _attr(app_el, "debuggable")
    if debuggable == "true":
        # Owner review (Aug 7): a production app shipping debuggable=true is a
        # direct tampering/debugging exposure (runtime attach, memory dumps,
        # run-as data access). Aug 8: the critical band was removed from the
        # vocabulary - high is the top severity.
        result.findings.append(
            FindingOut(
                tool="androguard",
                title="Application is debuggable (android:debuggable=true)",
                severity="high",
                file_path="AndroidManifest.xml",
                category="MASVS-RESILIENCE-4",
            )
        )
    cleartext = _attr(app_el, "usesCleartextTraffic")
    if cleartext == "true":
        result.findings.append(
            FindingOut(
                tool="androguard",
                title="Cleartext traffic allowed (android:usesCleartextTraffic=true)",
                severity="warning",
                file_path="AndroidManifest.xml",
                category="MASVS-NETWORK-1",
            )
        )
    return result


def _exported_components(manifest_el) -> StageResult:
    result = StageResult()
    app_el = _application_element(manifest_el)
    if app_el is None:
        return result
    for child in app_el:
        kind = _local(child)
        if kind not in ("activity", "service", "receiver", "provider"):
            continue
        name = _attr(child, "name")
        exported = _attr(child, "exported")
        has_intent_filter = any(_local(c) == "intent-filter" for c in child)
        permission = _attr(child, "permission") or _attr(app_el, "permission")
        # Pre-Android-12 default: a component with an intent filter is
        # implicitly exported unless android:exported="false" is set.
        effectively_exported = exported == "true" or (exported is None and has_intent_filter)
        if not effectively_exported:
            continue
        display = name or f"<{kind} with no android:name>"
        if has_intent_filter and not permission:
            result.findings.append(
                FindingOut(
                    tool="androguard",
                    title=(
                        f"Exported {kind} with intent filter and no permission "
                        f"requirement: {display}"
                    ),
                    severity="high",
                    file_path="AndroidManifest.xml",
                    category="MASVS-PLATFORM-1",
                    detail={
                        "check": "exported_component",
                        "component": name,
                        "kind": kind,
                        "exported": True,
                        "has_intent_filter": True,
                        "permission": None,
                    },
                )
            )
        elif exported == "true":
            result.findings.append(
                FindingOut(
                    tool="androguard",
                    title=f"Exported {kind}: {display}",
                    severity="warning",
                    file_path="AndroidManifest.xml",
                    category="MASVS-PLATFORM-1",
                    detail={
                        "check": "exported_component",
                        "component": name,
                        "kind": kind,
                        "exported": True,
                        "has_intent_filter": bool(has_intent_filter),
                        "permission": permission,
                    },
                )
            )
    return result


def _network_security_config(apk, manifest_el, result: StageResult) -> StageResult:
    out = StageResult()
    app_el = _application_element(manifest_el)
    if app_el is None:
        return out
    ref = _attr(app_el, "networkSecurityConfig")
    if not ref:
        return out  # nothing declared; platform default applies
    # "@xml/network_security_config" -> res/xml/network_security_config.xml
    candidates = []
    parts = ref.lstrip("@").split("/")
    if len(parts) == 2:
        candidates.append(f"res/{parts[0]}/{parts[1]}.xml")
        candidates.append(f"res/{parts[0]}/{parts[1]}")
    for name in candidates:
        try:
            raw = apk.get_file(name)
        except Exception:
            continue
        if not raw:
            continue
        _parse_nsc(raw, name, out)
        return out
    result.warnings.append(f"network security config declared but not found: {ref}")
    return out


def _parse_nsc(raw: bytes, name: str, out: StageResult) -> None:
    try:
        from lxml import etree

        root = etree.fromstring(raw)
    except Exception as exc:
        out.warnings.append(f"failed to parse network security config {name}: {exc}")
        return
    cleartext_permitted = _nsc_cleartext(root)
    if cleartext_permitted:
        out.findings.append(
            FindingOut(
                tool="androguard",
                title="Network security config permits cleartext traffic",
                severity="warning",
                file_path=name,
                category="MASVS-NETWORK-1",
                detail={"cleartext_traffic_permitted": True, "config": name},
            )
        )
    else:
        out.findings.append(
            FindingOut(
                tool="androguard",
                title="Network security config restricts cleartext traffic",
                severity="info",
                file_path=name,
                category="MASVS-NETWORK-1",
                detail={"cleartext_traffic_permitted": False, "config": name},
            )
        )


def _nsc_cleartext(root) -> bool:
    """Determine whether the network security config permits cleartext."""
    # <base-config cleartextTrafficPermitted="...">; default true pre-API 28.
    base = root.find("base-config")
    if base is not None:
        val = base.get("cleartextTrafficPermitted")
        if val is not None:
            return val.lower() == "true"
    # Any <domain-config cleartextTrafficPermitted="true"> overrides base.
    for dc in root.iter("domain-config"):
        val = dc.get("cleartextTrafficPermitted")
        if val is not None and val.lower() == "true":
            return True
    return False


def _permission_findings(apk) -> StageResult:
    result = StageResult()
    try:
        requested = set(apk.get_permissions() or [])
    except Exception as exc:
        result.warnings.append(f"failed to enumerate permissions: {exc}")
        return result
    for perm, (label, severity) in RISKY_PERMISSIONS.items():
        if perm in requested:
            result.findings.append(
                FindingOut(
                    tool="androguard",
                    title=f"Risky permission requested: {perm}",
                    severity=severity,
                    file_path="AndroidManifest.xml",
                    category="MASVS-PLATFORM-1",
                    detail={"check": "risky_permission", "permission": perm, "note": label},
                )
            )
    return result


def _certificate_findings(apk) -> StageResult:
    result = StageResult()
    try:
        certs = apk.get_certificates() or []
    except Exception as exc:
        result.warnings.append(f"failed to read signing certificate: {exc}")
        return result
    for i, cert in enumerate(certs, start=1):
        detail: dict = {"certificate_index": i}
        try:
            # androguard returns asn1crypto x509.Certificate objects here.
            detail["subject"] = str(cert.subject)
            detail["issuer"] = str(cert.issuer)
            detail["serial_number"] = str(cert.serial_number)
            detail["not_valid_before"] = str(cert.not_valid_before)
            detail["not_valid_after"] = str(cert.not_valid_after)
            detail["sha256_fingerprint"] = cert.sha256.hex()
        except Exception as exc:
            detail["error"] = str(exc)
        result.findings.append(
            FindingOut(
                tool="androguard",
                title=f"Signing certificate #{i}",
                severity="info",
                category=None,
                detail=detail,
            )
        )
    return result
