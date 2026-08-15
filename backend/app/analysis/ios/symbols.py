"""iOS Mach-O import-table scanner (M4 Layer 1 - iOS source #2).

Reads the Mach-O import table via LIEF and matches imported symbols against a
known-insecure API blocklist: legacy crypto (``CC_MD5``/``CC_SHA1``/``CC_DES``/
``CCCrypt``), the deprecated ``UIWebView``, old ``NSURLConnection``
certificate-bypass selectors, and ``ptrace``/``sysctl`` anti-debug imports.

Precision is **binary-level presence only** by design: an import proves the
code links/calls the API somewhere in the binary, but gives no source
location - findings say exactly that and note what constant-level detail
(e.g. ``kCCOptionECBMode``, ``PT_DENY_ATTACH``) cannot be confirmed
statically. String-level checks (e.g. ``kSecAttrAccessibleAlways``) are NOT
this scanner's job - they go through Gitleaks (see
``app/analysis/resources/gitleaks_ios.toml``).
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from app.analysis.base import TOOL_SYMBOLS, FindingOut, StageResult
from app.analysis.ios import macho


@dataclass(frozen=True)
class ImportRule:
    """One blocklist entry; ``symbol`` is matched as a substring of a
    normalized (leading underscore stripped) import name, so ``UIWebView``
    also catches ``_OBJC_CLASS_$_UIWebView``."""

    symbol: str
    title: str
    severity: str
    category: str | None = None
    note: str | None = None


IMPORT_RULES: tuple[ImportRule, ...] = (
    # --- legacy / broken crypto (libcommonCrypto) ---
    ImportRule(
        "CC_MD5",
        "Legacy MD5 hashing imported (CC_MD5)",
        "warning",
        "MASVS-CRYPTO-2",
        "MD5 is cryptographically broken - binary-level presence, no source location.",
    ),
    ImportRule(
        "CC_MD4",
        "Legacy MD4 hashing imported (CC_MD4)",
        "warning",
        "MASVS-CRYPTO-2",
        "MD4 is cryptographically broken - binary-level presence, no source location.",
    ),
    ImportRule(
        "CC_SHA1",
        "Legacy SHA-1 hashing imported (CC_SHA1)",
        "warning",
        "MASVS-CRYPTO-2",
        "SHA-1 is deprecated for security uses - binary-level presence, no source location.",
    ),
    ImportRule(
        "CC_DES",
        "Legacy DES cipher imported (CC_DES)",
        "high",
        "MASVS-CRYPTO-2",
        "DES is broken and must not be used - binary-level presence, no source location.",
    ),
    ImportRule(
        "CCCrypt",
        "Legacy CommonCrypto CCCrypt imported",
        "warning",
        "MASVS-CRYPTO-2",
        "Review algorithm/mode at the call site: ECB-mode constants (kCCOptionECBMode) "
        "are code-level and not visible in the import table.",
    ),
    ImportRule(
        "CCCryptorCreate",
        "Legacy CommonCrypto CCCryptorCreate imported",
        "warning",
        "MASVS-CRYPTO-2",
        "Review algorithm/mode at the call site; import-level presence only.",
    ),
    # --- deprecated / insecure webviews ---
    ImportRule(
        "UIWebView",
        "Deprecated UIWebView referenced",
        "warning",
        "MASVS-PLATFORM-2",
        "UIWebView is deprecated and insecure-by-default; use WKWebView. "
        "Binary-level presence, no source location.",
    ),
    # --- old NSURLConnection certificate-bypass patterns ---
    ImportRule(
        "setAllowsAnyHTTPSCertificate",
        "NSURLConnection certificate bypass (setAllowsAnyHTTPSCertificate)",
        # Owner calibration (Aug 7): complete TLS verification bypass -
        # direct MITM compromise, same class as the Android hostname verifier.
        # Aug 8: the critical band was removed - high is the top severity.
        "high",
        "MASVS-NETWORK-2",
        "Server identity verification disabled for this connection - binary-level "
        "presence, no source location.",
    ),
    ImportRule(
        "canAuthenticateAgainstProtectionSpace",
        "Custom NSURLConnection authentication (canAuthenticateAgainstProtectionSpace)",
        "warning",
        "MASVS-NETWORK-2",
        "Custom server-identity handling - verify it validates certificates. "
        "Binary-level presence, no source location.",
    ),
    # --- anti-debug / anti-tampering ---
    ImportRule(
        "ptrace",
        "ptrace imported - possible anti-debug (PT_DENY_ATTACH)",
        "warning",
        "MASVS-RESILIENCE-2",
        "ptrace(PT_DENY_ATTACH) is a common anti-debug technique - the constant is "
        "code-level and not visible in the import table.",
    ),
    ImportRule(
        "sysctl",
        "sysctl imported - possible anti-debug (KERN_PROC inspection)",
        "info",
        "MASVS-RESILIENCE-2",
        "sysctl KERN_PROC inspection is a common debugger-detection technique.",
    ),
    ImportRule(
        "syscall",
        "syscall imported - possible anti-debug",
        "info",
        "MASVS-RESILIENCE-2",
        "Direct syscall use can indicate anti-debugging; also common in jailbreak "
        "detection.",
    ),
)


def _match_rule(name: str) -> ImportRule | None:
    """Exact match wins over substring, so ``CCCryptorCreate`` hits its own
    rule rather than the broader ``CCCrypt`` one."""
    for rule in IMPORT_RULES:
        if rule.symbol == name:
            return rule
    for rule in IMPORT_RULES:
        if rule.symbol in name:
            return rule
    return None


def match_imports(names: Iterable[str], extra_names: Iterable[str] = ()) -> list[FindingOut]:
    """Match normalized symbol names against the blocklist (pure, testable).

    ``names`` are the Mach-O imported symbols; ``extra_names`` are optional
    ObjC class/selector names from LIEF's metadata when available (UIWebView
    and selector-level rules can live there rather than the import table).
    Returns findings with ``precision = binary-level presence`` (the caller's
    context builder derives it from ``tool="symbols"``).
    """
    normalized = {str(n).lstrip("_") for n in names if n} | {
        str(n).lstrip("_") for n in extra_names if n
    }
    findings: list[FindingOut] = []
    seen: set[tuple[str, str]] = set()
    for name in sorted(normalized):
        rule = _match_rule(name)
        if rule is None:
            continue
        key = (rule.title, name)
        if key in seen:
            continue
        seen.add(key)
        detail: dict = {"symbol": f"_{name}"}
        if rule.note:
            detail["note"] = rule.note
        findings.append(
            FindingOut(
                tool=TOOL_SYMBOLS,
                title=rule.title,
                severity=rule.severity,
                category=rule.category,
                detail=detail,
            )
        )
    return findings


def analyze_app_binary(app_root: Path) -> StageResult:
    """Scan the app's main executable import table for blocklisted APIs.

    Best-effort stage (errors are warnings, never a scan failure): a failed
    LIEF parse here means the Mach-O stage already failed and the scan is
    aborted upstream.
    """
    result = StageResult()
    exe_path = macho._find_main_executable(app_root)
    if exe_path is None:
        result.errors.append("no main executable - import-table scan skipped")
        return result
    try:
        binaries = macho._load_binaries(exe_path)
    except macho.MachoError as exc:
        result.errors.append(str(exc))
        return result

    # Dedup across slices: a fat binary (arm64 + armv7) would otherwise emit
    # the same finding once per slice - the matcher's own seen-set is per call.
    seen: set[tuple[str, str]] = set()
    for binary in binaries:
        imported = [s.name for s in binary.imported_symbols if s.name]
        extra: list[str] = []
        # Best-effort ObjC metadata (LIEF 1.x): class names surface UIWebView
        # even when it is only referenced via ObjC runtime calls. Guarded so a
        # missing/renamed API degrades to import-table-only scanning.
        objc = getattr(binary, "objc_metadata", None)
        if objc is not None:
            try:
                classes = getattr(objc, "classes", None) or []
                for cls in classes:
                    name = getattr(cls, "name", None)
                    if name:
                        extra.append(name)
            except Exception:  # pragma: no cover - defensive
                pass
        for finding in match_imports(imported, extra):
            key = (finding.title, str((finding.detail or {}).get("symbol", "")))
            if key in seen:
                continue
            seen.add(key)
            result.findings.append(finding)

    result.meta["import_table_scanned"] = True
    result.meta["imported_symbol_count"] = sum(
        len([s for s in b.imported_symbols if s.name]) for b in binaries
    )
    return result
