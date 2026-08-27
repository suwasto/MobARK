"""M12 (V2) default hook scripts + registry.

Each platform ships a set of default frida hook scripts (FR-D9): Android
pinning validators + root-detection; iOS ATS/pinning validators +
jailbreak-detection + Keychain calls. They are REAL, runnable frida JS in
``scripts/<platform>/*.js`` - authored now, but NOT executed by M12 (the
fake-device posture defers on-device execution to an owner manual
checkpoint; nothing injects them yet).

``default_hooks(platform)`` is the registry. Each hook is
``{id, name, platform, description, script}`` with a stable id
(``android-pinning``, ``ios-keychain``, ...) - the seed for M15's built-in
script library, and the ``code`` id the live event feed uses so a real hook
that fires later lands in the same feed.
"""
from __future__ import annotations

from pathlib import Path

_SCRIPTS_DIR = Path(__file__).parent


def _read_script(platform: str, filename: str) -> str:
    path = _SCRIPTS_DIR / platform / filename
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


_DEFAULT_HOOKS = {
    "android": [
        {
            "id": "android-pinning",
            "name": "Certificate pinning validators (Android)",
            "description": (
                "Observes certificate-pinning verification (TrustManager, "
                "OkHttp CertificatePinner, default HostnameVerifier) and logs "
                "each check. Read-only - does not bypass pinning."
            ),
            "filename": "android-pinning.js",
        },
        {
            "id": "android-root-detection",
            "name": "Root-detection observers (Android)",
            "description": (
                "Logs common root / tamper-detection probes (su-style "
                "Runtime.exec, root-path File.exists, frida system-property "
                "lookups). Read-only, does not bypass."
            ),
            "filename": "android-root-detection.js",
        },
    ],
    "ios": [
        {
            "id": "ios-pinning",
            "name": "ATS / certificate-pinning validators (iOS)",
            "description": (
                "Observes NSURLSession/CFNetwork pinning handshakes "
                "(didReceiveChallenge, NSAppTransportSecurity, SecTrust) and "
                "logs each. Read-only, does not bypass."
            ),
            "filename": "ios-pinning.js",
        },
        {
            "id": "ios-jailbreak-detection",
            "name": "Jailbreak-detection observers (iOS)",
            "description": (
                "Logs common jailbreak-detection probes (canOpenURL for "
                "detector apps, fork(0), suspicious path access). Read-only."
            ),
            "filename": "ios-jailbreak-detection.js",
        },
        {
            "id": "ios-keychain",
            "name": "Keychain access observers (iOS)",
            "description": (
                "Logs SecItemAdd/CopyMatching/Update/Delete Keychain calls "
                "so a tester can see what the app reads and writes. "
                "Read-only."
            ),
            "filename": "ios-keychain.js",
        },
    ],
}

_PLATFORMS = ("android", "ios")


def default_hooks(platform: str) -> list[dict]:
    """The default hook scripts for ``platform`` (real frida JS bodies).

    Unknown platforms return [] (the router rejects them before this is
    reached, but a caller outside the API still gets a clean empty list
    rather than a crash).
    """
    hooks = _DEFAULT_HOOKS.get(platform)
    if hooks is None:
        return []
    out = []
    for h in hooks:
        out.append(
            {
                "id": h["id"],
                "name": h["name"],
                "platform": platform,
                "description": h["description"],
                "script": _read_script(platform, h["filename"]),
            }
        )
    return out


def available_platforms() -> tuple[str, ...]:
    return _PLATFORMS