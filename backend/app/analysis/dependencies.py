"""Dependencies tab inventory - local-first, derived on demand.

Serves the dashboard's Dependencies tab entirely from data the scan pipeline
already produced (nothing new is persisted, nothing leaves the machine):

- **Android** - third-party Java/Kotlin package groups from the jadx
  ``sources`` tree (grouped by library, the app's own package excluded),
  native ``lib/*.so`` shared libraries from the APK itself, and runtime
  framework markers (Flutter / React Native / Unity / ...). App metadata
  (package + SDK levels) comes from the jadx-decoded ``AndroidManifest.xml``.
- **iOS** - linked dylibs from the persisted LIEF binary profile (system vs
  third-party) + embedded ``Frameworks/*.framework`` bundles; metadata from
  ``Info.plist``.

Known-CVE research is deliberately NOT baked into this endpoint: per the M7
owner reframe (Aug 9, 2026), "dependency CVE research" is the agent's
on-demand web-research use case - the dock asks with 🌐 Web on and the
agent decides when to search. This tab is the honest local inventory the
agent works from (the UI's per-dependency "Check known CVEs" button pre-fills
the dock question).

The inventory is **cached per scan** (module + a validated
``dependencies_cache.json`` beside the scan's trees - the same pattern as
tree_cache.json / smali_mapping.json) so repeated tab opens skip the
source-tree walk + APK zip read entirely. Identity = platform + tree/bundle
mtime + APK stat + a **findings fingerprint** - unlike the tree/mapping
caches, suppression changes the inventory (finding counts), and the route
passes the non-suppressed set, so any suppress/restore toggle flips the
fingerprint and recomputes. Best-effort throughout: any failure recomputes,
never a wrong answer.
"""
from __future__ import annotations

import hashlib
import json
import os
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

from app.analysis.base import TOOL_LIEF, TOOL_SEMGREP
from app.analysis.manifest import ANDROID_NS
from app.config import settings

# ---- Inventory cache ---------------------------------------------------------
# The expensive parts (source-tree walk, APK zip namelist read) are immutable
# per scan; the only mutable input is finding suppression, which the findings
# fingerprint below captures. Module cache keyed by the cache path, bounded
# (small payloads - 32 mirrors the smali_mapping cache); the persistent file
# is validated by a stored identity + shape version and survives restarts.
_DEPENDENCIES_CACHE: dict[str, tuple[str, dict]] = {}
_DEPENDENCIES_CACHE_MAX = 32
# Bump when the stored payload shape changes so stale persisted files rebuild.
_DEPENDENCIES_CACHE_VERSION = 1


def cache_path_for(scan_id: int) -> Path:
    """Per-scan cache file next to the scan's trees (``work/<scan>/``) - a
    SIBLING of ``decompiled/``/``bundle/`` so it is never mistaken for scan
    output."""
    return settings.data_dir / "work" / str(scan_id) / "dependencies_cache.json"


def _dir_mtime(path: Path) -> str:
    try:
        return str(path.stat().st_mtime_ns)
    except OSError:
        return "missing"


def _findings_fingerprint(findings) -> str:
    """Cheap deterministic fingerprint of the passed findings - covers BOTH
    suppression toggles (the route passes the non-suppressed set, so a
    suppress/restore changes the set) and re-runs (new finding ids)."""
    h = hashlib.sha256()
    for f in sorted(findings, key=lambda x: x.id):
        h.update(f"{f.id}:{f.tool}:{f.severity}\n".encode())
    return h.hexdigest()


def _cache_identity(scan, findings) -> str:
    """Identity of every inventory input. Cheap stats only - never walks."""
    parts = [scan.platform or "unknown"]
    work_dir = settings.data_dir / "work" / str(scan.id)
    if scan.platform == "android":
        parts.append(f"sources:{_dir_mtime(work_dir / 'decompiled' / 'sources')}")
        apk = _apk_path(scan)
        if apk is not None:
            try:
                st = apk.stat()
                parts.append(f"apk:{st.st_mtime_ns}:{st.st_size}")
            except OSError:
                pass
    else:
        app_root = _ios_app_root(work_dir)
        if app_root is not None:
            parts.append(f"bundle:{_dir_mtime(app_root)}")
    parts.append(_findings_fingerprint(findings))
    return "|".join(parts)


def _primary_tree_present(scan) -> bool:
    """The platform's primary tree dir exists (jadx ``sources`` / the iOS
    app bundle). Mirrors the smali_map pattern (``_tree_mtime`` -> None): a
    vanished tree is a cache MISS, never a reason to keep serving a stale
    payload."""
    work_dir = settings.data_dir / "work" / str(scan.id)
    if scan.platform == "android":
        return (work_dir / "decompiled" / "sources").is_dir()
    return _ios_app_root(work_dir) is not None


def _remember_cache(key: str, identity: str, payload: dict) -> None:
    _DEPENDENCIES_CACHE[key] = (identity, payload)
    # Evict the oldest-inserted entry when over the bound (dicts preserve
    # insertion order, so the first key is the oldest) - same rule as the
    # smali-mapping / graph explorer caches.
    while len(_DEPENDENCIES_CACHE) > _DEPENDENCIES_CACHE_MAX:
        _DEPENDENCIES_CACHE.pop(next(iter(_DEPENDENCIES_CACHE)))


def cached_inventory(scan, findings) -> dict | None:
    """The scan's cached inventory, or None on a miss.

    Identity-validated: a stale/torn file (shape change, partial write, or a
    suppression toggle since the cache was written) recomputes instead of
    serving garbage. A vanished tree is always a miss - never stale-serving.
    """
    if not _primary_tree_present(scan):
        return None
    identity = _cache_identity(scan, findings)
    key = str(cache_path_for(scan.id))
    cached = _DEPENDENCIES_CACHE.get(key)
    if cached is not None and cached[0] == identity:
        return cached[1]
    cache_path = Path(key)
    if cache_path.is_file():
        try:
            data = json.loads(cache_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = None
        if (
            data is not None
            and data.get("version") == _DEPENDENCIES_CACHE_VERSION
            and data.get("identity") == identity
            and isinstance(data.get("payload"), dict)
        ):
            _remember_cache(key, identity, data["payload"])
            return data["payload"]
    return None


def store_inventory(scan, findings, payload: dict) -> None:
    """Persist a computed inventory - in-memory + the on-disk cache file.

    Best-effort: a failed write (read-only FS etc.) still serves this process
    via the module cache; the next process recomputes. Atomic (tmp+rename) so
    a torn write never becomes the cache. Nothing is cached when the primary
    tree is missing (the smali_map precedent).
    """
    if not _primary_tree_present(scan):
        return
    identity = _cache_identity(scan, findings)
    key = str(cache_path_for(scan.id))
    _remember_cache(key, identity, payload)
    cache_path = Path(key)
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = cache_path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(
                {
                    "version": _DEPENDENCIES_CACHE_VERSION,
                    "identity": identity,
                    "payload": payload,
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        tmp.replace(cache_path)
    except OSError:
        pass  # best-effort cache

# Depth-2 grouping boundary: these top-level namespaces are umbrella roots -
# com/google, org/apache, androidx/... - so the group is the SECOND segment;
# a library that lives at the top level (okhttp3, retrofit2, rxjava) is its
# own group.
_GENERIC_TLDS = ("com", "org", "net", "io", "androidx", "kotlinx")

# JDK/runtime namespaces that ship with every JVM - not app dependencies.
_NOISE_GROUPS = frozenset({"java", "javax", "sun", "jdk", "dalvik", "kotlin"})

# Known third-party libraries -> human label. Matched as the LONGEST ancestor
# prefix of a package path, so ``com/google/android/gms/...`` groups under
# "com.google.android.gms" ("Google Play services") while the rest of
# ``com/google`` falls into the generic ``com.google`` bucket. Group keys are
# dotted names.
_KNOWN_ANDROID_LIBS: dict[str, str] = {
    "androidx": "AndroidX",
    "androidx.constraintlayout": "ConstraintLayout",
    "androidx.compose": "Jetpack Compose",
    "com.google.android.gms": "Google Play services",
    "com.google.android.material": "Material Components",
    "com.google.firebase": "Firebase",
    "com.google.gson": "Gson",
    "com.google.protobuf": "Protocol Buffers",
    "com.google.guava": "Guava",
    "com.google.dagger": "Dagger",
    "com.squareup": "Square (OkHttp/Picasso/Retrofit)",
    "okhttp3": "OkHttp",
    "retrofit2": "Retrofit",
    "io.reactivex": "RxJava",
    "org.apache": "Apache Commons",
    "org.bouncycastle": "BouncyCastle",
    "org.slf4j": "SLF4J",
    "org.json": "org.json",
    "com.fasterxml.jackson": "Jackson",
    "com.github.bumptech.glide": "Glide",
    "com.bumptech.glide": "Glide",
    "com.facebook": "Facebook SDK",
    "com.alibaba.fastjson": "Fastjson",
    "com.tencent": "Tencent SDKs",
    "com.android": "AOSP (com.android)",
    # Pre-AndroidX support library - lives under android/support/... and is a
    # real third-party dependency (bundled with the app), unlike the android.*
    # framework API itself.
    "android.support": "Android Support Library",
}

# Runtime framework markers - strong, file-name-based signals that the APK
# embeds a cross-platform engine (checked against the APK's zip namelist).
_RUNTIME_MARKERS: list[tuple[str, tuple[str, ...]]] = [
    ("Flutter", ("libflutter.so", "assets/flutter_assets/")),
    ("React Native", ("assets/index.android.bundle", "assets/index.android.jsbundle")),
    ("Unity", ("libunity.so", "libil2cpp.so", "assets/bin/Data/")),
    ("Cordova", ("assets/www/cordova.js", "cordova.js")),
    ("Xamarin", ("libmonodroid.so", "assemblies/", "libxamarin-app.so")),
    ("Capacitor", ("capacitor.config.json", "assets/public/")),
]

# iOS dylibs under these prefixes are Apple's own (the OS runtime); everything
# else - @rpath/... frameworks, bundled .dylibs - is a third-party dependency.
_IOS_SYSTEM_PREFIXES = ("/usr/", "/System/", "/Library/", "/private/")

# Cap the source-tree walk so a pathological decompile can never hang the
# endpoint; when it bites, ``truncated`` tells the UI the list is partial.
_MAX_WALK_FILES = 100_000


def _group_key(rel_dir: str) -> str | None:
    """Map a package-relative dir (slash- or dot-separated) to a dependency
    group key.

    Dotted group names: a known-library ancestor wins (longest match),
    otherwise the top-level segment - except the generic umbrella TLDs
    (com/google, org/apache, androidx) which group at the second segment.
    JDK/runtime namespaces return None (never shown as dependencies).
    """
    dotted = rel_dir.replace("/", ".")
    for known in sorted(_KNOWN_ANDROID_LIBS, key=len, reverse=True):
        if dotted == known or dotted.startswith(known + "."):
            return known
    parts = dotted.split(".")
    if parts[0] in _NOISE_GROUPS:
        return None
    if len(parts) >= 2 and parts[0] in _GENERIC_TLDS:
        return ".".join(parts[:2])
    return parts[0]


def _in_app(group: str, app_package: str | None) -> bool:
    """True when the group is (part of) the app's own package - never shown."""
    return bool(app_package) and (
        app_package == group or app_package.startswith(group + ".")
    )


def _walk_packages(sources: Path, app_package: str | None) -> tuple[dict[str, int], bool]:
    """Count source files per dependency group under the jadx ``sources`` tree.

    Returns ``(group -> file count, truncated)``. One bounded walk; the app's
    own package + JDK namespaces are excluded.
    """
    groups: dict[str, int] = {}
    truncated = False
    walked = 0
    if not sources.is_dir():
        return groups, truncated
    for dirpath, _dirnames, filenames in os.walk(sources):
        for fn in filenames:
            if not (fn.endswith(".java") or fn.endswith(".kt")):
                continue
            walked += 1
            if walked > _MAX_WALK_FILES:
                truncated = True
                break
            rel = os.path.relpath(dirpath, sources)
            if rel == ".":
                continue
            group = _group_key(rel)
            if group is None or _in_app(group, app_package):
                continue
            groups[group] = groups.get(group, 0) + 1
        if walked > _MAX_WALK_FILES:
            break
    return groups, truncated


def _finding_counts(findings, app_package: str | None) -> dict[str, dict[str, int]]:
    """Per-group finding tallies from the scan's semgrep findings.

    Finding ``file_path``s are root-relative (``com/google/android/gms/...`` -
    no ``sources/`` prefix), so they group with the same ``_group_key`` the
    tree walk uses. Suppressed findings are already filtered by the caller.
    """
    counts: dict[str, dict[str, int]] = {}
    for f in findings:
        if f.tool != TOOL_SEMGREP or not f.file_path:
            continue
        rel = Path(f.file_path).parent.as_posix()
        if rel == ".":
            continue
        group = _group_key(rel)
        if group is None or _in_app(group, app_package):
            continue
        entry = counts.setdefault(
            group, {"finding_count": 0, "high_count": 0, "medium_count": 0}
        )
        entry["finding_count"] += 1
        if f.severity == "high":
            entry["high_count"] += 1
        elif f.severity == "medium":
            entry["medium_count"] += 1
    return counts


def _android_manifest_meta(work_dir: Path) -> dict:
    """Package + SDK levels from the jadx-decoded AndroidManifest.xml."""
    mf = work_dir / "decompiled" / "resources" / "AndroidManifest.xml"
    if not mf.is_file():
        return {}
    try:
        root = ET.parse(mf).getroot()
    except (ET.ParseError, OSError):
        return {}
    meta: dict = {"package": root.get("package")}
    uses_sdk = root.find("uses-sdk")
    if uses_sdk is not None:
        meta["min_sdk"] = _int_or_none(uses_sdk.get(f"{{{ANDROID_NS}}}minSdkVersion"))
        meta["target_sdk"] = _int_or_none(
            uses_sdk.get(f"{{{ANDROID_NS}}}targetSdkVersion")
        )
    return meta


def _int_or_none(value) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _native_libs(apk_path: Path) -> tuple[list[dict], bool]:
    """``lib/<abi>/*.so`` shared libraries from the APK (grouped by name)."""
    libs: dict[str, set[str]] = {}
    try:
        with zipfile.ZipFile(apk_path) as zf:
            for name in zf.namelist():
                if name.startswith("lib/") and name.endswith(".so"):
                    parts = name.split("/")
                    if len(parts) == 3:
                        libs.setdefault(parts[2], set()).add(parts[1])
    except (zipfile.BadZipFile, OSError):
        return [], False
    return [
        {"name": lib, "abis": sorted(abis)} for lib, abis in sorted(libs.items())
    ], False


def _runtime_markers(apk_path: Path) -> list[str]:
    """Cross-platform engine detection from the APK's file layout."""
    markers: list[str] = []
    try:
        with zipfile.ZipFile(apk_path) as zf:
            names = zf.namelist()
    except (zipfile.BadZipFile, OSError):
        return markers
    for label, needles in _RUNTIME_MARKERS:
        # Substring match against the full entry names: libflutter.so lives at
        # lib/<abi>/libflutter.so - exact list membership would never hit.
        if any(needle in name for name in names for needle in needles):
            markers.append(label)
    return markers


def _detail_dict(finding) -> dict:
    """The persisted ``detail`` column is JSON text on the ORM row (the API
    schema parses it); handle both shapes."""
    d = finding.detail
    if isinstance(d, dict):
        return d
    if isinstance(d, str) and d:
        try:
            return json.loads(d)
        except json.JSONDecodeError:
            return {}
    return {}


def _ios_app_root(work_dir: Path) -> Path | None:
    """``bundle/Payload/*.app`` - the unpacked app bundle, if present."""
    payload = work_dir / "bundle" / "Payload"
    if not payload.is_dir():
        return None
    for child in sorted(payload.iterdir()):
        if child.is_dir() and child.suffix == ".app":
            return child
    return None


def _ios_plist_meta(app_root: Path) -> dict:
    from app.analysis.ios import plist as plist_mod

    info = app_root / "Info.plist"
    if not info.is_file():
        return {}
    try:
        data = plist_mod.load_info_plist(info)
    except plist_mod.PlistError:
        return {}
    return {
        "bundle_id": data.get("CFBundleIdentifier"),
        "version": data.get("CFBundleShortVersionString"),
    }


def _ios_dylibs(findings) -> list[str]:
    """Linked dylibs from the persisted LIEF binary profile (the "Linked
    dylibs (N)" info finding emitted per iOS scan at analysis time)."""
    for f in findings:
        if f.tool == TOOL_LIEF and (f.title or "").startswith("Linked dylibs"):
            return list(_detail_dict(f).get("dylibs") or [])
    return []


def _is_system_dylib(name: str) -> bool:
    return name.startswith(_IOS_SYSTEM_PREFIXES) or "libswift" in name


def _ios_frameworks(app_root: Path) -> list[str]:
    """Embedded ``Frameworks/*.framework`` bundles + loose .dylibs."""
    frameworks_dir = app_root / "Frameworks"
    out: set[str] = set()
    if frameworks_dir.is_dir():
        for child in sorted(frameworks_dir.iterdir()):
            if child.is_dir() and child.name.endswith(".framework"):
                out.add(child.name[: -len(".framework")])
            elif child.is_file() and child.name.endswith(".dylib"):
                out.add(child.name)
    return sorted(out)


# Kind ordering for the response (the UI groups by kind anyway - this keeps
# the payload stable and readable in tests/CLI).
_KIND_RANK = {"package": 0, "native": 1, "framework": 2, "dylib": 3}


def inventory(scan, findings) -> dict:
    """Build the Dependencies tab payload for a scan (best-effort throughout -
    a missing tree/APK/bundle degrades to an empty inventory, never a crash).

    ``findings`` must be the scan's NON-suppressed Finding rows (the caller
    filters; the route shares the risk/summary convention).
    """
    if scan.platform == "android":
        return _android_inventory(scan, findings)
    if scan.platform == "ios":
        return _ios_inventory(scan, findings)
    return {"platform": scan.platform or "unknown", "dependencies": []}


def _apk_path(scan) -> Path | None:
    """The uploaded APK file, or None when missing (mirrors jobs.py)."""
    storage = Path(scan.storage_path) if scan.storage_path else None
    apk = storage / scan.filename if storage and storage.is_dir() else storage
    return apk if apk is not None and apk.is_file() else None


def _android_inventory(scan, findings) -> dict:
    work_dir = settings.data_dir / "work" / str(scan.id)
    app_meta = _android_manifest_meta(work_dir)
    app_package = app_meta.get("package")

    packages, truncated = _walk_packages(
        work_dir / "decompiled" / "sources", app_package
    )
    counts = _finding_counts(findings, app_package)

    items: list[dict] = []
    # The walk is the primary source, but a semgrep finding inside a package
    # is authoritative evidence of presence too (e.g. the walk hit its cap, or
    # the file was filtered) - a finding-bearing group never disappears.
    for group in sorted(set(packages) | set(counts)):
        n = packages.get(group, 0)
        c = counts.get(group, {})
        if n == 0 and not c:
            continue
        items.append(
            {
                "name": group,
                "label": _KNOWN_ANDROID_LIBS.get(group),
                "kind": "package",
                "evidence": (
                    f"{n} source file{'s' if n != 1 else ''} under "
                    f"sources/{group.replace('.', '/')}"
                    if n
                    else "present - flagged by code findings"
                ),
                "file_count": n or None,
                "finding_count": c.get("finding_count", 0),
                "high_count": c.get("high_count", 0),
                "medium_count": c.get("medium_count", 0),
            }
        )

    apk_path = _apk_path(scan)
    if apk_path is not None:
        native, _ = _native_libs(apk_path)
        for lib in native:
            items.append(
                {
                    "name": lib["name"],
                    "kind": "native",
                    "evidence": f"APK lib/ - {' · '.join(lib['abis'])}",
                    "abis": lib["abis"],
                }
            )

    items.sort(
        key=lambda it: (
            _KIND_RANK.get(it["kind"], 9),
            -it.get("high_count", 0),
            -it.get("finding_count", 0),
            it["name"].lower(),
        )
    )
    return {
        "platform": "android",
        "app": app_meta,
        "runtime_markers": _runtime_markers(apk_path) if apk_path else [],
        "dependencies": items,
        "total": len(items),
        "truncated": truncated,
    }


def _ios_inventory(scan, findings) -> dict:
    work_dir = settings.data_dir / "work" / str(scan.id)
    app_root = _ios_app_root(work_dir)
    app_meta = _ios_plist_meta(app_root) if app_root else {}

    items: list[dict] = []
    for name in _ios_dylibs(findings):
        items.append(
            {
                "name": name,
                "kind": "dylib",
                "evidence": (
                    "Mach-O linked dylib"
                    if _is_system_dylib(name)
                    else "Mach-O linked dylib (third-party)"
                ),
                "system": _is_system_dylib(name),
            }
        )
    if app_root is not None:
        for fw in _ios_frameworks(app_root):
            items.append(
                {
                    "name": fw,
                    "kind": "framework",
                    "evidence": "embedded Frameworks/ bundle",
                }
            )

    items.sort(
        key=lambda it: (
            _KIND_RANK.get(it["kind"], 9),
            it.get("system") is True,
            it["name"].lower(),
        )
    )
    return {
        "platform": "ios",
        "app": app_meta,
        "runtime_markers": [],
        "dependencies": items,
        "total": len(items),
        "truncated": False,
    }
