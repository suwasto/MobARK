"""Agent tools — Layers 2 + 3 (plain-text + Graphify) and the M6
app-oriented set, zero embeddings.

Layer 2 — ``search_code`` / ``read_file``: plain-text operations over
whatever decompiled/extracted output exists for the scan's platform. The tools
themselves contain no platform branching — the ONLY platform knowledge lives
in ``resolve_tree_root`` (which tree to search/read).

Layer 3 — ``graph_query`` / ``graph_path`` / ``graph_explain``: Graphify
traversal for Android call-graph/structural questions. Android only: iOS has
no decompiled source tree, so no graph exists and the tools fail with a clear
reason. No Semgrep-based substitute is built for iOS graphing.

M6 — app-oriented tools (``read_manifest`` / ``get_decompiled_class`` /
``get_permissions`` / ``run_secrets_scan`` / ``search_strings``): the PRD
surface. These are deliberately platform-aware (unlike the Layer 2/3 tools):
Android reads the decompiled AndroidManifest.xml + jadx sources, iOS reads
Info.plist + the bundle. ``run_secrets_scan`` wraps the existing M1 gitleaks
wrapper — the agent layer never invokes gitleaks as a raw subprocess.
"""
from __future__ import annotations

import json
import os
import plistlib
import re
from pathlib import Path

from app.config import settings
from app.models import Scan

_BINARY_SNIFF_BYTES = 8192
_MAX_SEARCH_FILE_BYTES = 5 * 1024 * 1024
_MAX_SEARCH_HITS = 100
_MAX_READ_CHARS = 50_000

# M6 app-oriented tool bounds: the on-demand secrets re-scan is capped hard so
# a targeted run can never tie up the agent loop like a full pipeline scan.
_SECRETS_SCAN_TIMEOUT = 30  # seconds per run_secrets_scan call
# Matches gitleaks' own baked-in --max-target-megabytes 50 in
# analysis/gitleaks.py::scan_directory so the app guard never passes a target
# that the wrapper would then refuse internally.
_SECRETS_SCAN_MAX_MB = 50  # refuse targets larger than this
_SECRETS_SCAN_MAX_FILES = 5000  # refuse target trees with more files
_SECRETS_SCAN_MAX_RESULTS = 50  # findings returned to the model
_MAX_CLASS_CHARS = 60_000  # get_decompiled_class source cap
_MAX_MANIFEST_CHARS = 20_000  # read_manifest JSON cap
_MAX_PERMISSIONS = 200  # get_permissions row cap
_MAX_COMPONENTS = 100  # read_manifest exported-component cap

# Resource/string files for search_strings (Android strings.xml + layouts +
# JSON resources; iOS plist/strings/json/text resources). ``**/*.xml`` covers
# Android strings.xml; the rest add the other resource formats both platforms.
_STRING_GLOBS = (
    "**/*.xml",
    "**/*.strings",
    "**/*.json",
    "**/*.properties",
    "**/*.txt",
)

# Tools that are Android-only in v1 (no decompiled Swift/ObjC source on iOS).
_ANDROID_ONLY_TOOLS = frozenset({"get_decompiled_class"})

# M7 web tools: offered ONLY when BOTH gates hold — the scan's web-research
# opt-in (scans.web_research_enabled) AND an Active search engine
# (SearchStore.active()). They are the one deliberate egress in MASA, so the
# model never even sees them otherwise (same filter as _ANDROID_ONLY_TOOLS).
_WEB_TOOLS = frozenset({"web_search", "web_fetch"})
_MAX_WEB_RESULTS = 10
_WEB_FETCH_MAX_CHARS = 8000

_ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Suffixes treated as text outright; anything else is binary-sniffed.
_TEXT_SUFFIXES = {
    ".java", ".kt", ".kts", ".xml", ".plist", ".json", ".txt", ".properties",
    ".js", ".ts", ".html", ".css", ".md", ".smali", ".gradle", ".yaml",
    ".yml", ".swift", ".m", ".h", ".c", ".cpp", ".py", ".toml", ".ini",
    ".csv", ".strings", ".entitlements",
}


class ToolError(RuntimeError):
    """A tool failed cleanly — surfaced to the model as a JSON error result."""


# ---- scan tree resolution (the only platform knowledge) ----------------------


def resolve_tree_root(scan: Scan) -> Path:
    """The decompiled/extracted tree to search and read for a scan."""
    work = settings.data_dir / "work" / str(scan.id)
    if scan.platform == "android":
        decompiled = work / "decompiled"
        sources = decompiled / "sources"
        return sources if sources.is_dir() else decompiled
    if scan.platform == "ios":
        payload = work / "bundle" / "Payload"
        if payload.is_dir():
            app_dirs = sorted(p for p in payload.iterdir() if p.is_dir() and p.suffix == ".app")
            if app_dirs:
                return app_dirs[0]
        return payload
    raise ToolError(f"scan {scan.id} has no supported platform ({scan.platform!r})")


def _load_scan(scan_id: int) -> Scan:
    from app.db import SessionLocal  # deferred so tests can monkeypatch it

    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
    finally:
        db.close()
    if scan is None:
        raise ToolError(f"scan {scan_id} not found")
    return scan


def _tree_root(scan_id: int) -> Path:
    root = resolve_tree_root(_load_scan(scan_id))
    if not root.is_dir():
        raise ToolError(f"no decompiled/extracted tree for scan {scan_id} at {root}")
    return root


# ---- Layer 2: search_code / read_file ----------------------------------------


def is_text_file(path: Path) -> bool:
    """Binary sniff: NUL byte in the head => binary, else text.

    Public because the M5 decompiler tree module reuses the same rule.
    """
    if path.suffix.lower() in _TEXT_SUFFIXES:
        return True
    try:
        with path.open("rb") as fh:
            head = fh.read(_BINARY_SNIFF_BYTES)
    except OSError:
        return False
    return b"\x00" not in head


def search_code(
    scan_id: int,
    pattern: str,
    glob: str = "**/*",
    max_hits: int = _MAX_SEARCH_HITS,
) -> list[dict]:
    """Regex search over the scan tree, returns ``[{file, line, snippet}]``.

    Identical for Android and iOS — plain text over the scan's tree. Binary
    files are skipped (they are covered by gitleaks / the import-table
    scanner, not grep).
    """
    root = _tree_root(scan_id)
    try:
        regex = re.compile(pattern)
    except re.error as exc:
        raise ToolError(f"invalid regex {pattern!r}: {exc}") from exc

    hits: list[dict] = []
    for path in root.rglob(glob):
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > _MAX_SEARCH_FILE_BYTES or not is_text_file(path):
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = path.relative_to(root).as_posix()
        for lineno, line in enumerate(text.splitlines(), 1):
            if regex.search(line):
                hits.append(
                    {"file": rel, "line": lineno, "snippet": line.strip()[:_MAX_READ_CHARS]}
                )
                if len(hits) >= max_hits:
                    return hits
    return hits


def read_file(
    scan_id: int,
    path: str,
    line_start: int | None = None,
    line_end: int | None = None,
    max_chars: int = _MAX_READ_CHARS,
) -> str:
    """Read a file relative to the scan tree; inclusive ``line_start``/``line_end``.

    Path-traversal guarded: the resolved path must stay inside the tree.
    Binary Info.plist files are decoded via plistlib and rendered as text;
    other binary files are refused with a clear message.
    """
    root = _tree_root(scan_id)
    target = (root / path).resolve()
    if not target.is_relative_to(root.resolve()):
        raise ToolError(f"path escapes the scan tree: {path!r}")
    if not target.is_file():
        raise ToolError(f"not a file in the scan tree: {path}")

    try:
        data = target.read_bytes()
    except OSError as exc:
        raise ToolError(f"cannot read {path}: {exc}") from exc

    if target.suffix.lower() == ".plist":
        try:
            plist = plistlib.loads(data)
        except plistlib.InvalidFileException:
            pass  # not a (parseable) plist — fall through to text read
        else:
            return _cap(json.dumps(plist, indent=2, default=str), max_chars)

    if b"\x00" in data[:_BINARY_SNIFF_BYTES]:  # binary — see is_text_file()
        raise ToolError(
            f"{path} is a binary file — no text content (use the findings / import-table "
            "scanner for binary-level evidence)"
        )

    text = data.decode("utf-8", errors="replace")
    if line_start is not None or line_end is not None:
        lines = text.splitlines()
        start = line_start or 1
        end = min(line_end or len(lines), len(lines))
        text = "\n".join(lines[max(start, 1) - 1 : end])
    return _cap(text, max_chars)


def _cap(text: str, max_chars: int) -> str:
    if len(text) > max_chars:
        return text[:max_chars] + "…"
    return text


# ---- M7 web research tools (gated, on-demand) --------------------------------
# Two layers gate these (owner decision, Aug 9): the per-scan opt-in (the
# dock 🌐 toggle -> scans.web_research_enabled, default off) AND an Active
# search engine (the Settings radio list -> SearchStore.active()). The tools
# are only *offered* to the model when both hold, and the handlers re-check
# both defensively — a raw API caller can never invoke web egress on a scan
# that didn't opt in.


def web_tools_allowed(scan_id: int) -> bool:
    """Both gates: the scan's web-research opt-in AND an Active search engine.

    Shared by ``chat.py`` (decides whether the web tools are offered at all)
    and the tool handlers (defense in depth). Never raises — a missing scan
    or store simply denies.
    """
    from app.db import SessionLocal
    from app.models import Scan

    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        enabled = bool(scan is not None and scan.web_research_enabled)
    finally:
        db.close()
    if not enabled:
        return False
    from app.search.backends import get_search_store

    return get_search_store().active() is not None


def _deny_web() -> ToolError:
    return ToolError(
        "web research is not enabled for this scan — turn on the Agent dock "
        "🌐 toggle (and make sure a search engine is Active in Settings -> "
        "Search & research)"
    )


def web_search(scan_id: int, query: str) -> list[dict]:
    """Search the web via the single Active search engine (SearXNG).

    Returns ``[{title, url, snippet, engine}]`` (top ``_MAX_WEB_RESULTS``) so
    the model can cite source URLs. Errors carry the compose hint for the
    bundled engine (``docker compose --profile web up -d searxng``).
    """
    if not web_tools_allowed(scan_id):
        raise _deny_web()
    from app.search.backends import get_search_store
    from app.search.client import SearchError
    from app.search.client import query as search_query

    backend = get_search_store().active()
    if backend is None:
        raise ToolError(
            "no Active search engine — enable one in Settings -> Search & research"
        )
    try:
        return search_query(backend, query, limit=_MAX_WEB_RESULTS)
    except SearchError as exc:
        raise ToolError(str(exc)) from exc


def web_fetch(scan_id: int, url: str) -> dict:
    """Fetch one page (bounded, SSRF-guarded) and extract article text.

    Returns ``{"url", "title", "text"}`` — the model cites the post-redirect
    URL. Static pages only in v1; JS-rendered pages degrade cleanly.
    """
    if not web_tools_allowed(scan_id):
        raise _deny_web()
    from app.search.client import SearchError
    from app.search.client import web_fetch as fetch_page

    try:
        page = fetch_page(url)
    except SearchError as exc:
        raise ToolError(str(exc)) from exc
    page["text"] = page["text"][:_WEB_FETCH_MAX_CHARS]
    return page


# ---- M6 app-oriented tools (platform-aware by design) ------------------------
# Unlike the Layer 2/3 tools, these intentionally know the platform — the
# contract is ``read_manifest`` = AndroidManifest.xml / Info.plist and
# ``get_permissions`` = uses-permission set / usage-description keys. The
# platform-only filter (``_ANDROID_ONLY_TOOLS`` + ``schemas_for_platform``)
# keeps iOS from ever being *offered* the Android-only class tool.


def _android_manifest_path(scan: Scan) -> Path:
    """The decompiled ``resources/AndroidManifest.xml`` for a scan.

    jadx puts it under ``<decompiled>/resources/``; when ``resolve_tree_root``
    fell back to the whole ``decompiled`` dir (no ``sources/``), look directly
    under the root. Defensive both layouts.
    """
    root = resolve_tree_root(scan)
    candidate = root.parent / "resources" / "AndroidManifest.xml"
    if not candidate.is_file():
        candidate = root / "resources" / "AndroidManifest.xml"
    if not candidate.is_file():
        raise ToolError(f"AndroidManifest.xml not found at {candidate}")
    return candidate


def _shrink_list_fields(value: dict, max_chars: int) -> dict:
    """Trim the largest list fields until the JSON payload fits ``max_chars``.

    Keeps a bounded result (never a truncated JSON string): lists get halved
    repeatedly; fields that are still huge after the loop stay as-is and the
    caller's serialization caps the result. Values are always JSON-safe.
    """
    for _ in range(16):
        if len(json.dumps(value, default=str)) <= max_chars:
            return value
        largest = max(
            (k for k, v in value.items() if isinstance(v, list)),
            key=lambda k: len(value[k]),
            default=None,
        )
        if largest is None:
            break
        value[largest] = value[largest][: max(1, len(value[largest]) // 2)]
    return value


def read_manifest(scan_id: int) -> dict:
    """Bounded manifest summary — Android: decompiled AndroidManifest.xml;
iOS: Info.plist. Different shapes per platform (see the TOOL_SCHEMAS
description); both are JSON-safe and capped."""
    scan = _load_scan(scan_id)
    if scan.platform == "android":
        return _android_manifest_summary(scan)
    if scan.platform == "ios":
        return _ios_manifest_summary(scan)
    raise ToolError(f"scan {scan_id} has no supported platform ({scan.platform!r})")


def _android_manifest_summary(scan: Scan) -> dict:
    import xml.etree.ElementTree as ET

    path = _android_manifest_path(scan)
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        raise ToolError(f"cannot parse AndroidManifest.xml: {exc}") from exc
    root_el = tree.getroot()
    if root_el is None:
        raise ToolError("AndroidManifest.xml is empty")

    def a(el, name: str) -> str | None:
        return el.get(f"{{{_ANDROID_NS}}}{name}")

    out: dict = {"package": root_el.get("package")}
    version_code = a(root_el, "versionCode")
    version_name = a(root_el, "versionName")
    if version_code is not None:
        out["version_code"] = version_code
    if version_name is not None:
        out["version_name"] = version_name

    uses_sdk = root_el.find("uses-sdk")
    if uses_sdk is not None:
        min_sdk = a(uses_sdk, "minSdkVersion")
        target_sdk = a(uses_sdk, "targetSdkVersion")
        if min_sdk is not None:
            out["min_sdk"] = min_sdk
        if target_sdk is not None:
            out["target_sdk"] = target_sdk

    application = root_el.find("application")
    if application is not None:
        for key, attr in (
            ("debuggable", "debuggable"),
            ("allow_backup", "allowBackup"),
            ("cleartext_traffic", "usesCleartextTraffic"),
        ):
            val = a(application, attr)
            if val is not None:
                out[key] = val.lower() == "true"

    components: list[dict] = []
    if application is not None:
        for kind in ("activity", "service", "receiver", "provider"):
            for comp in application.iter(kind):
                name = a(comp, "name")
                if not name:
                    continue
                has_filter = any(c.tag == "intent-filter" for c in comp)
                exported = a(comp, "exported")
                effective = (
                    True
                    if exported == "true"
                    else False
                    if exported == "false"
                    else has_filter  # pre-Android-12 implicit export
                )
                components.append(
                    {
                        "name": name,
                        "kind": kind,
                        "exported": effective,
                        "has_intent_filter": has_filter,
                    }
                )
                if len(components) >= _MAX_COMPONENTS:
                    break
            if len(components) >= _MAX_COMPONENTS:
                break
    if components:
        out["exported_components"] = components
    return _shrink_list_fields(out, _MAX_MANIFEST_CHARS)


def _ios_manifest_summary(scan: Scan) -> dict:
    from app.analysis.ios.plist import (
        SENSITIVE_API_KEYS,
        USAGE_KEYS,
        PlistError,
        load_info_plist,
    )

    root = resolve_tree_root(scan)
    plist_path = root / "Info.plist"
    if not plist_path.is_file():
        raise ToolError(f"Info.plist not found in the bundle ({plist_path})")
    try:
        plist = load_info_plist(plist_path)
    except PlistError as exc:
        raise ToolError(f"cannot parse Info.plist: {exc}") from exc

    out = {
        "bundle_identifier": plist.get("CFBundleIdentifier"),
        "bundle_name": plist.get("CFBundleName") or plist.get("CFBundleDisplayName"),
        "bundle_version": plist.get("CFBundleShortVersionString"),
        "minimum_os_version": plist.get("MinimumOSVersion"),
        "app_transport_security": plist.get("NSAppTransportSecurity") or {},
        "background_modes": plist.get("UIBackgroundModes") or [],
    }
    usage = {
        key: {"label": USAGE_KEYS.get(key, key), "value": plist.get(key)}
        for key in plist
        if key in SENSITIVE_API_KEYS
    }
    if usage:
        out["usage_descriptions"] = usage
    return _shrink_list_fields(out, _MAX_MANIFEST_CHARS)


def get_decompiled_class(scan_id: int, fqcn: str) -> str:
    """Android only: decompiled source of one class from its fully-qualified
    name (``com.app.Foo`` → ``sources/com/app/Foo.java``; inner classes keep
    ``$``). Bounded source; clean not-found error. iOS gets an explicit
    "no decompiled source" error — there is no Swift/ObjC source in v1."""
    scan = _load_scan(scan_id)
    if scan.platform != "android":
        raise ToolError(
            "no decompiled source on iOS — get_decompiled_class is Android-only "
            "(use read_manifest / get_permissions / search_strings on the bundle)"
        )
    if not fqcn or ".." in fqcn or fqcn.startswith("/"):
        raise ToolError(f"invalid class name {fqcn!r}")
    root = resolve_tree_root(scan)
    rel = fqcn.replace(".", "/")
    for suffix in (".java", ".kt"):
        candidate = (root / f"{rel}{suffix}").resolve()
        if candidate.is_relative_to(root.resolve()) and candidate.is_file():
            try:
                text = candidate.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                raise ToolError(f"cannot read {candidate}: {exc}") from exc
            return _cap(text, _MAX_CLASS_CHARS)
    raise ToolError(
        f"class {fqcn!r} not found in the decompiled source tree "
        f"(tried {rel}.java/.kt)"
    )


def get_permissions(scan_id: int) -> list[dict]:
    """Requested permissions / usage-description keys.

    Android: every ``<uses-permission>`` from the decompiled manifest with
    its ``maxSdkVersion`` and a ``dangerous`` flag (the app's curated risky
    set — ``analysis/manifest.py::RISKY_PERMISSIONS``, not the full SDK
    permission database). iOS: declared usage-description keys (camera,
    microphone, location, …) — the same ``SENSITIVE_API_KEYS`` surface
    ``read_manifest`` uses, so the two tools never disagree.
    """
    scan = _load_scan(scan_id)
    if scan.platform == "android":
        return _android_permissions(scan)
    if scan.platform == "ios":
        return _ios_permissions(scan)
    raise ToolError(f"scan {scan_id} has no supported platform ({scan.platform!r})")


def _android_permissions(scan: Scan) -> list[dict]:
    import xml.etree.ElementTree as ET

    from app.analysis.manifest import RISKY_PERMISSIONS

    path = _android_manifest_path(scan)
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        raise ToolError(f"cannot parse AndroidManifest.xml: {exc}") from exc
    rows: list[dict] = []
    for perm in tree.getroot().iter("uses-permission"):
        name = perm.get(f"{{{_ANDROID_NS}}}name")
        if not name:
            continue
        max_sdk = perm.get(f"{{{_ANDROID_NS}}}maxSdkVersion")
        rows.append(
            {
                "name": name,
                "max_sdk_version": (
                    int(max_sdk) if max_sdk and max_sdk.isdigit() else None
                ),
                "dangerous": name in RISKY_PERMISSIONS,
            }
        )
        if len(rows) >= _MAX_PERMISSIONS:
            break
    return rows


def _ios_permissions(scan: Scan) -> list[dict]:
    from app.analysis.ios.plist import (
        SENSITIVE_API_KEYS,
        USAGE_KEYS,
        PlistError,
        load_info_plist,
    )

    root = resolve_tree_root(scan)
    plist_path = root / "Info.plist"
    if not plist_path.is_file():
        raise ToolError(f"Info.plist not found in the bundle ({plist_path})")
    try:
        plist = load_info_plist(plist_path)
    except PlistError as exc:
        raise ToolError(f"cannot parse Info.plist: {exc}") from exc
    return [
        {"key": key, "label": USAGE_KEYS.get(key, key), "value": plist.get(key)}
        for key in plist
        if key in SENSITIVE_API_KEYS
    ]


def run_secrets_scan(scan_id: int, path: str = "") -> list[dict]:
    """On-demand gitleaks re-run over a targeted directory in the scan tree.

    The full persisted secrets scan is already in the findings context (Layer
    1) — this re-runs the M1 gitleaks wrapper over a narrower path (e.g. a
    resource dir the scan skipped) with a per-call timeout + size guard.
    Wraps ``analysis/gitleaks.py::scan_directory``; the agent layer never
    invokes gitleaks directly.
    """
    import tempfile

    from app.analysis import gitleaks

    scan = _load_scan(scan_id)
    root = _tree_root(scan_id)
    target = (root / path).resolve() if path else root.resolve()
    if not target.is_relative_to(root.resolve()):
        raise ToolError(f"path escapes the scan tree: {path!r}")
    if not target.is_dir():
        raise ToolError(f"{path or '.'} is not a directory inside the scan tree")
    _guard_secrets_target(target)

    report_fd, report_name = tempfile.mkstemp(
        prefix=f"masa-secrets-{scan_id}-", suffix=".json"
    )
    os.close(report_fd)
    try:
        try:
            # iOS scans reuse the platform ruleset (M4 Layer 1) so an on-demand
            # re-run catches the same string-level rules (e.g.
            # kSecAttrAccessibleAlways) as the persisted pipeline scan.
            config = (
                Path(gitleaks.__file__).parent / "resources" / "gitleaks_ios.toml"
                if scan.platform == "ios"
                else None
            )
            result = gitleaks.scan_directory(
                target, Path(report_name), timeout=_SECRETS_SCAN_TIMEOUT, config=config
            )
        except gitleaks.GitleaksError as exc:
            raise ToolError(f"gitleaks unavailable for the on-demand scan: {exc}") from exc
        if result.errors:
            raise ToolError(f"secrets scan failed: {'; '.join(result.errors)}")
        return [
            {
                "rule_id": f.detail.get("rule_id") if f.detail else None,
                "file": f.file_path,
                "line": f.line_number,
                "severity": f.severity,
                "description": f.title,
            }
            for f in result.findings
        ][:_SECRETS_SCAN_MAX_RESULTS]
    finally:
        Path(report_name).unlink(missing_ok=True)


def _guard_secrets_target(target: Path) -> None:
    """Refuse on-demand secrets targets that are too large to bound the call
    (the walk itself is file-count-capped so it always terminates)."""
    total_bytes = 0
    files = 0
    for p in target.rglob("*"):
        if not p.is_file():
            continue
        files += 1
        if files > _SECRETS_SCAN_MAX_FILES:
            raise ToolError(
                f"secrets scan target has more than {_SECRETS_SCAN_MAX_FILES} files — "
                "pick a narrower path"
            )
        try:
            total_bytes += p.stat().st_size
        except OSError:
            continue
        if total_bytes > _SECRETS_SCAN_MAX_MB * 1024 * 1024:
            raise ToolError(
                f"secrets scan target exceeds {_SECRETS_SCAN_MAX_MB} MB — "
                "pick a narrower path"
            )


def search_strings(scan_id: int, pattern: str, max_hits: int = _MAX_SEARCH_HITS) -> list[dict]:
    """Regex search restricted to resource/string files — same result shape
    as ``search_code`` (``[{file, line, snippet}]``). Targets strings.xml /
    layouts / plists / JSON+text resources on both platforms."""
    seen: set[tuple[str, int]] = set()
    out: list[dict] = []
    for glob in _STRING_GLOBS:
        for hit in search_code(scan_id, pattern, glob=glob, max_hits=max_hits):
            key = (hit["file"], hit["line"])
            if key in seen:
                continue
            seen.add(key)
            out.append(hit)
            if len(out) >= max_hits:
                return out
    return out


# ---- Layer 3: Graphify tools (Android only) ----------------------------------


def _graph_path(scan_id: int) -> Path:
    from app.graph import graphify

    path = graphify.graph_path_for(scan_id)
    if not path.is_file():
        raise ToolError(
            f"no code graph for scan {scan_id} at {path} — run the graph build first "
            "(Android only; iOS has no decompiled source tree)"
        )
    return path


def graph_query(scan_id: int, question: str, budget: int = 1500) -> dict:
    """Structural question -> graph traversal answer ``{found, text, nodes, via}``."""
    from app.graph import graphify

    return graphify.query(_graph_path(scan_id), question, budget=budget)


def graph_path_between(scan_id: int, node_a: str, node_b: str) -> str:
    from app.graph import graphify

    return graphify.path_between(_graph_path(scan_id), node_a, node_b)


def graph_explain_node(scan_id: int, node: str) -> str:
    from app.graph import graphify

    return graphify.explain(_graph_path(scan_id), node)


# ---- LLM-facing tool surface -------------------------------------------------

TOOL_SCHEMAS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "search_code",
            "description": (
                "Regex search over the app's decompiled/extracted file tree (Android: "
                "jadx Java + resources; iOS: unpacked bundle files such as Info.plist and "
                "resources). Returns up to 100 matches with file, line, and the matching "
                "line text. Binary files are skipped. Works for both platforms."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Regex to search for"},
                    "glob": {
                        "type": "string",
                        "description": (
                            "Filename glob filter, e.g. '*.java' or '**/*.xml'. "
                            "Default '**/*'."
                        ),
                    },
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": (
                "Read a file from the app's decompiled/extracted tree (path relative to "
                "the tree), optionally a 1-indexed inclusive line range. Binary plist "
                "files are decoded to text. Works for both platforms."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Relative path inside the scan tree",
                    },
                    "line_start": {
                        "type": "integer",
                        "description": "First line (1-indexed, inclusive)",
                    },
                    "line_end": {"type": "integer", "description": "Last line (inclusive)"},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_manifest",
            "description": (
                "Bounded manifest summary. Android: package, version, min/target "
                "SDK, debuggable, allowBackup, cleartext-traffic flag, and exported "
                "components with intent filters. iOS: bundle id/name/version, "
                "MinimumOSVersion, App Transport Security config, usage-description "
                "strings, and background modes (from Info.plist). Returns JSON."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_decompiled_class",
            "description": (
                "Android only. Read the decompiled source of one class from its "
                "fully-qualified name (e.g. 'com.app.LoginActivity'; inner classes "
                "keep the $, e.g. 'com.app.Foo$Inner'). iOS has no decompiled "
                "source — the tool errors explicitly; use read_manifest / "
                "search_strings there instead."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "fqcn": {
                        "type": "string",
                        "description": "Fully-qualified class name",
                    },
                },
                "required": ["fqcn"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_permissions",
            "description": (
                "Permissions the app requests. Android: every uses-permission from "
                "the manifest with maxSdkVersion and a dangerous flag (curated "
                "risky set). iOS: declared usage-description keys (camera, "
                "microphone, location, ...) from Info.plist. Returns JSON."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_secrets_scan",
            "description": (
                "On-demand secrets (gitleaks) re-run over a targeted directory "
                "inside the scan tree (e.g. 'res' or 'assets'). The persisted "
                "secrets scan is already in the findings context — use this only "
                "to re-check a specific path. Bounded per call (~30s timeout, "
                "size-guarded). Returns normalized findings."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": (
                            "Directory relative to the scan tree root; empty/omitted "
                            "scans the whole tree"
                        ),
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_strings",
            "description": (
                "Regex search restricted to resource/string files (strings.xml, "
                "layouts, plists, JSON/text resources) — same result shape as "
                "search_code but scoped to app resources. Works for both "
                "platforms."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Regex to search for"},
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "graph_query",
            "description": (
                "Android only. Answer a structural/call-graph question (e.g. 'where is X', "
                "'what calls Y') by traversing the per-scan code graph. Fails cleanly when "
                "no graph is built. Do not use for iOS."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "question": {"type": "string", "description": "Structural question"},
                    "budget": {
                        "type": "integer",
                        "description": "Answer token budget (default 1500)",
                    },
                },
                "required": ["question"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "graph_path",
            "description": "Android only. Shortest path between two graph nodes (identifiers).",
            "parameters": {
                "type": "object",
                "properties": {
                    "node_a": {"type": "string", "description": "Start node identifier/label"},
                    "node_b": {"type": "string", "description": "End node identifier/label"},
                },
                "required": ["node_a", "node_b"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "graph_explain",
            "description": "Android only. Plain-language explanation of a graph node.",
            "parameters": {
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node identifier/label"},
                },
                "required": ["node"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": (
                "Search the public web via the configured search engine "
                "(SearXNG). Use ONLY when the question needs current or "
                "external information the scan data cannot answer — CVE "
                "lookups for detected library versions, OWASP MASTG "
                "guidance, dependency advisories. Returns up to 10 results "
                "with title, url, and snippet — always cite the source URLs "
                "you use. Queries leave this machine by design (the scan "
                "opted in)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query"},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "web_fetch",
            "description": (
                "Fetch one web page (static content only — no browser in "
                "v1) and extract its article text. Use on URLs from "
                "web_search, e.g. a CVE advisory or MASTG docs page, then "
                "cite the final URL in your answer. Size- and timeout-"
                "bounded; refuses private-network hosts."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "http(s) URL to fetch"},
                },
                "required": ["url"],
            },
        },
    },
]

_HANDLERS = {
    "search_code": lambda scan_id, a: search_code(scan_id, a["pattern"], a.get("glob", "**/*")),
    "read_file": lambda scan_id, a: read_file(
        scan_id, a["path"], a.get("line_start"), a.get("line_end")
    ),
    "read_manifest": lambda scan_id, a: read_manifest(scan_id),
    "get_decompiled_class": lambda scan_id, a: get_decompiled_class(scan_id, a["fqcn"]),
    "get_permissions": lambda scan_id, a: get_permissions(scan_id),
    "run_secrets_scan": lambda scan_id, a: run_secrets_scan(scan_id, a.get("path", "")),
    "search_strings": lambda scan_id, a: search_strings(scan_id, a["pattern"]),
    "graph_query": lambda scan_id, a: graph_query(scan_id, a["question"], a.get("budget", 1500)),
    "graph_path": lambda scan_id, a: graph_path_between(scan_id, a["node_a"], a["node_b"]),
    "graph_explain": lambda scan_id, a: graph_explain_node(scan_id, a["node"]),
    # M7: gated web tools — the handlers re-check both gates defensively, so
    # even a raw API caller can never trigger web egress on a non-opted-in scan.
    "web_search": lambda scan_id, a: web_search(scan_id, a["query"]),
    "web_fetch": lambda scan_id, a: web_fetch(scan_id, a["url"]),
}


def schemas_for_platform(
    platform: str | None,
    *,
    web_research_enabled: bool = False,
) -> list[dict]:
    """Tool schemas offered to a model for a scan's platform + web gating.

    iOS never *sees* Android-only tools (``get_decompiled_class``), so the
    model can't waste a round on a guaranteed-failing call — the same
    whitelist pattern as the Layer 1 findings-context tools
    (``context.py::platform_tools``). Android gets the full platform set.

    M7: the web tools (``web_search``/``web_fetch``) are appended only when
    BOTH gates hold — the per-scan opt-in passed here AND an Active search
    engine (checked by the caller via ``web_tools_allowed``). Off = the
    model never even sees the schemas, so it cannot burn a round on a
    call the scan did not permit.
    """
    return [
        s
        for s in TOOL_SCHEMAS
        if not (s["function"]["name"] in _ANDROID_ONLY_TOOLS and platform != "android")
        and not (s["function"]["name"] in _WEB_TOOLS and not web_research_enabled)
    ]


def execute_tool(scan_id: int, name: str, args: dict) -> str:
    """Run one tool call and return its result as a JSON string.

    Tool errors are returned as ``{"error": ...}`` so a bad call never
    crashes the agent loop.
    """
    handler = _HANDLERS.get(name)
    if handler is None:
        return json.dumps({"error": f"unknown tool {name!r}"})
    try:
        return json.dumps(handler(scan_id, args), default=str)
    except ToolError as exc:
        return json.dumps({"error": str(exc)})
    except Exception as exc:  # noqa: BLE001 - LLM input is untrusted; a bad
        # tool call must degrade to an error result, never crash the loop.
        return json.dumps({"error": f"{name} failed: {exc}"})
