"""M5 decompiler tab: file tree + guarded content reads.

Serves the Decompiler tab from real scan output - no mockups. Two roots for
Android (jadx ``sources/`` Java/Kotlin + ``resources/`` incl.
AndroidManifest.xml), one root for iOS (the unpacked ``Payload/*.app``
bundle - no source, but plist/entitlements/strings are readable).

The walk is **unbounded by default** (owner decision, Aug 10: the per-root
1500-node cap was removed - it truncated real trees mid-branch, hiding app
code behind library subtrees). ``max_nodes`` remains as an explicit opt-in
cap for callers that want one; ``max_depth`` stays as a safety guard against
pathological/cyclic trees (symlinked dirs could otherwise recurse forever).
When either explicit cap bites, ``truncated`` tells the UI the tree is
incomplete. Content reads reuse the same guards as the Layer 2 ``read_file``
tool: path-traversal protection, binary sniff, plist decode to text.
"""
from __future__ import annotations

import json
import plistlib
from collections.abc import Callable
from pathlib import Path

from pydantic import TypeAdapter
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from app.agent.tools import ToolError, is_text_file, resolve_tree_root
from app.analysis import apktool, editable
from app.models import Scan
from app.schemas import FileContentResponse, FileNode, FileTreeRoot

# Depth guard only (kept as a safety valve against pathological/symlink-
# cyclic trees - the node cap was removed Aug 10 per owner decision, so real
# trees always serve in full). 16 comfortably exceeds any realistic APK
# decompile tree (sources/com/... is ~5 levels).
MAX_DEPTH = 16
MAX_CONTENT_CHARS = 200_000
_BINARY_SNIFF_BYTES = 8192

# ---- Tree cache --------------------------------------------------------------
# The tree payload is immutable per scan (jadx trees land at scan time; the
# apktool roots land once at the on-demand decode; edits are DB diffs and
# rebuilds copy to a pristine dir - nothing mutates the listing afterwards),
# so it is computed once and cached per scan - the same pattern as the
# smali_mapping.json / graph explorer.json caches. Identity = the root-name
# set (changes when the decode lands) + the decoded manifest's mtime (the
# decode instance); a validated ``tree_cache.json`` survives restarts.
# Best-effort throughout: any failure recomputes, never a wrong tree.
_TREE_CACHE: dict[str, tuple[str, list[FileTreeRoot]]] = {}
# Bounded small on purpose: each payload is a FULL tree (multi-MB on big
# scans) - 8 mirrors the graph explorer cache's "4 most-recent" posture
# while tolerating a few active scans.
_TREE_CACHE_MAX = 8
# Bump when the stored payload shape changes so stale persisted files rebuild.
_TREE_CACHE_VERSION = 1
_TREE_ROOTS_ADAPTER: TypeAdapter[list[FileTreeRoot]] = TypeAdapter(list[FileTreeRoot])

# Directory names never shown in the tree. graphify-out is where the graph
# CLI writes while a build is in flight (it is relocated to data/graphs/ by
# graphify.build, but the decompiler tab must not render it mid-build).
_IGNORED_DIRS = {"graphify-out"}

# iOS synthetic root: generated documents from the persisted binary-level
# analysis (Mach-O profile, entitlements, symbols, import-table findings).
_ANALYSIS_ROOT = "analysis"

# Path suffix -> highlight.js language name (hljs lacks a smali grammar).
_LANGUAGES = {
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".xml": "xml",
    ".plist": "xml",
    ".json": "json",
    ".gradle": "groovy",
    ".properties": "properties",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".html": "xml",
    ".js": "javascript",
    ".ts": "typescript",
    ".css": "css",
    ".md": "markdown",
    ".swift": "swift",
    ".m": "objc",
    ".h": "objc",
    ".py": "python",
    ".c": "c",
    ".cpp": "cpp",
    ".toml": "ini",
    ".ini": "ini",
}


class TreeError(ValueError):
    """Bad tree path (unknown root, escapes, binary file) - API maps to 400."""


def roots_for(scan: Scan) -> list[tuple[str, Path]]:
    """``(root_name, absolute_path)`` pairs for a scan's platform.

    Android: ``sources`` (jadx Java/Kotlin) + ``resources`` when present,
    plus the M8 apktool roots **once the on-demand decode is ready**:
    ``smali``, ``smali_classesN`` (multidex), ``res``, and the synthetic
    ``AndroidManifest.xml`` root (whose path IS the decoded manifest file).
    iOS: the ``Payload/*.app`` bundle, named after the app dir. Empty list
    when the scan has no platform or no extracted tree yet.
    """
    try:
        main_root = resolve_tree_root(scan)
    except ToolError:
        return []
    if scan.platform == "android":
        roots = [("sources", main_root)]
        resources = main_root.parent / "resources"
        if resources.is_dir():
            roots.append(("resources", resources))
        if apktool.is_ready(scan.id):
            roots.extend(apktool.smali_roots(scan.id))
            apk_root = apktool.decoded_root(scan.id)
            res_dir = apk_root / "res"
            if res_dir.is_dir():
                roots.append(("res", res_dir))
            if (apk_root / editable.MANIFEST_ROOT).is_file():
                roots.append((editable.MANIFEST_ROOT, apk_root))
        return roots
    if scan.platform == "ios":
        return [(main_root.name, main_root)]
    return []


def list_tree(
    scan: Scan,
    *,
    max_depth: int = MAX_DEPTH,
    max_nodes: int | None = None,
) -> list[FileTreeRoot]:
    """Nested tree per root; unbounded by default (``max_nodes=None``).

    ``truncated`` is set only when an *explicit* cap is hit (a caller-passed
    ``max_nodes`` or the ``max_depth`` safety guard) - the default serves the
    full tree. iOS: the synthetic ``analysis`` root comes first, and the
    app-bundle walk is curated to text-readable files (raw binaries - the
    executable, images, .car, .nib - are hidden; the count lands in
    ``filtered_binaries`` so the UI can say how many were skipped).
    """
    roots: list[FileTreeRoot] = []
    if scan.platform == "ios":
        analysis = _analysis_root(scan)
        if analysis is not None:
            roots.append(analysis)
    for name, root_path in roots_for(scan):
        # M8: the decoded AndroidManifest.xml is a synthetic single-file root
        # (its path IS the manifest file) - never walk the whole apktool dir.
        if name == editable.MANIFEST_ROOT:
            roots.append(
                FileTreeRoot(
                    name=name,
                    total_nodes=1,
                    truncated=False,
                    filtered_binaries=0,
                    tree=[
                        FileNode(
                            name=editable.MANIFEST_ROOT,
                            path=editable.MANIFEST_ROOT,
                            type="file",
                        )
                    ],
                )
            )
            continue
        counter = {"nodes": 0, "truncated": False, "filtered": 0, "filtered_paths": []}
        # iOS only: hide binary blobs that the viewer cannot render - they
        # surface as a collapsed "Binary (Mach-O)" entry instead of raw rows.
        keep_file = is_text_file if scan.platform == "ios" else None
        tree = _walk(
            root_path,
            root_path,
            depth=0,
            max_depth=max_depth,
            max_nodes=max_nodes,
            counter=counter,
            keep_file=keep_file,
        )
        if scan.platform == "ios" and counter["filtered_paths"]:
            tree = [*tree, _binary_folder_node(counter["filtered_paths"])]
            # Keep total_nodes truthful: the synthetic folder + its children
            # are part of the served tree.
            counter["nodes"] += 1 + len(counter["filtered_paths"])
        roots.append(
            FileTreeRoot(
                name=name,
                total_nodes=counter["nodes"],
                truncated=counter["truncated"],
                filtered_binaries=counter["filtered"],
                tree=tree,
            )
        )
    return roots


def tree_cache_path(scan_id: int) -> Path:
    """Per-scan cache file next to the scan's trees (``work/<scan>/``) - a
    SIBLING of ``decompiled/`` and ``apktool/`` so the rebuild's pristine-tree
    copy never includes it."""
    return apktool.decoded_root(scan_id).parent / "tree_cache.json"


def _tree_identity(scan: Scan) -> str | None:
    """Cheap tree identity: the root names (which change the moment the
    on-demand apktool decode lands - smali/res/manifest appear) plus the
    decoded manifest's mtime (re-decode instance). The jadx trees are
    immutable per scan, so nothing else can change the listing. None when the
    scan has no roots yet (nothing to cache)."""
    roots = roots_for(scan)
    if not roots:
        return None
    # Note: the iOS synthetic ``analysis`` root is derived from DB findings
    # INSIDE list_tree (not part of roots_for), so it isn't literally covered
    # by this identity - it stays correct because findings are immutable per
    # scan (the docs derive from lief/symbols rows that land before ``done``).
    parts = [name for name, _ in roots]
    if scan.platform == "android" and apktool.is_ready(scan.id):
        try:
            parts.append(
                str(
                    (apktool.decoded_root(scan.id) / editable.MANIFEST_ROOT)
                    .stat()
                    .st_mtime
                )
            )
        except OSError:
            return None
    return "|".join(parts)


def _remember_tree(key: str, identity: str, roots: list[FileTreeRoot]) -> None:
    _TREE_CACHE[key] = (identity, roots)
    while len(_TREE_CACHE) > _TREE_CACHE_MAX:
        _TREE_CACHE.pop(next(iter(_TREE_CACHE)))


def _store_tree(key: str, identity: str, roots: list[FileTreeRoot]) -> None:
    """Persist a computed tree - in-memory + the on-disk cache file.

    Best-effort: a failed write (read-only FS etc.) still serves this process
    via the module cache; the next process recomputes. Atomic (tmp+rename) so
    a torn write never becomes the cache."""
    _remember_tree(key, identity, roots)
    try:
        tmp = Path(key).with_suffix(".tmp")
        tmp.write_text(
            json.dumps(
                {
                    "version": _TREE_CACHE_VERSION,
                    "identity": identity,
                    "roots": [r.model_dump() for r in roots],
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        tmp.replace(Path(key))
    except OSError:
        pass  # best-effort cache


def cached_list_tree(scan: Scan) -> list[FileTreeRoot]:
    """The scan's tree, served from cache when valid - the filesystem walk +
    serialize runs ONCE per scan; later Decompiler opens (same process, or
    across restarts via the validated ``tree_cache.json``) read the cached
    payload. Identity-validated: a stale/torn file (pre-decode capture, shape
    change, partial write) recomputes instead of serving garbage."""
    identity = _tree_identity(scan)
    if identity is None:
        return list_tree(scan)
    key = str(tree_cache_path(scan.id))
    cached = _TREE_CACHE.get(key)
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
            and data.get("version") == _TREE_CACHE_VERSION
            and data.get("identity") == identity
        ):
            try:
                roots = _TREE_ROOTS_ADAPTER.validate_python(data.get("roots"))
            except (ValueError, TypeError, KeyError):
                roots = None
            if roots is not None:
                _remember_tree(key, identity, roots)
                return roots
    roots = list_tree(scan)
    _store_tree(key, identity, roots)
    return roots


def _walk(
    root: Path,
    path: Path,
    *,
    depth: int,
    max_depth: int,
    max_nodes: int | None,
    counter: dict,
    keep_file: Callable[[Path], bool] | None = None,
) -> list[FileNode]:
    """Recursive walk. Unbounded by default; ``max_nodes`` (explicit opt-in
    cap) and ``max_depth`` (safety guard) set ``truncated`` when hit.
    ``keep_file`` (iOS curation) drops binary files from the tree, counting
    them in ``counter["filtered"]`` and pruning directories that end up
    empty."""
    if max_nodes is not None and counter["nodes"] >= max_nodes:
        counter["truncated"] = True
        return []
    if depth >= max_depth:
        counter["truncated"] = True
        return []
    nodes: list[FileNode] = []
    try:
        entries = sorted(
            path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())
        )
    except OSError:
        return nodes
    for entry in entries:
        if max_nodes is not None and counter["nodes"] >= max_nodes:
            counter["truncated"] = True
            break
        if entry.is_dir() and entry.name in _IGNORED_DIRS:
            continue
        rel = entry.relative_to(root).as_posix()
        if entry.is_dir():
            children = _walk(
                root,
                entry,
                depth=depth + 1,
                max_depth=max_depth,
                max_nodes=max_nodes,
                counter=counter,
                keep_file=keep_file,
            )
            if keep_file is not None and not children:
                continue  # curation: drop directories left with nothing readable
            counter["nodes"] += 1
            nodes.append(
                FileNode(
                    name=entry.name,
                    path=rel,
                    type="dir",
                    children=children,
                )
            )
        elif entry.is_file():
            if keep_file is not None and not keep_file(entry):
                counter["filtered"] += 1
                counter["filtered_paths"].append(rel)
                continue
            counter["nodes"] += 1
            nodes.append(FileNode(name=entry.name, path=rel, type="file"))
    return nodes


def _binary_folder_node(paths: list[str]) -> FileNode:
    """Collapsed "Binary (Mach-O)" entry listing hidden binary blobs.

    Children carry their full root-relative path as the display name (so it
    is clear where each blob lived) and the ``binary`` flag so the UI can
    render them as inert, non-viewable rows. The synthetic dir path never
    collides with a real file.
    """
    return FileNode(
        name=f"Binary (Mach-O) ({len(paths)})",
        path="__binary__",
        type="dir",
        children=[
            FileNode(name=p, path=p, type="file", binary=True)
            for p in sorted(paths)
        ],
    )


def read_tree_file(
    scan: Scan, path: str, *, effective: bool = True
) -> FileContentResponse:
    """Read a file as ``<root_name>/<relative path>`` with traversal guard.

    Binary files are refused; plists are decoded to JSON text (same rule as
    the Layer 2 tool). Content is capped at ``MAX_CONTENT_CHARS`` with a
    ``truncated`` flag so very large files stay cheap for the viewer. The
    synthetic ``analysis`` root (iOS) generates its documents on read.

    M8 Phase B: ``effective=True`` (default) overlays the newest **applied**
    edit's ``new_content`` for editable paths - the viewer shows the edited
    content, and the edit service calls ``effective=False`` for the pristine
    baseline. The on-disk apktool tree itself is never mutated.
    """
    root_name, sep, rel = path.partition("/")
    if not sep or not root_name or not rel:
        raise TreeError("path must be '<root>/<relative path>'")
    if root_name == _ANALYSIS_ROOT and scan.platform == "ios":
        for doc in _analysis_docs(scan):
            if doc.path == rel:
                return doc
        raise FileNotFoundError(f"no such analysis file: {path}")
    roots = dict(roots_for(scan))
    root = roots.get(root_name)
    if root is None:
        raise TreeError(f"unknown tree root {root_name!r}")
    target = (root / rel).resolve()
    if not target.is_relative_to(root.resolve()):
        raise TreeError("path escapes the scan tree")
    if not target.is_file():
        raise FileNotFoundError(f"no such file in the scan tree: {path}")

    data = target.read_bytes()

    if target.suffix.lower() == ".plist":
        try:
            plist = plistlib.loads(data)
        except plistlib.InvalidFileException:
            pass  # not a (parseable) plist - fall through to text read
        else:
            import json

            text = json.dumps(plist, indent=2, default=str)
            truncated = len(text) > MAX_CONTENT_CHARS
            return FileContentResponse(
                path=path,
                content=(text[:MAX_CONTENT_CHARS] + "…") if truncated else text,
                language="json",
                truncated=truncated,
                size=len(data),
            )

    if not is_text_file(target):
        raise TreeError(
            f"{path} is a binary file - no text content (use the findings / "
            "import-table scanner for binary-level evidence)"
        )
    text = data.decode("utf-8", errors="replace")
    if effective and scan.platform == "android":
        edit_path = editable.edit_path_from_tree_path(root_name, rel)
        if editable.can_edit(scan, edit_path):
            overlaid = _applied_edit_content(scan, edit_path)
            if overlaid is not None:
                text = overlaid
    truncated = len(text) > MAX_CONTENT_CHARS
    return FileContentResponse(
        path=path,
        content=(text[:MAX_CONTENT_CHARS] + "…") if truncated else text,
        language=_LANGUAGES.get(target.suffix.lower(), "plaintext"),
        truncated=truncated,
        size=len(data),
    )


def _applied_edit_content(scan: Scan, edit_path: str) -> str | None:
    """Newest applied edit's ``new_content`` for a path, or None (baseline).

    tree.py holds no DB session of its own; opens one defensively - a
    stale/mismatched DB degrades to the baseline rather than 500 the viewer
    (same posture as ``_scan_findings``)."""
    from app.db import SessionLocal
    from app.models import Edit

    db = None
    try:
        db = SessionLocal()
        edit = db.scalars(
            select(Edit)
            .where(
                Edit.scan_id == scan.id,
                Edit.file_path == edit_path,
                Edit.status == "applied",
            )
            .order_by(Edit.id.desc())
            .limit(1)
        ).first()
        return edit.new_content if edit is not None else None
    except SQLAlchemyError:
        return None
    finally:
        if db is not None:
            db.close()


# ---- iOS synthetic 'analysis' root ------------------------------------------


def _scan_findings(scan: Scan) -> list:
    """All findings for a scan (tree.py holds no DB session of its own).

    Defensive: a stale/mismatched DB must degrade to 'no analysis docs'
    rather than 500 the files endpoint (e.g. a pre-0004 database without
    the explanation column).
    """
    from app.db import SessionLocal
    from app.models import Finding

    db = None
    try:
        db = SessionLocal()
        return list(
            db.scalars(
                select(Finding)
                .where(Finding.scan_id == scan.id)
                .order_by(Finding.id)
            ).all()
        )
    except SQLAlchemyError:
        # Stale/mismatched DB schema must degrade to 'no analysis docs'
        # rather than 500 the files endpoint (e.g. a pre-0004 database
        # without the explanation column). Real programming errors still
        # propagate.
        return []
    finally:
        if db is not None:
            db.close()


def _detail_dict(finding) -> dict:
    """``finding.detail`` as a dict (the column stores tool payloads as JSON)."""
    detail = getattr(finding, "detail", None)
    if isinstance(detail, str) and detail:
        try:
            parsed = json.loads(detail)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return detail if isinstance(detail, dict) else {}


def _generated_doc(path: str, content: str, language: str) -> FileContentResponse:
    """FileContentResponse for a synthetic analysis document."""
    return FileContentResponse(
        path=path,
        content=content,
        language=language,
        truncated=False,
        size=len(content.encode("utf-8")),
    )


def _analysis_docs(scan: Scan) -> list[FileContentResponse]:
    """Generated documents for the iOS ``analysis`` root, built from the
    persisted LIEF profile + import-table findings - the same binary-level
    evidence the agent context sees, rendered as readable files so the
    Decompiler tab has meaningful content where Android has source.
    Returns [] when the scan produced no binary-level findings at all.
    """
    findings = _scan_findings(scan)
    lief = [f for f in findings if getattr(f, "tool", None) == "lief"]
    symbols = [f for f in findings if getattr(f, "tool", None) == "symbols"]
    if not lief and not symbols:
        return []

    def find(pred: Callable[[str], bool]):
        return next((f for f in lief if pred(f.title)), None)

    docs: list[FileContentResponse] = []

    # --- macho-profile.md ----------------------------------------------------
    lines = [
        "# Mach-O profile",
        "",
        "Binary-level analysis of the app's main executable (LIEF). No source",
        "location exists for these artifacts - they describe the binary itself.",
        "",
    ]
    slices = find(lambda t: t.startswith("Binary slices"))
    if slices:
        archs = _detail_dict(slices).get("architectures") or []
        lines += ["## Architectures"] + [f"- {a}" for a in archs] + [""]
    pie = find(lambda t: t == "Position-independent executable (PIE) disabled")
    canary = find(lambda t: t.startswith("Stack canary missing"))
    arc = find(lambda t: t.startswith("ARC enabled"))
    fairplay = find(lambda t: t.startswith("FairPlay-encrypted"))
    protections = pie or canary or arc or fairplay
    if protections:
        # Honest wording: an absent finding is 'not flagged', not 'present'
        # (the Mach-O stage may not have produced profile findings at all).
        lines += [
            "## Protections",
            f"- PIE: {'disabled (finding present)' if pie else 'not flagged'}",
            f"- Stack canary: {'missing (finding present)' if canary else 'not flagged'}",
            f"- ARC: {'enabled (finding present)' if arc else 'not detected'}",
            "- FairPlay encryption: "
            + ("yes - static coverage limited" if fairplay else "not flagged"),
            "",
        ]
    dylibs = find(lambda t: t.startswith("Linked dylibs"))
    if dylibs:
        libs = _detail_dict(dylibs).get("dylibs") or []
        lines += [f"## Linked dylibs ({len(libs)})"] + [f"- {lib}" for lib in libs] + [""]
    docs.append(_generated_doc("macho-profile.md", "\n".join(lines).rstrip() + "\n", "markdown"))

    # --- entitlements.plist (JSON text, same rendering as plist decode) ------
    ents = find(lambda t: t.startswith("Entitlements granted"))
    if ents:
        payload = _detail_dict(ents).get("entitlements") or {}
        content = json.dumps(payload, indent=2, default=str) + "\n"
    else:
        not_extractable = find(lambda t: t.startswith("Entitlements not extractable"))
        note = (
            _detail_dict(not_extractable).get("note")
            if not_extractable is not None
            else None
        )
        content = (
            json.dumps({"note": note or "No entitlements recorded for this binary."}, indent=2)
            + "\n"
        )
    docs.append(_generated_doc("entitlements.plist", content, "json"))

    # --- exported-symbols.txt --------------------------------------------------
    exp = find(lambda t: t.startswith("Exported symbols"))
    if exp:
        detail = _detail_dict(exp)
        count = detail.get("count") or 0
        sample = detail.get("sample") or []
        lines = [f"# Exported symbols ({count}) - first {len(sample)} shown"] + [
            f"_{s}" for s in sample
        ]
        docs.append(
            _generated_doc("exported-symbols.txt", "\n".join(lines) + "\n", "plaintext")
        )

    # --- insecure-imports.txt (import-table scanner findings) ------------------
    if symbols:
        lines = [
            "# Import-table findings (known-insecure APIs) - binary-level presence",
            "# These prove the app links/calls the API somewhere in the binary;",
            "# there is no source location for them.",
            "",
        ]
        for f in symbols:
            detail = _detail_dict(f)
            symbol = detail.get("symbol") or ""
            note = detail.get("note")
            lines += [
                f"## [{f.severity}] {f.title}",
                f"symbol: {symbol}",
            ]
            if note:
                lines.append(f"note: {note}")
            lines.append("")
        docs.append(
            _generated_doc("insecure-imports.txt", "\n".join(lines).rstrip() + "\n", "plaintext")
        )

    return docs


def _analysis_root(scan: Scan) -> FileTreeRoot | None:
    """Synthetic ``analysis`` root for iOS scans, or None when the scan has
    no binary-level findings to show."""
    if scan.platform != "ios":
        return None
    docs = _analysis_docs(scan)
    if not docs:
        return None
    nodes = [FileNode(name=d.path, path=d.path, type="file") for d in docs]
    return FileTreeRoot(
        name=_ANALYSIS_ROOT,
        total_nodes=len(nodes),
        truncated=False,
        filtered_binaries=0,
        tree=nodes,
    )
