"""M5 decompiler tab: bounded file tree + guarded content reads.

Serves the Decompiler tab from real scan output — no mockups. Two roots for
Android (jadx ``sources/`` Java/Kotlin + ``resources/`` incl.
AndroidManifest.xml), one root for iOS (the unpacked ``Payload/*.app``
bundle — no source, but plist/entitlements/strings are readable).

The walk is bounded (max depth + max nodes per root) so a large jadx tree
(thousands of files) stays cheap for the dashboard; ``truncated`` tells the
UI the tree is incomplete. Content reads reuse the same guards as the
Layer 2 ``read_file`` tool: path-traversal protection, binary sniff, plist
decode to text.
"""
from __future__ import annotations

import json
import plistlib
from collections.abc import Callable
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from app.agent.tools import ToolError, is_text_file, resolve_tree_root
from app.models import Scan
from app.schemas import FileContentResponse, FileNode, FileTreeRoot

MAX_DEPTH = 8
MAX_NODES_PER_ROOT = 1500
MAX_CONTENT_CHARS = 200_000
_BINARY_SNIFF_BYTES = 8192

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
    """Bad tree path (unknown root, escapes, binary file) — API maps to 400."""


def roots_for(scan: Scan) -> list[tuple[str, Path]]:
    """``(root_name, absolute_path)`` pairs for a scan's platform.

    Android: ``sources`` (jadx Java/Kotlin) + ``resources`` when present.
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
        return roots
    if scan.platform == "ios":
        return [(main_root.name, main_root)]
    return []


def list_tree(
    scan: Scan,
    *,
    max_depth: int = MAX_DEPTH,
    max_nodes: int = MAX_NODES_PER_ROOT,
) -> list[FileTreeRoot]:
    """Bounded nested tree per root; ``truncated`` set when either cap hit.

    iOS: the synthetic ``analysis`` root comes first, and the app-bundle
    walk is curated to text-readable files (raw binaries — the executable,
    images, .car, .nib — are hidden; the count lands in
    ``filtered_binaries`` so the UI can say how many were skipped).
    """
    roots: list[FileTreeRoot] = []
    if scan.platform == "ios":
        analysis = _analysis_root(scan)
        if analysis is not None:
            roots.append(analysis)
    for name, root_path in roots_for(scan):
        counter = {"nodes": 0, "truncated": False, "filtered": 0, "filtered_paths": []}
        # iOS only: hide binary blobs that the viewer cannot render — they
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


def _walk(
    root: Path,
    path: Path,
    *,
    depth: int,
    max_depth: int,
    max_nodes: int,
    counter: dict,
    keep_file: Callable[[Path], bool] | None = None,
) -> list[FileNode]:
    """Bounded recursive walk. ``keep_file`` (iOS curation) drops binary
    files from the tree, counting them in ``counter["filtered"]`` and
    pruning directories that end up empty."""
    if counter["nodes"] >= max_nodes:
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
        if counter["nodes"] >= max_nodes:
            counter["truncated"] = True
            break
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


def read_tree_file(scan: Scan, path: str) -> FileContentResponse:
    """Read a file as ``<root_name>/<relative path>`` with traversal guard.

    Binary files are refused; plists are decoded to JSON text (same rule as
    the Layer 2 tool). Content is capped at ``MAX_CONTENT_CHARS`` with a
    ``truncated`` flag so very large files stay cheap for the viewer. The
    synthetic ``analysis`` root (iOS) generates its documents on read.
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
            pass  # not a (parseable) plist — fall through to text read
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
            f"{path} is a binary file — no text content (use the findings / "
            "import-table scanner for binary-level evidence)"
        )
    text = data.decode("utf-8", errors="replace")
    truncated = len(text) > MAX_CONTENT_CHARS
    return FileContentResponse(
        path=path,
        content=(text[:MAX_CONTENT_CHARS] + "…") if truncated else text,
        language=_LANGUAGES.get(target.suffix.lower(), "plaintext"),
        truncated=truncated,
        size=len(data),
    )


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
    persisted LIEF profile + import-table findings — the same binary-level
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
        "location exists for these artifacts — they describe the binary itself.",
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
            + ("yes — static coverage limited" if fairplay else "not flagged"),
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
        lines = [f"# Exported symbols ({count}) — first {len(sample)} shown"] + [
            f"_{s}" for s in sample
        ]
        docs.append(
            _generated_doc("exported-symbols.txt", "\n".join(lines) + "\n", "plaintext")
        )

    # --- insecure-imports.txt (import-table scanner findings) ------------------
    if symbols:
        lines = [
            "# Import-table findings (known-insecure APIs) — binary-level presence",
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
