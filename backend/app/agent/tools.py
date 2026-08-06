"""Layers 2 + 3 agent tools — plain-text operations + Graphify, zero embeddings.

Layer 2 — ``search_code`` / ``read_file``: plain-text operations over
whatever decompiled/extracted output exists for the scan's platform. The tools
themselves contain no platform branching — the ONLY platform knowledge lives
in ``resolve_tree_root`` (which tree to search/read).

Layer 3 — ``graph_query`` / ``graph_path`` / ``graph_explain``: Graphify
traversal for Android call-graph/structural questions. Android only: iOS has
no decompiled source tree, so no graph exists and the tools fail with a clear
reason. No Semgrep-based substitute is built for iOS graphing.
"""
from __future__ import annotations

import json
import plistlib
import re
from pathlib import Path

from app.config import settings
from app.models import Scan

_BINARY_SNIFF_BYTES = 8192
_MAX_SEARCH_FILE_BYTES = 5 * 1024 * 1024
_MAX_SEARCH_HITS = 100
_MAX_READ_CHARS = 50_000

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
]

_HANDLERS = {
    "search_code": lambda scan_id, a: search_code(scan_id, a["pattern"], a.get("glob", "**/*")),
    "read_file": lambda scan_id, a: read_file(
        scan_id, a["path"], a.get("line_start"), a.get("line_end")
    ),
    "graph_query": lambda scan_id, a: graph_query(scan_id, a["question"], a.get("budget", 1500)),
    "graph_path": lambda scan_id, a: graph_path_between(scan_id, a["node_a"], a["node_b"]),
    "graph_explain": lambda scan_id, a: graph_explain_node(scan_id, a["node"]),
}


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
