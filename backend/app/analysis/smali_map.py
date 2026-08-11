"""Java⇄Smali mapping (M8 Phase B) - the Decompiler tab's view toggle.

Maps a tree path for a class between its jadx ``sources/.../*.java``
representation and its apktool ``smali{,classesN}/.../*.smali`` sibling,
**multidex-aware** (``smali`` first, then ``smali_classes2..N`` - first-found
wins, matching apktool's classes.dex -> smali layout). jadx's own fallback
``.smali`` files inside ``sources/`` are never matched here - they stay
read-only (only apktool smali is editable, and the UI must not confuse the
two).

Also owns the **finding→smali mapping cache** (the Decompiler's Smali-mode
dots/rail): ``compute_mapping`` builds a scan's finding→apktool-tree-path
map and ``cached_mapping``/``store_mapping`` persist it per scan, mirroring
the graph explorer.json pattern (module cache keyed by path + tree mtime,
bounded; a validated ``smali_mapping.json`` survives restarts).

**M8 follow-up (Aug 11): smali-mode line anchors.** jadx renumbers source
lines (a finding's ``line_number`` refers to the *jadx* output, and smali
``.line`` directives carry the *original* source lines - the two don't
match), so statement-level mapping is impossible. Instead the smali rail
notes are pinned at **method granularity**: ``compute_anchors`` finds the
jadx method containing each finding's line and maps it to that method's
``.method`` line in the smali file (by name; constructors map to
``<init>``). The anchors ride the same cache as the mapping (immutable per
scan - findings and the decoded tree never mutate).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from app.agent.tools import ToolError, resolve_tree_root
from app.analysis import apktool, editable

# Tree-path root prefixes.
_SOURCES_ROOT = "sources"


# ---- Finding→smali mapping cache --------------------------------------------
# The mapping endpoint re-walks the filesystem per finding path on every
# Decompiler open; the mapping is immutable per scan (findings are immutable
# per scan id - re-runs create new scans - suppression never changes finding
# paths, and the decoded apktool tree never mutates: edits are DB diffs), so
# it is cached once per scan. Keyed on the cache path + tree mtime (distinct
# scans and test tmp dirs never collide); the persistent file is validated by
# a stored tree mtime + shape version. Best-effort throughout: any failure
# degrades to a recompute, never a wrong answer.
_MAPPING_CACHE: dict[str, tuple[float, dict[str, str], dict[str, dict[str, int]]]] = {}
_MAPPING_CACHE_MAX = 32
# Bump when the stored row shape changes so stale persisted files rebuild.
# 2 = the Aug 11 anchors addition (mapping + anchors in one row).
_MAPPING_CACHE_VERSION = 2


def mapping_cache_path(scan_id: int) -> Path:
    """Per-scan cache file next to the decoded tree (``work/<scan>/``)."""
    return apktool.decoded_root(scan_id).parent / "smali_mapping.json"


def _tree_mtime(scan_id: int) -> float | None:
    """Decoded-tree identity: the manifest file's mtime. The tree never
    mutates after the once-per-scan decode, so this fully describes the
    mapping inputs. None when the tree vanished."""
    try:
        return (apktool.decoded_root(scan_id) / editable.MANIFEST_ROOT).stat().st_mtime
    except OSError:
        return None


def _remember(
    key: str,
    tree_mtime: float,
    mapping: dict[str, str],
    anchors: dict[str, dict[str, int]],
) -> None:
    _MAPPING_CACHE[key] = (tree_mtime, mapping, anchors)
    # Evict the oldest-inserted entry when over the bound (dicts preserve
    # insertion order, so the first key is the oldest) - same rule as the
    # graph explorer cache.
    while len(_MAPPING_CACHE) > _MAPPING_CACHE_MAX:
        _MAPPING_CACHE.pop(next(iter(_MAPPING_CACHE)))


def cached_mapping(scan_id: int) -> tuple[dict[str, str], dict[str, dict[str, int]]] | None:
    """The scan's cached (finding→smali mapping, line anchors), or None on a
    miss.

    The caller gates on ``apktool.is_ready`` first; a vanished tree (mtime
    stat fails) reads as a miss. Persisted cache files are validated by
    their stored tree mtime + version - a stale/torn file (older decode,
    shape change, partial write) recomputes instead of serving garbage.
    """
    key = str(mapping_cache_path(scan_id))
    tree_mtime = _tree_mtime(scan_id)
    if tree_mtime is None:
        return None
    cached = _MAPPING_CACHE.get(key)
    if cached is not None and cached[0] == tree_mtime:
        return cached[1], cached[2]
    cache_path = Path(key)
    if cache_path.is_file():
        try:
            data = json.loads(cache_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = None
        if (
            data is not None
            and data.get("version") == _MAPPING_CACHE_VERSION
            and data.get("tree_mtime") == tree_mtime
            and isinstance(data.get("mapping"), dict)
        ):
            mapping = {str(k): str(v) for k, v in data["mapping"].items()}
            anchors = {
                str(k): {str(kk): int(vv) for kk, vv in v.items()}
                for k, v in (data.get("anchors") or {}).items()
            }
            _remember(key, tree_mtime, mapping, anchors)
            return mapping, anchors
    return None


def compute_mapping(scan, paths: list[str]) -> dict[str, str]:
    """Finding→apktool tree-path mapping for one scan (no caching).

    ``paths`` are the scan's distinct finding file_paths (root-relative).
    ``.java``/``.kt`` rebuild the ``sources/`` prefix and map via
    ``java_to_smali`` (multidex first-found); ``res/...`` maps to ITSELF (the
    apktool res root serves the same relative path); the manifest maps to its
    synthetic root's single file (``AndroidManifest.xml/AndroidManifest.xml``).
    Everything else never maps.

    The res/manifest identity entries do NOT touch the filesystem - they
    assume the decoded tree exists (callers gate on ``apktool.is_ready``
    before calling this / the route returns early for undecoded scans).
    """
    mapping: dict[str, str] = {}
    for path in paths:
        if path.endswith((".java", ".kt")):
            tree_path = f"{_SOURCES_ROOT}/{path}"
            sibling = java_to_smali(scan, tree_path)
            if sibling:
                mapping[tree_path] = sibling
        elif path == editable.MANIFEST_ROOT:
            mapping[path] = editable.tree_path_from_edit_path(path)
        elif path.startswith("res/"):
            mapping[path] = path
    return mapping


def store_mapping(
    scan_id: int,
    mapping: dict[str, str],
    anchors: dict[str, dict[str, int]] | None = None,
) -> None:
    """Persist a computed mapping + anchors - in-memory + the on-disk cache
    file.

    Best-effort: a failed write (read-only FS etc.) still serves this process
    via the module cache; the next process recomputes. Atomic (tmp+rename) so
    a torn write never becomes the cache.
    """
    key = str(mapping_cache_path(scan_id))
    tree_mtime = _tree_mtime(scan_id)
    if tree_mtime is None:
        return
    anchors = anchors or {}
    _remember(key, tree_mtime, mapping, anchors)
    cache_path = Path(key)
    try:
        tmp = cache_path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(
                {
                    "version": _MAPPING_CACHE_VERSION,
                    "tree_mtime": tree_mtime,
                    "mapping": mapping,
                    "anchors": anchors,
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        tmp.replace(cache_path)
    except OSError:
        pass  # best-effort cache


def java_to_smali(scan, tree_path: str) -> str | None:
    """``sources/com/foo/AuthManager.java`` -> first-found smali sibling tree
    path (``smali/com/foo/AuthManager.smali`` or a ``smali_classesN/`` one),
    or None when the source has no decoded smali counterpart (only real apktool
    smali - never jadx's fallback smali)."""
    if getattr(scan, "platform", None) != "android":
        return None
    if not tree_path.startswith(f"{_SOURCES_ROOT}/"):
        return None
    rel = tree_path[len(f"{_SOURCES_ROOT}/") :]
    stem, dot, ext = rel.rpartition(".")
    if not dot or ext not in ("java", "kt"):
        return None
    smali_rel = f"{stem}.smali"
    for root_name, root_path in apktool.smali_roots(scan.id):
        if (root_path / smali_rel).is_file():
            return f"{root_name}/{smali_rel}"
    return None


# ---- Method-level line anchors (Aug 11) ------------------------------------
# jadx renumbers source lines (a finding's ``line_number`` refers to the
# *jadx* output; smali ``.line`` directives carry the *original* source
# lines - they don't match). The honest anchor is METHOD granularity: each
# finding's jadx line sits inside a jadx method; that method has a named
# ``.method`` in the smali file at a physical line. The smali rail notes are
# pinned there, so they scroll with the smali editor's own line numbers.
# Both parsers are defensive (any miss -> no anchor -> the note stacks from
# the top, the pre-Aug-11 behaviour) and never raise on odd input.

# jadx method declaration heuristics. A method starts at a line matching this
# at class-body depth (see _jadx_methods), with the name captured. Control
# keywords (if/for/while/switch/catch/try/do/synchronized...) are excluded by
# name - a jadx method line always leads with modifiers + return type + name.
_JADX_METHOD_RE = re.compile(
    r"^\s*(?:(?:public|private|protected|static|final|synchronized|native|abstract|strictfp|default)\s+)*"
    r"(?:<[^>]*>\s+)?"  # type parameters
    r"(?:[\w$<>\[\],.? ]+\s+)?"  # return type (may be absent for ctors)
    r"(?P<name>[\w$]+)\s*\("
)
_CTRL_KEYWORDS = frozenset(
    {"if", "for", "while", "switch", "catch", "try", "do", "else", "return",
     "new", "synchronized", "throw", "instanceof", "super", "this", "case"}
)


class _JadxMethod:
    __slots__ = ("name", "start", "end")

    def __init__(self, name: str, start: int, end: int):
        self.name = name
        self.start = start
        self.end = end


def _jadx_methods(text: str) -> list[_JadxMethod]:
    """Brace-counted jadx method list: ``(name, start_line, end_line)`` (1-based,
    inclusive). Only declarations at CLASS-BODY depth (1) are methods - control
    flow and anonymous classes live deeper, so their braces never confuse the
    walk. Multi-line throws clauses (the ``{`` lands on a later line) are
    handled by only closing a pending method once its body has actually opened
    (depth rose above class level)."""
    methods: list[_JadxMethod] = []
    depth = 0
    pending: _JadxMethod | None = None
    opened = False
    for lineno, line in enumerate(text.split("\n"), start=1):
        stripped = line.strip()
        if pending is None and depth == 1:
            m = _JADX_METHOD_RE.match(stripped)
            # Exclude control flow (name in _CTRL_KEYWORDS), anonymous-class
            # field initializers (``new Foo() {`` - jadx emits them at class
            # depth and the name would be the anonymous class, not a method;
            # the anchor would map to nothing in smali anyway), and bodiless
            # declarations (``;`` - abstract/interface methods AND field
            # initializers calling methods like ``String x = foo();`` would
            # otherwise open a phantom method that never closes).
            if (
                m
                and m.group("name") not in _CTRL_KEYWORDS
                and not re.match(r"\s*new\b", stripped)
                and not stripped.endswith(";")
            ):
                pending = _JadxMethod(m.group("name"), lineno, lineno)
                opened = False
        depth += stripped.count("{") - stripped.count("}")
        if depth > 1:
            opened = True
        if pending is not None:
            pending.end = lineno
            # The method body closed when depth dropped back to class depth
            # (and it had opened - a header whose ``{`` is on a later line
            # must not close on its own signature line).
            if opened and depth <= 1:
                methods.append(pending)
                pending = None
                opened = False
            elif not opened and depth <= 1 and "{" in stripped:
                # A single-line body - ``public int getX() { return 1; }`` -
                # opened AND closed on the same line, so depth never rose
                # above class level and ``opened`` stayed False. jadx emits
                # compact one-line bodies for trivial accessors, so without
                # this the method would never close and be dropped.
                methods.append(pending)
                pending = None
        if depth < 0:  # pathological input - reset instead of corrupting
            depth = 0
    return methods


def _smali_method_lines(text: str) -> dict[str, int]:
    """``.method`` name -> physical line (1-based). ``<init>``/``<clinit>``
    included; first occurrence wins (overloads share the anchor, matching the
    first-found rule everywhere else)."""
    out: dict[str, int] = {}
    for lineno, line in enumerate(text.split("\n"), start=1):
        stripped = line.strip()
        if not stripped.startswith(".method"):
            continue
        rest = stripped[len(".method") :].strip()
        # name = token right before the '(' (modifiers + params between).
        head, _, _ = rest.partition("(")
        tokens = head.split()
        if tokens:
            out.setdefault(tokens[-1], lineno)
    return out


def compute_anchors(
    scan,
    mapping: dict[str, str],
    finding_lines: dict[str, list[int]],
) -> dict[str, dict[str, int]]:
    """jadx finding line -> smali physical line anchors, keyed by smali tree
    path (``smali/...``): ``{smali_path: {str(jadx_line): smali_line}}``.

    For each mapped ``sources/.../*.java`` with line-bearing findings: read
    the jadx source, brace-count its methods, find the method containing each
    finding line, then map that method NAME to its ``.method`` line in the
    apktool smali sibling (constructors: the jadx name is the class simple
    name -> smali ``<init>``). Unresolvable lines simply get no anchor - the
    caller stacks those notes from the top. Never raises; missing files /
    unparseable text degrade to empty anchors.
    """
    from app.agent.tools import resolve_tree_root

    anchors: dict[str, dict[str, int]] = {}
    try:
        sources_root = resolve_tree_root(scan)
    except ToolError:
        return anchors
    for java_tree_path, smali_tree_path in mapping.items():
        if not java_tree_path.startswith(_SOURCES_ROOT + "/"):
            continue
        rel = java_tree_path[len(_SOURCES_ROOT) + 1 :]
        lines = finding_lines.get(rel)
        if not lines:
            continue
        jadx_file = sources_root / rel
        smali_file = apktool.decoded_root(scan.id) / smali_tree_path
        if not jadx_file.is_file() or not smali_file.is_file():
            continue
        try:
            jadx_text = jadx_file.read_text(encoding="utf-8", errors="replace")
            smali_text = smali_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        methods = _jadx_methods(jadx_text)
        smali_lines = _smali_method_lines(smali_text)
        class_name = _jadx_class_name(jadx_text)
        per_line: dict[str, int] = {}
        for line in sorted(set(lines)):
            name = _method_containing(methods, line)
            if name is None:
                continue
            # jadx constructors carry the class simple name; smali calls it
            # <init>. Static-initializer blocks have no jadx method name at
            # all, so they never anchor (acceptable - rare findings).
            smali_name = "<init>" if name == class_name else name
            smali_line = smali_lines.get(smali_name)
            if smali_line is not None:
                per_line[str(line)] = smali_line
        if per_line:
            anchors[smali_tree_path] = per_line
    return anchors


def _jadx_class_name(text: str) -> str | None:
    m = re.search(r"\bclass\s+([\w$]+)", text)
    return m.group(1) if m else None


def _method_containing(methods: list[_JadxMethod], line: int) -> str | None:
    for meth in methods:
        if meth.start <= line <= meth.end:
            return meth.name
    return None


def smali_to_java(scan, tree_path: str) -> str | None:
    """``smali{,classesN}/com/foo/AuthManager.smali`` -> its jadx ``sources/``
    sibling (``.java`` first, ``.kt`` fallback), or None. Only apktool smali
    roots are accepted (jadx-fallback ``sources/.../*.smali`` never maps back)."""
    if getattr(scan, "platform", None) != "android":
        return None
    first, sep, rel = tree_path.partition("/")
    if not sep or not (first == "smali" or first.startswith("smali_classes")):
        return None
    if not rel.endswith(".smali"):
        return None
    stem = rel[: -len(".smali")]
    try:
        sources_root = resolve_tree_root(scan)
    except ToolError:
        return None
    for ext in ("java", "kt"):
        candidate = f"{_SOURCES_ROOT}/{stem}.{ext}"
        if (sources_root / f"{stem}.{ext}").is_file():
            return candidate
    return None
