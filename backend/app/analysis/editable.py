"""M8 edit & recompile: the editability predicate + path mapping (Phase B).

**Only** the apktool-decoded, rebuildable surface is editable: ``smali*``\u200b/,
``res/``, and the decoded ``AndroidManifest.xml``. Everything else — the
entire jadx ``sources/`` root (a one-way decompiler; the PRD's explicit
non-goal), ``original/``, ``unknown/``, and the whole iOS bundle — stays
read-only. Enforced **server-side** here (the edit API, and in Phase C the
rebuild apply step, in Phase D the agent tool), never just in the UI.

Path convention: the ``edits`` table stores **apktool-root-relative** paths
(``smali/com/foo/A.smali``, ``res/values/strings.xml``, ``AndroidManifest.xml``),
while the decompiler tree + content endpoints use ``<root>/<relative>`` paths.
The two mapping helpers convert between them.
"""
from __future__ import annotations

# Synthetic tree root for the decoded AndroidManifest.xml (the plan's
# "decoded AndroidManifest.xml (synthetic root)"). Tree path for it is
# ``AndroidManifest.xml/AndroidManifest.xml``; the edit path is just
# ``AndroidManifest.xml``.
MANIFEST_ROOT = "AndroidManifest.xml"

# Hard cap on edit content (full-file rows); a clean 413-style rejection.
MAX_EDIT_CHARS = 200_000


def can_edit(scan, path: str) -> bool:
    """True only for apktool-root-relative editable paths (``path`` uses the
    edits-table convention). Never true for jadx ``sources/``, iOS bundles,
    or non-Android scans — enforced in the edit API + rebuild apply step."""
    if scan is None or getattr(scan, "platform", None) != "android":
        return False
    if not path:
        return False
    if path == MANIFEST_ROOT:
        return True
    first, sep, _rest = path.partition("/")
    if not sep:
        return False  # bare file names under the apktool root are not editable
    if first == "res":
        return True
    if first == "smali" or first.startswith("smali_classes"):
        return True
    return False


def edit_path_from_tree_path(root_name: str, rel: str) -> str:
    """Tree path (``<root>/<relative>``) -> edits-table path.

    The smali/res roots ARE apktool directories, so the tree path already is
    the edit path; the manifest synthetic root duplicates its name and strips
    to ``AndroidManifest.xml``.
    """
    if root_name == MANIFEST_ROOT:
        return MANIFEST_ROOT
    return f"{root_name}/{rel}" if rel else root_name


def tree_path_from_edit_path(edit_path: str) -> str:
    """Edits-table path -> tree path (the content-endpoint form)."""
    if edit_path == MANIFEST_ROOT:
        return f"{MANIFEST_ROOT}/{MANIFEST_ROOT}"
    return edit_path
