"""M8 Phase B: the edits table - DB-diff source of truth (edit/recompile).

Edits are **full-file rows in the DB, applied at rebuild** (owner decision,
Aug 10 2026) - never silent writes to the on-disk apktool tree, which stays
the pristine baseline. ``create_manual_edit`` baselines a new edit on the
file's *effective* content (baseline + the newest applied edit), so same-file
edits stack naturally; the effective content the viewer shows is exactly the
newest applied edit's ``new_content`` (or the baseline when there is none).
Apply/Reject/Revert are human API calls - never agent tools (decision 7).

Diff generation is stdlib ``difflib`` - no new dependency.
"""
from __future__ import annotations

import difflib

from sqlalchemy import select

from app.analysis import editable, tree
from app.models import Edit, utcnow


class EditError(ValueError):
    """Domain error for the edit service - the API maps it to a 400/409/413."""


def make_unified_diff(original: str, new: str, file_path: str) -> str:
    """A ``git diff``-style unified diff for one full-file edit (empty string
    when the content is identical - the create path rejects no-ops first)."""
    diff = difflib.unified_diff(
        original.splitlines(),
        new.splitlines(),
        fromfile=f"a/{file_path}",
        tofile=f"b/{file_path}",
        lineterm="",
    )
    return "\n".join(diff)


def newest_applied(db, scan_id: int, file_path: str) -> Edit | None:
    """The newest ``applied`` edit for a path, or None. Only applied edits
    shape the effective content; proposed/rejected/reverted never do."""
    return db.scalars(
        select(Edit)
        .where(
            Edit.scan_id == scan_id,
            Edit.file_path == file_path,
            Edit.status == "applied",
        )
        .order_by(Edit.id.desc())
        .limit(1)
    ).first()


def effective_content(db, scan_id: int, file_path: str) -> str | None:
    """The effective content for a path: newest applied edit's ``new_content``,
    or None when the baseline stands."""
    edit = newest_applied(db, scan_id, file_path)
    return edit.new_content if edit is not None else None


def create_manual_edit(db, scan, file_path: str, content: str) -> Edit:
    """Create a **manual** edit: validated, stacked on the effective content,
    stored as ``status=applied`` (the human authored it in the editor - no
    review step, unlike agent proposals in Phase D). Raises EditError on
    non-editable / oversized / unchanged content, TreeError/FileNotFoundError
    when the baseline cannot be read.
    """
    if not editable.can_edit(scan, file_path):
        raise EditError(f"{file_path!r} is not editable - only smali, res/, and "
                        "the decoded AndroidManifest.xml can be edited")
    if len(content) > editable.MAX_EDIT_CHARS:
        raise EditError(
            f"edit exceeds the {editable.MAX_EDIT_CHARS} character cap"
        )
    tree_path = editable.tree_path_from_edit_path(file_path)
    baseline = tree.read_tree_file(scan, tree_path, effective=False).content
    current = effective_content(db, scan.id, file_path)
    if current is None:
        current = baseline
    if content == current:
        raise EditError("content unchanged - nothing to save")
    edit = Edit(
        scan_id=scan.id,
        file_path=file_path,
        original_content=current,
        new_content=content,
        unified_diff=make_unified_diff(current, content, file_path),
        source="manual",
        status="applied",
        applied_at=utcnow(),
    )
    db.add(edit)
    db.commit()
    return edit


def create_agent_proposal(
    db, scan, file_path: str, content: str, instruction: str
) -> Edit:
    """Create an **agent** edit: validated, stacked on the effective content,
    stored as ``status=proposed`` - **never auto-applied** (decision 7: apply/
    reject/revert are human API calls). Raises EditError on non-editable /
    oversized / unchanged content, TreeError/FileNotFoundError when the
    baseline cannot be read. Same stacking rule as manual edits: the proposal
    baselines on the *effective* content so same-file proposals build on
    whatever is already applied, and its ``unified_diff`` is the review
    surface (D7 - file-by-file Apply/Reject in the UI).
    """
    if not editable.can_edit(scan, file_path):
        raise EditError(
            f"{file_path!r} is not editable - only smali, res/, and "
            "the decoded AndroidManifest.xml can be edited"
        )
    if len(content) > editable.MAX_EDIT_CHARS:
        raise EditError(f"edit exceeds the {editable.MAX_EDIT_CHARS} character cap")
    tree_path = editable.tree_path_from_edit_path(file_path)
    baseline = tree.read_tree_file(scan, tree_path, effective=False).content
    current = effective_content(db, scan.id, file_path)
    if current is None:
        current = baseline
    if content == current:
        raise EditError("content unchanged - nothing to propose")
    edit = Edit(
        scan_id=scan.id,
        file_path=file_path,
        original_content=current,
        new_content=content,
        unified_diff=make_unified_diff(current, content, file_path),
        source="agent",
        instruction=instruction,
        status="proposed",
    )
    db.add(edit)
    db.commit()
    return edit


def apply_edit(db, edit: Edit) -> Edit:
    """proposed -> applied (stamps applied_at). Agent proposals only - the
    human owns application."""
    if edit.status != "proposed":
        raise EditError(f"edit {edit.id} is {edit.status}, not proposed - only "
                        "proposed edits can be applied")
    edit.status = "applied"
    edit.applied_at = utcnow()
    db.commit()
    return edit


def reject_edit(db, edit: Edit) -> Edit:
    """proposed -> rejected."""
    if edit.status != "proposed":
        raise EditError(f"edit {edit.id} is {edit.status}, not proposed - only "
                        "proposed edits can be rejected")
    edit.status = "rejected"
    db.commit()
    return edit


def revert_edit(db, edit: Edit) -> Edit:
    """applied -> reverted: the effective content falls back to the previous
    applied edit (if any) or the baseline. Marking reverted removes it from
    the newest-applied lookup - stacks pop to the prior state."""
    if edit.status != "applied":
        raise EditError(f"edit {edit.id} is {edit.status}, not applied - only "
                        "applied edits can be reverted")
    edit.status = "reverted"
    db.commit()
    return edit
