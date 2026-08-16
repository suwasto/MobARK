"""M8 follow-up (Aug 16): the task-list.md artifact - tolerant parsing of the
agent's freeform plan, resolved-task rewriting (applied -> [x], rejected ->
[~]), supersede on a fresh change request, and the reject-pause message. Pure
filesystem over a monkeypatched data_dir - no DB, no network.
"""
from __future__ import annotations

import pytest

from app.analysis import edit_tasks


@pytest.fixture()
def work(monkeypatch, tmp_path):
    monkeypatch.setattr("app.config.settings.data_dir", tmp_path)
    return tmp_path


def _write(scan_id: int, content: str) -> edit_tasks.TaskList:
    return edit_tasks.write_task_list(scan_id, content)


def test_parse_freeform_tasks(work):
    tl = _write(
        1,
        "# Task: bypass the root check\n"
        "Some planning prose the agent left behind.\n"
        "- [ ] T1 remove android:debuggable (file: AndroidManifest.xml)\n"
        "- [x] T2 short-circuit RootCheck.isRooted (file: smali/com/foo/RootCheck.smali)\n"
        "- [~] T3 drop the root toast (file: res/values/strings.xml)\n",
    )
    assert tl.request == "bypass the root check"
    assert [t.token for t in tl.tasks] == ["T1", "T2", "T3"]
    assert [t.status for t in tl.tasks] == ["pending", "done", "rejected"]
    assert tl.tasks[0].file_path == "AndroidManifest.xml"
    assert tl.tasks[1].file_path == "smali/com/foo/RootCheck.smali"
    assert tl.tasks[2].file_path == "res/values/strings.xml"
    assert tl.next_pending().token == "T1"
    assert [t.token for t in tl.pending()] == ["T1"]
    # the artifact lives OUTSIDE the decompiled tree
    assert tl.path == work / "work" / "1" / "agent" / "task-list.md"


def test_parse_accepts_variant_markers_and_missing_tokens(work):
    tl = _write(
        1,
        "# Task: x\n"
        "- [done] the first (file: a.smali)\n"
        "- [todo] second\n"
        "- [r] third\n"
        "- plain prose is ignored\n",
    )
    assert [t.status for t in tl.tasks] == ["done", "pending", "rejected"]
    # no T<n> tokens -> synthetic, in order
    assert [t.token for t in tl.tasks] == ["T1", "T2", "T3"]
    assert tl.tasks[0].file_path == "a.smali"
    assert tl.tasks[1].file_path is None  # no recognizable editable path


def test_unparseable_file_is_empty_list_not_error(work):
    tl = _write(1, "# Just prose\nno checkboxes anywhere in here\n")
    assert tl.tasks == []
    assert tl.next_pending() is None


def test_mark_applied_flips_matching_task_and_preserves_formatting(work):
    _write(
        1,
        "# Task: t\n"
        "- [ ] T1 a (file: AndroidManifest.xml)\n"
        "- [ ] T2 b (file: smali/com/foo/B.smali)\n",
    )
    tl = edit_tasks.mark_task_resolved(1, "smali/com/foo/B.smali", verdict="applied")
    assert [t.status for t in tl.tasks] == ["pending", "done"]
    assert tl.next_pending().token == "T1"
    # the rewrite changed ONLY the marker - freeform formatting preserved
    assert "- [x] T2 b (file: smali/com/foo/B.smali)" in tl.raw
    assert "- [ ] T1 a (file: AndroidManifest.xml)" in tl.raw


def test_mark_rejected_flips_and_leaves_pending_for_later(work):
    _write(
        1,
        "# Task: t\n"
        "- [ ] T1 a (file: AndroidManifest.xml)\n"
        "- [ ] T2 b (file: smali/com/foo/B.smali)\n",
    )
    tl = edit_tasks.mark_task_resolved(1, "AndroidManifest.xml", verdict="rejected")
    assert [t.status for t in tl.tasks] == ["rejected", "pending"]
    assert tl.next_pending().token == "T2"
    assert "- [~] T1 a (file: AndroidManifest.xml)" in tl.raw


def test_mark_falls_back_to_first_pending_without_path_match(work):
    _write(1, "# Task: t\n- [ ] T1 a\n- [ ] T2 b\n")
    tl = edit_tasks.mark_task_resolved(1, "AndroidManifest.xml", verdict="applied")
    assert [t.status for t in tl.tasks] == ["done", "pending"]


def test_mark_no_artifact_or_exhausted(work):
    # no artifact -> None (single-file request - nothing to advance)
    assert edit_tasks.mark_task_resolved(1, "AndroidManifest.xml", verdict="applied") is None
    # exhausted list -> the list itself (not None), nothing to mark
    _write(1, "# Task: t\n- [x] T1 done\n")
    tl = edit_tasks.mark_task_resolved(1, "AndroidManifest.xml", verdict="applied")
    assert tl is not None
    assert tl.next_pending() is None


def test_supersede_archives_and_allows_fresh_start(work):
    _write(1, "# Task: old plan\n- [ ] T1 stale (file: AndroidManifest.xml)\n")
    archived = edit_tasks.supersede_task_list(1)
    assert archived is not None and archived.request == "old plan"
    assert not edit_tasks.task_file_path(1).exists()
    _write(1, "# Task: new plan\n- [ ] T1 fresh (file: smali/com/foo/A.smali)\n")
    assert edit_tasks.load_task_list(1).request == "new plan"
    # no-op when nothing is on disk
    assert edit_tasks.supersede_task_list(2) is None


def test_pause_message_lists_remaining_pending(work):
    _write(
        1,
        "# Task: bypass the root check\n"
        "- [ ] T1 disable debuggable (file: AndroidManifest.xml)\n"
        "- [ ] T2 neutralize RootCheck (file: smali/com/foo/RootCheck.smali)\n",
    )
    tl = edit_tasks.load_task_list(1)
    msg = edit_tasks.pause_message(tl, "AndroidManifest.xml")
    assert "rejected" in msg
    assert "T2" in msg
    assert "continue" in msg  # the human owns whether the rest is still wanted


def test_write_caps_oversized_content(work):
    tl = edit_tasks.write_task_list(1, "x" * (edit_tasks.MAX_TASK_LIST_CHARS + 1000))
    assert len(tl.raw) <= edit_tasks.MAX_TASK_LIST_CHARS + 100
