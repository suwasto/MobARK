"""M8 Phase D tests - the agent edit flow.

Covers the edit tool surface (``read_editable_file`` / ``propose_smali_edit``
in agent/tools.py), the ``create_agent_proposal`` service (proposed, never
auto-applied, stacks on effective content), the platform + decode-ready
gating matrix (schemas filter + handlers), and the fake-model flagship demo
(read -> propose -> cited diff for review) through the REAL agent loop.

Fixtures build a real on-disk apktool tree (work/<id>/apktool/) so the tools
execute against real files, like the rest of the tool tests.
"""
from __future__ import annotations

import json

import pytest

import app.config
from app.agent import tools
from app.analysis import edits
from app.models import Edit, Scan

ANDROID_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.example.demo">
    <uses-sdk android:minSdkVersion="21"/>
    <application android:allowBackup="true" android:debuggable="true">
        <activity android:name=".MainActivity" android:exported="true"/>
    </application>
</manifest>
"""

SMALI = """\
.class public Lcom/foo/AuthManager;
.super Ljava/lang/Object;

.method public static check(Landroid/content/Context;)Z
    .locals 0
    const/4 v0, 0x1
    return v0
.end method
"""

_EDIT_TOOLS = {"find_smali_sibling", "read_editable_file", "propose_smali_edit"}


@pytest.fixture()
def env(monkeypatch, db_session_factory, tmp_path, platform="android"):
    monkeypatch.setattr("app.config.settings.data_dir", tmp_path)
    monkeypatch.setattr("app.db.SessionLocal", db_session_factory)
    with db_session_factory() as session:
        scan = Scan(filename="app.apk", platform=platform, status="done")
        session.add(scan)
        session.commit()
        scan_id = scan.id
    return scan_id, tmp_path, db_session_factory


def _apktool_tree(tmp_path, scan_id, manifest=ANDROID_MANIFEST) -> None:
    """A decoded apktool tree: AndroidManifest.xml + one smali file."""
    root = tmp_path / "work" / str(scan_id) / "apktool"
    (root / "smali/com/foo").mkdir(parents=True)
    (root / "AndroidManifest.xml").write_text(manifest)
    (root / "smali/com/foo/AuthManager.smali").write_text(SMALI)


def _jadx_tree(tmp_path, scan_id) -> None:
    root = tmp_path / "work" / str(scan_id) / "decompiled"
    (root / "sources/com/foo").mkdir(parents=True)
    (root / "sources/com/foo/AuthManager.java").write_text(
        "public class AuthManager {}\n"
    )


# ---- gating matrix ------------------------------------------------------------


def test_edit_tools_allowed_requires_android_and_decode(env):
    scan_id, tmp_path, _ = env
    assert tools.edit_tools_allowed(scan_id) is False  # no decode yet
    _apktool_tree(tmp_path, scan_id)
    assert tools.edit_tools_allowed(scan_id) is True


def test_edit_tools_allowed_ios_never(monkeypatch, db_session_factory, tmp_path):
    monkeypatch.setattr("app.config.settings.data_dir", tmp_path)
    monkeypatch.setattr("app.db.SessionLocal", db_session_factory)
    with db_session_factory() as session:
        scan = Scan(filename="app.ipa", platform="ios", status="done")
        session.add(scan)
        session.commit()
        scan_id = scan.id
    _apktool_tree(tmp_path, scan_id)  # decode on iOS is impossible, but be safe
    assert tools.edit_tools_allowed(scan_id) is False


def test_schemas_for_platform_edit_tools_gate():
    off = {s["function"]["name"] for s in tools.schemas_for_platform("android")}
    on = {
        s["function"]["name"]
        for s in tools.schemas_for_platform("android", edit_tools_enabled=True)
    }
    assert _EDIT_TOOLS.isdisjoint(off)  # never offered by default
    assert _EDIT_TOOLS <= on  # offered when decode-ready


def test_schemas_for_platform_web_and_edit_filters_are_independent():
    both = {
        s["function"]["name"]
        for s in tools.schemas_for_platform(
            "android", web_research_enabled=True, edit_tools_enabled=True
        )
    }
    assert {"web_search", "web_fetch"} <= both
    assert _EDIT_TOOLS <= both
    web_only = {
        s["function"]["name"]
        for s in tools.schemas_for_platform(
            "android", web_research_enabled=True, edit_tools_enabled=False
        )
    }
    assert _EDIT_TOOLS.isdisjoint(web_only)
    assert {"web_search", "web_fetch"} <= web_only


# ---- find_smali_sibling ------------------------------------------------------


def test_find_smali_sibling_maps_jadx_path(env):
    """The bridge between search_code (jadx sources) and the edit tools
    (apktool smali): a sources/ class path maps to its smali sibling."""
    scan_id, tmp_path, _ = env
    _jadx_tree(tmp_path, scan_id)
    _apktool_tree(tmp_path, scan_id)
    result = tools.find_smali_sibling(
        scan_id, "sources/com/foo/AuthManager.java"
    )
    assert result == {"sibling": "smali/com/foo/AuthManager.smali"}


def test_find_smali_sibling_denied_without_decode(env):
    scan_id, tmp_path, _ = env
    _jadx_tree(tmp_path, scan_id)
    with pytest.raises(tools.ToolError, match="open the Smali view first"):
        tools.find_smali_sibling(scan_id, "sources/com/foo/AuthManager.java")


def test_find_smali_sibling_rejects_non_sources_path(env):
    scan_id, tmp_path, _ = env
    _apktool_tree(tmp_path, scan_id)
    with pytest.raises(tools.ToolError, match="not a sources/ class path"):
        tools.find_smali_sibling(scan_id, "smali/com/foo/AuthManager.smali")


def test_find_smali_sibling_no_sibling_is_error(env):
    """A class jadx decompiled but apktool didn't (or a jadx-fallback smali)
    has no editable sibling - a clean error, never a guessed path."""
    scan_id, tmp_path, _ = env
    _jadx_tree(tmp_path, scan_id)
    _apktool_tree(tmp_path, scan_id)
    (tmp_path / "work" / str(scan_id) / "decompiled" / "sources/com/foo"
     / "Nope.java").write_text("class Nope {}\n")
    with pytest.raises(tools.ToolError, match="no decoded smali sibling"):
        tools.find_smali_sibling(scan_id, "sources/com/foo/Nope.java")


def test_execute_tool_dispatches_find_smali_sibling(env):
    scan_id, tmp_path, _ = env
    _jadx_tree(tmp_path, scan_id)
    _apktool_tree(tmp_path, scan_id)
    out = json.loads(
        tools.execute_tool(
            scan_id, "find_smali_sibling",
            {"path": "sources/com/foo/AuthManager.java"},
        )
    )
    assert out == {"sibling": "smali/com/foo/AuthManager.smali"}


# ---- read_editable_file -------------------------------------------------------


def test_read_editable_file_denied_without_decode(env):
    scan_id, tmp_path, _ = env
    with pytest.raises(tools.ToolError, match="open the Smali view first"):
        tools.read_editable_file(scan_id, "AndroidManifest.xml")


def test_read_editable_file_reads_manifest(env):
    scan_id, tmp_path, _ = env
    _apktool_tree(tmp_path, scan_id)
    text = tools.read_editable_file(scan_id, "AndroidManifest.xml")
    assert 'android:debuggable="true"' in text
    assert "com.example.demo" in text


def test_read_editable_file_rejects_non_editable_path(env):
    scan_id, tmp_path, _ = env
    _apktool_tree(tmp_path, scan_id)
    with pytest.raises(tools.ToolError, match="not editable"):
        tools.read_editable_file(scan_id, "sources/com/foo/AuthManager.java")


def test_read_editable_file_traversal_guard(env):
    scan_id, tmp_path, _ = env
    _apktool_tree(tmp_path, scan_id)
    with pytest.raises(tools.ToolError, match="escapes"):
        tools.read_editable_file(scan_id, "../../etc/passwd")


def test_read_editable_file_missing_is_tool_error(env):
    scan_id, tmp_path, _ = env
    _apktool_tree(tmp_path, scan_id)
    with pytest.raises(tools.ToolError, match="not a file"):
        tools.read_editable_file(scan_id, "smali/com/foo/Nope.smali")


def test_read_editable_file_overlays_applied_edits(env):
    """The model must read the CURRENT state (newest applied edit), not the
    pristine on-disk baseline - proposals stack on effective content."""
    scan_id, tmp_path, db = env
    _apktool_tree(tmp_path, scan_id)
    with db() as session:
        scan = session.get(Scan, scan_id)
        edits.create_manual_edit(
            session, scan, "AndroidManifest.xml",
            ANDROID_MANIFEST.replace('android:debuggable="true"',
                                     'android:debuggable="false"'),
        )
    text = tools.read_editable_file(scan_id, "AndroidManifest.xml")
    assert 'android:debuggable="false"' in text
    assert 'android:debuggable="true"' not in text


# ---- propose_smali_edit -------------------------------------------------------


def test_propose_smali_edit_creates_proposed_not_applied(env):
    scan_id, tmp_path, db = env
    _apktool_tree(tmp_path, scan_id)
    result = tools.propose_smali_edit(
        scan_id,
        "AndroidManifest.xml",
        "Remove the debuggable flag for the test build",
        ANDROID_MANIFEST.replace('android:debuggable="true"',
                                 'android:debuggable="false"'),
    )
    assert result["status"] == "proposed"
    assert result["file_path"] == "AndroidManifest.xml"
    assert result["edit_id"] > 0
    assert "-" in result["unified_diff"] and "+" in result["unified_diff"]

    with db() as session:
        edit = session.get(Edit, result["edit_id"])
        assert edit.status == "proposed"
        assert edit.source == "agent"
        assert edit.instruction == "Remove the debuggable flag for the test build"
        # Never auto-applied: the effective content is unchanged (no applied row).
        assert edits.newest_applied(session, scan_id, "AndroidManifest.xml") is None


def test_propose_smali_edit_denied_without_decode(env):
    scan_id, tmp_path, _ = env
    with pytest.raises(tools.ToolError, match="open the Smali view first"):
        tools.propose_smali_edit(scan_id, "AndroidManifest.xml", "x", "y")


def test_propose_smali_edit_non_editable_is_tool_error(env):
    scan_id, tmp_path, _ = env
    _apktool_tree(tmp_path, scan_id)
    with pytest.raises(tools.ToolError, match="not editable"):
        tools.propose_smali_edit(
            scan_id, "sources/com/foo/AuthManager.java", "x", "class X {}"
        )


def test_propose_smali_edit_unchanged_is_tool_error(env):
    scan_id, tmp_path, _ = env
    _apktool_tree(tmp_path, scan_id)
    with pytest.raises(tools.ToolError, match="unchanged"):
        tools.propose_smali_edit(
            scan_id, "AndroidManifest.xml", "no-op", ANDROID_MANIFEST
        )


def test_propose_smali_edit_missing_file_is_tool_error(env):
    scan_id, tmp_path, _ = env
    _apktool_tree(tmp_path, scan_id)
    with pytest.raises(tools.ToolError):
        tools.propose_smali_edit(scan_id, "smali/com/foo/Nope.smali", "x", "y")


def test_propose_smali_edit_size_cap(env, monkeypatch):
    from app.analysis import editable

    scan_id, tmp_path, _ = env
    _apktool_tree(tmp_path, scan_id)
    monkeypatch.setattr(editable, "MAX_EDIT_CHARS", 10)
    with pytest.raises(tools.ToolError, match="character cap"):
        tools.propose_smali_edit(
            scan_id, "AndroidManifest.xml", "x", "y" * 20
        )


def test_proposals_never_leak_into_effective_content(env):
    """A proposed edit must NOT shape the effective content - only APPLIED
    edits stack; a proposal is a review candidate, not a live change."""
    scan_id, tmp_path, db = env
    _apktool_tree(tmp_path, scan_id)
    tools.propose_smali_edit(
        scan_id, "AndroidManifest.xml", "first",
        ANDROID_MANIFEST.replace('android:debuggable="true"',
                                 'android:debuggable="false"'),
    )
    with db() as session:
        # Effective content is still the baseline - proposals never apply.
        assert edits.effective_content(session, scan_id, "AndroidManifest.xml") is None


def test_propose_smali_edit_blocked_while_pending(env):
    """A file with a PROPOSED edit cannot get a second proposal - even with
    different content - until the human resolves the pending one (Apply/Reject).
    This is the service-level guard behind the 'endless re-proposal' fix:
    without it, a 'continue' turn (or a looping model) stacks duplicate
    proposals for the same file instead of waiting for the review verdict."""
    scan_id, tmp_path, db = env
    _apktool_tree(tmp_path, scan_id)
    first = tools.propose_smali_edit(
        scan_id, "AndroidManifest.xml", "disable debuggable",
        ANDROID_MANIFEST.replace('android:debuggable="true"',
                                 'android:debuggable="false"'),
    )
    with pytest.raises(tools.ToolError, match="still proposed"):
        tools.propose_smali_edit(
            scan_id, "AndroidManifest.xml", "remove allowBackup too",
            ANDROID_MANIFEST.replace('android:allowBackup="true"',
                                     'android:allowBackup="false"'),
        )
    # After the human REJECTS the pending proposal, a new one is allowed.
    with db() as session:
        edits.reject_edit(session, session.get(Edit, first["edit_id"]))
    second = tools.propose_smali_edit(
        scan_id, "AndroidManifest.xml", "remove allowBackup too",
        ANDROID_MANIFEST.replace('android:allowBackup="true"',
                                 'android:allowBackup="false"'),
    )
    assert second["status"] == "proposed"
    assert second["edit_id"] != first["edit_id"]


def test_propose_again_after_apply_then_revert(env):
    """The reported flow: the human APPLIES a proposal, then REVERTS it (the
    file is back to baseline), then asks the agent to edit the file again. A
    reverted edit is resolved - it must never block a new proposal (only a
    still-``proposed`` row does). Regression: after apply -> revert the
    service-level guard must pass so the agent can re-propose."""
    scan_id, tmp_path, db = env
    _apktool_tree(tmp_path, scan_id)
    first = tools.propose_smali_edit(
        scan_id, "AndroidManifest.xml", "disable debuggable",
        ANDROID_MANIFEST.replace('android:debuggable="true"',
                                 'android:debuggable="false"'),
    )
    # Human: apply, then revert (Restore original in Edit & recompile).
    with db() as session:
        edit = session.get(Edit, first["edit_id"])
        edits.apply_edit(session, edit)
        edits.revert_edit(session, session.get(Edit, first["edit_id"]))
        assert session.get(Edit, first["edit_id"]).status == "reverted"
    # The file is back at baseline - a new proposal for it must succeed.
    second = tools.propose_smali_edit(
        scan_id, "AndroidManifest.xml", "disable debuggable",
        ANDROID_MANIFEST.replace('android:debuggable="true"',
                                 'android:debuggable="false"'),
    )
    assert second["status"] == "proposed"
    assert second["edit_id"] != first["edit_id"]


# ---- execute_tool dispatch ----------------------------------------------------


def test_execute_tool_dispatches_edit_tools(env):
    scan_id, tmp_path, _ = env
    _apktool_tree(tmp_path, scan_id)
    out = json.loads(
        tools.execute_tool(scan_id, "read_editable_file", {"path": "AndroidManifest.xml"})
    )
    assert "com.example.demo" in out

    out = json.loads(
        tools.execute_tool(
            scan_id,
            "propose_smali_edit",
            {
                "path": "AndroidManifest.xml",
                "instruction": "toggle",
                "new_content": ANDROID_MANIFEST.replace(
                    'android:debuggable="true"', 'android:debuggable="false"'
                ),
            },
        )
    )
    assert out["status"] == "proposed" and out["edit_id"] > 0

    out = json.loads(
        tools.execute_tool(scan_id, "propose_smali_edit", {"path": "bad"})
    )
    assert "error" in out


# ---- fake-model flagship demo (read -> propose -> cited diff) -----------------


@pytest.fixture()
def demo_scan(monkeypatch, db_session_factory, tmp_path):
    """A done Android scan with BOTH trees: a jadx source (so the agent
    context/tree helpers work) AND a decoded apktool tree (so the edit tools
    execute for real)."""
    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    monkeypatch.setattr("app.db.SessionLocal", db_session_factory)
    with db_session_factory() as session:
        scan = Scan(filename="app.apk", platform="android", status="done")
        session.add(scan)
        session.commit()
        scan_id = scan.id
    _jadx_tree(tmp_path, scan_id)
    _apktool_tree(tmp_path, scan_id)
    return scan_id, db_session_factory


def _fake_backend():
    from app.model.backends import ModelBackend
    from app.model.fake import FAKE_MODEL

    return ModelBackend(
        id="fake",
        provider_id="fake",
        name="Fake (dev demo)",
        kind="local",
        base_url="",
        model=FAKE_MODEL,
        api_key="fake",
    )


def test_fake_edit_demo_streamed(demo_scan, monkeypatch):
    """THE flagship demo: the fake model + real loop + real edit tools,
    streamed. The dock sees thinking tokens, read_editable_file + a real
    propose_smali_edit step, then a cited answer pointing at the stored
    proposal - never applied automatically."""
    from app.agent import chat as chat_mod
    from app.agent.chat import answer_question

    scan_id, db = demo_scan
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: _fake_backend())
    events: list[chat_mod.AgentEvent] = []

    result = answer_question(
        scan_id,
        "Please disable debuggable for the test build",
        stream=True,
        on_event=events.append,
    )

    kinds = [e.kind for e in events]
    assert kinds[0] == "token"
    starts = [e for e in events if e.kind == "tool_start"]
    assert [s.payload["name"] for s in starts] == [
        "search_code",
        "read_editable_file",
        "propose_smali_edit",
    ]
    ends = [e for e in events if e.kind == "tool_end"]
    assert all(e.payload["status"] == "ok" for e in ends)

    assert "proposed" in result.answer
    assert "Review edits panel" in result.answer
    assert result.tool_mode == "tools"
    assert [r.name for r in result.tool_runs] == [
        "search_code",
        "read_editable_file",
        "propose_smali_edit",
    ]
    assert all(r.status == "ok" for r in result.tool_runs)

    # The stored row is PROPOSED - effective content untouched.
    with db() as session:
        rows = list(
            session.query(Edit).filter(Edit.scan_id == scan_id).all()
        )
        assert len(rows) == 1
        assert rows[0].status == "proposed"
        assert rows[0].source == "agent"
        assert rows[0].file_path == "AndroidManifest.xml"
        assert edits.newest_applied(session, scan_id, "AndroidManifest.xml") is None


def test_fake_edit_demo_buffered_path(demo_scan, monkeypatch):
    """The buffered /chat path runs the same script."""
    from app.agent import chat as chat_mod
    from app.agent.chat import answer_question

    scan_id, db = demo_scan
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: _fake_backend())
    result = answer_question(scan_id, "please harden the manifest")
    assert "proposed" in result.answer
    assert result.tool_mode == "tools"
    with db() as session:
        assert session.query(Edit).filter(Edit.scan_id == scan_id).count() == 1


def test_fake_edit_demo_uses_bar_target_hint(demo_scan, monkeypatch):
    """The ✨ Ask agent bar appends '(Target editable file: ...)' - the fake
    reads + proposes THAT file (smali here), not the manifest fallback."""
    from app.agent import chat as chat_mod
    from app.agent.chat import answer_question

    scan_id, db = demo_scan
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: _fake_backend())
    result = answer_question(
        scan_id,
        "Add a review marker to this file\n\n(Target editable file: "
        "smali/com/foo/AuthManager.smali)",
    )
    assert "smali/com/foo/AuthManager.smali" in result.answer
    with db() as session:
        edit = session.query(Edit).filter(Edit.scan_id == scan_id).one()
        assert edit.file_path == "smali/com/foo/AuthManager.smali"
        assert edit.status == "proposed"
        assert "# MobARK demo edit" in edit.new_content


def test_fake_edit_demo_editable_mention_targets_that_file(demo_scan, monkeypatch):
    """M8 follow-up: the dock's @-mention - '@smali/com/foo/AuthManager.smali
    add a review marker' targets the MENTIONED editable file (not the
    manifest fallback), same as the bar hint flow."""
    from app.agent import chat as chat_mod
    from app.agent.chat import answer_question

    scan_id, db = demo_scan
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: _fake_backend())
    result = answer_question(
        scan_id,
        "@smali/com/foo/AuthManager.smali add a review marker to the class",
    )
    assert "smali/com/foo/AuthManager.smali" in result.answer
    with db() as session:
        edit = session.query(Edit).filter(Edit.scan_id == scan_id).one()
        assert edit.file_path == "smali/com/foo/AuthManager.smali"
        assert edit.status == "proposed"
        assert "# MobARK demo edit" in edit.new_content


def test_fake_edit_demo_manifest_mention_targets_manifest(demo_scan, monkeypatch):
    """A manifest tree-path mention (the synthetic root's tree form)
    converts to the edits-table path 'AndroidManifest.xml'."""
    from app.agent import chat as chat_mod
    from app.agent.chat import answer_question

    scan_id, db = demo_scan
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: _fake_backend())
    answer_question(
        scan_id,
        "@AndroidManifest.xml/AndroidManifest.xml disable debuggable",
    )
    with db() as session:
        edit = session.query(Edit).filter(Edit.scan_id == scan_id).one()
        assert edit.file_path == "AndroidManifest.xml"
        assert edit.status == "proposed"
        assert 'android:debuggable="false"' in edit.new_content


def test_fake_edit_demo_jadx_mention_maps_via_smali_sibling(demo_scan, monkeypatch):
    """M8 follow-up: an @-mention of a JADX source (read-only) drives the
    search -> map -> read -> propose flow - find_smali_sibling maps the
    mentioned class to its editable smali, and the proposal targets the
    SIBLING, not the manifest fallback."""
    from app.agent import chat as chat_mod
    from app.agent.chat import answer_question

    scan_id, db = demo_scan
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: _fake_backend())
    events: list[chat_mod.AgentEvent] = []
    result = answer_question(
        scan_id,
        "@sources/com/foo/AuthManager.java add a review marker to this class",
        stream=True,
        on_event=events.append,
    )

    starts = [e.payload["name"] for e in events if e.kind == "tool_start"]
    assert starts == [
        "search_code",
        "find_smali_sibling",
        "read_editable_file",
        "propose_smali_edit",
    ]
    assert "smali/com/foo/AuthManager.smali" in result.answer
    with db() as session:
        edit = session.query(Edit).filter(Edit.scan_id == scan_id).one()
        assert edit.file_path == "smali/com/foo/AuthManager.smali"
        assert edit.status == "proposed"
        assert "# MobARK demo edit" in edit.new_content


def test_fake_edit_jadx_mention_no_sibling_is_honest_error(demo_scan, monkeypatch):
    """A jadx mention whose class has no decoded smali sibling fails cleanly
    (find_smali_sibling errors) - no proposal, honest answer."""
    from app.agent import chat as chat_mod
    from app.agent.chat import answer_question

    scan_id, db = demo_scan
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: _fake_backend())
    result = answer_question(
        scan_id,
        "@sources/com/foo/Nope.java fix this class",
    )
    assert "could not propose" in result.answer
    with db() as session:
        assert session.query(Edit).filter(Edit.scan_id == scan_id).count() == 0


def test_fake_edit_jadx_mention_alone_is_question_not_edit(demo_scan, monkeypatch):
    """An @-mention of a jadx source WITHOUT edit keywords is a question, not
    an edit request - it keeps the main demo (no proposal row)."""
    from app.agent import chat as chat_mod
    from app.agent.chat import answer_question

    scan_id, db = demo_scan
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: _fake_backend())
    result = answer_question(scan_id, "@sources/com/foo/AuthManager.java what does this do?")
    assert "search_code" in [r.name for r in result.tool_runs]
    with db() as session:
        assert session.query(Edit).filter(Edit.scan_id == scan_id).count() == 0


def test_fake_edit_demo_not_edit_question_runs_main_demo(demo_scan, monkeypatch):
    """A non-edit question on the same scan keeps the M6.1 main demo (the
    edit script must not hijack every question)."""
    from app.agent import chat as chat_mod
    from app.agent.chat import answer_question

    scan_id, db = demo_scan
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: _fake_backend())
    result = answer_question(scan_id, "where is the webview?")
    assert "search_code" in [r.name for r in result.tool_runs]
    with db() as session:
        assert session.query(Edit).filter(Edit.scan_id == scan_id).count() == 0


def test_fake_edit_demo_failed_read_composes_honest_answer(demo_scan, monkeypatch):
    """If the read errors (e.g. the bar target doesn't exist), the fake must
    NOT retry the same call - it composes an honest answer and the loop ends
    within the round limit (M7 web-demo precedent)."""
    from app.agent import chat as chat_mod
    from app.agent.chat import answer_question

    scan_id, db = demo_scan
    monkeypatch.setattr(chat_mod, "_pick_chat_backend", lambda: _fake_backend())
    result = answer_question(
        scan_id,
        "fix this\n\n(Target editable file: smali/com/foo/Nope.smali)",
    )
    assert "could not propose" in result.answer
    assert "not a file" in result.answer
    with db() as session:
        assert session.query(Edit).filter(Edit.scan_id == scan_id).count() == 0


def test_fake_edit_round_shapes_unit_level():
    """The script's round machine in isolation: no results -> read call;
    read result -> propose call with the REAL content-derived new_content;
    propose result -> final cited answer (no tool calls)."""
    from app.model.fake import _edit_response

    # Round 1: no tool results yet -> search the jadx tree for a keyword from
    # the question AND read the target (both in one round).
    r1 = _edit_response([{"role": "user", "content": "harden it"}])
    m1 = r1.choices[0].message
    assert [c.function.name for c in m1.tool_calls] == [
        "search_code",
        "read_editable_file",
    ]
    assert json.loads(m1.tool_calls[0].function.arguments) == {
        "pattern": "harden"
    }
    assert json.loads(m1.tool_calls[1].function.arguments) == {
        "path": "AndroidManifest.xml"
    }

    # Round 2: read result present -> propose (content derived from the read).
    r2 = _edit_response(
        [
            {"role": "user", "content": "harden it"},
            {"role": "tool", "tool_call_id": "call_read",
             "content": json.dumps(ANDROID_MANIFEST)},
        ]
    )
    m2 = r2.choices[0].message
    assert [c.function.name for c in m2.tool_calls] == ["propose_smali_edit"]
    args = json.loads(m2.tool_calls[0].function.arguments)
    assert args["path"] == "AndroidManifest.xml"
    assert args["instruction"] == "harden it"
    assert 'android:debuggable="false"' in args["new_content"]
    assert 'android:debuggable="true"' not in args["new_content"]

    # Round 3: propose result present -> final answer, no tool calls. The
    # top search hit is cited when search_code found one.
    r3 = _edit_response(
        [
            {"role": "tool", "tool_call_id": "call_search",
             "content": json.dumps([
                 {"file": "com/foo/AuthManager.java", "line": 12,
                  "snippet": "check() { return 1; }"}])},
            {"role": "tool", "tool_call_id": "call_propose",
             "content": json.dumps(
                 {"edit_id": 7, "file_path": "AndroidManifest.xml",
                  "status": "proposed", "unified_diff": "-a\\n+b"})},
        ]
    )
    m3 = r3.choices[0].message
    assert not getattr(m3, "tool_calls", None)
    assert "edit #7" in m3.content
    assert "com/foo/AuthManager.java:12" in m3.content
    assert "applied automatically" in m3.content


def test_fake_edit_stream_chunks_round1(monkeypatch):
    from app.model.fake import _edit_stream_chunks

    chunks = list(
        _edit_stream_chunks([{"role": "user", "content": "harden it"}])
    )
    contents = [c.choices[0].delta.content for c in chunks if c.choices[0].delta.content]
    assert "search the decompiled code" in "".join(contents)
    tool_chunks = [c.choices[0].delta.tool_calls for c in chunks if c.choices[0].delta.tool_calls]
    assert len(tool_chunks) == 2
    assert [tc[0]["function"]["name"] for tc in tool_chunks] == [
        "search_code",
        "read_editable_file",
    ]
