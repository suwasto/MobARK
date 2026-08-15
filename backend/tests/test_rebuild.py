"""M8 Phase C: rebuild pipeline - service + RQ job tests (tools mocked).

The keystore lifecycle, edit overlay, stage sequencing, artifact naming and
the fail-loudly contract (each stage maps to a specific RebuildError) are
the units under test. No subprocesses, no Redis.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from app.analysis import apktool, rebuild
from app.analysis.rebuild import RebuildError
from app.analysis.subprocess import RunResult
from app.models import Edit
from app.workers import jobs


class _Scan:
    """Minimal stand-in for a Scan row (build_apk only needs id + filename)."""

    def __init__(self, filename: str = "app.apk"):
        self.id = 7
        self.filename = filename


def _decoded_tree(tmp_path, monkeypatch, scan_id: int = 7) -> Path:
    """Point data_dir at tmp_path and materialize a decoded apktool tree."""
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    root = apktool.decoded_root(scan_id)
    (root / "smali/com/foo").mkdir(parents=True)
    (root / "AndroidManifest.xml").write_text("<manifest/>")
    (root / "smali/com/foo/AuthManager.smali").write_text(
        ".class public LAuthManager;\nconst/4 v0, 0x0\n"
    )
    return root


def _edit(scan_id: int, file_path: str, new_content: str = "edited\n") -> Edit:
    return Edit(
        scan_id=scan_id,
        file_path=file_path,
        original_content="old\n",
        new_content=new_content,
        unified_diff="-old\n+edited\n",
        source="manual",
        status="applied",
    )


def _make_scan_and_edits(db_factory, platform="android", status="done"):
    from app.models import Scan

    with db_factory() as session:
        scan = Scan(
            filename="app.apk",
            platform=platform,
            status=status,
            storage_path="/unused/uploads",
        )
        session.add(scan)
        session.commit()
        return scan.id


# ---- keystore ----------------------------------------------------------------


def test_ensure_keystore_generates_once(monkeypatch, tmp_path):
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    monkeypatch.setattr(rebuild, "_keytool_binary", lambda: "keytool")
    calls = []

    def fake_run(cmd, timeout):
        calls.append(cmd)
        # the real keytool would create the keystore file - the fake must too
        if cmd[0] == "keytool":
            ks = Path(cmd[cmd.index("-keystore") + 1])
            ks.parent.mkdir(parents=True, exist_ok=True)
            ks.write_bytes(b"fake-jks")
        return RunResult(0, "", "")

    monkeypatch.setattr(rebuild, "run_tool", fake_run)
    ks1, pass1 = rebuild.ensure_keystore()
    assert ks1.name == "mobark-test.jks"
    assert ks1.is_file()
    pf = tmp_path / "mobark-test.jks.pass"
    assert pf.is_file()
    assert pf.read_text().strip() == pass1
    assert len(pass1) >= 24
    assert oct(ks1.stat().st_mode & 0o777) == "0o600"
    assert oct(pf.stat().st_mode & 0o777) == "0o600"
    # the keytool argv carries the JKS storetype + the fixed alias
    assert "-storetype" in calls[0]
    assert "mobark-test" in calls[0]

    ks2, pass2 = rebuild.ensure_keystore()  # second call reuses, no regen
    assert ks2 == ks1
    assert pass2 == pass1
    assert len(calls) == 1


def test_ensure_keystore_keytool_failure_is_loud(monkeypatch, tmp_path):
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    monkeypatch.setattr(rebuild, "_keytool_binary", lambda: "keytool")
    monkeypatch.setattr(
        rebuild, "run_tool", lambda cmd, timeout: RunResult(1, "", "boom")
    )
    with pytest.raises(RebuildError) as exc:
        rebuild.ensure_keystore()
    assert exc.value.stage == "signing"
    assert "keytool failed" in str(exc.value)


# ---- edit overlay ------------------------------------------------------------


def test_apply_edits_overlays_content(monkeypatch, tmp_path):
    root = _decoded_tree(tmp_path, monkeypatch)
    rebuild.apply_edits(
        root, [_edit(7, "smali/com/foo/AuthManager.smali", new_content="patched\n")]
    )
    assert (root / "smali/com/foo/AuthManager.smali").read_text() == "patched\n"


def test_apply_edits_rejects_traversal_escape(monkeypatch, tmp_path):
    root = _decoded_tree(tmp_path, monkeypatch)
    with pytest.raises(RebuildError) as exc:
        rebuild.apply_edits(root, [_edit(7, "../evil.txt")])
    assert exc.value.stage == "applying"
    assert "escapes" in str(exc.value)
    assert not (root.parent / "evil.txt").exists()


def test_apply_edits_missing_file_fails_loudly(monkeypatch, tmp_path):
    root = _decoded_tree(tmp_path, monkeypatch)
    with pytest.raises(RebuildError) as exc:
        rebuild.apply_edits(root, [_edit(7, "smali/com/foo/Ghost.smali")])
    assert exc.value.stage == "applying"
    assert "not found" in str(exc.value)


# ---- build_apk pipeline ------------------------------------------------------


def _fake_pipeline_tools(monkeypatch, tmp_path):
    """Fake the tools so build_apk's stages all succeed: apktool.build writes
    the unsigned APK; zipalign/apksigner are run_tool fakes that materialize
    their outputs; apksigner verify prints a cert digest."""
    signed_payload = b"PK\x03\x04signed-apk"

    def fake_apktool_build(tree_dir, out_apk, timeout=None):
        out_apk.parent.mkdir(parents=True, exist_ok=True)
        out_apk.write_bytes(b"PK\x03\x04unsigned")

    monkeypatch.setattr(apktool, "build", fake_apktool_build)

    def fake_run(cmd, timeout):
        if cmd[0] == "zipalign":
            Path(cmd[-1]).write_bytes(b"PK\x03\x04aligned")
            return RunResult(0, "", "")
        if cmd[0] == "apksigner" and "sign" in cmd:
            out = Path(cmd[cmd.index("--out") + 1])
            out.write_bytes(signed_payload)
            return RunResult(0, "", "")
        if cmd[0] == "apksigner" and "verify" in cmd:
            return RunResult(
                0,
                "Signer #1 certificate DN: CN=MobARK Test Signer\n"
                "Signer #1 certificate SHA-256 digest: "
                "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899\n",
                "",
            )
        return RunResult(0, "", "")

    monkeypatch.setattr(rebuild, "run_tool", fake_run)
    monkeypatch.setattr(rebuild, "_keytool_binary", lambda: "keytool")
    monkeypatch.setattr(rebuild, "_zipalign_binary", lambda: "zipalign")
    monkeypatch.setattr(rebuild, "_apksigner_binary", lambda: "apksigner")
    # The keystore lifecycle is covered by its own tests - the pipeline
    # tests stub it out so the fake keytool never has to materialize a JKS.
    monkeypatch.setattr(
        rebuild,
        "ensure_keystore",
        lambda: (tmp_path / "mobark-test.jks", "test-pass"),
    )
    return signed_payload


def test_build_apk_full_pipeline_stages_and_naming(monkeypatch, tmp_path):
    root = _decoded_tree(tmp_path, monkeypatch)
    _fake_pipeline_tools(monkeypatch, tmp_path)
    stages = []
    artifact = rebuild.build_apk(
        _Scan(), [_edit(7, "smali/com/foo/AuthManager.smali", "patched\n")],
        build_id=3, on_stage=stages.append,
    )
    assert stages == ["applying", "rebuilding", "zipping", "signing"]
    # the -resigned-test- label is in the filename (decision 9)
    assert artifact.name == "app-resigned-test-3.apk"
    assert artifact.path.is_file()
    assert len(artifact.sha256) == 64
    assert artifact.cert_sha256 == "aabbccddeeff00112233445566778899" \
        "aabbccddeeff00112233445566778899"
    # intermediates cleaned; only the signed artifact remains
    remaining = {p.name for p in rebuild.artifact_dir(7).iterdir()}
    assert remaining == {"app-resigned-test-3.apk"}
    # edits applied on the fresh COPY; the pristine baseline never mutates
    work = rebuild.build_dir(7, 3)
    assert (work / "smali/com/foo/AuthManager.smali").read_text() == "patched\n"
    assert (root / "smali/com/foo/AuthManager.smali").read_text() != "patched\n"


def test_build_apk_zero_edits_builds_pristine(monkeypatch, tmp_path):
    _decoded_tree(tmp_path, monkeypatch)
    _fake_pipeline_tools(monkeypatch, tmp_path)
    artifact = rebuild.build_apk(_Scan(), [], build_id=4)
    assert artifact.name == "app-resigned-test-4.apk"


def test_build_apk_apktool_b_failure_fails_loudly(monkeypatch, tmp_path):
    """The awkward-APK rebuild contract (Phase E): a decoded tree apktool
    cannot assemble back - e.g. an edit that introduced invalid smali -
    fails at the 'rebuilding' stage with the specific stderr reason, wrapped
    into the pipeline's stage-tagged RebuildError (an ApktoolError must
    never escape build_apk untagged). No artifact survives a failed build."""
    _decoded_tree(tmp_path, monkeypatch)
    # The test fails at the apktool b stage - no zipalign/apksigner/keystore
    # fakes are needed (they are never reached).

    def boom(tree_dir, out_apk, timeout=None):
        out_apk.parent.mkdir(parents=True, exist_ok=True)
        raise apktool.ApktoolError(
            "apktool b exited 1: invalid smali at smali/com/foo/AuthManager.smali"
        )

    monkeypatch.setattr(apktool, "build", boom)
    with pytest.raises(RebuildError) as exc:
        rebuild.build_apk(_Scan(), [], build_id=8)
    assert exc.value.stage == "rebuilding"
    assert "invalid smali" in str(exc.value)
    # no artifact AND no intermediates survive a failed build
    assert list(rebuild.artifact_dir(7).iterdir()) == []


def test_build_apk_zipalign_failure_fails_loudly(monkeypatch, tmp_path):
    _decoded_tree(tmp_path, monkeypatch)

    def fake_apktool_build(tree_dir, out_apk, timeout=None):
        out_apk.parent.mkdir(parents=True, exist_ok=True)
        out_apk.write_bytes(b"PK")

    monkeypatch.setattr(apktool, "build", fake_apktool_build)
    monkeypatch.setattr(rebuild, "_zipalign_binary", lambda: "zipalign")
    monkeypatch.setattr(
        rebuild,
        "run_tool",
        lambda cmd, timeout: RunResult(1, "", "zipalign: input not aligned"),
    )
    with pytest.raises(RebuildError) as exc:
        rebuild.build_apk(_Scan(), [], build_id=5)
    assert exc.value.stage == "zipping"
    assert "zipalign exited 1" in str(exc.value)
    assert "input not aligned" in str(exc.value)


def test_build_apk_verify_gate_failure_fails_loudly(monkeypatch, tmp_path):
    _decoded_tree(tmp_path, monkeypatch)

    def fake_apktool_build(tree_dir, out_apk, timeout=None):
        out_apk.parent.mkdir(parents=True, exist_ok=True)
        out_apk.write_bytes(b"PK")

    monkeypatch.setattr(apktool, "build", fake_apktool_build)

    def fake_run(cmd, timeout):
        if cmd[0] == "zipalign":
            Path(cmd[-1]).write_bytes(b"PK")
            return RunResult(0, "", "")
        # the sign step succeeds but the VERIFY GATE fails - decision 9:
        # a signed-but-invalid APK is a failed build, never a silent break
        return RunResult(1, "", "Verifies")

    monkeypatch.setattr(rebuild, "run_tool", fake_run)
    monkeypatch.setattr(rebuild, "_keytool_binary", lambda: "keytool")
    monkeypatch.setattr(rebuild, "_zipalign_binary", lambda: "zipalign")
    monkeypatch.setattr(rebuild, "_apksigner_binary", lambda: "apksigner")
    monkeypatch.setattr(
        rebuild,
        "ensure_keystore",
        lambda: (tmp_path / "mobark-test.jks", "test-pass"),
    )
    with pytest.raises(RebuildError) as exc:
        rebuild.build_apk(_Scan(), [], build_id=6)
    assert exc.value.stage == "signing"
    # intermediates cleaned on failure too
    assert list(rebuild.artifact_dir(7).iterdir()) == []


def test_build_apk_requires_decode_ready(monkeypatch, tmp_path):
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)  # no decode
    with pytest.raises(RebuildError, match="decode not ready"):
        rebuild.build_apk(_Scan(), [], build_id=1)


# ---- run_rebuild job ----------------------------------------------------------


def _build_row(db_factory, scan_id, status="queued"):
    from app.models import Build

    with db_factory() as session:
        build = Build(scan_id=scan_id, status=status, stage="queued")
        session.add(build)
        session.commit()
        return build.id


def test_job_rebuild_success_snapshots_and_links(
    monkeypatch, db_session_factory, tmp_path
):
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    monkeypatch.setattr("app.db.SessionLocal", db_session_factory)
    scan_id = _make_scan_and_edits(db_session_factory)
    _decoded_tree(tmp_path, monkeypatch, scan_id)  # ready under the same data_dir
    with db_session_factory() as session:
        e1 = _edit(scan_id, "smali/com/foo/AuthManager.smali")
        session.add(e1)
        session.commit()
        edit_id = e1.id
    build_id = _build_row(db_session_factory, scan_id)

    captured = {}

    def fake_build_apk(scan, edits, build_id, on_stage=None):
        captured["edits"] = [e.id for e in edits]
        return rebuild.BuildArtifact(
            name="app-resigned-test-1.apk",
            path=tmp_path / "app-resigned-test-1.apk",
            sha256="ab" * 32,
            cert_sha256="cd" * 32,
        )

    monkeypatch.setattr("app.analysis.rebuild.build_apk", fake_build_apk)
    result = jobs.run_rebuild(scan_id, build_id)
    assert result["ok"] is True
    assert captured["edits"] == [edit_id]
    from app.models import Build, Edit

    with db_session_factory() as session:
        build = session.get(Build, build_id)
        assert build.status == "done"
        assert build.stage == "done"
        assert build.artifact_name == "app-resigned-test-1.apk"
        assert build.artifact_sha256 == "ab" * 32
        assert build.edits_json == f"[{edit_id}]"
        assert session.get(Edit, edit_id).build_id == build_id


def test_job_rebuild_zero_edits_allowed(monkeypatch, db_session_factory, tmp_path):
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    monkeypatch.setattr("app.db.SessionLocal", db_session_factory)
    scan_id = _make_scan_and_edits(db_session_factory)
    _decoded_tree(tmp_path, monkeypatch, scan_id)
    build_id = _build_row(db_session_factory, scan_id)
    captured = {}

    def fake_build_apk(scan, edits, build_id, on_stage=None):
        captured["edits"] = [e.id for e in edits]
        return rebuild.BuildArtifact(
            name="app-resigned-test-2.apk",
            path=tmp_path / "app-resigned-test-2.apk",
            sha256="ab" * 32,
            cert_sha256="cd" * 32,
        )

    monkeypatch.setattr("app.analysis.rebuild.build_apk", fake_build_apk)
    assert jobs.run_rebuild(scan_id, build_id)["ok"] is True
    assert captured["edits"] == []


def test_job_rebuild_failure_records_stage_and_error(
    monkeypatch, db_session_factory, tmp_path
):
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    monkeypatch.setattr("app.db.SessionLocal", db_session_factory)
    scan_id = _make_scan_and_edits(db_session_factory)
    _decoded_tree(tmp_path, monkeypatch, scan_id)
    build_id = _build_row(db_session_factory, scan_id)

    def boom(scan, edits, build_id, on_stage=None):
        raise RebuildError("zipping", "zipalign exited 1: input not aligned")

    monkeypatch.setattr("app.analysis.rebuild.build_apk", boom)
    result = jobs.run_rebuild(scan_id, build_id)
    assert result["ok"] is False
    assert result["stage"] == "zipping"
    assert "input not aligned" in result["error"]
    from app.models import Build

    with db_session_factory() as session:
        build = session.get(Build, build_id)
        assert build.status == "failed"
        assert build.stage == "zipping"
        assert "input not aligned" in build.error
        assert build.finished_at is not None


def test_job_rebuild_ios_rejects(monkeypatch, db_session_factory, tmp_path):
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    monkeypatch.setattr("app.db.SessionLocal", db_session_factory)
    scan_id = _make_scan_and_edits(db_session_factory, platform="ios")
    _decoded_tree(tmp_path, monkeypatch, scan_id)
    build_id = _build_row(db_session_factory, scan_id)
    called = []

    def fake_build_apk(*a, **k):
        called.append(True)
        raise AssertionError("must not run")

    monkeypatch.setattr("app.analysis.rebuild.build_apk", fake_build_apk)
    result = jobs.run_rebuild(scan_id, build_id)
    assert result["ok"] is False
    assert "Android-only" in result["error"]
    assert called == []


def test_job_rebuild_decode_not_ready(monkeypatch, db_session_factory, tmp_path):
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    monkeypatch.setattr("app.db.SessionLocal", db_session_factory)
    scan_id = _make_scan_and_edits(db_session_factory)
    build_id = _build_row(db_session_factory, scan_id)  # no decode tree
    result = jobs.run_rebuild(scan_id, build_id)
    assert result["ok"] is False
    assert "decode not ready" in result["error"]
    from app.models import Build

    with db_session_factory() as session:
        assert session.get(Build, build_id).status == "failed"


def test_job_rebuild_unknown_build(monkeypatch, db_session_factory, tmp_path):
    monkeypatch.setattr("app.db.SessionLocal", db_session_factory)
    scan_id = _make_scan_and_edits(db_session_factory)
    result = jobs.run_rebuild(scan_id, 999999)
    assert result["ok"] is False
    assert "not found" in result["error"]


def test_job_rebuild_awkward_edit_fails_loudly_at_stage(
    monkeypatch, db_session_factory, tmp_path
):
    """Phase E awkward-APK case end-to-end at the job level: an applied edit
    apktool cannot assemble fails the BUILD ROW at the 'rebuilding' stage
    with the specific reason and NO artifact (decision 8 - never a silently
    broken APK; the user sees the exact apktool complaint to fix).

    Note: this is the build-row CONTRACT test - the RebuildError('rebuilding')
    wrap itself is pinned by test_build_apk_apktool_b_failure_fails_loudly
    (the job's generic exception handler would also surface build.stage here
    because on_stage set it to 'rebuilding' before the call)."""
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    monkeypatch.setattr("app.db.SessionLocal", db_session_factory)
    scan_id = _make_scan_and_edits(db_session_factory)
    _decoded_tree(tmp_path, monkeypatch, scan_id)
    build_id = _build_row(db_session_factory, scan_id)

    def boom(tree_dir, out_apk, timeout=None):
        raise apktool.ApktoolError(
            "apktool b exited 1: invalid smali at smali/com/foo/AuthManager.smali"
        )

    monkeypatch.setattr(apktool, "build", boom)
    result = jobs.run_rebuild(scan_id, build_id)
    assert result["ok"] is False
    assert result["stage"] == "rebuilding"
    assert "invalid smali" in result["error"]
    from app.models import Build

    with db_session_factory() as session:
        build = session.get(Build, build_id)
        assert build.status == "failed"
        assert build.stage == "rebuilding"
        assert "invalid smali" in build.error
        assert build.artifact_name is None  # no artifact written


def test_job_rebuild_snapshot_isolates_mid_build_edits(
    monkeypatch, db_session_factory, tmp_path
):
    """Phase E race coverage: an edit APPLIED while the build runs must never
    reach the build tree - the job snapshots its edit set at start
    (edits_json) and the snapshot is the immutable record for the build, so a
    human can keep reviewing/applying while the worker builds."""
    monkeypatch.setattr(apktool.settings, "data_dir", tmp_path)
    monkeypatch.setattr("app.db.SessionLocal", db_session_factory)
    scan_id = _make_scan_and_edits(db_session_factory)
    _decoded_tree(tmp_path, monkeypatch, scan_id)
    with db_session_factory() as session:
        e1 = _edit(scan_id, "smali/com/foo/AuthManager.smali")
        session.add(e1)
        session.commit()
        edit_id = e1.id
    build_id = _build_row(db_session_factory, scan_id)
    captured = {}

    def fake_build_apk(scan, edits, build_id, on_stage=None):
        captured["edits"] = [e.id for e in edits]
        # Simulate the human accepting a proposal mid-build: this edit lands
        # AFTER the job snapshotted its set and must not be in the build.
        with db_session_factory() as session:
            late = _edit(
                scan_id, "smali/com/foo/AuthManager.smali", "late-change\n"
            )
            session.add(late)
            session.commit()
            captured["late_id"] = late.id
        return rebuild.BuildArtifact(
            name="app-resigned-test-1.apk",
            path=tmp_path / "app-resigned-test-1.apk",
            sha256="ab" * 32,
            cert_sha256="cd" * 32,
        )

    monkeypatch.setattr("app.analysis.rebuild.build_apk", fake_build_apk)
    assert jobs.run_rebuild(scan_id, build_id)["ok"] is True
    assert captured["edits"] == [edit_id]  # the snapshot, not the late edit
    from app.models import Build, Edit

    with db_session_factory() as session:
        build = session.get(Build, build_id)
        assert build.edits_json == f"[{edit_id}]"
        late = session.get(Edit, captured["late_id"])
        assert late.status == "applied"  # the human change is persisted...
        assert late.build_id is None  # ...but NOT consumed by this build


def test_job_rebuild_scan_mismatch_is_refused(monkeypatch, db_session_factory, tmp_path):
    """A build row enqueued against the wrong scan id is refused before any
    pipeline work - it must never build one scan under another's build row."""
    monkeypatch.setattr("app.db.SessionLocal", db_session_factory)
    scan_a = _make_scan_and_edits(db_session_factory)
    scan_b = _make_scan_and_edits(db_session_factory)
    build_id = _build_row(db_session_factory, scan_a)
    called = []

    def fake_build_apk(*a, **k):
        called.append(True)
        raise AssertionError("must not run")

    monkeypatch.setattr("app.analysis.rebuild.build_apk", fake_build_apk)
    result = jobs.run_rebuild(scan_b, build_id)
    assert result["ok"] is False
    assert "belongs to scan" in result["error"]
    assert called == []
    from app.models import Build

    with db_session_factory() as session:
        assert session.get(Build, build_id).status == "queued"  # untouched
