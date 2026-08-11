"""M8 Phase B: edits service + API, apktool tree roots, effective content,
Java⇄Smali mapping. No Redis, no network; subprocess-free (the decoded tree
is materialized on disk directly).
"""
from __future__ import annotations

import app.config
from app.analysis import apktool, editable
from app.models import Scan

ORIGINAL_SMALI = (
    ".class public Lcom/foo/AuthManager;\n"
    "\n"
    ".method public constructor <init>()V\n"
    "    return-void\n"
    ".end method\n"
)
# a modification (return-void -> const), so the unified diff has a -/+ pair
PATCHED_SMALI = (
    ".class public Lcom/foo/AuthManager;\n"
    "\n"
    ".method public constructor <init>()V\n"
    "    const/4 v0, 0x0\n"
    ".end method\n"
)


# ---- fixtures ---------------------------------------------------------------


def _make_decoded_scan(db_session_factory, tmp_path, monkeypatch, *, platform="android"):
    """Android scan with the full tree: jadx sources + decoded apktool roots
    (smali, smali_classes2, res, AndroidManifest.xml)."""
    import app.db

    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    # tree.py opens its own session for the effective-content overlay (same
    # pattern as the iOS analysis docs) - point it at the scratch DB.
    monkeypatch.setattr(app.db, "SessionLocal", db_session_factory)
    with db_session_factory() as session:
        scan = Scan(
            filename="app.apk",
            platform=platform,
            status="done",
            storage_path="/unused/uploads",
        )
        session.add(scan)
        session.commit()
        scan_id = scan.id

    work = tmp_path / "work" / str(scan_id)
    (work / "decompiled" / "sources" / "com" / "foo").mkdir(parents=True)
    (work / "decompiled" / "sources" / "com" / "foo" / "AuthManager.java").write_text(
        "package com.foo;\npublic class AuthManager {}\n"
    )
    (work / "decompiled" / "resources").mkdir(parents=True)

    root = apktool.decoded_root(scan_id)
    root.mkdir(parents=True)
    (root / "AndroidManifest.xml").write_text("<manifest/>\n")
    smali = root / "smali" / "com" / "foo"
    smali.mkdir(parents=True)
    (smali / "AuthManager.smali").write_text(ORIGINAL_SMALI)
    (root / "smali_classes2" / "com" / "foo").mkdir(parents=True)
    (root / "smali_classes2" / "com" / "foo" / "Extra.smali").write_text(
        ".class public Lcom/foo/Extra;\n"
    )
    (root / "res" / "values").mkdir(parents=True)
    (root / "res" / "values" / "strings.xml").write_text(
        '<resources><string name="app_name">MASA</string></resources>\n'
    )
    return scan_id


def _post_edit(client, scan_id, file_path, content):
    return client.post(
        f"/api/v1/scans/{scan_id}/edits",
        json={"file_path": file_path, "content": content},
    )


# ---- edits service: diff + stacking + transitions ---------------------------


def test_manual_edit_creates_applied_with_diff(
    client, db_session_factory, monkeypatch, tmp_path
):
    scan_id = _make_decoded_scan(db_session_factory, tmp_path, monkeypatch)
    r = _post_edit(client, scan_id, "smali/com/foo/AuthManager.smali", PATCHED_SMALI)
    assert r.status_code == 201
    body = r.json()
    assert body["source"] == "manual"
    assert body["status"] == "applied"
    assert body["applied_at"] is not None
    assert body["file_path"] == "smali/com/foo/AuthManager.smali"

    diff = client.get(f"/api/v1/scans/{scan_id}/edits/{body['id']}/diff").json()
    assert "-    return-void" in diff["diff"]
    assert "+    const/4 v0, 0x0" in diff["diff"]
    assert diff["file_path"] == "smali/com/foo/AuthManager.smali"


def test_edit_original_baselines_on_effective_content(
    client, db_session_factory, monkeypatch, tmp_path
):
    """Same-file stacking: edit 2's original is edit 1's new_content, so the
    diff is computed against the effective content, not the on-disk baseline."""
    scan_id = _make_decoded_scan(db_session_factory, tmp_path, monkeypatch)
    edit1 = _post_edit(client, scan_id, "smali/com/foo/AuthManager.smali", PATCHED_SMALI).json()
    # edit 2 adds a second line on top of edit 1's content
    stacked = PATCHED_SMALI + "    nop\n"
    edit2 = _post_edit(client, scan_id, "smali/com/foo/AuthManager.smali", stacked).json()
    assert edit2["id"] != edit1["id"]

    with db_session_factory() as session:
        from app.models import Edit

        e2 = session.get(Edit, edit2["id"])
        assert e2.original_content == PATCHED_SMALI  # edit 1's new_content
        assert e2.new_content == stacked
        # the diff is ONLY the nop addition - the const line is context, never
        # a removal (i.e. edit2 was not re-diffed against the on-disk baseline)
        assert "+    nop" in e2.unified_diff
        assert "-    const/4 v0, 0x0" not in e2.unified_diff


def test_edit_content_unchanged_rejected(client, db_session_factory, monkeypatch, tmp_path):
    scan_id = _make_decoded_scan(db_session_factory, tmp_path, monkeypatch)
    r = _post_edit(client, scan_id, "smali/com/foo/AuthManager.smali", ORIGINAL_SMALI)
    assert r.status_code == 400
    assert "unchanged" in r.json()["detail"]


def test_edit_manifest_and_res_editable(client, db_session_factory, monkeypatch, tmp_path):
    scan_id = _make_decoded_scan(db_session_factory, tmp_path, monkeypatch)
    r = _post_edit(client, scan_id, "AndroidManifest.xml", "<manifest><application/></manifest>\n")
    assert r.status_code == 201
    assert r.json()["file_path"] == "AndroidManifest.xml"
    r = _post_edit(
        client,
        scan_id,
        "res/values/strings.xml",
        '<resources><string name="app_name">EDITED</string></resources>\n',
    )
    assert r.status_code == 201


def test_edit_read_only_path_400(client, db_session_factory, monkeypatch, tmp_path):
    scan_id = _make_decoded_scan(db_session_factory, tmp_path, monkeypatch)
    for bad in (
        "sources/com/foo/AuthManager.java",
        "sources/com/foo/AuthManager.smali",  # jadx-fallback smali stays read-only
        "original/META-INF/MANIFEST.MF",
    ):
        r = _post_edit(client, scan_id, bad, "whatever")
        assert r.status_code == 400
        assert "not editable" in r.json()["detail"]


def test_edit_oversized_413(client, db_session_factory, monkeypatch, tmp_path):
    scan_id = _make_decoded_scan(db_session_factory, tmp_path, monkeypatch)
    big = "x" * (editable.MAX_EDIT_CHARS + 1)
    r = _post_edit(client, scan_id, "smali/com/foo/AuthManager.smali", big)
    assert r.status_code == 413


def test_edit_missing_file_404(client, db_session_factory, monkeypatch, tmp_path):
    scan_id = _make_decoded_scan(db_session_factory, tmp_path, monkeypatch)
    r = _post_edit(client, scan_id, "smali/com/foo/Missing.smali", "content")
    assert r.status_code == 404


def test_edit_requires_decode_ready(client, db_session_factory, monkeypatch, tmp_path):
    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    with db_session_factory() as session:
        scan = Scan(filename="app.apk", platform="android", status="done")
        session.add(scan)
        session.commit()
        scan_id = scan.id
    (tmp_path / "work" / str(scan_id) / "decompiled" / "sources").mkdir(parents=True)
    r = _post_edit(client, scan_id, "smali/com/foo/A.smali", "content")
    assert r.status_code == 409
    assert "decode not ready" in r.json()["detail"]


def test_edit_ios_409(client, db_session_factory, monkeypatch, tmp_path):
    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    with db_session_factory() as session:
        scan = Scan(filename="app.ipa", platform="ios", status="done")
        session.add(scan)
        session.commit()
        scan_id = scan.id
    r = _post_edit(client, scan_id, "AndroidManifest.xml", "x")
    assert r.status_code == 409
    assert "Android-only" in r.json()["detail"]


def test_edit_not_analyzed_409(client, db_session_factory, monkeypatch, tmp_path):
    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    with db_session_factory() as session:
        scan = Scan(filename="app.apk", platform="android", status="queued")
        session.add(scan)
        session.commit()
        scan_id = scan.id
    r = _post_edit(client, scan_id, "smali/com/foo/A.smali", "x")
    assert r.status_code == 409


# ---- apply / reject / revert (human-owned transitions) ----------------------


def test_apply_reject_revert_transitions(client, db_session_factory, monkeypatch, tmp_path):
    scan_id = _make_decoded_scan(db_session_factory, tmp_path, monkeypatch)
    # manual edits are applied already - reject/revert must 400 on wrong state
    edit = _post_edit(client, scan_id, "smali/com/foo/AuthManager.smali", PATCHED_SMALI).json()
    r = client.post(f"/api/v1/scans/{scan_id}/edits/{edit['id']}/reject")
    assert r.status_code == 400
    r = client.post(f"/api/v1/scans/{scan_id}/edits/{edit['id']}/apply")
    assert r.status_code == 400  # already applied

    # revert pops the effective content back to the baseline
    r = client.post(f"/api/v1/scans/{scan_id}/edits/{edit['id']}/revert")
    assert r.status_code == 200
    assert r.json()["status"] == "reverted"
    assert client.get(f"/api/v1/scans/{scan_id}/edits").json()[0]["status"] == "reverted"

    # an applied-then-reverted edit is no longer overlaid: viewer = baseline
    content = client.get(
        f"/api/v1/scans/{scan_id}/files/content",
        params={"path": "smali/com/foo/AuthManager.smali"},
    ).json()["content"]
    assert "const/4 v0, 0x0" not in content
    assert content == ORIGINAL_SMALI


def test_revert_pops_to_prior_applied_edit(
    client, db_session_factory, monkeypatch, tmp_path
):
    scan_id = _make_decoded_scan(db_session_factory, tmp_path, monkeypatch)
    e1 = _post_edit(client, scan_id, "smali/com/foo/AuthManager.smali", PATCHED_SMALI).json()
    stacked = PATCHED_SMALI + "    nop\n"
    e2 = _post_edit(client, scan_id, "smali/com/foo/AuthManager.smali", stacked).json()

    assert "nop" in client.get(
        f"/api/v1/scans/{scan_id}/files/content",
        params={"path": "smali/com/foo/AuthManager.smali"},
    ).json()["content"]

    # reverting the newest pops to edit 1's content
    client.post(f"/api/v1/scans/{scan_id}/edits/{e2['id']}/revert")
    content = client.get(
        f"/api/v1/scans/{scan_id}/files/content",
        params={"path": "smali/com/foo/AuthManager.smali"},
    ).json()["content"]
    assert "nop" not in content
    assert content == PATCHED_SMALI

    # reverting edit 1 too lands back on the pristine baseline
    client.post(f"/api/v1/scans/{scan_id}/edits/{e1['id']}/revert")
    content = client.get(
        f"/api/v1/scans/{scan_id}/files/content",
        params={"path": "smali/com/foo/AuthManager.smali"},
    ).json()["content"]
    assert content == ORIGINAL_SMALI


def test_edit_unknown_edit_404(client, db_session_factory, monkeypatch, tmp_path):
    scan_id = _make_decoded_scan(db_session_factory, tmp_path, monkeypatch)
    for action in ("apply", "reject", "revert"):
        assert (
            client.post(f"/api/v1/scans/{scan_id}/edits/999999/{action}").status_code
            == 404
        )
    assert client.get(f"/api/v1/scans/{scan_id}/edits/999999/diff").status_code == 404


# ---- effective content overlay (viewer reads edited content) ----------------


def test_viewer_shows_applied_edit_content(client, db_session_factory, monkeypatch, tmp_path):
    scan_id = _make_decoded_scan(db_session_factory, tmp_path, monkeypatch)
    _post_edit(client, scan_id, "smali/com/foo/AuthManager.smali", PATCHED_SMALI)
    content = client.get(
        f"/api/v1/scans/{scan_id}/files/content",
        params={"path": "smali/com/foo/AuthManager.smali"},
    ).json()
    assert "const/4 v0, 0x0" in content["content"]
    # the on-disk tree is untouched - the edit lives only in the DB
    assert (
        apktool.decoded_root(scan_id) / "smali" / "com" / "foo" / "AuthManager.smali"
    ).read_text() == ORIGINAL_SMALI


# ---- tree roots -------------------------------------------------------------


def test_tree_gains_apktool_roots_once_decoded(
    client, db_session_factory, monkeypatch, tmp_path
):
    scan_id = _make_decoded_scan(db_session_factory, tmp_path, monkeypatch)
    r = client.get(f"/api/v1/scans/{scan_id}/files")
    roots = [root["name"] for root in r.json()["roots"]]
    assert roots == [
        "sources",
        "resources",
        "smali",
        "smali_classes2",
        "res",
        "AndroidManifest.xml",
    ]
    manifest_root = next(x for x in r.json()["roots"] if x["name"] == "AndroidManifest.xml")
    assert [n["name"] for n in manifest_root["tree"]] == ["AndroidManifest.xml"]


def test_tree_has_no_apktool_roots_before_decode(
    client, db_session_factory, monkeypatch, tmp_path
):
    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    with db_session_factory() as session:
        scan = Scan(filename="app.apk", platform="android", status="done")
        session.add(scan)
        session.commit()
        scan_id = scan.id
    (tmp_path / "work" / str(scan_id) / "decompiled" / "sources").mkdir(parents=True)
    roots = [root["name"] for root in client.get(f"/api/v1/scans/{scan_id}/files").json()["roots"]]
    assert "smali" not in roots
    assert "AndroidManifest.xml" not in roots


def test_manifest_content_read(client, db_session_factory, monkeypatch, tmp_path):
    scan_id = _make_decoded_scan(db_session_factory, tmp_path, monkeypatch)
    r = client.get(
        f"/api/v1/scans/{scan_id}/files/content",
        params={"path": "AndroidManifest.xml/AndroidManifest.xml"},
    )
    assert r.status_code == 200
    assert r.json()["language"] == "xml"
    assert r.json()["content"] == "<manifest/>\n"


# ---- Java<->Smali sibling mapping -------------------------------------------


def test_java_to_smali_sibling(client, db_session_factory, monkeypatch, tmp_path):
    scan_id = _make_decoded_scan(db_session_factory, tmp_path, monkeypatch)
    r = client.get(
        f"/api/v1/scans/{scan_id}/files/smali-sibling",
        params={"path": "sources/com/foo/AuthManager.java"},
    )
    assert r.json() == {
        "path": "sources/com/foo/AuthManager.java",
        "sibling": "smali/com/foo/AuthManager.smali",
    }


def test_smali_to_java_sibling(client, db_session_factory, monkeypatch, tmp_path):
    scan_id = _make_decoded_scan(db_session_factory, tmp_path, monkeypatch)
    r = client.get(
        f"/api/v1/scans/{scan_id}/files/smali-sibling",
        params={"path": "smali/com/foo/AuthManager.smali"},
    )
    assert r.json()["sibling"] == "sources/com/foo/AuthManager.java"


def test_smali_sibling_no_counterpart(client, db_session_factory, monkeypatch, tmp_path):
    scan_id = _make_decoded_scan(db_session_factory, tmp_path, monkeypatch)
    # res file has no Java/Smali counterpart
    r = client.get(
        f"/api/v1/scans/{scan_id}/files/smali-sibling",
        params={"path": "res/values/strings.xml"},
    )
    assert r.json()["sibling"] is None
    # smali with no jadx java
    r = client.get(
        f"/api/v1/scans/{scan_id}/files/smali-sibling",
        params={"path": "smali_classes2/com/foo/Extra.smali"},
    )
    assert r.json()["sibling"] is None
    # java with no smali
    r = client.get(
        f"/api/v1/scans/{scan_id}/files/smali-sibling",
        params={"path": "sources/com/foo/Nope.java"},
    )
    assert r.json()["sibling"] is None


def test_smali_sibling_multidex_first_found(
    client, db_session_factory, monkeypatch, tmp_path
):
    """A class present in both smali and smali_classesN resolves to the
    first-found (smali) - apktool's classes.dex order."""
    scan_id = _make_decoded_scan(db_session_factory, tmp_path, monkeypatch)
    extra = apktool.decoded_root(scan_id) / "smali_classes2" / "com" / "foo"
    (extra / "AuthManager.smali").write_text(ORIGINAL_SMALI)
    r = client.get(
        f"/api/v1/scans/{scan_id}/files/smali-sibling",
        params={"path": "sources/com/foo/AuthManager.java"},
    )
    assert r.json()["sibling"] == "smali/com/foo/AuthManager.smali"


def test_smali_sibling_requires_analyzed(client, db_session_factory, monkeypatch, tmp_path):
    monkeypatch.setattr(app.config.settings, "data_dir", tmp_path)
    with db_session_factory() as session:
        scan = Scan(filename="app.apk", platform="android", status="queued")
        session.add(scan)
        session.commit()
        scan_id = scan.id
    r = client.get(
        f"/api/v1/scans/{scan_id}/files/smali-sibling",
        params={"path": "sources/com/foo/A.java"},
    )
    assert r.status_code == 409
