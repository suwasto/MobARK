"""M8 Phase B: the can_edit predicate + tree<->edit path mapping matrix."""
from __future__ import annotations

import pytest

from app.analysis import editable


def _scan(platform="android"):
    # class bodies don't close over function locals - set it explicitly
    class _S:
        pass

    _S.platform = platform
    return _S()


# ---- can_edit matrix --------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "AndroidManifest.xml",
        "smali/com/foo/AuthManager.smali",
        "smali_classes2/com/foo/Extra.smali",
        "smali_classes10/com/foo/Deep.smali",
        "res/values/strings.xml",
        "res/layout/activity_main.xml",
    ],
)
def test_can_edit_editable_paths(path):
    assert editable.can_edit(_scan(), path) is True


@pytest.mark.parametrize(
    "path",
    [
        "sources/com/foo/AuthManager.java",
        "sources/com/foo/AuthManager.smali",  # jadx-fallback smali: read-only
        "original/META-INF/MANIFEST.MF",
        "unknown/com/foo/A.smali",
        "apktool.yml",
        "",
        "smali",  # bare dir names are not files
        "res",
    ],
)
def test_can_edit_read_only_paths(path):
    assert editable.can_edit(_scan(), path) is False


def test_can_edit_ios_never():
    for path in ("smali/com/foo/A.smali", "res/values/strings.xml", "AndroidManifest.xml"):
        assert editable.can_edit(_scan("ios"), path) is False


def test_can_edit_none_scan():
    assert editable.can_edit(None, "smali/com/foo/A.smali") is False


# ---- path mapping -----------------------------------------------------------


def test_edit_path_from_tree_path():
    assert (
        editable.edit_path_from_tree_path("smali", "com/foo/A.smali")
        == "smali/com/foo/A.smali"
    )
    assert (
        editable.edit_path_from_tree_path("smali_classes2", "com/foo/B.smali")
        == "smali_classes2/com/foo/B.smali"
    )
    assert (
        editable.edit_path_from_tree_path("res", "values/strings.xml")
        == "res/values/strings.xml"
    )
    # the manifest synthetic root strips the duplicated root segment
    assert (
        editable.edit_path_from_tree_path("AndroidManifest.xml", "AndroidManifest.xml")
        == "AndroidManifest.xml"
    )


def test_tree_path_from_edit_path():
    assert (
        editable.tree_path_from_edit_path("smali/com/foo/A.smali")
        == "smali/com/foo/A.smali"
    )
    assert (
        editable.tree_path_from_edit_path("res/values/strings.xml")
        == "res/values/strings.xml"
    )
    assert (
        editable.tree_path_from_edit_path("AndroidManifest.xml")
        == "AndroidManifest.xml/AndroidManifest.xml"
    )
