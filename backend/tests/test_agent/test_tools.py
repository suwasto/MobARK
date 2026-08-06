"""Layer 2/3 tool tests — real temp trees, no network, no LLM, no graphify
subprocess (graph wrappers stub the graphify module).
"""
from __future__ import annotations

import json
import plistlib

import pytest

from app.agent import tools
from app.models import Scan


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


def _android_tree(tmp_path, scan_id, files: dict[str, str]) -> None:
    root = tmp_path / "work" / str(scan_id) / "decompiled" / "sources"
    root.mkdir(parents=True)
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)


def _binary_file(tmp_path, scan_id, rel: str, data: bytes) -> None:
    root = tmp_path / "work" / str(scan_id) / "decompiled" / "sources"
    root.mkdir(parents=True, exist_ok=True)
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)


# ---- search_code --------------------------------------------------------------


def test_search_code_finds_matches(env):
    scan_id, tmp_path, _ = env
    _android_tree(
        tmp_path,
        scan_id,
        {
            "com/app/Login.java": "package com.app;\npublic class Login {\n  void check() {}\n}\n",
            "res/xml/netsec.xml": "<network-security-config/>\n",
        },
    )
    hits = tools.search_code(scan_id, "Login")
    assert len(hits) == 1
    assert hits[0]["file"] == "com/app/Login.java"
    assert hits[0]["line"] == 2  # `public class Login` is line 2


def test_search_code_respects_glob(env):
    scan_id, tmp_path, _ = env
    _android_tree(
        tmp_path,
        scan_id,
        {
            "a.java": "config\n",
            "res/netsec.xml": "config\n",
        },
    )
    hits = tools.search_code(scan_id, "config", glob="*.java")
    assert len(hits) == 1
    assert hits[0]["file"] == "a.java"


def test_search_code_invalid_regex_is_tool_error(env):
    scan_id, tmp_path, _ = env
    _android_tree(tmp_path, scan_id, {"a.java": "x\n"})
    with pytest.raises(tools.ToolError, match="invalid regex"):
        tools.search_code(scan_id, "(")


def test_search_code_skips_binary_files(env):
    scan_id, tmp_path, _ = env
    _android_tree(tmp_path, scan_id, {"a.txt": "Login here\n"})
    _binary_file(tmp_path, scan_id, "blob.bin", b"\x00\x01\x02Login\x00\xff")
    hits = tools.search_code(scan_id, "Login")
    assert len(hits) == 1
    assert hits[0]["file"] == "a.txt"


def test_search_code_no_tree_is_tool_error(env):
    scan_id, tmp_path, _ = env
    with pytest.raises(tools.ToolError, match="no decompiled"):
        tools.search_code(scan_id, "x")


# ---- read_file ----------------------------------------------------------------


def test_read_file_whole_and_range(env):
    scan_id, tmp_path, _ = env
    text = "\n".join(f"line {i}" for i in range(1, 11))
    _android_tree(tmp_path, scan_id, {"a.txt": text})
    assert tools.read_file(scan_id, "a.txt") == text
    assert tools.read_file(scan_id, "a.txt", line_start=2, line_end=3) == "line 2\nline 3"


def test_read_file_traversal_guard(env):
    scan_id, tmp_path, _ = env
    _android_tree(tmp_path, scan_id, {"a.txt": "x"})
    with pytest.raises(tools.ToolError, match="escapes"):
        tools.read_file(scan_id, "../../../etc/passwd")


def test_read_file_missing_is_tool_error(env):
    scan_id, tmp_path, _ = env
    _android_tree(tmp_path, scan_id, {"a.txt": "x"})
    with pytest.raises(tools.ToolError, match="not a file"):
        tools.read_file(scan_id, "nope.txt")


def test_read_file_refuses_binary(env):
    scan_id, tmp_path, _ = env
    _binary_file(tmp_path, scan_id, "blob.bin", b"\x00\x01\x02")
    with pytest.raises(tools.ToolError, match="binary file"):
        tools.read_file(scan_id, "blob.bin")


def test_read_file_decodes_binary_plist(env):
    scan_id, tmp_path, _ = env
    _binary_file(
        tmp_path,
        scan_id,
        "Info.plist",
        plistlib.dumps(
            {"NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True}},
            fmt=plistlib.FMT_BINARY,
        ),
    )
    out = tools.read_file(scan_id, "Info.plist")
    assert "NSAllowsArbitraryLoads" in out
    assert "True" in out or "true" in out


# ---- iOS tree resolution ------------------------------------------------------


def test_ios_tree_root_resolves_payload_app(monkeypatch, db_session_factory, tmp_path):
    monkeypatch.setattr("app.config.settings.data_dir", tmp_path)
    monkeypatch.setattr("app.db.SessionLocal", db_session_factory)
    with db_session_factory() as session:
        scan = Scan(filename="app.ipa", platform="ios", status="done")
        session.add(scan)
        session.commit()
        scan_id = scan.id
    app_root = tmp_path / "work" / str(scan_id) / "bundle" / "Payload" / "Test.app"
    app_root.mkdir(parents=True)
    (app_root / "Info.plist").write_text("<?xml version='1.0'?><plist/>")
    hits = tools.search_code(scan_id, "plist")
    assert hits and hits[0]["file"] == "Info.plist"


# ---- Layer 3 graph tools (graphify stubbed) ----------------------------------


def _write_graph(tmp_path, scan_id):
    p = tmp_path / "graphs" / str(scan_id) / "graphify-out" / "graph.json"
    p.parent.mkdir(parents=True)
    p.write_text(json.dumps({"nodes": [{"id": "a"}], "links": []}))
    return p


def test_graph_tools_wrap_graphify(env, monkeypatch):
    scan_id, tmp_path, _ = env
    _write_graph(tmp_path, scan_id)
    from app.graph import graphify

    monkeypatch.setattr(
        graphify,
        "query",
        lambda p, q, budget=1500: {"found": True, "text": "X", "nodes": [], "via": "t"},
    )
    monkeypatch.setattr(graphify, "path_between", lambda p, a, b: "PATH: a -> b")
    monkeypatch.setattr(graphify, "explain", lambda p, n: "EXPLAIN: n")

    assert tools.graph_query(scan_id, "where is X")["found"] is True
    assert tools.graph_path_between(scan_id, "a", "b") == "PATH: a -> b"
    assert tools.graph_explain_node(scan_id, "n") == "EXPLAIN: n"


def test_graph_tool_no_graph_is_tool_error(env):
    scan_id, tmp_path, _ = env
    with pytest.raises(tools.ToolError, match="no code graph"):
        tools.graph_query(scan_id, "where")


# ---- execute_tool dispatch ----------------------------------------------------


def test_execute_tool_dispatch_and_error_paths(env):
    scan_id, tmp_path, _ = env
    _android_tree(tmp_path, scan_id, {"com/app/Login.java": "public class Login {}\n"})

    out = json.loads(tools.execute_tool(scan_id, "search_code", {"pattern": "Login"}))
    assert out[0]["file"] == "com/app/Login.java"

    out = json.loads(tools.execute_tool(scan_id, "search_code", {"pattern": "("}))
    assert "error" in out

    out = json.loads(tools.execute_tool(scan_id, "not_a_tool", {}))
    assert "unknown tool" in out["error"]

    out = json.loads(tools.execute_tool(scan_id, "read_file", {"path": "../../etc/passwd"}))
    assert "error" in out
