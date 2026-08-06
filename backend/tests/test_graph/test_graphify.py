"""graphify wrapper tests — subprocess stubbed, no real graphify calls."""
from __future__ import annotations

import json

import pytest

from app.graph import graphify
from app.graph.graphify import GraphifyError, GraphStats, build, query, search_labels


def _write_graph(tmp_path, nodes=(), links=()) -> object:
    p = tmp_path / "graph.json"
    p.write_text(
        json.dumps(
            {
                "nodes": [
                    {"id": nid, "label": label, "source_file": f, "source_location": loc}
                    for nid, label, f, loc in nodes
                ],
                "links": [
                    {
                        "source": s,
                        "target": t,
                        "relation": "calls",
                        "source_file": f,
                        "source_location": loc,
                    }
                    for s, t, f, loc in links
                ],
                "directed": False,
            }
        )
    )
    return p


def _stub_run(monkeypatch, *, returncode=0, stdout="", stderr="", exc=None):
    captured = {}
    # Pin the resolved command so tests don't depend on the host's PATH.
    monkeypatch.setattr(graphify.settings, "graphify_cmd", "graphify")

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["cwd"] = kwargs.get("cwd")
        if exc:
            raise exc
        return type("P", (), {"returncode": returncode, "stdout": stdout, "stderr": stderr})()

    monkeypatch.setattr(graphify.subprocess, "run", fake_run)
    return captured


# ---- counting ------------------------------------------------------------------


def test_count_graph_nodes_and_links(tmp_path):
    p = _write_graph(
        tmp_path,
        nodes=[
            ("n1", "ClassA", "a.java", "L1"),
            ("n2", "ClassB", "b.java", "L2"),
            ("n3", "ClassC", "c.java", "L3"),
        ],
        links=[("n1", "n2", "a.java", "L4"), ("n2", "n3", "b.java", "L5")],
    )
    assert graphify.count_graph(p) == (3, 2)


def test_count_graph_empty(tmp_path):
    p = _write_graph(tmp_path)
    assert graphify.count_graph(p) == (0, 0)


# ---- build ----------------------------------------------------------------------


def test_build_runs_update_with_cwd_and_parses_stats(monkeypatch, tmp_path):
    captured = _stub_run(monkeypatch, stdout="updating...")
    # Build layout: data/graphs/<scan_id>/graphify-out/graph.json (cwd = target).
    out_dir = tmp_path / "5" / "graphify-out"
    out_dir.mkdir(parents=True)
    (out_dir / "graph.json").write_text(
        json.dumps({"nodes": [{"id": "a"}] * 10, "links": [{"source": "a", "target": "b"}] * 20})
    )
    stats = build(5, tmp_path / "decompiled", tmp_path)
    assert isinstance(stats, GraphStats)
    assert stats.nodes == 10
    assert stats.edges == 20
    assert stats.graph_path == out_dir / "graph.json"
    assert captured["cmd"][0] == "graphify"
    assert captured["cmd"][1:3] == ["update", str(tmp_path / "decompiled")]
    assert "--no-cluster" in captured["cmd"]
    assert captured["cwd"] == tmp_path / "5"


def test_build_raises_on_nonzero_rc(monkeypatch, tmp_path):
    _stub_run(monkeypatch, returncode=1, stderr="boom")
    with pytest.raises(GraphifyError, match="boom"):
        build(5, tmp_path / "decompiled", tmp_path)


def test_build_raises_when_graph_json_missing(monkeypatch, tmp_path):
    _stub_run(monkeypatch, returncode=0, stdout="ok")
    with pytest.raises(GraphifyError):
        build(5, tmp_path / "decompiled", tmp_path)


def test_build_raises_on_timeout(monkeypatch, tmp_path):
    import subprocess as sp

    _stub_run(monkeypatch, exc=sp.TimeoutExpired("graphify", 60))
    with pytest.raises(GraphifyError, match="timed out"):
        build(5, tmp_path / "decompiled", tmp_path)


# ---- label search / query fallback -----------------------------------------------


def test_search_labels_matches_identifier_tokens(tmp_path):
    p = _write_graph(
        tmp_path,
        nodes=[
            ("id_ssl1", "NetworkSecurityConfig", "res/xml/netsec.xml", "L3"),
            ("id_ssl2", "MyWebViewClient", "com/app/MyWebViewClient.java", "L7"),
            ("id_other", "LoginActivity", "com/app/LoginActivity.java", "L1"),
        ],
    )
    hits = search_labels(p, "where is certificate pinning configured")
    # "certificate"/"pinning" match nothing; "configured" isn't a node label.
    assert hits == []

    hits = search_labels(p, "NetworkSecurityConfig")
    assert len(hits) == 1
    assert hits[0]["id"] == "id_ssl1"
    assert hits[0]["file"] == "res/xml/netsec.xml"
    assert hits[0]["line"] == 3


def test_search_labels_respects_limit_and_stopwords(tmp_path):
    p = _write_graph(
        tmp_path,
        nodes=[(f"id_{i}", f"Handler{i}", f"h{i}.java", f"L{i}") for i in range(10)],
    )
    assert len(search_labels(p, "show me all the Handler nodes", limit=3)) == 3


def test_query_falls_back_to_label_search_when_cli_finds_nothing(monkeypatch, tmp_path):
    p = _write_graph(
        tmp_path,
        nodes=[("id_wv", "MyWebViewClient", "com/app/MyWebViewClient.java", "L7")],
    )
    _stub_run(monkeypatch, returncode=0, stdout="No matching nodes found.")
    result = query(p, "where is the webview client")
    assert result["found"] is True
    assert result["via"] == "label-search"
    assert result["nodes"][0]["label"] == "MyWebViewClient"
    assert result["nodes"][0]["line"] == 7


def test_query_returns_false_when_nothing_matches(monkeypatch, tmp_path):
    p = _write_graph(tmp_path, nodes=[("id_x", "Foo", "f.java", "L1")])
    _stub_run(monkeypatch, returncode=0, stdout="No matching nodes found.")
    result = query(p, "certificate pinning")
    assert result["found"] is False
    assert result["via"] == "none"


def test_path_explain_affected_pass_graph_flag(monkeypatch, tmp_path):
    p = _write_graph(tmp_path)
    captured = _stub_run(monkeypatch, stdout="PATH: a -> b")
    out = graphify.path_between(p, "a", "b")
    assert out == "PATH: a -> b"
    assert captured["cmd"] == ["graphify", "path", "a", "b", "--graph", str(p)]
    assert "--graph" in captured["cmd"]
