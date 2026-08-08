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


def test_build_runs_update_and_relocates_input_dir_output(monkeypatch, tmp_path):
    """Regression (Aug 8): graphify 0.9.32 writes into the INPUT dir
    (``<decompiled>/graphify-out/``), not the cwd — build() must move it
    into the per-scan graphs dir so the decompiler tree stays clean and
    graph_path_for resolves. Verified empirically in the container."""
    captured = _stub_run(monkeypatch, stdout="updating...")
    decompiled = tmp_path / "decompiled"
    in_out = decompiled / "graphify-out"
    in_out.mkdir(parents=True)
    (in_out / "graph.json").write_text(
        json.dumps({"nodes": [{"id": "a"}] * 10, "links": [{"source": "a", "target": "b"}] * 20})
    )
    stats = build(5, decompiled, tmp_path)
    assert isinstance(stats, GraphStats)
    assert stats.nodes == 10
    assert stats.edges == 20
    assert stats.graph_path == tmp_path / "5" / "graphify-out" / "graph.json"
    assert stats.graph_path.is_file()
    # The input-side copy is gone — relocated, not copied.
    assert not (decompiled / "graphify-out").exists()
    assert captured["cmd"][0] == "graphify"
    assert captured["cmd"][1:3] == ["update", str(decompiled)]
    assert "--no-cluster" in captured["cmd"]
    assert captured["cwd"] == tmp_path / "5"


def test_build_keeps_existing_target_output(monkeypatch, tmp_path):
    """A re-run where the per-scan graph.json already exists (previous build)
    keeps it even if the input dir was re-polluted — target wins."""
    _stub_run(monkeypatch, stdout="updating...")
    decompiled = tmp_path / "decompiled"
    in_out = decompiled / "graphify-out"
    in_out.mkdir(parents=True)
    (in_out / "graph.json").write_text(
        json.dumps({"nodes": [{"id": "stale"}], "links": []})
    )
    out_dir = tmp_path / "5" / "graphify-out"
    out_dir.mkdir(parents=True)
    (out_dir / "graph.json").write_text(
        json.dumps({"nodes": [{"id": "good"}] * 3, "links": [{"source": "a", "target": "b"}] * 4})
    )
    stats = build(5, decompiled, tmp_path)
    assert stats.nodes == 3
    assert stats.edges == 4


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


# ---- Code maps explorer (search / node detail / hubs) ---------------------------


def _write_explorer_graph(tmp_path, nodes=(), links=()):
    p = tmp_path / "graph.json"
    p.write_text(
        json.dumps(
            {
                "nodes": [
                    {
                        "id": nid,
                        "label": label,
                        "file_type": ftype,
                        "source_file": f,
                        "source_location": loc,
                    }
                    for nid, label, ftype, f, loc in nodes
                ],
                "links": [
                    {"source": s, "target": t, "relation": rel} for s, t, rel in links
                ],
            }
        )
    )
    return p


def test_explorer_search_ranks_label_matches(tmp_path):
    p = _write_explorer_graph(
        tmp_path,
        nodes=[
            ("n1", "LoginActivity", "class", "com/a.java", "L10"),
            ("n2", "MyLoginHelper", "function", "com/b.java", "L5"),
            ("n3", "WebViewClient", "class", "com/c.java", "L1"),
        ],
    )
    rows, total = graphify.search(p, "login")
    assert total == 2
    # label-prefix (LoginActivity) ranks above label-substring (MyLoginHelper)
    assert [r["label"] for r in rows] == ["LoginActivity", "MyLoginHelper"]
    assert rows[0]["file"] == "com/a.java"
    assert rows[0]["line"] == 10
    assert rows[0]["file_type"] == "class"


def test_explorer_search_limit_total_and_stopwords(tmp_path):
    p = _write_explorer_graph(
        tmp_path,
        nodes=[(f"id_{i}", f"Handler{i}", "class", f"h{i}.java", f"L{i}") for i in range(10)],
    )
    rows, total = graphify.search(p, "show me all the Handler nodes", limit=3)
    assert total == 10
    assert len(rows) == 3


def test_explorer_search_empty_query_returns_nothing(tmp_path):
    p = _write_explorer_graph(tmp_path, nodes=[("n1", "Foo", "class", "f.java", "L1")])
    assert graphify.search(p, "  ") == ([], 0)


def test_explorer_node_detail_neighbors_and_directions(tmp_path):
    p = _write_explorer_graph(
        tmp_path,
        nodes=[
            ("a", "ClassA", "class", "a.java", "L1"),
            ("b", "ClassB", "class", "b.java", "L2"),
            ("c", "ClassC", "class", "c.java", "L3"),
            ("d", "ClassD", "class", "d.java", "L4"),
        ],
        links=[("a", "b", "calls"), ("b", "c", "calls"), ("d", "b", "imports")],
    )
    detail = graphify.node_detail(p, "b")
    assert detail is not None
    assert detail["node"]["id"] == "b"
    assert detail["degree"] == 3
    out = [n for n in detail["neighbors"] if n["direction"] == "out"]
    inn = [n for n in detail["neighbors"] if n["direction"] == "in"]
    assert [n["node"]["id"] for n in out] == ["c"]
    assert [n["node"]["id"] for n in inn] == ["a", "d"]
    assert out[0]["relation"] == "calls"
    assert inn[0]["relation"] == "calls"
    assert inn[1]["relation"] == "imports"


def test_explorer_node_detail_unknown_returns_none(tmp_path):
    p = _write_explorer_graph(tmp_path, nodes=[("a", "ClassA", "class", "a.java", "L1")])
    assert graphify.node_detail(p, "nope") is None


def test_explorer_hubs_ranks_by_degree(tmp_path):
    p = _write_explorer_graph(
        tmp_path,
        nodes=[
            ("a", "ClassA", "class", "a.java", "L1"),
            ("b", "ClassB", "class", "b.java", "L2"),
            ("c", "ClassC", "class", "c.java", "L3"),
        ],
        links=[("a", "b", "calls"), ("b", "c", "calls")],
    )
    hubs = graphify.hubs(p, limit=2)
    assert [h["node"]["id"] for h in hubs] == ["b", "a"]
    assert hubs[0]["degree"] == 2


def test_explorer_index_persisted_next_to_graph(tmp_path):
    p = _write_explorer_graph(tmp_path, nodes=[("a", "ClassA", "class", "a.java", "L1")])
    data1 = graphify.explorer_data(p)
    # First access compacts into explorer.json for future processes.
    assert (tmp_path / "explorer.json").is_file()
    data2 = graphify.explorer_data(p)
    assert data1 == data2
