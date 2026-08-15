"""M9 Phase B - POST /scans/{id}/report/regenerate API tests.

The regenerate endpoint reuses the M5 insight functions (summarize_scan /
explain_finding) with their cache-first semantics and the M5 error contract
(404 · 409 · 400 no-model on the AI route only · 502 upstream). The insight
functions are monkeypatched - no LLM. The report BODY assembly (Phase A)
never 400s on a missing model; only this AI route does.
"""
from __future__ import annotations

from app.models import Finding, Scan
from tests.conftest import authed_user_id


def _scan(db_session_factory, *, status="done"):
    with db_session_factory() as session:
        scan = Scan(
            filename="app.apk", platform="android", status=status,
            user_id=authed_user_id(db_session_factory),
        )
        session.add(scan)
        session.commit()
        return scan.id


def _scan_with_findings(db_session_factory, *, with_explanation=False):
    with db_session_factory() as session:
        scan = Scan(
            filename="app.apk", platform="android", status="done",
            user_id=authed_user_id(db_session_factory),
        )
        session.add(scan)
        session.commit()
        for i, sev in enumerate(("high", "warning", "info")):
            session.add(
                Finding(
                    scan_id=scan.id,
                    tool="semgrep",
                    title=f"{sev}-{i}",
                    severity=sev,
                    explanation=("cached" if with_explanation else None),
                )
            )
        session.commit()
        return scan.id


def _fake_summary(summary_text="Fresh executive summary."):
    def fake(scan, findings, security_score, regenerate=False):
        assert regenerate is True  # the report Regenerate is explicit
        # Mirror the real summarize_scan contract: it mutates the scan row
        # in place and the route commits (the M5 insights.py pattern).
        scan.ai_summary = summary_text
        return {
            "summary": summary_text,
            "cached": False,
            "model": "qwen2.5:7b",
            "generated_at": "2026-08-12T00:00:00Z",
        }

    return fake


def test_regenerate_refreshes_summary_and_persists(
    client, db_session_factory, monkeypatch
):
    scan_id = _scan_with_findings(db_session_factory)
    from app.api.routes import scans as routes

    monkeypatch.setattr(routes.insights, "summarize_scan", _fake_summary())

    def fake_explain(scan_id_, finding, regenerate=False):
        finding.explanation = "fresh"
        return {"explanation": "fresh", "cached": False}

    monkeypatch.setattr(routes.insights, "explain_finding", fake_explain)
    r = client.post(f"/api/v1/scans/{scan_id}/report/regenerate")
    assert r.status_code == 200
    body = r.json()
    assert body["summary"] == "Fresh executive summary."
    assert body["model"] == "qwen2.5:7b"
    assert body["explanations_generated"] == 3  # none cached -> all three filled
    # persisted to scans.ai_summary for the next assembled report
    with db_session_factory() as session:
        assert session.get(Scan, scan_id).ai_summary == "Fresh executive summary."


def test_regenerate_keeps_existing_explanations(
    client, db_session_factory, monkeypatch
):
    """Open item 4 default: missing explanations are filled, cached ones are
    NEVER re-spent (each is a separate LLM call)."""
    scan_id = _scan_with_findings(db_session_factory, with_explanation=True)
    from app.api.routes import scans as routes

    monkeypatch.setattr(routes.insights, "summarize_scan", _fake_summary())
    captured = {"explain_calls": 0}

    def fake_explain(scan_id_, finding, regenerate=False):
        assert finding.explanation  # only called for findings WITHOUT one
        captured["explain_calls"] += 1
        return {"explanation": "fresh", "cached": False}

    monkeypatch.setattr(routes.insights, "explain_finding", fake_explain)
    r = client.post(f"/api/v1/scans/{scan_id}/report/regenerate")
    assert r.status_code == 200
    assert r.json()["explanations_generated"] == 0  # all were cached already
    assert captured["explain_calls"] == 0


def test_regenerate_explanations_false_skips_explain_pass(
    client, db_session_factory, monkeypatch
):
    """explanations=false regenerates ONLY the summary - no per-finding LLM
    calls at all (the caller can defer the explanation cost)."""
    scan_id = _scan_with_findings(db_session_factory)
    from app.api.routes import scans as routes

    monkeypatch.setattr(routes.insights, "summarize_scan", _fake_summary())
    captured = {"explain_calls": 0}

    def fake_explain(scan_id_, finding, regenerate=False):
        captured["explain_calls"] += 1
        return {"explanation": "x", "cached": False}

    monkeypatch.setattr(routes.insights, "explain_finding", fake_explain)
    r = client.post(
        f"/api/v1/scans/{scan_id}/report/regenerate", params={"explanations": "false"}
    )
    assert r.status_code == 200
    assert r.json()["explanations_generated"] == 0
    assert captured["explain_calls"] == 0


def test_regenerate_excludes_suppressed_findings(
    client, db_session_factory, monkeypatch
):
    """Suppressed false positives never reach the summary OR the explanation
    pass (the risk/summary/agent convention)."""
    scan_id = _scan_with_findings(db_session_factory)
    with db_session_factory() as session:
        first = session.query(Finding).filter(Finding.scan_id == scan_id).first()
        first.suppressed = True
        session.commit()
    from app.api.routes import scans as routes

    monkeypatch.setattr(routes.insights, "summarize_scan", _fake_summary())

    def fake_explain(scan_id_, finding, regenerate=False):
        finding.explanation = "fresh"
        return {"explanation": "fresh", "cached": False}

    monkeypatch.setattr(routes.insights, "explain_finding", fake_explain)
    r = client.post(f"/api/v1/scans/{scan_id}/report/regenerate")
    assert r.status_code == 200
    assert r.json()["explanations_generated"] == 2  # only the 2 non-suppressed


def test_regenerate_error_contract(client, db_session_factory, monkeypatch):
    from app.agent import insights as insights_mod
    from app.api.routes import scans as routes
    from app.model.selection import NoModelConfigured

    scan_id = _scan_with_findings(db_session_factory)

    # 400 no chat model - only THIS AI route (the body assembly never 400s)
    def no_model(*args, **kwargs):
        raise NoModelConfigured("no chat model configured - pick a backend + model in Settings")

    monkeypatch.setattr(routes.insights, "summarize_scan", no_model)
    r = client.post(f"/api/v1/scans/{scan_id}/report/regenerate")
    assert r.status_code == 400
    assert "no chat model" in r.json()["detail"]

    # 502 upstream LLM failure
    def upstream_down(*args, **kwargs):
        raise insights_mod.InsightError("LLM call failed: connection refused")

    monkeypatch.setattr(routes.insights, "summarize_scan", upstream_down)
    r = client.post(f"/api/v1/scans/{scan_id}/report/regenerate")
    assert r.status_code == 502


def test_regenerate_guards(client, db_session_factory):
    # 404 unknown scan
    assert client.post("/api/v1/scans/999999/report/regenerate").status_code == 404
    # 409 not analyzed
    scan_id = _scan(db_session_factory, status="queued")
    r = client.post(f"/api/v1/scans/{scan_id}/report/regenerate")
    assert r.status_code == 409
    assert "not analyzed" in r.json()["detail"]
