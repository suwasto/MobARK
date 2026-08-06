"""Scan API — M0 list/get + M4 chat/graph + M5 dashboard surface.

M5 Phase A endpoints (see docs/progress/M5.md):
- ``POST /scans``                 multipart upload -> Scan(queued) + RQ job
- ``GET  /scans/{id}/findings``   severity-desc, ?severity / ?limit / ?offset
- ``POST /scans/{id}/summary``    cached AI overview (scans.ai_summary)
- ``POST /scans/{id}/findings/{fid}/explain``  cached AI explanation (FR-8)
- ``GET  /scans/{id}/files``      bounded decompiler tree
- ``GET  /scans/{id}/files/content?path=``     traversal-guarded content read

LLM error contract (shared by chat/explain/summary): 400 no chat model
configured (NoModelConfigured) · 502 upstream LLM failure (InsightError) ·
504 agent-loop deadline exceeded (AgentTimeout) · 409 scan not analyzed.
"""
from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from sqlalchemy import case, select
from sqlalchemy.orm import Session

from app.agent import insights
from app.agent.chat import AgentTimeout, ChatNotConfigured, answer_question
from app.analysis import tree
from app.analysis.risk import SEVERITY_ORDER, compute_risk_score
from app.config import settings
from app.db import get_db
from app.graph import graphify
from app.model.selection import NoModelConfigured
from app.models import Finding, Scan
from app.schemas import (
    ChatRequest,
    ChatResponse,
    Citation,
    ExplainResponse,
    FileContentResponse,
    FileTreeResponse,
    FindingRead,
    ScanGraphState,
    ScanRead,
    SummaryResponse,
)
from app.workers.jobs import enqueue_scan

router = APIRouter(prefix="/scans", tags=["scans"])

DbSession = Annotated[Session, Depends(get_db)]

_ALLOWED_ARTIFACTS = {".apk", ".ipa"}
_SEVERITY_RANK = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}
# Default covers the flagship test APK (InsecureBankv2: 523 findings); the
# frontend can page with ?offset for larger scans.
_FINDINGS_DEFAULT_LIMIT = 1000
_FINDINGS_MAX_LIMIT = 1000
ArtifactFile = Annotated[UploadFile, File()]


class _UploadTooLarge(Exception):
    """Internal sentinel: streamed upload exceeded MASA_MAX_UPLOAD_MB."""


def _get_scan_or_404(db: Session, scan_id: int) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return scan


def _require_analyzed(scan: Scan) -> None:
    if scan.status != "done":
        raise HTTPException(
            status_code=409,
            detail=f"scan {scan.id} is not analyzed yet (status={scan.status})",
        )


@router.get("", response_model=list[ScanRead])
def list_scans(db: DbSession) -> list[Scan]:
    """List scans, newest first."""
    return list(db.scalars(select(Scan).order_by(Scan.created_at.desc())).all())


@router.post("", response_model=ScanRead, status_code=201)
async def create_scan(db: DbSession, file: ArtifactFile) -> Scan:
    """Upload an APK/IPA: validate, save, create a queued scan, enqueue the job.

    Error semantics: 400 unsupported extension or not-a-zip (the scan row is
    rolled back so nothing phantom appears in the queue) · 413 over
    ``MASA_MAX_UPLOAD_MB`` · 500 the RQ enqueue failed (Redis down) — the
    saved artifact stays but the scan is marked ``failed`` with the reason
    rather than sitting in ``queued`` forever.
    """
    filename = Path(file.filename or "").name  # strip any path components
    suffix = Path(filename).suffix.lower()
    if not filename or suffix not in _ALLOWED_ARTIFACTS:
        raise HTTPException(
            status_code=400,
            detail=f"unsupported artifact type {suffix!r} (expected .apk or .ipa)",
        )

    scan = Scan(filename=filename, status="queued")
    db.add(scan)
    db.commit()
    scan_id = scan.id

    upload_dir = settings.data_dir / "uploads" / str(scan_id)
    upload_dir.mkdir(parents=True, exist_ok=True)
    stored = upload_dir / filename
    max_bytes = settings.max_upload_mb * 1024 * 1024
    size = 0
    try:
        try:
            with stored.open("wb") as out:
                while chunk := await file.read(1024 * 1024):
                    size += len(chunk)
                    if size > max_bytes:
                        raise _UploadTooLarge()
                    out.write(chunk)
        except _UploadTooLarge:
            stored.unlink(missing_ok=True)
            db.delete(scan)
            db.commit()
            raise HTTPException(
                status_code=413,
                detail=f"upload exceeds the {settings.max_upload_mb} MB limit",
            ) from None
        if not zipfile.is_zipfile(stored):
            stored.unlink(missing_ok=True)
            db.delete(scan)
            db.commit()
            raise HTTPException(
                status_code=400,
                detail="uploaded file is not a valid ZIP archive (APK/IPA)",
            )
        scan.storage_path = str(upload_dir)
        db.commit()
    finally:
        await file.close()

    try:
        enqueue_scan(scan_id)
    except Exception as exc:  # noqa: BLE001 - Redis down; never leave a phantom queued row
        scan.status = "failed"
        scan.stage = "failed"
        scan.error = f"analysis job enqueue failed: {exc}"
        db.commit()
        raise HTTPException(
            status_code=500,
            detail=f"scan saved but the analysis job could not be enqueued: {exc}",
        ) from exc
    return scan


@router.get("/{scan_id}", response_model=ScanRead)
def get_scan(scan_id: int, db: DbSession) -> Scan:
    scan = _get_scan_or_404(db, scan_id)
    # M5: legacy scans (analyzed before risk scoring existed) get a backfill.
    if scan.risk_score is None and scan.status == "done":
        findings = list(
            db.scalars(select(Finding).where(Finding.scan_id == scan_id)).all()
        )
        scan.risk_score = compute_risk_score(findings)
        db.commit()
    return scan


@router.get("/{scan_id}/findings", response_model=list[FindingRead])
def list_findings(
    scan_id: int,
    db: DbSession,
    severity: str | None = Query(default=None),
    limit: int = Query(default=_FINDINGS_DEFAULT_LIMIT, ge=1, le=_FINDINGS_MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> list[Finding]:
    """All findings for a scan: severity-desc (critical first) then id."""
    _get_scan_or_404(db, scan_id)
    if severity is not None and severity not in _SEVERITY_RANK:
        raise HTTPException(
            status_code=400,
            detail=f"unknown severity {severity!r} "
            f"(expected one of {', '.join(SEVERITY_ORDER)})",
        )
    stmt = select(Finding).where(Finding.scan_id == scan_id)
    if severity is not None:
        stmt = stmt.where(Finding.severity == severity)
    stmt = stmt.order_by(
        case(_SEVERITY_RANK, value=Finding.severity), Finding.id
    ).limit(limit).offset(offset)
    return list(db.scalars(stmt).all())


@router.post("/{scan_id}/summary", response_model=SummaryResponse)
def scan_summary(scan_id: int, db: DbSession) -> SummaryResponse:
    """AI overview summary (severity counts + top findings), cached on the row.

    A cached summary returns immediately with ``cached: true`` — no LLM call.
    """
    scan = _get_scan_or_404(db, scan_id)
    _require_analyzed(scan)
    findings = list(
        db.scalars(select(Finding).where(Finding.scan_id == scan_id)).all()
    )
    risk = (
        scan.risk_score
        if scan.risk_score is not None
        else compute_risk_score(findings)
    )
    try:
        result = insights.summarize_scan(scan, findings, risk)
    except NoModelConfigured as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except insights.InsightError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    db.commit()
    return SummaryResponse(**result)


@router.post("/{scan_id}/findings/{finding_id}/explain", response_model=ExplainResponse)
def explain_finding(scan_id: int, finding_id: int, db: DbSession) -> ExplainResponse:
    """FR-8: plain-language explanation + fix guidance for one finding.

    Grounded in the finding's detail + surrounding source lines; cached in
    ``findings.explanation`` so repeat requests are free.
    """
    scan = _get_scan_or_404(db, scan_id)
    finding = db.get(Finding, finding_id)
    if finding is None or finding.scan_id != scan_id:
        raise HTTPException(status_code=404, detail="finding not found")
    _require_analyzed(scan)
    try:
        result = insights.explain_finding(scan_id, finding)
    except NoModelConfigured as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except insights.InsightError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    db.commit()
    return ExplainResponse(**result)


@router.get("/{scan_id}/files", response_model=FileTreeResponse)
def scan_file_tree(scan_id: int, db: DbSession) -> FileTreeResponse:
    """Bounded decompiler tree — Android: sources + resources; iOS: *.app."""
    scan = _get_scan_or_404(db, scan_id)
    _require_analyzed(scan)
    return FileTreeResponse(
        platform=scan.platform or "unknown",
        roots=tree.list_tree(scan),
    )


@router.get("/{scan_id}/files/content", response_model=FileContentResponse)
def file_content(
    scan_id: int, db: DbSession, path: str = Query(min_length=1)
) -> FileContentResponse:
    """Read one file as ``<root>/<relative>`` for the code viewer.

    Traversal-guarded; binary files refused; plists decoded to JSON text.
    400 bad root / escaping / binary · 404 missing file.
    """
    scan = _get_scan_or_404(db, scan_id)
    _require_analyzed(scan)
    try:
        return tree.read_tree_file(scan, path)
    except tree.TreeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/{scan_id}/graph", response_model=ScanGraphState)
def scan_graph_state(scan_id: int, db: DbSession) -> ScanGraphState:
    """M4 Layer 3: per-scan Graphify graph state (filesystem-derived).

    No DB columns — "built" means ``graphs/<scan_id>/graphify-out/graph.json``
    exists; node/edge counts are streamed from the JSON. Android only.
    """
    scan = _get_scan_or_404(db, scan_id)
    if scan.platform != "android":
        return ScanGraphState(
            built=False,
            reason="graph is Android-only — iOS has no decompiled source tree",
        )
    graph_path = graphify.graph_path_for(scan_id)
    if not graph_path.is_file():
        return ScanGraphState(
            built=False,
            reason="graph not built yet — the graph build job is chained after analysis "
            "for Android scans",
        )
    nodes, edges = graphify.count_graph(graph_path)
    return ScanGraphState(
        built=True,
        nodes=nodes,
        edges=edges,
        graph_path=f"graphs/{scan_id}/graphify-out/graph.json",
    )


@router.post("/{scan_id}/chat", response_model=ChatResponse)
def chat_scan(scan_id: int, payload: ChatRequest, db: DbSession) -> ChatResponse:
    """M4: grounded agent answer over Layers 1-3 (findings context + tools).

    Zero embeddings — the RAG/vector path was removed from v1. 404 unknown
    scan · 409 scan not analyzed · 400 no chat model configured · 504 the
    agent loop exceeded its overall deadline (hung LLM call, hard-capped by
    ``payload.timeout_seconds`` / ``settings.chat_timeout_seconds``). The
    chat model comes from the M3 backend store — no new config surface.
    """
    scan = _get_scan_or_404(db, scan_id)
    if scan.status != "done":
        raise HTTPException(
            status_code=409,
            detail=f"scan {scan_id} is not analyzed yet (status={scan.status}) — "
            "run the scan job first",
        )
    try:
        result = answer_question(scan_id, payload.question, timeout=payload.timeout_seconds)
    except ChatNotConfigured as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except AgentTimeout as exc:
        raise HTTPException(status_code=504, detail=str(exc)) from exc
    return ChatResponse(
        answer=result.answer,
        citations=[
            Citation(file=c.file, line=c.line, snippet=c.snippet) for c in result.citations
        ],
        sources=result.sources,
    )
