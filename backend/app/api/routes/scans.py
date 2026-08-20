"""Scan API - M0 list/get + M4 chat/graph + M5 dashboard surface.

M5 Phase A endpoints (see docs/progress/M5.md):
- ``POST /scans``                 multipart upload -> Scan(queued) + RQ job
- ``GET  /scans/{id}/findings``   severity-desc, ?severity / ?limit / ?offset
- ``POST /scans/{id}/summary``    cached AI overview (scans.ai_summary)
- ``POST /scans/{id}/findings/{fid}/explain``  cached AI explanation (FR-8)
- ``GET  /scans/{id}/files``      bounded decompiler tree
- ``GET  /scans/{id}/files/content?path=``     traversal-guarded content read

LLM error contract (shared by chat/explain/summary): 400 no chat model
configured (NoModelConfigured) · 502 upstream LLM failure (InsightError /
ChatUpstreamError) · 504 agent-loop deadline exceeded (AgentTimeout) ·
409 scan not analyzed (or the user interrupted the chat via the Stop
button - ChatInterrupted).
"""
from __future__ import annotations

import json
import queue
import re
import tempfile
import threading
import zipfile
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, Response, StreamingResponse
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session
from starlette.background import BackgroundTask

from app.agent import insights, sessions
from app.agent.chat import (
    AgentEvent,
    AgentTimeout,
    ChatInterrupted,
    ChatNotConfigured,
    ChatUpstreamError,
    answer_question,
    check_configured,
    request_cancel,
    task_completion_answer,
)
from app.analysis import (
    apktool,
    dependencies,
    edit_tasks,
    editable,
    edits,
    rebuild,
    report,
    report_pdf,
    smali_map,
    tree,
    web_sources,
)
from app.analysis.risk import SEVERITY_ORDER, compute_risk_score, security_from_risk
from app.api.deps import require_scan_access
from app.config import settings
from app.db import get_db
from app.graph import graphify
from app.model.selection import NoModelConfigured
from app.models import Build, ChatSession, Edit, Finding, Scan, utcnow
from app.request_ctx import current_master_key, current_user_id
from app.schemas import (
    BatchSuppressRequest,
    BatchSuppressResponse,
    BuildRead,
    ChatCompleteRequest,
    ChatMessageRead,
    ChatRequest,
    ChatResponse,
    ChatSessionRead,
    ChatSessionUpdate,
    Citation,
    DependenciesResponse,
    EditCreate,
    EditDiffResponse,
    EditRead,
    EditReviewResult,
    ExplainResponse,
    FileContentResponse,
    FileTreeResponse,
    FindingRead,
    GraphHubsResponse,
    GraphNodeDetail,
    GraphSearchResponse,
    ReportRegenerateResponse,
    ReportResponse,
    ScanGraphState,
    ScanRead,
    SmaliMappingResponse,
    SmaliSiblingResponse,
    SmaliStatusResponse,
    SummaryResponse,
    ToolRunRead,
    WebResearchUpdate,
)
from app.workers.jobs import (
    enqueue_apktool_decode,
    enqueue_rebuild,
    enqueue_scan,
)

router = APIRouter(prefix="/scans", tags=["scans"])

DbSession = Annotated[Session, Depends(get_db)]

_ALLOWED_ARTIFACTS = {".apk", ".ipa"}
_SEVERITY_RANK = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}
# Default covers the flagship test APK (InsecureBankv2: 523 findings); the
# frontend can page with ?offset for larger scans.
_FINDINGS_DEFAULT_LIMIT = 1000
_FINDINGS_MAX_LIMIT = 5000
ArtifactFile = Annotated[UploadFile, File()]


class _UploadTooLarge(Exception):
    """Internal sentinel: streamed upload exceeded MOBARK_MAX_UPLOAD_MB."""


def _get_scan_or_404(db: Session, scan_id: int) -> Scan:
    """404 for unknown OR foreign scans (M9.1 decision 6 - no existence
    leak). The caller resolves from ``request_ctx.current_user_id`` (set by
    the router-level ``get_current_user`` guard), so EVERY scan-keyed route
    is gated structurally - a route cannot forget to pass the user. Auth-off
    mode (user id None) keeps today's open behavior. ``deps.require_scan_
    access`` is the shared rule the isolation tests exercise explicitly.
    """
    return require_scan_access(db, scan_id, current_user_id.get())


def _require_analyzed(scan: Scan) -> None:
    if scan.status != "done":
        raise HTTPException(
            status_code=409,
            detail=f"scan {scan.id} is not analyzed yet (status={scan.status})",
        )


def _require_graph(scan: Scan) -> Path:
    """Android-only + built-graph guard shared by the Code maps endpoints.

    The graph build job is chained after analysis for Android scans, so a
    built graph implies a done scan; 409 carries the human-readable reason
    either way (same wording as ``scan_graph_state``).
    """
    if scan.platform != "android":
        raise HTTPException(
            status_code=409,
            detail="graph is Android-only - iOS has no decompiled source tree",
        )
    graph_path = graphify.graph_path_for(scan.id)
    if not graph_path.is_file():
        raise HTTPException(
            status_code=409,
            detail="graph not built yet - the graph build job is chained after "
            "analysis for Android scans",
        )
    return graph_path


def _sse_frame(event: str, data: dict) -> str:
    """One Server-Sent Events frame (``event`` + JSON ``data`` line)."""
    return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"


def _chat_payload(result) -> dict:
    """The canonical ChatResponse-shaped payload for a finished turn."""
    return {
        "answer": result.answer,
        "citations": [
            {"file": c.file, "line": c.line, "snippet": c.snippet}
            for c in result.citations
        ],
        "sources": result.sources,
        "tool_mode": result.tool_mode,
        "tools_used": result.tools_used,
        # M8 follow-up: reasoning/thinking tokens - the dock renders them in
        # the specialized thinking box (streamed live + kept on the answer).
        "thinking": result.thinking or "",
        "tool_runs": [
            {
                "id": r.id,
                "name": r.name,
                "args": r.args,
                "status": r.status,
                "duration_ms": r.duration_ms,
                "result_preview": r.result_preview,
                "error": r.error,
                "count": r.count,
            }
            for r in result.tool_runs
        ],
    }


def _recompute_risk(db: Session, scan: Scan) -> None:
    """Recompute + persist the scan's risk score from its current findings.

    Called after a suppress/unsuppress toggle so the posture reflects the
    non-suppressed set immediately (``compute_risk_score`` skips rows with
    ``suppressed=True``). The cached AI summary is invalidated too - it may
    cite a finding that was just suppressed/restored, and stale cache would
    mislead the Overview.
    """
    findings = list(
        db.scalars(select(Finding).where(Finding.scan_id == scan.id)).all()
    )
    scan.risk_score = compute_risk_score(findings)
    scan.ai_summary = None
    db.commit()


@router.get("", response_model=list[ScanRead])
def list_scans(db: DbSession) -> list[Scan]:
    """List scans, newest first - M9.1: the CALLER's scans only (auth-off
    mode lists everything, today's open behavior)."""
    stmt = select(Scan)
    if settings.auth_enabled:
        # Auth-on: NULL-owner (unclaimed legacy) scans never appear either.
        stmt = stmt.where(Scan.user_id == current_user_id.get())
    return list(db.scalars(stmt.order_by(Scan.created_at.desc())).all())


@router.post("", response_model=ScanRead, status_code=201)
async def create_scan(db: DbSession, file: ArtifactFile) -> Scan:
    """Upload an APK/IPA: validate, save, create a queued scan, enqueue the job.

    Error semantics: 400 unsupported extension or not-a-zip (the scan row is
    rolled back so nothing phantom appears in the queue) · 413 over
    ``MOBARK_MAX_UPLOAD_MB`` · 500 the RQ enqueue failed (Redis down) - the
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

    # M9.1 Phase C: the scan is owned by the caller (auth-off -> None,
    # the pre-M9.1 unowned row; an admin claim adopts those later).
    scan = Scan(filename=filename, status="queued", user_id=current_user_id.get())
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
    include_suppressed: bool = Query(default=False),
) -> list[Finding]:
    """All findings for a scan: severity-desc (high first) then id.

    Suppressed (false-positive) findings are hidden by default; pass
    ``include_suppressed=true`` to see them (the review toggle).
    """
    _get_scan_or_404(db, scan_id)
    if severity is not None and severity not in _SEVERITY_RANK:
        raise HTTPException(
            status_code=400,
            detail=f"unknown severity {severity!r} "
            f"(expected one of {', '.join(SEVERITY_ORDER)})",
        )
    stmt = select(Finding).where(Finding.scan_id == scan_id)
    if not include_suppressed:
        stmt = stmt.where(Finding.suppressed == False)  # noqa: E712 - SQLAlchemy boolean
    if severity is not None:
        stmt = stmt.where(Finding.severity == severity)
    stmt = stmt.order_by(
        case(_SEVERITY_RANK, value=Finding.severity), Finding.id
    ).limit(limit).offset(offset)
    return list(db.scalars(stmt).all())


@router.post("/{scan_id}/findings/{finding_id}/suppress", response_model=FindingRead)
def suppress_finding(scan_id: int, finding_id: int, db: DbSession) -> Finding:
    """Mark a finding as a suppressed false positive (excluded from risk /
    summary / agent context). The scan's risk score is recomputed."""
    scan = _get_scan_or_404(db, scan_id)
    finding = db.get(Finding, finding_id)
    if finding is None or finding.scan_id != scan_id:
        raise HTTPException(status_code=404, detail="finding not found")
    _require_analyzed(scan)
    if not finding.suppressed:
        finding.suppressed = True
        finding.suppressed_at = utcnow()
        db.commit()
        _recompute_risk(db, scan)
    return finding


@router.post("/{scan_id}/findings/{finding_id}/unsuppress", response_model=FindingRead)
def unsuppress_finding(scan_id: int, finding_id: int, db: DbSession) -> Finding:
    """Restore a suppressed finding (review toggle). Risk recomputed."""
    scan = _get_scan_or_404(db, scan_id)
    finding = db.get(Finding, finding_id)
    if finding is None or finding.scan_id != scan_id:
        raise HTTPException(status_code=404, detail="finding not found")
    _require_analyzed(scan)
    if finding.suppressed:
        finding.suppressed = False
        finding.suppressed_at = None
        db.commit()
        _recompute_risk(db, scan)
    return finding


# M5 follow-up (batch suppression): the MASTG rules emit ONE finding per
# occurrence, so a single check (e.g. "runs on an up-to-date OS version" -
# ``Build.VERSION.SDK_INT`` per call site) can surface as dozens of identical
# rows. These endpoints toggle every finding matching the payload's criteria
# (title group / severity band / category, AND-combined) in one call and
# recompute the risk score ONCE (the per-row toggles would recompute n
# times). Both are idempotent: a match that finds nothing left to toggle
# returns 0, not an error.
def _batch_findings_stmt(
    scan_id: int, payload: BatchSuppressRequest, suppressed: bool
):
    """The AND-composed finding match for a batch toggle - every provided
    criterion narrows the set (title group, severity band, category)."""
    stmt = select(Finding).where(
        Finding.scan_id == scan_id,
        Finding.suppressed == suppressed,  # noqa: E712 - SQLAlchemy boolean
    )
    if payload.title is not None:
        stmt = stmt.where(Finding.title == payload.title)
    if payload.category is not None:
        stmt = stmt.where(Finding.category == payload.category)
    if payload.severity is not None:
        stmt = stmt.where(Finding.severity == payload.severity)
    if payload.finding_ids:
        stmt = stmt.where(Finding.id.in_(payload.finding_ids))
    return stmt


def _require_batch_severity(payload: BatchSuppressRequest) -> None:
    """A ``severity`` criterion must be a known severity (mirror of
    ``list_findings`` - a typo would otherwise silently match zero rows and
    read as "nothing to toggle" instead of a bad request)."""
    if payload.severity is not None and payload.severity not in _SEVERITY_RANK:
        raise HTTPException(
            status_code=400,
            detail=f"unknown severity {payload.severity!r} "
            f"(expected one of {', '.join(SEVERITY_ORDER)})",
        )


@router.post("/{scan_id}/findings/suppress-batch", response_model=BatchSuppressResponse)
def suppress_findings_batch(
    scan_id: int, payload: BatchSuppressRequest, db: DbSession
) -> BatchSuppressResponse:
    """Suppress every non-suppressed finding matching the payload (title /
    severity / category). Risk recomputed once."""
    scan = _get_scan_or_404(db, scan_id)
    _require_analyzed(scan)
    _require_batch_severity(payload)
    rows = list(db.scalars(_batch_findings_stmt(scan_id, payload, False)).all())
    if rows:
        now = utcnow()
        for f in rows:
            f.suppressed = True
            f.suppressed_at = now
        _recompute_risk(db, scan)
    return BatchSuppressResponse(
        suppressed=len(rows), finding_ids=[f.id for f in rows]
    )


@router.post("/{scan_id}/findings/unsuppress-batch", response_model=BatchSuppressResponse)
def unsuppress_findings_batch(
    scan_id: int, payload: BatchSuppressRequest, db: DbSession
) -> BatchSuppressResponse:
    """Restore every suppressed finding matching the payload (title /
    severity / category) - the review side's mirror. Risk recomputed once."""
    scan = _get_scan_or_404(db, scan_id)
    _require_analyzed(scan)
    _require_batch_severity(payload)
    rows = list(db.scalars(_batch_findings_stmt(scan_id, payload, True)).all())
    if rows:
        for f in rows:
            f.suppressed = False
            f.suppressed_at = None
        _recompute_risk(db, scan)
    return BatchSuppressResponse(
        restored=len(rows), finding_ids=[f.id for f in rows]
    )


@router.post("/{scan_id}/summary", response_model=SummaryResponse)
def scan_summary(
    scan_id: int,
    db: DbSession,
    regenerate: bool = Query(default=False),
) -> SummaryResponse:
    """AI overview summary (severity counts + top findings), cached on the row.

    A cached summary returns immediately with ``cached: true`` - no LLM call.
    Pass ``regenerate=true`` to bypass the cache and re-run the model (the
    UI's Regenerate button; explicit user opt-in that spends cost).
    """
    scan = _get_scan_or_404(db, scan_id)
    _require_analyzed(scan)
    # Suppressed false positives stay out of the AI summary's counts/top list.
    findings = list(
        db.scalars(
            select(Finding)
            .where(Finding.scan_id == scan_id, Finding.suppressed == False)  # noqa: E712
        ).all()
    )
    risk = (
        scan.risk_score
        if scan.risk_score is not None
        else compute_risk_score(findings)
    )
    try:
        # The summary prompt speaks the public score: higher is better.
        result = insights.summarize_scan(
            scan, findings, security_from_risk(risk), regenerate=regenerate
        )
    except NoModelConfigured as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except insights.InsightError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    db.commit()
    return SummaryResponse(**result)


@router.post("/{scan_id}/report/regenerate", response_model=ReportRegenerateResponse)
def regenerate_report(
    scan_id: int,
    db: DbSession,
    explanations: bool = Query(default=True),
) -> ReportRegenerateResponse:
    """M9 Phase B: the report's explicit Regenerate opt-in (decision 10).

    Re-runs the report's AI surfaces with the M5 regenerate semantics -
    cache-first by default, and this POST is the explicit cost-spending
    opt-in that bypasses the cache:
    - the executive summary is ALWAYS regenerated (``summarize_scan`` with
      ``regenerate=True``, persisted to ``scans.ai_summary``);
    - per-finding explanations are filled in ONLY when missing
      (``explanations=true``, the default - open item 4: "summary +
      explicitly missing explanations"; existing cached explanations are
      never re-spent, since each is a separate LLM call).

    Deliberate all-or-nothing transaction: one commit at the end, so a
    mid-loop explanation failure (502) discards the freshly generated
    summary too - the M5 single-commit shape; retrying regenerates both
    (the summary is re-spent either way, and already-explained findings are
    skipped).

    The report body itself (Phase A assembly) never 400s on a missing model
    - only THIS AI route does, with the M5 error contract: 404 unknown scan
    · 409 not analyzed · 400 no chat model configured (NoModelConfigured) ·
    502 upstream LLM failure (InsightError).
    """
    scan = _get_scan_or_404(db, scan_id)
    _require_analyzed(scan)
    # Suppressed false positives stay out of the summary AND the explanation
    # pass (the risk/summary/agent convention).
    findings = list(
        db.scalars(
            select(Finding)
            .where(Finding.scan_id == scan_id, Finding.suppressed == False)  # noqa: E712
        ).all()
    )
    risk = (
        scan.risk_score
        if scan.risk_score is not None
        else compute_risk_score(findings)
    )
    try:
        result = insights.summarize_scan(
            scan, findings, security_from_risk(risk), regenerate=True
        )
        generated = 0
        if explanations:
            for finding in findings:
                if not finding.explanation:
                    insights.explain_finding(scan_id, finding)
                    generated += 1
    except NoModelConfigured as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except insights.InsightError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    db.commit()
    return ReportRegenerateResponse(
        summary=result["summary"],
        explanations_generated=generated,
        model=result.get("model"),
        generated_at=result.get("generated_at"),
    )


def _report_stem(filename: str) -> str:
    """Sanitized export-file stem - ASCII-safe so a hostile filename can
    never smuggle quotes/CRLF into a Content-Disposition header."""
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", Path(filename).stem).strip(".-")
    return stem or "report"


def _assembled_report(db: Session, scan: Scan) -> str:
    """Assemble the scan's report body - cache-first (decision 7).

    Shared by GET /report and the export endpoints. Reads only persisted
    data: the non-suppressed findings, the cached dependencies inventory
    (its own findings-fingerprint cache), and the web-source ledger. The
    body cache is identity-validated: a suppress toggle / regenerate / web
    capture recomputes lazily instead of serving a stale body (the
    dependencies_cache pattern). Pure assembly - no LLM and no model
    required (decision 10).
    """
    findings = list(
        db.scalars(
            select(Finding).where(
                Finding.scan_id == scan.id, Finding.suppressed == False  # noqa: E712
            )
        ).all()
    )
    # Open item 2 footnote: how many findings suppression excluded (a
    # suppressed-only scan would otherwise read as "zero findings" with no
    # explanation). One count query - the rows themselves stay reviewable
    # in the Findings tab's include_suppressed view.
    suppressed_count = (
        db.scalar(
            select(func.count())
            .select_from(Finding)
            .where(Finding.scan_id == scan.id, Finding.suppressed == True)  # noqa: E712
        )
        or 0
    )
    deps = dependencies.cached_inventory(scan, findings)
    if deps is None:
        deps = dependencies.inventory(scan, findings)
        dependencies.store_inventory(scan, findings, deps)
    sources = web_sources.sources_for(scan.id)
    cached = report.cached_body(
        scan,
        findings,
        dependencies=deps,
        web_sources=sources,
        suppressed_count=suppressed_count,
    )
    if cached is not None:
        return cached
    body = report.assemble_report(
        scan,
        findings,
        dependencies=deps,
        web_sources=sources,
        suppressed_count=suppressed_count,
    )
    report.store_body(
        scan,
        body,
        findings=findings,
        dependencies=deps,
        web_sources=sources,
        suppressed_count=suppressed_count,
    )
    return body


@router.get("/{scan_id}/report", response_model=ReportResponse)
def scan_report(scan_id: int, db: DbSession) -> ReportResponse:
    """M9: the assembled report body (cached markdown) for the Report tab.

    404 unknown scan · 409 not analyzed. The body NEVER 400s on a missing
    model - the AI sections render their cached rows or the explicit no-AI
    note (decision 10); only the regenerate POST is an AI route.
    """
    scan = _get_scan_or_404(db, scan_id)
    _require_analyzed(scan)
    return ReportResponse(markdown=_assembled_report(db, scan), generated_at=utcnow())


@router.get("/{scan_id}/report/export")
def export_report(
    scan_id: int,
    db: DbSession,
    format: str = Query(default="md"),
    inline: bool = Query(
        default=False,
        description="serve with Content-Disposition: inline (the Report tab's "
        "live PDF iframe) instead of the download attachment",
    ),
) -> Response:
    """M9 Phase C: export the assembled report as Markdown or branded PDF.

    ``format=md`` streams the cached body itself with a ``{stem}-report.md``
    attachment; ``format=pdf`` renders the SAME body through reportlab
    platypus (BSD-3-Clause, decision 3) with a ``{stem}-report.pdf``
    attachment - one body, two media. ``inline=1`` swaps the disposition to
    inline (the Report tab renders the PDF in an iframe; the download anchors
    keep the attachment default). 404 unknown scan · 409 not analyzed · 400
    unknown format · 500 PDF render failure (timeout / size cap / invalid
    output - never a silent empty file).
    """
    scan = _get_scan_or_404(db, scan_id)
    _require_analyzed(scan)
    if format not in ("md", "pdf"):
        raise HTTPException(
            status_code=400, detail=f"unknown export format {format!r} (md | pdf)"
        )
    body = _assembled_report(db, scan)
    stem = _report_stem(scan.filename)
    disposition = "inline" if inline else "attachment"
    if format == "md":
        return Response(
            content=body,
            media_type="text/markdown; charset=utf-8",
            headers={
                "Content-Disposition": f'{disposition}; filename="{stem}-report.md"'
            },
        )
    try:
        pdf = report_pdf.render_pdf(body, stem=stem)
    except report_pdf.ReportPdfError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'{disposition}; filename="{stem}-report.pdf"'
        },
    )


@router.post("/{scan_id}/findings/{finding_id}/explain", response_model=ExplainResponse)
def explain_finding(
    scan_id: int,
    finding_id: int,
    db: DbSession,
    regenerate: bool = Query(default=False),
) -> ExplainResponse:
    """FR-8: plain-language explanation + fix guidance for one finding.

    Grounded in the finding's detail + surrounding source lines; cached in
    ``findings.explanation`` so repeat requests return it free (no LLM call).
    Pass ``regenerate=true`` to bypass the cache (the UI's Regenerate button
    - an explicit user opt-in that spends cost; default is cache-first).
    """
    scan = _get_scan_or_404(db, scan_id)
    finding = db.get(Finding, finding_id)
    if finding is None or finding.scan_id != scan_id:
        raise HTTPException(status_code=404, detail="finding not found")
    _require_analyzed(scan)
    try:
        result = insights.explain_finding(scan_id, finding, regenerate=regenerate)
    except NoModelConfigured as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except insights.InsightError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    db.commit()
    return ExplainResponse(**result)


@router.get("/{scan_id}/files", response_model=FileTreeResponse)
def scan_file_tree(scan_id: int, db: DbSession) -> FileTreeResponse:
    """Bounded decompiler tree - Android: sources + resources; iOS: *.app."""
    scan = _get_scan_or_404(db, scan_id)
    _require_analyzed(scan)
    return FileTreeResponse(
        platform=scan.platform or "unknown",
        # M5 Phase A: the tree is immutable per scan, so it is computed once
        # and cache-served afterwards (the same smali_mapping.json / graph
        # explorer.json pattern) - repeated Decompiler opens don't re-walk the
        # filesystem (owner, Aug 10).
        roots=tree.cached_list_tree(scan),
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


@router.get("/{scan_id}/dependencies", response_model=DependenciesResponse)
def scan_dependencies(scan_id: int, db: DbSession) -> DependenciesResponse:
    """Dependencies tab inventory (local-first, derived on demand, cached).

    Android: third-party Java/Kotlin package groups from the jadx sources
    tree (the app's own package excluded) + native ``lib/*.so`` from the APK
    + runtime engine markers. iOS: linked dylibs from the persisted LIEF
    binary profile (system vs third-party) + embedded frameworks. 404 unknown
    scan · 409 not analyzed. Suppressed findings never count toward the
    per-dependency tallies (the risk/summary convention).

    Computed once per scan and cache-served afterwards (a validated
    ``dependencies_cache.json`` beside the scan's trees; identity includes a
    findings fingerprint, so a suppress/restore toggle recomputes). Known-CVE
    research is the agent's web-research use case (M7) - the UI's "Check
    known CVEs" button pre-fills the dock question; nothing here leaves the
    machine.
    """
    scan = _get_scan_or_404(db, scan_id)
    _require_analyzed(scan)
    findings = list(
        db.scalars(
            select(Finding).where(
                Finding.scan_id == scan_id,
                Finding.suppressed == False,  # noqa: E712
            )
        ).all()
    )
    # Cache-first: the inventory is immutable per scan except for finding
    # suppression, and the identity fingerprint includes the (non-suppressed)
    # findings set - so a suppress/restore toggle recomputes, and repeated
    # tab opens skip the source-tree walk + APK zip read entirely (the
    # tree_cache.json / smali_mapping.json pattern).
    data = dependencies.cached_inventory(scan, findings)
    if data is None:
        data = dependencies.inventory(scan, findings)
        dependencies.store_inventory(scan, findings, data)
    return DependenciesResponse(**data, generated_at=utcnow())



# ---- M8 Phase A: on-demand apktool decode (Smali view) ----------------------

_STALL_HINT = (
    "the decode job is queued but no background worker is picking it up - "
    "the worker service may be down or busy. Start it with `docker compose "
    "up -d worker` (or `docker compose up -d`); the queued job runs as soon "
    "as a worker is available"
)


def _decode_stalled(scan) -> bool:
    """Stuck-queue predicate (shared by smali-status AND the trigger): a
    decode still ``queued`` with no worker consuming it. ``queued`` with a
    NULL clock is a legacy stuck row (every enqueue path stamps it now); a
    clock older than ``apktool_queue_stall_seconds`` is a worker that never
    picked the job up. SQLite round-trips DateTime as naive, so compare both
    sides naive UTC."""
    if scan.apktool_status != "queued":
        return False
    queued_at = scan.apktool_queued_at
    if queued_at is None:
        return True
    return (
        utcnow().replace(tzinfo=None) - queued_at.replace(tzinfo=None)
    ).total_seconds() > settings.apktool_queue_stall_seconds


@router.post("/{scan_id}/smali", response_model=SmaliStatusResponse, status_code=202)
def trigger_apktool_decode(scan_id: int, db: DbSession) -> SmaliStatusResponse:
    """On-demand apktool decode - the Smali chip's trigger (Android only).

    404 unknown scan · 409 not analyzed / iOS (Android-only) / decode
    already queued-decoding / already ready. ``not_started`` and ``failed``
    (retry) both enqueue. Response is the 202 queued state; poll
    ``GET /scans/{id}/smali-status`` for the outcome.
    """
    scan = _get_scan_or_404(db, scan_id)
    _require_analyzed(scan)
    if scan.platform != "android":
        raise HTTPException(
            status_code=409,
            detail="apktool decode is Android-only - iOS keeps the read-only "
            "bundle view (M8 decision 5)",
        )
    # Filesystem first: a stale column must never re-decode an existing tree.
    if apktool.is_ready(scan.id):
        scan.apktool_status = "ready"
        scan.apktool_error = None
        db.commit()
        raise HTTPException(
            status_code=409, detail="apktool already decoded for this scan"
        )
    if scan.apktool_status in {"queued", "decoding"} and not _decode_stalled(scan):
        raise HTTPException(
            status_code=409,
            detail=f"apktool decode already in progress (status={scan.apktool_status})",
        )
    if scan.apktool_status == "ready":
        raise HTTPException(
            status_code=409, detail="apktool already decoded for this scan"
        )
    scan.apktool_status = "queued"
    scan.apktool_error = None
    # The stall-guard clock: a ``queued`` state this old with no worker
    # consuming it means the RQ worker isn't running, not that apktool is
    # slow - smali-status reports ``stalled`` with a start-the-worker hint.
    # A STALLED scan is re-triggerable here (the guard above lets it through):
    # the ↻ Retry chip re-enqueues with a fresh clock instead of 409-ing.
    scan.apktool_queued_at = utcnow()
    db.commit()
    try:
        enqueue_apktool_decode(scan_id)
    except Exception as exc:  # noqa: BLE001 - Redis down; never leave a phantom queue row
        scan.apktool_status = "failed"
        scan.apktool_queued_at = None
        scan.apktool_error = f"decode job enqueue failed: {exc}"
        db.commit()
        raise HTTPException(
            status_code=500,
            detail=f"decode could not be enqueued: {exc}",
        ) from exc
    return SmaliStatusResponse(status="queued")


@router.get("/{scan_id}/smali-status", response_model=SmaliStatusResponse)
def smali_status(scan_id: int, db: DbSession) -> SmaliStatusResponse:
    """Current decode state for the Smali chip.

    ``ready`` is filesystem-derived (``apktool/AndroidManifest.xml``
    exists) - the same derive-don't-trust-the-column rule as the graph - so
    a crash mid-decode can never leave a phantom ready state; everything
    else reflects the status column (in-flight states + the specific
    failure reason).
    """
    scan = _get_scan_or_404(db, scan_id)
    if apktool.is_ready(scan.id):
        return SmaliStatusResponse(status="ready")
    # Stuck-queue guard (M8 follow-up, Aug 12): a decode that was enqueued
    # but never picked up is a missing RQ worker, not a slow apktool - the
    # chip was spinning "forever" whenever the worker service was down.
    if _decode_stalled(scan):
        return SmaliStatusResponse(status="stalled", error=_STALL_HINT)
    return SmaliStatusResponse(status=scan.apktool_status, error=scan.apktool_error)


# ---- M8 Phase B: edits (DB-diff source of truth) ---------------------------


def _get_edit_or_404(db: DbSession, scan_id: int, edit_id: int) -> Edit:
    # Ownership first: a foreign scan's edits are as unreachable as the scan.
    _get_scan_or_404(db, scan_id)
    edit = db.get(Edit, edit_id)
    if edit is None or edit.scan_id != scan_id:
        raise HTTPException(status_code=404, detail="edit not found")
    return edit


def _require_decode_ready(scan: Scan) -> None:
    """409 until the on-demand apktool decode is ready - edits (and the
    Smali view they depend on) need the decoded tree on disk."""
    if not apktool.is_ready(scan.id):
        raise HTTPException(
            status_code=409,
            detail="apktool decode not ready - open the Smali view first "
            "(the decode runs once and is cached per scan)",
        )


@router.get("/{scan_id}/edits", response_model=list[EditRead])
def list_edits(scan_id: int, db: DbSession) -> list[Edit]:
    """All edit rows for a scan, newest first (full history - D8)."""
    scan = _get_scan_or_404(db, scan_id)
    _require_analyzed(scan)
    return list(
        db.scalars(
            select(Edit).where(Edit.scan_id == scan_id).order_by(Edit.id.desc())
        ).all()
    )


@router.post("/{scan_id}/edits", response_model=EditRead, status_code=201)
def create_edit(scan_id: int, payload: EditCreate, db: DbSession) -> Edit:
    """Create a **manual** edit (the editor's Ctrl/Cmd+S).

    Guards: 404 unknown scan · 409 not analyzed / non-Android / decode not
    ready · 400 not an editable path (can_edit) · 413 over the content cap ·
    400 unchanged content / unreadable baseline. Created as ``applied`` - the
    human authored it in the editor, no review step (unlike agent proposals,
    Phase D). Stored as a DB diff; the on-disk apktool tree never changes.
    """
    scan = _get_scan_or_404(db, scan_id)
    _require_analyzed(scan)
    if scan.platform != "android":
        raise HTTPException(
            status_code=409,
            detail="edits are Android-only - iOS keeps the read-only bundle view "
            "(M8 decision 5)",
        )
    _require_decode_ready(scan)
    if not editable.can_edit(scan, payload.file_path):
        raise HTTPException(
            status_code=400,
            detail=f"{payload.file_path!r} is not editable - only smali, res/, and "
            "the decoded AndroidManifest.xml can be edited",
        )
    if len(payload.content) > editable.MAX_EDIT_CHARS:
        raise HTTPException(
            status_code=413,
            detail=f"edit exceeds the {editable.MAX_EDIT_CHARS} character cap",
        )
    try:
        return edits.create_manual_edit(db, scan, payload.file_path, payload.content)
    except edits.EditError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except tree.TreeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/{scan_id}/edits/{edit_id}/diff", response_model=EditDiffResponse)
def edit_diff(scan_id: int, edit_id: int, db: DbSession) -> EditDiffResponse:
    """The stored unified diff for one edit (the review surface)."""
    edit = _get_edit_or_404(db, scan_id, edit_id)
    return EditDiffResponse(file_path=edit.file_path, diff=edit.unified_diff)


def _edit_review_flags(scan_id: int, edit: Edit) -> dict:
    """The task-list flags for an apply/reject response (M8 follow-up,
    Aug 16): after the human resolves a proposal the route marks the
    matching task in the scan's task-list.md artifact and reports what to
    do next.

    - ``next_task_pending``: applied (or the list still has pending work) -
      the dock opens the advance stream, the next task's proposal starts
      itself.
    - ``task_complete``: the list is exhausted (all applied/rejected) - the
      dock runs the wrap-up summary.
    - ``paused`` + ``pause_message``: a REJECTION with tasks still pending -
      the loop stops here; the human owns whether the rest of the task is
      still wanted (the rejection message rides in ``pause_message``).

    No task list (single-file request) -> no flags; resolving it has nothing
    to advance, so the flow simply ends."""
    tl = edit_tasks.mark_task_resolved(
        scan_id, edit.file_path, verdict=edit.status
    )
    if tl is None:
        return {}
    if tl.next_pending() is None:
        return {"task_complete": True}
    if edit.status == "rejected":
        return {"paused": True, "pause_message": edit_tasks.pause_message(tl, edit.file_path)}
    return {"next_task_pending": True}


def _edit_review_result(scan_id: int, edit: Edit) -> EditReviewResult:
    """The EditRead row + the task-list flags, as one apply/reject response."""
    data = EditRead.model_validate(edit).model_dump()
    data.update(_edit_review_flags(scan_id, edit))
    return EditReviewResult(**data)


@router.post("/{scan_id}/edits/{edit_id}/apply", response_model=EditReviewResult)
def apply_edit(scan_id: int, edit_id: int, db: DbSession) -> EditReviewResult:
    """proposed -> applied (agent proposals; the human owns application).
    Marks the matching task in the scan's task-list.md artifact and reports
    whether the next task should auto-advance (M8 follow-up, Aug 16)."""
    edit = _get_edit_or_404(db, scan_id, edit_id)
    try:
        edits.apply_edit(db, edit)
    except edits.EditError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _edit_review_result(scan_id, edit)


@router.post("/{scan_id}/edits/{edit_id}/reject", response_model=EditReviewResult)
def reject_edit(scan_id: int, edit_id: int, db: DbSession) -> EditReviewResult:
    """proposed -> rejected. Marks the matching task rejected in the task
    list and - with tasks still pending - PAUSES the loop: the human owns
    whether the rest of the task is still wanted (M8 follow-up, Aug 16)."""
    edit = _get_edit_or_404(db, scan_id, edit_id)
    try:
        edits.reject_edit(db, edit)
    except edits.EditError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _edit_review_result(scan_id, edit)


@router.post("/{scan_id}/edits/{edit_id}/revert", response_model=EditRead)
def revert_edit(scan_id: int, edit_id: int, db: DbSession) -> Edit:
    """applied -> reverted: effective content falls back to the previous
    applied edit (if any) or the baseline (restore-original)."""
    edit = _get_edit_or_404(db, scan_id, edit_id)
    try:
        return edits.revert_edit(db, edit)
    except edits.EditError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{scan_id}/files/smali-sibling", response_model=SmaliSiblingResponse)
def smali_sibling(
    scan_id: int, db: DbSession, path: str = Query(min_length=1)
) -> SmaliSiblingResponse:
    """Java⇄Smali counterpart of a tree path (the view-toggle jump).

    Sources -> smali (multidex-aware, first-found) and back; null sibling
    for res/manifest files and classes without a decoded smali counterpart.
    """
    scan = _get_scan_or_404(db, scan_id)
    _require_analyzed(scan)
    sibling = smali_map.java_to_smali(scan, path) or smali_map.smali_to_java(scan, path)
    return SmaliSiblingResponse(path=path, sibling=sibling)


@router.get("/{scan_id}/smali-mapping", response_model=SmaliMappingResponse)
def smali_mapping(scan_id: int, db: DbSession) -> SmaliMappingResponse:
    """Finding→apktool tree-path mapping for the scan's findings - powers
    the Smali-mode tree dots + annotation rail (findings live on jadx
    ``sources/...`` paths; their apktool siblings annotate too).

    Scoped to finding-bearing paths (bounded payload - the dots only exist
    where findings exist):
    - ``sources/...`` -> ``smali{,classesN}/...`` (java/kt findings,
      multidex first-found via ``smali_map.java_to_smali``);
    - ``res/...`` -> ITSELF - the apktool ``res`` root serves the same
      relative paths as the jadx resources tree (identity mapping; the
      frontend strips the root prefix to re-key dots/rail);
    - ``AndroidManifest.xml`` -> ``AndroidManifest.xml/AndroidManifest.xml``
      (the synthetic apktool root's single file).

    404 unknown scan · 409 not analyzed / Android-only. An undecoded scan
    returns an empty mapping (no apktool tree - the identity entries must
    not leak before the decode exists); the frontend fetches only once the
    decode is ready.
    """
    scan = _get_scan_or_404(db, scan_id)
    _require_analyzed(scan)
    if scan.platform != "android":
        raise HTTPException(
            status_code=409,
            detail="smali mapping is Android-only - iOS keeps the read-only bundle view",
        )
    if not apktool.is_ready(scan.id):
        return SmaliMappingResponse(mapping={}, total=0)
    # Cache-first: the mapping (+ line anchors) is immutable per scan
    # (findings immutable per scan id, the decoded tree never mutates), so
    # repeated Decompiler opens skip the findings query + per-path filesystem
    # walk entirely. On a miss the mapping is computed from the scan's
    # distinct finding file_paths (ROOT-RELATIVE - the ``sources/`` prefix is
    # implied) and the line anchors from the distinct (path, line) pairs, then
    # both are persisted together.
    cached = smali_map.cached_mapping(scan.id)
    if cached is not None:
        mapping, anchors = cached
        return SmaliMappingResponse(mapping=mapping, anchors=anchors, total=len(mapping))
    rows = db.execute(
        select(Finding.file_path, Finding.line_number)
        .where(Finding.scan_id == scan_id, Finding.file_path.isnot(None))
        .distinct()
    ).all()
    paths = [r[0] for r in rows]
    finding_lines: dict[str, list[int]] = {}
    for fp, line in rows:
        if fp and line is not None:
            finding_lines.setdefault(fp, []).append(line)
    mapping = smali_map.compute_mapping(scan, paths)
    anchors = smali_map.compute_anchors(scan, mapping, finding_lines)
    smali_map.store_mapping(scan.id, mapping, anchors)
    return SmaliMappingResponse(mapping=mapping, anchors=anchors, total=len(mapping))


# ---- M8 Phase C: rebuild pipeline (recompile + resign) ---------------------


def _get_build_or_404(db: DbSession, scan_id: int, build_id: int) -> Build:
    # Ownership first: a foreign scan's builds (incl. the download) are as
    # unreachable as the scan.
    _get_scan_or_404(db, scan_id)
    build = db.get(Build, build_id)
    if build is None or build.scan_id != scan_id:
        raise HTTPException(status_code=404, detail="build not found")
    return build


# A worker crash mid-build leaves its row in ``queued`` (never picked up) or
# ``running`` (killed before the per-step timeout could fail it) forever - the
# one-in-flight guard would then block every future rebuild with no recourse.
# These ages mark such rows failed so the next trigger can proceed (the build
# pipeline's per-step timeouts mean a live build always settles well within
# the running threshold).
_QUEUED_STALE_MINUTES = 5
_RUNNING_STALE_MINUTES = 45


def _reap_stale_builds(db: DbSession, scan_id: int) -> None:
    """Fail queued/running builds whose worker clearly never finished them."""
    from datetime import UTC, datetime

    def _age_minutes(created) -> float:
        if created.tzinfo is None:
            created = created.replace(tzinfo=UTC)  # SQLite drops tzinfo
        return (datetime.now(UTC) - created).total_seconds() / 60

    for build in db.scalars(
        select(Build).where(
            Build.scan_id == scan_id, Build.status.in_(["queued", "running"])
        )
    ).all():
        threshold = (
            _QUEUED_STALE_MINUTES if build.status == "queued" else _RUNNING_STALE_MINUTES
        )
        if _age_minutes(build.created_at) > threshold:
            build.status = "failed"
            build.stage = build.stage or "queued"
            build.error = (
                f"stale build (no worker finished it within "
                f"{threshold} min) - re-run the rebuild"
            )
            build.finished_at = utcnow()
    db.commit()


@router.post("/{scan_id}/rebuild", response_model=BuildRead, status_code=202)
def trigger_rebuild(scan_id: int, db: DbSession) -> Build:
    """Enqueue a recompile: snapshot applied edits -> apktool b -> zipalign
    -> apksigner sign (install-scoped TEST keystore) -> verify gate.

    404 unknown scan · 409 not analyzed / iOS (Android-only) / decode not
    ready / a rebuild already in flight (one per scan - Phase E hardens the
    concurrency edges) · 500 enqueue failure (the build row is marked failed
    with the reason). Zero applied edits is allowed - a default rebuild of
    the pristine tree. The artifact's filename carries the ``-resigned-
    test-`` label (decision 9).
    """
    scan = _get_scan_or_404(db, scan_id)
    _require_analyzed(scan)
    if scan.platform != "android":
        raise HTTPException(
            status_code=409,
            detail="rebuild is Android-only - iOS keeps the read-only bundle "
            "view (M8 decision 5)",
        )
    _require_decode_ready(scan)
    # A crashed worker can leave a build stuck in queued/running - fail those
    # stale rows first so the guard below can't lock the scan out forever.
    _reap_stale_builds(db, scan_id)
    in_flight = db.scalars(
        select(Build)
        .where(Build.scan_id == scan_id, Build.status.in_(["queued", "running"]))
        .limit(1)
    ).first()
    if in_flight is not None:
        raise HTTPException(
            status_code=409,
            detail=f"a rebuild is already in progress "
            f"(build {in_flight.id}, status={in_flight.status})",
        )
    build = Build(scan_id=scan_id, status="queued", stage="queued")
    db.add(build)
    db.commit()
    try:
        enqueue_rebuild(scan_id, build.id)
    except Exception as exc:  # noqa: BLE001 - Redis down; never leave a phantom queued row
        build.status = "failed"
        build.stage = "queued"
        build.error = f"rebuild enqueue failed: {exc}"
        build.finished_at = utcnow()
        db.commit()
        raise HTTPException(
            status_code=500,
            detail=f"rebuild could not be enqueued: {exc}",
        ) from exc
    return build


@router.get("/{scan_id}/builds", response_model=list[BuildRead])
def list_builds(scan_id: int, db: DbSession) -> list[Build]:
    """Full rebuild history for a scan, newest first (D8)."""
    _get_scan_or_404(db, scan_id)
    return list(
        db.scalars(
            select(Build).where(Build.scan_id == scan_id).order_by(Build.id.desc())
        ).all()
    )


@router.get("/{scan_id}/builds/{build_id}", response_model=BuildRead)
def get_build(scan_id: int, build_id: int, db: DbSession) -> Build:
    """One build - the recompile modal's poll target for live stage updates."""
    return _get_build_or_404(db, scan_id, build_id)


@router.get("/{scan_id}/builds/{build_id}/download")
def download_build(scan_id: int, build_id: int, db: DbSession) -> FileResponse:
    """Download a done build's resigned TEST APK (decision 8: re-downloadable
    at any time).

    404 unknown build / artifact missing on disk · 409 build not done. The
    attachment filename carries the ``-resigned-test-`` label and the
    ``X-Resigned-Test-Build`` header marks the response - the persistent
    test-build label (decision 10) travels with the file, not just the UI.
    """
    build = _get_build_or_404(db, scan_id, build_id)
    if build.status != "done" or not build.artifact_path:
        raise HTTPException(
            status_code=409,
            detail=f"build {build_id} has no downloadable artifact "
            f"(status={build.status})",
        )
    path = Path(build.artifact_path)
    if not path.is_file():
        raise HTTPException(
            status_code=404, detail="artifact file missing on disk - re-run the build"
        )
    # The artifact_path is server-written, but a stale/edited DB must never
    # stream an arbitrary file - constrain it to the scan's artifact dir.
    if not path.resolve().is_relative_to(rebuild.artifact_dir(scan_id).resolve()):
        raise HTTPException(
            status_code=404, detail="artifact path escapes the scan's artifact dir"
        )
    return FileResponse(
        path,
        media_type="application/vnd.android.package-archive",
        filename=build.artifact_name or path.name,
        headers={"X-Resigned-Test-Build": "true"},
    )


@router.get("/{scan_id}/source-zip")
def download_source_zip(scan_id: int, db: DbSession) -> FileResponse:
    """Download the scan's decoded source tree as a zip - smali / res /
    AndroidManifest.xml - with applied edits overlaid (the effective source
    a rebuild starts from).

    Generated on demand from the pristine apktool decode: edits are DB diffs
    overlaid into the zip, never written onto the tree (the baseline never
    changes). The zip's top-level folder and attachment name carry the
    ``<original-stem>-source`` label. The temp zip is unlinked after the
    response streams. 404 unknown scan · 409 not analyzed / iOS
    (Android-only) / decode not ready.
    """
    scan = _get_scan_or_404(db, scan_id)
    _require_analyzed(scan)
    if scan.platform != "android":
        raise HTTPException(
            status_code=409,
            detail="source zip is Android-only - iOS keeps the read-only bundle "
            "view (M8 decision 5)",
        )
    _require_decode_ready(scan)
    applied = list(
        db.scalars(
            select(Edit)
            .where(Edit.scan_id == scan_id, Edit.status == "applied")
            .order_by(Edit.id)
        ).all()
    )
    # The zip is derived on demand into a temp file beside the scan's work
    # dir (the decode lives there), then streamed - never held in memory
    # (decoded trees can be large) and never cached (edits change over time).
    with tempfile.NamedTemporaryFile(
        prefix=f"scan{scan_id}-source-",
        suffix=".zip",
        dir=str(apktool.decoded_root(scan_id).parent),
        delete=False,
    ) as tf:
        tmp = Path(tf.name)
    try:
        rebuild.export_source_zip(scan, applied, tmp)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise
    return FileResponse(
        tmp,
        media_type="application/zip",
        filename=f"{rebuild.source_stem(scan)}.zip",
        background=BackgroundTask(tmp.unlink, missing_ok=True),
    )


@router.put("/{scan_id}/web-research", response_model=ScanRead)
def set_web_research(scan_id: int, payload: WebResearchUpdate, db: DbSession) -> Scan:
    """M7: per-scan web research opt-in (the dock 🌐 toggle / Settings).

    This is the privacy gate ONLY - engine-agnostic: it permits the agent's
    web tools for this scan; which engine (if any) is Active is a Settings
    concern (``SearchStore``). The chat layer enforces both gates per call.
    """
    scan = _get_scan_or_404(db, scan_id)
    if scan.web_research_enabled != payload.enabled:
        scan.web_research_enabled = payload.enabled
        db.commit()
    return scan


@router.get("/{scan_id}/graph", response_model=ScanGraphState)
def scan_graph_state(scan_id: int, db: DbSession) -> ScanGraphState:
    """M4 Layer 3: per-scan Graphify graph state (filesystem-derived).

    No DB columns - "built" means ``graphs/<scan_id>/graphify-out/graph.json``
    exists; node/edge counts are streamed from the JSON. Android only.
    """
    scan = _get_scan_or_404(db, scan_id)
    if scan.platform != "android":
        return ScanGraphState(
            built=False,
            reason="graph is Android-only - iOS has no decompiled source tree",
        )
    graph_path = graphify.graph_path_for(scan_id)
    if not graph_path.is_file():
        return ScanGraphState(
            built=False,
            reason="graph not built yet - the graph build job is chained after analysis "
            "for Android scans",
        )
    nodes, edges = graphify.count_graph(graph_path)
    return ScanGraphState(
        built=True,
        nodes=nodes,
        edges=edges,
        graph_path=f"graphs/{scan_id}/graphify-out/graph.json",
    )


@router.get("/{scan_id}/graph/search", response_model=GraphSearchResponse)
def graph_search(
    scan_id: int,
    db: DbSession,
    q: str = Query(default="", max_length=200),
    limit: int = Query(default=25, ge=1, le=100),
) -> GraphSearchResponse:
    """Code maps: substring search over graph node labels/ids (Android only).

    404 unknown scan · 409 non-Android or graph not built yet. The graph.json
    is compacted into a per-scan explorer index on first access (cached), so
    repeated searches never re-parse the multi-MB file.
    """
    scan = _get_scan_or_404(db, scan_id)
    graph_path = _require_graph(scan)
    rows, total = graphify.search(graph_path, q.strip(), limit=limit)
    return GraphSearchResponse(query=q, total=total, nodes=rows)


@router.get("/{scan_id}/graph/hubs", response_model=GraphHubsResponse)
def graph_hubs(
    scan_id: int,
    db: DbSession,
    limit: int = Query(default=25, ge=1, le=100),
) -> GraphHubsResponse:
    """Code maps: most-connected nodes by link degree - the initial view."""
    scan = _get_scan_or_404(db, scan_id)
    graph_path = _require_graph(scan)
    return GraphHubsResponse(hubs=graphify.hubs(graph_path, limit=limit))


@router.get("/{scan_id}/graph/node/{node_id}", response_model=GraphNodeDetail)
def graph_node(scan_id: int, node_id: str, db: DbSession) -> GraphNodeDetail:
    """Code maps: one node + its neighbors (in/out, relation-tagged).

    404 unknown node id (id is a graphify internal, e.g. ``@127.0.0.1`` or a
    symbol) · 409 non-Android / graph not built.
    """
    scan = _get_scan_or_404(db, scan_id)
    graph_path = _require_graph(scan)
    detail = graphify.node_detail(graph_path, node_id)
    if detail is None:
        raise HTTPException(status_code=404, detail=f"graph node {node_id!r} not found")
    return detail


# ---- M9 follow-up: multi-session agent chat --------------------------------
# The dock's thread now persists in the DB (chat_sessions + chat_messages):
# CRUD below, and /chat + /chat/stream load the session's history and write
# the user/assistant turns back. The chat loop itself stays stateless - it
# still receives ``history``; sessions just feed it from the DB instead of
# the client's 6-turn window (which stays as a fallback for callers without
# a session_id).


def _session_read(db: Session, s: ChatSession) -> ChatSessionRead:
    last = sessions.last_message(db, s.id)
    return ChatSessionRead(
        id=s.id,
        scan_id=s.scan_id,
        title=s.title,
        created_at=s.created_at,
        updated_at=s.updated_at,
        message_count=sessions.message_count(db, s.id),
        last_content=(last.content[:160] if last else None),
    )


def _session_history_or_404(db: Session, scan_id: int, payload: ChatRequest) -> list[dict]:
    """The persisted thread for ``payload.session_id`` as history dicts, and
    a freshly-persisted user turn for the question being asked.

    The history is loaded BEFORE the user message is appended (the current
    question is added by ``answer_question`` itself - it is not part of the
    history). The user turn is persisted before the LLM call so an
    interrupted/cancelled turn still shows what was asked in the thread.
    ``history`` on the payload is the fallback when no session is given.
    """
    if payload.session_id is None:
        return [t.model_dump() for t in payload.history]
    session = sessions.get_session(db, payload.session_id, scan_id)
    if session is None:
        raise HTTPException(status_code=404, detail="chat session not found")
    history = [
        {"role": m.role, "content": m.content}
        for m in sessions.session_history(db, session.id)
    ]
    sessions.add_message(db, session, role="user", content=payload.question)
    return history


def _persist_assistant_turn(db: Session, session_id: int, result) -> None:
    """Append the finished assistant turn (answer + tool trace) to a session.
    No-op when the session vanished mid-turn."""
    session = sessions.get_session(db, session_id)
    if session is None:
        return
    sessions.add_message(
        db,
        session,
        role="assistant",
        content=result.answer,
        tool_runs=[
            {
                "id": r.id,
                "name": r.name,
                "args": r.args,
                "status": r.status,
                "duration_ms": r.duration_ms,
                "result_preview": r.result_preview,
                "error": r.error,
                "count": r.count,
            }
            for r in result.tool_runs
        ]
        or None,
        # Citation-shaped dicts so reloaded history re-renders the source
        # chips exactly like the live ChatResponse.
        citations=[
            {"file": c.file, "line": c.line, "snippet": c.snippet}
            for c in result.citations
        ]
        or None,
    )


@router.get("/{scan_id}/chat/sessions", response_model=list[ChatSessionRead])
def list_chat_sessions(scan_id: int, db: DbSession) -> list[ChatSessionRead]:
    """All chat sessions for a scan, most recently used first (the dock's
    session switcher). 404 unknown scan."""
    _get_scan_or_404(db, scan_id)
    return [_session_read(db, s) for s in sessions.list_sessions(db, scan_id)]


@router.post("/{scan_id}/chat/sessions", response_model=ChatSessionRead)
def create_chat_session(scan_id: int, db: DbSession) -> ChatSessionRead:
    """A fresh empty session (title auto-derives from the first question)."""
    _get_scan_or_404(db, scan_id)
    return _session_read(db, sessions.create_session(db, scan_id))


@router.post("/{scan_id}/chat/sessions/{session_id}/rename", response_model=ChatSessionRead)
def rename_chat_session(
    scan_id: int, session_id: int, payload: ChatSessionUpdate, db: DbSession
) -> ChatSessionRead:
    """Rename one session (404 unknown session / not this scan's)."""
    _get_scan_or_404(db, scan_id)
    session = sessions.get_session(db, session_id, scan_id)
    if session is None:
        raise HTTPException(status_code=404, detail="chat session not found")
    return _session_read(db, sessions.rename_session(db, session, payload.title))


@router.delete("/{scan_id}/chat/sessions/{session_id}")
def delete_chat_session(scan_id: int, session_id: int, db: DbSession) -> dict:
    """Delete one session - its messages cascade (404 unknown session / not
    this scan's)."""
    _get_scan_or_404(db, scan_id)
    session = sessions.get_session(db, session_id, scan_id)
    if session is None:
        raise HTTPException(status_code=404, detail="chat session not found")
    sessions.delete_session(db, session)
    return {"deleted": True}


@router.get("/{scan_id}/chat/sessions/{session_id}/messages", response_model=list[ChatMessageRead])
def chat_session_messages(scan_id: int, session_id: int, db: DbSession) -> list[ChatMessageRead]:
    """The full thread for one session (the switcher loads it on select,
    and a reload restores the active session's history)."""
    _get_scan_or_404(db, scan_id)
    session = sessions.get_session(db, session_id, scan_id)
    if session is None:
        raise HTTPException(status_code=404, detail="chat session not found")
    out: list[ChatMessageRead] = []
    for m in sessions.session_history(db, session.id):
        tool_runs: list = []
        if m.tool_runs_json:
            try:
                tool_runs = [ToolRunRead(**t) for t in json.loads(m.tool_runs_json)]
            except (json.JSONDecodeError, TypeError, ValueError):
                tool_runs = []  # stale/corrupt trace - render without steps
        citations: list = []
        if m.citations_json:
            try:
                citations = [Citation(**c) for c in json.loads(m.citations_json)]
            except (json.JSONDecodeError, TypeError, ValueError):
                citations = []  # stale/corrupt - render without chips
        out.append(
            ChatMessageRead(
                id=m.id,
                role=m.role,
                content=m.content,
                created_at=m.created_at,
                tool_runs=tool_runs,
                citations=citations,
            )
        )
    return out


@router.post("/{scan_id}/chat", response_model=ChatResponse)
def chat_scan(scan_id: int, payload: ChatRequest, db: DbSession) -> ChatResponse:
    """M4: grounded agent answer over Layers 1-3 (findings context + tools).

    Zero embeddings - the RAG/vector path was removed from v1. 404 unknown
    scan · 409 scan not analyzed · 400 no chat model configured · 502 the
    upstream LLM backend failed (model not loadable, connection error - the
    detail carries the upstream message) · 504 the agent loop exceeded its
    overall deadline (hung LLM call, hard-capped by
    ``payload.timeout_seconds`` / ``settings.chat_timeout_seconds``). The
    chat model comes from the M3 backend store - no new config surface.
    """
    scan = _get_scan_or_404(db, scan_id)
    if scan.status != "done":
        raise HTTPException(
            status_code=409,
            detail=f"scan {scan_id} is not analyzed yet (status={scan.status}) - "
            "run the scan job first",
        )
    # M9 follow-up: session-aware turns - load the persisted thread (and
    # persist the user turn) when a session_id is given.
    history = _session_history_or_404(db, scan_id, payload)
    try:
        result = answer_question(
            scan_id,
            payload.question,
            timeout=payload.timeout_seconds,
            max_tool_rounds=payload.max_tool_rounds,
            mentioned_files=payload.mentioned_files,
            history=history,
            # M9.1 Phase C: the scan owner's id + vault key resolve the
            # user's model/search stores inside the agent loop.
            user_id=current_user_id.get(),
            master_key=current_master_key.get(),
        )
    except ChatNotConfigured as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ChatInterrupted as exc:
        # The user hit Stop - the client already aborted and reads nothing,
        # but a curl/test caller must never mistake the 409 for an answer.
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except AgentTimeout as exc:
        raise HTTPException(status_code=504, detail=str(exc)) from exc
    except ChatUpstreamError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    # M9 open item 1: capture the web URLs the agent actually fetched this
    # turn into the scan's ledger (the report's External references section) -
    # best-effort, never affects the response.
    web_sources.capture_from_turn(scan_id, result.tool_runs)
    # M9 follow-up: persist the finished assistant turn back to the session.
    if payload.session_id is not None:
        _persist_assistant_turn(db, payload.session_id, result)
    # Shared with the SSE stream's final answer frame - one payload shape.
    return ChatResponse(**_chat_payload(result))


@router.post("/{scan_id}/chat/stream")
def chat_scan_stream(scan_id: int, payload: ChatRequest, db: DbSession) -> StreamingResponse:
    """M6 follow-up: SSE stream of one agent turn - live tool steps + tokens.

    The buffered ``/chat`` returns only the final answer; this streams the
    agent loop as it runs: ``token`` frames (answer text as it is generated),
    ``tool_start``/``tool_end`` pairs (live steps), then a final ``answer``
    frame carrying the canonical ChatResponse-shaped payload (including the
    persistent ``tool_runs`` trace). Errors arrive as an ``error`` frame with
    a kind + detail (the same contract the buffered endpoint encodes as HTTP
    codes: no-model / upstream / timeout / interrupted) - the client
    classifies them into the existing error-bubble copy.

    The ``answer_question`` call runs on a worker thread pushing frames
    through a queue so the generator can yield live; the existing cancel
    machinery (``POST /chat/cancel`` + client fetch abort) stops the loop at
    the next boundary. Keepalive ``: ping`` comments flow every 15 s while a
    tool call is running so the connection never looks dead.
    """
    scan = _get_scan_or_404(db, scan_id)
    if scan.status != "done":
        raise HTTPException(
            status_code=409,
            detail=f"scan {scan_id} is not analyzed yet (status={scan.status}) - "
            "run the scan job first",
        )
    # A missing model is a clean pre-stream HTTP 400 (nothing sent yet);
    # answer_question would otherwise raise mid-stream after the 200 headers.
    try:
        check_configured()
    except ChatNotConfigured as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    # M9 follow-up: a bad session_id is a clean pre-stream 404 (nothing sent
    # yet) - the worker thread does its own DB work with a fresh connection.
    if payload.session_id is not None and sessions.get_session(
        db, payload.session_id, scan_id
    ) is None:
        raise HTTPException(status_code=404, detail="chat session not found")
    # M9.1 Phase C: capture the scan owner's id + vault key BEFORE the
    # worker thread - a new thread does not inherit the request thread's
    # contextvars, and the agent loop resolves the user's model/search
    # stores (and decrypts key blobs) from them.
    uid = current_user_id.get()
    mk = current_master_key.get()

    def gen():
        frames: queue.Queue[str | None] = queue.Queue()

        def on_event(event: AgentEvent) -> None:
            frames.put(_sse_frame(event.kind, event.payload))

        def run() -> None:
            # The worker must NOT touch the request-scoped `db` (SQLite +
            # threads) - it opens its own connection for the session work.
            from app.db import SessionLocal as _SessionLocal

            work_db = _SessionLocal()
            try:
                history: list[dict] = [t.model_dump() for t in payload.history]
                if payload.session_id is not None:
                    session = sessions.get_session(work_db, payload.session_id, scan_id)
                    if session is None:
                        frames.put(
                            _sse_frame(
                                "error", {"kind": "error", "detail": "chat session not found"}
                            )
                        )
                        return
                    history = [
                        {"role": m.role, "content": m.content}
                        for m in sessions.session_history(work_db, session.id)
                    ]
                    # Persist the user turn before the LLM call so an
                    # interrupted turn still shows what was asked - EXCEPT
                    # for an ADVANCE turn (M8 follow-up, Aug 16): there is
                    # no user question, the backend builds the continuation
                    # from the task-list artifact.
                    if not payload.advance:
                        sessions.add_message(
                            work_db, session, role="user", content=payload.question
                        )
                result = answer_question(
                    scan_id,
                    payload.question,
                    timeout=payload.timeout_seconds,
                    max_tool_rounds=payload.max_tool_rounds,
                    stream=True,
                    on_event=on_event,
                    mentioned_files=payload.mentioned_files,
                    history=history,
                    advance=payload.advance,
                    user_id=uid,
                    master_key=mk,
                )
                # M9 open item 1: same ledger capture as the buffered route -
                # best-effort, never affects the stream.
                web_sources.capture_from_turn(scan_id, result.tool_runs)
                # M9 follow-up: persist the finished assistant turn (answer +
                # tool trace) back to the session.
                if payload.session_id is not None:
                    _persist_assistant_turn(work_db, payload.session_id, result)
                frames.put(_sse_frame("answer", _chat_payload(result)))
            except ChatNotConfigured as exc:
                frames.put(_sse_frame("error", {"kind": "no-model", "detail": str(exc)}))
            except ChatUpstreamError as exc:
                frames.put(_sse_frame("error", {"kind": "upstream", "detail": str(exc)}))
            except AgentTimeout as exc:
                frames.put(_sse_frame("error", {"kind": "timeout", "detail": str(exc)}))
            except ChatInterrupted as exc:
                frames.put(_sse_frame("error", {"kind": "interrupted", "detail": str(exc)}))
            except Exception as exc:  # noqa: BLE001 - stream must terminate cleanly
                frames.put(_sse_frame("error", {"kind": "error", "detail": str(exc)}))
            finally:
                work_db.close()
                frames.put(None)  # sentinel - end the stream

        threading.Thread(target=run, daemon=True).start()
        while True:
            try:
                frame = frames.get(timeout=15)
            except queue.Empty:
                # Long-running tool call (e.g. run_secrets_scan): keep the
                # connection alive - SSE comments are ignored by clients.
                yield ": keepalive\n\n"
                continue
            if frame is None:
                break
            yield frame

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/{scan_id}/chat/complete-task", response_model=ChatResponse)
def complete_task(scan_id: int, payload: ChatCompleteRequest, db: DbSession) -> ChatResponse:
    """M8 follow-up (Aug 16): the task-complete wrap-up - when a task list
    is exhausted (every proposal applied or rejected), ONE small LLM call
    summarizes what changed / was rejected. No tools, no findings context -
    a fraction of a full turn; falls back to a deterministic summary when
    the model cannot answer (a wrap-up never errors the review). The
    finished turn is persisted to the session so the dock's final agent
    message survives a reload."""
    _get_scan_or_404(db, scan_id)
    result = task_completion_answer(
        scan_id,
        user_id=current_user_id.get(),
        master_key=current_master_key.get(),
    )
    if payload.session_id is not None:
        session = sessions.get_session(db, payload.session_id, scan_id)
        if session is None:
            raise HTTPException(status_code=404, detail="chat session not found")
        _persist_assistant_turn(db, payload.session_id, result)
    return ChatResponse(**_chat_payload(result))


@router.post("/{scan_id}/chat/cancel")
def cancel_chat(scan_id: int, db: DbSession) -> dict:
    """Stop any in-flight agent chat for the scan (the Stop button).

    Sets the in-process cancel flag that ``answer_question`` polls at every
    agent-loop boundary, so the LLM stops at the next round instead of
    burning the whole budget. No-op when nothing is running - the flag only
    exists while a request is in flight. The aborted chat request itself
    comes back 409 (``ChatInterrupted``).
    """
    _get_scan_or_404(db, scan_id)
    request_cancel(scan_id)
    return {"cancelled": True}
