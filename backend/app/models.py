from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


class Scan(Base):
    """A single uploaded application under test (APK or IPA)."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    # "android" | "ios" - detected by M1/M2; null until then.
    platform: Mapped[str | None] = mapped_column(String(16))
    # queued | running | done | failed
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued")
    # 0-100 aggregate RISK score, computed by the scan job (M5,
    # analysis/risk.py). The public-facing security score (100 - risk) is
    # derived on read via the property below - never stored, so the two
    # cannot drift (owner decision, Aug 7: higher is better).
    risk_score: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(Text)
    # Where the uploaded artifact + working directory live under MASA_DATA_DIR.
    storage_path: Mapped[str | None] = mapped_column(String(1024))
    # M5: cached AI overview summary (Overview tab; POST /scans/{id}/summary).
    ai_summary: Mapped[str | None] = mapped_column(Text)
    # M5: human-readable pipeline stage for the progress screen, e.g.
    # "decompiling" | "analyzing" | "secrets" | "done" (written by run_scan).
    stage: Mapped[str | None] = mapped_column(String(32))
    # M7: per-scan web research opt-in (privacy gate). The agent's web tools
    # (web_search/web_fetch) are offered only when this is on AND an Active
    # search engine exists (SearchStore.active()). Default off; controlled by
    # the dock 🌐 toggle + Settings -> Search & research.
    web_research_enabled: Mapped[bool] = mapped_column(default=False, nullable=False)
    # M8: on-demand apktool decode state (Android only; the Smali view +
    # edit/recompile feature). not_started | queued | decoding | ready | failed
    # - ``ready`` is also filesystem-derived via analysis/apktool.py::is_ready
    # (the column tracks in-flight states; the tree on disk is the truth).
    # ``apktool_error`` carries the specific decode failure for the UI.
    apktool_status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="not_started"
    )
    apktool_error: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    @property
    def security_score(self) -> int | None:
        """0-100 security score (higher = better); None until analyzed."""
        from app.analysis.risk import security_from_risk

        return security_from_risk(self.risk_score)

    findings: Mapped[list[Finding]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class Edit(Base):
    """One file edit (M8 edit & recompile, Android only) - DB-diff source
    of truth. Full-file rows: ``original_content`` (the effective baseline at
    creation) + ``new_content`` + the generated ``unified_diff``. The on-disk
    apktool tree stays pristine; the rebuild job overlays applied edits onto
    a fresh copy. ``status``: proposed | applied | rejected | reverted -
    manual edits are created applied; agent proposals (Phase D) start
    proposed and the human applies. ``build_id`` is filled when a rebuild
    consumes the edit (Phase C).
    """

    __tablename__ = "edits"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # apktool-root-relative: smali/com/foo/A.smali, res/values/strings.xml,
    # AndroidManifest.xml
    file_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    original_content: Mapped[str] = mapped_column(Text, nullable=False)
    new_content: Mapped[str] = mapped_column(Text, nullable=False)
    unified_diff: Mapped[str] = mapped_column(Text, nullable=False)
    # manual | agent
    source: Mapped[str] = mapped_column(String(16), nullable=False, default="manual")
    # the agent's natural-language ask, for attribution (agent edits only)
    instruction: Mapped[str | None] = mapped_column(Text)
    # proposed | applied | rejected | reverted
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="proposed")
    # which build consumed this edit (nullable until a rebuild runs)
    build_id: Mapped[int | None] = mapped_column(
        ForeignKey("builds.id", ondelete="SET NULL"), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Build(Base):
    """One recompile attempt (M8 Phase C) - full rebuild history per scan
    (decision 8). The pipeline snapshots the applied edits at job start
    (``edits_json``), so edits accepted mid-build never mutate the build tree;
    a done build's artifact is re-downloadable at any time.
    """

    __tablename__ = "builds"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # queued | running | done | failed
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued")
    # applying | rebuilding | zipping | signing | done (queued before the job)
    stage: Mapped[str] = mapped_column(String(32), nullable=False, default="queued")
    # specific failure: the failing stage's stderr excerpt - never a silent break
    error: Mapped[str | None] = mapped_column(Text)
    # JSON list of applied edit ids at snapshot time
    edits_json: Mapped[str | None] = mapped_column(Text)
    artifact_name: Mapped[str | None] = mapped_column(String(512))
    artifact_path: Mapped[str | None] = mapped_column(String(1024))
    artifact_sha256: Mapped[str | None] = mapped_column(String(64))

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Finding(Base):
    """A single structured finding attached to a scan.

    Core columns cover PRD FR-4 (title, severity, file/line, category).
    ``detail`` holds the tool-specific payload as JSON text; M1 defines and
    validates the exact payload shape per producing tool (androguard /
    gitleaks / semgrep / lief).
    """

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    # high | medium | low | info (no critical band - owner decision Aug 8,
    # 2026; see migration 0005 for the critical->high data rewrite).
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    file_path: Mapped[str | None] = mapped_column(String(1024))
    line_number: Mapped[int | None] = mapped_column(Integer)
    # MASVS/MASTG-mappable category - refined in M1.
    category: Mapped[str | None] = mapped_column(String(128))
    # MASTG test id (e.g. MASTG-TEST-0073) when known from the vendored mapping.
    mastg_test_id: Mapped[str | None] = mapped_column(String(64))
    # Which tool produced this finding (androguard | gitleaks | semgrep | plist | lief | ...).
    tool: Mapped[str] = mapped_column(String(64), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text)
    # True = static-only finding (all current findings; runtime/dynamic
    # confirmation is out of scope for v1 - M2's mockup "static-only" label).
    static_only: Mapped[bool] = mapped_column(default=True, nullable=False)
    # M5: cached AI explanation (POST /scans/{id}/findings/{fid}/explain).
    # Re-running a scan deletes findings, so stale explanations never survive.
    explanation: Mapped[str | None] = mapped_column(Text)
    # M5 (Aug 8): per-finding false-positive suppression. Suppressed findings
    # are hidden from the default findings list, excluded from the risk
    # score / AI summary / agent context, and restorable via the review
    # toggle. ``suppressed_at`` records when it was suppressed.
    suppressed: Mapped[bool] = mapped_column(default=False, nullable=False)
    suppressed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    scan: Mapped[Scan] = relationship(back_populates="findings")
