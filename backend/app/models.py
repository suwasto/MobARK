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
    # "android" | "ios" — detected by M1/M2; null until then.
    platform: Mapped[str | None] = mapped_column(String(16))
    # queued | running | done | failed
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued")
    # 0-100 aggregate score, computed from M5 onward.
    risk_score: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(Text)
    # Where the uploaded artifact + working directory live under MASA_DATA_DIR.
    storage_path: Mapped[str | None] = mapped_column(String(1024))

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    findings: Mapped[list[Finding]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


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
    # critical | high | medium | low | info
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    file_path: Mapped[str | None] = mapped_column(String(1024))
    line_number: Mapped[int | None] = mapped_column(Integer)
    # MASVS/MASTG-mappable category — refined in M1.
    category: Mapped[str | None] = mapped_column(String(128))
    # MASTG test id (e.g. MASTG-TEST-0073) when known from the vendored mapping.
    mastg_test_id: Mapped[str | None] = mapped_column(String(64))
    # Which tool produced this finding (androguard | gitleaks | semgrep | plist | lief | ...).
    tool: Mapped[str] = mapped_column(String(64), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text)
    # True = static-only finding (all current findings; runtime/dynamic
    # confirmation is out of scope for v1 — M2's mockup "static-only" label).
    static_only: Mapped[bool] = mapped_column(default=True, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    scan: Mapped[Scan] = relationship(back_populates="findings")
