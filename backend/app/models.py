from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, text
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
    # When the decode was enqueued - the stuck-queue guard's clock: a
    # ``queued`` state older than ``apktool_queue_stall_seconds`` means the
    # RQ worker is not running (a decode that never executes looks exactly
    # like a slow one), so smali-status reports ``stalled`` with guidance.
    apktool_queued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # M9.1: the owning user (per-user data isolation - decision 1). NULL for
    # legacy rows and auth-off scans; the first registered user's claim
    # (``users.claim_unowned``) adopts them. SQLite can't ALTER-ADD NOT NULL,
    # so the column is nullable and the APP enforces ownership on every new
    # scan (create_scan sets it from the current user). Everything downstream
    # keys off this row's id - one ownership check at the API boundary
    # isolates findings/chats/edits/builds/reports with it.
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )

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
    # high | warning | info (no critical band - owner decision Aug 8, 2026,
    # see migration 0005 for the critical->high rewrite; the low band was
    # dropped and medium renamed warning Aug 15, 2026 - see migrations
    # 0016 (low->info) and 0017 (medium->warning)).
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


class ChatSession(Base):
    """One agent chat thread for a scan (multi-session chat, M9 follow-up).

    The backend never used to persist chat (the dock held the thread
    client-side and re-sent the last 6 turns); sessions move the thread to
    the DB so it survives reloads and the model can see a much larger
    window. Per-scan (a scan's dock is its own workspace); messages cascade
    on delete. ``title`` is auto-derived from the first question and
    renameable (PATCH). ``updated_at`` is the session list's sort key +
    the "most recent" pick.
    """

    __tablename__ = "chat_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(120), nullable=False, default="New chat")

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    messages: Mapped[list[ChatMessage]] = relationship(
        back_populates="session",
        cascade="all, delete-orphan",
        order_by="ChatMessage.position",
    )


class ChatMessage(Base):
    """One persisted turn in a chat session (user or assistant).

    ``position`` is the in-session order (messages render + reach the model
    in this order). Assistant turns carry the tool-run trace
    (``tool_runs_json``) so reloaded history can re-render the collapsible
    "Tools (n)" steps. Content is capped at write time (the same 4000-char
    per-turn bound the client history used).
    """

    __tablename__ = "chat_messages"

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(
        ForeignKey("chat_sessions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # user | assistant
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    # JSON list of ToolRun-shaped dicts (assistant turns only)
    tool_runs_json: Mapped[str | None] = mapped_column(Text)
    # JSON list of Citation-shaped dicts ({file, line, snippet}, assistant
    # turns only) - reloaded history re-renders the clickable source chips.
    citations_json: Mapped[str | None] = mapped_column(Text)
    position: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    session: Mapped[ChatSession] = relationship(back_populates="messages")


class User(Base):
    """One account (M9.1 auth). Three auth methods converge on this row:
    local username/password (``password_hash`` set, ``auth_provider=local``)
    and GitHub/Google OAuth (``oauth_id`` + ``auth_provider``, NULL
    password - Phase B). ``email`` is unique when present; OAuth account
    linking matches on verified email second (Phase B). The FIRST registered
    user is ``is_admin`` (owner decision, Aug 14) and auto-claims legacy
    unowned scans. ``is_active=False`` is account deactivation - a disabled
    user's sessions stop working (401).
    """

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    email: Mapped[str | None] = mapped_column(String(255), unique=True)
    # scrypt$n$r$p$salt$hash (app/auth/security.py); NULL for OAuth-only users.
    password_hash: Mapped[str | None] = mapped_column(String(512))
    # local | github | google
    auth_provider: Mapped[str] = mapped_column(
        String(16), nullable=False, default="local"
    )
    oauth_id: Mapped[str | None] = mapped_column(String(255))
    is_admin: Mapped[bool] = mapped_column(nullable=False, default=False)
    is_active: Mapped[bool] = mapped_column(nullable=False, default=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    # Phase E: partial UNIQUE index - at most ONE admin row ever (the
    # concurrent first-registration race's DB backstop; migration 0014).
    # The predicate differs per dialect (SQLite: `= 1`, Postgres: truthy).
    __table_args__ = (
        Index(
            "ix_users_single_admin",
            "is_admin",
            unique=True,
            sqlite_where=text("is_admin = 1"),
            postgresql_where=text("is_admin"),
        ),
    )


class Session(Base):
    """One login session (M9.1 auth). The cookie carries the opaque
    ``secrets.token_urlsafe(32)`` raw token; ONLY its SHA-256 digest is
    stored here, so a DB leak exposes verifier rows, never usable tokens.
    ``expires_at`` slides forward on use (sliding 7-day window, owner
    decision 5); logout revokes the exact row. Cascades on user delete.
    """

    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    # M9.1 vault: the user's master key wrapped under THIS session's raw
    # token (AES-GCM) - NULL until the vault is unlocked (local users: at
    # login; OAuth users: via POST /auth/vault/unlock). Only ciphertext
    # ever touches the DB - the raw token lives solely in the browser
    # cookie, and the stored digest cannot be inverted to unwrap it.
    vault_wrap: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
