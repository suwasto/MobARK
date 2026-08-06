"""Shared types for MASA analysis stages.

``FindingOut`` is the single normalized findings shape every stage emits.
The DB persistence layer maps it onto the ``findings`` table.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

# Allowed severity values — kept in sync with the findings table.
SEVERITIES = ("critical", "high", "medium", "low", "info")

# Tools that produce findings in M1.
TOOL_ANDROGUARD = "androguard"
TOOL_GITLEAKS = "gitleaks"
TOOL_SEMGREP = "semgrep"
# Tools that produce findings in M2.
TOOL_PLIST = "plist"
TOOL_LIEF = "lief"
# M4 Layer 1: iOS Mach-O import-table scanner (known-insecure API blocklist).
TOOL_SYMBOLS = "symbols"


@dataclass
class FindingOut:
    """A normalized finding produced by any analysis stage."""

    tool: str  # androguard | gitleaks | semgrep | plist | lief
    title: str
    severity: str
    file_path: str | None = None
    line_number: int | None = None
    category: str | None = None  # MASVS v2 control id, e.g. MASVS-NETWORK-1
    mastg_test_id: str | None = None
    detail: dict | None = None
    # True when the finding comes from static analysis alone (no runtime/
    # dynamic confirmation). M2 sets it on every iOS finding; M1 findings are
    # static too, so the column defaults to True across the board.
    static_only: bool = True

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"invalid severity: {self.severity!r}")


@dataclass
class StageResult:
    """Result of one analysis stage: findings plus diagnostics."""

    findings: list[FindingOut] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    # App package name (e.g. ``com.example.app``) when a stage knows it.
    # Used to scope code findings to first-party vs bundled-library code.
    app_package: str | None = None
    # Free-form stage metadata (bundle ids, binary headers, ...) that is not
    # itself findings but should be visible to the orchestrator/report.
    meta: dict = field(default_factory=dict)

    def extend(self, other: StageResult) -> None:
        self.findings.extend(other.findings)
        self.errors.extend(other.errors)
        self.warnings.extend(other.warnings)
        self.meta.update(other.meta)


@dataclass
class ScanResult:
    """Aggregate result of a full scan pipeline."""

    platform: str = "android"
    findings: list[FindingOut] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    decompiled_root: Path | None = None
    app_root: Path | None = None  # unpacked iOS bundle root (Payload/*.app)
    meta: dict = field(default_factory=dict)
