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


@dataclass
class FindingOut:
    """A normalized finding produced by any analysis stage."""

    tool: str  # androguard | gitleaks | semgrep
    title: str
    severity: str
    file_path: str | None = None
    line_number: int | None = None
    category: str | None = None  # MASVS v2 control id, e.g. MASVS-NETWORK-1
    mastg_test_id: str | None = None
    detail: dict | None = None

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

    def extend(self, other: StageResult) -> None:
        self.findings.extend(other.findings)
        self.errors.extend(other.errors)
        self.warnings.extend(other.warnings)


@dataclass
class ScanResult:
    """Aggregate result of a full scan pipeline."""

    platform: str = "android"
    findings: list[FindingOut] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    decompiled_root: Path | None = None
