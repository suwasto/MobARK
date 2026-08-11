"""Gitleaks subprocess wrapper + JSON report normalizer.

Invoked as ``gitleaks dir`` (file/dir scan, not git history - we scan the
decompiled tree). ``--exit-code 0`` is important: gitleaks exits 1 when
leaks are *found*, which for us is a normal scan result, not a failure.
"""
from __future__ import annotations

import json
from pathlib import Path

from app.analysis.base import FindingOut, StageResult
from app.analysis.severity import gitleaks_severity
from app.analysis.subprocess import resolve_binary, run_tool, tail
from app.config import settings


class GitleaksError(Exception):
    pass


def gitleaks_binary() -> str:
    bin_path = resolve_binary("gitleaks", "gitleaks_cmd", tools_subdir="gitleaks/gitleaks")
    if bin_path is None:
        raise GitleaksError("gitleaks not found on PATH (set MASA_GITLEAKS_CMD)")
    return bin_path


def scan_directory(
    target: Path,
    report_path: Path,
    timeout: int | None = None,
    config: Path | None = None,
) -> StageResult:
    """Run gitleaks over ``target`` and write a JSON report to ``report_path``.

    ``config`` (optional) points at a custom TOML ruleset passed via
    ``--config`` - e.g. the iOS keychain-accessibility rules
    (``app/analysis/resources/gitleaks_ios.toml``, M4 Layer 1).
    """
    result = StageResult()
    # Resolve to absolute paths: the tool runs with cwd=target, so relative
    # target/report args would be re-resolved against the tool's cwd and break.
    target = Path(target).resolve()
    report_path = Path(report_path).resolve()
    cmd = [
        gitleaks_binary(),
        "dir",
        "--no-banner",
        "--exit-code",
        "0",
        "--report-format",
        "json",
        "--report-path",
        str(report_path),
        "--max-target-megabytes",
        "50",
    ]
    if config is not None:
        cmd += ["--config", str(Path(config).resolve())]
    cmd.append(str(target))
    timeout = timeout or settings.gitleaks_timeout_seconds
    r = run_tool(cmd, timeout=timeout, cwd=target)
    if r.timed_out:
        result.errors.append(f"gitleaks timed out after {timeout}s")
        return result
    if not report_path.is_file():
        result.errors.append(f"gitleaks failed (exit {r.returncode}): {tail(r.stderr)}")
        return result
    try:
        result.findings.extend(normalize_report(report_path, target))
    except ValueError as exc:
        result.errors.append(str(exc))
    return result


def normalize_report(report_path: Path, root: Path) -> list[FindingOut]:
    """Convert a gitleaks JSON report into normalized findings.

    ``File`` paths are rewritten relative to ``root`` so stored findings
    reference ``smali/...``, ``resources/...`` etc. rather than absolute
    container paths.
    """
    try:
        raw = json.loads(report_path.read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid gitleaks JSON report: {exc}") from exc

    root_str = str(root)
    findings: list[FindingOut] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        file_path = item.get("File") or ""
        if file_path.startswith(root_str + "/"):
            file_path = file_path[len(root_str) + 1 :]
        rule_id = item.get("RuleID") or "unknown-rule"
        findings.append(
            FindingOut(
                tool="gitleaks",
                title=f"Hardcoded secret detected: {rule_id}",
                severity=gitleaks_severity(rule_id),
                file_path=file_path or None,
                line_number=item.get("StartLine"),
                detail={
                    "rule_id": rule_id,
                    "rule_description": item.get("Description"),
                    "secret": item.get("Secret"),
                    "match": item.get("Match"),
                    "entropy": item.get("Entropy"),
                    "tags": item.get("Tags") or [],
                    "fingerprint": item.get("Fingerprint"),
                },
            )
        )
    return findings
