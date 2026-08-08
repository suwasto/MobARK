"""Semgrep subprocess wrapper + JSON report normalizer.

Rules live in two vendored directories under ``app/analysis/rules/``:
``masa/`` (hand-curated Java/Kotlin rules) and ``mastg/`` (rules vendored
from the OWASP MASTG repo, see ``scripts/sync_mastg.py``). Semgrep runs
with ``--oss-only --metrics off`` and always as a subprocess.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from app.analysis.base import FindingOut, StageResult
from app.analysis.severity import semgrep_severity
from app.analysis.subprocess import resolve_binary, run_tool, tail
from app.config import settings

RULES_DIR = Path(__file__).parent / "rules"

# MASTG rules embed the control id in the message, e.g. "[MASVS-STORAGE-2]".
MASVS_RE = re.compile(r"\[(MASVS-[A-Z]+-\d+)\]")


class SemgrepError(Exception):
    pass


def semgrep_binary() -> str:
    bin_path = resolve_binary("semgrep", "semgrep_cmd", tools_subdir="semgrep/semgrep")
    if bin_path is None:
        raise SemgrepError("semgrep not found (set MASA_SEMGREP_CMD)")
    return bin_path


def scan_source_tree(
    target: Path,
    report_path: Path,
    timeout: int | None = None,
    app_package: str | None = None,
) -> StageResult:
    """Run semgrep over the decompiled source tree with vendored rules.

    ``app_package`` (e.g. ``com.example.app``) tags findings whose file is
    outside the app's own package as bundled third-party library code, so
    the dashboard can filter or group library noise.
    """
    result = StageResult()
    # Resolve to absolute paths: tools run with cwd=target, so a relative
    # target/report would be re-resolved against the tool's cwd and break.
    target = Path(target).resolve()
    report_path = Path(report_path).resolve()
    config_dirs = _collect_rule_dirs()
    if not config_dirs:
        result.errors.append("no semgrep rules found in app/analysis/rules")
        return result

    cmd = [
        semgrep_binary(),
        "scan",
        "--json",
        "--output",
        str(report_path),
        "--metrics",
        "off",
        "--oss-only",
        "--no-git-ignore",
    ]
    for d in config_dirs:
        cmd += ["--config", str(d)]
    cmd.append(str(target))

    timeout = timeout or settings.semgrep_timeout_seconds
    r = run_tool(cmd, timeout=timeout, cwd=target)
    if r.timed_out:
        result.errors.append(f"semgrep timed out after {timeout}s")
        return result
    if not report_path.is_file():
        result.errors.append(
            f"semgrep failed (exit {r.returncode}): {tail(r.stderr) or tail(r.stdout)}"
        )
        return result
    try:
        result.findings.extend(normalize_report(report_path, target, app_package))
    except ValueError as exc:
        result.errors.append(str(exc))
    return result


def _collect_rule_dirs() -> list[Path]:
    dirs: list[Path] = []
    for name in ("masa", "mastg"):
        d = RULES_DIR / name
        if d.is_dir() and any(d.glob("*.yml")):
            dirs.append(d)
    return dirs


def normalize_report(
    report_path: Path,
    root: Path,
    app_package: str | None = None,
) -> list[FindingOut]:
    """Convert a semgrep ``--json`` report into normalized findings."""
    try:
        data = json.loads(report_path.read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid semgrep JSON report: {exc}") from exc

    root_str = str(root)
    # com.example.app -> com/example/app/ ; used to split first-party vs library.
    pkg_prefix = app_package.replace(".", "/") + "/" if app_package else None
    findings: list[FindingOut] = []
    for item in data.get("results", []):
        if not isinstance(item, dict):
            continue
        check_id = item.get("check_id") or "unknown-rule"
        path = item.get("path") or ""
        # Strip the scan root so paths are relative (report paths are absolute).
        rel_path = (
            path[len(root_str) + 1 :] if path.startswith(root_str + "/") else path
        )
        # jadx nests app code under sources/; tolerate both the root=<sources>
        # convention (pipeline) and root=<decompiled> (unit tests) when tagging.
        scope_path = rel_path[8:] if rel_path.startswith("sources/") else rel_path
        in_app_package = bool(pkg_prefix) and scope_path.startswith(pkg_prefix)
        extra = item.get("extra") or {}
        message = extra.get("message") or ""
        native_severity = str(extra.get("severity") or "INFO").upper()
        category = None
        m = MASVS_RE.search(message)
        if m:
            category = m.group(1)
        start = item.get("start") or {}
        title = message.strip().splitlines()[0][:500] if message.strip() else check_id
        detail: dict = {
            "check_id": check_id,
            "native_severity": extra.get("severity"),
            "message": message,
            "metadata": extra.get("metadata"),
        }
        if pkg_prefix:
            detail["in_app_package"] = in_app_package
            detail["scope"] = "app" if in_app_package else "third_party_library"
        findings.append(
            FindingOut(
                tool="semgrep",
                title=title,
                severity=semgrep_severity(check_id, native_severity),
                file_path=rel_path or None,
                line_number=start.get("line"),
                category=category,
                detail=detail,
            )
        )
    return findings
