"""Safe subprocess runner for MobARK's external CLI tools.

Every tool MobARK shells out to (jadx, gitleaks, semgrep) goes through
:func:`run_tool` so policy lives in one place: per-tool timeouts, bounded
capture, and explicit timed-out reporting. Tools are always invoked as
subprocesses, never imported, per the project's license posture.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from app.config import settings


@dataclass
class RunResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


def resolve_binary(name: str, env_var: str, tools_subdir: str | None = None) -> str | None:
    """Resolve a tool binary: explicit env override, tools dir, then PATH."""
    override = getattr(settings, env_var, None)
    if override:
        return override
    if tools_subdir:
        candidate = settings.tools_dir / tools_subdir
        if candidate.is_file():
            return str(candidate)
    return shutil.which(name)


def run_tool(
    cmd: list[str],
    *,
    timeout: int,
    cwd: Path | None = None,
    env_extra: dict[str, str] | None = None,
) -> RunResult:
    """Run a tool, capturing output. Never raises on tool failure.

    Timeouts and non-zero exit codes are reported in the result; callers
    decide whether that constitutes a scan failure (per-stage policy).
    """
    env = None
    if env_extra:
        env = os.environ.copy()
        env.update(env_extra)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=env,
            errors="replace",
        )
    except subprocess.TimeoutExpired as exc:
        return RunResult(
            returncode=-1,
            stdout=_decode(exc.stdout),
            stderr=_decode(exc.stderr),
            timed_out=True,
        )
    return RunResult(proc.returncode, proc.stdout, proc.stderr)


def _decode(data: bytes | str | None) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", "replace")
    return data


def tail(text: str, limit: int = 4000) -> str:
    """Last ``limit`` characters of captured output, for error messages."""
    return text[-limit:] if text else ""
