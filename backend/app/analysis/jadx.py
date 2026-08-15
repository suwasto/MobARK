"""jadx decompilation wrapper (APK in -> Java/Kotlin source tree out).

jadx is a JVM CLI tool, invoked strictly as a subprocess. ``decompile()``
produces jadx's ``-d`` layout: ``<out>/sources`` and ``<out>/resources``.
"""
from __future__ import annotations

from pathlib import Path

from app.analysis.subprocess import resolve_binary, run_tool, tail
from app.config import settings


class JadxError(Exception):
    """Decompilation failed (bad APK, missing tool, timeout)."""


def jadx_binary() -> str:
    bin_path = resolve_binary("jadx", "jadx_cmd", tools_subdir="jadx/bin/jadx")
    if bin_path is None:
        raise JadxError("jadx not found on PATH (install it or set MOBARK_JADX_CMD)")
    return bin_path


def _java_env() -> dict[str, str] | None:
    """Point jadx at a specific JVM when MOBARK_JAVA_HOME is set."""
    java_home = settings.java_home
    if not java_home:
        return None
    return {"JAVA_HOME": java_home, "PATH": f"{java_home}/bin"}


def decompile(apk_path: Path, out_dir: Path, timeout: int | None = None) -> None:
    """Decompile ``apk_path`` into ``out_dir``.

    Raises :class:`JadxError` on failure; the orchestrator decides whether
    that fails the scan (decompile is a required stage in M1).
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        jadx_binary(),
        "-d",
        str(out_dir),
        "--no-debug-info",
        "--show-bad-code",
        "--threads-count",
        str(settings.jadx_threads),
        str(apk_path),
    ]
    timeout = timeout or settings.jadx_timeout_seconds
    result = run_tool(cmd, timeout=timeout, env_extra=_java_env())
    if result.timed_out:
        raise JadxError(f"jadx timed out after {timeout}s")
    if result.returncode != 0:
        raise JadxError(
            f"jadx exited {result.returncode}: {tail(result.stderr) or tail(result.stdout)}"
        )
    if not out_dir.is_dir() or not any(out_dir.iterdir()):
        raise JadxError("jadx exited 0 but produced no output")
