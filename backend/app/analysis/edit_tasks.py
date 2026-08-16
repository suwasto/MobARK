"""M8 follow-up (Aug 16): the agent's task-list artifact.

The sequential edit flow (propose one file per turn, the human reviews, then
the next file) used to re-derive "what is left of the task" from a flat list
of edit rows on every "continue" - re-rendering the full findings context and
history each time, and looping forever on single-file requests. This module
replaces that with a persistent plan: a ``task-list.md`` artifact the agent
writes and re-reads, kept OUTSIDE the decompiled tree (``work/<scan_id>/
agent/``) so rebuilds and tree reads never see it.

Flow (see chat.py): a multi-file change request makes the agent call
``write_task_list`` with the plan, then propose the TOP pending task. When
the human applies/rejects a proposal, the route marks the matching task in
the file (``[x]`` applied / ``[~]`` rejected) and either starts the next
turn automatically (apply, or a task still pending) or pauses (reject - the
human owns whether the remaining tasks are still wanted). Single-file
requests never create a file, so resolving them has nothing to advance - no
loop. A new change request supersedes a stale list (kept as
``task-list.superseded-<ts>.md``).

The agent writes the file FREEFORM (decision: faithful to the artifact
model), so the parser is deliberately tolerant: it extracts a ``# Task:``
header, checkbox-style task lines (``- [ ]`` / ``- [x]`` / ``- [~]`` /
``- [done]`` / ``- [todo]`` ...), an optional ``T<n>`` token, and an
optional ``(file: <path>)`` target, ignoring everything else. A file with
no recognizable task lines is treated as NO task list (the old
review-state behavior remains the fallback), so a mangled file can never
drive the auto-advance.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from pathlib import Path

from app.config import settings

TASK_FILE_NAME = "task-list.md"
SUPERSEDED_PREFIX = "task-list.superseded-"

# Statuses a task line can carry (parsed from the checkbox marker).
PENDING = "pending"
DONE = "done"
REJECTED = "rejected"

_MARKER = {PENDING: "[ ]", DONE: "[x]", REJECTED: "[~]"}

# Best-effort file-path extraction from a freeform task line: an explicit
# ``(file: path)`` first, then any recognizable editable path shape.
_FILE_EXPLICIT_RE = re.compile(r"\((?:file|target|path)\s*:\s*([^)]+)\)", re.IGNORECASE)
_FILE_PATH_RE = re.compile(
    r"\b(smali(?:_\w+)?/[\w./-]+\.smali|res/[\w./-]+|AndroidManifest\.xml)\b"
)
_REQUEST_RE = re.compile(r"^#\s*(?:task|request|goal|plan)\s*:\s*(.+)$", re.IGNORECASE)
_TASK_LINE_RE = re.compile(r"^\s*[-*]\s*\[\s*([^\]]*?)\s*\]\s*(.+?)\s*$")
_TOKEN_RE = re.compile(r"^(T\d+)\b")

# How much markdown the agent may write (freeform but bounded).
MAX_TASK_LIST_CHARS = 20_000


@dataclass(frozen=True)
class TaskItem:
    """One parsed task line."""

    token: str
    description: str
    status: str  # pending | done | rejected
    file_path: str | None = None
    line: int = 0  # 1-based line number in the raw file (for rewriting)

    @property
    def resolved(self) -> bool:
        return self.status != PENDING


@dataclass
class TaskList:
    """The parsed artifact - the raw text is kept so task rewrites preserve
    the agent's freeform formatting (only the checkbox marker changes)."""

    path: Path
    raw: str
    request: str
    tasks: list[TaskItem]

    def next_pending(self) -> TaskItem | None:
        return next((t for t in self.tasks if t.status == PENDING), None)

    def pending(self) -> list[TaskItem]:
        return [t for t in self.tasks if t.status == PENDING]


def _parse_status(marker: str) -> str:
    m = marker.strip().lower()
    if m in ("", " ", "-", "todo", "pending", "open", "waiting"):
        return PENDING
    if m in ("x", "done", "yes", "completed", "complete"):
        return DONE
    # ``~`` / ``r`` are the agent's rejected markers (kept distinct from
    # pending so the advance loop never re-proposes a rejected task).
    if m in ("r", "rejected", "no", "skip", "skipped", "~"):
        return REJECTED
    return PENDING  # unknown markers stay pending - never auto-skip


def _parse_file_path(desc: str) -> str | None:
    explicit = _FILE_EXPLICIT_RE.search(desc)
    if explicit:
        return explicit.group(1).strip().strip("`'\"")
    m = _FILE_PATH_RE.search(desc)
    return m.group(1) if m else None


def task_file_path(scan_id: int) -> Path:
    """The artifact path for a scan - under ``work/<scan_id>/agent/``,
    outside the decompiled tree so tree reads / rebuilds never touch it."""
    return settings.data_dir / "work" / str(scan_id) / "agent" / TASK_FILE_NAME


def parse(content: str, path: Path | None = None) -> TaskList:
    """Tolerantly parse the artifact. A file with no recognizable task lines
    still yields an empty TaskList (callers treat empty == no plan)."""
    request = ""
    tasks: list[TaskItem] = []
    fallback = 1  # synthetic T<n> when the agent omitted tokens
    for n, line in enumerate(content.splitlines(), start=1):
        rm = _REQUEST_RE.match(line)
        if rm and not request:
            request = rm.group(1).strip()
            continue
        tm = _TASK_LINE_RE.match(line)
        if not tm:
            continue
        status = _parse_status(tm.group(1))
        desc = tm.group(2).strip()
        token_m = _TOKEN_RE.match(desc)
        if token_m:
            token = token_m.group(1)
            desc = desc[token_m.end() :].lstrip(" .:-")
        else:
            token = f"T{fallback}"
            fallback += 1
        tasks.append(
            TaskItem(
                token=token,
                description=desc,
                status=status,
                file_path=_parse_file_path(desc),
                line=n,
            )
        )
    return TaskList(path=path or task_file_path(0), raw=content, request=request, tasks=tasks)


def load_task_list(scan_id: int) -> TaskList | None:
    """The parsed artifact, or None when absent or unreadable. An empty file
    (no task lines) yields an empty TaskList - NOT None - so a cleared plan
    still suppresses the stale-list fallback."""
    path = task_file_path(scan_id)
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    return parse(content, path)


def _write(scan_id: int, content: str) -> TaskList:
    path = task_file_path(scan_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return parse(content, path)


def write_task_list(scan_id: int, content: str) -> TaskList:
    """Store a freshly authored artifact (the agent's write_task_list tool).
    Bounded; returns the parsed list."""
    if len(content) > MAX_TASK_LIST_CHARS:
        content = content[:MAX_TASK_LIST_CHARS] + "\n… [truncated]"
    return _write(scan_id, content)


def supersede_task_list(scan_id: int) -> TaskList | None:
    """Rename an existing artifact aside (kept for the record) so a NEW
    change request starts with a clean plan. No-op when absent."""
    path = task_file_path(scan_id)
    if not path.is_file():
        return None
    ts = time.strftime("%Y%m%d-%H%M%S")
    archived = path.with_name(f"{SUPERSEDED_PREFIX}{ts}.md")
    try:
        path.rename(archived)
    except OSError:
        return None
    try:
        return parse(archived.read_text(encoding="utf-8", errors="replace"), archived)
    except OSError:
        return None


def mark_task_resolved(
    scan_id: int, file_path: str, *, verdict: str
) -> TaskList | None:
    """Flip the matching pending task's marker in the artifact: ``applied``
    -> ``[x]``, ``rejected`` -> ``[~]`` (the human owns the verdict; the
    advance loop skips rejected tasks and never re-proposes them).

    The task matching an edit is the first PENDING task whose ``(file:)``
    target equals the edit's path; when the freeform line carries no path
    (or no task matches), fall back to the first pending task so a resolve
    never silently orphans the loop. Returns the updated list, or None when
    there is no artifact / no pending task to mark (a single-file request
    without a task list - nothing to advance)."""
    tl = load_task_list(scan_id)
    if tl is None or not tl.tasks:
        return None
    marker = "[x]" if verdict == "applied" else "[~]"
    target: TaskItem | None = None
    for t in tl.tasks:
        if t.status == PENDING and t.file_path == file_path:
            target = t
            break
    if target is None:
        target = tl.next_pending()
    if target is None:
        return tl  # nothing pending - the plan is already exhausted
    lines = tl.raw.splitlines()
    if 1 <= target.line <= len(lines):
        lines[target.line - 1] = re.sub(
            r"\[\s*[^\]]*?\s*\]", marker, lines[target.line - 1], count=1
        )
    return _write(scan_id, "\n".join(lines))


def render_section(tl: TaskList) -> str:
    """The TASK LIST section for the system prompt - the compact plan the
    agent reads to know what is done and what is next."""
    lines: list[str] = []
    if tl.request:
        lines.append(f"# Task: {tl.request}")
    for t in tl.tasks:
        fp = f" (file: {t.file_path})" if t.file_path else ""
        lines.append(f"- {_MARKER[t.status]} {t.token} {t.description}{fp}")
    return "\n".join(lines)


def pause_message(tl: TaskList, file_path: str) -> str:
    """The chat message after a REJECT pauses the loop: the remaining
    pending tasks, and what the human can do (continue / adjust / stop)."""
    pending = tl.pending()
    if not pending:
        return (
            f"The proposal for {file_path} was rejected and the task list is "
            "now complete. Say the word if you want anything redone or changed."
        )
    listing = ", ".join(f"{t.token} ({t.description[:60]})" for t in pending)
    return (
        f"The proposal for {file_path} was rejected, so I paused the task "
        f"here - the remaining work may no longer be wanted. Still pending: "
        f"{listing}. Reply 'continue' to proceed with the next pending task, "
        "tell me how to adjust, or say stop."
    )
