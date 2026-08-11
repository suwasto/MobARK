"""Dev-only deterministic fake LLM (M6 follow-up) — demo the Agent dock's
live tool steps + token streaming with zero Ollama.

``MASA_FAKE_MODEL=1`` (``Settings.fake_model_enabled``) seeds a ``fake``
backend into the M3 store; ``model/client.py`` short-circuits its chat calls
here. The fake never touches a real server — instead it scripts one
deterministic turn that still runs the REAL agent loop + REAL tools:

  round 1: a little \"thinking aloud\" text (streamed tokens), then two tool
           calls — ``search_code`` (the pattern split across two streamed
           deltas on purpose, so the demo also exercises the defensive
           tool-call accumulation path) and ``read_manifest``. Both execute
           against the scan's real tree, so the steps show real hit counts.
  round 2: a final answer composed from the REAL tool results — it cites the
           actual first search hit (``file:line`` -> clickable src-chip) when
           one exists, and mentions the manifest summary otherwise.

The script itself is constant; only the scan's real data shapes the final
text. Calls without a ``tools`` kwarg (insights explain/summary, the
plain-chat fallback) get a canned plain answer. ``health`` short-circuits the
Settings probe for the fake so the card renders green.
"""
from __future__ import annotations

import json
import re
from types import SimpleNamespace

FAKE_MODEL = "demo"

# Deterministic script constants.
_THINK_TEXT = (
    "Let me search the decompiled source for WebView usage, "
    "then check what the manifest declares."
)
# search_code arguments split across two streamed chunks — the demo exercises
# _accumulate_tool_call_deltas' concatenation exactly like a real local server.
_TOOL_CALLS_STREAM = [
    {
        "index": 0,
        "id": "call_search",
        "function": {"name": "search_code", "arguments": '{"pattern": "WebV'},
    },
    {"index": 0, "function": {"arguments": 'iew"}'}},
    {
        "index": 1,
        "id": "call_manifest",
        "function": {"name": "read_manifest", "arguments": "{}"},
    },
]
_PLAIN_ANSWER = (
    "This is a dev-demo answer from the built-in fake model "
    "(MASA_FAKE_MODEL=1) — no LLM was contacted. It streams like a real "
    "answer so the dock's token + tool-step UI can be verified without "
    "Ollama running."
)

# M7: the web-research demo script — used when the offered tool set includes
# the gated web tools (scan opt-in on + Active engine). Mirrors the flagship
# "does library X have known CVEs?" case with REAL tools against REAL search
# results: round 1 streams thinking + web_search (the query is the USER'S OWN
# question text, so a manual test can type its own search), round 2
# web_fetch's the top hit's URL, round 3 composes the answer citing the
# source URL — from the page when it read cleanly, else from the search
# results themselves (a bot-hostile page must never be retried until the
# round limit; hit live in the containerized e2e, Aug 9: medium.com 403s the
# honest MASA UA).
_WEB_THINK_TEXT = (
    "This needs current external information — let me search the web for "
    "known advisories, then read the top source."
)
# Fallback query when the user's question is empty / too short to search.
_WEB_SEARCH_QUERY = "InsecureBankv2 known vulnerabilities CVE"


def _web_query(messages: list[dict]) -> str:
    """The round-1 web_search query: the user's ACTUAL question text when it's
    a plausible query (>=4 chars), else the canned demo query — so a manual
    web-search test types its own search and the fake runs it verbatim (a
    real model would paraphrase; the fake is a script)."""
    for m in reversed(messages):
        if m.get("role") == "user" and (m.get("content") or "").strip():
            q = m["content"].strip()
            return q if len(q) >= 4 else _WEB_SEARCH_QUERY
    return _WEB_SEARCH_QUERY


def _offers_web(tools: list[dict] | None) -> bool:
    """True when the offered tool schemas include the gated web tools."""
    if not tools:
        return False
    return any(
        (t.get("function") or {}).get("name") == "web_search" for t in tools
    )


def _compose_web_answer(messages: list[dict]) -> str:
    """Final web-research answer from the REAL tool results: cite the fetched
    page (title + first text + final URL) when available, else the top search
    result — so the demo renders clickable URLs, like a real model's answer.
    A failed page read is acknowledged but never rendered as evidence."""
    results: list[dict] = []
    page: dict = {}
    fetch_failed = False
    for result in _tool_results(messages):
        if isinstance(result, dict) and "error" in result:
            fetch_failed = True
            continue  # a failed tool must never render as evidence
        if isinstance(result, list) and result and isinstance(result[0], dict):
            if "url" in result[0]:
                results = result
        elif isinstance(result, dict) and "url" in result and "text" in result:
            page = result
    tail = (
        "This is a dev-demo answer from the built-in fake model "
        "(MASA_FAKE_MODEL=1); no LLM was contacted."
    )
    if page:
        title = page.get("title") or page.get("url")
        excerpt = (page.get("text") or "").strip()[:220]
        return (
            "I researched this via web search and read the top advisory. "
            f"**{title}** — {excerpt} Source: {page.get('url')}. " + tail
        )
    if results:
        top = results[0]
        blocked = (
            " (the top page blocked direct reading, so I'm citing the search "
            "result itself)"
            if fetch_failed
            else ""
        )
        return (
            f"Web search returned {len(results)} results; the top one is "
            f"`{top.get('title')}` ({top.get('url')}){blocked}. " + tail
        )
    return _PLAIN_ANSWER


def _web_response(messages: list[dict]):
    """Buffered round response for the web-research demo script.

    Deterministic 3-round shape (fits the default ``max_tool_rounds=3``):
    round 1 issues ``web_search``; round 2 fetches the TOP result once;
    round 3 composes the final cited answer — from the fetched page when it
    read cleanly, else from the search results themselves. A failed fetch
    (e.g. HTTP 403 from a bot-hostile page like medium.com — hit live in the
    containerized e2e, Aug 9) is NEVER retried on the same URL: the old
    script re-fetched it until the round limit and the answer lost its
    citation.
    """
    results = _tool_results(messages)
    search_rows: list[dict] = []
    fetch_tried = False
    for r in results:
        if isinstance(r, list) and r and isinstance(r[0], dict) and "url" in r[0]:
            search_rows = r
        elif isinstance(r, dict) and ("text" in r or "error" in r):
            fetch_tried = True  # a page read OR a failed fetch attempt
    if not search_rows and not fetch_tried:
        # No results yet (or the first search came back empty) — search with
        # the user's own question text (manual tests type their query).
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content=_WEB_THINK_TEXT,
                        tool_calls=[
                            _tool_call(
                                "call_search",
                                "web_search",
                                json.dumps({"query": _web_query(messages)}),
                            )
                        ],
                    )
                )
            ]
        )
    if search_rows and not fetch_tried:
        # Round 2: fetch the top result exactly once.
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content="Now reading the top advisory.",
                        tool_calls=[
                            _tool_call(
                                "call_fetch",
                                "web_fetch",
                                json.dumps({"url": search_rows[0]["url"]}),
                            )
                        ],
                    )
                )
            ]
        )
    # Round 3 (fetch attempted — success OR failure): compose the answer.
    return SimpleNamespace(
        choices=[
            SimpleNamespace(message=SimpleNamespace(content=_compose_web_answer(messages)))
        ]
    )


def _web_stream_chunks(messages: list[dict]):
    """Streaming chunks for the web-research demo script (same round logic as
    ``_web_response``, tokenized for the SSE demo)."""
    resp = _web_response(messages)
    message = resp.choices[0].message
    content = message.content or ""
    tool_calls = list(getattr(message, "tool_calls", None) or [])
    for word in content.split(" "):
        yield _chunk(content=word + " ")
    for tc in tool_calls:
        fn = tc.function
        yield _chunk(
            tool_calls=[
                {
                    "index": 0,
                    "id": tc.id,
                    "function": {"name": fn.name, "arguments": fn.arguments},
                }
            ]
        )


# M8 Phase D: the edit-demo script — the flagship "ask the agent to edit"
# flow with zero Ollama. Deterministic 3-round shape (fits the default
# max_tool_rounds=3), running the REAL search_code + read_editable_file +
# propose_smali_edit tools against the scan's real trees:
#   round 1: thinking text + search_code (a content keyword from the user's
#            OWN question, so a manual test types its own request and the
#            demo searches for a real term in it — a real model would
#            paraphrase; the fake is a script) + read_editable_file on the
#            target file (the "(Target editable file: ...)" hint when present,
#            else AndroidManifest.xml)
#   round 2: propose_smali_edit — a REAL proposed edit row + unified diff
#            (manifest: toggles android:debuggable; smali: appends a # comment)
#   round 3: a cited answer naming the top search hit + the stored proposal
#            for human review (it is NEVER auto-applied — the Review edits
#            panel owns that).
# A failed read/propose composes an honest answer instead of retrying, so the
# script always lands within the round limit (M7 web-demo precedent).
_EDIT_THINK_TEXT = (
    "Let me search the decompiled code for the relevant logic, read the "
    "editable file, then propose the change for your review."
)
# The ✨ Ask agent bar used to append this hint so the proposal targets the
# OPEN file — the parser stays for compatibility (the dock sends plain
# questions now; a real model would just follow the conversation).
_EDIT_TARGET_RE = re.compile(r"\(Target editable file: ([^)\n]+)\)")

# Words too generic to search for (the round-1 search_code pattern is the
# first 4+-char content word from the user's question that isn't one of
# these) — "disable password validation in authentication" -> "password".
_EDIT_SEARCH_STOPWORDS = frozenset(
    {
        "the", "this", "that", "with", "from", "have", "your", "please",
        "make", "change", "remove", "disable", "enable", "fix", "edit",
        "add", "and", "for", "are", "was", "build", "test", "app",
        "code", "file", "check", "turn", "off", "on",
    }
)

# Questions that read as edit requests (the bar always counts via the hint).
_EDIT_KEYWORDS = (
    "edit", "propose", "modify", "change", "fix", "harden", "append",
    "add a", "remove", "disable", "enable", "toggle", "patch",
)

# Path-ish @mentions in the dock: ``@sources/com/foo/A.java`` etc. The
# frontend ALSO sends the paths structurally (ChatRequest.mentioned_files),
# but the fake is a script over the raw messages, so it parses the mention
# text like a real model reading the question.
_MENTION_RE = re.compile(
    r"@([A-Za-z0-9_./-]+\.(?:java|kt|kts|smali|xml|plist|json|txt|"
    r"properties|yml|yaml|html|strings|entitlements))"
)


def _offers_edit(tools: list[dict] | None) -> bool:
    """True when the offered tool schemas include the M8 edit tools."""
    if not tools:
        return False
    return any(
        (t.get("function") or {}).get("name") == "propose_smali_edit"
        for t in tools
    )


def _edit_requested(messages: list[dict], tools: list[dict] | None) -> bool:
    """Run the edit demo only for edit-y questions when edit tools are
    offered: the bar's target-file hint always counts, an @-mention of an
    EDITABLE path (smali/manifest/res) counts too (the dock's flagship
    "@file … change it" flow), plus edit keywords for plain dock questions.
    A jadx-source mention alone (e.g. "@A.java what does this do?") is a
    question, not an edit request — it keeps the main demo."""
    if not _offers_edit(tools):
        return False
    for m in reversed(messages):
        if m.get("role") == "user":
            content = m.get("content") or ""
            if _EDIT_TARGET_RE.search(content):
                return True
            for hit in _MENTION_RE.findall(content):
                if _mention_to_edit_path(hit) is not None:
                    return True
            q = content.lower()
            return any(k in q for k in _EDIT_KEYWORDS)
    return False


def _mention_to_edit_path(mention: str) -> str | None:
    """Tree-path mention -> edits-table path when the mention is editable
    (smali*/res/AndroidManifest.xml), else None (jadx sources are read-only
    — a real model would find_smali_sibling; the demo treats them as a
    question, not an edit target)."""
    from app.analysis import editable

    root, sep, rel = mention.partition("/")
    if not sep:
        return None
    if root == editable.MANIFEST_ROOT:
        if rel == editable.MANIFEST_ROOT:
            return editable.MANIFEST_ROOT
        return None  # manifest tree root only serves the manifest file
    if root == "res" or root == "smali" or root.startswith("smali_classes"):
        return editable.edit_path_from_tree_path(root, rel)
    return None


def _jadx_mention(messages: list[dict]) -> str | None:
    """The first ``@sources/...`` mention in the user's question, if any —
    a jadx class the demo maps to its editable smali sibling via the REAL
    find_smali_sibling tool (the flagship search -> map -> read -> propose
    flow, driven by a mention instead of a search hit)."""
    for m in reversed(messages):
        if m.get("role") != "user":
            continue
        for hit in _MENTION_RE.findall(m.get("content") or ""):
            if hit.startswith("sources/") and hit.endswith((".java", ".kt", ".kts")):
                return hit
    return None


def _edit_target(messages: list[dict]) -> str:
    """The demo's target: an @-mentioned editable path first (the dock's
    "@file … change it" flow), else the bar's ``(Target editable file:
    ...)`` hint when it names a supported editable path (.smali /
    AndroidManifest.xml), else the always-present decoded
    AndroidManifest.xml."""
    for m in reversed(messages):
        if m.get("role") != "user":
            continue
        for hit in _MENTION_RE.findall(m.get("content") or ""):
            edit_path = _mention_to_edit_path(hit)
            if edit_path is not None:
                return edit_path
        hit = _EDIT_TARGET_RE.search(m.get("content") or "")
        if hit:
            target = hit.group(1).strip()
            if target == "AndroidManifest.xml" or target.endswith(".smali"):
                return target
        return "AndroidManifest.xml"
    return "AndroidManifest.xml"


def _edit_instruction(messages: list[dict]) -> str:
    """The user's own instruction text (the bar hint line + @-mentions
    stripped) — the proposal's instruction column + the smali comment show
    it verbatim."""
    for m in reversed(messages):
        if m.get("role") == "user":
            content = _MENTION_RE.sub(
                "", _EDIT_TARGET_RE.sub("", m.get("content") or "")
            ).strip()
            return content if content else "MASA demo edit"
    return "MASA demo edit"


def _edit_search_pattern(messages: list[dict]) -> str:
    """The round-1 search_code pattern: a CONTENT keyword from the user's own
    question (the first 4+-char word that isn't a stopword, @-mentions and
    the bar hint stripped), so a manual test types its own request and the
    demo searches for a real term in it — a real model would paraphrase the
    request; the fake is a script (M7 web-demo precedent: the user's question
    is the query)."""
    for m in reversed(messages):
        if m.get("role") != "user":
            continue
        content = _MENTION_RE.sub(
            "", _EDIT_TARGET_RE.sub("", m.get("content") or "")
        )
        for word in re.findall(r"[A-Za-z_][A-Za-z0-9_]{3,}", content):
            if word.lower() not in _EDIT_SEARCH_STOPWORDS:
                return word
    return "password"


def _edit_new_content(
    target: str, original: str, instruction: str
) -> str | None:
    """The demo's NEW content built from the REAL current content — a
    deterministic, byte-exact change that yields a real diff:
    - AndroidManifest.xml: toggle ``android:debuggable`` (true<->false; insert
      false on the <application> tag when absent) — the classic pentest edit.
    - .smali: append a ``#`` comment (valid smali, a harmless real change).
    - Anything else (res XML etc.): None — the demo never guesses an XML edit
      that could duplicate an attribute or break the document (honest fallback
      over a broken proposal).
    """
    if target == "AndroidManifest.xml":
        if 'android:debuggable="true"' in original:
            return original.replace(
                'android:debuggable="true"', 'android:debuggable="false"', 1
            )
        if 'android:debuggable="false"' in original:
            return original.replace(
                'android:debuggable="false"', 'android:debuggable="true"', 1
            )
        if "android:debuggable" in original:
            return None  # unexpected value — never guess (duplicate-attr risk)
        # The first REAL <application> tag — never one inside an XML comment
        # (a comment like `<!-- <application ... -->` would otherwise get a
        # corrupt insert; an unclosed comment before the match = inside one).
        tag = None
        for m in re.finditer(r"<application\b", original):
            head = original[: m.start()]
            if head.count("<!--") > head.count("-->"):
                continue  # inside a comment
            tag = m
            break
        if tag is None:
            return None
        idx = tag.end()
        return original[:idx] + ' android:debuggable="false"' + original[idx:]
    if target.endswith(".smali"):
        note = f"# MASA demo edit — {instruction}"
        return original.rstrip() + "\n\n" + note + "\n"
    return None


def _compose_edit_answer(propose: dict, search_hits: list[dict]) -> str:
    """Final answer from the REAL stored proposal: cite the file + edit id,
    show the first diff lines, and point at the Review edits panel — the
    human applies, never the agent (decision 7). When the round-1
    ``search_code`` found hits, the top hit is cited too (the dock renders
    it as a clickable file:line chip), so the demo shows the full
    search -> read -> propose -> review flow."""
    edit_id = propose.get("edit_id")
    file_path = propose.get("file_path")
    head = (
        f"I proposed an edit to `{file_path}` — stored as edit "
        f"#{edit_id} for your review (nothing was applied automatically)."
    )
    if search_hits:
        top = search_hits[0]
        line = top.get("line")
        loc = f"{top['file']}:{line}" if line else top["file"]
        head = (
            f"I found the relevant code at `{loc}` — `"
            f"{(top.get('snippet') or '').strip()[:80]}`. " + head
        )
    diff = propose.get("unified_diff") or ""
    if diff:
        lines = diff.splitlines()[:10]
        head += " The diff starts:\n```diff\n" + "\n".join(lines) + "\n```"
    head += (
        " Open the Review edits panel and Apply or Reject it per file — then "
        "Edit & recompile to build a resigned test APK."
    )
    return (
        head + " This is a dev-demo answer from the built-in fake model "
        "(MASA_FAKE_MODEL=1); no LLM was contacted."
    )


def _compose_edit_failed(error: str) -> str:
    return (
        f"I could not propose the edit: {error}. "
        "This is a dev-demo answer from the built-in fake model "
        "(MASA_FAKE_MODEL=1); no LLM was contacted."
    )


def _edit_response(messages: list[dict]):
    """Buffered round response for the edit-demo script (see the module
    comment for the round shapes). Deterministic state machine over the REAL
    tool results; a failed step composes an honest answer rather than
    retrying the same call until the round limit.

    Shapes (default max_tool_rounds=3 -> 4 model rounds available):
    - editable mention / no mention: round 1 search_code + read_editable_file
      (target), round 2 propose, round 3 answer.
    - jadx ``@sources/...`` mention: round 1 search_code + find_smali_sibling
      (map the class to its editable smali), round 2 read_editable_file
      (sibling), round 3 propose, round 4 answer — the search -> map ->
      read -> propose flow driven by a mention.
    """
    results = _tool_results(messages)
    search_hits: list[dict] = []
    read_text: str | None = None
    propose: dict | None = None
    error: str | None = None
    sibling: str | None = None
    for r in results:
        if isinstance(r, dict) and "edit_id" in r:
            propose = r
        elif isinstance(r, dict) and "sibling" in r and isinstance(r.get("sibling"), str):
            sibling = r["sibling"]
        elif isinstance(r, dict) and "error" in r:
            error = r["error"]
        elif isinstance(r, str):
            read_text = r
        elif isinstance(r, list) and r and isinstance(r[0], dict) and "file" in r[0]:
            search_hits = r

    if propose is not None:
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content=_compose_edit_answer(propose, search_hits)
                    )
                )
            ]
        )
    if error is not None:
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content=_compose_edit_failed(error))
                )
            ]
        )
    target = _edit_target(messages)
    jadx = _jadx_mention(messages)
    if jadx is not None and sibling is None:
        # Round 1 (jadx mention): search the jadx tree for a keyword from the
        # user's own question AND map the mentioned class to its editable
        # smali sibling — both in one round (the loop executes every tool
        # call in a message before the next model call).
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content=_EDIT_THINK_TEXT,
                        tool_calls=[
                            _tool_call(
                                "call_search",
                                "search_code",
                                json.dumps(
                                    {"pattern": _edit_search_pattern(messages)}
                                ),
                            ),
                            _tool_call(
                                "call_map",
                                "find_smali_sibling",
                                json.dumps({"path": jadx}),
                            ),
                        ],
                    )
                )
            ]
        )
    if sibling is not None and read_text is None:
        # Round 2 (jadx mention): read the mapped editable sibling.
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content="Now reading the mapped smali sibling.",
                        tool_calls=[
                            _tool_call(
                                "call_read",
                                "read_editable_file",
                                json.dumps({"path": sibling}),
                            )
                        ],
                    )
                )
            ]
        )
    if read_text is None:
        # Round 1 (editable mention / plain): search the jadx tree for a
        # keyword from the user's own question (a real model would
        # paraphrase; the fake is a script) AND read the editable target —
        # both in one round (the loop executes every tool call in a message
        # before the next model call).
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content=_EDIT_THINK_TEXT,
                        tool_calls=[
                            _tool_call(
                                "call_search",
                                "search_code",
                                json.dumps(
                                    {"pattern": _edit_search_pattern(messages)}
                                ),
                            ),
                            _tool_call(
                                "call_read",
                                "read_editable_file",
                                json.dumps({"path": target}),
                            ),
                        ],
                    )
                )
            ]
        )
    # The propose target: the jadx mention's mapped sibling when one drove
    # the read, else the editable mention / default target. (Round 2 of the
    # jadx flow read `sibling`; proposing to the manifest fallback would be
    # a wrong-path diff.)
    propose_path = sibling or target
    new_content = _edit_new_content(
        propose_path, read_text, _edit_instruction(messages)
    )
    if new_content is None:
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content=_compose_edit_failed(
                            f"cannot build a safe change for {propose_path} "
                            "(only AndroidManifest.xml and .smali files are "
                            "supported by the demo script)"
                        )
                    )
                )
            ]
        )
    return SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(
                    content="Now proposing the edit for your review.",
                    tool_calls=[
                        _tool_call(
                            "call_propose",
                            "propose_smali_edit",
                            json.dumps(
                                {
                                    "path": propose_path,
                                    "instruction": _edit_instruction(messages),
                                    "new_content": new_content,
                                }
                            ),
                        )
                    ],
                )
            )
        ]
    )


def _edit_stream_chunks(messages: list[dict]):
    """Streaming chunks for the edit-demo script (same round logic as
    ``_edit_response``, tokenized for the SSE demo). Round 1 issues TWO
    tool calls (search_code + read_editable_file), so each chunk carries a
    DISTINCT index — the accumulator would otherwise merge them into one
    (same-index deltas concatenate args into a single call)."""
    resp = _edit_response(messages)
    message = resp.choices[0].message
    content = message.content or ""
    tool_calls = list(getattr(message, "tool_calls", None) or [])
    for word in content.split(" "):
        yield _chunk(content=word + " ")
    for n, tc in enumerate(tool_calls):
        fn = tc.function
        yield _chunk(
            tool_calls=[
                {
                    "index": n,
                    "id": tc.id,
                    "function": {"name": fn.name, "arguments": fn.arguments},
                }
            ]
        )


def is_fake(backend) -> bool:
    """True for the dev-only fake backend (short-circuit target)."""
    return getattr(backend, "provider_id", None) == "fake"


def _has_tool_results(messages: list[dict]) -> bool:
    """True once a prior round's tool result is in the conversation — the
    fake's round 2 (compose the final answer from real tool results)."""
    return any(m.get("role") == "tool" for m in messages)


def _tool_results(messages: list[dict]) -> list[dict]:
    """The JSON-decoded tool-role contents, in order."""
    out = []
    for m in messages:
        if m.get("role") != "tool":
            continue
        try:
            out.append(json.loads(m.get("content") or ""))
        except (json.JSONDecodeError, TypeError):
            out.append({})
    return out


def _compose_answer(messages: list[dict]) -> str:
    """The final answer, derived from the REAL tool results.

    ``search_code`` returns ``[{file, line, snippet}]`` — cite the first hit
    so the dock renders a clickable file:line chip that jumps the Decompiler
    tab (the same path a real model's citation takes). ``read_manifest``
    returns a JSON object — surface a one-line summary as a fallback so even
    a no-hit scan (iOS) gets a real, grounded answer.
    """
    search_hits: list[dict] = []
    manifest: dict = {}
    for result in _tool_results(messages):
        # A failed tool comes back as {"error": ...} — never mistake it for
        # manifest data (review catch: a broken read_manifest used to render
        # as "the manifest summary is available").
        if isinstance(result, dict) and "error" in result:
            continue
        has_file = (
            isinstance(result, list)
            and result
            and isinstance(result[0], dict)
            and "file" in result[0]
        )
        if has_file:
            search_hits = result
        elif isinstance(result, dict) and result:
            manifest = result

    if search_hits:
        top = search_hits[0]
        snippet = (top.get("snippet") or "").strip()[:120]
        line = top.get("line")
        loc = f"{top['file']}:{line}" if line else top["file"]
        text = (
            "I found WebView usage in the decompiled source. The first match "
            f"is in `{loc}` — `{snippet}`. "
            "This is a dev-demo answer from the built-in fake model "
            "(MASA_FAKE_MODEL=1); no LLM was contacted."
        )
        return text
    if manifest:
        package = manifest.get("package") or manifest.get("bundle_identifier")
        head = "The search found no source-level WebView match, but the "
        head += "manifest summary is available"
        if package:
            head += f" (package/bundle `{package}`)"
        return (
            head + ". This is a dev-demo answer from the built-in fake model "
            "(MASA_FAKE_MODEL=1); no LLM was contacted."
        )
    return _PLAIN_ANSWER


def _chunk(content=None, tool_calls=None):
    """One litellm-shaped streaming chunk (OpenAI delta shape)."""
    return SimpleNamespace(
        choices=[SimpleNamespace(delta=SimpleNamespace(content=content, tool_calls=tool_calls))]
    )


def _tool_call(call_id: str, name: str, arguments: str):
    return SimpleNamespace(
        id=call_id, type="function", function=SimpleNamespace(name=name, arguments=arguments)
    )


def fake_chat_response(messages: list[dict], tools: list[dict] | None):
    """Buffered-shape response (``.choices[0].message``) for the fake.

    Script selection: web tools offered (M7 scan opt-in + Active engine) ->
    the web-research demo (web_search -> web_fetch -> cited answer);
    otherwise tools offered + no results yet -> thinking content + two tool
    calls; tools offered + results present -> composed answer; no tools
    (plain chat/insights) -> canned plain answer.
    """
    if tools is None:
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=_PLAIN_ANSWER))]
        )
    if _offers_web(tools):
        return _web_response(messages)
    # M8 Phase D: edit-y questions on a decode-ready Android scan run the
    # edit-demo script (read -> propose -> cited diff for review).
    if _edit_requested(messages, tools):
        return _edit_response(messages)
    if _has_tool_results(messages):
        return SimpleNamespace(
            choices=[
                SimpleNamespace(message=SimpleNamespace(content=_compose_answer(messages)))
            ]
        )
    return SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(
                    content=_THINK_TEXT,
                    tool_calls=[
                        _tool_call("call_search", "search_code", '{"pattern": "WebView"}'),
                        _tool_call("call_manifest", "read_manifest", "{}"),
                    ],
                )
            )
        ]
    )


def fake_stream_chunks(messages: list[dict], tools: list[dict] | None):
    """Yield litellm-shaped streaming chunks for the fake backend."""
    if tools is None:
        for word in _PLAIN_ANSWER.split(" "):
            yield _chunk(content=word + " ")
        return
    if _offers_web(tools):
        yield from _web_stream_chunks(messages)
        return
    # M8 Phase D: the edit-demo script streams exactly like the others.
    if _edit_requested(messages, tools):
        yield from _edit_stream_chunks(messages)
        return
    if _has_tool_results(messages):
        for word in _compose_answer(messages).split(" "):
            yield _chunk(content=word + " ")
        return
    # Round 1: thinking tokens, then the two tool calls (args split across
    # deltas — the same incremental accumulation shape litellm normalizes).
    for word in _THINK_TEXT.split(" "):
        yield _chunk(content=word + " ")
    for delta in _TOOL_CALLS_STREAM:
        yield _chunk(tool_calls=[delta])
