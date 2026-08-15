#!/usr/bin/env bash
# M9 follow-up - contract-style e2e against a REAL Gemini backend.
#
# The unit tests monkeypatch the LLM; this gate drives the full stack (API +
# DB + tools) with an actual Google model to prove the agent's edit flow and
# multi-session persistence work end to end. Default model: Gemini 3.5
# Flash-Lite (gemini-3.5-flash-lite, stable - the curated list in
# app/model/providers.py). Override with MOBARK_E2E_MODEL.
#
#   Phase 1 - configure + probe: POST /model/backends {gemini, key, model},
#     disable any other enabled-with-model backend (pick_chat_backend takes
#     the FIRST match, so a leftover Ollama config would win), then the full
#     completion probe must come back reachable + probe_ok (validates key +
#     model BEFORE the expensive scan).
#   Phase 2 - scan + decode: upload InsecureBankv2.apk -> done, trigger the
#     on-demand apktool decode (POST /smali) -> ready.
#   Phase 3 - agent edit flow (the flagship M8 surface), streamed + sessioned:
#     "@AndroidManifest.xml set android:debuggable to false" - the REAL model
#     must run a propose_smali_edit step (tool_end ok) and the edits table
#     must show a proposed AndroidManifest.xml row. Same turn runs inside a
#     chat session; the persisted thread must round-trip user+assistant
#     turns with the tool trace AND the citation chips.
#   Phase 4 - continue turn: a second streamed turn in the SAME session
#     (the sequential edit flow) must answer cleanly, proving the persisted
#     history feeds the model across turns.
#
# Usage:  scripts/e2e_gemini.sh [apk]
#   APK defaults to docs/InsecureBankv2.apk. Requires MOBARK_GEMINI_API_KEY.
#   MOBARK_E2E_MODEL overrides the model id (default gemini-3.5-flash-lite).
#   SKIP_BUILD=1 skips the (incremental) docker compose build.
#   KEEP_STACK=1 leaves the compose stack up (manual inspection).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BASE="${BASE:-http://localhost:8000}"
API="$BASE/api/v1"
APK="${1:-$ROOT/docs/InsecureBankv2.apk}"
PYTHON="${PYTHON:-$ROOT/backend/.venv/bin/python}"
MODEL="${MOBARK_E2E_MODEL:-gemini-3.5-flash-lite}"
WORK="$(mktemp -d /tmp/mobark_gemini_e2e.XXXXXX)"
KEEP_STACK="${KEEP_STACK:-0}"
cleanup() {
  rm -rf "$WORK"
  if [ "$KEEP_STACK" != "1" ]; then
    docker compose down >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

pass() { printf '  \033[32mok\033[0m %s\n' "$1"; }
fail() { printf '\033[31mFAIL:\033[0m %s\n' "$1"; exit 1; }

: "${MOBARK_GEMINI_API_KEY:?MOBARK_GEMINI_API_KEY is required - set it to a Google AI Studio API key (the script POSTs it to /model/backends)}"

# Print one value from a JSON doc on stdin: strings raw, bools lowercase,
# null -> empty.
json_get() {
  "$PYTHON" -c '
import sys, json
d = json.load(sys.stdin)
v = '"$1"'
if isinstance(v, bool):
    print("true" if v else "false")
elif v is None:
    print("")
else:
    print(v)
'
}

# Parse an SSE body into {answer, tools, error} (answer = the ChatResponse
# payload, tools = the tool_end steps).
parse_sse() {
  "$PYTHON" - <<'PYEOF'
import json, sys
text = sys.stdin.read()
answer, error = None, None
tools = []
for block in text.strip().split("\n\n"):
    if not block or block.startswith(":"):
        continue
    event, data_lines = None, []
    for line in block.splitlines():
        if line.startswith("event:"):
            event = line[len("event:"):].strip()
        elif line.startswith("data:"):
            data_lines.append(line[len("data:"):].strip())
    if not event or not data_lines:
        continue
    data = json.loads("\n".join(data_lines))
    if event == "answer":
        answer = data
    elif event == "error":
        error = data
    elif event == "tool_end":
        tools.append({"name": data.get("name"), "status": data.get("status")})
print(json.dumps({"answer": answer, "tools": tools, "error": error}))
PYEOF
}

wait_scan_done() {
  local id="$1"
  for _ in $(seq 1 200); do
    local st
    st=$(curl -fsS "$API/scans/$id" | json_get 'd["status"]')
    [ "$st" = "done" ] && return 0
    [ "$st" = "failed" ] && return 1
    sleep 3
  done
  return 1
}

wait_smali_ready() {
  local id="$1"
  for _ in $(seq 1 100); do
    local st err
    st=$(curl -fsS "$API/scans/$id/smali-status" | json_get 'd["status"]')
    [ "$st" = "ready" ] && return 0
    if [ "$st" = "failed" ]; then
      err=$(curl -fsS "$API/scans/$id/smali-status" | json_get 'd["error"]')
      echo "$err"
      return 1
    fi
    sleep 3
  done
  return 1
}

# One streamed chat turn in a session -> writes $WORK/turn.json via parse_sse.
run_turn() { # $1 scan_id  $2 session_id  $3 question
  local qjson
  qjson=$("$PYTHON" -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$3")
  curl -fsS -X POST "$API/scans/$1/chat/stream" \
    -H 'Content-Type: application/json' \
    -d "{\"question\": $qjson, \"session_id\": $2, \"mentioned_files\": [\"AndroidManifest.xml/AndroidManifest.xml\"]}" \
    > "$WORK/stream.txt"
  parse_sse < "$WORK/stream.txt" > "$WORK/turn.json"
}

# ---- stack ------------------------------------------------------------------

echo "== up (Gemini backend) =="
if [ "${SKIP_BUILD:-0}" != "1" ]; then
  echo "== build (incremental - toolchain layers cached) =="
  docker compose build app worker
fi
docker compose up -d redis app worker

echo "== wait for health =="
health_ok=0
for _ in $(seq 1 60); do
  if curl -fsS "$API/health" >/dev/null 2>&1; then health_ok=1; break; fi
  sleep 2
done
[ "$health_ok" = "1" ] || fail "API did not become healthy at $API/health"

# ---- Phase 1: configure + probe the Gemini backend --------------------------

echo "== Phase 1: Gemini backend ($MODEL) =="
code=$(curl -sS -o "$WORK/backend.json" -w '%{http_code}' -X POST "$API/model/backends" \
  -H 'Content-Type: application/json' \
  -d "{\"provider_id\": \"gemini\", \"api_key\": \"$MOBARK_GEMINI_API_KEY\", \"model\": \"$MODEL\"}")
[ "$code" = "201" ] || [ "$code" = "200" ] || fail "could not configure the Gemini backend (HTTP $code): $(cat "$WORK/backend.json")"
pass "backend configured"

# pick_chat_backend resolves the FIRST enabled backend with a model - a
# leftover local backend (e.g. an older store with Ollama + a model) would
# win over Gemini. Disable any other enabled-with-model backend.
"$PYTHON" - "$API" <<'PYEOF'
import json, sys, urllib.request
api = sys.argv[1]
def call(path, method="GET", body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(api + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)
for b in call("/model/backends"):
    if b["id"] != "gemini" and b.get("enabled") and b.get("model"):
        call("/model/backends/" + b["id"], method="PUT", body={"enabled": False})
PYEOF
pass "only the Gemini backend is enabled-with-model"

probe=$(curl -fsS -X POST "$API/model/backends/gemini/test")
reachable=$(echo "$probe" | json_get 'd["health"]["reachable"]')
probe_ok=$(echo "$probe" | json_get 'd["health"]["probe_ok"]')
[ "$reachable" = "true" ] || fail "Gemini backend unreachable - check the key/network"
[ "$probe_ok" = "true" ] || fail "Gemini completion probe failed - key/model rejected"
pass "completion probe ok (key + model valid)"

# ---- Phase 2: scan + smali decode -------------------------------------------

echo "== Phase 2: scan + apktool decode =="
[ -f "$APK" ] || fail "missing sample: $APK"
SCAN_ID=$(curl -fsS -F "file=@$APK" "$API/scans" | json_get 'd["id"]')
echo "  scan $SCAN_ID"
wait_scan_done "$SCAN_ID" || fail "scan $SCAN_ID failed or timed out"
pass "scan done"

code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$API/scans/$SCAN_ID/smali")
[ "$code" = "202" ] || fail "smali trigger expected 202, got $code (already decoded? then smali-status below decides)"
if ! wait_smali_ready "$SCAN_ID" >/dev/null 2>&1; then
  fail "apktool decode did not become ready - check 'docker compose logs worker' for the decode error"
fi
pass "smali decode ready (edit tools on)"

# ---- Phase 3: agent edit flow (real model, streamed, sessioned) --------------

echo "== Phase 3: agent edit flow - '@AndroidManifest.xml set android:debuggable to false' =="
SESS=$(curl -fsS -X POST "$API/scans/$SCAN_ID/chat/sessions" | json_get 'd["id"]')
echo "  session $SESS"

QUESTION="Set android:debuggable to false in AndroidManifest.xml and propose the edit."
run_turn "$SCAN_ID" "$SESS" "$QUESTION"

stream_err=$(json_get 'd.get("error")' < "$WORK/turn.json")
[ -z "$stream_err" ] || fail "stream error frame: $stream_err"
ANSWER=$(json_get 'd["answer"]["answer"] if d.get("answer") else ""' < "$WORK/turn.json")
[ -n "$ANSWER" ] || fail "no answer frame in the stream"
case "$ANSWER" in *"tool-call limit"*) fail "agent loop exhausted (tool-call limit): $ANSWER" ;; esac
TOOLS=$(json_get '" ".join(t.get("name") or "" for t in d["tools"])' < "$WORK/turn.json")
case " $TOOLS " in
  *" propose_smali_edit "*) pass "propose_smali_edit step ran (tools: $TOOLS)" ;;
  *) fail "no propose_smali_edit step - tools were: [$TOOLS]; answer: $ANSWER" ;;
esac

# The edits table must hold a PROPOSED AndroidManifest.xml row (never applied).
EDITS=$(curl -fsS "$API/scans/$SCAN_ID/edits")
PROPOSED=$(echo "$EDITS" | json_get '" ".join(e["file_path"] + ":" + e["status"] for e in d if e["status"] == "proposed")')
case " $PROPOSED " in
  *"AndroidManifest.xml:proposed"*) pass "proposal stored: $PROPOSED" ;;
  *) fail "no proposed AndroidManifest.xml edit - got: [$PROPOSED]; answer: $ANSWER" ;;
esac

# Session persistence: the turn round-tripped user + assistant with the tool
# trace and the citation chips.
MSGS=$(curl -fsS "$API/scans/$SCAN_ID/chat/sessions/$SESS/messages")
ROLES=$(echo "$MSGS" | json_get '" ".join(m["role"] for m in d)')
[ "$ROLES" = "user assistant" ] || fail "session turns not persisted: [$ROLES]"
ASSIST_JSON=$(echo "$MSGS" | json_get 'd[1]')
echo "$ASSIST_JSON" > "$WORK/assist.json"
ASSIST_TOOLS=$(json_get '" ".join(t["name"] for t in d["tool_runs"])' < "$WORK/assist.json")
case " $ASSIST_TOOLS " in
  *" propose_smali_edit "*) pass "assistant turn persisted with the tool trace" ;;
  *) fail "persisted turn lost the propose tool trace: [$ASSIST_TOOLS]" ;;
esac
CIT_COUNT=$(json_get 'len(d["citations"])' < "$WORK/assist.json")
[ "$CIT_COUNT" -ge 1 ] || fail "persisted assistant turn has no citations - answer was: $ANSWER"
pass "citations persisted ($CIT_COUNT) - reloaded history keeps the source chips"

TITLE=$(curl -fsS "$API/scans/$SCAN_ID/chat/sessions" | json_get 'd[0]["title"]')
[ -n "$TITLE" ] && [ "$TITLE" != "New chat" ] || fail "session was not auto-titled"
pass "session auto-titled: \"$TITLE\""

# ---- Phase 4: continue turn in the same session ------------------------------

echo "== Phase 4: continue turn (persisted history feeds the model) =="
CONT_QUESTION="continue - review the current edit state and propose the next file's edit for the task, or say the task is complete"
run_turn "$SCAN_ID" "$SESS" "$CONT_QUESTION"
stream_err=$(json_get 'd.get("error")' < "$WORK/turn.json")
[ -z "$stream_err" ] || fail "continue stream error frame: $stream_err"
CONT_ANSWER=$(json_get 'd["answer"]["answer"] if d.get("answer") else ""' < "$WORK/turn.json")
[ -n "$CONT_ANSWER" ] || fail "no answer frame on the continue turn"
ROLES=$(curl -fsS "$API/scans/$SCAN_ID/chat/sessions/$SESS/messages" | json_get '" ".join(m["role"] for m in d)')
[ "$ROLES" = "user assistant user assistant" ] || fail "continue turn not persisted: [$ROLES]"
pass "continue turn answered + persisted (4 turns)"
echo
echo "  model: $MODEL"
echo "  answer: $ANSWER"
echo
echo "== PASSED =="
