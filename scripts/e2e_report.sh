#!/usr/bin/env bash
# M9 Phase E - containerized contract-style e2e for report generation.
#
# Decision 9 (no emulator/device): the gate asserts the generated artifacts
# are well-formed via their bytes, not by installing them. This script runs
# the FULL compose stack against the REAL sample artifacts and verifies the
# report surface end to end:
#
#   Phase 1 - Android, no AI (MASA_FAKE_MODEL=0, the honest default):
#     upload InsecureBankv2.apk -> done -> GET /report asserts the sections
#     AND the no-AI fallback note (decision 10 - the body never 400s on a
#     missing model); export?format=md streams the SAME cached body with a
#     Content-Disposition attachment; export?format=pdf yields a %PDF with
#     extractable section headings + working page numbers (reportlab).
#     A suppress toggle recomputes the body (decision 7): the one-line
#     "Suppressed findings" footnote (open item 2) appears and the cached
#     body changes.
#   Phase 2 - iOS parity: iBugBazaar.ipa -> the binary-profile body + both
#     exports render (decision 8).
#   Phase 3 - AI surface: restart the stack with MASA_FAKE_MODEL=1 (the
#     deterministic dev LLM) -> POST /report/regenerate -> the executive
#     summary + per-finding explanations land in the cached body.
#
# Usage:  scripts/e2e_report.sh [apk] [ipa]
#   APK/IPA default to docs/InsecureBankv2.apk / docs/iBugBazaar.ipa.
#   SKIP_BUILD=1 skips the (incremental) docker compose build.
#   PYTHON overrides the interpreter used for pypdf text extraction
#   (default: backend/.venv/bin/python - the dev venv with pypdf).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BASE="${BASE:-http://localhost:8000}"
API="$BASE/api/v1"
APK="${1:-$ROOT/docs/InsecureBankv2.apk}"
IPA="${2:-$ROOT/docs/iBugBazaar.ipa}"
PYTHON="${PYTHON:-$ROOT/backend/.venv/bin/python}"
# Scratch dir (mktemp - concurrent runs never clobber each other) + a
# guaranteed teardown: the stack is brought down on BOTH success and
# failure so a failed gate never strands the containers. KEEP_STACK=1
# skips the down (manual inspection).
WORK="$(mktemp -d /tmp/masa_e2e.XXXXXX)"
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

# ---- stack ------------------------------------------------------------------

if [ "${SKIP_BUILD:-0}" != "1" ]; then
  echo "== build (incremental - toolchain layers cached) =="
  docker compose build app worker
fi

echo "== up (no-AI default) =="
docker compose up -d redis app worker

echo "== wait for health =="
health_ok=0
for _ in $(seq 1 60); do
  if curl -fsS "$API/health" >/dev/null 2>&1; then health_ok=1; break; fi
  sleep 2
done
[ "$health_ok" = "1" ] || fail "API did not become healthy at $API/health"

wait_scan_done() {
  local id="$1"
  for _ in $(seq 1 120); do
    local st
    st=$(curl -fsS "$API/scans/$id" | "$PYTHON" -c 'import sys,json;print(json.load(sys.stdin)["status"])')
    [ "$st" = "done" ] && return 0
    [ "$st" = "failed" ] && return 1
    sleep 3
  done
  return 1
}

upload_scan() {
  local file="$1"
  curl -fsS -F "file=@$file" "$API/scans" \
    | "$PYTHON" -c 'import sys,json;print(json.load(sys.stdin)["id"])'
}

pdf_headings() {
  # %PDF text extraction via pypdf (dev dep - NOT in the image; run on host).
  # A gate failure prints its REASON to stdout so the caller's fail message
  # carries it (under set -e the substitution captures nothing otherwise).
  "$PYTHON" - "$1" <<'PYEOF'
import io, sys
from pypdf import PdfReader
data = open(sys.argv[1], "rb").read()
if not data.startswith(b"%PDF"):
    print("not a PDF")
    sys.exit(1)
if len(data) <= 1000:
    print("suspiciously small PDF")
    sys.exit(1)
reader = PdfReader(io.BytesIO(data))
text = " ".join((p.extract_text() or "") for p in reader.pages)
print(" ".join(text.split()))
PYEOF
}

# ---- Phase 1: Android, no AI -------------------------------------------------

echo "== Phase 1: Android (InsecureBankv2) - no AI =="
[ -f "$APK" ] || fail "missing sample: $APK"
AND_ID=$(upload_scan "$APK")
echo "  scan $AND_ID"
wait_scan_done "$AND_ID" || fail "scan $AND_ID failed or timed out"

md=$(curl -fsS "$API/scans/$AND_ID/report" | "$PYTHON" -c 'import sys,json;print(json.load(sys.stdin)["markdown"])')
for needle in "# MASA security report" "## Executive summary" "## Severity breakdown" "## Findings" "## Android surface" "## Dependencies"; do
  case "$md" in *"$needle"*) : ;; *) fail "report lacks section: $needle" ;; esac
done
case "$md" in *"No AI summary yet"*) pass "no-AI fallback note present (decision 10)" ;; *) fail "expected the no-AI fallback note" ;; esac
case "$md" in *"Suppressed findings"*) fail "footnote must be absent before any suppression" ;; *) : ;; esac
pass "report body sections"

# markdown export = the same cached body + attachment header
curl -fsS -D "$WORK/md_hdr" -o "$WORK/report.md" "$API/scans/$AND_ID/report/export?format=md"
grep -qi 'attachment; filename="InsecureBankv2-report.md"' "$WORK/md_hdr" || fail "md Content-Disposition missing"
# Both sides stripped of trailing newlines (bash $(...) eats them; the file
# ends with one) - interior content must match byte-for-byte.
[ "$(cat "$WORK/report.md")" = "$md" ] || fail "md export diverges from the GET body"
pass "markdown export matches the body"

# pdf export: %PDF magic + headings + page numbers
curl -fsS -o "$WORK/report.pdf" "$API/scans/$AND_ID/report/export?format=pdf"
pdf_text=$(pdf_headings "$WORK/report.pdf") || fail "pdf gate: $pdf_text"
for needle in "MASA security report" "Executive summary" "InsecureBankv2" "page 1"; do
  case "$pdf_text" in *"$needle"*) : ;; *) fail "pdf lacks: $needle" ;; esac
done
pass "pdf export: %PDF + headings + page numbers"

# suppress -> body recomputes (decision 7) with the open-item-2 footnote
FID=$(curl -fsS "$API/scans/$AND_ID/findings?limit=1" \
  | "$PYTHON" -c 'import sys,json;print(json.load(sys.stdin)[0]["id"])')
curl -fsS -X POST "$API/scans/$AND_ID/findings/$FID/suppress" >/dev/null
md2=$(curl -fsS "$API/scans/$AND_ID/report" | "$PYTHON" -c 'import sys,json;print(json.load(sys.stdin)["markdown"])')
case "$md2" in *"**Suppressed findings:** 1 excluded"*) pass "suppress recompute + footnote" ;; *) fail "suppressed footnote missing after toggle" ;; esac
[ "$md2" != "$md" ] || fail "body did not change after suppress"
pass "cache invalidated by suppression"

# ---- Phase 2: iOS parity ------------------------------------------------------

echo "== Phase 2: iOS (iBugBazaar) - binary profile parity =="
[ -f "$IPA" ] || fail "missing sample: $IPA"
IOS_ID=$(upload_scan "$IPA")
echo "  scan $IOS_ID"
wait_scan_done "$IOS_ID" || fail "scan $IOS_ID failed or timed out"

ios_md=$(curl -fsS "$API/scans/$IOS_ID/report" | "$PYTHON" -c 'import sys,json;print(json.load(sys.stdin)["markdown"])')
case "$ios_md" in *"**App:** iBugBazaar.ipa (ios)"*) : ;; *) fail "ios header missing" ;; esac
case "$ios_md" in *"## iOS binary profile"*) pass "iOS binary profile section" ;; *) fail "iOS binary profile missing" ;; esac
case "$ios_md" in *"## Android surface"*) fail "Android section leaked onto iOS" ;; *) : ;; esac
curl -fsS -o "$WORK/ios.pdf" "$API/scans/$IOS_ID/report/export?format=pdf"
ios_text=$(pdf_headings "$WORK/ios.pdf") || fail "ios pdf gate: $ios_text"
case "$ios_text" in *"iOS binary profile"*) pass "iOS PDF renders the binary profile" ;; *) fail "iOS PDF lacks binary profile" ;; esac

# ---- Phase 3: AI surface via the fake model -----------------------------------

echo "== Phase 3: regenerate with the fake model (MASA_FAKE_MODEL=1) =="
MASA_FAKE_MODEL=1 docker compose up -d app worker
# The recreate re-runs migrations + uvicorn startup (and seeds the fake
# backend at import) - wait for health before POSTing.
for _ in $(seq 1 60); do
  if curl -fsS "$API/health" >/dev/null 2>&1; then break; fi
  sleep 2
done
curl -fsS "$API/health" >/dev/null || fail "app did not restart healthy with the fake model"
reg=$(curl -fsS -X POST "$API/scans/$AND_ID/report/regenerate" \
  | "$PYTHON" -c 'import sys,json;d=json.load(sys.stdin);print(d["summary"]);print(d["explanations_generated"])')
summary=$(printf '%s\n' "$reg" | head -1)
[ -n "$summary" ] || fail "regenerate returned an empty summary"
md3=$(curl -fsS "$API/scans/$AND_ID/report" | "$PYTHON" -c 'import sys,json;print(json.load(sys.stdin)["markdown"])')
case "$md3" in *"No AI summary yet"*) fail "AI summary did not replace the fallback note" ;; *) : ;; esac
case "$md3" in *"$summary"*) pass "regenerated summary persisted into the report body" ;; *) fail "regenerated summary missing from body" ;; esac
pass "regenerate + cache identity (ai_summary) recompute"

# ---- gate ----------------------------------------------------------------------

echo "== image size =="
docker images masa-app:latest --format '{{.Repository}}:{{.Tag}} {{.Size}}'
echo "== PASSED =="
