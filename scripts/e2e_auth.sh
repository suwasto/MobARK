#!/usr/bin/env bash
# M9.1 Phase E - containerized contract-style e2e for authentication +
# per-user isolation (decision 10 - no emulator, no browser automation; the
# same curl-driven contract style as e2e_report.sh).
#
# Runs the FULL compose stack on a FRESH data volume and verifies the auth
# surface end to end:
#
#   Phase 1 - fresh volume + stack up (register-admin needs an EMPTY users
#     table: the FIRST registered user is the instance admin).
#   Phase 2 - register the admin -> is_admin + session cookie; logout ->
#     me 401; login round-trip -> me 200 (the session surface).
#   Phase 3 - admin uploads InsecureBankv2.apk -> scan done.
#   Phase 4 - a SECOND user registers (is_admin false) -> GET /scans is
#     their own EMPTY dashboard, and the admin's scan reads as 404 -
#     byte-identical to a nonexistent scan (no existence leak).
#   Phase 5 - claim visibility: a CLI-created UNOWNED scan (cli scan, no
#     --user) is invisible to everyone (404) until the admin POSTs
#     /auth/claim - then it reads 200 for the admin, still 404 for the
#     second user, and a re-claim is a no-op (claimed: 0).
#   Phase 6 - OAuth providers: absent by default (providers == [local]);
#     with GitHub/Google client env set, the list gains both (the login
#     view's button rule - no config, no button).
#   Phase 7 - auth-off parity: MASA_AUTH_ENABLED=0 restores the fully-open
#     behavior - /scans readable with NO session, /auth/me -> null,
#     register/login inert (400).
#
# Usage:  scripts/e2e_auth.sh [apk]
#   APK defaults to docs/InsecureBankv2.apk.
#   SKIP_BUILD=1 skips the (incremental) docker compose build.
#   KEEP_STACK=1 leaves the stack up (manual inspection).
#   FRESH=0 skips the destructive `docker compose down -v` (only sensible
#   against an already-empty data volume - the register-admin assertion
#   REQUIRES zero users).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BASE="${BASE:-http://localhost:8000}"
API="$BASE/api/v1"
APK="${1:-$ROOT/docs/InsecureBankv2.apk}"
PYTHON="${PYTHON:-$ROOT/backend/.venv/bin/python}"
FRESH="${FRESH:-1}"
WORK="$(mktemp -d /tmp/masa_auth_e2e.XXXXXX)"
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

# Print one value from a JSON doc on stdin: strings raw, bools lowercase,
# null -> empty.
json_get() {
  "$PYTHON" -c '
import json, sys
d = json.load(sys.stdin)
keys = sys.argv[1].split(".")
for k in keys:
    d = d[k]
if d is None:
    print("")
elif isinstance(d, bool):
    print("true" if d else "false")
else:
    print(d)
' "$1"
}

# ---- fresh volume ------------------------------------------------------------

if [ "$FRESH" = "1" ]; then
  echo "== fresh volume (down -v wipes masa-data + redis-data) =="
  docker compose down -v >/dev/null 2>&1 || true
fi

if [ "${SKIP_BUILD:-0}" != "1" ]; then
  echo "== build (incremental - toolchain layers cached) =="
  docker compose build app worker
fi

echo "== up =="
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
    st=$(curl -fsS -b "$WORK/admin.jar" "$API/scans/$id" \
      | "$PYTHON" -c 'import sys,json;print(json.load(sys.stdin)["status"])')
    [ "$st" = "done" ] && return 0
    [ "$st" = "failed" ] && return 1
    sleep 3
  done
  return 1
}

# ---- Phase 2: register admin -------------------------------------------------

echo "== Phase 2: register admin (first user = instance admin) =="
[ -f "$APK" ] || fail "missing sample: $APK"

ADMIN=$(curl -fsS -c "$WORK/admin.jar" -X POST "$API/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password123"}')
echo "  user: $(printf '%s' "$ADMIN" | json_get user.username) admin=$(printf '%s' "$ADMIN" | json_get user.is_admin)"
[ "$(printf '%s' "$ADMIN" | json_get user.is_admin)" = "true" ] \
  || fail "first registered user must be admin"
grep -q "masa_session" "$WORK/admin.jar" || fail "register did not set the session cookie"
pass "admin registered + session cookie"

# logout -> me 401; login -> me 200 (the session surface round-trip)
code=$(curl -s -o /dev/null -w "%{http_code}" -b "$WORK/admin.jar" -X POST "$API/auth/logout")
[ "$code" = "204" ] || fail "logout expected 204, got $code"
code=$(curl -s -o /dev/null -w "%{http_code}" -b "$WORK/admin.jar" "$API/auth/me")
[ "$code" = "401" ] || fail "me after logout expected 401, got $code"
curl -fsS -c "$WORK/admin.jar" -X POST "$API/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password123"}' >/dev/null
ME=$(curl -fsS -b "$WORK/admin.jar" "$API/auth/me")
[ "$(printf '%s' "$ME" | json_get username)" = "admin" ] || fail "login round-trip failed"
pass "logout/login round-trip"

# ---- Phase 3: admin upload + scan ---------------------------------------------

echo "== Phase 3: admin uploads InsecureBankv2.apk =="
ADMIN_SCAN=$(curl -fsS -b "$WORK/admin.jar" -F "file=@$APK" "$API/scans")
ADMIN_SCAN_ID=$(printf '%s' "$ADMIN_SCAN" | json_get id)
echo "  scan $ADMIN_SCAN_ID"
wait_scan_done "$ADMIN_SCAN_ID" || fail "admin scan $ADMIN_SCAN_ID failed or timed out"
ADMIN_LIST=$(curl -fsS -b "$WORK/admin.jar" "$API/scans")
case "$ADMIN_LIST" in *"InsecureBankv2.apk"*) : ;; *) fail "admin's list lacks their scan" ;; esac
pass "admin scan done + listed for the owner"

# ---- Phase 4: second user - isolation ------------------------------------------

echo "== Phase 4: second user registers - 404 isolation + own empty dashboard =="
curl -fsS -c "$WORK/user2.jar" -X POST "$API/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}' >/dev/null
U2_ME=$(curl -fsS -b "$WORK/user2.jar" "$API/auth/me")
[ "$(printf '%s' "$U2_ME" | json_get username)" = "alice" ] || fail "second user register failed"
U2_IS_ADMIN=$(curl -fsS -b "$WORK/user2.jar" "$API/auth/me" | json_get is_admin)
[ "$U2_IS_ADMIN" = "false" ] || fail "second user must NOT be admin (got $U2_IS_ADMIN)"
pass "second user is a regular user"

# the admin's scan: 404 for alice, with a body identical to a missing scan
FOREIGN=$(curl -s -b "$WORK/user2.jar" "$API/scans/$ADMIN_SCAN_ID")
MISSING=$(curl -s -b "$WORK/user2.jar" "$API/scans/999999")
code=$(curl -s -o /dev/null -w "%{http_code}" -b "$WORK/user2.jar" "$API/scans/$ADMIN_SCAN_ID")
[ "$code" = "404" ] || fail "foreign scan expected 404, got $code"
[ "$FOREIGN" = "$MISSING" ] || fail "foreign-scan 404 must be byte-identical to a missing scan"
pass "foreign scan 404 == missing scan 404"

# alice's dashboard: empty (she has no scans)
U2_LIST=$(curl -fsS -b "$WORK/user2.jar" "$API/scans")
[ "$U2_LIST" = "[]" ] || fail "second user's dashboard must be empty, got: $U2_LIST"
pass "second user's own (empty) dashboard"

# ---- Phase 5: claim visibility -------------------------------------------------

echo "== Phase 5: unowned (CLI) scan - invisible until the admin claims =="
# A host-operator CLI scan with no --user creates an UNOWNED row - the audit
# gap-1 path. Create a dummy artifact inside the app container and register
# it; the row lands with user_id NULL.
docker compose exec -T app sh -c \
  'printf "PK\x03\x04" > /tmp/unowned.apk && python -m app.cli scan /tmp/unowned.apk' \
  >/dev/null
UNOWNED_ID=$(docker compose exec -T app python -c \
  "import sqlite3; c=sqlite3.connect('/data/masa.db'); print(c.execute('SELECT id FROM scans ORDER BY id DESC LIMIT 1').fetchone()[0])")
echo "  unowned scan $UNOWNED_ID"

# invisible to everyone before the claim (admin included)
code=$(curl -s -o /dev/null -w "%{http_code}" -b "$WORK/admin.jar" "$API/scans/$UNOWNED_ID")
[ "$code" = "404" ] || fail "unowned scan must 404 for the admin pre-claim, got $code"
code=$(curl -s -o /dev/null -w "%{http_code}" -b "$WORK/user2.jar" "$API/scans/$UNOWNED_ID")
[ "$code" = "404" ] || fail "unowned scan must 404 for the second user pre-claim, got $code"
pass "unowned scan invisible pre-claim"

CLAIM=$(curl -fsS -b "$WORK/admin.jar" -X POST "$API/auth/claim")
[ "$(printf '%s' "$CLAIM" | json_get claimed)" = "1" ] \
  || fail "admin claim should adopt exactly 1 scan, got: $CLAIM"
pass "admin claim adopted the unowned scan"

# now visible to the admin, still 404 for alice
code=$(curl -s -o /dev/null -w "%{http_code}" -b "$WORK/admin.jar" "$API/scans/$UNOWNED_ID")
[ "$code" = "200" ] || fail "claimed scan must read 200 for the admin, got $code"
code=$(curl -s -o /dev/null -w "%{http_code}" -b "$WORK/user2.jar" "$API/scans/$UNOWNED_ID")
[ "$code" = "404" ] || fail "claimed scan must still 404 for the second user, got $code"
pass "claim visible only to the admin"

# idempotent: a re-claim touches nothing
CLAIM2=$(curl -fsS -b "$WORK/admin.jar" -X POST "$API/auth/claim")
[ "$(printf '%s' "$CLAIM2" | json_get claimed)" = "0" ] \
  || fail "re-claim should be a no-op, got: $CLAIM2"
pass "re-claim idempotent"

# non-admin claim is forbidden
code=$(curl -s -o /dev/null -w "%{http_code}" -b "$WORK/user2.jar" -X POST "$API/auth/claim")
[ "$code" = "403" ] || fail "non-admin claim expected 403, got $code"
pass "non-admin claim 403"

# ---- Phase 6: OAuth providers per env -------------------------------------------

echo "== Phase 6: OAuth buttons present only when configured =="
PROV=$(curl -fsS "$API/auth/providers")
case "$PROV" in *'"local"'*) : ;; *) fail "local provider missing: $PROV" ;; esac
case "$PROV" in *github*) fail "github must be ABSENT without env keys: $PROV" ;; *) : ;; esac
pass "providers = [local] without OAuth env"

echo "  restart with GitHub/Google env set..."
MASA_GITHUB_CLIENT_ID=ci-test MASA_GITHUB_CLIENT_SECRET=ci-test \
MASA_GOOGLE_CLIENT_ID=ci-test.apps.googleusercontent.com MASA_GOOGLE_CLIENT_SECRET=ci-test \
  docker compose up -d app worker >/dev/null
for _ in $(seq 1 60); do
  if curl -fsS "$API/health" >/dev/null 2>&1; then break; fi
  sleep 2
done
curl -fsS "$API/health" >/dev/null || fail "app did not restart healthy"
PROV=$(curl -fsS "$API/auth/providers")
case "$PROV" in *github*) : ;; *) fail "github missing with env set: $PROV" ;; esac
case "$PROV" in *google*) : ;; *) fail "google missing with env set: $PROV" ;; esac
pass "providers include github + google with env keys"

# ---- Phase 7: auth-off parity ----------------------------------------------------

echo "== Phase 7: MASA_AUTH_ENABLED=0 restores the open behavior =="
MASA_AUTH_ENABLED=0 docker compose up -d app worker >/dev/null
for _ in $(seq 1 60); do
  if curl -fsS "$API/health" >/dev/null 2>&1; then break; fi
  sleep 2
done
curl -fsS "$API/health" >/dev/null || fail "app did not restart healthy (auth-off)"

# /scans with NO session: open
code=$(curl -s -o /dev/null -w "%{http_code}" "$API/scans")
[ "$code" = "200" ] || fail "auth-off /scans without session expected 200, got $code"
# me -> null, register/login inert
[ "$(curl -fsS "$API/auth/me")" = "null" ] || fail "auth-off me must be null"
code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"nobody","password":"password123"}')
[ "$code" = "400" ] || fail "auth-off register expected 400 (inert), got $code"
code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"nobody","password":"password123"}')
[ "$code" = "400" ] || fail "auth-off login expected 400 (inert), got $code"
pass "auth-off parity: open routes + inert auth surface"

echo "== PASSED =="
