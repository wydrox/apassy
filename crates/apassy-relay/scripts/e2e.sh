#!/usr/bin/env bash
# End-to-end check of the relay on this machine, with the real binaries.
#
# It builds apassy-relay, apassy-team, and the dev example e2e_relay. It makes a
# team vault in a temp dir with a synthetic key, then:
#   1. checks that `apassy-relay serve` starts, answers /healthz, and refuses a
#      request without the edge header;
#   2. serves the same vault with examples/e2e_relay.rs (the same server code, plus
#      a mock HTTPS upstream for api.stripe.com and api.github.com);
#   3. sets up the team with apassy-team: a collection, a staging Stripe item, a
#      production GitHub item, an invite, a member, a grant, an agent token;
#   4. runs a known-safe command (runs at once);
#   5. runs a command with the production item: it waits; the owner denies it;
#   6. runs a command with the production item that calls the relay proxy: it
#      waits; the owner approves it; the upstream sees the real synthetic value
#      and the command sees only the placeholder;
#   7. revokes the grant: the live session is refused, and a new run is denied;
#   8. checks that the audit holds no value, placeholder, or token.
#
# All values are synthetic. Nothing leaves 127.0.0.1. Exit 0 means every check passed.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

STRIPE_CANARY="sk_test_51SyntheticCanaryValue0123456789abcdefABCDEF"
GITHUB_CANARY="ghp_SyntheticCanaryTwoValue0123456789abcdefABCDEF"

step() { printf '\n== %s\n' "$*"; }
ok() { printf 'ok: %s\n' "$*"; }
fail() {
	printf 'FAIL: %s\n' "$*" >&2
	exit 1
}

step "Build"
cargo build --quiet --bin apassy-relay --bin apassy-team --example e2e_relay
BIN="$ROOT/target/debug"
RELAY_BIN="$BIN/apassy-relay"
TEAM_BIN="$BIN/apassy-team"
E2E_BIN="$BIN/examples/e2e_relay"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/apassy-relay-e2e.XXXXXX")"
RELAY_PID=""
cleanup() {
	if [ -n "$RELAY_PID" ]; then kill "$RELAY_PID" 2>/dev/null || true; fi
	wait 2>/dev/null || true
	rm -rf "$TMP"
}
trap cleanup EXIT

PORT=$((20000 + RANDOM % 20000))
URL="http://127.0.0.1:$PORT"
EDGE="e2e-synthetic-edge-secret-0123456789abcdef0123456789"
umask 077
printf '%s' "e2e synthetic vault passphrase" >"$TMP/vault_key"
printf '%s' "$EDGE" >"$TMP/edge_secret"
export APASSY_RELAY_DATA="$TMP/data"
export APASSY_RELAY_LISTEN="127.0.0.1:$PORT"
export APASSY_RELAY_PUBLIC_URL="$URL"
export APASSY_RELAY_KEY_FILE="$TMP/vault_key"
export APASSY_RELAY_EDGE_SECRET_FILE="$TMP/edge_secret"
export APASSY_RELAY_APPROVAL_TIMEOUT=120
# The CLI must not pick up the settings or tokens of the person running this.
unset APASSY_RELAY_URL APASSY_TEAM_TOKEN APASSY_TOKEN APASSY_EDGE_SECRET

wait_healthy() {
	for _ in $(seq 1 100); do
		if curl -fsS "$URL/healthz" >/dev/null 2>&1; then return 0; fi
		sleep 0.1
	done
	fail "the relay did not answer /healthz"
}

stop_relay() {
	kill "$RELAY_PID"
	wait "$RELAY_PID" 2>/dev/null || true
	RELAY_PID=""
}

step "apassy-relay init and serve"
"$RELAY_BIN" init --team e2e --owner owner >"$TMP/owner_token" 2>"$TMP/init.err"
grep -Eq '^apassy_mbr_[0-9a-f]{64}$' "$TMP/owner_token" || fail "init did not print one owner token"
ok "init printed the owner token once"
"$RELAY_BIN" serve 2>"$TMP/serve.err" &
RELAY_PID=$!
wait_healthy
ok "apassy-relay serve answers /healthz"
code=$(curl -s -o "$TMP/noedge.json" -w '%{http_code}' "$URL/v1/me")
[ "$code" = 403 ] && grep -q '"edge_refused"' "$TMP/noedge.json" || fail "no edge header was not refused"
code=$(curl -s -o /dev/null -w '%{http_code}' -H "X-Apassy-Edge: $EDGE" "$URL/v1/me")
[ "$code" = 401 ] || fail "the edge header alone gave $code, not 401"
ok "no edge header: 403 edge_refused; edge header without a token: 401"
stop_relay

step "Serve the same vault with the mock upstream (examples/e2e_relay.rs)"
E2E_UPSTREAM_LOG="$TMP/upstream.log" "$E2E_BIN" 2>"$TMP/e2e_relay.err" &
RELAY_PID=$!
wait_healthy
ok "relay with mock upstream on $URL"

OWNER_CFG="$TMP/owner-config"
MEMBER_CFG="$TMP/member-config"
AGENT_CFG="$TMP/agent-config"
mkdir -p "$OWNER_CFG" "$MEMBER_CFG" "$AGENT_CFG"
owner() { XDG_CONFIG_HOME="$OWNER_CFG" APASSY_EDGE_SECRET="$EDGE" "$TEAM_BIN" "$@"; }
member() { XDG_CONFIG_HOME="$MEMBER_CFG" APASSY_EDGE_SECRET="$EDGE" "$TEAM_BIN" "$@"; }
agent() {
	XDG_CONFIG_HOME="$AGENT_CFG" APASSY_RELAY_URL="$URL" APASSY_TOKEN="$AGENT_TOKEN" \
		APASSY_EDGE_SECRET="$EDGE" "$TEAM_BIN" "$@"
}

step "Team setup with apassy-team"
owner init --relay "$URL" <"$TMP/owner_token"
COLLECTION=$(owner collection create payments)
STRIPE_ITEM=$(printf '%s' "$STRIPE_CANARY" | owner item add --collection "$COLLECTION" \
	--name "Stripe test key" --env STRIPE_API_KEY --environment staging --provider stripe)
GITHUB_ITEM=$(printf '%s' "$GITHUB_CANARY" | owner item add --collection "$COLLECTION" \
	--name "GitHub deploy token" --env GITHUB_TOKEN --environment production --host api.github.com)
ok "collection $COLLECTION, staging Stripe item $STRIPE_ITEM, production GitHub item $GITHUB_ITEM"
owner invite --role member >"$TMP/invite_code" 2>/dev/null
member join --relay "$URL" --name alice <"$TMP/invite_code" >"$TMP/join.out"
MEMBER_ID=$(sed -n 's/.*(member \([0-9][0-9]*\)).*/\1/p' "$TMP/join.out")
[ -n "$MEMBER_ID" ] || fail "join did not print a member id"
if member join --relay "$URL" --name bob <"$TMP/invite_code" >/dev/null 2>&1; then
	fail "an invite code worked twice"
fi
ok "alice joined as member $MEMBER_ID; the invite code does not work twice"
GRANT=$(owner grant --collection "$COLLECTION" --member "$MEMBER_ID")
AGENT_TOKEN=$(member agent create alice-agent 2>/dev/null)
case "$AGENT_TOKEN" in apassy_agt_*) ;; *) fail "agent create did not print a token" ;; esac
ok "grant $GRANT; alice made an agent token"
agent access >"$TMP/access.out"
grep -q STRIPE_API_KEY "$TMP/access.out" || fail "the agent does not see its items"

step "A known-safe command runs at once"
agent run --items "$STRIPE_ITEM" --purpose "list the files" \
	--request "Show me the files in this folder." -- ls -la >"$TMP/ls.out" 2>"$TMP/ls.err" ||
	fail "the known-safe run failed: $(cat "$TMP/ls.err")"
grep -q "Waiting for an approver" "$TMP/ls.err" && fail "the known-safe run waited"
ok "ls -la ran without an approver"

wait_pending() {
	for _ in $(seq 1 100); do
		owner pending --json >"$TMP/pending.json"
		RUN_ID=$(sed -n 's/.*"run_id": *\([0-9][0-9]*\).*/\1/p' "$TMP/pending.json" | head -n1)
		if [ -n "$RUN_ID" ]; then return 0; fi
		sleep 0.1
	done
	fail "no run is pending"
}

step "A production item waits; the owner denies"
agent run --items "$GITHUB_ITEM" --purpose "check the repo" \
	--request "What is the state of my repo?" --wait 60 -- git status >/dev/null 2>"$TMP/deny.err" &
RUN_PID=$!
wait_pending
owner pending >"$TMP/pending.txt"
grep -q "Production credential" "$TMP/pending.txt" || fail "the pending run has no production note"
owner deny "$RUN_ID" --reason "not now"
status=0
wait "$RUN_PID" || status=$?
[ "$status" = 3 ] || fail "a denied run exited $status, not 3"
grep -q approval_denied "$TMP/deny.err" || fail "the denial has no code"
ok "run $RUN_ID waited, was denied, and apassy-team run exited 3"

step "A production item waits; the owner approves; the command calls the proxy"
# The child gets the edge secret as E2E_EDGE, because here there is no Worker in
# front of the relay to add it. apassy-team never passes APASSY_EDGE_SECRET on.
# shellcheck disable=SC2016
CHILD='curl -sS -D "$E2E_DIR/headers.txt" -H "X-Apassy-Edge: $E2E_EDGE" -H "Authorization: Bearer $GITHUB_TOKEN" "$GITHUB_API_URL/user"; printf "\nplaceholder=%s\n" "$GITHUB_TOKEN"; printf "%s\n%s\n" "$GITHUB_TOKEN" "$GITHUB_API_URL" > "$E2E_DIR/session"'
E2E_DIR="$TMP" E2E_EDGE="$EDGE" agent run --items "$GITHUB_ITEM" --purpose "read the GitHub user" \
	--request "Who am I on GitHub?" --wait 60 -- sh -c "$CHILD" >"$TMP/run.out" 2>"$TMP/run.err" &
RUN_PID=$!
wait_pending
owner approve "$RUN_ID" --reason "fine for the check"
status=0
wait "$RUN_PID" || status=$?
[ "$status" = 0 ] || fail "the approved run exited $status: $(cat "$TMP/run.err")"
grep -q "Waiting for an approver (run $RUN_ID)" "$TMP/run.err" || fail "the run did not wait"
PLACEHOLDER=$(sed -n 's/^placeholder=//p' "$TMP/run.out")
[ -n "$PLACEHOLDER" ] || fail "the command printed no placeholder"
[ "$PLACEHOLDER" != "$GITHUB_CANARY" ] || fail "the command got the real value"
[ "${#PLACEHOLDER}" = "${#GITHUB_CANARY}" ] || fail "the placeholder has another length"
for _ in $(seq 1 40); do
	if grep -qs "authorization=Bearer $GITHUB_CANARY" "$TMP/upstream.log"; then break; fi
	sleep 0.05
done
grep -qs "authorization=Bearer $GITHUB_CANARY" "$TMP/upstream.log" ||
	fail "the upstream did not see the real value. Command output: $(cat "$TMP/run.out")"
grep -q "\"authorization\":\"Bearer $PLACEHOLDER\"" "$TMP/run.out" ||
	fail "the echo did not come back with the placeholder"
grep -qi "^x-echo-authorization: Bearer $PLACEHOLDER" "$TMP/headers.txt" ||
	fail "the echo header did not come back with the placeholder"
if grep -q "$GITHUB_CANARY" "$TMP/run.out" "$TMP/run.err" "$TMP/headers.txt"; then
	fail "the command output holds the real value"
fi
echo "upstream saw:   $(grep 'api.github.com GET /user' "$TMP/upstream.log" | tail -n1)"
echo "command saw:    $(grep -o '"authorization":"[^"]*"' "$TMP/run.out" | head -n1)"
ok "run $RUN_ID: the upstream saw the synthetic value, the command saw only the placeholder"

step "Revoke the grant"
owner revoke --grant "$GRANT"
SESSION_BASE=$(sed -n 2p "$TMP/session")
code=$(curl -s -o "$TMP/revoked.json" -w '%{http_code}' -H "X-Apassy-Edge: $EDGE" \
	-H "Authorization: Bearer $PLACEHOLDER" "$SESSION_BASE/user")
[ "$code" = 403 ] && grep -q '"session_invalid"' "$TMP/revoked.json" ||
	fail "the session still works after revocation ($code)"
ok "the live session is refused: 403 session_invalid"
status=0
agent run --items "$GITHUB_ITEM" --purpose "check the repo" --request "Again?" -- true \
	>/dev/null 2>"$TMP/revoked.err" || status=$?
[ "$status" = 3 ] && grep -q not_granted "$TMP/revoked.err" ||
	fail "a run after revocation exited $status: $(cat "$TMP/revoked.err")"
ok "a new run is denied: not_granted, exit 3"

step "The audit holds no secret"
owner audit --json --limit 500 >"$TMP/audit.json"
for action in run_allowed run_pending run_denied run_approved session_started session_ended grant_revoked proxy_request; do
	grep -q "\"$action\"" "$TMP/audit.json" || fail "the audit has no $action"
done
for needle in "$STRIPE_CANARY" "$GITHUB_CANARY" "$PLACEHOLDER" "$AGENT_TOKEN" \
	"$(cat "$TMP/owner_token")" "$(cat "$TMP/invite_code")" "$EDGE" apassy_ses_; do
	if grep -qF "$needle" "$TMP/audit.json"; then fail "the audit holds a secret"; fi
done
ok "$(grep -c '"action"' "$TMP/audit.json") audit rows, no value, placeholder, token, or session key"

printf '\nE2E PASSED\n'
