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
#      production GitHub item (each value is sealed by the CLI, and its key goes to
#      keys.json in a temp XDG dir), an invite, a member, a grant, an agent token;
#   4. starts `apassy-team host` on the owner's side, cut off from any terminal;
#   5. runs a known-safe command with the staging item: the host releases it by
#      itself, with no question;
#   6. asks for a known-safe session as an agent, and uses it against the mock
#      upstream: the upstream sees the real synthetic value, the agent sees only the
#      placeholder;
#   7. runs a command with the production item: the host must ask the person, there
#      is no terminal, so it denies the run ("No one at the host."). (The yes path
#      is in tests/e2e.rs, where a test gives the answers. No switch here or there
#      can approve a run without a person.);
#   8. runs a command with an item whose key is not on this host: denied, unknown item;
#   9. revokes the grant: the live session is refused, and a new run is denied;
#  10. checks that the audit and host.log hold no value, placeholder, token, or item key.
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
BIN="${CARGO_TARGET_DIR:-$ROOT/target}/debug"
RELAY_BIN="$BIN/apassy-relay"
TEAM_BIN="$BIN/apassy-team"
E2E_BIN="$BIN/examples/e2e_relay"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/apassy-relay-e2e.XXXXXX")"
RELAY_PID=""
HOST_PID=""
cleanup() {
	if [ -n "$HOST_PID" ]; then kill "$HOST_PID" 2>/dev/null || true; fi
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
unset APASSY_RELAY_URL APASSY_TEAM_TOKEN APASSY_TOKEN APASSY_EDGE_SECRET APASSY_TEAM
# Device keys go to files in the temp config dirs, never to the macOS Keychain.
export APASSY_TEAM_KEY_STORE=file

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
grep -Eq '^apassy_mbr_t_[a-z2-7]{10}_[0-9a-f]{64}$' "$TMP/owner_token" || fail "init did not print one owner token"
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
# Starts the owner's host in the background, cut off from any terminal. The subshell
# execs, so $! (HOST_PID) is the host process itself and `kill` stops it.
start_host() {
	(
		export XDG_CONFIG_HOME="$OWNER_CFG" APASSY_EDGE_SECRET="$EDGE"
		exec perl -MPOSIX -e 'POSIX::setsid() or die "setsid: $!\n"; exec @ARGV or die "exec: $!\n"' \
			"$TEAM_BIN" host
	) >"$1" 2>"$2" &
	HOST_PID=$!
}
mode_of() { perl -e 'printf "%o\n", (stat $ARGV[0])[2] & 0777' "$1"; }
member() { XDG_CONFIG_HOME="$MEMBER_CFG" APASSY_EDGE_SECRET="$EDGE" "$TEAM_BIN" "$@"; }
agent() {
	XDG_CONFIG_HOME="$AGENT_CFG" APASSY_RELAY_URL="$URL" APASSY_TOKEN="$AGENT_TOKEN" \
		APASSY_EDGE_SECRET="$EDGE" "$TEAM_BIN" "$@"
}

step "Team setup with apassy-team"
owner init --relay "$URL" <"$TMP/owner_token"
COLLECTION=$(owner collection create payments)
STRIPE_ITEM=$(printf '%s' "$STRIPE_CANARY" | owner item add --collection "$COLLECTION" \
	--name "Stripe test key" --env STRIPE_API_KEY --environment staging --provider stripe \
	2>"$TMP/item1.err")
GITHUB_ITEM=$(printf '%s' "$GITHUB_CANARY" | owner item add --collection "$COLLECTION" \
	--name "GitHub deploy token" --env GITHUB_TOKEN --environment production --host api.github.com \
	2>"$TMP/item2.err")
ok "collection $COLLECTION, staging Stripe item $STRIPE_ITEM, production GitHub item $GITHUB_ITEM"
KEYS="$OWNER_CFG/apassy-team/keys.json"
[ -f "$KEYS" ] || fail "item add wrote no keys.json"
[ "$(mode_of "$KEYS")" = 600 ] || fail "keys.json is not mode 0600"
[ "$(mode_of "$OWNER_CFG/apassy-team")" = 700 ] || fail "the key directory is not mode 0700"
[ "$(grep -c '"uid"' "$KEYS")" = 2 ] || fail "keys.json does not hold two items"
grep -q "keys.json" "$TMP/item1.err" || fail "item add did not say where the key is"
if grep -qF "$STRIPE_CANARY" "$KEYS" "$TMP/item1.err" "$TMP/item2.err"; then
	fail "the value is in keys.json or in the output of item add"
fi
ITEM_KEYS=$(sed -n 's/^ *"key": *"\([^"]*\)".*/\1/p' "$KEYS")
[ "$(printf '%s\n' "$ITEM_KEYS" | wc -l | tr -d ' ')" = 2 ] || fail "keys.json does not hold two keys"
ok "keys.json has both keys (mode 0600, directory 0700); the value is not in it"
owner invite --role member --name alice --grant "$COLLECTION" >"$TMP/invite_link" 2>/dev/null
grep -Eq "^$URL/join#apassy_inv_t_[a-z2-7]{10}_[0-9a-f]{64}\$" "$TMP/invite_link" || fail "invite did not print one link"
member join --relay "$URL" --device alice-laptop --no-wait <"$TMP/invite_link" >"$TMP/join.out" 2>"$TMP/join.err" ||
	fail "join failed: $(cat "$TMP/join.err")"
WORDS=$(sed -n 's/.*Safety words: //p' "$TMP/join.out")
[ "$(printf '%s\n' "$WORDS" | wc -w | tr -d ' ')" = 2 ] || fail "join did not print two safety words: $(cat "$TMP/join.out")"
JOIN_ID=$(owner joins | awk '$2 == "alice" {print $1}')
[ -n "$JOIN_ID" ] || fail "the owner does not see the join of alice"
if owner joins --json | grep -qF "$WORDS"; then fail "the relay shows the safety words to the confirmer"; fi
if owner confirm "$JOIN_ID" --words "wrong words" >/dev/null 2>&1; then fail "a join was confirmed with wrong words"; fi
owner confirm "$JOIN_ID" --words "$WORDS" >/dev/null || fail "the owner could not confirm with the right words"
member join --resume >"$TMP/joined.out" 2>&1 || fail "join --resume failed: $(cat "$TMP/joined.out")"
grep -q "Joined" "$TMP/joined.out" || fail "the member did not join: $(cat "$TMP/joined.out")"
member me | grep -q "member alice" || fail "alice cannot sign in with her device"
BOB_CFG="$TMP/bob-config"
mkdir -p "$BOB_CFG"
if XDG_CONFIG_HOME="$BOB_CFG" APASSY_EDGE_SECRET="$EDGE" "$TEAM_BIN" join --relay "$URL" --name bob \
	--device bob-laptop --no-wait <"$TMP/invite_link" >/dev/null 2>&1; then
	fail "an invite code worked twice"
fi
MEMBER_ID=$(owner members | awk '$2 == "alice" {print $1}')
ok "alice joined as member $MEMBER_ID with a device after the owner typed her words; the invite works once"
GRANT=$(owner grants | awk '/alice/ {print $1}')
[ -n "$GRANT" ] || fail "the invite did not grant the collection"
AGENT_TOKEN=$(member agent create alice-agent 2>/dev/null)
case "$AGENT_TOKEN" in apassy_tagt_t_*) ;; *) fail "agent create did not print a token" ;; esac
ok "grant $GRANT; alice made an agent token"
agent access >"$TMP/access.out"
grep -q STRIPE_API_KEY "$TMP/access.out" || fail "the agent does not see its items"

step "Start the owner's host (no terminal)"
# The host asks the person on /dev/tty. Here there is no person: setsid cuts the
# process off from any terminal, so a question can only end in a denial. There is no
# switch that says yes.
start_host "$TMP/host.out" "$TMP/host.err"
for _ in $(seq 1 100); do
	if grep -q "apassy-team host: team" "$TMP/host.err" 2>/dev/null; then break; fi
	if ! kill -0 "$HOST_PID" 2>/dev/null; then fail "the host exited: $(cat "$TMP/host.err")"; fi
	sleep 0.1
done
grep -q "apassy-team host: team" "$TMP/host.err" || fail "the host did not start: $(cat "$TMP/host.err")"
ok "apassy-team host is waiting for runs"
HOST_LOG="$OWNER_CFG/apassy-team/host.log"
last_decision() { tail -n1 "$HOST_LOG" | sed -n 's/.*"decision":"\([a-z_]*\)".*/\1/p'; }

step "A known-safe command runs with no question"
agent run --items "$STRIPE_ITEM" --purpose "list the files" \
	--request "Show me the files in this folder." --wait 60 -- ls -la >"$TMP/ls.out" 2>"$TMP/ls.err" ||
	fail "the known-safe run failed: $(cat "$TMP/ls.err")"
[ "$(last_decision)" = auto ] || fail "the host did not release it by itself (log: $(tail -n1 "$HOST_LOG"))"
ok "ls -la waited for the host, and the host released it automatically"

step "A known-safe session works against the mock upstream"
# The agent asks through the API, because apassy-team run keeps the session to itself.
ask_run() {
	# $1 item id, $2 JSON array of the command
	curl -sS -H "X-Apassy-Edge: $EDGE" -H "Authorization: Bearer $AGENT_TOKEN" \
		-H 'Content-Type: application/json' -X POST "$URL/v1/runs" \
		-d "{\"items\":[$1],\"command\":$2,\"purpose\":\"read the balance\",\"user_request\":\"What is my Stripe balance?\",\"cwd\":\"/work\"}"
}
ask_run "$STRIPE_ITEM" '["stripe","balance","retrieve"]' >"$TMP/ask.json"
grep -q '"status":"pending"' "$TMP/ask.json" || fail "a known-safe run was not pending: $(cat "$TMP/ask.json")"
if grep -q '"session"' "$TMP/ask.json"; then fail "a session came before the release"; fi
BAL_RUN=$(sed -n 's/.*"run_id":\([0-9][0-9]*\).*/\1/p' "$TMP/ask.json")
for _ in $(seq 1 100); do
	curl -sS -H "X-Apassy-Edge: $EDGE" -H "Authorization: Bearer $AGENT_TOKEN" \
		"$URL/v1/runs/$BAL_RUN?wait=2" >"$TMP/bal.json"
	if grep -q '"status":"ready"' "$TMP/bal.json"; then break; fi
	if grep -q '"status":"denied"\|"status":"timed_out"' "$TMP/bal.json"; then
		fail "the balance run did not start: $(cat "$TMP/bal.json")"
	fi
done
grep -q '"status":"ready"' "$TMP/bal.json" || fail "the balance run never became ready"
PLACEHOLDER=$(sed -n 's/.*"STRIPE_API_KEY":"\([^"]*\)".*/\1/p' "$TMP/bal.json")
SESSION_BASE=$(sed -n 's/.*"STRIPE_API_BASE":"\([^"]*\)".*/\1/p' "$TMP/bal.json")
[ -n "$PLACEHOLDER" ] && [ -n "$SESSION_BASE" ] || fail "no session in the ready run"
[ "$PLACEHOLDER" != "$STRIPE_CANARY" ] || fail "the agent got the real value"
[ "${#PLACEHOLDER}" = "${#STRIPE_CANARY}" ] || fail "the placeholder has another length"
curl -sS -D "$TMP/headers.txt" -H "X-Apassy-Edge: $EDGE" -H "Authorization: Bearer $PLACEHOLDER" \
	"$SESSION_BASE/v1/balance" >"$TMP/balance.out"
for _ in $(seq 1 40); do
	if grep -qs "authorization=Bearer $STRIPE_CANARY" "$TMP/upstream.log"; then break; fi
	sleep 0.05
done
grep -qs "authorization=Bearer $STRIPE_CANARY" "$TMP/upstream.log" ||
	fail "the upstream did not see the real value. Output: $(cat "$TMP/balance.out")"
grep -q "\"authorization\":\"Bearer $PLACEHOLDER\"" "$TMP/balance.out" ||
	fail "the echo did not come back with the placeholder"
grep -qi "^x-echo-authorization: Bearer $PLACEHOLDER" "$TMP/headers.txt" ||
	fail "the echo header did not come back with the placeholder"
if grep -qF "$STRIPE_CANARY" "$TMP/balance.out" "$TMP/headers.txt" "$TMP/bal.json"; then
	fail "the agent saw the real value"
fi
echo "upstream saw:   $(grep 'api.stripe.com GET /v1/balance' "$TMP/upstream.log" | tail -n1)"
echo "agent saw:      $(grep -o '"authorization":"[^"]*"' "$TMP/balance.out" | head -n1)"
ok "run $BAL_RUN: the upstream saw the synthetic value, the agent saw only the placeholder"
[ "$(last_decision)" = auto ] || fail "the host did not release the balance run by itself"

step "A production item needs a person: no one is there, so the host denies"
status=0
agent run --items "$GITHUB_ITEM" --purpose "check the repo" \
	--request "What is the state of my repo?" --wait 60 -- git status >/dev/null 2>"$TMP/deny.err" || status=$?
[ "$status" = 3 ] || fail "a production run exited $status, not 3"
grep -q approval_denied "$TMP/deny.err" || fail "the denial has no code"
grep -q "No one at the host." "$TMP/deny.err" || fail "the denial has no reason: $(cat "$TMP/deny.err")"
[ "$(last_decision)" = denied ] || fail "the host did not log a denial"
ok "the production run was denied by the host ('No one at the host.'), and apassy-team run exited 3"

step "An item whose key is not on this host is denied"
# Someone with the owner token adds an item on the relay without the host's key
# store: a sealed text of random bytes. The host has no key for it.
FOREIGN_UID=$(openssl rand -hex 16)
FOREIGN_SEALED=$(openssl rand 40 | openssl base64 -A | tr '+/' '-_' | tr -d '=')
code=$(curl -s -o "$TMP/foreign.json" -w '%{http_code}' -H "X-Apassy-Edge: $EDGE" \
	-H "Authorization: Bearer $(cat "$TMP/owner_token")" -H 'Content-Type: application/json' \
	-X POST "$URL/v1/items" \
	-d "{\"collection_id\":$COLLECTION,\"name\":\"Foreign\",\"env_name\":\"FOREIGN_KEY\",\"uid\":\"$FOREIGN_UID\",\"sealed\":\"$FOREIGN_SEALED\",\"hosts\":[\"api.example.com\"],\"environment\":\"staging\"}")
[ "$code" = 200 ] || fail "the relay refused the foreign item ($code): $(cat "$TMP/foreign.json")"
FOREIGN_ITEM=$(sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p' "$TMP/foreign.json")
status=0
agent run --items "$FOREIGN_ITEM" --purpose "list the files" --request "Show me the files." \
	--wait 60 -- ls -la >/dev/null 2>"$TMP/foreign.err" || status=$?
[ "$status" = 3 ] || fail "a run with a foreign item exited $status, not 3"
grep -q "Unknown item on this host." "$TMP/foreign.err" || fail "no reason: $(cat "$TMP/foreign.err")"
[ "$(last_decision)" = unknown_item ] || fail "the host did not log the unknown item"
ok "the run was denied: Unknown item on this host."

step "Revoke the grant"
owner revoke --grant "$GRANT"
code=$(curl -s -o "$TMP/revoked.json" -w '%{http_code}' -H "X-Apassy-Edge: $EDGE" \
	-H "Authorization: Bearer $PLACEHOLDER" "$SESSION_BASE/v1/balance")
[ "$code" = 403 ] && grep -q '"session_invalid"' "$TMP/revoked.json" ||
	fail "the session still works after revocation ($code)"
ok "the live session is refused: 403 session_invalid"
status=0
agent run --items "$STRIPE_ITEM" --purpose "check the repo" --request "Again?" -- true \
	>/dev/null 2>"$TMP/revoked.err" || status=$?
[ "$status" = 3 ] && grep -q not_granted "$TMP/revoked.err" ||
	fail "a run after revocation exited $status: $(cat "$TMP/revoked.err")"
ok "a new run is denied: not_granted, exit 3"

step "The approve endpoint says where to approve"
code=$(curl -s -o "$TMP/approve.json" -w '%{http_code}' -H "X-Apassy-Edge: $EDGE" \
	-H "Authorization: Bearer $(cat "$TMP/owner_token")" -X POST "$URL/v1/approvals/1/approve")
[ "$code" = 403 ] && grep -q '"approve_on_host"' "$TMP/approve.json" || fail "approve gave $code"
status=0
owner approve 1 >/dev/null 2>"$TMP/approve.err" || status=$?
[ "$status" = 2 ] && grep -q "apassy-team host" "$TMP/approve.err" || fail "apassy-team approve: exit $status"
ok "approve: 403 approve_on_host, and the CLI points to apassy-team host"

step "The owner moves from the owner token to a device key"
kill "$HOST_PID" 2>/dev/null || true
wait "$HOST_PID" 2>/dev/null || true
HOST_PID=""
owner device enroll --name owner-mac >"$TMP/enroll.out" 2>&1 || fail "device enroll failed: $(cat "$TMP/enroll.out")"
grep -q "Enrolled device" "$TMP/enroll.out" || fail "device enroll did not enroll: $(cat "$TMP/enroll.out")"
if grep -qF "$(cat "$TMP/owner_token")" "$OWNER_CFG/apassy-team/settings.json"; then
	fail "the owner token is still in the settings"
fi
code=$(curl -s -o /dev/null -w '%{http_code}' -H "X-Apassy-Edge: $EDGE" \
	-H "Authorization: Bearer $(cat "$TMP/owner_token")" "$URL/v1/me")
[ "$code" = 401 ] || fail "the owner token still works after enroll ($code)"
owner device list | grep -q "owner-mac" || fail "the owner cannot sign in with the device"
start_host "$TMP/host2.out" "$TMP/host2.err"
for _ in $(seq 1 100); do
	if grep -q "apassy-team host: team" "$TMP/host2.err" 2>/dev/null; then break; fi
	if ! kill -0 "$HOST_PID" 2>/dev/null; then fail "the device host exited: $(cat "$TMP/host2.err")"; fi
	sleep 0.1
done
grep -q "apassy-team host: team" "$TMP/host2.err" || fail "the device host did not start: $(cat "$TMP/host2.err")"
owner grant --collection "$COLLECTION" --member "$MEMBER_ID" >/dev/null
agent run --items "$STRIPE_ITEM" --purpose "list the files" \
	--request "Show me the files in this folder." --wait 60 -- ls -la >/dev/null 2>"$TMP/ls2.err" ||
	fail "the run through the device host failed: $(cat "$TMP/ls2.err")"
[ "$(last_decision)" = auto ] || fail "the device host did not release it (log: $(tail -n1 "$HOST_LOG"))"
ok "the owner token stopped; the key-holder device signs in and its host releases a run"

step "A second team on the same relay"
"$RELAY_BIN" admin team-code --hours 1 >"$TMP/team_code" 2>/dev/null
grep -Eq '^apassy_tcd_[0-9a-f]{64}$' "$TMP/team_code" || fail "admin team-code did not print one code"
SECOND_CFG="$TMP/second-config"
mkdir -p "$SECOND_CFG"
second() { XDG_CONFIG_HOME="$SECOND_CFG" APASSY_EDGE_SECRET="$EDGE" "$TEAM_BIN" "$@"; }
second create --relay "$URL" --team second --name olga <"$TMP/team_code" >"$TMP/create.out"
if second create --relay "$URL" --team third --name eve <"$TMP/team_code" >/dev/null 2>&1; then
	fail "a team code worked twice"
fi
second me | grep -q '^team second (t_' || fail "the second owner is not in the second team"
if second item list | grep -q STRIPE_API_KEY; then fail "the second team sees an item of the first"; fi
owner me | grep -q '^team e2e (t_' || fail "the first owner left the first team"
"$RELAY_BIN" admin teams >"$TMP/teams.json"
[ "$(grep -c '"id"' "$TMP/teams.json")" = 2 ] || fail "admin teams does not list two teams"
if grep -q -e payments -e alice -e STRIPE "$TMP/teams.json"; then fail "admin teams shows team content"; fi
ok "admin team-code, apassy-team create, two separate teams, the operator sees no content"

step "The audit and host.log hold no secret"
owner audit --json --limit 500 >"$TMP/audit.json"
for action in run_pending run_denied run_released session_started session_ended grant_revoked proxy_request; do
	grep -q "\"$action\"" "$TMP/audit.json" || fail "the audit has no $action"
done
for action in run_approved run_allowed; do
	if grep -q "\"$action\"" "$TMP/audit.json"; then fail "the audit has $action"; fi
done
for needle in "$STRIPE_CANARY" "$GITHUB_CANARY" "$PLACEHOLDER" "$AGENT_TOKEN" \
	"$(cat "$TMP/owner_token")" "$(sed 's/.*#//' "$TMP/invite_link")" "$(cat "$TMP/team_code")" "$EDGE" \
	apassy_ses_ $ITEM_KEYS; do
	if grep -qF "$needle" "$TMP/audit.json" "$HOST_LOG"; then fail "the audit or host.log holds a secret"; fi
done
ok "$(grep -c '"action"' "$TMP/audit.json") audit rows and $(wc -l <"$HOST_LOG" | tr -d ' ') host.log lines, no value, placeholder, token, session key, or item key"

printf '\nE2E PASSED\n'
