#!/usr/bin/env bash
# LibreVote MVP demo script.
# Creates a full voting workflow on Node A, serves it via HTTP,
# and syncs it to a fresh Node B using P2P peer sync.
#
# Usage:
#   ./scripts/demo-mvp.sh                         # build + run
#   ./scripts/demo-mvp.sh /path/to/librevote       # use pre-built binary
#   ./scripts/demo-mvp.sh -keep                    # keep temp dir after run
#
# Deterministic: every run produces the same tally. Safe to rerun.

set -euo pipefail

KEEP=false
BIN=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -keep) KEEP=true; shift ;;
    *)     BIN="$1"; shift ;;
  esac
done

TMPDIR="$(mktemp -d -t librevote-demo.XXXXXX)"

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    echo
    echo "[demo] stopping node A server (pid $SERVER_PID)..."
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  if $KEEP; then
    echo "[demo] kept data dir: $TMPDIR"
  else
    rm -rf "$TMPDIR"
  fi
}
trap cleanup EXIT

if [[ -z "$BIN" ]]; then
  echo "[demo] building librevote ..."
  SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
  PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
  BIN="${TMPDIR}/librevote"
  go build -o "$BIN" "$PROJECT_DIR/cmd/librevote"
fi

if [[ ! -x "$BIN" ]]; then
  echo "error: binary not found or not executable: $BIN" >&2
  exit 1
fi

# Find a free port on 127.0.0.1.
PORT=$(python3 -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()" 2>/dev/null) || true
if [[ -z "$PORT" ]]; then
  for p in $(seq 20000 20100); do
    if ! ss -tln 2>/dev/null | grep -q "127.0.0.1:$p "; then
      PORT=$p
      break
    fi
  done
fi
if [[ -z "$PORT" ]]; then
  echo "error: could not find free port" >&2
  exit 1
fi

DB_A="${TMPDIR}/demo_a.sqlite"
DB_B="${TMPDIR}/demo_b.sqlite"
NET="demo-net"
PEER_URL="http://127.0.0.1:${PORT}"

# run prints the command, executes it, and fails on non-zero exit.
run() {
  local label="$1"
  shift
  echo
  echo "--- $label ---"
  echo "\$ librevote $*"
  "$BIN" "$@"
}

echo "=== LibreVote MVP Demo ==="
echo "demo dir: $TMPDIR"
echo "node A db: $DB_A"
echo "node B db: $DB_B"
echo "network:  $NET"
echo "port:     $PORT"

# ---- Node A: Create full workflow ----

run "init A"               init                         --db "$DB_A" --network "$NET"

run "trustee election"     trustee-election create      --db "$DB_A" --network "$NET" --id ts-demo --title "MVP Trustee Selection"

run "nomination alice"     trustee nominate             --db "$DB_A" --network "$NET" --selection ts-demo --name alice
run "nomination bob"       trustee nominate             --db "$DB_A" --network "$NET" --selection ts-demo --name bob
run "nomination carol"     trustee nominate             --db "$DB_A" --network "$NET" --selection ts-demo --name carol

run "trustee vote"         trustee vote                --db "$DB_A" --network "$NET" --selection ts-demo --voter voter-1 --candidates alice,bob,carol

run "result build"         trustee result build         --db "$DB_A" --network "$NET" --selection ts-demo

run "election create"      election create              --db "$DB_A" --network "$NET" --id an-demo --title "Demo Election" --selection ts-demo --options yes,no,abstain

run "consent alice"        trustee consent              --db "$DB_A" --network "$NET" --name alice --election an-demo
run "consent bob"          trustee consent              --db "$DB_A" --network "$NET" --name bob   --election an-demo
run "consent carol"        trustee consent              --db "$DB_A" --network "$NET" --name carol --election an-demo

run "tally-key alice"      tally-key contribute         --db "$DB_A" --network "$NET" --election an-demo --name alice
run "tally-key bob"        tally-key contribute         --db "$DB_A" --network "$NET" --election an-demo --name bob
run "tally-key carol"      tally-key contribute         --db "$DB_A" --network "$NET" --election an-demo --name carol

run "tally-key build"      tally-key build              --db "$DB_A" --network "$NET" --election an-demo

run "ballot voter-1"       ballot cast                  --db "$DB_A" --network "$NET" --election an-demo --voter voter-1 --choice yes
run "ballot voter-2"       ballot cast                  --db "$DB_A" --network "$NET" --election an-demo --voter voter-2 --choice no
run "ballot voter-3"       ballot cast                  --db "$DB_A" --network "$NET" --election an-demo --voter voter-3 --choice yes

run "tally build A"        tally build                  --db "$DB_A" --network "$NET" --election an-demo

echo
echo "========== TALLY RESULT (Node A, local compute) =========="
run "tally show A"         tally show                   --db "$DB_A" --network "$NET" --election an-demo
echo "=========================================================="

# ---- Start Node A HTTP server ----

echo
echo "--- starting node A server on ${PEER_URL} ---"
"$BIN" node serve --db "$DB_A" --listen "127.0.0.1:${PORT}" &
SERVER_PID=$!
echo "[demo] node A server pid: $SERVER_PID"

# Wait until the server is accepting connections.
for i in $(seq 1 20); do
  if curl -sf "${PEER_URL}/inventory?scope=network" >/dev/null 2>&1; then
    echo "[demo] node A server ready (attempt $i)"
    break
  fi
  sleep 0.25
done

# ---- Node B: Init, sync from Node A, and show tally ----

run "init B"               init                         --db "$DB_B" --network "$NET"

echo
echo "============ P2P SYNC: Node B pulls objects from Node A ============"

# First pass: objects with cross-scope dependencies will land as pending_dependencies.
run "sync network scope"   node sync                    --db "$DB_B" --peer "$PEER_URL" --scope network

run "sync trustee scope"   node sync                    --db "$DB_B" --peer "$PEER_URL" --scope trustee_selection_id --scope-id ts-demo

run "sync election scope"  node sync                    --db "$DB_B" --peer "$PEER_URL" --scope election_id --scope-id an-demo

echo "--- second pass: revalidate pending cross-scope dependencies ---"

# Second pass: pending objects are not servable and will be re-fetched.
# Their dependencies are now available from the first pass.
run "sync network (2)"     node sync                    --db "$DB_B" --peer "$PEER_URL" --scope network

run "sync election (2)"    node sync                    --db "$DB_B" --peer "$PEER_URL" --scope election_id --scope-id an-demo

echo "====================================================================="

echo
echo "========== TALLY RESULT (Node B, via P2P sync) =========="
run "tally show B"         tally show                   --db "$DB_B" --network "$NET" --election an-demo
echo "=========================================================="

echo
echo "demo complete"
