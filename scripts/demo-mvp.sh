#!/usr/bin/env bash
# LibreVote MVP demo script — Stage 9 Networking Integration.
# Creates a full voting workflow on Node A, starts both nodes with
# libp2p/Kademlia discovery + GossipSub announcements to demonstrate
# the full P2P object sync path.
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

# Track PIDs for cleanup
NODE_A_PID=""
NODE_B_PID=""

cleanup() {
  echo
  for pid in "$NODE_B_PID" "$NODE_A_PID"; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      echo "[demo] stopping process pid $pid ..."
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
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
  echo "[demo] built: $BIN"
fi

if [[ ! -x "$BIN" ]]; then
  echo "error: binary not found or not executable: $BIN" >&2
  exit 1
fi

# Find a free port for HTTP.
find_free_port() {
  for p in $(seq 20000 20100); do
    if ! ss -tln 2>/dev/null | grep -q "127.0.0.1:$p "; then
      echo "$p"
      return
    fi
  done
  python3 -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()" 2>/dev/null || true
}

HTTP_PORT_A=$(find_free_port)
if [[ -z "$HTTP_PORT_A" ]]; then
  echo "error: could not find free HTTP port for Node A" >&2
  exit 1
fi

# HTTP_PORT_B is allocated after Node A binds, so ports are guaranteed distinct.

DB_A="${TMPDIR}/demo_a.sqlite"
DB_B="${TMPDIR}/demo_b.sqlite"
NET="demo-net"

# run prints the command, executes it, and fails on non-zero exit.
run() {
  local label="$1"
  shift
  echo
  echo "--- $label ---"
  echo "\$ librevote $*"
  "$BIN" "$@"
}

echo "=== LibreVote MVP Demo (Stage 9: P2P with Discovery + GossipSub) ==="
echo "demo dir: $TMPDIR"
echo "node A db: $DB_A"
echo "node B db: $DB_B"
echo "network:  $NET"
echo "node A HTTP port: $HTTP_PORT_A"

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

# ---- Stage 9: P2P Integration Demo ----

echo
echo "============ STAGE 9: P2P Discovery + GossipSub ============"

# Start Node A as an integrated node (HTTP + libp2p + GossipSub).
# Node A runs in server mode to act as a bootstrap peer.
NODE_A_KEY="${TMPDIR}/node_a.key"

echo
echo "--- starting integrated Node A ---"
echo "\$ librevote node start --db $DB_A --listen-http 127.0.0.1:${HTTP_PORT_A} \\"
echo "    --listen-p2p /ip4/127.0.0.1/tcp/0 --key $NODE_A_KEY \\"
echo "    --http-advertise http://127.0.0.1:${HTTP_PORT_A} --mode server \\"
echo "    --announce-interval 3s"
"$BIN" node start \
    --db "$DB_A" \
    --listen-http "127.0.0.1:${HTTP_PORT_A}" \
    --listen-p2p "/ip4/127.0.0.1/tcp/0" \
    --key "$NODE_A_KEY" \
    --http-advertise "http://127.0.0.1:${HTTP_PORT_A}" \
    --mode server \
    --announce-interval 3s \
    > "${TMPDIR}/node_a.out" 2>&1 &
NODE_A_PID=$!
echo "[demo] Node A pid: $NODE_A_PID"

# Wait for Node A to be ready (HTTP server + libp2p).
NODE_A_READY=false
for i in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:${HTTP_PORT_A}/inventory?scope=network" >/dev/null 2>&1; then
    echo "[demo] Node A HTTP ready (attempt $i)"
    NODE_A_READY=true
    break
  fi
  sleep 0.5
done
if ! $NODE_A_READY; then
  echo "error: Node A did not become ready on port $HTTP_PORT_A" >&2
  echo "Node A output (last 20 lines):"
  tail -20 "${TMPDIR}/node_a.out" 2>/dev/null || true
  exit 1
fi

# Extract Node A's peer ID and actual listen multiaddr from startup output.
PEER_ID_A=""
LISTEN_ADDR_A=""
if [[ -f "${TMPDIR}/node_a.out" ]]; then
  PEER_ID_A=$(grep -oP 'peer_id:\s*\K\S+' "${TMPDIR}/node_a.out" | head -1 || true)
  LISTEN_ADDR_A=$(grep -oP 'libp2p listen:\s*\K\S+' "${TMPDIR}/node_a.out" | head -1 || true)
fi
if [[ -z "$PEER_ID_A" ]]; then
  echo "[demo] warning: could not parse Node A peer_id from output"
fi
if [[ -z "$LISTEN_ADDR_A" ]]; then
  echo "[demo] warning: could not parse Node A listen address from output"
  echo "[demo] Node A output (first 20 lines):"
  head -20 "${TMPDIR}/node_a.out" 2>/dev/null || true
fi
echo "[demo] Node A peer_id: $PEER_ID_A"
echo "[demo] Node A listen multiaddr: $LISTEN_ADDR_A"

echo
echo "--- starting integrated Node B ---"

# Allocate Node B port after Node A is bound, guaranteeing distinct ports.
HTTP_PORT_B=$(find_free_port)
if [[ -z "$HTTP_PORT_B" ]]; then
  echo "error: could not find free HTTP port for Node B" >&2
  exit 1
fi
echo "[demo] node B HTTP port: $HTTP_PORT_B"

# Init Node B first.
run "init B"               init                         --db "$DB_B" --network "$NET"

NODE_B_KEY="${TMPDIR}/node_b.key"
BOOTSTRAP_NODE_B=""
if [[ -n "$LISTEN_ADDR_A" ]]; then
  BOOTSTRAP_NODE_B="$LISTEN_ADDR_A"
elif [[ -n "$PEER_ID_A" ]]; then
  echo "[demo] warning: no listen addr, falling back to constructed bootstrap"
  BOOTSTRAP_NODE_B="/ip4/127.0.0.1/tcp/0/p2p/${PEER_ID_A}"
fi

# Node B bootstraps from Node A's libp2p address if available,
# otherwise falls back to discovery-only mode.
NODE_B_ARGS=(
    --db "$DB_B"
    --listen-http "127.0.0.1:${HTTP_PORT_B}"
    --listen-p2p "/ip4/127.0.0.1/tcp/0"
    --key "$NODE_B_KEY"
    --http-advertise "http://127.0.0.1:${HTTP_PORT_B}"
    --mode client
    --announce-interval 10s
)
if [[ -n "$BOOTSTRAP_NODE_B" ]]; then
  NODE_B_ARGS+=(--bootstrap "$BOOTSTRAP_NODE_B")
fi

echo "\$ librevote node start ${NODE_B_ARGS[*]}"
"$BIN" node start "${NODE_B_ARGS[@]}" \
    > "${TMPDIR}/node_b.out" 2>&1 &
NODE_B_PID=$!
echo "[demo] Node B pid: $NODE_B_PID"

# Wait for Node B HTTP server.
NODE_B_READY=false
for i in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:${HTTP_PORT_B}/inventory?scope=network" >/dev/null 2>&1; then
    echo "[demo] Node B HTTP ready (attempt $i)"
    NODE_B_READY=true
    break
  fi
  sleep 0.5
done
if ! $NODE_B_READY; then
  echo "error: Node B did not become ready on port $HTTP_PORT_B" >&2
  echo "Node B output (last 20 lines):"
  tail -20 "${TMPDIR}/node_b.out" 2>/dev/null || true
  exit 1
fi

echo
echo "--- waiting for gossip sync between nodes ---"
# Wait for Node B to receive objects via GossipSub-triggered direct fetch.
# Node A announces its objects every 3 seconds with a unique publish timestamp
# so each cycle produces distinct GossipSub message IDs that bypass protocol-level
# duplicate suppression. Node B fetches full envelopes via HTTP and ingests them.
#
# Stage 9 success requires a servable TallyResult in election scope on Node B.
# Object count alone is insufficient; we explicitly check object_type.
SYNCED=false
TALLY_RESULT_OBJ_ID=""
for i in $(seq 1 40); do
  refs_json=$(curl -sf "http://127.0.0.1:${HTTP_PORT_B}/inventory?scope=election_id&scope_id=an-demo" 2>/dev/null || true)
  if [[ -n "$refs_json" ]]; then
    TALLY_RESULT_OBJ_ID=$(echo "$refs_json" | python3 -c "
import sys, json
refs = json.load(sys.stdin)
for r in refs:
    if r.get('object_type') == 'TallyResult':
        print(r['object_id'])
        break
" 2>/dev/null || true)
  fi
  if [[ -n "$TALLY_RESULT_OBJ_ID" ]]; then
    echo "[demo] Node B has servable TallyResult after $((i * 3)) seconds (id=$TALLY_RESULT_OBJ_ID)"
    SYNCED=true
    break
  fi
  if [[ $((i % 4)) -eq 0 ]]; then
    echo "[demo] waiting for TallyResult (${i}/40, +$((i * 3))s)... Node B election inventory:"
    if [[ -n "$refs_json" ]]; then
      echo "$refs_json" | python3 -m json.tool 2>/dev/null | grep -E 'object_type|TallyResult' | head -10 || echo "  (no TallyResult yet)"
    fi
  fi
  sleep 3
done

if ! $SYNCED; then
  echo
  echo "[demo] ================================================================"
  echo "[demo] *** FAILURE: GossipSub sync did not deliver TallyResult.     ***"
  echo "[demo] *** The P2P gossip path is required for this demo.           ***"
  echo "[demo] *** Static sync fallback is disabled to avoid masking bugs.  ***"
  echo "[demo] ================================================================" >&2
  exit 1
fi

echo
echo "===================================================================="
echo "[demo] SUCCESS: Node B synced via Kademlia/GossipSub/direct fetch."
echo "[demo] No static sync fallback was required."
echo "===================================================================="

# Stop Node B to run tally show against its DB (no storage lock conflict).
echo
echo "--- stopping Node B for local tally verification ---"
if [[ -n "$NODE_B_PID" ]] && kill -0 "$NODE_B_PID" 2>/dev/null; then
  kill "$NODE_B_PID" 2>/dev/null || true
  wait "$NODE_B_PID" 2>/dev/null || true
  NODE_B_PID=""
fi
echo "[demo] Node B stopped. Running tally show on its local DB."

echo
echo "========== TALLY RESULT (Node B, local DB after P2P sync) =========="
"$BIN" tally show --db "$DB_B" --network "$NET" --election an-demo
echo "===================================================================="

echo
echo "--- Node B P2P log (last 10 announcement-related lines) ---"
if [[ -f "${TMPDIR}/node_b.out" ]]; then
  grep -i "gossip\|discovery\|announce" "${TMPDIR}/node_b.out" 2>/dev/null | tail -10 || echo "  (no P2P log lines found)"
fi
echo "=========================================================="

echo
echo "demo complete"
