#!/usr/bin/env bash
set -euo pipefail

TMPDIR="$(mktemp -d -t librevote-frontend-smoke.XXXXXX)"
BIN="$TMPDIR/librevote"
PID=""

cleanup() {
  if [[ -n "$PID" ]] && kill -0 "$PID" 2>/dev/null; then
    kill "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
  fi
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

go build -o "$BIN" "$PROJECT_DIR/cmd/librevote"

find_free_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(('127.0.0.1', 0))
print(s.getsockname()[1])
s.close()
PY
}

PORT="$(find_free_port)"
DB="$TMPDIR/node.sqlite"
OUT="$TMPDIR/frontend.out"

"$BIN" frontend serve \
  --db "$DB" \
  --network frontend-smoke \
  --listen-http "127.0.0.1:$PORT" \
  --listen-p2p /ip4/127.0.0.1/tcp/0 \
  --mode server \
  --announce-interval 30s \
  > "$OUT" 2>&1 &
PID="$!"

for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:$PORT/api/network/status" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

INDEX="$(curl -fsS "http://127.0.0.1:$PORT/")"
STATUS="$(curl -fsS "http://127.0.0.1:$PORT/api/network/status")"

if [[ "$INDEX" != *"LibreVote Node"* ]]; then
  echo "error: frontend index does not contain LibreVote Node" >&2
  exit 1
fi

if [[ "${INDEX,,}" == *"demo"* ]]; then
  echo "error: frontend index contains demo string" >&2
  exit 1
fi

python3 - "$STATUS" <<'PY'
import json
import sys

status = json.loads(sys.argv[1])
required = [
    'node_name',
    'peer_id',
    'listen_multiaddrs',
    'connected_peer_count',
    'connected_peer_label',
    'bootstrap_peers',
    'bootstrap_peer_count',
]
missing = [key for key in required if key not in status]
if missing:
    raise SystemExit('missing status fields: ' + ', '.join(missing))
if status['node_name'] != 'LibreVote Node':
    raise SystemExit('unexpected node_name: ' + status['node_name'])
PY

echo "frontend smoke passed: http://127.0.0.1:$PORT/"
