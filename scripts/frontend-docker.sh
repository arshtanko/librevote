#!/usr/bin/env bash
set -euo pipefail

COUNT="${1:-4}"
PUBLIC_IP="${PUBLIC_IP:-127.0.0.1}"
IMAGE="librevote-frontend:local"
NETWORK="librevote-frontend-net"
NAME_PREFIX="librevote-frontend"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

for i in $(seq 1 "$COUNT"); do
  docker rm -f "$NAME_PREFIX-$i" >/dev/null 2>&1 || true
  docker volume rm "$NAME_PREFIX-$i-data" >/dev/null 2>&1 || true
done

docker build -t "$IMAGE" -f - "$PROJECT_DIR" <<'DOCKERFILE'
FROM golang:1.23 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/librevote ./cmd/librevote

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/librevote /librevote
ENTRYPOINT ["/librevote"]
DOCKERFILE

docker network inspect "$NETWORK" >/dev/null 2>&1 || docker network create "$NETWORK" >/dev/null

for i in $(seq 1 "$COUNT"); do
  http_port=$((18080 + i - 1))
  p2p_port=$((19000 + i - 1))

  if [[ "$PUBLIC_IP" == "127.0.0.1" ]]; then
    http_advertise="http://$NAME_PREFIX-$i:8080"
  else
    http_advertise="http://$PUBLIC_IP:$http_port"
  fi

  docker run -d \
    --name "$NAME_PREFIX-$i" \
    --network "$NETWORK" \
    -p "${PUBLIC_IP}:${http_port}:8080" \
    -p "${PUBLIC_IP}:${p2p_port}:9000" \
    -v "$NAME_PREFIX-$i-data:/data" \
    "$IMAGE" frontend serve \
      --db /data/node \
      --network frontend-local \
      --listen-http 0.0.0.0:8080 \
      --listen-p2p /ip4/0.0.0.0/tcp/9000 \
      --http-advertise "$http_advertise" \
      --mode server \
      --announce-interval 30s \
    >/dev/null
done

echo "LibreVote frontend nodes started without bootstrap, elections, or votes."
for i in $(seq 1 "$COUNT"); do
  http_port=$((18080 + i - 1))
  p2p_port=$((19000 + i - 1))
  url="http://${PUBLIC_IP}:${http_port}/"
  peer_id=""
  for _ in $(seq 1 40); do
    peer_id="$(docker logs "$NAME_PREFIX-$i" 2>&1 | sed -n 's/.*peer_id: //p' | head -n 1 || true)"
    if [[ -n "$peer_id" ]]; then
      break
    fi
    sleep 0.25
  done
  echo "node $i frontend: $url"
  if [[ -n "$peer_id" ]]; then
    echo "node $i bootstrap multiaddr: /ip4/${PUBLIC_IP}/tcp/${p2p_port}/p2p/${peer_id}"
  else
    echo "node $i bootstrap multiaddr: unavailable; inspect logs with docker logs $NAME_PREFIX-$i"
  fi
done
