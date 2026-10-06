#!/usr/bin/env bash
# Runs a local vseqd cluster in Docker: per node, one container for the
# node and one for its blocks server, sharing the ledger volume (the
# blocks server mounts it read-only).
# Uses plain docker (no compose plugin needed).
#
#   local_cluster.sh up [N]   build the image, generate keys, start N nodes (default 4)
#   local_cluster.sh down     stop and remove the containers and network
#   local_cluster.sh logs I   follow node I's log
#
# Node i gets IP $VSEQ_SUBNET.(10+i) and serves its API on host port
# 18000+i; its blocks server listens on host port 18500+i.
# Build vseqd first: make -j vseqd
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../../.." && pwd)
WORK=${VSEQ_DOCKER_DIR:-$ROOT/build/vseq-docker}
SUBNET=${VSEQ_SUBNET:-172.28.0}
API_BASE=${VSEQ_API_BASE:-18000}
BLOCKS_BASE=${VSEQ_BLOCKS_BASE:-18500}
NET=vseq

down() {
  docker ps -aq --filter "label=vseq.node" | xargs -r docker rm -f >/dev/null
  docker volume ls -q --filter "label=vseq.node" | xargs -r docker volume rm >/dev/null
  docker network rm "$NET" >/dev/null 2>&1 || true
}

cmd=${1:-up}

case "$cmd" in
up)
  n=${2:-4}
  bin="$ROOT/$(make -C "$ROOT" --silent --no-print-directory objdir)/bin/vseqd"
  [ -x "$bin" ] || { echo "vseqd not built; run: make -j vseqd" >&2; exit 1; }
  down
  rm -rf "$WORK"
  mkdir -p "$WORK"
  cp "$bin" "$WORK/vseqd"
  cp "$HERE/Dockerfile" "$WORK/"
  docker build -q -t vseqd:local "$WORK" >/dev/null

  "$bin" gen-cluster --nodes "$n" --dir "$WORK/cluster" --host "$SUBNET.10" --base-port 9000 \
         --distinct-hosts --api-host 127.0.0.1 --api-base-port "$API_BASE" \
         --blocks-base-port "$BLOCKS_BASE" --log-path "" >/dev/null
  chmod 0644 "$WORK"/cluster/node-*.toml  # readable by the container user

  docker network create --subnet "$SUBNET.0/24" "$NET" >/dev/null
  for ((i = 0; i < n; i++)); do
    docker volume create --label vseq.node="$i" "vseq-data-$i" >/dev/null
    docker run -d --name "vseq-node-$i" --label vseq.node="$i" \
      --network "$NET" --ip "$SUBNET.$((10 + i))" \
      -p "127.0.0.1:$((API_BASE + i)):8000" \
      -v "$WORK/cluster:/cluster:ro" -v "vseq-data-$i:/data" \
      vseqd:local run --cluster /cluster/cluster.toml --key "/cluster/node-$i.toml" \
                      --ledger /data/ledger --api-port 8000 --log-path "" >/dev/null
    docker run -d --name "vseq-blocks-$i" --label vseq.node="$i" \
      -p "127.0.0.1:$((BLOCKS_BASE + i)):8500" \
      -v "$WORK/cluster:/cluster:ro" -v "vseq-data-$i:/data:ro" \
      vseqd:local blocks --cluster /cluster/cluster.toml --ledger /data/ledger --port 8500 --log-path "" >/dev/null
  done
  echo "cluster config: $WORK/cluster/cluster.toml"
  for ((i = 0; i < n; i++)); do
    echo "vseq-node-$i api: http://127.0.0.1:$((API_BASE + i))/status  blocks: http://127.0.0.1:$((BLOCKS_BASE + i))/blocks"
  done
  ;;
down)
  down
  ;;
logs)
  docker logs -f "vseq-node-${2:?node index}"
  ;;
*)
  echo "usage: $0 {up [N]|down|logs I}" >&2
  exit 1
  ;;
esac
