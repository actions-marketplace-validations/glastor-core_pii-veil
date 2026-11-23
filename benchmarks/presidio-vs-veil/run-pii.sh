#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

run_target() {
  local service="$1"
  local container="$2"
  local port="$3"

  echo "============================================================"
  echo " Benchmarking: ${service} (port ${port})"
  echo "============================================================"
  docker compose up -d --build "${service}"

  echo "Waiting for http://localhost:${port}/health ..."
  for i in $(seq 1 60); do
    if curl -sf "http://localhost:${port}/health" >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done

  k6 run -e "TARGET_URL=http://localhost:${port}/api/v1/redact" k6-pii.js
  echo "--- Container Memory & CPU Snapshot ---"
  docker stats --no-stream "${container}"
  docker compose down
}

run_target "rust-pii-veil" "glastor-bench-pii-veil" 8091
run_target "python-presidio" "glastor-bench-presidio" 8092
