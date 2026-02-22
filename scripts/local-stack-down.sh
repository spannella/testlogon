#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

RUN_DIR="${REPO_ROOT}/.local/run"

if command -v docker >/dev/null 2>&1; then
  docker compose -f docker-compose.local.yml down -v || true
fi

stop_pid() {
  local name="$1"
  local pid_file="${RUN_DIR}/${name}.pid"
  if [[ -f "$pid_file" ]]; then
    local pid
    pid="$(cat "$pid_file")"
    if kill -0 "$pid" >/dev/null 2>&1; then
      kill "$pid" >/dev/null 2>&1 || true
    fi
    rm -f "$pid_file"
  fi
}

stop_pid "moto-server"
stop_pid "localstack"
stop_pid "dynamodb-local"
stop_pid "stripe-mock"
stop_pid "mock-kms"

echo "Local stack stopped."
