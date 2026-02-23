#!/usr/bin/env bash
# dev.sh — master control script for the local dev environment.
# Usage: scripts/dev.sh <start|stop|restart|status> [--no-clean]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$REPO_ROOT"

LOCAL_RUN_DIR="${REPO_ROOT}/.local/run"
DEV_LOG_DIR="${REPO_ROOT}/.logs/dev"
BACKEND_LOG="${DEV_LOG_DIR}/backend.log"
FRONTEND_LOG="${DEV_LOG_DIR}/frontend.log"
BACKEND_PID_FILE="${LOCAL_RUN_DIR}/backend.pid"
FRONTEND_PID_FILE="${LOCAL_RUN_DIR}/frontend.pid"
DDB_BOOTSTRAP_MARKER="${LOCAL_RUN_DIR}/ddb-bootstrap.done"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_mkdir() { mkdir -p "$LOCAL_RUN_DIR" "$DEV_LOG_DIR"; }

_stop_pid_file() {
  local pid_file="$1" label="$2"
  if [[ -f "$pid_file" ]]; then
    local pid
    pid="$(cat "$pid_file")"
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      echo "Stopped $label (pid $pid)"
    fi
    rm -f "$pid_file"
  fi
}

_is_running() {
  local pid_file="$1"
  [[ -f "$pid_file" ]] && kill -0 "$(cat "$pid_file")" 2>/dev/null
}

_probe_http() {
  local url="$1"
  local code
  code="$(curl -q -s -o /dev/null -w "%{http_code}" --max-time 2 "$url" 2>/dev/null || true)"
  [[ "$code" != "000" && -n "$code" ]]
}

_status_icon() { $1 && echo "up" || echo "down"; }

_detect_external_ip() {
  local ip
  ip="$(curl -q -s --max-time 3 https://checkip.amazonaws.com 2>/dev/null | tr -d '[:space:]' || true)"
  if [[ "${ip}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then echo "$ip"; return; fi
  ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1);exit}}' || true)"
  [[ -n "$ip" ]] && echo "$ip" && return
  hostname -I 2>/dev/null | awk '{print $1}'
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

cmd_start() {
  local clean=1
  for arg in "$@"; do [[ "$arg" == "--no-clean" ]] && clean=0; done

  _mkdir

  # Bootstrap env
  if [[ ! -f ".env.local" ]] && [[ -f ".env.local.example" ]]; then
    cp .env.local.example ".env.local"
    echo "Created .env.local from .env.local.example"
  fi
  set -a
  [[ -f ".env.local" ]] && source ".env.local"
  [[ -f ".env"       ]] && source ".env"
  set +a

  # Detect public IP for backend URL (used by email links, webhooks, etc.)
  local dev_host
  dev_host="$(_detect_external_ip || true)"
  if [[ -n "$dev_host" ]]; then
    if [[ -z "${PUBLIC_BASE_URL:-}" || "${PUBLIC_BASE_URL}" == *"localhost"* || "${PUBLIC_BASE_URL}" == *"127.0.0.1"* ]]; then
      export PUBLIC_BASE_URL="http://${dev_host}:8000"
    fi
    echo "Using local dev host ${dev_host}"
    echo "PUBLIC_BASE_URL=${PUBLIC_BASE_URL}"
  fi

  if [[ "$clean" == "1" ]]; then
    echo "=== Wiping dev environment for a clean start ==="
    cmd_stop --quiet 2>/dev/null || true
    local ddb_data="${REPO_ROOT}/.local/tools/dynamodb-local/data"
    [[ -d "$ddb_data" ]] && { echo "Clearing DynamoDB data: ${ddb_data}"; rm -f "${ddb_data:?}"/*; }
    rm -f "$DDB_BOOTSTRAP_MARKER"
    [[ -d "$DEV_LOG_DIR"                ]] && { echo "Clearing dev logs: ${DEV_LOG_DIR}"; rm -f "${DEV_LOG_DIR}"/*.log; }
    local infra_log="${REPO_ROOT}/.local/logs"
    [[ -d "$infra_log" ]] && { echo "Clearing infra logs: ${infra_log}"; rm -f "${infra_log}"/*.log; }
    echo "=== Clean wipe complete ==="
  fi

  echo "Dev logs will be written to:"
  echo "  backend : ${BACKEND_LOG}"
  echo "  frontend: ${FRONTEND_LOG}"

  # Start mock infrastructure (moto, DynamoDB Local, Stripe mock, KMS mock)
  echo "Starting local mock infrastructure..."
  scripts/local-stack-up.sh

  # Bootstrap DynamoDB tables (skips if marker exists and FORCE not set)
  if [[ "${DEV_DDB_BOOTSTRAP:-1}" != "0" ]]; then
    if [[ "${DEV_FORCE_DDB_BOOTSTRAP:-0}" == "1" || ! -f "$DDB_BOOTSTRAP_MARKER" ]]; then
      echo "Initializing local DynamoDB tables..."
      PYTHONPATH="${REPO_ROOT}" python3 scripts/local-ddb-init.py
      if [[ "${DEV_DDB_SEED:-0}" == "1" ]]; then
        echo "Seeding local DynamoDB records..."
        PYTHONPATH="${REPO_ROOT}" python3 scripts/local-ddb-seed.py
      fi
      date -u +"%Y-%m-%dT%H:%M:%SZ" > "$DDB_BOOTSTRAP_MARKER"
      echo "DynamoDB table bootstrap complete."
    else
      echo "DynamoDB table bootstrap already completed; skipping."
    fi
  fi

  # Activate venv if present
  [[ -d .venv ]] && source .venv/bin/activate

  # Start backend
  echo "Starting backend..."
  scripts/run_local_mock_backend.sh >>"$BACKEND_LOG" 2>&1 &
  echo $! > "$BACKEND_PID_FILE"
  echo "Backend started (pid $(cat "$BACKEND_PID_FILE")) → log: ${BACKEND_LOG}"

  # Start frontend
  if [[ -f "frontend/package.json" ]]; then
    echo "Starting frontend..."
    npm --prefix frontend run dev >>"$FRONTEND_LOG" 2>&1 &
    echo $! > "$FRONTEND_PID_FILE"
    echo "Frontend started (pid $(cat "$FRONTEND_PID_FILE")) → log: ${FRONTEND_LOG}"
  fi

  echo ""
  echo "Waiting up to 30s for backend and frontend..."
  local deadline=$((SECONDS + 30))
  while ((SECONDS < deadline)); do
    _probe_http "http://localhost:8000/openapi.json" && _probe_http "http://localhost:3000/" && break
    sleep 2
  done

  echo ""
  cmd_status
}

cmd_stop() {
  local quiet=0
  for arg in "$@"; do [[ "$arg" == "--quiet" ]] && quiet=1; done

  _stop_pid_file "$FRONTEND_PID_FILE" "frontend"
  _stop_pid_file "$BACKEND_PID_FILE"  "backend"
  # Belt-and-suspenders: kill any orphaned processes
  pkill -f "uvicorn app.main:app" 2>/dev/null || true
  pkill -f "vite"                 2>/dev/null || true
  scripts/local-stack-down.sh

  [[ "$quiet" == "0" ]] && echo "Dev stack stopped."
}

cmd_restart() {
  cmd_stop --quiet 2>/dev/null || true
  sleep 1
  cmd_start "$@"
}

cmd_status() {
  _mkdir

  local s3_ok ddb_ok cog_ok stripe_ok kms_ok be_ok fe_ok
  _probe_http "http://localhost:4566/"          && s3_ok=true     || s3_ok=false
  _probe_http "http://localhost:8001/"          && ddb_ok=true    || ddb_ok=false
  _probe_http "http://localhost:4566/health"    && cog_ok=true    || cog_ok=false
  _probe_http "http://localhost:12111/"         && stripe_ok=true || stripe_ok=false
  _probe_http "http://localhost:7999/health"    && kms_ok=true    || kms_ok=false
  _probe_http "http://localhost:8000/openapi.json" && be_ok=true  || be_ok=false
  _probe_http "http://localhost:3000/"          && fe_ok=true     || fe_ok=false

  local be_proc fe_proc
  _is_running "$BACKEND_PID_FILE"  && be_proc=true || be_proc=false
  _is_running "$FRONTEND_PID_FILE" && fe_proc=true || fe_proc=false

  echo "Dev stack status:"
  printf "  %-34s [%s]\n" "S3/Moto (LocalStack)"            "$(_status_icon $s3_ok)"
  printf "  %-34s [%s]\n" "DynamoDB Local"                  "$(_status_icon $ddb_ok)"
  printf "  %-34s [%s]\n" "Cognito (LocalStack)"            "$(_status_icon $cog_ok)"
  printf "  %-34s [%s]\n" "Stripe mock"                     "$(_status_icon $stripe_ok)"
  printf "  %-34s [%s]\n" "KMS mock"                        "$(_status_icon $kms_ok)"
  printf "  %-34s [%s]  process=%s\n" "Backend  (localhost:8000)" "$(_status_icon $be_ok)" "$($be_proc && echo running || echo stopped)"
  printf "  %-34s [%s]  process=%s\n" "Frontend (localhost:3000)" "$(_status_icon $fe_ok)" "$($fe_proc && echo running || echo stopped)"
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

cmd="${1:-help}"
shift || true

case "$cmd" in
  start)   cmd_start   "$@" ;;
  stop)    cmd_stop    "$@" ;;
  restart) cmd_restart "$@" ;;
  status)  cmd_status        ;;
  help|-h|--help)
    echo "Usage: scripts/dev.sh <start|stop|restart|status> [--no-clean]"
    echo ""
    echo "  start [--no-clean]  Start the full dev stack (clean wipe by default)"
    echo "  stop                Stop all dev processes"
    echo "  restart [--no-clean]  Stop then start"
    echo "  status              Show health of all services"
    ;;
  *)
    echo "Unknown command: $cmd" >&2
    echo "Usage: scripts/dev.sh <start|stop|restart|status>" >&2
    exit 1
    ;;
esac
