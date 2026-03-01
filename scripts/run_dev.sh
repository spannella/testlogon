#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

backend_mode="mock"
MOCK_WAIT_TIMEOUT_SECONDS=60
DEV_LOG_DIR="${DEV_LOG_DIR:-$REPO_ROOT/.logs/dev}"
BACKEND_LOG_PATH="${DEV_BACKEND_LOG_PATH:-$DEV_LOG_DIR/backend.log}"
FRONTEND_LOG_PATH="${DEV_FRONTEND_LOG_PATH:-$DEV_LOG_DIR/frontend.log}"
LOCAL_RUN_DIR="${REPO_ROOT}/.local/run"
DDB_BOOTSTRAP_MARKER_PATH="${LOCAL_RUN_DIR}/ddb-bootstrap.done"
DEV_DDB_BOOTSTRAP="${DEV_DDB_BOOTSTRAP:-1}"
DEV_DDB_SEED="${DEV_DDB_SEED:-0}"
DEV_FORCE_DDB_BOOTSTRAP="${DEV_FORCE_DDB_BOOTSTRAP:-0}"
clean_mode=1

usage() {
  cat <<'USAGE'
Usage: scripts/run_dev.sh [--real-backend|--mock-backend]

Options:
  --mock-backend   Start backend using scripts/run_local_mock_backend.sh (default)
  --real-backend   Start backend directly with current env/.env configuration
  --no-clean       Skip the clean wipe; reuse existing databases, logs, and services
  -h, --help       Show this help message
USAGE
}

while (($#)); do
  case "$1" in
    --real-backend)
      backend_mode="real"
      ;;
    --mock-backend)
      backend_mode="mock"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --no-clean)
      clean_mode=0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

mkdir -p "$(dirname "$BACKEND_LOG_PATH")" "$(dirname "$FRONTEND_LOG_PATH")"
touch "$BACKEND_LOG_PATH" "$FRONTEND_LOG_PATH"


if [[ -d ".venv" ]]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
else
  echo "Warning: .venv not found; using system Python/uvicorn/npm from PATH." >&2
fi

set -a
# In mock mode, load .env.local first so endpoint URLs and table names are
# available to the init scripts (local-s3-init.py, local-ddb-init.py, etc.)
# before run_local_mock_backend.sh sources it for the backend itself.
if [[ "$backend_mode" == "mock" ]]; then
  if [[ ! -f ".env.local" ]] && [[ -f ".env.local.example" ]]; then
    cp .env.local.example ".env.local"
    echo "Created .env.local from .env.local.example"
  fi
  if [[ -f ".env.local" ]]; then
    # shellcheck disable=SC1091
    source .env.local
  fi
fi
if [[ -f ".env" ]]; then
  # shellcheck disable=SC1091
  source .env
fi
set +a

# DLU-017: auto-enable Dev Tools Log UI and canonical log path defaults for local runs.
: "${VITE_ENABLE_DEVTOOLS_LOG_UI:=1}"
: "${DEVTOOLS_EMAIL_LOG_PATH:=${DEV_EMAIL_LOG:-$DEV_LOG_DIR/emails.log}}"
: "${DEVTOOLS_SMS_LOG_PATH:=${DEV_SMS_LOG:-$DEV_LOG_DIR/sms.log}}"
: "${DEVTOOLS_BILLING_STRIPE_LOG_PATH:=.local/logs/stripe-mock.log}"
: "${DEVTOOLS_BILLING_BACKEND_LOG_PATH:=${DEV_BACKEND_LOG_PATH:-$DEV_LOG_DIR/backend.log}}"
export VITE_ENABLE_DEVTOOLS_LOG_UI
export DEVTOOLS_EMAIL_LOG_PATH DEVTOOLS_SMS_LOG_PATH
export DEVTOOLS_BILLING_STRIPE_LOG_PATH DEVTOOLS_BILLING_BACKEND_LOG_PATH

echo "Dev logs will be written to:"
echo "  backend : $BACKEND_LOG_PATH"
echo "  frontend: $FRONTEND_LOG_PATH"
echo "Dev Tools Log UI enabled: VITE_ENABLE_DEVTOOLS_LOG_UI=${VITE_ENABLE_DEVTOOLS_LOG_UI}"
echo "Dev Tools log sources:"
echo "  email   : ${DEVTOOLS_EMAIL_LOG_PATH}"
echo "  sms     : ${DEVTOOLS_SMS_LOG_PATH}"
echo "  stripe  : ${DEVTOOLS_BILLING_STRIPE_LOG_PATH}"
echo "  backend : ${DEVTOOLS_BILLING_BACKEND_LOG_PATH}"

detect_external_ip() {
  local detected

  detected="$(curl -q -s --max-time 3 https://checkip.amazonaws.com 2>/dev/null | tr -d '[:space:]')"
  if [[ "${detected}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "${detected}"
    return 0
  fi

  if command -v ip >/dev/null 2>&1; then
    detected="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}')"
    if [[ -n "${detected}" ]]; then
      echo "${detected}"
      return 0
    fi
  fi

  if command -v hostname >/dev/null 2>&1; then
    detected="$(hostname -I 2>/dev/null | awk '{print $1}')"
    if [[ -n "${detected}" ]]; then
      echo "${detected}"
      return 0
    fi
  fi

  return 1
}

ensure_external_base_urls() {
  local dev_host="${LOCAL_DEV_HOST:-}"
  if [[ -z "${dev_host}" ]]; then
    dev_host="$(detect_external_ip || true)"
  fi

  if [[ -z "${dev_host}" ]]; then
    echo "Warning: Could not detect external IP; leaving API/public base URLs unchanged." >&2
    return
  fi

  local backend_url="http://${dev_host}:8000"

  if [[ -z "${PUBLIC_BASE_URL:-}" || "${PUBLIC_BASE_URL}" == *"localhost"* || "${PUBLIC_BASE_URL}" == *"127.0.0.1"* ]]; then
    export PUBLIC_BASE_URL="${backend_url}"
  fi

  # NOTE: VITE_API_BASE_URL is intentionally NOT set here.  All browser API
  # calls must route through the Vite proxy (/ui, /v1, …→ localhost:8000) so
  # that session cookies are always issued for the same origin as the page.
  # Setting an absolute EC2 IP here causes cookies to be scoped to that IP
  # while EventSource/SSE uses the page origin → cookie mismatch → 401s.

  echo "Using local dev host ${dev_host}"
  echo "PUBLIC_BASE_URL=${PUBLIC_BASE_URL}"
}

probe_http() {
  local url="$1"
  local code
  code="$(curl -q -s -o /dev/null -w "%{http_code}" --max-time 2 "$url" 2>/dev/null || true)"
  [[ "$code" != "000" ]]
}

mock_component_ready() {
  local component="$1"
  case "$component" in
    "twilio")
      [[ "${DEV_MODE:-1}" == "1" ]]
      ;;
    "s3") probe_http "http://localhost:8000/openapi.json" ;;
    "dynamodb") probe_http "http://localhost:8001/" ;;
    "cognito") probe_http "http://localhost:4566/health" ;;
    "stripe") probe_http "http://localhost:12111/" ;;
    "kms") probe_http "http://localhost:7999/health" ;;
    "ccbill") probe_http "http://localhost:8000/openapi.json" ;;
    "ups") probe_http "http://localhost:8000/openapi.json" ;;
    *) return 1 ;;
  esac
}

all_mock_components_ready() {
  local component
  for component in s3 dynamodb cognito stripe kms ccbill twilio ups; do
    if ! mock_component_ready "$component"; then
      return 1
    fi
  done
  return 0
}

print_mock_component_status() {
  local label="$1"
  local component="$2"
  if mock_component_ready "$component"; then
    if [[ "$component" == "twilio" ]]; then
      echo "[mock] ${label}: running (DEV_MODE=1 in-app simulation)"
    else
      echo "[mock] ${label}: running"
    fi
  else
    if [[ "$component" == "twilio" ]]; then
      echo "[mock] ${label}: not enabled (set DEV_MODE=1)"
    else
      echo "[mock] ${label}: not reachable"
    fi
  fi
}

wait_for_mock_components() {
  local deadline=$((SECONDS + MOCK_WAIT_TIMEOUT_SECONDS))
  while ((SECONDS < deadline)); do
    if all_mock_components_ready; then
      return 0
    fi
    sleep 2
  done
  return 1
}

ensure_local_mock_infra() {
  echo "Starting local mock infrastructure (LocalStack, DynamoDB, Stripe mock)..."
  scripts/local-stack-up.sh
}

wipe_clean() {
  echo "=== Wiping dev environment for a clean start ==="

  # Stop infrastructure services (moto, dynamodb-local, stripe-mock)
  echo "Stopping local stack services..."
  scripts/local-stack-down.sh || true

  # Kill any leftover backend uvicorn process
  pkill -f "uvicorn app.main:app" >/dev/null 2>&1 || true

  # Kill any leftover frontend vite/npm dev process
  pkill -f "vite" >/dev/null 2>&1 || true

  # Wipe DynamoDB persistent data (must be AFTER dynamodb-local is stopped)
  local ddb_data_dir="${REPO_ROOT}/.local/tools/dynamodb-local/data"
  if [[ -d "$ddb_data_dir" ]]; then
    echo "Clearing DynamoDB data: ${ddb_data_dir}"
    rm -f "${ddb_data_dir:?}"/*
  fi

  # Remove bootstrap marker so tables are recreated from scratch
  rm -f "${DDB_BOOTSTRAP_MARKER_PATH}"

  # Clear dev logs
  if [[ -d "${DEV_LOG_DIR}" ]]; then
    echo "Clearing dev logs: ${DEV_LOG_DIR}"
    rm -f "${DEV_LOG_DIR}"/*.log
  fi

  # Clear infra logs
  local infra_log_dir="${REPO_ROOT}/.local/logs"
  if [[ -d "$infra_log_dir" ]]; then
    echo "Clearing infra logs: ${infra_log_dir}"
    rm -f "${infra_log_dir}"/*.log
  fi

  echo "=== Clean wipe complete ==="
}

ensure_dynamodb_tables_initialized() {
  mkdir -p "${LOCAL_RUN_DIR}"

  if [[ "${DEV_DDB_BOOTSTRAP}" == "0" ]]; then
    echo "Skipping DynamoDB bootstrap because DEV_DDB_BOOTSTRAP=0."
    return 0
  fi

  if [[ "${DEV_FORCE_DDB_BOOTSTRAP}" != "1" ]] && [[ -f "${DDB_BOOTSTRAP_MARKER_PATH}" ]]; then
    echo "DynamoDB table bootstrap already completed; skipping (marker: ${DDB_BOOTSTRAP_MARKER_PATH})."
    return 0
  fi

  if [[ "${DEV_FORCE_DDB_BOOTSTRAP}" == "1" ]]; then
    echo "Forcing DynamoDB bootstrap because DEV_FORCE_DDB_BOOTSTRAP=1."
  fi

  echo "Initializing local DynamoDB tables..."
  if ! PYTHONPATH="${REPO_ROOT}" python3 scripts/local-ddb-init.py; then
    echo "ERROR: DynamoDB bootstrap failed while running scripts/local-ddb-init.py. Backend startup aborted." >&2
    echo "Hint: fix the bootstrap error, then retry; to re-run init after success use DEV_FORCE_DDB_BOOTSTRAP=1 or remove ${DDB_BOOTSTRAP_MARKER_PATH}." >&2
    return 1
  fi

  if [[ "${DEV_DDB_SEED}" == "1" ]]; then
    echo "Seeding local DynamoDB records because DEV_DDB_SEED=1..."
    if ! PYTHONPATH="${REPO_ROOT}" python3 scripts/local-ddb-seed.py; then
      echo "ERROR: DynamoDB seed failed while running scripts/local-ddb-seed.py. Backend startup aborted." >&2
      echo "Hint: disable seeding with DEV_DDB_SEED=0 or fix the seed script/data and retry." >&2
      return 1
    fi
  fi

  date -u +"%Y-%m-%dT%H:%M:%SZ" > "${DDB_BOOTSTRAP_MARKER_PATH}"
  echo "DynamoDB table bootstrap complete. Marker written to ${DDB_BOOTSTRAP_MARKER_PATH}."
}

if [[ "$clean_mode" == "1" ]]; then
  wipe_clean
fi

ensure_external_base_urls

cleanup() {
  if [[ -n "${BACKEND_PID:-}" ]]; then
    kill "$BACKEND_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if [[ "$backend_mode" == "mock" ]]; then
  ensure_local_mock_infra
  ensure_dynamodb_tables_initialized
  scripts/run_local_mock_backend.sh >>"$BACKEND_LOG_PATH" 2>&1 &
  echo "Backend running in mock mode on http://localhost:8000"
else
  uvicorn app.main:app --reload --host 0.0.0.0 --port 8000 >>"$BACKEND_LOG_PATH" 2>&1 &
  echo "Backend running in real mode on http://localhost:8000"
fi
BACKEND_PID=$!

if [[ "$backend_mode" == "mock" ]]; then
  echo "Waiting up to ${MOCK_WAIT_TIMEOUT_SECONDS}s for mock components to come online..."
  if wait_for_mock_components; then
    echo "All mock components are up."
  else
    echo "Timed out waiting for all mock components; showing current status."
  fi

  echo "Mock component status:"
  print_mock_component_status "MinIO/S3 (LocalStack)" "s3"
  print_mock_component_status "Local DynamoDB" "dynamodb"
  print_mock_component_status "Local Cognito (LocalStack)" "cognito"
  print_mock_component_status "Local Stripe mock" "stripe"
  print_mock_component_status "Local KMS mock" "kms"
  print_mock_component_status "Local CCBill mock" "ccbill"
  print_mock_component_status "Local Twilio mock" "twilio"
  print_mock_component_status "Local UPS mock" "ups"
fi

if [[ -f "frontend/package.json" ]]; then
  echo "Frontend dev server starting on http://localhost:5173"
  if [[ "${VITE_ENABLE_DEVTOOLS_LOG_UI}" == "1" ]]; then
    echo "Dev Tools Log UI: http://localhost:5173/dev-tools/log-ui"
  fi
  npm --prefix frontend run dev >>"$FRONTEND_LOG_PATH" 2>&1
else
  wait "$BACKEND_PID"
fi
