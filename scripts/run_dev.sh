#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

backend_mode="mock"
MOCK_WAIT_TIMEOUT_SECONDS=60

usage() {
  cat <<'USAGE'
Usage: scripts/run_dev.sh [--real-backend|--mock-backend]

Options:
  --mock-backend   Start backend using scripts/run_local_mock_backend.sh (default)
  --real-backend   Start backend directly with current env/.env configuration
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
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

if [[ -d ".venv" ]]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
else
  echo "Warning: .venv not found; using system Python/uvicorn/npm from PATH." >&2
fi

set -a
if [[ -f ".env" ]]; then
  # shellcheck disable=SC1091
  source .env
fi
set +a


probe_http() {
  local url="$1"
  local code
  code="$(curl -sS -o /dev/null -w "%{http_code}" --max-time 2 "$url" || true)"
  [[ "$code" != "000" ]]
}

mock_component_ready() {
  local component="$1"
  case "$component" in
    "twilio")
      [[ "${DEV_MODE:-1}" == "1" ]]
      ;;
    "s3") probe_http "http://localhost:4566/health" ;;
    "dynamodb") probe_http "http://localhost:8001/" ;;
    "cognito") probe_http "http://localhost:4566/health" ;;
    "stripe") probe_http "http://localhost:12111/" ;;
    "ccbill") probe_http "http://localhost:8000/mock/ccbill/subscriptions/mock-subscription" ;;
    "ups") probe_http "http://localhost:8000/mock/ups/label" ;;
    *) return 1 ;;
  esac
}

all_mock_components_ready() {
  local component
  for component in s3 dynamodb cognito stripe ccbill twilio ups; do
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

cleanup() {
  if [[ -n "${BACKEND_PID:-}" ]]; then
    kill "$BACKEND_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if [[ "$backend_mode" == "mock" ]]; then
  scripts/run_local_mock_backend.sh &
  echo "Backend running in mock mode on http://localhost:8000"
else
  uvicorn app.main:app --reload --host 0.0.0.0 --port 8000 &
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
  print_mock_component_status "Local CCBill mock" "ccbill"
  print_mock_component_status "Local Twilio mock" "twilio"
  print_mock_component_status "Local UPS mock" "ups"
fi

if [[ -f "frontend/package.json" ]]; then
  npm --prefix frontend run dev -- --host 0.0.0.0 --port 5173
else
  wait "$BACKEND_PID"
fi
