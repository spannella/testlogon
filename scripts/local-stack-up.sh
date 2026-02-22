#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_ROOT}"

RUN_DIR="${REPO_ROOT}/.local/run"
TOOLS_DIR="${REPO_ROOT}/.local/tools"
LOG_DIR="${REPO_ROOT}/.local/logs"
mkdir -p "${RUN_DIR}" "${TOOLS_DIR}" "${LOG_DIR}"

probe() {
  curl -q -s -o /dev/null -w "%{http_code}" --max-time 2 "$1" 2>/dev/null || true
}

is_up() {
  [[ "$(probe "$1")" != "000" ]]
}

wait_up() {
  local url="$1"
  local label="$2"
  local attempts="${3:-40}"
  for _ in $(seq 1 "$attempts"); do
    if is_up "$url"; then
      return 0
    fi
    sleep 1
  done
  echo "Timed out waiting for ${label} at ${url}" >&2
  return 1
}

start_with_pidfile() {
  local name="$1"
  local cmd="$2"
  local expected_pattern="$3"
  local pid_file="${RUN_DIR}/${name}.pid"

  if [[ -f "$pid_file" ]]; then
    local existing_pid
    existing_pid="$(cat "$pid_file")"
    if kill -0 "$existing_pid" >/dev/null 2>&1 && ps -p "$existing_pid" -o args= | grep -F "$expected_pattern" >/dev/null 2>&1; then
      return 0
    fi
    rm -f "$pid_file"
  fi

  nohup bash -lc "$cmd" >"${LOG_DIR}/${name}.log" 2>&1 &
  echo $! > "$pid_file"
}

install_dynamodb_local() {
  local dest="${TOOLS_DIR}/dynamodb-local"
  if [[ -f "${dest}/DynamoDBLocal.jar" ]]; then
    return 0
  fi

  mkdir -p "$dest"
  echo "Installing DynamoDB Local..."
  curl -q -sSL https://s3.us-west-2.amazonaws.com/dynamodb-local/dynamodb_local_latest.tar.gz -o "${dest}/dynamodb_local_latest.tar.gz"
  tar -xzf "${dest}/dynamodb_local_latest.tar.gz" -C "$dest"
}

install_stripe_mock() {
  local bin_dir="${TOOLS_DIR}/stripe-mock"
  local bin="${bin_dir}/stripe-mock"
  if [[ -x "$bin" ]]; then
    return 0
  fi

  mkdir -p "$bin_dir"
  local arch
  case "$(uname -m)" in
    x86_64) arch="linux_amd64" ;;
    aarch64|arm64) arch="linux_arm64" ;;
    *)
      echo "Unsupported architecture for stripe-mock: $(uname -m)" >&2
      return 1
      ;;
  esac

  local version="v0.197.0"
  local tarball="stripe-mock_${version#v}_${arch}.tar.gz"
  local url="https://github.com/stripe/stripe-mock/releases/download/${version}/${tarball}"
  echo "Installing stripe-mock (${version})..."
  curl -q -sSL "$url" -o "${bin_dir}/${tarball}"
  tar -xzf "${bin_dir}/${tarball}" -C "$bin_dir"
  chmod +x "$bin"
}

start_host_stack() {
  command -v java >/dev/null 2>&1 || { echo "java is required for DynamoDB Local (install openjdk-17-jre-headless)." >&2; return 1; }
  command -v python3 >/dev/null 2>&1 || { echo "python3 is required for host AWS mocks." >&2; return 1; }

  export PATH="$HOME/.local/bin:$PATH"

  if ! command -v moto_server >/dev/null 2>&1 || ! python3 -c "import flask" >/dev/null 2>&1; then
    echo "Installing moto server for host-mode S3/Cognito mocks..."
    python3 -m pip install --user "moto[server]>=5,<6" >/dev/null
  fi

  install_dynamodb_local
  mkdir -p "${TOOLS_DIR}/dynamodb-local/data"
  install_stripe_mock

  if ! is_up "http://localhost:4566/"; then
    start_with_pidfile "moto-server" "moto_server -H 0.0.0.0 -p 4566" "moto_server -H 0.0.0.0 -p 4566"
  fi

  if ! is_up "http://localhost:8001/"; then
    start_with_pidfile "dynamodb-local" "java -Djava.library.path='${TOOLS_DIR}/dynamodb-local/DynamoDBLocal_lib' -jar '${TOOLS_DIR}/dynamodb-local/DynamoDBLocal.jar' -sharedDb -dbPath '${TOOLS_DIR}/dynamodb-local/data' -port 8001" "DynamoDBLocal.jar"
  fi

  if ! is_up "http://localhost:12111/"; then
    start_with_pidfile "stripe-mock" "'${TOOLS_DIR}/stripe-mock/stripe-mock' -http-port 12111 -https-port 12112" "stripe-mock"
  fi

  if ! is_up "http://localhost:7999/health"; then
    start_with_pidfile "mock-kms" "python3 '${SCRIPT_DIR}/mock_kms_server.py'" "mock_kms_server.py"
  fi

  echo "Waiting for local services to be healthy..."
  wait_up "http://localhost:4566/" "Moto AWS mock (S3/Cognito)"
  wait_up "http://localhost:8001/" "DynamoDB Local"
  wait_up "http://localhost:12111/" "Stripe mock"
  wait_up "http://localhost:7999/health" "Mock KMS"
}

if command -v docker >/dev/null 2>&1; then
  docker compose -f docker-compose.local.yml up -d

  echo "Waiting for local services to be healthy..."
  for _ in {1..40}; do
    if curl -q -sf http://localhost:4566/health >/dev/null 2>&1 && curl -q -sf http://localhost:8001/ >/dev/null 2>&1 && curl -q -sf http://localhost:12111/ >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
else
  echo "Docker not found; starting local stack in host mode (moto + DynamoDB Local + stripe-mock)."
  start_host_stack
fi

# Load .env.local so init scripts have the endpoint URLs and bucket names they need.
# run_dev.sh may have already exported these, but source again for direct invocation.
if [[ -f "${REPO_ROOT}/.env.local" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "${REPO_ROOT}/.env.local"
  set +a
fi

PYTHONPATH="${REPO_ROOT}" python3 scripts/local-s3-init.py
PYTHONPATH="${REPO_ROOT}" python3 scripts/local-cognito-init.py
PYTHONPATH="${REPO_ROOT}" python3 scripts/local-ses-init.py
PYTHONPATH="${REPO_ROOT}" python3 scripts/local-kms-init.py

echo ""
echo "Local stack is starting."
echo "DynamoDB Local: http://localhost:8001"
echo "AWS mock (moto): http://localhost:4566"
echo "Stripe mock:    http://localhost:12111"
