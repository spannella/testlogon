#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

backend_mode="mock"

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

if [[ ! -d ".venv" ]]; then
  echo "Missing .venv; run scripts/setup_ubuntu.sh first." >&2
  exit 1
fi

set -a
if [[ -f ".env" ]]; then
  # shellcheck disable=SC1091
  source .env
fi
set +a

source .venv/bin/activate

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

if [[ -f "frontend/package.json" ]]; then
  npm --prefix frontend run dev -- --host 0.0.0.0 --port 5173
else
  wait "$BACKEND_PID"
fi
