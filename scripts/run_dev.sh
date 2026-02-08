#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

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

uvicorn app.main:app --reload --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!

echo "Backend running on http://localhost:8000"

if [[ -f "frontend/package.json" ]]; then
  npm --prefix frontend run dev -- --host 0.0.0.0 --port 5173
else
  wait "$BACKEND_PID"
fi
