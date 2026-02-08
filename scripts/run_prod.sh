#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [[ ! -d ".venv" ]]; then
  echo "Missing .venv; run scripts/setup_ubuntu.sh first." >&2
  exit 1
fi

if [[ ! -f ".env.production" ]]; then
  echo "Missing .env.production; run scripts/setup_prod_creds.sh first." >&2
  exit 1
fi

set -a
# shellcheck disable=SC1091
source .env.production
set +a

source .venv/bin/activate

exec gunicorn \
  -k uvicorn.workers.UvicornWorker \
  -w 2 \
  -b 0.0.0.0:8000 \
  app.main:app
