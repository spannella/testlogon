#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

ENV_FILE=".env.local"
if [[ ! -f "$ENV_FILE" ]]; then
  cp .env.local.example "$ENV_FILE"
  echo "Created $ENV_FILE from .env.local.example"
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"

# Force local mock-friendly defaults unless caller explicitly overrides.
: "${DEV_MODE:=1}"
: "${CCBILL_MOCK_ENABLED:=1}"
: "${CCBILL_BASE_URL:=http://localhost:8000/mock/ccbill}"
: "${CCBILL_WEBHOOK_VERIFY_MODE:=local}"
: "${CCBILL_WEBHOOK_SIGNATURE_SECRET:=local-ccbill-webhook-secret}"
: "${UPS_BASE_URL:=http://localhost:8000/mock/ups}"
: "${UPS_AUTH_URL:=http://localhost:8000/mock/ups/oauth/token}"
: "${UPS_CLIENT_ID:=local_ups_client}"
: "${UPS_CLIENT_SECRET:=local_ups_secret}"
: "${UPS_WEBHOOK_SECRET:=local-ups-webhook-secret}"
: "${AWS_ACCESS_KEY_ID:=test}"
: "${AWS_SECRET_ACCESS_KEY:=test}"
: "${AWS_REGION:=us-east-1}"
set +a

if [[ -d .venv ]]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

ensure_fastapi_multipart_dependency() {
  if ! command -v python >/dev/null 2>&1; then
    return 0
  fi

  if python - <<'PYCODE' >/dev/null 2>&1
import importlib.metadata as md
md.distribution("multipart")
PYCODE
  then
    echo "Removing incompatible 'multipart' package from active Python environment..."
    python -m pip uninstall -y multipart >/dev/null 2>&1 || true
  fi

  if ! python - <<'PYCODE' >/dev/null 2>&1
import importlib.metadata as md
md.distribution("python-multipart")
PYCODE
  then
    echo "Installing required 'python-multipart' package..."
    python -m pip install -q python-multipart==0.0.9
  fi
}

ensure_fastapi_multipart_dependency

echo "Starting backend in local mock mode on http://localhost:8000"
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
