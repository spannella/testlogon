#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  SUDO="sudo"
else
  SUDO=""
fi

$SUDO apt-get update
$SUDO apt-get install -y --no-install-recommends \
  build-essential \
  ca-certificates \
  curl \
  python3-venv \
  python3-pip \
  python3-dev \
  openjdk-17-jre-headless \
  nodejs \
  npm

if ! command -v just >/dev/null 2>&1; then
  echo "Installing just..."
  curl -fsSL https://just.systems/install.sh | $SUDO bash -s -- --to /usr/local/bin
fi

if [[ ! -d ".venv" ]]; then
  python3 -m venv .venv
fi

source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
pip uninstall -y multipart >/dev/null 2>&1 || true
pip install gunicorn
pip install "moto[server]>=5,<6"

deactivate

if [[ -f "frontend/package.json" ]]; then
  npm --prefix frontend install
  if [[ -n "${SUDO_USER:-}" ]]; then
    chown -R "${SUDO_USER}:${SUDO_USER}" frontend/node_modules frontend/package-lock.json 2>/dev/null || true
    chown -R "${SUDO_USER}:${SUDO_USER}" frontend 2>/dev/null || true
  fi
  chmod -R u+rwX frontend/node_modules 2>/dev/null || true
fi

echo "Setup complete. Configure env vars (see docs/run-deploy.md) and run: just start"
