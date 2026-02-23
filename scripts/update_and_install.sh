#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  SUDO="sudo"
else
  SUDO=""
fi

if [[ -n "${SUDO_USER:-}" ]]; then
  TARGET_USER="$SUDO_USER"
else
  TARGET_USER="$(id -un)"
fi

run_as_target() {
  if [[ "$(id -un)" == "$TARGET_USER" ]]; then
    bash -lc "$*"
  else
    sudo -u "$TARGET_USER" -H bash -lc "$*"
  fi
}

ensure_venv_writable() {
  if run_as_target "cd '$REPO_ROOT' && touch .venv/.codex_write_test >/dev/null 2>&1 && rm -f .venv/.codex_write_test"; then
    return 0
  fi

  echo "Detected a permissions issue in .venv; attempting to repair ownership..."

  if [[ -n "$SUDO" ]]; then
    $SUDO chown -R "$TARGET_USER:$TARGET_USER" .venv
  else
    chown -R "$TARGET_USER:$TARGET_USER" .venv
  fi

  if run_as_target "cd '$REPO_ROOT' && touch .venv/.codex_write_test >/dev/null 2>&1 && rm -f .venv/.codex_write_test"; then
    return 0
  fi

  echo "Warning: ownership repair did not resolve .venv permissions; recreating .venv..."

  if [[ -n "$SUDO" ]]; then
    $SUDO rm -rf .venv
  else
    rm -rf .venv
  fi

  run_as_target "cd '$REPO_ROOT' && python3 -m venv .venv"
}

ensure_node_runtime() {
  if ! command -v node >/dev/null 2>&1; then
    return 0
  fi

  local node_major
  node_major="$(node -p "Number(process.versions.node.split('.')[0])" 2>/dev/null || echo 0)"
  if [[ "$node_major" =~ ^[0-9]+$ ]] && (( node_major >= 20 )); then
    return 0
  fi

  echo "Detected Node.js ${node_major}; upgrading to Node.js 20.x for frontend compatibility..."
  $SUDO install -d -m 0755 /etc/apt/keyrings
  curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
    | $SUDO gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
  echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" \
    | $SUDO tee /etc/apt/sources.list.d/nodesource.list >/dev/null
  $SUDO apt-get update
  $SUDO apt-get install -y --no-install-recommends nodejs
}

ensure_npm_cli() {
  if command -v npm >/dev/null 2>&1; then
    return 0
  fi

  if command -v corepack >/dev/null 2>&1; then
    corepack enable npm >/dev/null 2>&1 || corepack enable >/dev/null 2>&1 || true
  fi

  if command -v npm >/dev/null 2>&1; then
    return 0
  fi

  echo "Error: npm is not available after installing Node.js. Verify your Node.js installation and rerun this script." >&2
  exit 1
}

if git rev-parse --abbrev-ref --symbolic-full-name "@{u}" >/dev/null 2>&1; then
  git fetch --all --prune
  git pull --ff-only
else
  echo "Warning: current branch has no upstream; skipping git fetch/pull." >&2
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
  gnupg

ensure_node_runtime
ensure_npm_cli

if ! command -v just >/dev/null 2>&1; then
  echo "Installing just..."
  curl -fsSL https://just.systems/install.sh | $SUDO bash -s -- --to /usr/local/bin
fi

if [[ ! -d ".venv" ]]; then
  run_as_target "cd '$REPO_ROOT' && python3 -m venv .venv"
fi

ensure_venv_writable

run_as_target "
  cd '$REPO_ROOT'
  source .venv/bin/activate
  python -m pip install --upgrade pip
  pip install -r requirements.txt
  pip uninstall -y multipart >/dev/null 2>&1 || true
  pip install gunicorn
  pip install 'moto[server]>=5,<6'
"

if [[ -f "frontend/package.json" ]]; then
  npm --prefix frontend install
  if [[ -n "${SUDO_USER:-}" ]]; then
    chown -R "${SUDO_USER}:${SUDO_USER}" frontend/node_modules frontend/package-lock.json 2>/dev/null || true
    chown -R "${SUDO_USER}:${SUDO_USER}" frontend 2>/dev/null || true
  fi
  chmod -R u+rwX frontend/node_modules 2>/dev/null || true
fi

echo "Update complete. Configure env vars (see docs/run-deploy.md) and run: just start"
