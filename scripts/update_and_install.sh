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
  if run_as_target "cd '$REPO_ROOT' && touch .venv/.codex_write_test && rm -f .venv/.codex_write_test"; then
    return 0
  fi

  echo "Detected a permissions issue in .venv; attempting to repair ownership..."

  if [[ -n "$SUDO" ]]; then
    $SUDO chown -R "$TARGET_USER:$TARGET_USER" .venv
  else
    chown -R "$TARGET_USER:$TARGET_USER" .venv
  fi

  if run_as_target "cd '$REPO_ROOT' && touch .venv/.codex_write_test && rm -f .venv/.codex_write_test"; then
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
  npm

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

echo "Update complete. Configure env vars (see docs/run-deploy.md) and run scripts/run_dev.sh."
