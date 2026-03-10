#!/usr/bin/env bash
# setup_ubuntu.sh — First-run setup for a clean Ubuntu/Debian host.
# Run once after cloning the repo, then use: scripts/dev.sh start
#
# Usage:
#   bash scripts/setup_ubuntu.sh          # full setup
#   bash scripts/setup_ubuntu.sh --no-e2e # skip Playwright browser install
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

GREEN="\033[0;32m"; YELLOW="\033[0;33m"; BOLD="\033[1m"; NC="\033[0m"
log()  { printf "${BOLD}==> %s${NC}\n" "$*"; }
ok()   { printf "${GREEN}[OK]${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}[WARN]${NC} %s\n" "$*"; }

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then SUDO="sudo"; else SUDO=""; fi

if [[ -n "${SUDO_USER:-}" ]]; then TARGET_USER="$SUDO_USER"; else TARGET_USER="$(id -un)"; fi

run_as_target() { if [[ "$(id -un)" == "$TARGET_USER" ]]; then bash -c "$*"; else sudo -u "$TARGET_USER" bash -c "$*"; fi; }

SKIP_E2E=0
for arg in "$@"; do [[ "$arg" == "--no-e2e" ]] && SKIP_E2E=1; done

# ---------------------------------------------------------------------------
# 1. System packages
# ---------------------------------------------------------------------------
log "Installing system packages..."
$SUDO apt-get update -qq
$SUDO apt-get install -y --no-install-recommends \
  build-essential ca-certificates curl gnupg git \
  python3-venv python3-pip python3-dev \
  openjdk-17-jre-headless

# Node.js 20.x (upgrade if < 20 or missing)
install_node20() {
  log "Installing Node.js 20.x via NodeSource..."
  $SUDO install -d -m 0755 /etc/apt/keyrings
  curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
    | $SUDO gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
  echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" \
    | $SUDO tee /etc/apt/sources.list.d/nodesource.list >/dev/null
  $SUDO apt-get update -qq
  $SUDO apt-get install -y --no-install-recommends nodejs
}

if ! command -v node >/dev/null 2>&1; then
  install_node20
else
  NODE_MAJOR="$(node -p "Number(process.versions.node.split('.')[0])" 2>/dev/null || echo 0)"
  if (( NODE_MAJOR < 20 )); then
    warn "Node.js ${NODE_MAJOR} detected — upgrading to 20.x..."
    install_node20
  else
    ok "Node.js $(node --version) already installed."
  fi
fi

# Ensure npm is available
if ! command -v npm >/dev/null 2>&1; then
  command -v corepack >/dev/null 2>&1 && corepack enable npm 2>/dev/null || true
fi
command -v npm >/dev/null 2>&1 || { echo "ERROR: npm not available after Node.js install." >&2; exit 1; }
ok "npm $(npm --version) available."

# just command runner (optional but used by justfile)
if ! command -v just >/dev/null 2>&1; then
  log "Installing just..."
  curl -fsSL https://just.systems/install.sh | $SUDO bash -s -- --to /usr/local/bin
fi

# ---------------------------------------------------------------------------
# 2. Python virtual environment + dependencies
# ---------------------------------------------------------------------------
log "Setting up Python virtual environment..."
if [[ ! -d ".venv" ]]; then
  run_as_target "cd '${REPO_ROOT}' && python3 -m venv .venv"
  ok "Created .venv"
else
  ok ".venv already exists."
fi

# Repair ownership if needed (common when re-running as different user/sudo)
if ! run_as_target "cd '${REPO_ROOT}' && .venv/bin/python -c 'import sys' 2>/dev/null"; then
  warn "Repairing .venv ownership..."
  [[ -n "$SUDO" ]] && $SUDO chown -R "${TARGET_USER}:${TARGET_USER}" .venv || chown -R "${TARGET_USER}:${TARGET_USER}" .venv
fi

log "Installing Python dependencies..."
run_as_target "
  cd '${REPO_ROOT}'
  .venv/bin/pip install --upgrade pip -q
  .venv/bin/pip install -r requirements.txt -q
  .venv/bin/pip uninstall -y multipart >/dev/null 2>&1 || true
  .venv/bin/pip install 'moto[server]>=5,<6' gunicorn -q
"
ok "Python dependencies installed."

# ---------------------------------------------------------------------------
# 3. Node / frontend dependencies
# ---------------------------------------------------------------------------
log "Installing frontend dependencies..."
npm --prefix frontend install --silent
if [[ -n "${SUDO_USER:-}" ]]; then
  chown -R "${SUDO_USER}:${SUDO_USER}" frontend/node_modules frontend/package-lock.json 2>/dev/null || true
fi
ok "Frontend dependencies installed."

# ---------------------------------------------------------------------------
# 4. Environment files
# ---------------------------------------------------------------------------
log "Configuring environment files..."

# Backend .env.local
if [[ ! -f ".env.local" ]]; then
  cp .env.local.example .env.local
  ok "Created .env.local from .env.local.example"
fi

# Generate UI_ACCESS_TOKEN_SECRET if missing/empty
if ! grep -q "^UI_ACCESS_TOKEN_SECRET=.\+" .env.local 2>/dev/null; then
  SECRET="$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")"
  # Replace the line (whether it exists with empty value or not)
  if grep -q "^UI_ACCESS_TOKEN_SECRET=" .env.local; then
    sed -i "s|^UI_ACCESS_TOKEN_SECRET=.*|UI_ACCESS_TOKEN_SECRET=${SECRET}|" .env.local
  else
    echo "UI_ACCESS_TOKEN_SECRET=${SECRET}" >> .env.local
  fi
  ok "Generated UI_ACCESS_TOKEN_SECRET"
fi

# Generate API_KEY_PEPPER if missing/empty
if ! grep -q "^API_KEY_PEPPER=.\+" .env.local 2>/dev/null; then
  PEPPER="$(python3 -c "import secrets; print(secrets.token_hex(32))")"
  if grep -q "^API_KEY_PEPPER=" .env.local; then
    sed -i "s|^API_KEY_PEPPER=.*|API_KEY_PEPPER=${PEPPER}|" .env.local
  else
    echo "API_KEY_PEPPER=${PEPPER}" >> .env.local
  fi
  ok "Generated API_KEY_PEPPER"
fi

# Frontend .env.local (seed from example; Cognito IDs filled in by stack startup)
if [[ ! -f "frontend/.env.local" ]]; then
  cp frontend/.env.local.example frontend/.env.local
  ok "Created frontend/.env.local from frontend/.env.local.example"
fi

# ---------------------------------------------------------------------------
# 5. Playwright browsers (for E2E tests)
# ---------------------------------------------------------------------------
if [[ "$SKIP_E2E" -eq 0 ]]; then
  log "Installing Playwright browsers (Chromium)..."
  # Install system deps for Playwright headless Chromium
  cd frontend
  npx playwright install chromium --with-deps 2>&1 | tail -5 || warn "Playwright browser install failed (non-fatal — E2E tests will fail until fixed)"
  cd "$REPO_ROOT"
  ok "Playwright Chromium installed."
else
  warn "Skipping Playwright browser install (--no-e2e)."
fi

# ---------------------------------------------------------------------------
# 6. Make scripts executable
# ---------------------------------------------------------------------------
chmod +x scripts/dev.sh scripts/local-stack-up.sh scripts/local-stack-down.sh \
         scripts/run_local_mock_backend.sh scripts/verify_ready.sh \
         scripts/setup_ubuntu.sh scripts/update_and_install.sh 2>/dev/null || true

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
printf "\n${GREEN}${BOLD}Setup complete!${NC}\n\n"
echo "Next steps:"
echo "  1. Start the dev stack + seed E2E sessions (first run downloads DynamoDB Local + Stripe mock):"
echo "       just up"
echo ""
echo "  2. Run E2E tests:"
echo "       just e2e"
echo ""
echo "  App will be available at:"
echo "    Frontend: http://localhost:3000"
echo "    Backend:  http://localhost:8000"
echo ""
echo "  Daily workflow:"
echo "    just restart    # clean-wipe + restart + re-seed sessions"
