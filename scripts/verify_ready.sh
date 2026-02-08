#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
NC="\033[0m"

print_status() {
  local status="$1"
  local message="$2"

  case "$status" in
    ok)
      printf "%b[OK]%b %s\n" "$GREEN" "$NC" "$message"
      ;;
    warn)
      printf "%b[WARN]%b %s\n" "$YELLOW" "$NC" "$message"
      ;;
    fail)
      printf "%b[FAIL]%b %s\n" "$RED" "$NC" "$message"
      ;;
  esac
}

missing=0

if command -v python3 >/dev/null 2>&1; then
  print_status ok "python3 is installed."
else
  print_status fail "python3 is missing."
  missing=1
fi

if command -v node >/dev/null 2>&1; then
  print_status ok "node is installed."
else
  print_status warn "node is missing (frontend dependencies may not be ready)."
fi

if command -v npm >/dev/null 2>&1; then
  print_status ok "npm is installed."
else
  print_status warn "npm is missing (frontend dependencies may not be ready)."
fi

if [[ -d ".venv" ]]; then
  print_status ok "Python virtual environment (.venv) exists."
  # shellcheck disable=SC1091
  source .venv/bin/activate
  if python -m pip check >/dev/null 2>&1; then
    print_status ok "Python packages look consistent."
  else
    print_status warn "Python packages may need updates (pip check reported issues)."
  fi
  deactivate
else
  print_status fail "Python virtual environment (.venv) is missing."
  missing=1
fi

if [[ -f "frontend/package.json" ]]; then
  if [[ -d "frontend/node_modules" ]]; then
    print_status ok "Frontend dependencies are installed."
  else
    print_status warn "Frontend dependencies are missing (run npm --prefix frontend install)."
  fi
else
  print_status warn "No frontend/package.json found; skipping frontend checks."
fi

if [[ "$missing" -eq 0 ]]; then
  printf "\n%bAll prerequisites are installed. The application is ready to run.%b\n" "$GREEN" "$NC"
else
  printf "\n%bSome prerequisites are missing. Please run scripts/update_and_install.sh.%b\n" "$RED" "$NC"
  exit 1
fi
