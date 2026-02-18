#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [[ -d .venv ]]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

echo "Running mock-mode backend tests..."
python3 -m unittest \
  tests.test_ccbill_mock \
  tests.test_ups \
  tests.test_billing_ccbill \
  tests.test_billing_routes

echo "Mock-mode tests passed."
