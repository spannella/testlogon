#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_ROOT}"

export DEV_ENABLE_KEYCLOAK=1

scripts/local-stack-up.sh

echo ""
echo "Local AD SSO host-mode dependencies are up."
echo "Next step: generate root provider payload with:"
echo "  python3 scripts/local-ad-sso-provider-config.py"
