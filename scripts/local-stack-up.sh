#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_ROOT}"

docker compose -f docker-compose.local.yml up -d

echo "Waiting for local services to be healthy..."
for _ in {1..40}; do
  if curl -sf http://localhost:4566/health >/dev/null && curl -sf http://localhost:8001/ >/dev/null; then
    break
  fi
  sleep 1
done

python3 scripts/local-s3-init.py

echo ""
echo "Local stack is starting."
echo "DynamoDB Local: http://localhost:8001"
echo "LocalStack:     http://localhost:4566"
echo "Stripe mock:    http://localhost:12111"
