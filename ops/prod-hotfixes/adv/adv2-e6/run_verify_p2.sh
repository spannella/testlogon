#!/usr/bin/env bash
cd /home/ubuntu/testlogon || exit 1
set -a
. ./.env.local
set +a
export PYTHONPATH=/home/ubuntu/testlogon
.venv/bin/python ops/prod-hotfixes/adv/adv2-e6/verify_adv2e6_p2.py 2>&1 \
  | grep -vE "API.?key|API-key|stale_route|rollout surfaces|mounted on routes"
