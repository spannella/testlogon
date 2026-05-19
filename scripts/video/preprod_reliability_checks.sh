#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
REPORT_PATH="${1:-${ROOT_DIR}/video-data/reliability_report.json}"

python "${ROOT_DIR}/scripts/video/preprod_reliability_checks.py" --report "${REPORT_PATH}"
