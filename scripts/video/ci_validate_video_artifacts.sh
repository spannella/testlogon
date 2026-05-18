#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
ARTIFACT_ROOT="${1:-${ROOT_DIR}/video-data}"
WATERMARK_SNAPSHOT="${2:-}"

if [ -n "${WATERMARK_SNAPSHOT}" ]; then
  python "${ROOT_DIR}/scripts/video/ci_validate_video_artifacts.py" --root "${ARTIFACT_ROOT}" --watermark-snapshot "${WATERMARK_SNAPSHOT}"
else
  python "${ROOT_DIR}/scripts/video/ci_validate_video_artifacts.py" --root "${ARTIFACT_ROOT}"
fi
