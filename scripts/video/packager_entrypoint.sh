#!/bin/sh
set -eu

while true; do
  python /workspace/scripts/video/package_manifests.py || true
  sleep 2
done
