#!/bin/sh
set -eu

echo "[transcoder] starting ABR workers for input ${INPUT_URL:-rtmp://ingest/live/localdemo}"

while true; do
  python /workspace/scripts/video/run_abr_transcoder.py || true
  echo "[transcoder] input lost or disconnected; restarting ABR workers in 2s"
  sleep 2
done
