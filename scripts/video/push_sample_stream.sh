#!/bin/sh
set -eu

STREAM_KEY="${1:-localdemo}"
TARGET_URL="${TARGET_URL:-rtmp://localhost:1935/live/${STREAM_KEY}}"

echo "[push] streaming synthetic sample to ${TARGET_URL}"

ffmpeg -hide_banner -loglevel warning -re -stream_loop -1 \
  -f lavfi -i testsrc=size=1280x720:rate=30 \
  -f lavfi -i sine=frequency=1000:sample_rate=48000 \
  -c:v libx264 -preset veryfast -g 60 -sc_threshold 0 \
  -c:a aac -b:a 128k \
  -f flv "${TARGET_URL}"
