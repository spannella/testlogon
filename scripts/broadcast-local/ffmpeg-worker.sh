#!/usr/bin/env bash
set -euo pipefail

STREAM_KEY="${BROADCAST_STREAM_KEY:-devstream}"
INPUT_URL="${BROADCAST_INPUT_URL:-rtmp://rtmp:1935/live/${STREAM_KEY}}"
OUTPUT_ROOT="${BROADCAST_OUTPUT_ROOT:-/data/hls}"
WATERMARK_PATH="${BROADCAST_WATERMARK_PATH:-/assets/watermark.ppm}"
RESTART_DELAY_SECS="${BROADCAST_RESTART_DELAY_SECS:-3}"
ARCHIVE_COPY_ROOT="${BROADCAST_ARCHIVE_COPY_ROOT:-/data/archive}"
FFMPEG_LOG_FILE="${BROADCAST_FFMPEG_LOG_FILE:-/data/logs/ffmpeg-worker.log}"

mkdir -p "$(dirname "${FFMPEG_LOG_FILE}")"
touch "${FFMPEG_LOG_FILE}"
exec >>"${FFMPEG_LOG_FILE}" 2>&1

SESSION_DIR="${OUTPUT_ROOT}/${STREAM_KEY}"
ARCHIVE_SESSION_DIR="${ARCHIVE_COPY_ROOT}/${STREAM_KEY}"
mkdir -p "${SESSION_DIR}"
mkdir -p "${ARCHIVE_SESSION_DIR}"

echo "[broadcast-ffmpeg] stream_key=${STREAM_KEY}"
echo "[broadcast-ffmpeg] input=${INPUT_URL}"
echo "[broadcast-ffmpeg] output=${SESSION_DIR}"
echo "[broadcast-ffmpeg] archive_output=${ARCHIVE_SESSION_DIR}"
echo "[broadcast-ffmpeg] watermark=${WATERMARK_PATH}"

while true; do
  rm -f "${SESSION_DIR}"/*.m3u8 "${SESSION_DIR}"/*.ts 2>/dev/null || true

  ffmpeg -hide_banner -loglevel warning \
    -re -i "${INPUT_URL}" \
    -loop 1 -i "${WATERMARK_PATH}" \
    -filter_complex "[1:v]scale='min(220,iw*110)':-1[wm];[0:v][wm]overlay=W-w-24:H-h-24[vout]" \
    -map 0:a? -map "[vout]" \
    -c:v libx264 -preset veryfast -g 48 -keyint_min 48 -sc_threshold 0 \
    -b:v:0 3500k -maxrate:v:0 4200k -bufsize:v:0 7000k -s:v:0 1920x1080 \
    -b:v:1 1800k -maxrate:v:1 2200k -bufsize:v:1 3600k -s:v:1 1280x720 \
    -b:v:2 900k -maxrate:v:2 1100k -bufsize:v:2 1800k -s:v:2 854x480 \
    -var_stream_map "v:0,a:0 v:1,a:0 v:2,a:0" \
    -c:a aac -ar 48000 -b:a 128k \
    -f hls \
    -hls_time 4 \
    -hls_playlist_type event \
    -hls_flags independent_segments+append_list+delete_segments \
    -master_pl_name master.m3u8 \
    -hls_segment_filename "${SESSION_DIR}/v%v-seg-%06d.ts" \
    "${SESSION_DIR}/v%v.m3u8" || true

  rm -f "${ARCHIVE_SESSION_DIR}"/*.m3u8 "${ARCHIVE_SESSION_DIR}"/*.ts 2>/dev/null || true
  cp -f "${SESSION_DIR}/"*.m3u8 "${ARCHIVE_SESSION_DIR}/" 2>/dev/null || true
  cp -f "${SESSION_DIR}/"*.ts "${ARCHIVE_SESSION_DIR}/" 2>/dev/null || true

  echo "[broadcast-ffmpeg] ffmpeg exited; retrying in ${RESTART_DELAY_SECS}s"
  sleep "${RESTART_DELAY_SECS}"
done
