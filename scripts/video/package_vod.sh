#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
OUT_ROOT="${OUT_ROOT:-${ROOT_DIR}/video-data}"
SRC="${SRC:-${OUT_ROOT}/input/vod_source.mp4}"
DURATION="${DURATION:-12}"

mkdir -p "${OUT_ROOT}/input" "${OUT_ROOT}/hls/1080p" "${OUT_ROOT}/hls/720p" "${OUT_ROOT}/hls/540p" "${OUT_ROOT}/hls/360p" "${OUT_ROOT}/dash"

if ! command -v ffmpeg >/dev/null 2>&1; then
  echo "ffmpeg is required for package_vod.sh (not found on PATH)" >&2
  exit 1
fi

echo "[vod] generating synthetic source at ${SRC}"
ffmpeg -hide_banner -loglevel warning -y \
  -f lavfi -i testsrc=size=1920x1080:rate=30 \
  -f lavfi -i sine=frequency=1000:sample_rate=48000 \
  -t "${DURATION}" \
  -c:v libx264 -pix_fmt yuv420p -c:a aac -b:a 128k \
  "${SRC}"

echo "[vod] packaging ABR HLS renditions"
ffmpeg -hide_banner -loglevel warning -y -i "${SRC}" \
  -filter:v:0 scale=1920:1080 -c:v:0 libx264 -b:v:0 6000k -c:a:0 aac -b:a:0 192k \
  -f hls -hls_time 4 -hls_playlist_type vod -hls_segment_filename "${OUT_ROOT}/hls/1080p/seg_%03d.ts" "${OUT_ROOT}/hls/1080p/index.m3u8"
ffmpeg -hide_banner -loglevel warning -y -i "${SRC}" \
  -filter:v scale=1280:720 -c:v libx264 -b:v 3500k -c:a aac -b:a 128k \
  -f hls -hls_time 4 -hls_playlist_type vod -hls_segment_filename "${OUT_ROOT}/hls/720p/seg_%03d.ts" "${OUT_ROOT}/hls/720p/index.m3u8"
ffmpeg -hide_banner -loglevel warning -y -i "${SRC}" \
  -filter:v scale=960:540 -c:v libx264 -b:v 2200k -c:a aac -b:a 128k \
  -f hls -hls_time 4 -hls_playlist_type vod -hls_segment_filename "${OUT_ROOT}/hls/540p/seg_%03d.ts" "${OUT_ROOT}/hls/540p/index.m3u8"
ffmpeg -hide_banner -loglevel warning -y -i "${SRC}" \
  -filter:v scale=640:360 -c:v libx264 -b:v 1200k -c:a aac -b:a 96k \
  -f hls -hls_time 4 -hls_playlist_type vod -hls_segment_filename "${OUT_ROOT}/hls/360p/seg_%03d.ts" "${OUT_ROOT}/hls/360p/index.m3u8"

python "${ROOT_DIR}/scripts/video/package_manifests.py"

"${ROOT_DIR}/scripts/video/validate_manifests.sh" "${OUT_ROOT}"

echo "[vod] done. Open http://localhost:8089/hls/master.m3u8 and http://localhost:8089/dash/manifest.mpd"
