#!/bin/sh
set -eu

OUT_ROOT="${1:-$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)/video-data}"

for path in \
  "${OUT_ROOT}/hls/master.m3u8" \
  "${OUT_ROOT}/hls/1080p/index.m3u8" \
  "${OUT_ROOT}/hls/720p/index.m3u8" \
  "${OUT_ROOT}/hls/540p/index.m3u8" \
  "${OUT_ROOT}/hls/360p/index.m3u8" \
  "${OUT_ROOT}/dash/manifest.mpd"; do
  [ -f "${path}" ] || { echo "missing: ${path}" >&2; exit 1; }
done

grep -q "1080p/index.m3u8" "${OUT_ROOT}/hls/master.m3u8"
grep -q "720p/index.m3u8" "${OUT_ROOT}/hls/master.m3u8"
grep -q "540p/index.m3u8" "${OUT_ROOT}/hls/master.m3u8"
grep -q "360p/index.m3u8" "${OUT_ROOT}/hls/master.m3u8"
grep -q "v_1080p" "${OUT_ROOT}/dash/manifest.mpd"
grep -q "v_720p" "${OUT_ROOT}/dash/manifest.mpd"
grep -q "v_540p" "${OUT_ROOT}/dash/manifest.mpd"
grep -q "v_360p" "${OUT_ROOT}/dash/manifest.mpd"

echo "manifest validation passed"
