#!/usr/bin/env bash
# Stitch recorded demo segments into one MP4.
#
# Usage:
#   scripts/build_demo_video.sh [OUTPUT.mp4] [seg1 seg2 ...]
#   - OUTPUT.mp4 : output filename under frontend/e2e/demo/out/ (default demo_v2_verticals.mp4)
#   - seg prefixes : which segments to include, in order. If omitted, ALL seg*.demo.ts
#                    are discovered and ordered numerically (seg1..segN).
#
# Examples:
#   scripts/build_demo_video.sh demo_v2_verticals.mp4 seg1 seg2 seg3 seg4 seg5 seg6
#   scripts/build_demo_video.sh demo_full_platform.mp4        # all segments
set -euo pipefail

cd "$(dirname "$0")/../frontend"
ART="e2e/demo/.artifacts"
OUT="e2e/demo/out"

OUTNAME="${1:-demo_v2_verticals.mp4}"
[ $# -ge 1 ] && shift || true
if [ $# -ge 1 ]; then
  SEGS=("$@")
else
  mapfile -t SEGS < <(ls e2e/demo/*.demo.ts 2>/dev/null \
    | sed -E 's#.*/(seg[0-9]+)-.*#\1#' | sort -V | uniq)
fi

TMP="$OUT/tmp_$$"
mkdir -p "$OUT" "$TMP"
trap 'rm -rf "$TMP"' EXIT

n=0
for seg in "${SEGS[@]}"; do
  webm=$(find "$ART" -type f -name "video.webm" -path "*${seg}-*" -printf '%T@ %p\n' 2>/dev/null \
         | sort -rn | head -1 | cut -d' ' -f2-)
  if [ -z "${webm:-}" ] || [ ! -f "$webm" ]; then
    echo "WARN: no webm for $seg — skipping" >&2
    continue
  fi
  n=$((n+1))
  out="$TMP/$(printf '%02d' "$n")-${seg}.mp4"
  echo "normalize $seg"
  ffmpeg -y -loglevel error -i "$webm" -f lavfi -i anullsrc=channel_layout=stereo:sample_rate=48000 \
    -filter_complex "[0:v]scale=1920:1080:force_original_aspect_ratio=decrease,pad=1920:1080:(ow-iw)/2:(oh-ih)/2:color=black,fps=30,format=yuv420p[v]" \
    -map "[v]" -map 1:a -shortest \
    -c:v libx264 -preset veryfast -crf 22 -c:a aac -b:a 96k "$out"
done

shopt -s nullglob
mapfile -t parts < <(ls "$TMP"/[0-9][0-9]-*.mp4 | sort)
if [ "${#parts[@]}" -eq 0 ]; then
  echo "ERROR: no segments normalized — nothing to stitch" >&2
  exit 1
fi

echo "=== concat ${#parts[@]} segments -> $OUTNAME ==="
inputs=(); filter=""
for i in "${!parts[@]}"; do
  inputs+=(-i "${parts[$i]}")
  filter+="[$i:v:0][$i:a:0]"
done
filter+="concat=n=${#parts[@]}:v=1:a=1[v][a]"
ffmpeg -y -loglevel error "${inputs[@]}" -filter_complex "$filter" \
  -map "[v]" -map "[a]" -c:v libx264 -preset veryfast -crf 22 -c:a aac -b:a 96k \
  "$OUT/$OUTNAME"
dur=$(ffprobe -v error -show_entries format=duration -of default=nk=1:nw=1 "$OUT/$OUTNAME" 2>/dev/null || echo "?")
echo "DONE: $OUT/$OUTNAME  (~${dur}s)"
ls -lh "$OUT/$OUTNAME"
