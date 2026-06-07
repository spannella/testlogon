#!/usr/bin/env bash
#
# Stitch the per-segment Playwright demo recordings into one walkthrough film.
#
#   1. Locate each segment's recorded webm under frontend/e2e/demo/.artifacts/
#      (one per `segNN-*.demo.ts` test) → copy to frontend/e2e/demo/out/segNN.webm
#   2. Generate a branded intro title card (3s).
#   3. Normalize every clip to identical H.264 1080p30 + a silent AAC track
#      (consistent streams so concat is clean and a voiceover can be muxed later).
#   4. Concat intro + all segments (numeric order) → out/demo_walkthrough.mp4
#
# Re-run any segment with:
#   cd frontend && npx playwright test -c playwright.demo.config.ts e2e/demo/segNN-*.demo.ts
# then re-run this script.
#
# Voiceover (later): scripts/render_voiceover.py builds out/voiceover.mp3 from
# docs/demo-video-script.md via ElevenLabs, then:
#   ffmpeg -i out/demo_walkthrough.mp4 -i out/voiceover.mp3 -map 0:v -map 1:a \
#          -c:v copy -c:a aac -shortest out/demo_walkthrough_voiced.mp4
set -euo pipefail

ROOT="/home/ubuntu/testlogon"
ART="$ROOT/frontend/e2e/demo/.artifacts"
OUT="$ROOT/frontend/e2e/demo/out"
W=1920; H=1080; FPS=30
mkdir -p "$OUT"

echo "== collecting segment recordings =="
shopt -s nullglob
declare -a SEG_MP4S=()

# Intro title card (3s, branded).
INTRO="$OUT/_intro.mp4"
ffmpeg -y -loglevel error \
  -f lavfi -i "color=c=0x020617:s=${W}x${H}:d=3.2:r=${FPS}" \
  -f lavfi -i "anullsrc=channel_layout=stereo:sample_rate=48000" \
  -vf "drawtext=text='Platform Walkthrough':fontcolor=white:fontsize=72:x=(w-text_w)/2:y=(h-text_h)/2-40,drawtext=text='A guided tour of every major feature':fontcolor=0x94a3b8:fontsize=30:x=(w-text_w)/2:y=(h-text_h)/2+60" \
  -c:v libx264 -pix_fmt yuv420p -r ${FPS} -t 3.2 -c:a aac -shortest "$INTRO"
SEG_MP4S+=("$INTRO")

# Each segment: copy webm out, normalize to mp4 with a silent audio track.
for dir in "$ART"/seg*-*.demo.ts-*; do
  [ -d "$dir" ] || continue
  webm="$dir/video.webm"
  [ -f "$webm" ] || continue
  seg="$(basename "$dir" | sed -E 's/^(seg[0-9]+).*/\1/')"   # seg01, seg02, ...
  cp "$webm" "$OUT/$seg.webm"
  mp4="$OUT/$seg.mp4"
  echo "  normalizing $seg ($(basename "$webm"))"
  ffmpeg -y -loglevel error \
    -i "$OUT/$seg.webm" \
    -f lavfi -i "anullsrc=channel_layout=stereo:sample_rate=48000" \
    -vf "scale=${W}:${H}:force_original_aspect_ratio=decrease,pad=${W}:${H}:(ow-iw)/2:(oh-ih)/2:color=0x020617,fps=${FPS},setsar=1" \
    -map 0:v:0 -map 1:a:0 \
    -c:v libx264 -preset veryfast -crf 20 -pix_fmt yuv420p \
    -c:a aac -shortest "$mp4"
  SEG_MP4S+=("$mp4")
done

if [ "${#SEG_MP4S[@]}" -le 1 ]; then
  echo "No segment recordings found under $ART — run the demo specs first." >&2
  exit 1
fi

# Sort segments numerically (intro stays first).
echo "== concatenating ${#SEG_MP4S[@]} clips =="
LIST="$OUT/_concat.txt"
: > "$LIST"
echo "file '$INTRO'" >> "$LIST"
for f in $(printf '%s\n' "${SEG_MP4S[@]}" | grep -E '/seg[0-9]+\.mp4$' | sort); do
  echo "file '$f'" >> "$LIST"
done

FINAL="$OUT/demo_walkthrough.mp4"
ffmpeg -y -loglevel error -f concat -safe 0 -i "$LIST" -c copy -movflags +faststart "$FINAL"

DUR=$(ffprobe -v error -show_entries format=duration -of default=nw=1:nk=1 "$FINAL")
printf "\n== done ==\n  %s\n  duration: %.0f s (%.1f min)\n" "$FINAL" "$DUR" "$(echo "$DUR/60" | bc -l)"
