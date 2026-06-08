#!/usr/bin/env bash
#
# Assemble the FINAL voiced walkthrough with per-segment audio/video sync.
#
# Problem: each segment's narration (voiceNN.mp3) is not the same length as its
# recorded video (segNN.webm). A naive single-track mux drifts. Fix: for every
# segment, set its slot length to max(video, narration)+tail; pad the VIDEO by
# freezing its last frame and pad the AUDIO with trailing silence (+ a short
# lead-in) so each segment's narration stays locked to its own footage.
#
# Inputs (produced earlier):
#   out/segNN.webm        recorded segment video (from record_all_demo.sh)
#   out/voiceNN.mp3       segment narration (from render_voiceover.py)
# Output:
#   out/demo_walkthrough_voiced.mp4
set -euo pipefail
ROOT="/home/ubuntu/testlogon"
OUT="$ROOT/frontend/e2e/demo/out"
A="$OUT/aligned"
W=1920; H=1080; FPS=30; LEADIN=0.4; TAIL=0.6
rm -rf "$A"; mkdir -p "$A"

dur() { ffprobe -v error -show_entries format=duration -of default=nw=1:nk=1 "$1"; }

vids=(); auds=()

# Intro title card (video) + matching silence (audio).
INTRO_V="$A/00_intro.mp4"; INTRO_DUR=3.2
ffmpeg -y -loglevel error -f lavfi -i "color=c=0x020617:s=${W}x${H}:r=${FPS}" \
  -vf "drawtext=text='Platform Walkthrough':fontcolor=white:fontsize=72:x=(w-text_w)/2:y=(h-text_h)/2-40,drawtext=text='A guided tour of every major feature':fontcolor=0x94a3b8:fontsize=30:x=(w-text_w)/2:y=(h-text_h)/2+60" \
  -t $INTRO_DUR -c:v libx264 -preset veryfast -crf 20 -pix_fmt yuv420p -an "$INTRO_V"
INTRO_A="$A/00_intro.m4a"
ffmpeg -y -loglevel error -f lavfi -i "anullsrc=channel_layout=stereo:sample_rate=48000" -t $INTRO_DUR -c:a aac "$INTRO_A"
vids+=("$INTRO_V"); auds+=("$INTRO_A")

for webm in "$OUT"/seg*.webm; do
  [ -f "$webm" ] || continue
  seg="$(basename "$webm" .webm)"          # segNN
  voice="$OUT/voice${seg#seg}.mp3"          # voiceNN.mp3
  vDur=$(dur "$webm")
  if [ -f "$voice" ]; then aDur=$(dur "$voice"); else aDur=0; fi
  # slot = max(video, leadin+narration+tail)
  need=$(awk "BEGIN{print $LEADIN+$aDur+$TAIL}")
  slot=$(awk "BEGIN{print ($vDur>$need)?$vDur:$need}")
  echo "  $seg: video=${vDur}s narration=${aDur}s -> slot=${slot}s"

  # Video: scale/pad to 1080p, then freeze last frame out to `slot`.
  vout="$A/${seg}.mp4"
  ffmpeg -y -loglevel error -i "$webm" \
    -vf "scale=${W}:${H}:force_original_aspect_ratio=decrease,pad=${W}:${H}:(ow-iw)/2:(oh-ih)/2:color=0x020617,fps=${FPS},setsar=1,tpad=stop_mode=clone:stop_duration=$(awk "BEGIN{d=$slot-$vDur; print (d>0)?d:0}")" \
    -t "$slot" -an -c:v libx264 -preset veryfast -crf 20 -pix_fmt yuv420p "$vout"

  # Audio: lead-in silence + narration + trailing silence to fill `slot`.
  aout="$A/${seg}.m4a"
  if [ -f "$voice" ]; then
    ffmpeg -y -loglevel error -i "$voice" \
      -af "adelay=$(awk "BEGIN{print int($LEADIN*1000)}")|$(awk "BEGIN{print int($LEADIN*1000)}"),apad" \
      -t "$slot" -ar 48000 -ac 2 -c:a aac "$aout"
  else
    ffmpeg -y -loglevel error -f lavfi -i "anullsrc=channel_layout=stereo:sample_rate=48000" -t "$slot" -c:a aac "$aout"
  fi
  vids+=("$vout"); auds+=("$aout")
done

# Concat video track and audio track separately (slots match per segment), then mux.
vlist="$A/_v.txt"; alist="$A/_a.txt"; : >"$vlist"; : >"$alist"
for f in "${vids[@]}"; do echo "file '$f'" >>"$vlist"; done
for f in "${auds[@]}"; do echo "file '$f'" >>"$alist"; done
ffmpeg -y -loglevel error -f concat -safe 0 -i "$vlist" -c copy "$A/_video.mp4"
ffmpeg -y -loglevel error -f concat -safe 0 -i "$alist" -c copy "$A/_audio.m4a"

FINAL="$OUT/demo_walkthrough_voiced.mp4"
ffmpeg -y -loglevel error -i "$A/_video.mp4" -i "$A/_audio.m4a" -map 0:v -map 1:a \
  -c:v copy -c:a aac -movflags +faststart -shortest "$FINAL"

D=$(dur "$FINAL")
printf "\n== voiced film ==\n  %s\n  duration: %.0fs (%.1f min)\n" "$FINAL" "$D" "$(awk "BEGIN{print $D/60}")"
