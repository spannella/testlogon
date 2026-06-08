#!/usr/bin/env bash
#
# Record every demo segment and PRESERVE each webm.
#
# Playwright cleans its outputDir at the start of each run, so recording segNN
# wipes the previous segments' artifacts. This driver restarts the stack clean
# (so each segment seeds its own data with no cross-segment clutter), runs one
# segment spec, then immediately copies its webm to e2e/demo/out/segNN.webm
# (outside the outputDir) before the next run can wipe it.
#
# Usage:  bash scripts/record_all_demo.sh            # all segments
#         bash scripts/record_all_demo.sh 04 09 12    # only these
# Then:   bash scripts/build_demo_video.sh
set -u
ROOT="/home/ubuntu/testlogon"
ART="$ROOT/frontend/e2e/demo/.artifacts"
OUT="$ROOT/frontend/e2e/demo/out"
mkdir -p "$OUT"

cd "$ROOT/frontend"
mapfile -t SPECS < <(ls e2e/demo/seg*-*.demo.ts | sort)

want=("$@")
in_want() { [ ${#want[@]} -eq 0 ] && return 0; for w in "${want[@]}"; do [ "$w" = "$1" ] && return 0; done; return 1; }

declare -a OK=() FAIL=()
for spec in "${SPECS[@]}"; do
  n=$(basename "$spec" | sed -E 's/^seg([0-9]+).*/\1/')
  in_want "$n" || continue
  echo "================ SEGMENT $n ================"
  ( cd "$ROOT" && just restart >/dev/null 2>&1 ) && echo "  [restart ok]"
  if npx playwright test -c playwright.demo.config.ts "$spec" --reporter=line >"/tmp/rec_seg$n.log" 2>&1; then
    src=$(find "$ART" -type d -name "seg${n}-*" 2>/dev/null | head -1)
    if [ -n "$src" ] && [ -f "$src/video.webm" ]; then
      cp "$src/video.webm" "$OUT/seg${n}.webm"
      dur=$(ffprobe -v error -show_entries format=duration -of default=nw=1:nk=1 "$OUT/seg${n}.webm" 2>/dev/null)
      echo "  [PASS] seg$n -> out/seg$n.webm (${dur%.*}s)"
      OK+=("$n")
    else
      echo "  [WARN] seg$n passed but no webm found"
      FAIL+=("$n")
    fi
  else
    echo "  [FAIL] seg$n spec failed — see /tmp/rec_seg$n.log"
    tail -3 "/tmp/rec_seg$n.log" | sed 's/^/    /'
    FAIL+=("$n")
  fi
done

echo "================ SUMMARY ================"
echo "  preserved: ${OK[*]:-none}"
echo "  failed:    ${FAIL[*]:-none}"
echo "  out webms: $(ls "$OUT"/seg*.webm 2>/dev/null | wc -l)"
