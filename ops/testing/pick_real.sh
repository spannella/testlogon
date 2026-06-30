#!/usr/bin/env bash
# pick_real.sh — drive the REAL Android system picker that is currently on screen and
# select a seeded media item, returning it to the app under test.
#
# Two picker families are handled (auto-detected by the foreground package):
#
#   1. Android Photo Picker  (com.google.android.photopicker / providers.media.module)
#        Launched by ActivityResultContracts.PickVisualMedia / PickMultipleVisualMedia.
#        Modern Compose UI: grid cells have NO resource-id; each selectable cell is a
#        clickable parent <View> whose child carries content-desc="Photo taken on ..."
#        or "Video taken on ... with duration ...". We locate the first matching cell,
#        tap its center, and (for multi-select) tap the "Add"/"Add (N)" confirm button.
#
#   2. DocumentsUI  (com.google.android.documentsui)
#        Launched by ActivityResultContracts.OpenDocument / OpenMultipleDocuments and,
#        on this device, by GetContent too. Classic View UI with stable ids: file rows
#        are com.google.android.documentsui:id/item_root, each with android:id/title
#        (the filename) and content-desc="Preview the file <name>". We tap the row whose
#        title matches the requested/seeded filename.
#
# This script does NOT launch the picker — the app must already have opened it (e.g. the
# Feed compose "Add photos" button). It polls until a known picker is foreground, then acts.
#
# Usage:
#   ./pick_real.sh <serial> <photo|video|document> [name]
#     <serial>   adb serial of the target device (required).
#     mode:
#       photo      select first image in the Photo Picker (or, if DocumentsUI is up,
#                  the first image-typed file / a *.jpg seed).
#       video      select first video in the Photo Picker (or a *.mp4 seed in DocumentsUI).
#       document   select a file in DocumentsUI by name (default: testlogon_seed.pdf).
#     [name]       optional filename to match in DocumentsUI (default depends on mode:
#                  document->testlogon_seed.pdf, photo->testlogon_seed.jpg,
#                  video->testlogon_seed.mp4).
#
# Exit codes: 0 = item selected & picker dismissed; 1 = bad args; 2 = no picker appeared;
#             3 = could not find a matching item; 4 = selected but confirm button not found.
set -uo pipefail

SERIAL="${1:-}"
MODE="${2:-}"
NAME="${3:-}"
if [ -z "$SERIAL" ] || [ -z "$MODE" ]; then
  echo "usage: pick_real.sh <serial> <photo|video|document> [name]" >&2
  exit 1
fi
case "$MODE" in photo|video|document) : ;; *) echo "bad mode: $MODE" >&2; exit 1;; esac
ADB="adb -s $SERIAL"

# Default seed filename per mode (used for DocumentsUI name matching).
if [ -z "$NAME" ]; then
  case "$MODE" in
    document) NAME="testlogon_seed.pdf" ;;
    photo)    NAME="testlogon_seed.jpg" ;;
    video)    NAME="testlogon_seed.mp4" ;;
  esac
fi

OEM=$($ADB shell getprop ro.product.manufacturer 2>/dev/null | tr -d '\r')
echo "pick_real: serial=$SERIAL mode=$MODE name=$NAME oem=$OEM"

DUMP=/sdcard/pick_real_dump.xml
LOCAL_DUMP="/tmp/pick_real_dump_${SERIAL}.xml"

fg_pkg() { $ADB shell dumpsys window 2>/dev/null | grep -m1 'mCurrentFocus' | tr -d '\r'; }

dump_ui() {
  # uiautomator dump can transiently fail while the window animates; retry a few times.
  local i
  for i in 1 2 3; do
    if $ADB shell uiautomator dump "$DUMP" >/dev/null 2>&1; then
      $ADB pull "$DUMP" "$LOCAL_DUMP" >/dev/null 2>&1 && [ -s "$LOCAL_DUMP" ] && return 0
    fi
    sleep 1
  done
  return 1
}

# center-tap a uiautomator bounds string "[x1,y1][x2,y2]"
tap_bounds() {
  local b="$1"
  local nums; nums=$(echo "$b" | grep -oE '[0-9]+')
  local x1 y1 x2 y2; read -r x1 y1 x2 y2 <<< "$(echo "$nums" | tr '\n' ' ')"
  local cx=$(( (x1 + x2) / 2 ))
  local cy=$(( (y1 + y2) / 2 ))
  echo "pick_real: tap center=($cx,$cy) of $b"
  $ADB shell input tap "$cx" "$cy" >/dev/null 2>&1
}

# Given the raw XML on stdin and a python-free approach, extract the bounds of the FIRST
# <node> whose content-desc matches a regex. The photo-picker cell that is *clickable* is the
# PARENT of the content-desc node, but its bounds are identical to the desc node's bounds
# (verified on-device), so tapping the desc node's center hits the cell.
# IMPORTANT: split the dump into ONE <node ...> per line first (tr '<' -> newline). The
# uiautomator XML is effectively a single physical line, so we must isolate node elements
# before grepping, otherwise a match's `bounds=` would resolve to the first (root) node.
nodes() { tr '<' '\n' < "$LOCAL_DUMP"; }

bounds_for_desc() {
  local re="$1"
  nodes \
    | grep -iE "content-desc=\"$re" \
    | grep -oE 'bounds="\[[0-9]+,[0-9]+\]\[[0-9]+,[0-9]+\]"' \
    | head -1 | sed -E 's/^bounds="//; s/"$//'
}

# DocumentsUI: bounds of the item_root row whose content-desc is "Preview the file <name>".
bounds_for_docname() {
  local name="$1"
  nodes \
    | grep -iE "content-desc=\"Preview the file ${name}\"" \
    | grep -oE 'bounds="\[[0-9]+,[0-9]+\]\[[0-9]+,[0-9]+\]"' \
    | head -1 | sed -E 's/^bounds="//; s/"$//'
}

# A generic "tap text" using uiautomator-dumped bounds for a node whose text== given string.
bounds_for_text() {
  local t="$1"
  nodes \
    | grep -iE "text=\"${t}\"" \
    | grep -oE 'bounds="\[[0-9]+,[0-9]+\]\[[0-9]+,[0-9]+\]"' \
    | head -1 | sed -E 's/^bounds="//; s/"$//'
}

# ---- wait for a known picker to be foreground (poll up to ~12s) ----
PICKER=""
for i in $(seq 1 12); do
  FG=$(fg_pkg)
  if echo "$FG" | grep -qiE 'com.google.android.photopicker|providers.media.module/.*PhotoPicker|providers.media'; then
    PICKER="photopicker"; break
  elif echo "$FG" | grep -qiE 'com.google.android.documentsui|com.android.documentsui'; then
    PICKER="documentsui"; break
  fi
  sleep 1
done
if [ -z "$PICKER" ]; then
  echo "pick_real: ERROR no system picker is foreground. focus=$(fg_pkg)" >&2
  exit 2
fi
echo "pick_real: detected picker=$PICKER (focus=$(fg_pkg))"
sleep 1   # let the grid/list settle

if ! dump_ui; then
  echo "pick_real: ERROR could not dump UI" >&2
  exit 2
fi

if [ "$PICKER" = "photopicker" ]; then
  # Choose desc regex by mode.
  case "$MODE" in
    video) DESC_RE="Video taken" ;;
    *)     DESC_RE="Photo taken" ;;   # photo (and fall-through default)
  esac
  B=""
  for attempt in 1 2 3; do
    B=$(bounds_for_desc "$DESC_RE")
    [ -n "$B" ] && break
    # not found yet (grid still loading or need to scroll a touch); re-dump
    sleep 1; dump_ui || true
  done
  if [ -z "$B" ]; then
    echo "pick_real: ERROR no '$DESC_RE...' cell found in Photo Picker" >&2
    exit 3
  fi
  tap_bounds "$B"
  sleep 1

  # If we're still in the picker, it's a MULTI-select session waiting for confirmation.
  FG=$(fg_pkg)
  if echo "$FG" | grep -qiE 'photopicker|providers.media'; then
    echo "pick_real: still in picker -> multi-select, looking for Add/Done confirm"
    dump_ui || true
    # The confirm button text varies: "Add", "Add (1)", "Done", "Select". Try in order.
    CB=""
    for label in "Add \\(1\\)" "Add" "Done" "Select \\(1\\)" "Select"; do
      CB=$(bounds_for_text "$label")
      [ -n "$CB" ] && { echo "pick_real: confirm button matched '$label'"; break; }
    done
    if [ -n "$CB" ]; then
      tap_bounds "$CB"; sleep 1
    else
      echo "pick_real: WARN confirm button not found; single-tap may have already returned" >&2
    fi
  fi

else
  # DocumentsUI: pick by filename. The full-width clickable row carries the filename as the
  # text of an android:id/title node spanning [0,y1][screenW,y2]; tapping its center hits the
  # row. (The "Preview the file <name>" content-desc lives on a small right-edge icon and is
  # NOT the row tap target, so we match on the title text instead.)
  B=$(bounds_for_text "$NAME")
  if [ -z "$B" ]; then
    # Try the other common seed names as a fallback for photo/video modes.
    for alt in testlogon_seed.pdf testlogon_seed.jpg testlogon_seed.png testlogon_seed.mp4; do
      B=$(bounds_for_text "$alt")
      [ -n "$B" ] && { echo "pick_real: fell back to seed '$alt'"; break; }
    done
  fi
  if [ -z "$B" ]; then
    echo "pick_real: ERROR file '$NAME' not visible in DocumentsUI (is it seeded? run seed_media.sh)" >&2
    exit 3
  fi
  tap_bounds "$B"
  sleep 1
  # OpenMultipleDocuments needs a confirm; single OpenDocument returns on tap. If still up:
  FG=$(fg_pkg)
  if echo "$FG" | grep -qiE 'documentsui'; then
    dump_ui || true
    # "Select" / "Open" / "Add" / "Done" button id options
    for label in "Select" "Open" "Add" "Done"; do
      CB=$(bounds_for_text "$label")
      [ -n "$CB" ] && { tap_bounds "$CB"; break; }
    done
  fi
fi

sleep 1
FG=$(fg_pkg)
if echo "$FG" | grep -qiE 'com.testlogon.android'; then
  echo "pick_real: SUCCESS returned to app ($FG)"
  exit 0
elif echo "$FG" | grep -qiE 'photopicker|providers.media|documentsui'; then
  echo "pick_real: WARN still in picker after select ($FG)" >&2
  exit 4
else
  echo "pick_real: returned to $FG (not the picker) — likely success"
  exit 0
fi
