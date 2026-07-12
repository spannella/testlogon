#!/usr/bin/env bash
# seed_media.sh — push valid sample media onto an Android device's shared storage and
# make it visible to the system Photo Picker / DocumentsUI by triggering MediaScanner.
#
# Idempotent: re-pushing overwrites the same destination files; re-scanning is harmless.
#
# Usage:
#   ./seed_media.sh [<serial>]
#     <serial>  adb serial of the target device. If omitted and exactly one device is
#               attached, that device is used; otherwise the script errors and lists devices.
#
# Source media lives in the repo's debug asset dir (the same tiny VALID files the in-app
# test seam serves):  app/src/debug/assets/test_media/{sample.jpg,sample.png,sample.mp4,sample.pdf}
#
# Destinations (standard public dirs that both the Photo Picker and DocumentsUI index):
#   sample.jpg -> /sdcard/Pictures/testlogon_seed.jpg     (Photo Picker: image)
#   sample.png -> /sdcard/Pictures/testlogon_seed.png     (Photo Picker: image)
#   sample.mp4 -> /sdcard/Movies/testlogon_seed.mp4       (Photo Picker: video)
#   sample.jpg -> /sdcard/DCIM/testlogon_seed_dcim.jpg    (DCIM camera roll, Photo Picker "Recent")
#   sample.pdf -> /sdcard/Download/testlogon_seed.pdf     (DocumentsUI / Downloads)
#
# After push, each media file is registered with MediaStore via a per-file
# MEDIA_SCANNER_SCAN_FILE broadcast (the documented, root-free way to index a single file).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Repo asset dir is ../../android/app/src/debug/assets/test_media relative to ops/testing/
ASSET_DIR="$(cd "$SCRIPT_DIR/../../android/app/src/debug/assets/test_media" 2>/dev/null && pwd || true)"
if [ -z "${ASSET_DIR:-}" ] || [ ! -f "$ASSET_DIR/sample.jpg" ]; then
  # Fallback: allow override via TL_TEST_MEDIA env (useful if run from elsewhere)
  ASSET_DIR="${TL_TEST_MEDIA:-}"
fi
if [ -z "${ASSET_DIR:-}" ] || [ ! -f "$ASSET_DIR/sample.jpg" ]; then
  echo "ERROR: cannot locate sample media. Expected app/src/debug/assets/test_media/ relative to this script," >&2
  echo "       or set TL_TEST_MEDIA to the dir containing sample.jpg/png/mp4/pdf." >&2
  exit 2
fi

SERIAL="${1:-}"
if [ -z "$SERIAL" ]; then
  mapfile -t DEVS < <(adb devices | awk 'NR>1 && $2=="device"{print $1}')
  if [ "${#DEVS[@]}" -eq 1 ]; then
    SERIAL="${DEVS[0]}"
  else
    echo "ERROR: specify a serial. Attached devices:" >&2
    adb devices >&2
    exit 2
  fi
fi
ADB="adb -s $SERIAL"
echo "seed_media: device=$SERIAL  assets=$ASSET_DIR"

# (dest path | source file) pairs
push_and_scan() {
  local src="$1" dst="$2"
  echo "  push $(basename "$src") -> $dst"
  $ADB push "$src" "$dst" >/dev/null
  # Trigger a single-file media scan. Works without root; MediaStore picks up name/mime/size.
  $ADB shell am broadcast -a android.intent.action.MEDIA_SCANNER_SCAN_FILE \
      -d "file://$dst" >/dev/null 2>&1 || true
}

push_and_scan "$ASSET_DIR/sample.jpg" /sdcard/Pictures/testlogon_seed.jpg
push_and_scan "$ASSET_DIR/sample.png" /sdcard/Pictures/testlogon_seed.png
push_and_scan "$ASSET_DIR/sample.mp4" /sdcard/Movies/testlogon_seed.mp4
push_and_scan "$ASSET_DIR/sample.jpg" /sdcard/DCIM/testlogon_seed_dcim.jpg
push_and_scan "$ASSET_DIR/sample.pdf" /sdcard/Download/testlogon_seed.pdf

# Some OEMs (incl. Samsung) honor a recursive MediaStore scan of the volume too; do a
# best-effort full-volume scan as a backstop so anything missed by per-file broadcasts indexes.
$ADB shell content call --uri content://media/external/file \
    --method scan_volume --arg external_primary >/dev/null 2>&1 || true

echo "seed_media: verifying MediaStore rows..."
# Count how many of our seeded names MediaStore now knows about (image+video).
# NOTE: avoid a --where clause here; nested single-quotes don't survive an `ssh '...'`
# wrapper reliably. Just project _display_name across the whole collection and grep.
IMG=$($ADB shell content query --uri content://media/external/images/media \
      --projection _display_name 2>/dev/null | grep -c "testlogon_seed" || true)
VID=$($ADB shell content query --uri content://media/external/video/media \
      --projection _display_name 2>/dev/null | grep -c "testlogon_seed" || true)
echo "seed_media: MediaStore images matching=$IMG video matching=$VID (expect images>=3, video>=1)"
if [ "${IMG:-0}" -lt 1 ]; then
  echo "seed_media: WARNING — no seeded images found in MediaStore; the Photo Picker may not show them." >&2
fi
echo "seed_media: DONE"
