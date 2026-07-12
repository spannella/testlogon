# ops/testing — driving the REAL Android system media pickers

Host-side tooling for a batch agent to exercise the TestLogon Android app's media-pick
call sites **through the real Android system pickers** (no in-app test seam). This is the
complement to the in-app debug test-seam (`app/src/debug/.../testseam/`, gated by
`debug.testlogon.testhooks`): when you want to test the genuine end-to-end picker → URI →
upload path, leave the seam **OFF** (`adb shell setprop debug.testlogon.testhooks 0`) and
use these scripts to drive the OS picker UI.

All scripts assume:
- adb is on PATH (`source ~/.android-dev.env` first on the dev host).
- The tiny VALID sample media live in `android/app/src/debug/assets/test_media/`
  (`sample.jpg`, `sample.png`, `sample.mp4`, `sample.pdf`).

---

## Scripts

### `seed_media.sh [<serial>]`
Pushes the sample media onto the device's shared storage and registers each file with
MediaStore (so the Photo Picker and DocumentsUI show them):

| source       | device path                         | surface                          |
|--------------|-------------------------------------|----------------------------------|
| sample.jpg   | /sdcard/Pictures/testlogon_seed.jpg | Photo Picker (image)             |
| sample.png   | /sdcard/Pictures/testlogon_seed.png | Photo Picker (image)             |
| sample.mp4   | /sdcard/Movies/testlogon_seed.mp4   | Photo Picker (video)             |
| sample.jpg   | /sdcard/DCIM/testlogon_seed_dcim.jpg| Photo Picker "Recent" / camera roll |
| sample.pdf   | /sdcard/Download/testlogon_seed.pdf | DocumentsUI / Downloads          |

Idempotent (re-push overwrites; re-scan is harmless). Each file is indexed with a
per-file `MEDIA_SCANNER_SCAN_FILE` broadcast plus a best-effort full-volume
`content call ... scan_volume` backstop, then verified by counting MediaStore rows.
If exactly one device is attached the serial may be omitted.

```
source ~/.android-dev.env
ops/testing/seed_media.sh R5CX821TA9R
# -> seed_media: MediaStore images matching=3 video matching=1 ... DONE
```

### `pick_real.sh <serial> <photo|video|document> [name]`
Drives whichever real system picker is **currently on screen** and selects a seeded item,
returning it to the app. It does NOT launch the picker — the app (or a manual `am start`)
must already have opened it. It polls (up to ~12 s) until a known picker is foreground,
dumps the UI, locates the target, taps it, handles the multi-select confirm button, and
verifies focus returned to the app.

- `photo`    — first image in the Photo Picker (or a seeded image file in DocumentsUI).
- `video`    — first video in the Photo Picker (or a seeded mp4 in DocumentsUI).
- `document` — a file in DocumentsUI by name (default `testlogon_seed.pdf`).
- `[name]`   — optional filename to match in DocumentsUI.

Exit codes: `0` selected & returned to app; `1` bad args; `2` no picker appeared;
`3` no matching item; `4` selected but confirm button not found.

```
# from inside the app: tap the Feed compose "Add photos", then:
ops/testing/pick_real.sh R5CX821TA9R photo
```

---

## Which picker does each app flow trigger? (and which pick_real mode to use)

Determined from the contracts used at each call site (`grep ActivityResultContracts.*`):

| Contract                         | Real picker on this device            | pick_real mode | Example app flows |
|----------------------------------|---------------------------------------|----------------|-------------------|
| `PickVisualMedia` (ImageOnly)    | **Android Photo Picker** (`com.google.android.photopicker`) | `photo` | Feed add-video poster, profile photo, message image, comment image, EditPost, lottery cover |
| `PickVisualMedia` (VideoOnly)    | Android Photo Picker                  | `video`  | Feed `compose_add_video`, message video |
| `PickMultipleVisualMedia(n)`     | Android Photo Picker (multi-select)   | `photo`  | Feed `compose_add_photos`, EditPost photos, message multi-image gallery |
| `GetContent`                     | **DocumentsUI** (`com.google.android.documentsui`) | `photo`/`document` | KYC docs, proof-of-funds, support-ticket attach, group post/comment image, syndicate, video comments |
| `OpenDocument` / `OpenMultipleDocuments` | **DocumentsUI**               | `document` | Files upload, video upload (source file), message file-share |
| `TakePicture` (camera)           | System camera app (NOT a picker)      | n/a — use the **in-app test seam** `kind camera` (writes sample.jpg into the target Uri); the real camera can't be driven headless | KYC capture, ID scanner, facial, residency, proof-of-funds |

Notes:
- **Photo Picker** (modern, Compose, API 30+; this device is API 36 Android 16): grid cells
  have NO resource-id. Each cell is a clickable parent `<View>` whose child carries
  `content-desc="Photo taken on <date>"` or `"Video taken on <date> with duration ..."`.
  The desc node's bounds equal the cell's bounds, so `pick_real` taps the desc node center.
  Multi-select adds a checkmark and an **"Add"/"Done"** confirm button — `pick_real` matches
  that text and taps it.
- **DocumentsUI** (classic View UI, stable ids): file rows expose the filename via an
  `android:id/title` text node spanning the full row width; `pick_real` matches the filename
  text and taps the row center. (The `content-desc="Preview the file <name>"` lives on a
  small right-edge preview icon — NOT the row tap target — so it is intentionally not used.)
- **camera** (`TakePicture`) writes to a caller-supplied FileProvider Uri; there is no
  selectable UI to drive headlessly. Use the in-app seam (`am broadcast -a
  com.testlogon.test.PICK --es kind camera`, with `debug.testlogon.testhooks 1`) for those.

---

## OEM branching
`pick_real.sh` reads `ro.product.manufacturer` and logs it, but the selection logic keys off
the **foreground package** (`com.google.android.photopicker` vs `com.google.android.documentsui`),
which is the stable, OEM-independent signal — on a Samsung (One UI) A15 the Google modules
(`com.google.android.photopicker`, `com.google.android.providers.media.module`,
`com.google.android.documentsui`) handle these intents, not the Samsung media provider, so
no Samsung-specific selector path was needed. The detection-by-foreground-package + bounded
content-desc / title-text fallback is designed to also cover a stock (Google) device; that
path is logic-verified but a Pixel hardware pass is still pending (see VERIFICATION below).

---

## VERIFICATION (on attached device only)
Tested on **Samsung Galaxy A15 `R5CX821TA9R` (One UI, Android 16 / API 36)** — the only
device attached; the **Pixel 7a was NOT connected**, so the stock pass is a TODO.

- `seed_media.sh` → 3 images + 1 video indexed in MediaStore; pdf in Downloads. PASS.
- `pick_real document` (standalone DocumentsUI) → selected `testlogon_seed.pdf`, returned to app. PASS.
- `pick_real photo` (standalone Photo Picker) → selected first image, returned to app. PASS.
- `pick_real video` (standalone Photo Picker) → selected first video, returned to app. PASS.
- **Full app flow:** Feed compose FAB → composer → `compose_add_photos` launched the REAL
  Photo Picker (multi-select) → `pick_real photo` selected the first image, matched the
  **"Done"** confirm, returned to app → `compose_image_thumb` rendered → added body →
  `compose_post_submit` → returned to `feed_screen`, **0 crashes**. PASS.
