# Media-picker test automation (TestLogon Android)

Two independent ways to automate the app's 24 media-pick call sites (which use
`ActivityResultContracts`: `PickVisualMedia`, `PickMultipleVisualMedia`, `GetContent`,
`OpenDocument`, `OpenMultipleDocuments`, `TakePicture`). The Android system photo/document
picker is an external process and is flaky to drive directly, so we provide:

1. **DEBUG TEST SEAM** (preferred for CI / headless) — an in-app intercepting
   `ActivityResultRegistry` that synthesizes a picked URI from bundled sample media, with
   **no system UI at all**. Gated triple-inert (see Release safety).
2. **REAL PICKER routine** (`pick_real.sh`) — host-side UIAutomator that drives whichever
   genuine system picker (Photo Picker / DocumentsUI) is foreground and selects a seeded file.

Both verified on-device on the Galaxy A15 `R5CX821TA9R` (One UI, Android 16 / API 36).
**Only the A15 was attached** for these runs; the Pixel 7a `32281JEHN13840` pass is still TODO.

---

## 1. DEBUG TEST SEAM

### What it is
Debug-only code under `android/app/src/debug/java/com/testlogon/android/testseam/`:
- `TestPickRegistry.kt` — subclass of `ActivityResultRegistry`. MainActivity provides it as the
  `LocalActivityResultRegistryOwner` in debug, so **every** `rememberLauncherForActivityResult`
  call site routes through it with zero call-site edits. When armed + gated, it synthesizes a
  typed result from `TestMediaProvider` and `dispatchResult()`s with no system UI. Otherwise it
  delegates to the real registry (genuine system picker).
- `TestMediaProvider.kt` — `content://${applicationId}.testmedia/<name>` provider (`exported=false`)
  serving the bundled sample files with proper `OpenableColumns` name/size and bytes.
- `TestSeamGate.kt` — the gate (see Release safety).
- `TestPickArmReceiver.kt` — exported `BroadcastReceiver` (action `com.testlogon.test.PICK`).
- `TestHooks.kt` — debug facade (returns the intercepting owner). A **release no-op shim** at
  `app/src/release/.../TestHooks.kt` returns `null`, so MainActivity (in `src/main`) compiles in
  both variants and release uses the genuine platform owner.
- Sample media: `app/src/debug/assets/test_media/sample.{jpg,png,mp4,pdf}` — tiny VALID files.

### Enable command (the gate)
The seam is **INERT** until the system property is set. Enable per device:
```
adb -s <serial> shell setprop debug.testlogon.testhooks 1     # enable
adb -s <serial> shell setprop debug.testlogon.testhooks 0     # disable (back to real picker)
```
Read fresh on every pick (no relaunch needed to toggle). `debug.*` namespace is world-settable
without root.

### Broadcast syntax (arm the next pick)
Arm is one-shot, consumed by the next matching pick. Only takes effect when the gate is on.
```
adb -s <serial> shell am broadcast -a com.testlogon.test.PICK --es kind <KIND> -p com.testlogon.android
```
Kinds:
| kind          | synthesizes                              | use for contracts                         |
|---------------|------------------------------------------|-------------------------------------------|
| `image`       | sample.jpg (single Uri)                  | PickVisualMedia / GetContent / OpenDocument |
| `png`         | sample.png (single Uri)                  | same                                      |
| `video`       | sample.mp4 (single Uri)                  | PickVisualMedia(VideoOnly) / GetContent   |
| `pdf`         | sample.pdf (single Uri)                  | GetContent / OpenDocument (file attach)   |
| `multi_image` | sample.jpg + sample.png (List<Uri>); add `--ei count N` | PickMultipleVisualMedia / OpenMultipleDocuments |
| `multi_av`    | sample.jpg + sample.mp4 (List<Uri>)      | gallery "photo OR video" multi-pick       |
| `camera`      | writes sample.jpg bytes into the camera target Uri, returns true | TakePicture |
| `clear`       | disarm                                   | —                                         |

### Typical flow
```
adb -s <serial> shell setprop debug.testlogon.testhooks 1
# navigate the app to the screen with the picker button (uiautomator dump + input tap)
adb -s <serial> shell am broadcast -a com.testlogon.test.PICK --es kind image -p com.testlogon.android
# tap the picker button -> no system UI; logcat: TestPickRegistry: synthesized ...
# complete + submit the form
adb -s <serial> shell setprop debug.testlogon.testhooks 0     # leave inert
```
Confirm it worked:
```
adb -s <serial> logcat -d -s TestPickRegistry TestPickArmReceiver   # "armed ..." then "synthesized ..."
adb -s <serial> shell dumpsys window | grep mCurrentFocus           # stays on com.testlogon.android (no picker)
adb -s <serial> logcat -b crash -d | grep -c FATAL                  # must be 0
```

---

## 2. REAL PICKER routine (`pick_real.sh`)

For exercising the genuine system pickers. Located at `ops/testing/`.

### Seed media onto the device (once)
```
ops/testing/seed_media.sh <serial>
```
Pushes the 4 sample files to `/sdcard/{Pictures,Movies,DCIM,Download}` and registers them with
MediaStore (so Photo Picker shows them). Idempotent.

### Drive the picker
With the **seam disabled** (`setprop debug.testlogon.testhooks 0`), tap the in-app picker button so
the real picker is foreground, then:
```
ops/testing/pick_real.sh <serial> <photo|video|document> [filename]
```
- `photo` / `video` → Android Photo Picker (PickVisualMedia / PickMultipleVisualMedia). Matches the
  first cell by child `content-desc="Photo taken on…"` / `"Video taken on…"`, handles the
  multi-select **"Add"/"Done"** confirm button.
- `document` → DocumentsUI (OpenDocument / OpenMultipleDocuments / GetContent on this device).
  Matches the file row by `android:id/title` filename text.
- Default filename = the seeded `testlogon_seed.*`.
- Detection keys off the **foreground package**, OEM-independent. On the Samsung A15 the Google
  modules service these intents (no Samsung-only path needed). Exit codes 0/1/2/3/4.

`TakePicture` (camera, the 9 KYC sites) is **not** drivable by pick_real — use the seam `kind camera`.

---

## Which flow uses which contract (for picking the right kind / mode)

| App flow | Contract | seam kind | pick_real mode |
|----------|----------|-----------|----------------|
| Feed compose add-photos | PickMultipleVisualMedia | `image` or `multi_image` | photo |
| Feed compose add-video | PickVisualMedia(VideoOnly) | `video` | video |
| Messaging "Attach photo or video" (gallery) | PickMultipleVisualMedia | `image` / `video` / `multi_av` | photo / video |
| Newsfeed comment image | PickVisualMedia | `image` | photo |
| Support ticket attach file | GetContent | `pdf` | document |
| My Videos upload | PickVisualMedia(VideoOnly) | `video` | video |
| Files / message file-share | OpenDocument / OpenMultipleDocuments | `pdf` / `multi_image` | document |
| Profile/EditPost/lottery cover image | PickVisualMedia | `image` | photo |
| KYC docs / proof-of-funds (camera) | TakePicture | `camera` | (seam only) |

Note: some in-app buttons open an **in-app VFS browser** (e.g. support "Attach from Files",
`thread_attach_media` GIF sheet) rather than an ActivityResult picker — those do NOT route through
either tool. Use the ActivityResult-backed button (e.g. support `support_attach_file` = GetContent).

---

## Release safety (proven)

The seam is triple-inert and provably excluded from release:
1. Release `TestHooks` returns `null` → no intercepting owner → genuine platform picker.
2. Debug gate requires `BuildConfig.DEBUG`.
3. AND requires the runtime sysprop `debug.testlogon.testhooks == "1"`.

Verified on the built **release APK** (`app/build/outputs/apk/release/app-release-unsigned.apk`):
- Manifest contains **no** `testmedia` provider and **no** `com.testlogon.test.PICK` receiver.
- Assets contain **no** `test_media/sample.*`.
- Dex contains **only** `TestHooks` (the no-op shim); none of `TestPickRegistry`,
  `TestMediaProvider`, `TestSeamGate`, `TestPickArmReceiver`, `ArmState`, `Arm`, `PickKind`.
The debug APK (control) contains all of them. (Release build type has no `signingConfig` → the
release APK is unsigned; debug-source-only structure is what guarantees exclusion.)
