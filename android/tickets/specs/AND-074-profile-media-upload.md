---
id: AND-074
title: Profile media upload
milestone: M2
epic: E10
priority: P2
size: M
status: draft
depends_on: [AND-072, AND-117]
blocks: []
---

# AND-074 — Profile media upload

## 1. Overview & Goal

Enable an authenticated user to replace their profile **avatar** and **cover** images from within the Edit Profile experience. The implementation follows the backend's three-step object-storage protocol: the client requests a short-lived upload URL (**presign**), uploads the raw image bytes directly to object storage (**PUT**), then notifies the API that the upload completed (**confirm**). Before upload the user crops/squares the chosen image locally.

Success means: a user picks (or captures) an image, crops it, the bytes upload via the presigned URL, the confirm call attaches the new media key to their profile, and the new avatar renders immediately in-app and after a cold reload — without ever routing the image bytes through the FastAPI app server.

Goal acceptance (from backlog): *New avatar uploads and displays (tested).* This spec treats avatar as the primary path and cover as the secondary path that reuses the same machinery via a `MediaKind` parameter.

## 2. Context & References

- Lives inside the Edit Profile feature (`:feature-profile`) shipped by **AND-072 (Edit profile basics)**. AND-074 adds the media rows (avatar + cover) to that screen and the upload pipeline behind them. AND-072 owns the surrounding form, the `ProfileRepository.updateProfile` write path, and persistence/reload verification.
- **AND-117 (Stale/reconnect UX hooks)** provides the shared "showing cached / reconnecting" affordance and backend-health signal this ticket reuses to disable the upload control and surface a clear message when the dev host is unreachable, rather than failing silently.
- Module layering: `:app -> :feature-profile -> :core-network, :core-model, :core-data, :core-ui, :core-testing`.
- Stack: Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6, DataStore, Coil. minSdk 24, compile/target 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- Backend: FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). Cookie-based auth with `ui_csrf` echoed as `X-CSRF-Token`; persistent cookie jar; single `POST /ui/session/refresh` retry on 401. OpenAPI at `/openapi.json` is the authoritative contract; exact field names below MUST be reconciled against it during AND-074 implementation (see §13).
- Namespace / applicationId base: `com.testlogon.android`.

## 3. Functional Requirements

FR-1. From the Edit Profile screen, the avatar row exposes a tappable control ("Change photo") that opens an image source chooser: **Photo library** (Photo Picker) and **Camera**.
FR-2. The cover row exposes the same control, parameterized by `MediaKind.COVER`. Avatar crops to a 1:1 square; cover crops to a 16:9 rectangle.
FR-3. After selection, the user is presented with an interactive **crop** UI (pan + zoom) constrained to the target aspect ratio. Confirming the crop produces the final bytes to upload.
FR-4. The cropped image is downscaled and re-encoded to JPEG before upload: avatar max edge 1024 px, cover max edge 1920 px, quality 0.85. Result MUST be ≤ 5 MB; if larger after encoding, quality steps down (0.85 → 0.7 → 0.6) before failing.
FR-5. Upload runs as presign → PUT → confirm. Progress (indeterminate, then determinate during PUT) is shown; the control is disabled during upload.
FR-6. On confirm success the new image displays immediately (the in-memory profile state updates) and survives a cold reload (the server-side profile now references the new media key).
FR-7. The user may cancel before the PUT begins. Cancellation after PUT begins aborts the request; no confirm is sent, and the previous avatar remains.
FR-8. Permissions: Photo Picker requires no storage permission on any supported API level. Camera capture requires `CAMERA` runtime permission with a rationale; denial degrades gracefully to library-only.
FR-9. When the backend health signal (AND-117) reports the host as down/stale, the upload control is disabled with an inline message; no presign request is attempted.
FR-10. Both EXIF orientation correction and stripping of EXIF GPS/location tags happen client-side before upload (see §8).

## 4. Technical Design

### Module placement
All new code lands in `:feature-profile` except the reusable HTTP upload helper, which lives in `:core-network` so other media tickets can reuse it.

### Domain & state types (`:core-model`)
```kotlin
enum class MediaKind { AVATAR, COVER }

data class UploadTarget(
    val kind: MediaKind,
    val uploadUrl: String,      // presigned PUT URL (absolute, object-store host)
    val mediaKey: String,       // opaque storage key to echo back on confirm
    val requiredHeaders: Map<String, String>, // headers presign demands on PUT
    val expiresAtEpochMs: Long,
)

sealed interface MediaUploadState {
    data object Idle : MediaUploadState
    data object Preparing : MediaUploadState            // presign in flight
    data class Uploading(val fraction: Float) : MediaUploadState
    data object Confirming : MediaUploadState
    data class Success(val mediaKind: MediaKind, val url: String) : MediaUploadState
    data class Error(val cause: AppError, val retryable: Boolean) : MediaUploadState
}
```

### Image pipeline (`:feature-profile`, `image/`)
```kotlin
interface ImageProcessor {
    /** Decode -> apply EXIF rotation -> crop to rect -> scale to maxEdge -> encode JPEG -> strip GPS. */
    suspend fun process(
        source: Uri,
        cropRect: CropRect,        // normalized 0..1 in source space
        maxEdgePx: Int,
        quality: Int,
    ): ProcessedImage   // file:// Uri in app cache + contentLength + "image/jpeg"
}

data class ProcessedImage(val uri: Uri, val contentLength: Long, val contentType: String)
```
Decoding uses `BitmapFactory` with `inSampleSize` computed from `BoundingBox` to avoid OOM on large gallery images; final bytes are written to `context.cacheDir/profile-uploads/*.jpg` and deleted after confirm or on cancel.

### Crop UI
A Compose crop screen `ProfileCropScreen(source: Uri, kind: MediaKind, onConfirm: (CropRect) -> Unit, onCancel: () -> Unit)` using a gesture-driven overlay (`Modifier.pointerInput` transform). No third-party crop library is added; the mask is a fixed-aspect window and the user pans/zooms the image beneath it. `CropRect` is the normalized intersection.

### Network helper (`:core-network`)
```kotlin
interface RawUploader {
    suspend fun put(
        url: String,
        body: ProcessedImage,
        headers: Map<String, String>,
        onProgress: (sent: Long, total: Long) -> Unit,
    ): ApiResult<Unit>
}
```
`RawUploaderImpl` uses a **separate OkHttpClient** (no auth/CSRF interceptors, no cookie jar — the presigned URL is self-authenticating) built via the Hilt-provided base client `.newBuilder()` with `writeTimeout = 60s` and `callTimeout = 90s`. The request body is a streaming `RequestBody` over the cached file that emits progress via a `CountingSink`. The presign and confirm calls use the **normal** authenticated Retrofit client (cookies + `X-CSRF-Token`).

### Repository (`:core-data`)
```kotlin
interface ProfileMediaRepository {
    suspend fun presign(kind: MediaKind, contentType: String, sizeBytes: Long): ApiResult<UploadTarget>
    suspend fun confirm(kind: MediaKind, mediaKey: String): ApiResult<MediaConfirmResult>
}

data class MediaConfirmResult(val mediaKind: MediaKind, val url: String, val version: Long)
```
The repository orchestration (presign → PUT → confirm) lives in the ViewModel so PUT progress and cancellation are observable.

### ViewModel
```kotlin
@HiltViewModel
class ProfileMediaViewModel @Inject constructor(
    private val mediaRepo: ProfileMediaRepository,
    private val uploader: RawUploader,
    private val imageProcessor: ImageProcessor,
    private val health: BackendHealthSignal,   // from AND-117
) : ViewModel() {
    val uploadState: StateFlow<MediaUploadState>
    fun startUpload(kind: MediaKind, source: Uri, crop: CropRect)
    fun cancel()
}
```
`startUpload` runs in a `viewModelScope` job retained for cancellation: process → (gate on `health`) → presign → put(onProgress) → confirm → emit `Success`, then push the new `url` into the shared profile state owned by AND-072 so the avatar recomposes. The job is cancelled by `cancel()`; the in-flight OkHttp call is cancelled via the coroutine cancellation bridge.

## 5. API Contract

All three endpoints below are on the authenticated UI surface and require the session cookie + `X-CSRF-Token` header. Paths/fields are the working contract and MUST be verified against `/openapi.json` (§13). The PUT goes to the object store, not FastAPI.

### Presign
`POST /ui/profile/media/presign`
Request:
```json
{ "kind": "avatar", "content_type": "image/jpeg", "size_bytes": 184320 }
```
Response `200`:
```json
{
  "upload_url": "https://<bucket>.s3.amazonaws.com/...&X-Amz-Signature=...",
  "media_key": "profile/u_123/avatar/8f1c...jpg",
  "required_headers": { "Content-Type": "image/jpeg" },
  "expires_in": 300
}
```

### Direct upload (object store)
`PUT {upload_url}` — body is the raw JPEG bytes. Headers: exactly the `required_headers` from presign (typically `Content-Type: image/jpeg`). **No** session cookie, **no** `X-CSRF-Token`. Success: `200`/`204` with empty body. The client must not append query params or extra headers, or the signature breaks.

### Confirm
`POST /ui/profile/media/confirm`
Request:
```json
{ "kind": "avatar", "media_key": "profile/u_123/avatar/8f1c...jpg" }
```
Response `200`:
```json
{ "kind": "avatar", "url": "http://18.222.237.167:8000/media/profile/u_123/avatar/8f1c...jpg", "version": 7 }
```

### Read-back
The new URL is also reflected by `GET /ui/me` (avatar/cover fields), used to verify persistence on cold reload.

### Error envelope
FastAPI `detail` may be `string`, `[{ "msg": "...", "loc": [...] }]`, or `{ "code": "...", ... }`. The shared mapper (`:core-network`) normalizes all three into `AppError`. Notable cases: `413` (size rejected at presign), `415` (unsupported content type), `409`/`410` (media_key expired/already confirmed), `401` (session expired → refresh-once-and-retry on presign/confirm; never on the PUT).

## 6. Data & State Management

- **Ephemeral upload state** lives only in `ProfileMediaViewModel` as `StateFlow<MediaUploadState>`; it is not persisted across process death (an interrupted upload restarts from picking, by design — presigned URLs are short-lived).
- **Profile state** (the displayed avatar/cover URLs) is owned by AND-072's `ProfileViewModel`/`ProfileRepository`. On confirm success, AND-074 calls the AND-072 mutation (`ProfileRepository.applyMediaUrl(kind, url, version)`) which updates the Room-backed profile cache and emits to the profile `StateFlow`. Coil then loads the new URL.
- **Cache invalidation:** the confirm response `url` is treated as a new key (the `media_key` is content-addressed, so the URL changes). No manual Coil cache busting is required; if the backend reuses a stable URL, append `?v={version}` as the Coil model key.
- **Temp files:** processed JPEGs in `cacheDir/profile-uploads/` are deleted in a `finally` block after confirm/cancel/error; a startup sweep clears any orphans older than 24h.
- **No new Room entities** are introduced by this ticket; it writes through AND-072's existing profile entity (adds/uses `avatarUrl`, `coverUrl`, `mediaVersion` columns if not already present — coordinate with AND-072).

## 7. Error Handling & Resilience

- **Timeouts:** presign/confirm use the app default ~20s; PUT uses 60s write / 90s call timeout for large uploads on the flaky dev host.
- **Retry policy:** presign (idempotent GET-like POST that returns a fresh URL) and the read-back may use bounded backoff. **PUT and confirm are NOT auto-retried** to avoid duplicate/partial objects; the user retries manually via the `Error(retryable=true)` state. A failed PUT discards the `media_key` and the next attempt re-presigns.
- **401 handling:** presign/confirm participate in the standard refresh-once-then-retry. The PUT never carries auth, so 401/403 from the object store means the URL expired → surface "Upload link expired, try again" and re-presign on retry.
- **Expired presign:** if PUT starts after `expiresAtEpochMs`, skip the PUT and re-presign first.
- **Host down (AND-117):** if `BackendHealthSignal` is unhealthy at `startUpload`, short-circuit to `Error(NetworkUnavailable, retryable=true)` and show the shared stale/reconnect affordance; do not attempt presign.
- **OOM safety:** decode with subsampling; if processing still fails, emit `Error` with "Image too large to process" and keep the prior avatar.
- **Partial upload / cancel:** cancelling mid-PUT aborts the OkHttp call, sends no confirm, leaves the prior media intact (object-store object is orphaned and reaped server-side).

## 8. Security & Privacy

- **Transport:** PUT may target HTTPS object storage even though the API host is plaintext. The network-security config must continue to allow cleartext only for the dev API host; the presigned host should use TLS. Do not relax cleartext globally.
- **Credentials:** the presigned URL embeds a short-lived signature; never log it. The PUT client carries no cookies — confirm via OkHttp that no cookie jar/auth interceptor is attached to `RawUploaderImpl`.
- **Location privacy:** strip EXIF GPS and other identifying tags during re-encode (re-encoding to a fresh JPEG drops them; explicitly verify no `ExifInterface` copy occurs). Preserve only orientation correction (applied by rotating pixels, not by writing an orientation tag).
- **CSRF:** presign/confirm send `X-CSRF-Token` from the `ui_csrf` cookie per the shared interceptor.
- **Content validation:** restrict picker to images; enforce `image/jpeg` after re-encode and the ≤5 MB cap before presign so server rejections are rare.
- **PII in logs:** never log image bytes, file paths with usernames, or full presigned URLs (log host + key prefix only).

## 9. Accessibility & i18n

- The "Change photo" control has a `contentDescription` ("Change profile photo" / "Change cover photo") and a ≥48 dp touch target.
- Crop screen controls (rotate, confirm, cancel) are buttons with labels, reachable by TalkBack and keyboard; the crop gesture surface exposes an accessibility action "Reset crop".
- Upload progress announces via `liveRegion` (e.g., "Uploading photo, 60 percent"); success/error announce as polite/assertive respectively.
- All user-facing strings live in `strings.xml` (no hardcoded literals): chooser labels, progress, error messages, permission rationale. Support RTL mirroring for the chooser and crop chrome.
- Respect large font scaling; crop overlay sizing is density-independent (dp), not pixel-hardcoded.

## 10. Telemetry & Logging

- Structured events (no PII): `profile_media_upload_started{kind}`, `_presign_ok{kind,ms}`, `_put_progress` (sampled), `_put_ok{kind,bytes,ms}`, `_confirm_ok{kind,version,ms}`, `_failed{kind,stage,error_code}`, `_cancelled{kind,stage}`.
- `stage` ∈ `{process, presign, put, confirm}` to localize failures on the flaky host.
- Debug-only logs gate behind `BuildConfig.DEBUG`; redact URLs to `host + keyPrefix(12)`.
- Surface counts feed a basic upload-success-rate metric; no image content or dimensions beyond byte size are recorded.

## 11. Testing Strategy

**Unit (`:core-testing`, JUnit + coroutines test):**
- `ImageProcessor`: EXIF orientation 6/8 inputs rotate correctly; output ≤ maxEdge; quality step-down reduces size under 5 MB; output is JPEG with no GPS tags.
- `RawUploaderImpl`: progress callbacks sum to total; MockWebServer 200/204 → `Success`; 403 → `Error`; cancellation aborts the call and no confirm follows.
- Error mapper: 413/415/409/410 and all three `detail` shapes map to expected `AppError`.
- ViewModel state machine: Idle→Preparing→Uploading→Confirming→Success; host-down short-circuits to Error without a presign call (verify via fake repo).

**Instrumented / Compose UI:**
- Crop screen renders the correct aspect mask per `MediaKind`; confirm emits a `CropRect`.
- Control disabled and inline message shown when health signal is unhealthy.

**Acceptance (end-to-end, satisfies backlog "tested"):**
- Espresso/Compose test stubs presign + object-store PUT (MockWebServer) + confirm, drives pick→crop→upload, asserts the avatar `AsyncImage` model updates to the confirmed URL and that a simulated cold reload (`GET /ui/me` returning the new URL) shows the same image. This is the **canonical avatar-uploads-and-displays** test.

## 12. Dependencies & Sequencing

- **Depends on AND-072** (Edit profile basics): the host screen, profile state holder, and the `applyMediaUrl` mutation + persistence/reload verification. AND-074 cannot merge before AND-072's profile state and Room columns exist.
- **Depends on AND-117** (Stale/reconnect UX hooks): `BackendHealthSignal` and the shared stale affordance gate the upload control.
- Implicitly relies on the established `:core-network` auth/CSRF/refresh interceptors and `ApiResult`/error mapper (delivered by earlier networking tickets in the dependency chain of AND-072).
- Sequencing: land `ImageProcessor` + crop UI (no backend) → `RawUploader` in `:core-network` (MockWebServer-tested) → repository presign/confirm → ViewModel orchestration → wire into AND-072 screen → e2e acceptance test.

## 13. Risks & Open Questions

- **Contract drift:** exact presign/confirm paths and field names (`kind` vs `media_type`, `upload_url` vs `url`, header echoing) are assumed; reconcile with `/openapi.json` and the web reference (`frontend/src/api/endpoints/*`) before coding. *Owner: implementer at kickoff.*
- **Presigned host TLS & CORS:** whether the object store is S3 (HTTPS) or a backend-proxied path on the plaintext dev host affects the network-security config and whether `RawUploader` can skip cookies. *Open.*
- **Crop without a library:** hand-rolled gesture crop adds UI risk; fallback is `androidx`/community crop lib if effort exceeds budget (size estimate assumes hand-rolled M).
- **Cover aspect & display:** confirm the cover render aspect (16:9 assumed) with AND-072's profile layout.
- **Duplicate confirm idempotency:** behavior when the same `media_key` is confirmed twice (409 vs 200) determines retry UX; verify server semantics.

## 14. Acceptance Criteria

AC-1. From Edit Profile, a user can pick from library or camera, crop to the avatar's 1:1 mask, and upload; the new avatar displays without leaving the screen. **(backlog: "New avatar uploads and displays")**
AC-2. After a cold app restart, the uploaded avatar still displays (served via the confirmed `GET /ui/me` URL). **(automated)**
AC-3. The upload uses presign → PUT-to-storage → confirm; image bytes never traverse the FastAPI app server (verified by the MockWebServer route assertions). **(automated)**
AC-4. Cover upload works via the same flow with a 16:9 crop. **(automated UI)**
AC-5. Images are re-encoded to JPEG ≤ 5 MB, EXIF-orientation-corrected, and stripped of GPS tags before upload. **(unit-tested)**
AC-6. When the backend health signal is unhealthy, the upload control is disabled with an inline message and no presign call is made. **(unit + UI test)**
AC-7. PUT and confirm are not auto-retried; failures surface a manual-retry state that re-presigns, and cancellation leaves the prior media intact. **(unit-tested)**
AC-8. Presigned URLs are never logged; the PUT request carries no session cookie or CSRF header. **(verified by test/inspection)**
AC-9. All user-facing strings are in `strings.xml`; controls expose content descriptions and progress is announced to TalkBack. **(lint + a11y check)**

## 15. Definition of Done

- All Acceptance Criteria met; the canonical avatar upload-and-display e2e test passes in CI.
- New code in `:feature-profile` and `:core-network` under `com.testlogon.android`; module layering respected (no `:feature-*` → `:feature-*` deps).
- Unit + instrumented tests added per §11; coverage for `ImageProcessor`, `RawUploaderImpl`, error mapping, and the ViewModel state machine.
- Presign/confirm field names reconciled against `/openapi.json`; any deviations from §5 documented in the PR.
- No lint regressions; no hardcoded strings; ktlint/detekt clean.
- Temp upload files are cleaned up (finally + startup sweep) — verified no leaks in instrumented test.
- Telemetry events emit with correct `stage`/`kind` and no PII; debug logs gated by `BuildConfig.DEBUG`.
- PR description notes resolved/outstanding §13 items; reviewer sign-off from the AND-072 owner on the shared profile-state integration.
