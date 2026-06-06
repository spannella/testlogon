---
id: AND-074
title: Profile media upload
milestone: M2
epic: E10
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-072, AND-117]
blocks: []
---

# AND-074 — Profile media upload

## 1. Overview & Goal

Enable an authenticated user to replace their profile **avatar** (`kind=profile`) and **cover** (`kind=cover`) images from within the Edit Profile experience.

> **CORRECTED (review 2026-06-06):** An earlier draft of this spec described a three-step presign → direct-PUT-to-object-storage → confirm protocol. **That contract does not exist on the backend.** The authoritative OpenAPI spec exposes a **single endpoint** — `POST /ui/profile/photos/{kind}/upload` — that accepts a `multipart/form-data` body with one binary field named `file`. There is **no** `/ui/profile/media/presign` or `/ui/profile/media/confirm` path, no presigned object-store URL, and no `media_key`/`confirm` step. The image bytes **do** transit the FastAPI app server (that is how the web reference client uploads them). The spec below has been rewritten to the real one-call multipart contract; the presign/PUT/confirm design is preserved only as historical context where noted.

Success means: a user picks (or captures) an image, optionally crops it, the JPEG bytes are POSTed as multipart to `/ui/profile/photos/{kind}/upload`, the response returns the updated `Profile` plus the new public `url`, and the new avatar renders immediately in-app and after a cold reload (the server-side profile now carries the new `profile_photo_url`/`cover_photo_url`).

Goal acceptance (from backlog): *New avatar uploads and displays (tested).* This spec treats avatar (`kind=profile`) as the primary path and cover (`kind=cover`) as the secondary path that reuses the same machinery via a `MediaKind` parameter.

## 2. Context & References

- Lives inside the Edit Profile feature (`:feature-profile`) shipped by **AND-072 (Edit profile basics)**. AND-074 adds the media rows (avatar + cover) to that screen and the upload pipeline behind them. AND-072 owns the surrounding form, the `ProfileRepository.updateProfile` write path, and persistence/reload verification.
- **AND-117 (Stale/reconnect UX hooks)** provides the shared "showing cached / reconnecting" affordance and backend-health signal this ticket reuses to disable the upload control and surface a clear message when the dev host is unreachable, rather than failing silently.
- Module layering: `:app -> :feature-profile -> :core-network, :core-model, :core-data, :core-ui, :core-testing`.
- Stack: Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6, DataStore, Coil. minSdk 24, compile/target 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- Backend: FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). Cookie-based auth with `ui_csrf` echoed as `X-CSRF-Token`; persistent cookie jar; single `POST /ui/session/refresh` retry on 401. **Verified** against the frontend reference (`src/api/client.ts`: `getCookie("ui_csrf")` → `X-CSRF-Token`; `credentials: "include"`; `refreshSession()` calling `POST /ui/session/refresh` once on 401) and the OpenAPI index (`POST /ui/session/refresh`). The multipart upload travels through this **same authenticated client** (web's `api.upload` delegates to `api()`), so it carries cookies + `X-CSRF-Token` and participates in the 401 refresh-once retry. OpenAPI at `/openapi.json` is the authoritative contract; the upload endpoint and field names below were reconciled against it during this review (see §16).
- Namespace / applicationId base: `com.testlogon.android`.

## 3. Functional Requirements

FR-1. From the Edit Profile screen, the avatar row exposes a tappable control ("Change photo") that opens an image source chooser: **Photo library** (Photo Picker) and **Camera**.
FR-2. The cover row exposes the same control, parameterized by `MediaKind.COVER`. Avatar crops to a 1:1 square; cover crops to a 16:9 rectangle.
FR-3. After selection, the user is presented with an interactive **crop** UI (pan + zoom) constrained to the target aspect ratio. Confirming the crop produces the final bytes to upload.
FR-4. The cropped image is downscaled and re-encoded to JPEG before upload: avatar max edge 1024 px, cover max edge 1920 px, quality 0.85. Result MUST be ≤ 5 MB; if larger after encoding, quality steps down (0.85 → 0.7 → 0.6) before failing.
FR-5. Upload is a **single authenticated multipart POST** to `POST /ui/profile/photos/{kind}/upload` (field `file`). Progress (indeterminate, then determinate as the multipart body streams) is shown; the control is disabled during upload. *(Corrected: was "presign → PUT → confirm"; no such multi-step flow exists — see §16.)*
FR-6. On a `200` response the new image displays immediately (the response body carries the updated `Profile` and the new `url`; the in-memory profile state updates) and survives a cold reload (the server-side profile now carries the new `profile_photo_url`/`cover_photo_url`).
FR-7. The user may cancel before the POST begins. Cancellation after the POST begins aborts the in-flight OkHttp call (coroutine cancellation), no upload completes, and the previous avatar remains.
FR-8. Permissions: Photo Picker requires no storage permission on any supported API level. Camera capture requires `CAMERA` runtime permission with a rationale; denial degrades gracefully to library-only.
FR-9. When the backend health signal (AND-117) reports the host as down/stale, the upload control is disabled with an inline message; no upload request is attempted.
FR-10. Both EXIF orientation correction and stripping of EXIF GPS/location tags happen client-side before upload (see §8).

## 4. Technical Design

### Module placement
All new code lands in `:feature-profile` except the reusable HTTP upload helper, which lives in `:core-network` so other media tickets can reuse it.

### Domain & state types (`:core-model`)
> **CORRECTED:** The wire `kind` path segment is **`profile`** (avatar) or **`cover`** — verified from `src/api/endpoints/profile.ts: uploadProfilePhoto(kind: "profile" | "cover", ...)`. Map the enum accordingly: `AVATAR -> "profile"`, `COVER -> "cover"`. The previous `UploadTarget` (presigned URL / `mediaKey` / `requiredHeaders` / `expiresAtEpochMs`) is removed — there is no presign step.
```kotlin
enum class MediaKind(val wire: String) { AVATAR("profile"), COVER("cover") }

sealed interface MediaUploadState {
    data object Idle : MediaUploadState
    data object Preparing : MediaUploadState            // local image processing
    data class Uploading(val fraction: Float) : MediaUploadState  // multipart body streaming
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
Decoding uses `BitmapFactory` with `inSampleSize` computed from `BoundingBox` to avoid OOM on large gallery images; final bytes are written to `context.cacheDir/profile-uploads/*.jpg` and deleted after the upload completes or on cancel.

### Crop UI
A Compose crop screen `ProfileCropScreen(source: Uri, kind: MediaKind, onConfirm: (CropRect) -> Unit, onCancel: () -> Unit)` using a gesture-driven overlay (`Modifier.pointerInput` transform). No third-party crop library is added; the mask is a fixed-aspect window and the user pans/zooms the image beneath it. `CropRect` is the normalized intersection.

### Network helper (`:core-network`)
> **CORRECTED:** There is no presigned object-store PUT. The reusable helper instead streams a **multipart/form-data** body to the FastAPI host using the **normal authenticated client** (cookies + `X-CSRF-Token`), since the upload goes through the app server (verified: web `api.upload` delegates to the authenticated `api()`).
```kotlin
interface ProfilePhotoUploader {
    /** Multipart POST of the processed JPEG as form field "file" to /ui/profile/photos/{kind}/upload. */
    suspend fun upload(
        kind: MediaKind,
        body: ProcessedImage,
        onProgress: (sent: Long, total: Long) -> Unit,
    ): ApiResult<MediaUploadResult>
}

data class MediaUploadResult(val mediaKind: MediaKind, val url: String, val profile: ProfileDto)
```
`ProfilePhotoUploaderImpl` uses the Hilt-provided **authenticated** OkHttp/Retrofit client (cookie jar + `X-CSRF-Token` + 401 refresh-once) so it can reach the protected endpoint. It builds a `MultipartBody.Part` named `file` over the cached JPEG (`media-type image/jpeg`, `filename` e.g. `avatar.jpg`); the part's `RequestBody` is wrapped with a `CountingSink` to emit upload progress. Use a longer `writeTimeout = 60s` / `callTimeout = 90s` on this call (via `.newBuilder()` on the base client) for large uploads on the flaky dev host; do **not** strip the auth interceptors or cookie jar. The Retrofit method declares `@Multipart` with `@Part file: MultipartBody.Part` and `@Path("kind") kind: String` against `POST ui/profile/photos/{kind}/upload`.

### Repository (`:core-data`)
> **CORRECTED:** Single call, not presign+confirm. Path `kind` is the `MediaKind.wire` value (`profile`/`cover`).
```kotlin
interface ProfileMediaRepository {
    suspend fun uploadPhoto(
        kind: MediaKind,
        body: ProcessedImage,
        onProgress: (sent: Long, total: Long) -> Unit,
    ): ApiResult<MediaUploadResult>
}
```
The 200 response body shape is `{ "profile": Profile, "url": string }` (verified: `src/api/endpoints/profile.ts` declares `api.upload<{ profile: Profile; url: string }>`). There is **no** `version` field and **no** `media_key`. The repository simply forwards to `ProfilePhotoUploader`; orchestration (process → gate on health → upload) lives in the ViewModel so streaming progress and cancellation are observable.

### ViewModel
```kotlin
@HiltViewModel
class ProfileMediaViewModel @Inject constructor(
    private val mediaRepo: ProfileMediaRepository,
    private val imageProcessor: ImageProcessor,
    private val health: BackendHealthSignal,   // from AND-117
) : ViewModel() {
    val uploadState: StateFlow<MediaUploadState>
    fun startUpload(kind: MediaKind, source: Uri, crop: CropRect)
    fun cancel()
}
```
`startUpload` runs in a `viewModelScope` job retained for cancellation: process → (gate on `health`) → `mediaRepo.uploadPhoto(kind, processed, onProgress)` → emit `Success`, then push the new `url` into the shared profile state owned by AND-072 so the avatar recomposes. *(Corrected: removed the presign/put/confirm staging — it is a single upload call.)* The job is cancelled by `cancel()`; the in-flight OkHttp call is cancelled via the coroutine cancellation bridge.

## 5. API Contract

> **CORRECTED (review 2026-06-06):** This section previously described three endpoints (`/ui/profile/media/presign`, a direct object-store `PUT`, and `/ui/profile/media/confirm`). **None of those exist.** The real contract is a single authenticated multipart upload, verified against OpenAPI (`POST /ui/profile/photos/{kind}/upload`, body schema `Body_ui_upload_profile_photo_ui_profile_photos__kind__upload_post`) and the web reference (`src/api/endpoints/profile.ts: uploadProfilePhoto`).

### Upload (single call)
`POST /ui/profile/photos/{kind}/upload`
- `kind` is a **path parameter**: `profile` (avatar) or `cover`. *(Verified — web client passes `"profile" | "cover"`; backend declares `kind` as a path `string`.)*
- Auth: session cookie + `X-CSRF-Token` (the upload uses the normal authenticated client; bytes transit FastAPI). Participates in the standard 401 refresh-once-then-retry.
- Body: `multipart/form-data` with **one** part named **`file`** (binary). *(Verified — request schema has a single required `file: string($binary)`; web appends `formData.append("file", file)`.)* Do **not** set `Content-Type` manually on the request envelope; let OkHttp emit the multipart boundary (the per-part `Content-Type: image/jpeg` is set on the `MultipartBody.Part`).
- Optional query param `user_sub` and headers `X-SESSION-ID`/`X-IMPERSONATION-TOKEN` exist (admin/impersonation use); the normal mobile client omits them.

Response `200` (`application/json`):
```json
{
  "profile": { "...": "full updated Profile object (profile_photo_url / cover_photo_url etc.)" },
  "url": "http://18.222.237.167:8000/<served-media-path>"
}
```
> **Note:** the OpenAPI 200 schema is empty (`{}`, untyped). The concrete `{ profile, url }` shape comes from the web reference (`api.upload<{ profile: Profile; url: string }>`). There is **no** `version` field and **no** `media_key`. Treat the `{ profile, url }` shape as the working contract but tolerate missing fields defensively (Moshi nullable). Prefer `profile.profile_photo_url` / `profile.cover_photo_url` from the returned `profile` as the source of truth; `url` is the convenience copy of the just-uploaded image.

### Read-back
The new URL is reflected by `GET /ui/me` and `GET /ui/profile` (both verified present in the OpenAPI index). On the `Profile` object the relevant fields are **`profile_photo_url`** and **`cover_photo_url`** *(verified: `src/api/types.ts: interface Profile`)* — not `avatarUrl`/`coverUrl`. Used to verify persistence on cold reload.

### Error envelope
FastAPI returns `422 HTTPValidationError` for a malformed/missing `file` part (the only documented error response: `detail: [{ "msg", "loc", "type" }]`). The shared mapper (`:core-network`) normalizes the `detail` (which may be `string`, the validation array, or `{ "code": ... }`) into `AppError`. Other status codes (`413` payload-too-large, `415` unsupported media type, `401` session expired) are **not declared in OpenAPI for this endpoint** and are treated as unverified-but-defensively-handled assumptions (see §16): `401` → refresh-once-and-retry via the standard interceptor; `413`/`415` → non-retryable `Error` with a clear message; surface anything else as a generic retryable upload error.

## 6. Data & State Management

- **Ephemeral upload state** lives only in `ProfileMediaViewModel` as `StateFlow<MediaUploadState>`; it is not persisted across process death (an interrupted upload restarts from picking, by design).
- **Profile state** (the displayed avatar/cover URLs) is owned by AND-072's `ProfileViewModel`/`ProfileRepository`. On a `200` upload response, AND-074 calls the AND-072 mutation (`ProfileRepository.applyMediaUrl(kind, url)` — *no `version` arg; the upload response has no version field*) which updates the Room-backed profile cache and emits to the profile `StateFlow`. Coil then loads the new URL. Prefer the `profile_photo_url`/`cover_photo_url` from the returned `profile` object; fall back to the top-level `url`.
- **Cache invalidation:** rely on the server returning a changed `url`/`*_photo_url` after upload. **Unverified assumption:** whether the backend returns a content-addressed (changing) URL or a stable one is not documented (see §16). If the URL is stable across re-uploads, append a cache-busting key (e.g. `?t={uploadEpochMs}`) as the Coil model key, since there is no `version` field to use.
- **Temp files:** processed JPEGs in `cacheDir/profile-uploads/` are deleted in a `finally` block after success/cancel/error; a startup sweep clears any orphans older than 24h.
- **No new Room entities** are introduced by this ticket; it writes through AND-072's existing profile entity (adds/uses `profilePhotoUrl`, `coverPhotoUrl` columns mapping the API's `profile_photo_url`/`cover_photo_url` if not already present — coordinate with AND-072). No `mediaVersion` column is needed (the API returns no version).

## 7. Error Handling & Resilience

- **Timeouts:** the read-back (`GET /ui/me`) uses the app default ~20s; the multipart upload POST uses 60s write / 90s call timeout for large bodies on the flaky dev host.
- **Retry policy:** the read-back may use bounded backoff. **The upload POST is NOT auto-retried** to avoid duplicate writes / wasted bandwidth; the user retries manually via the `Error(retryable=true)` state.
- **401 handling:** the upload POST participates in the standard refresh-once-then-retry (it uses the authenticated client). *(Corrected: the previous "PUT carries no auth / object-store 401 means URL expired" reasoning is moot — there is no presigned URL.)*
- **Host down (AND-117):** if `BackendHealthSignal` is unhealthy at `startUpload`, short-circuit to `Error(NetworkUnavailable, retryable=true)` and show the shared stale/reconnect affordance; do not attempt the upload.
- **OOM safety:** decode with subsampling; if processing still fails, emit `Error` with "Image too large to process" and keep the prior avatar.
- **Partial upload / cancel:** cancelling mid-upload aborts the OkHttp call (coroutine cancellation); the multipart POST never completes, so the server does not commit a new photo and the prior media stays intact.

## 8. Security & Privacy

- **Transport:** the upload POST targets the **same plaintext dev API host** as every other call (there is no separate object-store host). The network-security config must continue to allow cleartext only for the dev API host; do not relax cleartext globally. *(Corrected: the prior "PUT targets HTTPS object storage" claim is removed — bytes go to FastAPI over the existing channel.)*
- **Credentials:** the upload **does** carry the session cookie + `X-CSRF-Token` (it must, to reach the protected endpoint). Never log the cookie or CSRF value. *(Corrected: the prior "PUT client carries no cookies / no auth interceptor" requirement is wrong and must NOT be implemented — stripping auth would 401 the upload.)*
- **Location privacy:** strip EXIF GPS and other identifying tags during re-encode (re-encoding to a fresh JPEG drops them; explicitly verify no `ExifInterface` copy occurs). Preserve only orientation correction (applied by rotating pixels, not by writing an orientation tag).
- **CSRF:** the upload POST sends `X-CSRF-Token` from the `ui_csrf` cookie per the shared interceptor *(verified: `src/api/client.ts` sets `X-CSRF-Token` from `getCookie("ui_csrf")` on all requests including `api.upload`)*.
- **Content validation:** restrict picker to images; enforce `image/jpeg` after re-encode and the ≤5 MB cap **before** the upload so server rejections are rare.
- **PII in logs:** never log image bytes, file paths with usernames, the session cookie, or the CSRF token. Log only the request host + `kind` and the returned URL's host + path prefix.

## 9. Accessibility & i18n

- The "Change photo" control has a `contentDescription` ("Change profile photo" / "Change cover photo") and a ≥48 dp touch target.
- Crop screen controls (rotate, confirm, cancel) are buttons with labels, reachable by TalkBack and keyboard; the crop gesture surface exposes an accessibility action "Reset crop".
- Upload progress announces via `liveRegion` (e.g., "Uploading photo, 60 percent"); success/error announce as polite/assertive respectively.
- All user-facing strings live in `strings.xml` (no hardcoded literals): chooser labels, progress, error messages, permission rationale. Support RTL mirroring for the chooser and crop chrome.
- Respect large font scaling; crop overlay sizing is density-independent (dp), not pixel-hardcoded.

## 10. Telemetry & Logging

- Structured events (no PII): `profile_media_upload_started{kind}`, `_upload_progress` (sampled), `_upload_ok{kind,bytes,ms}`, `_failed{kind,stage,error_code}`, `_cancelled{kind,stage}`. *(Corrected: removed `_presign_ok`/`_put_ok`/`_confirm_ok` — single upload call; no `version` available to log.)*
- `stage` ∈ `{process, upload}` to localize failures on the flaky host.
- Debug-only logs gate behind `BuildConfig.DEBUG`; redact URLs to `host + pathPrefix(12)`.
- Surface counts feed a basic upload-success-rate metric; no image content or dimensions beyond byte size are recorded.

## 11. Testing Strategy

**Unit (`:core-testing`, JUnit + coroutines test):**
- `ImageProcessor`: EXIF orientation 6/8 inputs rotate correctly; output ≤ maxEdge; quality step-down reduces size under 5 MB; output is JPEG with no GPS tags.
- `ProfilePhotoUploaderImpl`: builds a multipart body with one part named `file` and `Content-Type: image/jpeg`; progress callbacks sum to total; MockWebServer 200 → `Success` parsing `{ profile, url }`; 401→refresh→retry; cancellation aborts the call. Assert the request is `POST /ui/profile/photos/{kind}/upload` with the path `kind` = `profile`/`cover` and that the request carries the `X-CSRF-Token` header (i.e. it uses the authenticated client).
- Error mapper: 422 validation array, plus 413/415 and all three `detail` shapes (string / array / `{code}`) map to expected `AppError`.
- ViewModel state machine: Idle→Preparing→Uploading→Success; host-down short-circuits to Error without an upload call (verify via fake repo).

**Instrumented / Compose UI:**
- Crop screen renders the correct aspect mask per `MediaKind`; confirm emits a `CropRect`.
- Control disabled and inline message shown when health signal is unhealthy.

**Acceptance (end-to-end, satisfies backlog "tested"):**
- Espresso/Compose test stubs the multipart upload endpoint (MockWebServer returns `{ profile, url }`), drives pick→crop→upload, asserts the avatar `AsyncImage` model updates to the returned `url`/`profile_photo_url` and that a simulated cold reload (`GET /ui/me` returning the new URL) shows the same image. This is the **canonical avatar-uploads-and-displays** test. *(Corrected: single endpoint, not presign+PUT+confirm.)*

## 12. Dependencies & Sequencing

- **Depends on AND-072** (Edit profile basics): the host screen, profile state holder, and the `applyMediaUrl` mutation + persistence/reload verification. AND-074 cannot merge before AND-072's profile state and Room columns exist.
- **Depends on AND-117** (Stale/reconnect UX hooks): `BackendHealthSignal` and the shared stale affordance gate the upload control.
- Implicitly relies on the established `:core-network` auth/CSRF/refresh interceptors and `ApiResult`/error mapper (delivered by earlier networking tickets in the dependency chain of AND-072).
- Sequencing: land `ImageProcessor` + crop UI (no backend) → `ProfilePhotoUploader` (multipart) in `:core-network` (MockWebServer-tested) → `ProfileMediaRepository.uploadPhoto` → ViewModel orchestration → wire into AND-072 screen → e2e acceptance test.

## 13. Risks & Open Questions

- **Contract drift: RESOLVED at review (2026-06-06).** The real endpoint is a single `POST /ui/profile/photos/{kind}/upload` multipart (`file` part), `kind ∈ {profile, cover}`, response `{ profile, url }`. The presign/PUT/confirm design is dead. Remaining minor risk: the OpenAPI 200 schema is untyped (`{}`), so `{ profile, url }` is sourced from the web client — tolerate field absence defensively.
- **Response URL stability:** the upload response `url`/`*_photo_url` may be stable across re-uploads (no `version` field exists). If stale-image caching is observed, add a time-based Coil cache key. *Open — not determinable from sources.*
- **Crop without a library:** hand-rolled gesture crop adds UI risk; fallback is `androidx`/community crop lib if effort exceeds budget (size estimate assumes hand-rolled M). Note: the **web reference does not crop at all** — it uploads the raw picked file. Client-side crop + downscale + EXIF-strip are **Android-side enhancements** beyond the web contract, not backend requirements.
- **Cover aspect & display:** confirm the cover render aspect (16:9 assumed) with AND-072's profile layout.
- **Server-side processing unknowns:** whether the backend re-encodes/strips EXIF/resizes server-side is not documented; the Android client strips EXIF/GPS locally regardless (defense in depth). *Open.*

## 14. Acceptance Criteria

AC-1. From Edit Profile, a user can pick from library or camera, crop to the avatar's 1:1 mask, and upload; the new avatar displays without leaving the screen. **(backlog: "New avatar uploads and displays")**
AC-2. After a cold app restart, the uploaded avatar still displays (re-fetched via `GET /ui/me`/`GET /ui/profile`, whose `profile_photo_url` now carries the new image). **(automated)**
AC-3. The upload is a single authenticated `multipart/form-data` POST to `/ui/profile/photos/{kind}/upload` with one part named `file`; the request carries the session cookie + `X-CSRF-Token` (verified by MockWebServer request assertions). *(Corrected: the prior AC claimed presign→PUT→confirm with bytes bypassing FastAPI — the real contract routes bytes through the app server on a single endpoint.)* **(automated)**
AC-4. Cover upload works via the same flow with a 16:9 crop. **(automated UI)**
AC-5. Images are re-encoded to JPEG ≤ 5 MB, EXIF-orientation-corrected, and stripped of GPS tags before upload. **(unit-tested)**
AC-6. When the backend health signal is unhealthy, the upload control is disabled with an inline message and no upload call is made. **(unit + UI test)**
AC-7. The upload POST is not auto-retried; failures surface a manual-retry state, and cancellation aborts the in-flight call leaving the prior media intact. *(Corrected: was "PUT and confirm ... re-presigns".)* **(unit-tested)**
AC-8. Secrets are never logged: the session cookie and `X-CSRF-Token` value are never written to logs, and returned media URLs are redacted to host + path-prefix. *(Corrected: the prior AC required the upload to carry NO cookie/CSRF — that is wrong; the upload MUST be authenticated to reach the protected endpoint.)* **(verified by test/inspection)**
AC-9. All user-facing strings are in `strings.xml`; controls expose content descriptions and progress is announced to TalkBack. **(lint + a11y check)**

## 15. Definition of Done

- All Acceptance Criteria met; the canonical avatar upload-and-display e2e test passes in CI.
- New code in `:feature-profile` and `:core-network` under `com.testlogon.android`; module layering respected (no `:feature-*` → `:feature-*` deps).
- Unit + instrumented tests added per §11; coverage for `ImageProcessor`, `ProfilePhotoUploaderImpl`, error mapping, and the ViewModel state machine.
- Upload endpoint/field names reconciled against `/openapi.json` (`POST /ui/profile/photos/{kind}/upload`, `file` part, `kind ∈ {profile, cover}`); any deviations from §5 documented in the PR.
- No lint regressions; no hardcoded strings; ktlint/detekt clean.
- Temp upload files are cleaned up (finally + startup sweep) — verified no leaks in instrumented test.
- Telemetry events emit with correct `stage`/`kind` and no PII; debug logs gated by `BuildConfig.DEBUG`.
- PR description notes resolved/outstanding §13 items; reviewer sign-off from the AND-072 owner on the shared profile-state integration.

## 16. Citations & Assumption Audit

Each key technical claim with its verdict and an exact source pointer. OpenAPI pointers use `METHOD /path` and/or schema name; frontend pointers use `src/...: symbol`; framework choices are labeled "framework ref".

1. **Upload endpoint is `POST /ui/profile/photos/{kind}/upload`** (single multipart call). VERDICT: **Corrected** (draft claimed `/ui/profile/media/presign` + object-store `PUT` + `/ui/profile/media/confirm`). SOURCE: OpenAPI `POST /ui/profile/photos/{kind}/upload` (op `ui_upload_profile_photo_...`); `src/api/endpoints/profile.ts: uploadProfilePhoto`. No `/ui/profile/media/*` paths exist in `openapi.index.txt`.
2. **`kind` is a path param with values `profile` (avatar) and `cover`.** VERDICT: **Corrected** (draft used `"avatar"`). SOURCE: `src/api/endpoints/profile.ts: uploadProfilePhoto(kind: "profile" | "cover", ...)`; OpenAPI path-param `kind: string`.
3. **Request body is `multipart/form-data` with one binary part named `file`.** VERDICT: **Verified**. SOURCE: OpenAPI schema `Body_ui_upload_profile_photo_ui_profile_photos__kind__upload_post` (`properties.file: string($binary)`, `required: [file]`); `src/api/endpoints/profile.ts` (`formData.append("file", file)`).
4. **Bytes transit the FastAPI app server (no direct-to-storage PUT).** VERDICT: **Corrected** (draft asserted bytes never traverse FastAPI). SOURCE: `src/api/client.ts: api.upload` delegates to `api()` (same host); OpenAPI request body declared on the FastAPI path itself.
5. **Upload is authenticated (session cookie + `X-CSRF-Token`) and uses the 401 refresh-once retry.** VERDICT: **Corrected** (draft required the PUT to carry NO auth). SOURCE: `src/api/client.ts` — `credentials: "include"`, `headers.set("X-CSRF-Token", getCookie("ui_csrf"))`, `refreshSession()` → `POST /ui/session/refresh` once on 401; `api.upload` routes through this same path.
6. **Success response shape `{ profile: Profile, url: string }`; no `version`, no `media_key`.** VERDICT: **Corrected** (draft response had `kind`/`media_key`/`version`/`upload_url`). SOURCE: `src/api/endpoints/profile.ts` (`api.upload<{ profile: Profile; url: string }>`). NOTE: OpenAPI 200 schema is untyped (`{}`), so the shape is sourced from the web client (treat as working contract; tolerate absent fields).
7. **Profile media fields are `profile_photo_url` and `cover_photo_url`.** VERDICT: **Corrected** (draft used `avatarUrl`/`coverUrl`/`mediaVersion`). SOURCE: `src/api/types.ts: interface Profile` (lines ~487–488).
8. **Read-back endpoints `GET /ui/me` and `GET /ui/profile` exist.** VERDICT: **Verified**. SOURCE: OpenAPI `GET /ui/me`, `GET /ui/profile`.
9. **`POST /ui/session/refresh` is the 401 retry path.** VERDICT: **Verified**. SOURCE: OpenAPI `POST /ui/session/refresh`; `src/api/client.ts: refreshSession`.
10. **CSRF token comes from the `ui_csrf` cookie, echoed as `X-CSRF-Token`.** VERDICT: **Verified**. SOURCE: `src/api/client.ts: getCookie("ui_csrf")` → `X-CSRF-Token`.
11. **Only `422 HTTPValidationError` is a documented error for this endpoint.** VERDICT: **Verified** (for the documented set). SOURCE: OpenAPI responses for `POST /ui/profile/photos/{kind}/upload` (`200`, `422`). `413`/`415`/`401` handling is an **Unverified-assumption** (defensive) — not declared in OpenAPI for this path.
12. **The web client does NOT crop; it uploads the raw `image/*` file.** VERDICT: **Verified** (re web behavior). SOURCE: `src/pages/settings/Profile.tsx: handlePhotoChange` (`input.accept = "image/*"`, mutates with the raw `File`). Android-side crop/downscale/EXIF-strip are enhancements beyond the web contract (Unverified-assumption that the backend requires them).
13. **Photo Picker requires no storage permission; Camera requires `CAMERA` runtime permission.** VERDICT: **Unverified-assumption** (framework ref). SOURCE: framework ref — Android Photo Picker docs (developer.android.com/training/data-storage/shared/photopicker) and runtime-permissions docs (developer.android.com/training/permissions/requesting). Not verifiable from backend/frontend sources.
14. **EXIF re-encode strips GPS while preserving orientation (rotate pixels).** VERDICT: **Unverified-assumption** (framework ref). SOURCE: framework ref — `android.media.ExifInterface` / `BitmapFactory` docs. Correctness is an Android implementation detail, not in the cited contract.
15. **Cover aspect ratio 16:9 / avatar 1:1.** VERDICT: **Unverified-assumption**. SOURCE: none — neither the OpenAPI spec nor the web client enforces crop aspect; confirm with AND-072 layout.

### Corrections made
- Replaced the entire fabricated **presign → object-store PUT → confirm** protocol with the real single multipart endpoint `POST /ui/profile/photos/{kind}/upload` (Overview, FR-5/6/7/9, §4 types/uploader/repository/ViewModel, §5 API Contract, §7, §8, §10, §11, §13, AC-3/AC-7/AC-8, §15).
- Fixed `kind` value `avatar` → `profile` and the `MediaKind` enum mapping (`AVATAR→"profile"`, `COVER→"cover"`).
- Fixed response shape to `{ profile, url }`; removed non-existent `media_key`/`version`/`upload_url`/`required_headers`/`expires_in`.
- Fixed profile field names to `profile_photo_url`/`cover_photo_url`; removed `mediaVersion` column and `applyMediaUrl(..., version)` arg.
- Reversed the security stance: the upload **carries** cookie + `X-CSRF-Token` and goes over the existing plaintext dev host (was "no auth, HTTPS object store"). AC-8 reworded to "never log secrets" instead of "no cookie/CSRF on PUT".
- Renamed `RawUploader`→`ProfilePhotoUploader`, `MediaConfirmResult`→`MediaUploadResult`; removed `UploadTarget` and `Confirming` state.
- Telemetry `stage` reduced to `{process, upload}`; removed presign/put/confirm events and `version` logging.

### Open assumptions
- **HTTP status set beyond 200/422** (`401`/`413`/`415`): handled defensively; only `422` is documented in OpenAPI for this endpoint.
- **Response `url` stability / cache-busting:** no `version` field exists; unknown whether re-uploads return a changed URL. Add a time-based Coil key if stale images are observed.
- **Server-side image processing** (resize/EXIF-strip/format coercion): undocumented; the client strips EXIF/GPS locally regardless.
- **Crop aspect ratios, Photo Picker / Camera permission behavior, EXIF handling:** Android-platform/UX decisions not derivable from the backend or web reference (framework refs only).
- **Cover render aspect (16:9):** to confirm against AND-072's profile layout.

## 17. Test Plan

Test targets: **JVM** = local JVM/Robolectric unit; **MockWebServer** = JVM contract test against a stubbed server; **emulator(test35)** = headless AVD API 35 x86_64 (CI Compose/instrumented); **device(SM-A156U)** = physical Samsung Galaxy A15 5G, API 34 arm64 (hardware-dependent). Use the physical device for real camera capture and ABI/API-34 verification; use the emulator for fast UI/instrumented suites.

- **TC-AND-074-01 — Happy path: avatar pick → crop → upload → display.** Type: instrumented/e2e (emulator(test35)). Preconditions: authenticated session; MockWebServer stubs `POST /ui/profile/photos/profile/upload` → 200 `{ profile:{profile_photo_url:U2}, url:U2 }`; health healthy. Steps: open Edit Profile → tap Change photo → pick library image → confirm 1:1 crop → wait for upload. Expected: request is `POST /ui/profile/photos/profile/upload`, `multipart/form-data` with one part `file` (`image/jpeg`); on 200 the avatar `AsyncImage` model becomes `U2` without leaving the screen. Traces: AC-1, AC-3.
- **TC-AND-074-02 — Cold-reload persistence.** Type: instrumented/e2e (emulator(test35)). Preconditions: TC-01 completed; MockWebServer `GET /ui/me` → `profile_photo_url:U2`. Steps: kill + relaunch app → open profile. Expected: avatar renders `U2` from the re-fetched profile. Traces: AC-2.
- **TC-AND-074-03 — Multipart contract assertion.** Type: contract/MockWebServer (JVM). Preconditions: `ProfilePhotoUploaderImpl` wired to MockWebServer. Steps: call `upload(AVATAR, processed, onProgress)`; inspect recorded request. Expected: method POST, path `/ui/profile/photos/profile/upload`, `Content-Type: multipart/form-data; boundary=...`, exactly one part named `file` with per-part `Content-Type: image/jpeg`; request carries `X-CSRF-Token` and session cookie; response parsed to `MediaUploadResult(url=U2)`. Traces: AC-3, AC-8.
- **TC-AND-074-04 — Cover path uses kind=cover with 16:9 crop.** Type: contract/MockWebServer + Compose-UI (emulator(test35)). Preconditions: stub `POST /ui/profile/photos/cover/upload` → 200. Steps: trigger cover change → confirm 16:9 crop → upload. Expected: crop mask is 16:9; request path segment is `cover`; cover image updates to returned url. Traces: AC-4.
- **TC-AND-074-05 — Image processing: downscale, JPEG, ≤5 MB, quality step-down.** Type: unit (JVM/Robolectric). Preconditions: oversized source bitmap. Steps: run `ImageProcessor.process` with avatar maxEdge 1024 / cover 1920. Expected: output is JPEG, max edge ≤ target, bytes ≤ 5 MB; quality steps 0.85→0.7→0.6 when needed. Traces: AC-5.
- **TC-AND-074-06 — EXIF orientation correction + GPS strip.** Type: unit (JVM/Robolectric). Preconditions: inputs with EXIF orientation 6 and 8 and embedded GPS tags. Steps: process; re-read output EXIF. Expected: pixels visually upright; output contains no GPS/location tags and no orientation tag (rotation baked into pixels). Traces: AC-5, AC-8.
- **TC-AND-074-07 — Health-down short-circuit.** Type: unit + Compose-UI (JVM for VM; emulator(test35) for UI). Preconditions: `BackendHealthSignal` unhealthy (fake). Steps: attempt upload. Expected (VM): state goes straight to `Error(NetworkUnavailable, retryable=true)`, fake repo records **zero** upload calls. Expected (UI): control disabled + inline stale/reconnect message. Traces: AC-6.
- **TC-AND-074-08 — 422 validation error mapping.** Type: contract/MockWebServer (JVM). Preconditions: stub upload → 422 `{detail:[{msg,loc,type}]}`. Steps: upload. Expected: mapped to `AppError` (non-retryable validation), `Error` state surfaced, prior avatar unchanged. Traces: AC-7.
- **TC-AND-074-09 — 401 refresh-once-then-retry on upload.** Type: contract/MockWebServer (JVM). Preconditions: stub upload → 401 once, `POST /ui/session/refresh` → 200, retried upload → 200. Steps: upload. Expected: exactly one refresh call then a successful retried upload; `Success`. Traces: AC-3, AC-7.
- **TC-AND-074-10 — Flaky-host / offline upload failure.** Type: contract/MockWebServer (JVM). Preconditions: server drops connection / socket timeout mid-body. Steps: upload. Expected: no auto-retry; `Error(retryable=true)`; prior media intact; temp file cleaned in `finally`. Traces: AC-7.
- **TC-AND-074-11 — Cancel mid-upload.** Type: contract/MockWebServer (JVM). Preconditions: server throttles body. Steps: start upload, call `cancel()` mid-stream. Expected: OkHttp call aborted, no `Success`, no profile mutation, temp file deleted, prior avatar retained. Traces: AC-7.
- **TC-AND-074-12 — Secrets/PII not logged.** Type: unit/inspection (JVM). Preconditions: capture logger output during upload. Steps: run upload with DEBUG logging. Expected: logs contain no session cookie, no `X-CSRF-Token` value, no full media URL (host + path-prefix only); no image bytes. Traces: AC-8.
- **TC-AND-074-13 — Real camera capture → crop → upload (hardware).** Type: instrumented/e2e — **MUST run on device(SM-A156U)** (real `CAMERA`). Preconditions: `CAMERA` granted; MockWebServer or sandbox upload stub. Steps: tap Change photo → Camera → capture → crop 1:1 → upload. Expected: camera intent returns a real image; pipeline produces JPEG; upload posts `kind=profile`; avatar updates. Rationale: emulator camera is synthetic; verifies arm64/API-34 capture + EXIF path. Traces: AC-1, AC-5.
- **TC-AND-074-14 — Camera permission denied degrades to library-only + accessibility.** Type: Compose-UI / instrumented (emulator(test35); permission UI also spot-checked on device). Preconditions: deny `CAMERA`. Steps: open source chooser. Expected: rationale shown, Camera option disabled/hidden, library still works; "Change photo" control has contentDescription and ≥48dp target; progress announced via `liveRegion` ("Uploading photo, NN percent"). Traces: AC-1, AC-9, AC-6 (a11y of disabled state).

### Coverage matrix
| Acceptance criterion | Covered by |
|---|---|
| AC-1 (pick/camera→crop→upload→display) | TC-01, TC-13, TC-14 |
| AC-2 (survives cold reload) | TC-02 |
| AC-3 (single multipart endpoint, authenticated) | TC-01, TC-03, TC-09 |
| AC-4 (cover via same flow, 16:9) | TC-04 |
| AC-5 (JPEG ≤5MB, EXIF orientation, GPS strip) | TC-05, TC-06, TC-13 |
| AC-6 (health-down disables control, no upload) | TC-07, TC-14 |
| AC-7 (no auto-retry; manual retry; cancel keeps prior media) | TC-08, TC-09, TC-10, TC-11 |
| AC-8 (secrets not logged; auth carried correctly) | TC-03, TC-06, TC-12 |
| AC-9 (strings, content descriptions, TalkBack progress) | TC-14 |
