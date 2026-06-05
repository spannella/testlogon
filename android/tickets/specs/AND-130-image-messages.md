---
id: AND-130
title: Image messages
milestone: M3
epic: E19
priority: P0
size: L
status: draft
depends_on: [AND-129]
blocks: []
---

# AND-130 — Image messages

## 1. Overview & Goal

Add the ability to send and view **image messages** in a TestLogon conversation on
the native Android client. A user can pick an image from the device gallery or
capture a new photo with the camera, the app downscales/compresses it locally,
uploads the bytes through the reusable attachment pipeline delivered by
**AND-129** (`presign → PUT → confirm`), then posts a message of type `image`
referencing the confirmed attachment via `POST /messages/image`. Inbound and
outbound image messages render as bounded thumbnails inline in the message list,
and tapping a thumbnail opens a full-screen, zoomable image viewer.

The acceptance bar for the ticket is concrete: **an image sends and displays
full-screen on tap**. This spec covers the image-specific UI (picker/capture,
compression, thumbnail bubble, viewer), the `/messages/image` and
`images/presign` contracts, and how this feature composes with the generic
uploader from AND-129 rather than re-implementing transport.

Out of scope: video/audio attachments, multi-image albums, image editing
(crop/markup/filters), GIF/sticker pickers, and message editing. These are
separate tickets in epic E19 and are not built here.

## 2. Context & References

- **Module:** `feature-messaging` (Compose UI + ViewModel), reusing
  `core-data` (uploader, repositories), `core-network` (Retrofit services),
  `core-model` (DTOs/domain), `core-ui` (theme, shared composables). Package
  base `com.testlogon.android` throughout, e.g.
  `com.testlogon.android.feature.messaging.image`.
- **Depends on AND-129 — Attachment pipeline (presign→PUT→confirm):** provides
  `AttachmentUploader` with progress/cancel/retry. AND-130 supplies the
  image-specific presign request (`images/presign`), compression, and the
  message-create call; it does **not** own the PUT transport.
- **Transitive deps:** AND-117 (network/auth/cookie-jar foundation; cookie
  session + `X-CSRF-Token`), AND-129's transitive chain. The conversation list
  and composer (E19 messaging base) are assumed present.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. Web reference for
  shapes: `frontend/src/api/endpoints/messages.ts`,
  `frontend/src/api/endpoints/attachments.ts`, `frontend/src/api/types.ts`.
- **Auth:** cookie-based session; every mutating call carries the `ui_csrf`
  cookie echoed as the `X-CSRF-Token` header; on `401` the OkHttp authenticator
  performs a single `POST /ui/session/refresh` then retries (provided by
  AND-117, applies automatically here).

## 3. Functional Requirements

FR-1 **Entry points.** The message composer exposes an "attach image" action
opening a bottom sheet with two choices: *Photo Library* and *Take Photo*.

FR-2 **Pick from gallery.** Use the Android Photo Picker
(`ActivityResultContracts.PickVisualMedia` with
`PickVisualMediaRequest(ImageOnly)`). No storage permission is required on any
supported API level (minSdk 24); the picker returns a scoped, read-only
`content://` URI.

FR-3 **Capture photo.** Use `ActivityResultContracts.TakePicture` writing to an
app-private `FileProvider` URI under `context.cacheDir/images/`. Request
`CAMERA` permission at point of use; if denied, show a rationale and fall back to
gallery only.

FR-4 **Compression.** Before upload, decode with downsampling
(`BitmapFactory.Options.inSampleSize`), scale longest edge to **≤ 2048 px**, and
re-encode to JPEG at quality **80** (PNG preserved only when source has alpha and
is under the size cap). Target output **≤ 5 MB**; if still larger after first
pass, drop quality in steps (80→70→60) until under cap or quality floor 50.
EXIF orientation is honored before encode; EXIF GPS/maker tags are **stripped**.

FR-5 **Thumbnail generation.** Produce a small thumbnail (longest edge 320 px,
JPEG q70) used for the inline bubble and optimistic local rendering before the
remote URL is available.

FR-6 **Upload.** Hand the compressed file to `AttachmentUploader` (AND-129) with
the presign descriptor from `images/presign`. Show inline progress (0–100%) on
the optimistic bubble, with **cancel** and, on failure, **retry**.

FR-7 **Send message.** After `confirm` returns an `attachment_id`, call
`POST /messages/image` with the conversation id and attachment id. On success
replace the optimistic bubble with the server message.

FR-8 **Inline rendering.** Image messages render as a rounded thumbnail bubble
(max 240×320 dp, aspect-preserving) loaded via Coil from the server thumbnail
URL, with a sent/sending/failed status indicator for outbound messages.

FR-9 **Full-screen viewer.** Tapping a thumbnail navigates to a full-screen
viewer showing the full-resolution image with pinch-to-zoom, double-tap zoom,
pan, a dark scrim, and a close affordance (back gesture + top-bar close).

FR-10 **Optimistic + offline states.** A send shows immediately as
"sending"; on transport failure the bubble shows "failed" with retry. Picking
while offline is allowed up to confirm; the failed state persists across process
death via the outbox (see §6).

## 4. Technical Design

New package `com.testlogon.android.feature.messaging.image`.

**Image processing** runs off the main thread (Dispatchers.Default for CPU,
Dispatchers.IO for file writes):

```kotlin
data class ProcessedImage(
    val file: File,          // compressed full-size, cacheDir/images/out
    val thumbFile: File,     // 320px thumbnail
    val mimeType: String,    // "image/jpeg" | "image/png"
    val width: Int,
    val height: Int,
    val byteSize: Long,
)

interface ImageProcessor {
    suspend fun process(source: Uri): ApiResult<ProcessedImage>
}

class DefaultImageProcessor @Inject constructor(
    @ApplicationContext private val context: Context,
) : ImageProcessor {
    suspend fun process(source: Uri): ApiResult<ProcessedImage> = withContext(Dispatchers.Default) { /* decode, downsample, rotate via ExifInterface, scale ≤2048, encode JPEG q80 loop ≤5MB, strip GPS, write thumb */ }

    companion object { const val MAX_EDGE = 2048; const val MAX_BYTES = 5L * 1024 * 1024; const val THUMB_EDGE = 320 }
}
```

**Repository** orchestrates presign → upload (AND-129) → confirm → create:

```kotlin
interface ImageMessageRepository {
    fun sendImage(conversationId: String, source: Uri): Flow<ImageSendState>
}

sealed interface ImageSendState {
    data class Processing(val localId: String) : ImageSendState
    data class Uploading(val localId: String, val progress: Float) : ImageSendState
    data class Sent(val localId: String, val message: Message) : ImageSendState
    data class Failed(val localId: String, val error: AppError, val canRetry: Boolean) : ImageSendState
}

class DefaultImageMessageRepository @Inject constructor(
    private val imagesApi: ImagesApi,         // images/presign
    private val messagesApi: MessagesApi,     // /messages/image
    private val uploader: AttachmentUploader, // AND-129
    private val processor: ImageProcessor,
    private val outbox: ImageOutboxDao,       // Room
) : ImageMessageRepository
```

`sendImage` emits a cold `Flow<ImageSendState>`: persist an outbox row
(`localId = UUID`), `process()`, request presign, delegate the PUT to
`uploader.upload(...)` mapping its progress fractions to `Uploading`, call
confirm, then `POST /messages/image`, and finally `Sent`. Cancellation of the
collector cancels the underlying upload via structured concurrency.

**ViewModel** (`feature-messaging` exposes `StateFlow<UiState>`):

```kotlin
@HiltViewModel
class MessageListViewModel @Inject constructor(
    private val repo: ImageMessageRepository,
    private val savedState: SavedStateHandle,
) : ViewModel() {
    val uiState: StateFlow<MessageListUiState>
    fun onImagePicked(uri: Uri)        // launches sendImage flow
    fun onCancelUpload(localId: String)
    fun onRetryUpload(localId: String)
    fun onOpenViewer(messageId: String)
}
```

**Navigation-Compose** adds a viewer destination
`messaging/image/{messageId}` rendered as a full-screen composable.

**Compose UI:**

```kotlin
@Composable fun ImageMessageBubble(model: ImageBubbleModel, onTap: () -> Unit, onRetry: () -> Unit, onCancel: () -> Unit)
@Composable fun ImagePickerSheet(onPickGallery: () -> Unit, onCapture: () -> Unit, onDismiss: () -> Unit)
@Composable fun FullScreenImageViewer(url: String, contentDescription: String?, onClose: () -> Unit)
```

`FullScreenImageViewer` uses Coil `AsyncImage` with a `graphicsLayer`
scale/translation state driven by `Modifier.pointerInput` (`detectTransformGestures`
for pinch/pan, `detectTapGestures(onDoubleTap)` for double-tap zoom 1×↔3×),
clamped to [1×, 4×] and pan bounds.

## 5. API Contract

Two endpoints owned by this ticket; the intermediate `PUT` is owned by AND-129.

**Presign — `POST /images/presign`** (request an upload target sized for the
processed image):

```json
// request
{ "filename": "photo.jpg", "content_type": "image/jpeg",
  "byte_size": 384122, "width": 1536, "height": 2048 }
// 200 response
{ "attachment_id": "att_01HZ...", "upload_url": "https://s3.../att_01HZ?X-Amz-...",
  "method": "PUT", "headers": { "Content-Type": "image/jpeg" }, "expires_in": 900 }
```

**Confirm** is the AND-129 `confirm` call keyed by `attachment_id` (e.g.
`POST /attachments/{attachment_id}/confirm`); reused as-is.

**Create image message — `POST /messages/image`:**

```json
// request
{ "conversation_id": "cnv_01HX...", "attachment_id": "att_01HZ...",
  "client_msg_id": "f1c2-...uuid" }
// 200/201 response
{ "id": "msg_01J0...", "conversation_id": "cnv_01HX...", "type": "image",
  "sender_id": "usr_01AB...", "created_at": "2026-06-05T17:04:22Z",
  "attachment": { "id": "att_01HZ...", "url": "https://cdn/.../full.jpg",
    "thumbnail_url": "https://cdn/.../thumb.jpg", "width": 1536, "height": 2048,
    "content_type": "image/jpeg", "byte_size": 384122 } }
```

Retrofit services:

```kotlin
interface ImagesApi {
    @POST("images/presign")
    suspend fun presign(@Body body: PresignRequest): Response<PresignResponse>
}
interface MessagesApi {
    @POST("messages/image")
    suspend fun createImageMessage(@Body body: CreateImageMessageRequest): Response<MessageDto>
}
```

`client_msg_id` provides idempotency/dedup so an optimistic bubble reconciles
with the echoed server message. All three POSTs carry session cookies +
`X-CSRF-Token` automatically (AND-117 interceptor). Exact field names are
verified against `/openapi.json` and `frontend/src/api/types.ts` during
implementation; deviations are reconciled in the DTO layer, not the UI.

**FastAPI error mapping:** `detail` may be `string`, `[{msg,...}]`, or
`{code,...}`; map through the shared `ErrorBodyAdapter` to `AppError` (reused
from core-network). `413` (payload too large from storage on PUT) and `409`
(duplicate `client_msg_id`) are handled explicitly (see §7).

## 6. Data & State Management

**ViewModel state.** `MessageListUiState` holds the message list plus a map
`outbound: Map<localId, OutboundImage>` whose entries carry
`{ thumbUri, progress, status }`. Status is derived from the latest
`ImageSendState`. Composables read from `StateFlow`; no business logic in UI.

**Outbox (Room, core-data).** A `pending_image_messages` table survives process
death so a send-in-flight or failed send is resumable:

```kotlin
@Entity(tableName = "pending_image_messages")
data class ImageOutboxEntity(
    @PrimaryKey val localId: String,
    val conversationId: String,
    val sourceUri: String,
    val processedPath: String?,
    val attachmentId: String?,   // set after confirm
    val status: String,          // PROCESSING|UPLOADING|UPLOADED|SENT|FAILED
    val clientMsgId: String,
    val updatedAt: Long,
)
```

The repository advances `status` as the flow progresses and deletes the row on
`Sent`. On app start, `PendingImageReconciler` resumes rows stuck at
`UPLOADED` (re-issue `/messages/image` with the same `client_msg_id`) and marks
others `FAILED` for user-initiated retry.

**Caching & images.** Coil handles in-memory + disk caching for thumbnails and
full images keyed by URL. Processed JPEGs live in `cacheDir/images/` and are
pruned after `Sent` or on a size-bounded LRU sweep at startup. DataStore is not
used here (no user prefs introduced).

**Threading.** Decode/encode on `Dispatchers.Default`, file IO on
`Dispatchers.IO`, network via Retrofit suspend on OkHttp's pool; UI state
updates marshalled back through the ViewModel's `viewModelScope`.

## 7. Error Handling & Resilience

- **Unreliable dev host:** apply ~20s OkHttp call timeout (AND-117 default).
  `images/presign` is a non-idempotent POST → **no automatic retry**; surface a
  retryable `Failed`. `confirm`/`PUT` retry policy is owned by AND-129. GET of
  image bytes (Coil) may use bounded backoff.
- **Compression failure / unsupported/corrupt image:** `process()` returns
  `ApiResult.Error(AppError.InvalidImage)`; show "Couldn't process this image."
  and abort before any network call.
- **Presign expiry / `403` on PUT:** treat as expired upload URL → re-presign
  once, then re-upload (single transparent retry), else `Failed` with retry.
- **`413` Payload Too Large:** re-run compression at the next-lower quality tier
  and retry once; if still over cap, `Failed` with message "Image too large to
  send."
- **`409` duplicate `client_msg_id`:** treat as success — fetch/adopt the
  existing server message and reconcile the optimistic bubble.
- **`401`:** handled by the refresh-once authenticator (AND-117); transparent.
- **Offline:** allow pick + process; presign fails fast → `Failed`/retry;
  outbox persists intent. No partial/zombie messages are shown as sent.
- **Cancel:** cancels the upload coroutine, deletes the outbox row and any
  partially uploaded local temp; bubble disappears.

## 8. Security & Privacy

- **Permissions:** no storage permission (Photo Picker is permissionless);
  `CAMERA` requested only at capture time with rationale and graceful fallback.
- **EXIF privacy:** strip GPS and maker-note tags during re-encode; only
  width/height/orientation are retained. This prevents leaking location.
- **FileProvider:** camera output written to an app-private path exposed via a
  `FileProvider` authority `com.testlogon.android.fileprovider`; URIs granted
  transiently with `FLAG_GRANT_READ_URI_PERMISSION`. No world-readable files.
- **Transport:** dev backend is plaintext HTTP (cleartext allowed for the dev
  host domain only via network-security-config from AND-117); presigned PUT
  targets are HTTPS. CSRF token attached to all mutating calls.
- **Cache hygiene:** processed temp files live in app-private `cacheDir` and are
  pruned post-send; no images written to shared/public storage.
- **Logging:** never log image bytes, presigned URLs (contain signed query
  params), or cookies/CSRF values.

## 9. Accessibility & i18n

- Thumbnails expose `contentDescription` = "Image from {sender}, {time}" (or
  "Sent image"); sending/failed states announced via state semantics.
- Full-screen viewer: `contentDescription` for the image, a labelled Close
  button (min 48dp touch target), and zoom controls reachable via TalkBack;
  pinch gestures have a double-tap fallback for switch/keyboard users.
- Picker sheet items are buttons with text labels (not icon-only).
- All user-facing strings (sheet labels, status text, error messages) live in
  `strings.xml`; no hardcoded text. Respect RTL via start/end paddings.
- Status indicators pair color with an icon/text (never color-only) to satisfy
  contrast/color-blind requirements; progress has a numeric/percent semantic.

## 10. Telemetry & Logging

Structured analytics events (via the app's existing logger abstraction):
`image_attach_started{source: gallery|camera}`,
`image_compressed{in_bytes, out_bytes, in_edge, out_edge, ms}`,
`image_upload_progress` (sampled), `image_send_succeeded{ms, out_bytes}`,
`image_send_failed{stage: process|presign|put|confirm|create, error_code}`,
`image_viewer_opened`. Logs use the app Timber tree at DEBUG for stage
transitions; PII/URLs/bytes excluded (§8). Failure events record the failing
**stage** to localize regressions between this ticket and AND-129.

## 11. Testing Strategy

- **Unit (JVM) — `DefaultImageProcessor`:** Robolectric/`BitmapFactory` fixtures
  assert longest edge ≤2048, output ≤5MB, EXIF rotation applied, GPS stripped,
  thumbnail ≤320px, alpha-PNG path. Quality step-down loop covered.
- **Unit — `DefaultImageMessageRepository`:** fake `AttachmentUploader` +
  **MockWebServer** for `images/presign` and `/messages/image`. Assert the
  `ImageSendState` emission order (Processing→Uploading(progress)→Sent), the
  presign body fields, that `client_msg_id` is stable across retry, and 409/413/
  403-reupload branches. Reuses `core-testing`.
- **DAO — `ImageOutboxDao`:** in-memory Room; resume/reconcile logic for rows at
  `UPLOADED` and `FAILED`.
- **ViewModel:** `Turbine` over `StateFlow`; verify optimistic bubble, progress,
  cancel removes bubble, retry re-runs flow, failed state on MockWebServer 500.
- **Compose UI tests:** `ImageMessageBubble` renders thumbnail + status;
  tapping invokes `onTap`; `FullScreenImageViewer` semantics (Close present,
  double-tap toggles zoom via test-exposed state). Picker sheet click routing.
- **Instrumented happy path:** stub picker result via test `ActivityResultRegistry`,
  MockWebServer backend → asserts image sends and viewer opens on tap (the
  ticket's acceptance scenario).

## 12. Dependencies & Sequencing

- **Hard dependency:** **AND-129** (uploader: presign→PUT→confirm with progress/
  cancel/retry). AND-130 must not re-implement transport; it consumes
  `AttachmentUploader`. Transitively requires **AND-117** (network/auth/cookie
  jar, cleartext dev config, CSRF, refresh authenticator).
- **Sequencing:** land AND-129 first; AND-130 adds `images/presign` descriptor
  mapping, `ImageProcessor`, `/messages/image`, bubble + viewer. The messaging
  base composer (E19) must exist to host the attach action.
- **Libraries (already in stack):** Coil (image load/cache), AndroidX Activity
  Result (Photo Picker / TakePicture), ExifInterface, Room, Hilt/KSP. No new
  third-party deps anticipated; `androidx.exifinterface:exifinterface` added if
  not already present.
- **Blocks:** none listed in backlog (video/album/edit tickets are independent).

## 13. Risks & Open Questions

- **Endpoint shape uncertainty:** exact `images/presign` and `/messages/image`
  field names must be confirmed against `/openapi.json` and the web reference;
  the DTO layer absorbs any drift. *Action: verify before coding the services.*
- **Thumbnail source:** does the backend generate `thumbnail_url`, or must the
  client upload a separate thumbnail? Spec assumes server-side derivation from
  the full image; if not, add a second presign/PUT for the thumb. *Open.*
- **Single attachment per message:** `/messages/image` is assumed one attachment
  per message; albums are out of scope. Confirm cardinality.
- **Dev host flakiness:** large PUTs over plaintext HTTP to an unreliable host
  may time out; relies on AND-129's retry. Monitor `image_send_failed{stage}`.
- **Memory pressure on large source images:** mitigated by `inSampleSize`
  downsampling before full decode; OOM guarded with try/catch → `InvalidImage`.
- **OEM camera quirks** with `TakePicture` returning empty/0-byte files; guard
  with a byte-size check post-capture.

## 14. Acceptance Criteria

AC-1 User can open the attach sheet and choose **gallery** or **camera**;
gallery requires no runtime permission, camera prompts for `CAMERA` once.
AC-2 A selected/captured image is compressed to longest edge ≤2048px and ≤5MB,
with EXIF orientation applied and GPS stripped (verified by unit test).
AC-3 The image uploads via the AND-129 uploader with visible inline progress
(0→100%), and **cancel** and **retry** work (verified with MockWebServer).
AC-4 On success, `POST /messages/image` creates the message and the optimistic
bubble reconciles with the server message (idempotent via `client_msg_id`).
AC-5 Both inbound and outbound image messages render as bounded thumbnails in
the list, loaded from `thumbnail_url`.
AC-6 **Tapping a thumbnail opens a full-screen viewer** showing the full image
with pinch/double-tap zoom and pan, and a working close (primary acceptance).
AC-7 Failure at any stage yields a clear failed state with retry; offline pick
+ failed send persists across process death (outbox).
AC-8 No location/EXIF leakage; no images written to shared storage; no
URLs/cookies/bytes logged.

## 15. Definition of Done

- All sections 1–14 implemented in `feature-messaging` under
  `com.testlogon.android.*`; `images/presign` and `/messages/image` wired
  through Retrofit and verified against `/openapi.json`.
- Unit, DAO, ViewModel, Compose, and one instrumented happy-path test pass in CI;
  MockWebServer-based repository tests cover progress/cancel/retry and
  409/413/403 branches.
- Lint, Detekt/ktlint, and Compose-metrics checks clean; no new strict-mode disk/
  network on main thread.
- All strings externalized; TalkBack pass on bubble + viewer; RTL verified.
- No regressions to AND-129's uploader API (consumed, not modified).
- Telemetry events emitted with correct `stage` on failure; PII excluded.
- Code reviewed and merged to `android-port`.
