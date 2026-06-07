---
id: AND-130
title: Image messages
milestone: M3
epic: E19
priority: P0
size: L
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-129]
blocks: []
---

# AND-130 — Image messages

## 1. Overview & Goal

Add the ability to send and view **image messages** in a TestLogon conversation on
the native Android client. A user can pick an image from the device gallery or
capture a new photo with the camera, the app downscales/compresses it locally,
uploads the bytes through the reusable attachment pipeline delivered by
**AND-129** (`presign → PUT`), then posts a message of kind `image`
referencing the uploaded object by `bucket`/`key` via
`POST /messaging/conversations/{conversation_id}/messages/image`. Inbound and
outbound image messages render as bounded thumbnails inline in the message list,
and tapping a thumbnail opens a full-screen, zoomable image viewer.

> **Review note (AND-130):** the backend uses a two-step flow, **not** a
> three-step presign→PUT→confirm. The presign call returns `bucket`/`key`/
> `upload_url`/`content_type`; the client PUTs the bytes directly to `upload_url`
> and then calls create-image-message with the `bucket`+`key` it received. There
> is **no** separate `confirm` endpoint and **no** `attachment_id`. All paths are
> namespaced under `/messaging/conversations/{conversation_id}/...`. See §5 and
> §16 for the corrected contract verified against OpenAPI and the web client.

The acceptance bar for the ticket is concrete: **an image sends and displays
full-screen on tap**. This spec covers the image-specific UI (picker/capture,
compression, thumbnail bubble, viewer), the
`/messaging/conversations/{conversation_id}/messages/image` and
`/messaging/conversations/{conversation_id}/images/presign` contracts, and how
this feature composes with the generic uploader from AND-129 rather than
re-implementing transport.

Out of scope: video/audio attachments, multi-image albums, image editing
(crop/markup/filters), GIF/sticker pickers, and message editing. These are
separate tickets in epic E19 and are not built here.

## 2. Context & References

- **Module:** `feature-messaging` (Compose UI + ViewModel), reusing
  `core-data` (uploader, repositories), `core-network` (Retrofit services),
  `core-model` (DTOs/domain), `core-ui` (theme, shared composables). Package
  base `com.testlogon.android` throughout, e.g.
  `com.testlogon.android.feature.messaging.image`.
- **Depends on AND-129 — Attachment pipeline (presign→PUT):** provides
  `AttachmentUploader` with progress/cancel/retry. AND-130 supplies the
  image-specific presign request (the per-conversation `images/presign`),
  compression, and the message-create call; it does **not** own the PUT
  transport. (Corrected: the pipeline is presign→PUT only — there is no
  `confirm` step in this backend; see §5/§16.)
- **Transitive deps:** AND-117 (network/auth/cookie-jar foundation; cookie
  session + `X-CSRF-Token`), AND-129's transitive chain. The conversation list
  and composer (E19 messaging base) are assumed present.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. Web reference for
  shapes (corrected paths): `src/api/endpoints/messaging.ts` (`sendImageMessage`),
  `src/api/endpoints/messagingAdapter.ts` (`adaptMessage`, image URL derivation),
  `src/api/client.ts` (auth/CSRF/refresh).
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

FR-6 **Upload.** Hand the compressed file to `AttachmentUploader` (AND-129) to
PUT it to the `upload_url` returned by the per-conversation `images/presign`.
Show inline progress (0–100%) on the optimistic bubble, with **cancel** and, on
failure, **retry**. (There is no `confirm` round-trip; presign→PUT only.)

FR-7 **Send message.** After the PUT succeeds, call
`POST /messaging/conversations/{conversation_id}/messages/image` with the
`bucket` + `key` from the presign response (plus `content_type`, `kind:"image"`,
`filename`, `filesize`, `width`, `height`). On success replace the optimistic
bubble with the returned `MessageOut` (keyed by `message_id`).

FR-8 **Inline rendering.** Image messages render as a rounded thumbnail bubble
(max 240×320 dp, aspect-preserving) loaded via Coil from the image URL. There is
no server `thumbnail_url`; the URL is taken from `image.url` if present, else
derived as `https://{image.bucket}.s3.amazonaws.com/{image.key}`. A
sent/sending/failed status indicator is shown for outbound messages.

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

**Repository** orchestrates presign → upload/PUT (AND-129) → create (no confirm):

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
(`localId = UUID`), `process()`, request presign (carrying only
`content_type`+`filename`), delegate the PUT of bytes to `uploader.upload(...)`
mapping its progress fractions to `Uploading`, then
`POST .../messages/image` with the presign's `bucket`+`key`, and finally
`Sent`. There is no confirm call. Cancellation of the collector cancels the
underlying upload via structured concurrency.

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

Two endpoints owned by this ticket; the intermediate `PUT` (to S3) is owned by
AND-129. **All shapes below are corrected and verified** against the OpenAPI
spec and the web client (`src/api/endpoints/messaging.ts: sendImageMessage`);
see §16 for per-claim citations. The earlier draft's `/images/presign`,
`/messages/image`, `attachment_id`, `confirm` step, `client_msg_id`, and
`thumbnail_url` were all incorrect and have been replaced.

**Presign — `POST /messaging/conversations/{conversation_id}/images/presign`**
(req schema `SendImagePresignIn`, resp `PresignOut`). The request carries **only**
`content_type` and `filename` — there is no `byte_size`/`width`/`height` on
presign:

```json
// request (SendImagePresignIn)
{ "content_type": "image/jpeg", "filename": "photo.jpg" }
// 200 response (PresignOut)
{ "upload_url": "https://<bucket>.s3.amazonaws.com/<key>?X-Amz-...",
  "bucket": "tl-messaging-media",
  "key": "conversations/cnv_.../<uuid>.jpg",
  "content_type": "image/jpeg" }
```

**PUT to S3 (AND-129 transport):** the client PUTs the processed bytes directly
to `upload_url` with header `Content-Type: <content_type>`. The web client does
exactly this (`uploadToPresignedUrl`). **There is no `confirm` endpoint and no
`attachment_id`** in this backend; the create call below references the object by
the `bucket`+`key` returned from presign.

**Create image message —
`POST /messaging/conversations/{conversation_id}/messages/image`**
(req schema `CreateImageMessageIn`, resp `MessageOut`). `bucket` and `key` are
the **only required** fields; the rest are optional metadata:

```json
// request (CreateImageMessageIn) — required: bucket, key
{ "bucket": "tl-messaging-media",
  "key": "conversations/cnv_.../<uuid>.jpg",
  "content_type": "image/jpeg",
  "kind": "image",
  "filename": "photo.jpg",
  "filesize": 384122,
  "width": 1536, "height": 2048,
  "file_created_at": 1749142640 }
// optional thumbnail/preview (client-uploaded; see §16): preview_bucket, preview_key
// 200 response (MessageOut) — note: integer epoch created_at, field `kind`, id is `message_id`
{ "message_id": "msg_01J0...", "conversation_id": "cnv_01HX...",
  "sender_id": "usr_01AB...", "kind": "image", "created_at": 1749142662,
  "image": { "bucket": "tl-messaging-media",
             "key": "conversations/cnv_.../<uuid>.jpg",
             "content_type": "image/jpeg", "width": 1536, "height": 2048 } }
```

The display URL is **derived client-side** when the `image` object has no
explicit `url`: `https://{bucket}.s3.amazonaws.com/{key}` (web reference:
`messagingAdapter.ts: buildS3ObjectUrl`). There is **no `thumbnail_url`** field;
a thumbnail/preview, if desired, is a *second* presign+PUT supplied via
`preview_bucket`/`preview_key` on the create request (see §13/§16).

Retrofit services (corrected paths; conversation id is a path param):

```kotlin
interface ImagesApi {
    @POST("messaging/conversations/{conversationId}/images/presign")
    suspend fun presign(
        @Path("conversationId") conversationId: String,
        @Body body: PresignRequest, // { content_type, filename }
    ): Response<PresignResponse>     // { upload_url, bucket, key, content_type }
}
interface MessagesApi {
    @POST("messaging/conversations/{conversationId}/messages/image")
    suspend fun createImageMessage(
        @Path("conversationId") conversationId: String,
        @Body body: CreateImageMessageRequest, // { bucket, key, content_type, kind, filename, filesize, width, height, ... }
    ): Response<MessageDto>          // MessageOut (message_id, kind, created_at:Long, image{...})
}
```

There is **no `client_msg_id`/idempotency key** on these endpoints (verified:
absent from `CreateImageMessageIn` and from the web client). Optimistic-bubble
reconciliation must therefore key on the returned `message_id` (and a local
`localId` tracked in the outbox), not a client-supplied dedup id. Both POSTs
carry session cookies + `X-CSRF-Token` automatically (AND-117 interceptor;
verified in `client.ts`).

**FastAPI error mapping:** documented responses for these routes are
`200`, `400`, `401`, `403`, `429`, and `422` (`HTTPValidationError`). `422`
returns `{ "detail": [ {loc, msg, type}, ... ] }` (schema `ValidationError`).
Map through the shared `ErrorBodyAdapter` to `AppError`. **Neither `409` nor
`413` is documented** for these endpoints (the original draft's 409/413 handling
was speculative — see §7 and §16). S3 PUT may still return `403` (expired
presigned URL); that is handled at the transport layer.

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
    val uploadBucket: String?,   // set after presign
    val uploadKey: String?,      // set after presign; references the PUT object
    val status: String,          // PROCESSING|UPLOADING|UPLOADED|SENT|FAILED
    val updatedAt: Long,
)
```

> Corrected: the entity previously held `attachmentId`/`clientMsgId`. The backend
> has no `attachment_id`, no `confirm`, and no `client_msg_id`; the create call is
> keyed on `bucket`+`key`, so the outbox persists those instead.

The repository advances `status` as the flow progresses and deletes the row on
`Sent`. On app start, `PendingImageReconciler` resumes rows stuck at
`UPLOADED` (re-issue `.../messages/image` with the persisted `bucket`+`key`) and
marks others `FAILED` for user-initiated retry. Because the API exposes no
idempotency key, a reconciler retry that races a previously-succeeded create can
produce a duplicate message; mitigate by only auto-resuming rows confirmed
`UPLOADED` (PUT done, create not yet acknowledged) and de-duping locally on
`message_id` when the list refresh returns the server copy (see §16 open
assumptions).

**Caching & images.** Coil handles in-memory + disk caching for thumbnails and
full images keyed by URL. Processed JPEGs live in `cacheDir/images/` and are
pruned after `Sent` or on a size-bounded LRU sweep at startup. DataStore is not
used here (no user prefs introduced).

**Threading.** Decode/encode on `Dispatchers.Default`, file IO on
`Dispatchers.IO`, network via Retrofit suspend on OkHttp's pool; UI state
updates marshalled back through the ViewModel's `viewModelScope`.

## 7. Error Handling & Resilience

- **Unreliable dev host:** apply ~20s OkHttp call timeout (AND-117 default).
  The per-conversation `images/presign` is a non-idempotent POST → **no
  automatic retry**; surface a retryable `Failed`. `PUT` retry policy is owned by
  AND-129. GET of image bytes (Coil) may use bounded backoff.
- **Compression failure / unsupported/corrupt image:** `process()` returns
  `ApiResult.Error(AppError.InvalidImage)`; show "Couldn't process this image."
  and abort before any network call.
- **Presign expiry / `403` on S3 PUT:** treat as expired upload URL → re-presign
  once, then re-upload (single transparent retry), else `Failed` with retry. (The
  create endpoint may also return `403` for authorization failures; that surfaces
  as `Failed`, not a re-presign.)
- **Oversized image:** keep the client-side compression cap (§4) as the primary
  guard since `413` is **not** a documented response for these endpoints. If the
  S3 PUT nonetheless rejects an oversized object, re-run compression at the
  next-lower quality tier and retry once; if still over cap, `Failed` with message
  "Image too large to send." (Corrected: the original draft assumed an app-level
  `413` from `/messages/image`; the contract does not document one — see §16.)
- **Duplicate sends:** the API has **no `client_msg_id`/idempotency key** and
  does **not** document `409`, so a duplicate cannot be detected server-side.
  Prevent duplicates client-side (disable re-send while in flight; reconcile on
  `message_id` after the list refresh). (Corrected: removed the speculative
  "`409` duplicate `client_msg_id` → success" handling.)
- **`401`:** handled by the refresh-once authenticator (AND-117) which POSTs
  `/ui/session/refresh` and retries once (verified in `client.ts`); transparent.
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
`image_send_failed{stage: process|presign|put|create, error_code}`,
`image_viewer_opened`. Logs use the app Timber tree at DEBUG for stage
transitions; PII/URLs/bytes excluded (§8). Failure events record the failing
**stage** to localize regressions between this ticket and AND-129.

## 11. Testing Strategy

- **Unit (JVM) — `DefaultImageProcessor`:** Robolectric/`BitmapFactory` fixtures
  assert longest edge ≤2048, output ≤5MB, EXIF rotation applied, GPS stripped,
  thumbnail ≤320px, alpha-PNG path. Quality step-down loop covered.
- **Unit — `DefaultImageMessageRepository`:** fake `AttachmentUploader` +
  **MockWebServer** for the per-conversation `images/presign` and
  `messages/image`. Assert the `ImageSendState` emission order
  (Processing→Uploading(progress)→Sent), the presign body fields
  (`content_type`+`filename` only), that the create body carries the presign's
  `bucket`+`key`, and the `403`-reupload branch. (No `client_msg_id`, `409`, or
  app-level `413` to assert — see §5/§16.) Reuses `core-testing`.
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

- **Endpoint shape uncertainty:** RESOLVED during this review. Confirmed paths
  `POST /messaging/conversations/{conversation_id}/images/presign` (req
  `SendImagePresignIn`, resp `PresignOut`) and
  `POST /messaging/conversations/{conversation_id}/messages/image` (req
  `CreateImageMessageIn`, resp `MessageOut`) against OpenAPI and
  `messaging.ts: sendImageMessage`. The DTO layer still isolates the UI from any
  future drift.
- **Thumbnail source:** RESOLVED. The backend does **not** return a
  `thumbnail_url`; the message `image` object carries `bucket`/`key` (or a `url`)
  and the client derives `https://{bucket}.s3.amazonaws.com/{key}`
  (`messagingAdapter.ts: buildS3ObjectUrl`). For a distinct low-res preview the
  client may do a *second* presign+PUT and pass `preview_bucket`/`preview_key`
  on the create request (optional fields on `CreateImageMessageIn`). For AND-130
  the simplest correct approach is to reuse the single full image (downscaled by
  Coil for the bubble) and treat a separate preview as optional polish.
- **Single attachment per message:** Confirmed — `messages/image` is one image
  object per message (gallery/multi-image is a separate `messages/gallery`-style
  flow with `free_images`/`locked_images`, out of scope).
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
AC-4 On success, `POST /messaging/conversations/{conversation_id}/messages/image`
(body keyed on `bucket`+`key`) creates the message and the optimistic bubble
reconciles with the returned `MessageOut` by `message_id`. (No server-side
idempotency key exists; duplicates are prevented client-side.)
AC-5 Both inbound and outbound image messages render as bounded thumbnails in
the list, loaded from the image `url` (or `bucket`/`key`-derived S3 URL); there
is no `thumbnail_url`.
AC-6 **Tapping a thumbnail opens a full-screen viewer** showing the full image
with pinch/double-tap zoom and pan, and a working close (primary acceptance).
AC-7 Failure at any stage yields a clear failed state with retry; offline pick
+ failed send persists across process death (outbox).
AC-8 No location/EXIF leakage; no images written to shared storage; no
URLs/cookies/bytes logged.

## 15. Definition of Done

- All sections 1–14 implemented in `feature-messaging` under
  `com.testlogon.android.*`; the per-conversation `images/presign` and
  `messages/image` endpoints wired through Retrofit and verified against
  `/openapi.json` (`SendImagePresignIn`/`PresignOut`/`CreateImageMessageIn`/
  `MessageOut`).
- Unit, DAO, ViewModel, Compose, and one instrumented happy-path test pass in CI;
  MockWebServer-based repository tests cover progress/cancel/retry, the
  `403`-reupload branch, and `422` validation mapping.
- Lint, Detekt/ktlint, and Compose-metrics checks clean; no new strict-mode disk/
  network on main thread.
- All strings externalized; TalkBack pass on bubble + viewer; RTL verified.
- No regressions to AND-129's uploader API (consumed, not modified).
- Telemetry events emitted with correct `stage` on failure; PII excluded.
- Code reviewed and merged to `android-port`.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Presign endpoint path.** Claim: `POST /messaging/conversations/{conversation_id}/images/presign`.
   **VERDICT: Corrected** (draft said `POST /images/presign`).
   Source: OpenAPI `POST /messaging/conversations/{conversation_id}/images/presign`
   (op `presign_image_upload...`); `src/api/endpoints/messaging.ts: sendImageMessage` (line ~391).
2. **Presign request schema.** Claim: body is `{ content_type, filename }` only.
   **VERDICT: Corrected** (draft added `byte_size`/`width`/`height`).
   Source: OpenAPI schema `SendImagePresignIn` (only `content_type`, `filename`, both with defaults);
   `messaging.ts: sendImageMessage` request body.
3. **Presign response schema.** Claim: returns `{ upload_url, bucket, key, content_type }`.
   **VERDICT: Corrected** (draft said `{ attachment_id, upload_url, method, headers, expires_in }`).
   Source: OpenAPI schema `PresignOut` (required: `upload_url, bucket, key, content_type`);
   `messaging.ts` presign generic type.
4. **No confirm step.** Claim: flow is presign → PUT → create (no `confirm`, no `attachment_id`).
   **VERDICT: Corrected** (draft asserted a `POST /attachments/{attachment_id}/confirm` step).
   Source: `messaging.ts: sendImageMessage` PUTs to `presign.upload_url` then immediately POSTs create with `bucket`/`key`;
   no confirm op exists in the OpenAPI index for this flow.
5. **Create-message endpoint path.** Claim: `POST /messaging/conversations/{conversation_id}/messages/image`.
   **VERDICT: Corrected** (draft said `POST /messages/image`).
   Source: OpenAPI `POST /messaging/conversations/{conversation_id}/messages/image`
   (op `create_image_message...`, resp `200:MessageOut`); `messaging.ts` line ~438.
6. **Create-message request schema.** Claim: required `bucket`+`key`; optional `content_type, kind, filename, filesize, width, height, file_created_at, preview_bucket, preview_key, caption, ...`.
   **VERDICT: Corrected** (draft said `{ conversation_id, attachment_id, client_msg_id }`).
   Source: OpenAPI schema `CreateImageMessageIn` (required: `bucket, key`); `messaging.ts: sendImageMessage` payload.
7. **No `client_msg_id` / idempotency key.** Claim: absent from the API.
   **VERDICT: Corrected** (draft relied on it for dedup/idempotency).
   Source: `CreateImageMessageIn` has no such field; `messaging.ts` sends none.
8. **Create-message response schema.** Claim: `MessageOut` with `message_id` (id), `kind` (not `type`), integer-epoch `created_at`, and an `image` object (no `attachment`/`thumbnail_url`).
   **VERDICT: Corrected** (draft used `id`, `type`, ISO `created_at`, and `attachment.{url,thumbnail_url}`).
   Source: OpenAPI schema `MessageOut` (required `conversation_id, message_id, sender_id, created_at:integer, kind`; has `image`, no `attachment`/`thumbnail_url`);
   `messagingAdapter.ts: adaptMessage` (maps `message_id`, `created_at` via numeric `toNum`, `image`).
9. **Image display URL derivation.** Claim: use `image.url` if present, else `https://{bucket}.s3.amazonaws.com/{key}`; no `thumbnail_url`.
   **VERDICT: Corrected** (draft loaded a server `thumbnail_url`).
   Source: `messagingAdapter.ts: buildS3ObjectUrl` and the `image` URL fallback (lines ~22-64).
10. **Thumbnail/preview is client-supplied, optional.** Claim: a separate preview is a second presign+PUT passed as `preview_bucket`/`preview_key`.
    **VERDICT: Verified.** Source: `CreateImageMessageIn.preview_bucket`/`preview_key`;
    `messaging.ts` locked-image flow (lines ~932-963) presigns + uploads a preview blob and passes `preview_bucket`/`preview_key`.
11. **Direct S3 PUT with `Content-Type`.** Claim: client PUTs bytes to `upload_url` with `Content-Type`.
    **VERDICT: Verified.** Source: `messaging.ts` `uploadToPresignedUrl(...)` / `fetch(presign.upload_url,{method:"PUT",headers:{"Content-Type":...}})`.
12. **Auth/CSRF model.** Claim: cookie session, `ui_csrf` cookie echoed as `X-CSRF-Token`, credentials included.
    **VERDICT: Verified.** Source: `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`, `credentials:"include"`, lines ~167-183).
13. **401 refresh-once.** Claim: on `401`, `POST /ui/session/refresh` once, then retry.
    **VERDICT: Verified.** Source: `client.ts: refreshSession()` (`POST /ui/session/refresh`, lines ~121-130) and the 401 retry path (lines ~191-224).
14. **Documented error responses for these routes.** Claim: `200/400/401/403/422/429`; `422` = `{detail:[ValidationError]}`; no `409`/`413`.
    **VERDICT: Corrected** (draft asserted explicit `409` and app-level `413`).
    Source: OpenAPI index lines for `messages/image` (resp `...;422:HTTPValidationError;400;401;403;429`); schema `HTTPValidationError` → array of `ValidationError`.
15. **Single image per `messages/image`.** Claim: one image object per message; multi-image is a separate gallery flow.
    **VERDICT: Verified.** Source: `CreateImageMessageIn` is single-object; `MessageOut.free_images`/`locked_images` and the separate gallery send path in `messaging.ts` (lines ~909-968).
16. **Web reference file locations.** Claim: image logic lives in `src/api/endpoints/messaging.ts` + `messagingAdapter.ts` + `client.ts`.
    **VERDICT: Corrected** (draft cited non-existent `endpoints/messages.ts` and `endpoints/attachments.ts`).
    Source: directory listing of `src/api/endpoints/` (no `messages.ts`/`attachments.ts`; `messaging.ts` present).
17. **Android Photo Picker is permissionless (minSdk 24).** Claim: `PickVisualMedia` needs no storage permission.
    **VERDICT: Verified (framework ref).** Source: developer.android.com/training/data-storage/shared/photopicker.
18. **`TakePicture` + FileProvider for camera capture.** Claim: capture to app-private `FileProvider` URI with transient read grant.
    **VERDICT: Verified (framework ref).** Source: developer.android.com/reference/androidx/activity/result/contract/ActivityResultContracts.TakePicture and developer.android.com/reference/androidx/core/content/FileProvider.
19. **EXIF read/orientation/strip via ExifInterface.** Claim: honor orientation, strip GPS/maker tags.
    **VERDICT: Verified (framework ref).** Source: developer.android.com/reference/androidx/exifinterface/media/ExifInterface.
20. **Cleartext to dev host only via network-security-config.** Claim: plaintext HTTP allowed only for the dev domain (from AND-117).
    **VERDICT: Unverified-assumption** (AND-117 config not in the reviewed sources). Carried over as a dependency assumption.

### Corrections made

- §1/§2/§5/§13/§14/§15: replaced `/images/presign` and `/messages/image` with the
  per-conversation namespaced paths (claims 1, 5).
- §5: rewrote presign request to `{content_type, filename}` (claim 2) and presign
  response to `{upload_url, bucket, key, content_type}` (claim 3).
- §1/§2/§4/§5/§6/§7/§11: removed the non-existent `confirm` step and
  `attachment_id`; the create call is keyed on `bucket`+`key` (claims 4, 6).
- §5/§6/§7/§11/§14: removed `client_msg_id` / idempotency-key assumptions (claim 7).
- §5/§14: corrected response shape to `MessageOut` (`message_id`, `kind`,
  integer-epoch `created_at`, `image{}`); removed `attachment.thumbnail_url`
  (claims 8, 9).
- §3/§5/§8/§13: replaced server `thumbnail_url` with client-side S3 URL derivation
  and the optional `preview_bucket`/`preview_key` thumbnail path (claims 9, 10).
- §5/§7/§11/§15: removed speculative `409`/`413` handling; aligned to documented
  `400/401/403/422/429` with `422 = {detail:[…]}` (claim 14).
- §2: fixed web-reference file paths to `messaging.ts`/`messagingAdapter.ts`/
  `client.ts` (claim 16).
- §10: dropped `confirm` from the failure-`stage` enum.

### Open assumptions

- **A1 (claim 20): dev-host cleartext config.** The `network-security-config`
  permitting plaintext HTTP to the dev host comes from AND-117, which is not in
  the reviewed sources. Assumed present; verify when AND-117 lands.
- **A2: AND-129 `AttachmentUploader` surface.** Progress/cancel/retry API and the
  exact `upload(...)` signature are owned by AND-129 and not in the reviewed
  sources. Assumed to expose a progress `Flow` and structured-concurrency cancel.
- **A3: duplicate-send safety.** With no server idempotency key (claim 7), a
  reconciler retry that races a succeeded create can duplicate a message. Mitigated
  client-side (in-flight guard + `message_id` de-dup on list refresh); there is no
  server-side guarantee to verify against.
- **A4: server-side image size/type limits.** Not expressed in
  `SendImagePresignIn`/`CreateImageMessageIn`; the client-side ≤5MB/≤2048px caps
  are a product choice, not a contract-derived limit. Unverifiable from sources.
- **A5: `image` object inner fields** (e.g. whether the server echoes `width`/
  `height`/`content_type`) are typed as a free-form object
  (`additionalProperties:true`) in `MessageOut.image`; exact keys are not
  guaranteed by the schema. The adapter reads `url`/`bucket`/`key` defensively.

## 17. Test Plan

Test target legend: **JVM** = JVM unit/Robolectric (local, no device);
**EMU** = headless emulator AVD `test35` (x86_64, API 35) for fast UI/instrumented
CI suites; **DEV** = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a)
for real-hardware behavior (camera, etc.).

- **TC-AND-130-01 — Image processing caps & EXIF strip.**
  Type: unit (JVM/Robolectric). Target: JVM. Test target: `DefaultImageProcessor`.
  Preconditions: fixture images incl. a 6000px landscape JPEG with EXIF
  orientation=6 + GPS tags, and an alpha PNG. Steps: call `process(uri)` for each.
  Expected: output longest edge ≤2048px; output ≤5MB; pixels rotated to match
  orientation; output EXIF has no GPS/maker tags; thumbnail longest edge ≤320px;
  alpha PNG kept as PNG when under cap. Traces: AC-2.
- **TC-AND-130-02 — Quality step-down loop.**
  Type: unit (JVM/Robolectric). Target: JVM. Test target: `DefaultImageProcessor`.
  Preconditions: a high-entropy image that exceeds 5MB at q80. Steps: run `process`.
  Expected: quality steps 80→70→60 until ≤5MB (or floor 50); final byteSize ≤5MB
  or a clear `InvalidImage` if floor exceeded. Traces: AC-2.
- **TC-AND-130-03 — Happy-path send contract (presign→PUT→create).**
  Type: contract/MockWebServer. Target: JVM. Test target:
  `DefaultImageMessageRepository` + fake `AttachmentUploader`.
  Preconditions: MockWebServer queues `200 PresignOut {upload_url,bucket,key,content_type}`
  then `200 MessageOut`. Steps: collect `sendImage(convId, uri)`.
  Expected: presign request body is exactly `{content_type, filename}` to
  `/messaging/conversations/{id}/images/presign`; PUT issued to `upload_url`;
  create request to `/messaging/conversations/{id}/messages/image` carries the
  presign `bucket`+`key` (+`kind:"image"`, dims); emission order
  Processing→Uploading(progress)→Sent; `Sent.message.message_id` populated from
  `MessageOut`. Traces: AC-3, AC-4.
- **TC-AND-130-04 — Auth headers on mutating calls.**
  Type: contract/MockWebServer. Target: JVM. Test target: OkHttp stack + repository.
  Preconditions: `ui_csrf` cookie present in the cookie jar. Steps: run a send.
  Expected: presign and create requests carry the session cookie and
  `X-CSRF-Token` equal to `ui_csrf`. Traces: AC-4, AC-8.
- **TC-AND-130-05 — 401 refresh-once then retry.**
  Type: contract/MockWebServer. Target: JVM. Test target: authenticator + repository.
  Preconditions: create returns `401` once, refresh `POST /ui/session/refresh`
  returns `200`, create retry returns `200 MessageOut`. Steps: run a send.
  Expected: exactly one `/ui/session/refresh` POST, then one create retry; final
  `Sent`. Second consecutive `401` → `Failed`, no infinite loop. Traces: AC-3, AC-7.
- **TC-AND-130-06 — 403 on PUT → single transparent re-presign+reupload.**
  Type: contract/MockWebServer. Target: JVM. Test target: repository.
  Preconditions: first PUT → `403`; second presign `200`; second PUT `200`; create `200`.
  Steps: run a send. Expected: re-presign happens exactly once, reupload succeeds,
  `Sent`; a second `403` → `Failed` retryable. Traces: AC-3, AC-7.
- **TC-AND-130-07 — 422 validation mapping.**
  Type: contract/MockWebServer. Target: JVM. Test target: `ErrorBodyAdapter` + repository.
  Preconditions: create returns `422 {"detail":[{"loc":["body","key"],"msg":"field required","type":"value_error.missing"}]}`.
  Steps: run a send. Expected: maps to `AppError` with a user-facing message;
  emits `Failed(canRetry=…)`; no crash on the array `detail` shape. Traces: AC-7.
- **TC-AND-130-08 — Offline / flaky dev host fast-fail.**
  Type: contract/MockWebServer. Target: JVM (MockWebServer with
  `SocketPolicy.NO_RESPONSE`/disconnect to simulate the unreliable host).
  Test target: repository. Preconditions: presign times out / connection dropped.
  Steps: run a send. Expected: presign is **not** auto-retried (non-idempotent
  POST); emits `Failed(canRetry=true)` within the ~20s timeout; an outbox row
  persists for user retry; no message shown as sent. Traces: AC-7.
- **TC-AND-130-09 — Outbox persistence & reconcile across process death.**
  Type: integration (Room in-memory + repository). Target: JVM/Robolectric.
  Test target: `ImageOutboxDao` + `PendingImageReconciler`.
  Preconditions: rows at `UPLOADED` (with `bucket`/`key`) and `UPLOADING`.
  Steps: simulate restart → run reconciler. Expected: `UPLOADED` row re-issues
  create with the persisted `bucket`+`key`; non-`UPLOADED` in-flight rows marked
  `FAILED` for manual retry; `Sent` deletes the row; local de-dup on `message_id`
  prevents a duplicate bubble. Traces: AC-4, AC-7.
- **TC-AND-130-10 — ViewModel optimistic / cancel / retry.**
  Type: unit (JVM, Turbine over StateFlow). Target: JVM. Test target:
  `MessageListViewModel`. Preconditions: fake repo emitting each `ImageSendState`.
  Steps: `onImagePicked` (assert optimistic bubble + progress), `onCancelUpload`
  (assert bubble removed, upload cancelled), then a failing send + `onRetryUpload`
  (assert flow re-runs). Expected: state transitions match; no business logic in UI.
  Traces: AC-3, AC-7.
- **TC-AND-130-11 — Compose bubble + viewer (UI).**
  Type: Compose-UI. Target: EMU. Test target: `ImageMessageBubble`,
  `FullScreenImageViewer`, `ImagePickerSheet`. Preconditions: Coil test dispatcher
  with a fake image. Steps: assert bubble renders thumbnail + status; tapping
  invokes `onTap`/navigates; viewer Close present; double-tap toggles
  test-exposed zoom state (1×↔3×); picker sheet routes gallery/camera taps.
  Expected: all assertions pass. Traces: AC-5, AC-6.
- **TC-AND-130-12 — Accessibility (TalkBack/semantics).**
  Type: Compose-UI (instrumented). Target: EMU. Test target: bubble + viewer + sheet.
  Steps: assert bubble `contentDescription` ("Image from {sender}…"/"Sent image");
  Close button has a label and ≥48dp touch target; sending/failed announced via
  state semantics; picker items are labelled buttons; status pairs icon/text (not
  color-only). Expected: semantics present; RTL layout mirrors. Traces: AC-5, AC-6, AC-8.
- **TC-AND-130-13 — Gallery pick happy path (no permission) + viewer open (e2e).**
  Type: instrumented/e2e. Target: EMU. Test target: full feature with stubbed
  `ActivityResultRegistry` (returns a content URI) + MockWebServer backend.
  Steps: open attach sheet → Photo Library → stubbed pick → observe progress →
  message appears → tap thumbnail → full-screen viewer opens with zoom/close.
  Expected: image sends and displays full-screen on tap; **no runtime storage
  permission requested**. Traces: AC-1, AC-3, AC-4, AC-5, AC-6.
- **TC-AND-130-14 — Real camera capture, CAMERA permission, EXIF/GPS, no shared-storage leak.**
  Type: instrumented/e2e. Target: **DEV (physical device required)** — exercises
  the real camera, MediaStore, and OEM `TakePicture` behavior; cannot be trusted
  on the emulator. Test target: capture flow + processor + send.
  Steps: open attach sheet → Take Photo → grant `CAMERA` once → capture a real
  photo (device has GPS/location) → send. Expected: capture writes only to
  app-private `cacheDir` via the `com.testlogon.android.fileprovider` authority
  (no file in shared/public storage); processed JPEG has GPS stripped; 0-byte/empty
  capture is guarded → `InvalidImage`; image sends and is viewable full-screen;
  CAMERA-denied path shows rationale and falls back to gallery only. Traces: AC-1,
  AC-2, AC-6, AC-8.

### Coverage matrix

| Acceptance criterion | Covered by |
|---|---|
| AC-1 (attach sheet; gallery no-perm / camera one-time CAMERA) | TC-13, TC-14 |
| AC-2 (compress ≤2048px/≤5MB, EXIF rotate, GPS strip) | TC-01, TC-02, TC-14 |
| AC-3 (upload via AND-129 with progress, cancel, retry) | TC-03, TC-05, TC-06, TC-10, TC-13 |
| AC-4 (create message keyed on bucket/key; reconcile by message_id) | TC-03, TC-04, TC-09, TC-13 |
| AC-5 (inbound+outbound thumbnails from url/bucket+key) | TC-11, TC-12, TC-13 |
| AC-6 (tap → full-screen viewer with zoom/pan/close) | TC-11, TC-12, TC-13, TC-14 |
| AC-7 (failed state + retry; offline persists across process death) | TC-05, TC-06, TC-07, TC-08, TC-09, TC-10 |
| AC-8 (no EXIF/location leak; no shared storage; no URL/cookie/byte logging) | TC-04, TC-12, TC-14 |
