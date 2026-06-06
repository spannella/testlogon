---
id: AND-131
title: Video messages / share
milestone: M3
epic: E19
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-129, AND-023]
blocks: []
---

# AND-131 — Video messages / share

## 1. Overview & Goal

Add the ability to **share a video** into a TestLogon conversation as a `video_share` message and play it back **inline** inside the message bubble without leaving the conversation. This ticket sits in the Messaging epic (E19) and is the video counterpart to AND-130 (Image messages).

> **REVIEW CORRECTION (authoritative, 2026-06-06):** The web reference implements `/messages/video-share` as **sharing a video that already exists in the user's VOD library**, referenced by an opaque `video_id`. The compose flow is `VideoPickerDialog` → `listMyVideos({status:"published"})` → pick → `POST /messaging/conversations/{conversation_id}/messages/video-share` with body `{ video_id, text?, send_at? }` (see `src/api/endpoints/messaging.ts: sendVideoShareMessage` and `src/pages/messages/VideoPickerDialog.tsx`). The request schema `CreateVideoShareMessageIn` has **only** `video_id` (required), `text`, and `send_at` — there is **no** `attachment_id`, `poster_url`, `duration_ms`, `width`, or `height` in the post body. Inline playback uses **HLS** (`hls_manifest_url` + `playback_token` query param), **not** progressive MP4. The original draft's "pick local file → AND-129 presign→PUT→confirm → post `kind="video"` with attachment_id/dimensions" model describes a *different* message kind (`kind="video"`, the per-file attachment in `ComposeBar.onSendVideoAttachment` via the images/presign pipeline) and does not match the `video_share` route this ticket scopes. The sections below are corrected to the real `video_share` contract; full audit in §16.

Concretely, a user composing a message in a conversation can pick a published video from their own video library (`VideoPickerDialog`), optionally add caption text, send it, and have the resulting `video_share` message render an inline HLS player that plays on tap (thumbnail/poster → play → in-bubble playback). Other participants who load the conversation see the same inline player backed by the server-issued `hls_manifest_url` + `playback_token`.

The single acceptance bar from the backlog is: **"Video sends and plays inline."** Everything below decomposes that into implementation-ready requirements. This ticket owns the video-share compose UX (`/messages/video-share`), the message-payload wiring (`video_id`), and the inline HLS player composable. It **reuses** the playback engine from the Media3 layer (AND-166) rather than re-implementing it. If a *fresh* device-local video must be uploaded before sharing, the authoritative path is the VOD pipeline `POST /ui/videos/upload/presign` → PUT → `POST /ui/videos/upload/complete` → then share by the returned `video_id` (see §5); this is **not** the AND-129 messages-attachment pipeline.

Out of scope: in-app recording/capture of new video (camera capture is image-only per AND-130; video capture is a future enhancement, see §13), transcoding, trimming/editing, and full-screen immersive playback (deferred; inline only).

> **REVIEW CORRECTION:** The original draft listed "HLS adaptive streaming for messages" as out of scope and asserted "messages are progressive MP4". This is **wrong**: the web `VideoShareCard` plays the shared video via the HLS manifest (`hls_manifest_url`) with a `playback_token`, using the shared `MediaPlayer mode="vod"` (see `src/pages/messages/VideoShareCard.tsx`). HLS inline playback is therefore **in scope** for this ticket. Out of scope remains: device-local progressive-MP4-only assumptions, DRM-protected playback edge cases (the `video_share` object carries `drm_enabled`; when true, treat as a degraded/"open externally" case per §7), and the streaming-epic E23 live-broadcast concerns.

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, Android app under `android/`, branch `android-port`. New code lands in `feature-messages` with shared building blocks in `core-data`, `core-network`, `core-model`, and `core-ui`.
- **Namespace:** all packages under `com.testlogon.android`. Feature code under `com.testlogon.android.feature.messages.video`.
- **Dependencies (authoritative, from backlog):**
  - **AND-129** — Attachment pipeline (presign→PUT→confirm). Provides `AttachmentUploader` with progress + cancel + retry. This ticket consumes it; it does not own upload transport.
  - **AND-023 (media)** — the media-capable navigation/host context this share route is wired into. The inline player engine itself is provided by **AND-166** (Media3/ExoPlayer `PlayerManager`, lifecycle-aware single-player reuse); this ticket depends on that wrapper being available and degrades gracefully if Media3 is absent (see §7).
- **Related (not blocking):** AND-130 (Image messages — sibling pattern for pick/compress/thumbnail/viewer), AND-128 (Messaging core tests), AND-280/AND-166/AND-167 (streaming/playback engine).
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable; ~20s timeouts, bounded backoff retry for idempotent GETs only). OpenAPI at `/openapi.json`. Web reference: `frontend/src/api/endpoints/*.ts`, `frontend/src/api/types.ts`.
- **Auth (verified against `src/api/client.ts`):** the web client sends, on every `api` call: `Authorization: Bearer <accessToken>` (from the auth store), `X-CSRF-Token` from the `ui_csrf` cookie, and `credentials: "include"` (session cookies). OpenAPI declares these endpoints with header params `authorization`, `X-SESSION-ID` (and optionally `X-API-Key`, `X-IMPERSONATION-TOKEN`). On a 401 for an already-authenticated user, the client calls `POST /ui/session/refresh` (cookie-based, `credentials:"include"`) **once**, then retries the original request; a second 401 logs out. The Android client must replicate **all three** auth carriers (Bearer token + `X-CSRF-Token` + persistent cookie jar), not cookie+CSRF alone. (Original draft omitted the Bearer token and `X-SESSION-ID`; the 401→refresh-once→retry behavior was correct — see §16.)

## 3. Functional Requirements

> **REVIEW CORRECTION:** FR-1..FR-6 originally described a device-local file pick + AND-129 presign→PUT→confirm flow producing a `kind="video"` message. That is not the `video-share` route. The corrected primary flow below mirrors the web `VideoPickerDialog` + `sendVideoShareMessage` (share an existing published library video by `video_id`). The fresh-upload variant (FR-1b) is retained as the secondary path and is wired to the **VOD** pipeline, not AND-129.

FR-1. From the conversation compose bar, a "share video" action opens an in-app **video library picker** that lists the user's own published videos via `GET /ui/videos?status=published` (`listMyVideos`), showing thumbnail, title, and duration; the user selects one and may add optional caption `text`. (Mirrors `src/pages/messages/VideoPickerDialog.tsx` + `ComposeBar onSendVideoShare`.)

FR-1b. (Secondary, optional) If the user wants to share a *new* device-local video, the system video picker (`ActivityResultContracts.PickVisualMedia` with `VideoOnly`, fallback `GetContent("video/*")` on minSdk 24 devices lacking Photo Picker) selects the file, which is uploaded via the **VOD pipeline** — `POST /ui/videos/upload/presign` (`VideoUploadPresignIn` → `VideoUploadPresignOut`, which returns `video_id`, `upload_url`, `max_size_bytes`) → PUT raw bytes to `upload_url` → `POST /ui/videos/upload/complete` (`VideoUploadCompleteIn`) — then the returned `video_id` is shared via the FR-7 post. This is **not** the AND-129 messages-attachment pipeline.

FR-2. Client-side pre-validation of a fresh upload candidate (FR-1b only): MIME `video/*` (whitelist `video/mp4`, `video/webm`, `video/3gpp`, `video/quicktime`); size ≤ the server-advertised limit. Note: the VOD presign schema permits up to **10 GiB** (`VideoUploadPresignIn.file_size_bytes maximum=10737418240`) and `VideoUploadPresignOut.max_size_bytes` is authoritative; the original draft's "100 MB / 300 s" client defaults are **unverified** and must not be hard-failed below the server limit (see §16 Open assumptions). Library-share (FR-1) needs no client size/duration validation — the asset is already a processed VOD.

FR-3. For a fresh upload (FR-1b), a local preview renders (a frame thumbnail via `MediaMetadataRetriever` + play-overlay + duration badge) with a determinate upload-progress indicator and a **cancel** control. For library-share (FR-1), the picker shows the server `thumbnail_url`/`duration_seconds`; no local extraction needed.

FR-4. On send, library-share posts immediately (no upload step). For FR-1b the compose action is disabled until the VOD upload+complete reaches a terminal state (`video_id` ready, or failed/cancelled).

FR-5. A failed fresh upload offers **retry** (reusing the same local URI) and **cancel/discard**. Cancel removes the pending item from the composer. Library-share post failures offer retry of the post.

FR-6. On send, a message of kind **`video_share`** is posted via `POST /messaging/conversations/{conversation_id}/messages/video-share` with body `{ video_id, text?, send_at? }` (`CreateVideoShareMessageIn`). The response (`MessageOut` / `Message`) carries the server-resolved `video_share` object (`video_id`, `title`, `thumbnail_url`, `duration_seconds`, `width`, `height`, `visibility`, `drm_enabled`, `hls_manifest_url`, `playback_token`, `playback_expires_at`). The client does **not** send poster/duration/dimensions — the server returns them.

FR-7. In the conversation list, a `video_share` message renders an **inline player surface**: `thumbnail_url` poster + play button initially; tapping play attaches the shared Media3 player to the **HLS** `MediaItem` built from `hls_manifest_url` with the `playback_token` appended as a `token` query param (mirrors `VideoShareCard`). Only one inline player is active at a time (reuse the AND-166 single-player constraint).

FR-8. Playback exposes play/pause, a scrubber, current/total time, and a mute toggle. Audio defaults to **muted** on first autostart-by-tap is not used; playback is user-initiated and starts **unmuted** on explicit tap. Scrolling the player off-screen pauses and releases it.

FR-9. The player is lifecycle-aware: it pauses on `ON_PAUSE` and releases on `ON_STOP`/composable disposal.

FR-10. A "share" affordance on a sent/received `video_share` message lets the user share the video out of the app via `Intent.ACTION_SEND` (text/plain). Note: the `video_share` object exposes only `hls_manifest_url` + a short-lived `playback_token` (`playback_expires_at`), not a stable public URL; outbound share should therefore prefer a canonical in-app video link (e.g. derived from `video_id`) rather than the expiring tokenized manifest URL, which would break for the recipient. (Unverified: no canonical public-share-URL field is exposed by the API in the sources — see §16 Open assumptions.)

## 4. Technical Design

New route registered in the messages nav graph:

```kotlin
// com.testlogon.android.feature.messages.video
const val VIDEO_SHARE_ROUTE = "messages/video-share?threadId={threadId}"

fun NavGraphBuilder.videoShareScreen(onClose: () -> Unit) {
    composable(
        route = VIDEO_SHARE_ROUTE,
        arguments = listOf(navArgument("threadId") { type = NavType.StringType }),
    ) { VideoShareRoute(onClose = onClose) }
}
```

ViewModel exposes a single `StateFlow<UiState>`:

```kotlin
@HiltViewModel
class VideoShareViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val uploader: AttachmentUploader,       // AND-129
    private val messagesRepository: MessagesRepository,
    private val videoMeta: VideoMetadataExtractor,  // wraps MediaMetadataRetriever
) : ViewModel() {

    val uiState: StateFlow<VideoShareUiState>

    fun onVideoPicked(uri: Uri)
    fun onSend()
    fun onCancelUpload()
    fun onRetry()
    fun onDiscard()
}

sealed interface VideoShareUiState {
    data object Empty : VideoShareUiState
    data class Validating(val uri: Uri) : VideoShareUiState
    data class Ready(val draft: VideoDraft) : VideoShareUiState
    data class Uploading(val draft: VideoDraft, val progress: Float) : VideoShareUiState // 0f..1f
    data class Sending(val draft: VideoDraft) : VideoShareUiState
    data class Failed(val draft: VideoDraft?, val error: UiError, val canRetry: Boolean) : VideoShareUiState
    data object Sent : VideoShareUiState
}

data class VideoDraft(
    val localUri: Uri,
    val mimeType: String,
    val sizeBytes: Long,
    val durationMs: Long,
    val width: Int,
    val height: Int,
    val posterUri: Uri,        // cached extracted frame
)
```

Inline playback composable (thread list cell):

```kotlin
@Composable
fun InlineVideoPlayer(
    message: VideoMessageUi,
    playerManager: PlayerManager,  // AND-166, lifecycle-aware single-player
    modifier: Modifier = Modifier,
)
```

`InlineVideoPlayer` shows `AsyncImage(thumbnailUrl)` + play overlay until tapped, then builds an **HLS** `MediaItem` from `hls_manifest_url` with the `playback_token` appended as `?token=…` (mirroring `VideoShareCard`) and calls `playerManager.attach(playerView, mediaItem)`. A `DisposableEffect` releases on dispose; an `onGloballyPositioned`/visibility observer pauses when scrolled out of the viewport. (Original draft used `MediaItem.fromUri(message.videoUrl)` for a progressive MP4 URL — corrected to the tokenized HLS manifest. Media3's HLS source requires the `media3-exoplayer-hls` artifact — see §16 framework ref.)

> **REVIEW CORRECTION:** The send flow does **not** reuse the AND-129 attachment uploader for the `video-share` route. The primary send is a plain JSON POST of `{ video_id, text? }`; only the optional fresh-upload variant (FR-1b) uploads bytes, and it uses the VOD pipeline.

Primary send inside `onSend()` (library-share, mirrors `sendVideoShareMessage`):

```kotlin
// POST /messaging/conversations/{conversationId}/messages/video-share
messagesRepository.sendVideoShare(
    conversationId = conversationId,
    body = CreateVideoShareMessageIn(videoId = draft.videoId, text = caption),
) // -> MessageOut (kind = "video_share"), carrying the resolved video_share object
```

Optional fresh-upload variant (FR-1b) — VOD pipeline, then share:

```kotlin
val presign = vodApi.presignUpload(            // POST /ui/videos/upload/presign
    VideoUploadPresignIn(filename, contentType, fileSizeBytes))
uploadBytes(presign.uploadUrl, draft.localUri) // PUT raw bytes (storage-signed, no app auth)
vodApi.completeUpload(                          // POST /ui/videos/upload/complete
    VideoUploadCompleteIn(ticketId = presign.ticketId, key = presign.key))
// then send video-share with presign.videoId
```

Module placement: route + composables + ViewModel in `feature-messages`; `VideoMessageUi` mapping in `core-data`/`core-model`; the optional `VideoMetadataExtractor` (FR-1b only) wraps `MediaMetadataRetriever`. `PlayerManager` is an injected interface. The AND-129 `AttachmentUploader` is **not** required for the primary flow; FR-1b uses a VOD upload client instead. New Gradle dependency: Media3 HLS (`androidx.media3:media3-exoplayer-hls`) is required if not already present for AND-166 (original draft's "no new Gradle dependency" claim assumed progressive MP4 — re-check against AND-166's dependency set; flagged in §16).

## 5. API Contract

> **REVIEW CORRECTION:** This entire section was rewritten. None of the originally-cited endpoints (`/messages/attachments/presign`, `/messages/attachments/{id}/confirm`, `/messages/threads/{thread_id}/messages`) exist in the OpenAPI index. The real endpoints are under `/messaging/conversations/{conversation_id}/…` and `/ui/videos/…`. Verified shapes below.

**(a) Primary: post a video-share message (verified).**

```
POST /messaging/conversations/{conversation_id}/messages/video-share
Authorization: Bearer <accessToken>
X-CSRF-Token: <ui_csrf>            (+ session cookie; X-SESSION-ID per OpenAPI)
{ "video_id": "vid_…",            # required, 1..128 chars
  "text": "optional caption",     # optional, <=2000 chars
  "send_at": 1717689600 }         # optional epoch (schedule)
→ 200  MessageOut  (see (c))
```
op `create_video_share_message_…`; request schema `CreateVideoShareMessageIn` (required: `video_id`; plus `text`, `send_at`). Mirrors `src/api/endpoints/messaging.ts: sendVideoShareMessage` (`SendVideoShareReq = { video_id; text?; send_at? }`). **No** `attachment_id`/`poster_url`/`duration_ms`/`width`/`height` in the request.

**(b) Optional: upload a fresh device-local video (VOD pipeline, verified).** Only needed for FR-1b; the `video_id` it yields is then fed to (a).

```
POST /ui/videos/upload/presign
{ "filename": "clip.mp4", "content_type": "video/mp4",
  "file_size_bytes": 7340032 }    # required; max 10737418240 (10 GiB)
→ 200  VideoUploadPresignOut
{ "video_id": "vid_…", "upload_url": "https://…", "presigned_url": "https://…",
  "bucket": "…", "key": "…", "s3_key": "…", "ticket_id": "…",
  "content_type": "video/mp4", "expires_at": "…", "expires_in_seconds": 900,
  "max_size_bytes": 10737418240 }

PUT <upload_url>   (raw bytes; storage-signed; NO app auth headers/cookies)
→ 200/204

POST /ui/videos/upload/complete
{ "ticket_id": "…", "key": "…" }  # VideoUploadCompleteIn (see schema during impl)
→ 200  VideoUploadCompleteOut  (video_id ready to share)
```
ops `vod_presign_upload_…` / `vod_complete_upload_…`; web: `src/api/endpoints/videos.ts: presignVideoUpload`, `completeVideoUpload`. The legacy `POST /ui/videos/{videoId}/upload/complete` is **deprecated** — use the body form.

**(c) Message read shape (verified).** Reads use `GET /messaging/conversations/{conversation_id}/messages` (params `limit`, `before`; cursor-style, suits Paging 3). A `video_share` message (`Message` / `MessageOut`) has `message_id`, `conversation_id`, `sender_id`, `kind: "video_share"`, `created_at` (**epoch number**, not ISO string), optional `text`, and a `video_share` object:

```
"video_share": {
  "video_id": "vid_…", "owner_user_id": "…", "title": "…",
  "thumbnail_url": "https://…",        # poster
  "duration_seconds": 42, "width": 1280, "height": 720,
  "visibility": "published", "drm_enabled": false,
  "hls_manifest_url": "https://…/manifest.m3u8",   # HLS, not MP4
  "playback_token": "…", "playback_expires_at": 1717690000 }
```
Source: `src/api/types.ts: Message.video_share` and `MessageOut` schema. The inline player builds the HLS `MediaItem` from `hls_manifest_url` + `?token=<playback_token>` (see `VideoShareCard`).

**(d) Picker source (verified).** The library picker lists the user's videos via `GET /ui/videos?status=published` → `VideoListOut` (`listMyVideos`), items of `VideoListItem` (`video_id`, `title`, `thumbnail_url?`, `duration_seconds?`, `visibility`, …).

Error envelope follows the FastAPI `detail` convention: `422 HTTPValidationError` is `{ "detail": [{ "loc": [...], "msg": "...", "type": "..." }] }`; other 4xx may be `{ "detail": "string" }`. The shared `ApiResult<T>` decoder handles both; `normalizeErrorDetail` in `src/api/client.ts` is the web reference. A mapper isolates any field drift.

## 6. Data & State Management

- **UI state:** single `StateFlow<VideoShareUiState>` per §4; conversation cells derive `VideoMessageUi(videoId, title, thumbnailUrl, hlsManifestUrl, playbackToken, playbackExpiresAt, durationSeconds, aspectRatio, drmEnabled, isOutgoing)` from the `Message.video_share` object (note: field names are `thumbnail_url`, `duration_seconds`, `hls_manifest_url`, `playback_token`, `playback_expires_at` — corrected from the draft's `videoUrl`/`posterUrl`/`durationMs`).
- **No new Room entity is required for the draft.** The in-flight draft lives in ViewModel state. Confirmed `video_share` messages are cached by the existing Room message DAO (AND-12x); this ticket adds `kind="video_share"` columns/fields (`video_id`, `title`, `thumbnail_url`, `duration_seconds`, `width`, `height`, `visibility`, `drm_enabled`, `hls_manifest_url`, `playback_token`, `playback_expires_at`) to the message cache mapping — additive, with a Room migration if the messages table predates them. **Do not persist `playback_token` long-term** — it is short-lived (`playback_expires_at`); on cache hit past expiry, re-fetch the message to obtain a fresh token.
- **Poster/thumbnail cache:** remote `thumbnail_url` is loaded by Coil with normal HTTP caching. For the optional FR-1b fresh-upload preview only, a locally extracted frame may be written to `cacheDir/video-posters/<hash>.jpg`.
- **DataStore:** any client-side pre-validation limits for FR-1b (`max_video_bytes`, `allowed_video_mimes`) read from a feature-config DataStore key; the **authoritative** size cap is `VideoUploadPresignOut.max_size_bytes` from the server. Library-share (FR-1) has no client limits. No per-user prefs added.
- **Paging:** unchanged — `video_share` cells participate in the existing `PagingData<MessageUi>` conversation stream (backed by `GET /messaging/conversations/{conversation_id}/messages`, `limit`/`before`). Player attach/detach is keyed on the visible item key so recomposition during paging does not leak players.

## 7. Error Handling & Resilience

- **Validation errors** (FR-1b fresh-upload only: size/MIME) surface as `Failed(canRetry=false)` with a specific message; user re-picks. Library-share has no such validation. A `422 HTTPValidationError` from the post (e.g., bad/empty `video_id`) is decoded from `detail[].msg` and shown.
- **Post errors (primary flow):** `POST …/messages/video-share` may return `422` (validation) → `Failed(canRetry=false)` for malformed input, or 5xx/network timeout (~20s, dev host flakiness) → `Failed(canRetry=true)`. The post body is small JSON; retry is safe to offer.
- **Upload errors (FR-1b VOD pipeline):** `POST /ui/videos/upload/presign` 4xx/5xx; the storage `PUT` may time out on large files; `POST /ui/videos/upload/complete` may fail. Cancel cooperatively cancels the coroutine and aborts the PUT. The `PUT` is **not** retried automatically (large non-idempotent body); presign/complete may use bounded backoff. Expired presign (`expires_in_seconds`) → re-presign once then surface.
- **Retry policy:** only idempotent GETs (conversation reload) use the global retry policy.
- **401 during presign/complete/post:** the OkHttp authenticator performs `POST /ui/session/refresh` once and retries; persistent cookie jar + Bearer token + `X-CSRF-Token` re-applied (verified against `src/api/client.ts`).
- **Playback errors:** `Player.Listener.onPlayerError` (unsupported codec, HLS manifest fetch failure, **expired `playback_token`** → likely 401/403 on the manifest) flips the cell to a retry/poster state with a "Couldn't play video" message; tap-to-retry **re-fetches the message** to get a fresh `hls_manifest_url`/`playback_token`, then re-`prepare()`s the `MediaItem` (a stale token cannot be fixed by re-prepare alone).
- **Media3 / HLS absent, `PlayerManager` unavailable, or `drm_enabled=true`:** inline cell degrades to poster + "Open externally" (`ACTION_VIEW`). This keeps the conversation usable if AND-166 ships late or DRM playback is unsupported.
- **Stale/offline:** cached `video_share` messages render the cached `thumbnail_url`; play attempt while offline shows offline state and offers retry when connectivity returns (and re-fetches the token if expired).

## 8. Security & Privacy

- All app→backend calls carry `Authorization: Bearer <token>` + `X-CSRF-Token` (from `ui_csrf` cookie) + session cookies (verified `src/api/client.ts`); the FR-1b storage `PUT` to `upload_url` uses only the storage-signed URL and must **not** attach Bearer/CSRF/session cookies (separate OkHttp call/tag so the cookie+auth interceptors are bypassed for the presigned host).
- Dev backend is plaintext HTTP; cleartext is permitted only for the dev host via a scoped `network_security_config` (no app-wide cleartext). Presigned storage URLs and HLS manifest URLs are expected to be HTTPS; reject non-HTTPS presign/manifest URLs in non-debug builds.
- **`playback_token` is a bearer secret for media:** it grants HLS playback access. Append it only to the manifest request; never log it; treat it as short-lived (`playback_expires_at`) and do not persist it beyond the cache TTL.
- Local video URIs are accessed via `contentResolver` with the picker-granted read permission; no broad `READ_EXTERNAL_STORAGE` is requested (Photo Picker / SAF scoped access on minSdk 24+).
- Poster frames cached in app-private `cacheDir` (not world-readable). Extracted metadata stays on-device until confirm.
- Outbound **share** must send a canonical, non-expiring video link (derived from `video_id`), **never** the tokenized `hls_manifest_url?token=…` (the `playback_token` is a secret and expires) and never local file paths or cookies. (No public-share-URL field is exposed in the sources — see §16; treat the exact share URL form as an open assumption.)
- No PII is logged; URIs and attachment ids are not written to analytics in cleartext beyond opaque ids.

## 9. Accessibility & i18n

- Play/pause, mute, scrubber, cancel, retry, and share controls have `contentDescription`s; the scrubber exposes `Slider` semantics with current/total time announced.
- The inline player surface has a `Role.Button` poster with description "Play video, <duration>"; on play it announces state changes via `liveRegion`.
- Touch targets ≥ 48dp; controls operable without color-only cues; respect `LocalContentColor`/Material 3 dynamic color and dark theme.
- All strings (`video_attach`, `video_too_large`, `video_too_long`, `video_upload_failed`, `video_play_failed`, `video_share`, duration format) in `strings.xml`; durations formatted with locale-aware `DateUtils.formatElapsedTime`.
- RTL-safe layouts (scrubber and time labels mirror correctly). Respect system captions/`Reduce animations` where applicable.

## 10. Telemetry & Logging

- Events (via the app's analytics abstraction, opaque ids only): `video_attach_started`, `video_validation_failed{reason}`, `video_upload_started`, `video_upload_progress` (sampled), `video_upload_cancelled`, `video_upload_failed{http_status}`, `video_message_sent{duration_ms,size_bucket}`, `video_play_started`, `video_play_error{code}`, `video_shared`.
- Logging via the core logger at `Log.d/w` in debug; release strips verbose logs. No raw URLs, cookies, or CSRF tokens logged. Upload progress logged only in debug.
- Player errors include Media3 `PlaybackException.errorCode` (numeric) for triage, not media URLs.

## 11. Testing Strategy

- **Unit (JVM, `core-testing` + MockWebServer):**
  - `VideoShareViewModel` state machine: pick → validate(ok/fail) → upload(progress) → confirm → post → `Sent`; cancel and retry paths.
  - Validation rules: oversize, over-duration, disallowed MIME each yield `Failed(canRetry=false)`.
  - Upload mapping from AND-129 events to `Uploading.progress`/`Failed`.
  - Library-share post happy path mocked with MockWebServer, asserting `Authorization: Bearer` + `X-CSRF-Token` present on app calls, and that the `video-share` body is exactly `{ video_id, text? }` (no attachment/poster/dimensions). For FR-1b: presign→PUT→complete, asserting app-auth headers **absent** on the presigned PUT.
  - 401 → `POST /ui/session/refresh` once → retry succeeds (one refresh only).
- **Mapper tests:** `video-share` post + `GET …/messages` JSON → `VideoMessageUi` (`video_share` object fields incl. `created_at` epoch number, `hls_manifest_url`, `playback_token`), including FastAPI `detail`/`HTTPValidationError` error variants.
- **Compose UI tests (Robolectric/`createAndroidComposeRule`):**
  - Composer shows preview + progress + cancel; cancel returns to `Empty`.
  - Thread cell shows poster + play; tap shows player surface (player attach faked via test double of `PlayerManager`).
  - Degraded mode (no `PlayerManager`) shows "Open externally".
- **Instrumented (1 smoke):** an **HLS** stream plays inline using the real `PlayerManager`, mirroring AND-166's playback acceptance, to satisfy "plays inline" end-to-end. Runs on the emulator headlessly per AND-128; codec/ABI-sensitive playback should also be spot-checked on the physical device (§17).
- A fake VOD upload client (flow of progress events, FR-1b) and a fake `PlayerManager` are added to `core-testing`.

## 12. Dependencies & Sequencing

- **AND-129** (messages-attachment uploader) — **NOT a hard dependency for the `video-share` flow** (correction): the primary flow is a JSON post of `video_id`, and the optional fresh-upload (FR-1b) uses the **VOD** pipeline (`/ui/videos/upload/*`), not AND-129. Keep AND-129 listed in `depends_on` for sibling alignment but treat it as soft. The backlog `Deps: AND-129` is reinterpreted accordingly (flagged in §16).
- **Blocked by AND-023 (media)** — the media-capable host/nav context this `/messages/video-share` route attaches to.
- **Needs AND-166** (Media3 `PlayerManager`) for true inline playback; degrade path (§7) lets this ticket land and pass non-playback tests before AND-166, with the inline-play smoke test enabled once AND-166 merges.
- **Coordinates with AND-130** (Image messages) — share the picker/preview/compose-bar patterns and the message `kind` discriminator; align field names to avoid mapper divergence.
- **Feeds AND-128** (messaging core tests) — add video cases there or keep them feature-local; no circular block.
- Sequencing: implement ViewModel + upload wiring + composer first (testable via MockWebServer), then inline player cell, then share intent, then enable instrumented smoke.

## 13. Risks & Open Questions

- **Q1: RESOLVED.** Yes — there is a dedicated `POST /messaging/conversations/{conversation_id}/messages/video-share` (op `create_video_share_message_…`, req `CreateVideoShareMessageIn`, resp `MessageOut`). It is **not** `kind="video"` on a generic post and does **not** use the AND-129 attachment presign. The message kind is `video_share` and the body is `{ video_id, text?, send_at? }`.
- **Q2: RESOLVED.** The poster is **server-generated**: the `video_share` object returns `thumbnail_url`; the client neither uploads nor sends a poster for the share. (The client only extracts a local preview frame for the optional FR-1b upload UX, not for the message.)
- **Q3: RESOLVED (playback) / OPEN (external share).** Playback uses an **expiring** tokenized HLS manifest (`hls_manifest_url` + `playback_token` + `playback_expires_at`) — so the token must not be persisted/shared and must be refreshed on expiry. For *external* share there is no exposed permanent public URL field; the canonical share-link form is an **open assumption** (§16).
- **Q4: PARTIALLY RESOLVED.** For FR-1b uploads, the server limit is authoritative: `VideoUploadPresignIn.file_size_bytes` max **10 GiB** and `VideoUploadPresignOut.max_size_bytes`. There is **no** duration limit and **no** 100 MB/300 s limit in the API — the draft's client defaults were unverified and should be dropped/relaxed (§16). Library-share (FR-1) has no client limits at all.
- **Risk:** Dev host flakiness on large PUTs (~20s timeout) may cause frequent upload failures; mitigated by clear retry UX, not auto-retry of the PUT.
- **Risk:** Inline player leaks during fast paging/scroll; mitigated by single-player reuse + lifecycle/visibility release (covered by tests).
- **Deferred:** in-app video capture, trimming, HLS adaptive message video, full-screen player — out of scope, future epic E23 tickets.

## 14. Acceptance Criteria

AC-1. User can open the video-library picker in a conversation, see their published videos (thumbnail/title/duration), and select one; optional caption text may be added. (For the optional FR-1b fresh-upload path, an invalid file by MIME/size is rejected with a specific message before upload.)
AC-2. The picker/preview shows the server `thumbnail_url` + duration (library-share); for FR-1b, a local poster + determinate upload progress + working cancel.
AC-3. On send, the client posts `POST /messaging/conversations/{conversation_id}/messages/video-share` with `{ video_id, text? }`, carrying `Authorization: Bearer …` + `X-CSRF-Token` + session cookie; for FR-1b the storage `PUT` carries **none** of those app-auth headers/cookies.
AC-4. After a successful post, a `kind="video_share"` message appears in the conversation for the sender (and on reload for the recipient), populated from the returned `video_share` object.
AC-5. **A video message plays inline** in the bubble on tap (thumbnail → play → in-bubble **HLS** playback via `hls_manifest_url`+`playback_token`) with play/pause, scrubber, time, and mute — satisfying the backlog acceptance "Video sends and plays inline."
AC-6. Only one inline player is active at a time; scrolling the player off-screen pauses/releases it; lifecycle stop releases it.
AC-7. Post/upload failure offers retry/discard; playback failure shows a retry-from-poster state (re-fetching a fresh `playback_token` when expired).
AC-8. Degraded mode (no Media3/HLS support, or `drm_enabled=true`) shows poster + "Open externally" without crashing.
AC-9. Share action sends a canonical non-expiring video link (derived from `video_id`, **not** the tokenized manifest URL) via `ACTION_SEND`.
AC-10. Unit + MockWebServer + Compose tests pass headlessly; the HLS inline-play smoke passes once AND-166 is integrated.

## 15. Definition of Done

- All §14 acceptance criteria met and demonstrated.
- Code merged to `android-port` under `com.testlogon.android.feature.messages.video` with the route registered in the messages nav graph.
- Media3 **HLS** support (`androidx.media3:media3-exoplayer-hls`) present (via AND-166 or added here); no other new Gradle dependencies; cleartext restricted to the dev host via scoped `network_security_config`.
- Strings externalized; controls have content descriptions; dark/RTL verified.
- Telemetry events emitted with opaque ids only; no secrets/URLs logged.
- Tests added to `core-testing` (fakes) and `feature-messages`; CI green headlessly; the inline-play instrumented smoke gated/enabled per AND-166 availability.
- Open questions Q1–Q4 either resolved against `/openapi.json` + web reference, or filed as follow-up tickets with the chosen interim assumption documented.
- Code review approved; no TODOs left in shipped paths.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Endpoint for sending a video-share message is `POST /messaging/conversations/{conversation_id}/messages/video-share`.** — **Corrected** (draft said `POST /messages/threads/{thread_id}/messages` with `kind="video"`). Source: OpenAPI `POST /messaging/conversations/{conversation_id}/messages/video-share` (op `create_video_share_message_…`, req `CreateVideoShareMessageIn`, resp `200:MessageOut`); `src/api/endpoints/messaging.ts: sendVideoShareMessage`.
2. **Request body is `{ video_id (required), text?, send_at? }` — no `attachment_id`/`poster_url`/`duration_ms`/`width`/`height`.** — **Corrected**. Source: schema `CreateVideoShareMessageIn` (`components.schemas.CreateVideoShareMessageIn`); `src/api/endpoints/messaging.ts: SendVideoShareReq`.
3. **The shared message references an existing library video by `video_id`; the picker lists the user's published videos via `GET /ui/videos?status=published`.** — **Corrected/Verified** (draft assumed device-local file pick). Source: `src/pages/messages/VideoPickerDialog.tsx` (`listMyVideos({status:"published"})`); OpenAPI `GET /ui/videos` (op `list_own_videos_…`, resp `VideoListOut`); `src/api/endpoints/videos.ts: listMyVideos`, `VideoListItem`.
4. **Message kind is `video_share` (not `video`); read shape carries a `video_share` object with `video_id, owner_user_id, title, thumbnail_url, duration_seconds, width, height, visibility, drm_enabled, hls_manifest_url, playback_token, playback_expires_at`; `created_at` is an epoch number.** — **Corrected**. Source: `src/api/types.ts: Message` (kind union + `video_share` block, `created_at: number`); schema `MessageOut`.
5. **Inline playback uses HLS (`hls_manifest_url` + `playback_token` appended as `?token=`), not progressive MP4.** — **Corrected** (draft said messages are progressive MP4 and HLS is out of scope). Source: `src/pages/messages/VideoShareCard.tsx` (builds `manifestUrl` with `token=`, renders `MediaPlayer mode="vod"`); `src/api/types.ts: Message.video_share.hls_manifest_url`.
6. **Reads use `GET /messaging/conversations/{conversation_id}/messages` with `limit`/`before` params.** — **Corrected** (draft cited `GET /messages/threads/{thread_id}/messages`). Source: OpenAPI `GET /messaging/conversations/{conversation_id}/messages` (op `list_messages_…`, params `limit,before,...`).
7. **Fresh device-local upload (optional FR-1b) uses the VOD pipeline: `POST /ui/videos/upload/presign` → PUT → `POST /ui/videos/upload/complete`, yielding a `video_id`.** — **Corrected/Verified** (draft used AND-129 `/messages/attachments/presign|confirm`, which do not exist). Source: OpenAPI `POST /ui/videos/upload/presign` (req `VideoUploadPresignIn`, resp `VideoUploadPresignOut`) and `POST /ui/videos/upload/complete` (req `VideoUploadCompleteIn`); `src/api/endpoints/videos.ts: presignVideoUpload`, `completeVideoUpload`.
8. **VOD presign size limit is server-authoritative: `file_size_bytes` max 10 GiB; response `max_size_bytes`. No API duration limit.** — **Corrected** (draft asserted 100 MB / 300 s client limits). Source: schema `VideoUploadPresignIn.file_size_bytes` (`maximum: 10737418240`), `VideoUploadPresignOut.max_size_bytes`.
9. **AND-129 messages-attachment pipeline does not exist as the draft described (`/messages/attachments/presign`, `/messages/attachments/{id}/confirm`).** — **Corrected**: no such paths in the OpenAPI index. The closest real per-file message upload is `POST /messaging/conversations/{conversation_id}/images/presign` (req `SendImagePresignIn` → `PresignOut`), used by `onSendVideoAttachment`/`kind="video"` — a *different* message kind, out of scope for `video-share`. Source: OpenAPI index grep for `attachment`/`presign`; `src/api/endpoints/messaging.ts` (images/presign).
10. **Auth: web client sends `Authorization: Bearer <accessToken>` + `X-CSRF-Token` (from `ui_csrf` cookie) + session cookies (`credentials:"include"`); OpenAPI also declares `X-SESSION-ID`.** — **Corrected** (draft said cookie+CSRF only, omitting Bearer + X-SESSION-ID). Source: `src/api/client.ts` (lines ~157–171, 183); OpenAPI params on `…/video-share` (`authorization, X-SESSION-ID`).
11. **On 401 (authenticated user), client calls `POST /ui/session/refresh` once, retries; second 401 logs out.** — **Verified**. Source: `src/api/client.ts: refreshSession` + 401 branch (lines ~119–225).
12. **The presigned storage PUT must not carry app session cookies/auth.** — **Verified** (concept holds for the VOD PUT). Source: `src/api/endpoints/messaging.ts: uploadToPresignedUrl` (raw `fetch`, no `api` wrapper) / videos upload pattern.
13. **422 errors follow FastAPI `HTTPValidationError` (`detail: [{loc,msg,type}]`); other 4xx may be `{detail: string}`.** — **Verified**. Source: OpenAPI `HTTPValidationError` schema (resp `422` on these ops); `src/api/client.ts: normalizeErrorDetail`.
14. **Lifecycle-aware single-player reuse / Media3 ExoPlayer** for inline playback. — **Verified (design intent, depends on AND-166)** for the wrapper; **framework ref** for the engine: Media3 ExoPlayer lifecycle + HLS — https://developer.android.com/media/media3/exoplayer/hls and https://developer.android.com/media/media3/ui/compose .
15. **Android Photo Picker (`PickVisualMedia`) / SAF for FR-1b file selection on API 34/35.** — **framework ref**: https://developer.android.com/training/data-storage/shared/photopicker .
16. **`ACTION_SEND` for outbound share.** — **framework ref**: https://developer.android.com/training/sharing/send .

### Corrections made

- §1/§5/§14: send endpoint `messages/threads/{thread_id}/messages` (`kind="video"`, attachment_id) → **`/messaging/conversations/{conversation_id}/messages/video-share`** with `{video_id,text?,send_at?}`, kind `video_share` (claims 1, 2, 4, 6).
- §1/§3: device-local-file-pick + AND-129 presign→PUT→confirm model → **library-share by `video_id`** (primary) plus a corrected VOD-pipeline fresh-upload variant (claims 3, 7, 9).
- §1/§4/§5/§7: progressive-MP4 / `videoUrl` playback → **HLS `hls_manifest_url` + `playback_token`** with token-refresh-on-expiry handling (claim 5).
- §2/§7/§8/§14: auth model expanded to Bearer + X-CSRF-Token + cookies (+X-SESSION-ID) (claim 10).
- §3/§13: dropped the unverified 100 MB / 300 s limits; server `max_size_bytes` (10 GiB cap) is authoritative (claim 8).
- §6: corrected Room/UI field names to `thumbnail_url`/`duration_seconds`/`hls_manifest_url`/etc.; added do-not-persist-`playback_token` rule.
- §12: AND-129 downgraded from hard to soft dependency for this route.

### Open assumptions (unverifiable from the provided sources)

- **Canonical external-share URL form.** No public, non-expiring share-URL field is exposed by the API for a shared video; FR-10/AC-9 assume a `video_id`-derived in-app deep link. *Why unverifiable:* no such field in `MessageOut`/`video_share`/`videos.ts`; needs a backend/product decision or a follow-up ticket.
- **`VideoUploadCompleteIn` exact field set.** Web `completeVideoUpload` passes `ticket_id` + `key` (deprecating the `videoId`-path form); the precise schema fields were not fully expanded here. *Why:* not read in full — confirm `components.schemas.VideoUploadCompleteIn` at implementation.
- **Whether messaging permits sharing videos the user does not own.** The picker only lists `listMyVideos`; whether the endpoint accepts an arbitrary `video_id` (e.g. another creator's published video) is unverified. *Why:* not stated in the OpenAPI description or frontend.
- **`drm_enabled=true` playback support.** The field exists; whether Media3 must integrate a DRM/license flow is undefined in the sources. Treated as a degraded "open externally" case pending clarification.
- **Backlog `Deps: AND-129`.** The backlog lists AND-129, but the verified contract does not use the AND-129 attachment pipeline. *Why:* reconciliation is a planning decision; documented as soft dep.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **emulator** = headless AVD `test35` (x86_64, API 35); **device** = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a). Hardware/codec/ABI-sensitive cases prefer **device**.

- **TC-AND-131-01 — Library picker lists published videos** · Type: contract/MockWebServer · Target: JVM · Preconditions: MockWebServer returns `VideoListOut` with 2 published items. · Steps: open share-video action → ViewModel/picker queries `GET /ui/videos?status=published`. · Expected: request path+`status=published` query correct; both items rendered with `thumbnail_url`/`title`/`duration_seconds`; empty list shows "No shareable videos". · Traces: AC-1.

- **TC-AND-131-02 — Send video-share happy path (body + auth)** · Type: contract/MockWebServer · Target: JVM · Preconditions: a `video_id` selected; MockWebServer returns `MessageOut` (kind `video_share`). · Steps: `onSend()` posts. · Expected: `POST /messaging/conversations/{cid}/messages/video-share`; JSON body is exactly `{ "video_id": "...", "text": "..."? }` (no attachment/poster/dimensions); headers include `Authorization: Bearer …` and `X-CSRF-Token`; state → `Sent`. · Traces: AC-3, AC-4.

- **TC-AND-131-03 — Posted message maps to UI from `video_share` object** · Type: unit (mapper) · Target: JVM · Preconditions: a `MessageOut` JSON with full `video_share` block (`created_at` epoch number, `hls_manifest_url`, `playback_token`, `duration_seconds`, `width/height`, `drm_enabled:false`). · Steps: map to `VideoMessageUi`. · Expected: all fields mapped; `created_at` parsed as epoch; aspect ratio = width/height; HLS URL + token retained; no crash on absent optional fields. · Traces: AC-4, AC-5.

- **TC-AND-131-04 — Inline HLS playback plays on tap** · Type: instrumented/e2e · Target: **device** (then emulator smoke) · Preconditions: a `video_share` cell with a valid HLS manifest + token (test stream); real `PlayerManager` (AND-166). · Steps: tap poster. · Expected: player attaches, HLS `MediaItem` built from `hls_manifest_url?token=…`, playback starts in-bubble with play/pause + scrubber + time + mute; frames render. **Must run on device** to validate arm64 HLS codec/decoder behavior (API 34) vs emulator (API 35). · Traces: AC-5, AC-10.

- **TC-AND-131-05 — Single-player reuse + scroll/lifecycle release** · Type: Compose-UI / instrumented · Target: emulator (logic), device (real release) · Preconditions: two `video_share` cells; fake then real `PlayerManager`. · Steps: play cell A, then play cell B; scroll A off-screen; send app to background (`ON_STOP`). · Expected: only one active player at a time (A releases when B starts); scrolling off-screen pauses+releases; `ON_STOP` releases; no leak across paging. · Traces: AC-6.

- **TC-AND-131-06 — Validation 422 on bad video_id** · Type: contract/MockWebServer · Target: JVM · Preconditions: MockWebServer returns `422 HTTPValidationError` (`detail:[{loc,msg,type}]`) for empty/invalid `video_id`. · Steps: `onSend()`. · Expected: decoded `detail[].msg` surfaced; state `Failed(canRetry=false)`; no crash on the `detail` array shape. · Traces: AC-7.

- **TC-AND-131-07 — Flaky dev host: 5xx/timeout on post → retryable** · Type: contract/MockWebServer · Target: JVM · Preconditions: MockWebServer returns 503 then 200; client ~20s timeout. · Steps: `onSend()`, then user taps retry. · Expected: first attempt → `Failed(canRetry=true)`; retry re-posts and succeeds; the small JSON post is **not** auto-retried silently (user-initiated). · Traces: AC-7.

- **TC-AND-131-08 — 401 → refresh once → retry** · Type: contract/MockWebServer · Target: JVM · Preconditions: authenticated; post returns 401, `POST /ui/session/refresh` returns 200, retried post returns 200. · Steps: `onSend()`. · Expected: exactly one `/ui/session/refresh` call, then one retry that succeeds; a second 401 would trigger logout (assert single-refresh). · Traces: AC-3, AC-7.

- **TC-AND-131-09 — FR-1b fresh upload: presigned PUT carries no app auth** · Type: contract/MockWebServer · Target: JVM · Preconditions: MockWebServer for `POST /ui/videos/upload/presign` (→ `VideoUploadPresignOut`), a second server for the presigned PUT, and `POST /ui/videos/upload/complete`. · Steps: pick local file → presign → PUT → complete → share. · Expected: presign/complete carry Bearer+CSRF; the **PUT to `upload_url` carries NO `Authorization`/`X-CSRF-Token`/session cookie**; resulting `video_id` is posted to `video-share`. · Traces: AC-3.

- **TC-AND-131-10 — Playback error: expired playback_token recovers** · Type: integration / instrumented · Target: emulator (mock) + device (real) · Preconditions: a cell whose `playback_expires_at` is in the past (or manifest returns 403). · Steps: tap play → `onPlayerError` → tap retry. · Expected: cell shows "Couldn't play video"; retry **re-fetches the message** to obtain a fresh `hls_manifest_url`/`playback_token`, then re-prepares and plays (a stale token alone is not re-prepared). · Traces: AC-7.

- **TC-AND-131-11 — Degraded mode (no Media3/HLS or drm_enabled) → Open externally** · Type: Compose-UI · Target: emulator (Robolectric) · Preconditions: `PlayerManager` unavailable, or `video_share.drm_enabled=true`. · Steps: render cell, tap poster. · Expected: poster + "Open externally"; tapping fires `ACTION_VIEW`; no crash; no inline player attached. · Traces: AC-8.

- **TC-AND-131-12 — Outbound share sends canonical link, not tokenized manifest** · Type: Compose-UI / instrumented · Target: emulator · Preconditions: a `video_share` cell with `hls_manifest_url`+`playback_token`. · Steps: tap share. · Expected: `ACTION_SEND` (`text/plain`) chooser fires; shared text is a `video_id`-derived canonical link and **does not contain** `playback_token` or the raw tokenized manifest URL; no cookies/file paths leaked. · Traces: AC-9, (security).

- **TC-AND-131-13 — Offline behavior** · Type: integration · Target: device (real radio toggle) or emulator (airplane mode) · Preconditions: cached `video_share` message; network off. · Steps: open conversation, tap play. · Expected: cached `thumbnail_url` renders; play shows offline state + retry; on reconnect, retry re-fetches token and plays. **Prefer device** to exercise real connectivity transitions. · Traces: AC-5, AC-7.

- **TC-AND-131-14 — Accessibility of player + controls** · Type: Compose-UI (accessibility) · Target: emulator · Preconditions: a `video_share` cell. · Steps: run a11y assertions / TalkBack semantics tree. · Expected: poster has `Role.Button` + "Play video, <duration>"; play/pause, mute, scrubber, share, retry have `contentDescription`s; touch targets ≥ 48dp; scrubber exposes `Slider` semantics with current/total time; state changes announced via `liveRegion`. · Traces: AC-5, AC-6 (and §9).

#### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 | TC-01 |
| AC-2 | TC-01 (library thumb/duration); TC-09 (FR-1b preview/upload) |
| AC-3 | TC-02, TC-08, TC-09 |
| AC-4 | TC-02, TC-03 |
| AC-5 | TC-03, TC-04, TC-13, TC-14 |
| AC-6 | TC-05, TC-14 |
| AC-7 | TC-06, TC-07, TC-08, TC-10, TC-13 |
| AC-8 | TC-11 |
| AC-9 | TC-12 |
| AC-10 | TC-04 (and the full JVM/Compose suite running headlessly: TC-01,02,03,06,07,08,09,11) |
