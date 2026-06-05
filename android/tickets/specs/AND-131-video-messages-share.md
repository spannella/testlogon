---
id: AND-131
title: Video messages / share
milestone: M3
epic: E19
priority: P1
size: M
status: draft
depends_on: [AND-129, AND-023]
blocks: []
---

# AND-131 — Video messages / share

## 1. Overview & Goal

Add the ability to attach a video to a message in a TestLogon conversation thread, upload it through the reusable attachment pipeline, and play it back **inline** inside the message bubble without leaving the thread. This ticket sits in the Messaging epic (E19) and is the video counterpart to AND-130 (Image messages).

Concretely, a user composing a message in a thread can pick a video from the device (gallery / document picker), see a local preview with an upload-progress affordance, send it, and have the resulting message render an inline video player that plays on tap. Other participants who load the thread see the same inline player backed by the server-hosted media URL.

The single acceptance bar from the backlog is: **"Video sends and plays inline."** Everything below decomposes that into implementation-ready requirements. This ticket owns the video-specific compose/attach UX (`/messages/video-share`), the message-payload wiring, and the inline player composable. It explicitly **reuses** the upload mechanics from AND-129 (presign → PUT → confirm) and the playback engine from the Media3 layer (AND-166) rather than re-implementing either.

Out of scope: in-app recording/capture of new video (camera capture is image-only per AND-130; video capture is a future enhancement, see §13), HLS adaptive streaming for messages (messages are progressive MP4; HLS lives in the streaming epic E23), transcoding, trimming/editing, and full-screen immersive playback (deferred; inline only).

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, Android app under `android/`, branch `android-port`. New code lands in `feature-messages` with shared building blocks in `core-data`, `core-network`, `core-model`, and `core-ui`.
- **Namespace:** all packages under `com.testlogon.android`. Feature code under `com.testlogon.android.feature.messages.video`.
- **Dependencies (authoritative, from backlog):**
  - **AND-129** — Attachment pipeline (presign→PUT→confirm). Provides `AttachmentUploader` with progress + cancel + retry. This ticket consumes it; it does not own upload transport.
  - **AND-023 (media)** — the media-capable navigation/host context this share route is wired into. The inline player engine itself is provided by **AND-166** (Media3/ExoPlayer `PlayerManager`, lifecycle-aware single-player reuse); this ticket depends on that wrapper being available and degrades gracefully if Media3 is absent (see §7).
- **Related (not blocking):** AND-130 (Image messages — sibling pattern for pick/compress/thumbnail/viewer), AND-128 (Messaging core tests), AND-280/AND-166/AND-167 (streaming/playback engine).
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable; ~20s timeouts, bounded backoff retry for idempotent GETs only). OpenAPI at `/openapi.json`. Web reference: `frontend/src/api/endpoints/*.ts`, `frontend/src/api/types.ts`.
- **Auth:** cookie-based session + `ui_csrf` cookie echoed as `X-CSRF-Token`; persistent cookie jar; on 401, `POST /ui/session/refresh` once then retry. All endpoints here are session-protected.

## 3. Functional Requirements

FR-1. From the thread compose bar, a "video" attach action opens the system video picker (`ActivityResultContracts.PickVisualMedia` with `VideoOnly`, fallback `GetContent("video/*")` on minSdk 24 devices lacking Photo Picker).

FR-2. After selection, the app validates the candidate: MIME must be `video/*` (whitelist `video/mp4`, `video/webm`, `video/3gpp`, `video/quicktime`); size must be ≤ configurable max (default **100 MB**); duration must be ≤ configurable max (default **300 s**). Validation failures show an inline error and abort before any upload.

FR-3. A local preview renders immediately (a frame thumbnail extracted via `MediaMetadataRetriever` plus a play-overlay glyph and duration badge) with a determinate upload-progress indicator and a **cancel** control.

FR-4. On send, the video is uploaded via the AND-129 pipeline (presign → PUT → confirm). The compose action is disabled until upload reaches a terminal state (confirmed or failed/cancelled).

FR-5. A failed upload offers **retry** (reusing the same local URI) and **cancel/discard**. Cancel removes the pending attachment from the composer.

FR-6. On successful confirm, a message of kind `video` is posted to the thread carrying the confirmed attachment id/URL, duration, dimensions, and poster (thumbnail) URL.

FR-7. In the thread list, a `video` message renders an **inline player surface**: poster image + play button initially; tapping play attaches the shared Media3 player and begins playback inline within the bubble. Only one inline player is active at a time (reuse the AND-166 single-player constraint).

FR-8. Playback exposes play/pause, a scrubber, current/total time, and a mute toggle. Audio defaults to **muted** on first autostart-by-tap is not used; playback is user-initiated and starts **unmuted** on explicit tap. Scrolling the player off-screen pauses and releases it.

FR-9. The player is lifecycle-aware: it pauses on `ON_PAUSE` and releases on `ON_STOP`/composable disposal.

FR-10. A "share" affordance on a sent/received video message lets the user share the video's URL out of the app via `Intent.ACTION_SEND` (text/plain URL). (The `/video-share` route name covers both intra-thread send and this outbound share.)

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

`InlineVideoPlayer` shows `AsyncImage(posterUrl)` + play overlay until tapped, then calls `playerManager.attach(playerView, MediaItem.fromUri(message.videoUrl))`. A `DisposableEffect` releases on dispose; an `onGloballyPositioned`/visibility observer pauses when scrolled out of the viewport.

Upload flow inside `onSend()` reuses AND-129:

```kotlin
uploader.upload(
    AttachmentRequest(
        uri = draft.localUri,
        mimeType = draft.mimeType,
        kind = AttachmentKind.VIDEO,
    )
).collect { ev -> /* map to Uploading.progress / Failed / confirmedId */ }
```

Module placement: route + composables + ViewModel in `feature-messages`; `VideoMetadataExtractor` and `VideoMessageUi` mapping in `core-data`/`core-model`; reused `AttachmentUploader`/`PlayerManager` are injected interfaces. No new Gradle dependency is added by this ticket (Media3 and OkHttp/Retrofit/Coil already present).

## 5. API Contract

This ticket does **not** define new transport — it composes two existing surfaces:

**(a) Attachment upload (owned by AND-129).** Presign → PUT → confirm. Shapes used here:

```
POST /messages/attachments/presign
X-CSRF-Token: <ui_csrf>
{ "filename": "clip.mp4", "content_type": "video/mp4",
  "size_bytes": 7340032, "kind": "video" }
→ 200
{ "attachment_id": "att_01H...", "upload_url": "https://.../put?...",
  "method": "PUT", "headers": { "Content-Type": "video/mp4" },
  "expires_in": 900 }

PUT <upload_url>   (raw bytes; not session-cookie protected; storage-signed)
→ 200/204

POST /messages/attachments/{attachment_id}/confirm
X-CSRF-Token: <ui_csrf>
{ "duration_ms": 42000, "width": 1280, "height": 720,
  "poster_attachment_id": "att_01H...thumb" }
→ 200 { "attachment_id": "...", "url": "https://.../clip.mp4",
        "poster_url": "https://.../thumb.jpg", "status": "ready" }
```

The poster frame may itself be uploaded as a second attachment (image) via the same pipeline before confirm; if the backend generates server-side posters, `poster_attachment_id` is omitted and `poster_url` is read from the confirm response.

**(b) Post message (owned by messaging core, AND-12x).** This ticket adds the `video` body variant:

```
POST /messages/threads/{thread_id}/messages
X-CSRF-Token: <ui_csrf>
{ "kind": "video",
  "attachment_id": "att_01H...",
  "poster_url": "https://.../thumb.jpg",
  "duration_ms": 42000, "width": 1280, "height": 720 }
→ 201 { "id": "msg_...", "kind": "video", "video_url": "https://.../clip.mp4",
        "poster_url": "...", "duration_ms": 42000, "created_at": "..." }
```

Reads use the existing thread fetch (`GET /messages/threads/{thread_id}/messages`, Paging 3). Exact field names are confirmed against `/openapi.json` and `frontend/src/api/types.ts` during implementation; a mapper isolates drift. Error envelope follows the FastAPI `detail` convention (string | `[{msg}]` | `{code,...}`) via the shared `ApiResult<T>` decoder.

## 6. Data & State Management

- **UI state:** single `StateFlow<VideoShareUiState>` per §4; thread cells derive `VideoMessageUi(videoUrl, posterUrl, durationMs, aspectRatio, isOutgoing)` from the message model.
- **No new Room entity is required for the draft.** The in-flight draft lives in ViewModel state. Confirmed video messages are cached by the existing Room message DAO (AND-12x); this ticket only adds the `kind="video"` columns/fields (`video_url`, `poster_url`, `duration_ms`, `width`, `height`) to the message cache mapping — additive, with a Room migration if the messages table predates them.
- **Poster cache:** the locally extracted frame is written to app cache dir (`cacheDir/video-posters/<hash>.jpg`) and loaded by Coil; remote `poster_url` is loaded by Coil with normal HTTP caching.
- **DataStore:** validation limits (`max_video_bytes`, `max_video_duration_ms`, `allowed_video_mimes`) read from a feature-config DataStore key with the defaults in §3; no per-user prefs added.
- **Paging:** unchanged — video cells participate in the existing `PagingData<MessageUi>` thread stream. Player attach/detach is keyed on the visible item key so recomposition during paging does not leak players.

## 7. Error Handling & Resilience

- **Validation errors** (size/duration/MIME) surface as `Failed(canRetry=false)` with a specific message; user re-picks.
- **Upload errors** map from AND-129 events: network timeout (~20s), 4xx (e.g., expired presign → re-presign once then surface), 5xx (dev host flakiness → `Failed(canRetry=true)`). Cancel cooperatively cancels the upload coroutine and aborts the PUT.
- **PUT is not retried automatically** (non-idempotent multipart-ish body); confirm and presign GET-equivalent steps may use bounded backoff. Only idempotent GETs (thread reload) use the global retry policy.
- **401 during presign/confirm/post:** the OkHttp authenticator performs `POST /ui/session/refresh` once and retries; persistent cookie jar preserved.
- **Playback errors:** `Player.Listener.onPlayerError` (e.g., unsupported codec, network) flips the cell to a retry/poster state with a "Couldn't play video" message and a tap-to-retry that re-`prepare()`s the `MediaItem`.
- **Media3 absent / `PlayerManager` unavailable:** inline cell degrades to poster + "Open externally" (`ACTION_VIEW` on `video_url`). This keeps the thread usable if AND-166 ships late.
- **Stale/offline:** cached video messages render poster from cache; play attempt while offline shows offline state and offers retry when connectivity returns.

## 8. Security & Privacy

- All app→backend calls carry session cookies + `X-CSRF-Token` from the `ui_csrf` cookie; the storage `PUT` uses only the storage-signed URL and must **not** attach session cookies (separate OkHttp call/tag so the cookie jar interceptor is bypassed for the presigned host).
- Dev backend is plaintext HTTP; cleartext is permitted only for the dev host via a scoped `network_security_config` (no app-wide cleartext). Presigned storage URLs are expected to be HTTPS; reject non-HTTPS presign URLs in non-debug builds.
- Local video URIs are accessed via `contentResolver` with the picker-granted read permission; no broad `READ_EXTERNAL_STORAGE` is requested (Photo Picker / SAF scoped access on minSdk 24+).
- Poster frames cached in app-private `cacheDir` (not world-readable). Extracted metadata stays on-device until confirm.
- Outbound **share** sends only the video URL (text/plain), never local file paths or cookies. If the URL is a signed/expiring URL, the share dialog notes nothing extra — the URL is the server-authorized share token.
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
  - Presign→PUT→confirm→post happy path fully mocked with MockWebServer, asserting `X-CSRF-Token` present on app calls and **absent** on the presigned PUT, and that `kind="video"` body fields match §5.
  - 401 → refresh-once → retry succeeds (one refresh only).
- **Mapper tests:** confirm/post JSON → `VideoMessageUi`, including FastAPI `detail` error variants.
- **Compose UI tests (Robolectric/`createAndroidComposeRule`):**
  - Composer shows preview + progress + cancel; cancel returns to `Empty`.
  - Thread cell shows poster + play; tap shows player surface (player attach faked via test double of `PlayerManager`).
  - Degraded mode (no `PlayerManager`) shows "Open externally".
- **Instrumented (1 smoke):** progressive MP4 plays inline using the real `PlayerManager`, mirroring AND-166's progressive-MP4 acceptance, to satisfy "plays inline" end-to-end. Runs headlessly per AND-128 expectations.
- A fake `AttachmentUploader` (flow of progress events) and a fake `PlayerManager` are added to `core-testing`.

## 12. Dependencies & Sequencing

- **Blocked by AND-129** (uploader) — hard dependency; mock the interface to develop in parallel, integrate when merged.
- **Blocked by AND-023 (media)** — the media-capable host/nav context this `/messages/video-share` route attaches to.
- **Needs AND-166** (Media3 `PlayerManager`) for true inline playback; degrade path (§7) lets this ticket land and pass non-playback tests before AND-166, with the inline-play smoke test enabled once AND-166 merges.
- **Coordinates with AND-130** (Image messages) — share the picker/preview/compose-bar patterns and the message `kind` discriminator; align field names to avoid mapper divergence.
- **Feeds AND-128** (messaging core tests) — add video cases there or keep them feature-local; no circular block.
- Sequencing: implement ViewModel + upload wiring + composer first (testable via MockWebServer), then inline player cell, then share intent, then enable instrumented smoke.

## 13. Risks & Open Questions

- **Q1:** Does the backend expose a dedicated `/messages/video-share` endpoint, or is video just `kind="video"` on the generic message-post + AND-129 presign? Spec assumes the latter; confirm against `/openapi.json` and `frontend/src/api/endpoints`.
- **Q2:** Server-generated posters vs client-uploaded poster frame — which is authoritative? Spec supports both; need backend answer to drop the client poster upload.
- **Q3:** Are message video URLs permanent or signed/expiring? Affects Coil/player caching and the share affordance (expiring URLs make external share fragile).
- **Q4:** Max size/duration limits — confirm backend-enforced limits so client defaults (100 MB / 300 s) match and we fail fast.
- **Risk:** Dev host flakiness on large PUTs (~20s timeout) may cause frequent upload failures; mitigated by clear retry UX, not auto-retry of the PUT.
- **Risk:** Inline player leaks during fast paging/scroll; mitigated by single-player reuse + lifecycle/visibility release (covered by tests).
- **Deferred:** in-app video capture, trimming, HLS adaptive message video, full-screen player — out of scope, future epic E23 tickets.

## 14. Acceptance Criteria

AC-1. User can pick a video from the system picker in a thread; invalid videos (MIME/size/duration) are rejected with a specific message before any upload.
AC-2. A picked video shows a local poster + determinate upload progress + working cancel.
AC-3. On send, the video uploads via the AND-129 presign→PUT→confirm pipeline; the presigned PUT carries **no** session cookie/CSRF header while app calls carry `X-CSRF-Token`.
AC-4. After confirm, a `kind="video"` message is posted and appears in the thread for sender (and on reload for recipient).
AC-5. **A video message plays inline** in the bubble on tap (poster → play → in-bubble playback) with play/pause, scrubber, time, and mute — satisfying the backlog acceptance "Video sends and plays inline."
AC-6. Only one inline player is active at a time; scrolling the player off-screen pauses/releases it; lifecycle stop releases it.
AC-7. Upload failure offers retry/discard; playback failure shows a retry-from-poster state.
AC-8. Degraded mode (no Media3) shows poster + "Open externally" without crashing.
AC-9. Share action sends the video URL via `ACTION_SEND`.
AC-10. Unit + MockWebServer + Compose tests pass headlessly; the progressive-MP4 inline-play smoke passes once AND-166 is integrated.

## 15. Definition of Done

- All §14 acceptance criteria met and demonstrated.
- Code merged to `android-port` under `com.testlogon.android.feature.messages.video` with the route registered in the messages nav graph.
- No new Gradle dependencies beyond those already in the stack; cleartext restricted to the dev host via scoped `network_security_config`.
- Strings externalized; controls have content descriptions; dark/RTL verified.
- Telemetry events emitted with opaque ids only; no secrets/URLs logged.
- Tests added to `core-testing` (fakes) and `feature-messages`; CI green headlessly; the inline-play instrumented smoke gated/enabled per AND-166 availability.
- Open questions Q1–Q4 either resolved against `/openapi.json` + web reference, or filed as follow-up tickets with the chosen interim assumption documented.
- Code review approved; no TODOs left in shipped paths.
