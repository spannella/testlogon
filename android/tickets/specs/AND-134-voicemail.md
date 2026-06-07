---
id: AND-134
title: Voicemail
milestone: M3
epic: E19
priority: P2
size: M
depends_on: [AND-133]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
---

# AND-134 — Voicemail

## 1. Overview & Goal

Implement the **Voicemail** feature for the TestLogon native Android app: when a call cannot be connected (missed / declined / busy), the caller may leave an asynchronous **audio or video** voicemail tied to that call, which the callee plays back inline in the conversation. Unlike inline voice messages (AND-133), voicemails are tied to a `call_id` and rendered as a distinct message **kind** (`kind: "voicemail"`) inside the conversation message stream — they are NOT a free-standing entity and do NOT live under a top-level `/voicemail` namespace.

> **REVIEW CORRECTION (see §16).** This spec was originally drafted against an assumed top-level `/voicemail` namespace with its own inbox, `recipient_id` addressing, `/voicemail/{id}/read`, and `DELETE /voicemail/{id}`. The authoritative OpenAPI + web reference show the real contract is **conversation-scoped and call-centric**: `POST /messaging/conversations/{conversation_id}/voicemail/presign` and `POST /messaging/conversations/{conversation_id}/voicemail`, both returning a `MessageOut` of `kind: "voicemail"`. There is **no** voicemail inbox endpoint, **no** `recipient_id` in the body, and **no** voicemail-specific read or delete endpoint. Sections below have been corrected inline; remaining vestigial "inbox" language is retained only where it still maps to the conversation message list, and flagged.

This ticket reuses the recording, waveform-capture, and presigned-upload machinery delivered by AND-133, but adds: (a) the voicemail send flow (presign → S3/object PUT → `POST .../voicemail`), (b) rendering received voicemails inline in the conversation thread (audio waveform player or video player) with a "Call back" affordance, and (c) the consume/seen lifecycle (via existing message view/consume endpoints, not a voicemail-specific one). The deliverable lives in a new `feature-voicemail` module and a `core-data` repository, with playback driven by Media3/ExoPlayer. **Video voicemail capture/playback is in scope** — the contract supports `mode: "audio" | "video"`.

**Done = a recorded audio/video clip can be uploaded via presign and sent as a voicemail in a conversation, and a received voicemail (kind=voicemail) renders inline and plays back correctly (send/play works).**

## 2. Context & References

- **Backlog:** AND-134 — Voicemail · Feature · P2 · Deps: AND-133. Scope: `/voicemail(+presign)` flow. Acceptance: *Voicemail send/play works.*
- **Upstream dependency AND-133 (Voice messages):** owns `AudioRecorder`, `WaveformCapture`, the `presign → S3 PUT → confirm` upload pipeline, and the shared `AudioPlayerController` over Media3. AND-134 consumes these as collaborators; it does **not** re-implement recording or waveform rendering.
- **Repo:** `spannella/testlogon`, branch `android-port`, app under `android/`. Web reference: the voicemail API lives in `src/api/endpoints/messaging.ts` (`presignVoicemail`, `createVoicemail`, `sendVoicemail`) — there is **no** `voicemail.ts`. Shared types in `src/api/types.ts` (`Message.voicemail` nested object). Screens: `src/pages/messages/VoicemailRecorder.tsx` (capture/send) and `src/pages/messages/VoicemailBubble.tsx` (inline playback). [CORRECTED — original referenced a nonexistent `voicemail.ts`.]
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. The voicemail endpoints are `POST /messaging/conversations/{conversation_id}/voicemail/presign` (`PresignVoicemailRequest`) and `POST /messaging/conversations/{conversation_id}/voicemail` (`CreateVoicemailRequest` → `MessageOut`). [CORRECTED — there is no top-level `/voicemail`.]
- **Module layering:** `app -> feature-voicemail -> core-{network,model,data,ui,testing}`. ViewModels expose `StateFlow<UiState>`; all network returns typed `ApiResult<T>`.
- **Auth:** cookie-based session with `X-CSRF-Token` echoed from the `ui_csrf` cookie; the OkHttp stack (persistent cookie jar + CSRF + single `/ui/session/refresh` retry on 401) is shared infrastructure and is assumed present.

## 3. Functional Requirements

FR-1 **Record & send.** Within a conversation, after a missed/declined/busy call, the caller records **audio or video** (via AND-133 `AudioRecorder` for audio; camera capture for video — see FR-9), reviews it (duration + waveform/preview), and sends it. Sending performs: `POST .../voicemail/presign` (server returns `message_id`, `upload_url`, `s3_key`) → PUT bytes to `upload_url` → `POST .../voicemail` with `{message_id, call_id, s3_key, content_type, size_bytes, duration_seconds, waveform_data, mode}`. [CORRECTED — server pre-allocates `message_id` and `s3_key` at presign; the create body does NOT include `recipient_id`/`conversation_id` (conversation is in the path).]

FR-2 **Call/conversation addressing.** A voicemail is tied to a `conversation_id` (path) and a `call_id` (body). Both are passed into the feature via navigation args from the call/conversation context. There is **no** `recipient_id` field. [CORRECTED.]

FR-3 **Inline rendering (not a dedicated inbox).** Received voicemails are messages with `kind: "voicemail"` and appear inline in the conversation message stream (`GET /messaging/conversations/{conversation_id}/messages`, paged via `before` cursor). A voicemail bubble shows the call-state label ("Missed call"/"Call declined"/"Busy"), duration, waveform (audio) or video player, and a **Call back** action. [CORRECTED — there is no `GET /voicemail` inbox endpoint; "inbox" semantics map onto the conversation message list.]

FR-4 **Playback.** Tapping a voicemail bubble plays the audio (waveform player) or video through Media3/ExoPlayer with play/pause and a scrub bar; only one plays at a time. The media URL comes from `message.voicemail.audio_url` / `message.voicemail.video_url` (presigned, short-lived). Playing marks it consumed/seen (FR-6). [CORRECTED — field is `audio_url`/`video_url`, not `playback_url`.]

FR-5 **Re-send / discard before send.** Before upload the user may discard and re-record, or skip. After a failed upload the user may retry the send without re-recording (the local file + allocated `message_id`/`s3_key` are retained until success or explicit discard).

FR-6 **Seen/consumed state.** Voicemails carry the generic message consumption lifecycle (`consumption_policy` may be `listen_once`; `consumption_state` ∈ `pending|consumed|expired|failed`; `consumed_at`, `read_by_count`, `read_by_user_ids`). Marking seen uses existing **message** endpoints — `POST .../messages/{message_id}/view` (`ViewMessageIn` → `ViewAckOut`) and, for listen-once media, `POST .../messages/{message_id}/attachment/consume` (`ConsumeAttachmentIn` → `ConsumeAttachmentOut`) — and/or conversation-level `POST .../read`. [CORRECTED — there is NO `POST /voicemail/{id}/read`; UI may still optimistically flip local seen state.]

FR-7 **Offline/stale states.** Conversation history renders cached messages when offline (Room), with a stale banner; recording is allowed offline and the send is surfaced as failed-retryable (no background queue in this ticket — see Risks).

FR-8 **Deletion.** Deletion uses the generic message endpoints, NOT a voicemail-specific one: `DELETE /messaging/conversations/{conversation_id}/messages/{message_id}` (delete-for-me) or `DELETE .../messages/{message_id}/revoke` (revoke-for-all). Support swipe-to-delete on the bubble with optimistic removal + undo where allowed. [CORRECTED — `DELETE /voicemail/{id}` does not exist.]

FR-9 **Video voicemail.** Because the contract supports `mode: "video"`, the feature must handle video capture (camera + mic) and inline video playback, in addition to audio. Audio is the default mode. [ADDED — required by the contract; original spec omitted video entirely.]

## 4. Technical Design

### Module & package layout
All packages under `com.testlogon.android`.

```
feature-voicemail/
  com.testlogon.android.feature.voicemail
    VoicemailInboxScreen.kt        // @Composable inbox list
    VoicemailComposeScreen.kt      // record + review + send
    VoicemailPlayerBar.kt          // play/pause + scrub (wraps AudioPlayerController)
    VoicemailInboxViewModel.kt
    VoicemailComposeViewModel.kt
    nav/VoicemailNavigation.kt     // routes & NavGraphBuilder ext
core-data/
  com.testlogon.android.core.data.voicemail
    VoicemailRepository.kt
    VoicemailRepositoryImpl.kt
    VoicemailUploader.kt           // presign -> PUT -> POST orchestration
core-network/
  com.testlogon.android.core.network.voicemail
    VoicemailApi.kt                // Retrofit interface
core-model/
  com.testlogon.android.core.model.voicemail
    Voicemail.kt, VoicemailDraft.kt, PresignRequest.kt, PresignResponse.kt
```

### Navigation
[CORRECTION] There is no standalone voicemail inbox; the "inbox" route below should be understood as a filtered view over the conversation message list, and the compose route takes `conversationId` + `callId` (not a `recipientId`). The original `recipientId` arg is replaced by `callId`; entry is from the post-call (missed/declined/busy) prompt within a conversation. Single-Activity Navigation-Compose. Routes:

```kotlin
object VoicemailRoutes {
    const val INBOX = "voicemail/inbox"
    const val COMPOSE = "voicemail/compose/{recipientId}?conversationId={conversationId}"
    fun compose(recipientId: String, conversationId: String? = null): String
}

fun NavGraphBuilder.voicemailGraph(nav: NavController)
```

### Retrofit interface
[CORRECTED] All paths are conversation-scoped; list/read/delete reuse the generic message endpoints.
```kotlin
interface VoicemailApi {
    // Inline rendering reuses the conversation message list (kind=voicemail rows).
    @GET("messaging/conversations/{conversationId}/messages")
    suspend fun listMessages(
        @Path("conversationId") conversationId: String,
        @Query("limit") limit: Int = 30,
        @Query("before") before: String? = null,   // cursor param is `before`, not `cursor`
    ): Response<List<MessageDto>>                    // 200 body is an array (no wrapper schema)

    @POST("messaging/conversations/{conversationId}/voicemail/presign")
    suspend fun presign(
        @Path("conversationId") conversationId: String,
        @Body body: PresignVoicemailRequest,        // {call_id, content_type, size_bytes, mode}
    ): Response<PresignVoicemailResponse>           // {message_id, upload_url, s3_key}

    @POST("messaging/conversations/{conversationId}/voicemail")
    suspend fun create(
        @Path("conversationId") conversationId: String,
        @Body body: CreateVoicemailRequest,         // see §5; returns MessageOut (kind=voicemail)
    ): Response<MessageDto>

    // "Mark read" = generic message view / listen-once consume — NOT a voicemail endpoint.
    @POST("messaging/conversations/{conversationId}/messages/{messageId}/view")
    suspend fun markViewed(
        @Path("conversationId") conversationId: String,
        @Path("messageId") messageId: String,
        @Body body: ViewMessageIn,
    ): Response<ViewAckOut>

    @POST("messaging/conversations/{conversationId}/messages/{messageId}/attachment/consume")
    suspend fun consumeOnce(
        @Path("conversationId") conversationId: String,
        @Path("messageId") messageId: String,
        @Body body: ConsumeAttachmentIn,            // {consumption_attempt_id, trigger, playback_seconds?}
    ): Response<ConsumeAttachmentOut>

    // Deletion reuses generic message delete/revoke.
    @DELETE("messaging/conversations/{conversationId}/messages/{messageId}")
    suspend fun deleteForMe(
        @Path("conversationId") conversationId: String,
        @Path("messageId") messageId: String,
    ): Response<Unit>
}
```

### Upload orchestration
`VoicemailUploader` is the only place that touches the raw presigned URL; it uses a **second OkHttp client without the cookie/CSRF interceptors** (S3 must not receive session cookies) injected via a Hilt `@Named("plain")` qualifier.

```kotlin
class VoicemailUploader @Inject constructor(
    private val api: VoicemailApi,
    @Named("plain") private val s3Client: OkHttpClient,
) {
    suspend fun upload(draft: VoicemailDraft): ApiResult<Voicemail>
    // [CORRECTED to real contract]
    // 1) val p = api.presign(conversationId,
    //        PresignVoicemailRequest(callId, contentType, sizeBytes, mode))  // -> {message_id, upload_url, s3_key}
    // 2) s3Client PUT draft.file to p.upload_url with Content-Type = contentType
    // 3) api.create(conversationId, CreateVoicemailRequest(
    //        messageId = p.message_id, callId, s3Key = p.s3_key, contentType,
    //        sizeBytes, durationSeconds, waveformData, mode))               // -> MessageOut (kind=voicemail)
    // NOTE content_type must match the presign pattern ^(audio|video)/(webm|mp4|ogg|wav);
    //      duration_seconds in [0.5, 60]; waveform_data length in [10, 200]; size_bytes <= 50 MiB.
}
```

### Repository
```kotlin
interface VoicemailRepository {
    fun inboxPaging(): Flow<PagingData<Voicemail>>      // Paging 3 + RemoteMediator over Room
    suspend fun send(draft: VoicemailDraft): ApiResult<Voicemail>
    suspend fun markRead(id: String): ApiResult<Voicemail>
    suspend fun delete(id: String): ApiResult<Unit>
    fun observeUnreadCount(): Flow<Int>
}
```

### Playback
Reuse AND-133's `AudioPlayerController` (single shared `ExoPlayer`). `VoicemailPlayerBar` binds to its `StateFlow<PlaybackState>` and calls `play(uri)`, `pause()`, `seekTo(ms)`. The inbox holds the currently-playing id in UI state so a new tap stops the previous item.

### State
ViewModels expose immutable `StateFlow<UiState>` sealed types (see §6) and emit one-shot effects (snackbars, nav) via a `Channel`-backed `Flow`.

## 5. API Contract

Base: `${BASE_URL}/` (dev `http://18.222.237.167:8000/`). All calls carry session cookies + `X-CSRF-Token` (verified against `src/api/client.ts`); **except** the upload PUT. The shapes below are **verified against `/openapi.json` and the web reference** — see §16. [ENTIRE SECTION CORRECTED — the original top-level `/voicemail` contract was fictional.]

**Presign — `POST /messaging/conversations/{conversation_id}/voicemail/presign`** (req `PresignVoicemailRequest`)
```json
// request
{ "call_id": "call_abc", "content_type": "audio/mp4", "size_bytes": 48211, "mode": "audio" }
// content_type MUST match ^(audio|video)/(webm|mp4|ogg|wav) ; size_bytes in [1, 52428800] ; mode default "audio"
// response (per web reference sendVoicemail/presignVoicemail; OpenAPI declares 200 with no body schema)
{ "message_id": "m_<32 hex>", "upload_url": "https://.../...&X-Amz-Signature=...", "s3_key": "voicemail/..." }
```
Note: the server **pre-allocates** `message_id` and `s3_key` at presign; the client echoes them back in create.

**Upload — `PUT {upload_url}`** (no cookies/CSRF): body = raw media bytes, header `Content-Type` = the request `content_type`. Success = `200`/`204`.

**Create — `POST /messaging/conversations/{conversation_id}/voicemail`** (req `CreateVoicemailRequest` → `MessageOut`)
```json
// request — required: message_id, call_id, s3_key, content_type, size_bytes, duration_seconds, waveform_data
{ "message_id": "m_<32 hex>",            // pattern ^m_[a-f0-9]{32}$
  "call_id": "call_abc",
  "s3_key": "voicemail/...",
  "content_type": "audio/mp4",
  "size_bytes": 48211,                    // [1, 52428800]
  "duration_seconds": 7.4,               // number, [0.5, 60]
  "waveform_data": [0.1, 0.7, ...],      // 10..200 numbers
  "mode": "audio" }                      // "audio" | "video", default "audio"
// response (MessageOut, kind="voicemail") — relevant fields:
{ "message_id": "m_...", "conversation_id": "conv_...", "sender_id": "u_999",
  "kind": "voicemail", "created_at": 1749132131,            // epoch seconds (integer)
  "consumption_policy": "listen_once",                       // nullable; may be "none"/"view_once"/"listen_once"
  "consumption_state": "pending",                            // nullable; pending|consumed|expired|failed
  "consumed_at": null, "read_by_count": 0, "read_by_user_ids": [],
  "voicemail": {                                             // nested object (additionalProperties)
    "call_id": "call_abc", "mode": "audio",
    "audio_url": "https://.../clip.m4a?sig=...",             // presigned, short-lived (video_url for video)
    "video_url": null, "content_type": "audio/mp4", "size_bytes": 48211,
    "duration_seconds": 7.4, "waveform_data": [0.1, 0.7, ...],
    "call_state": "missed",                                  // "missed" | "declined" | "busy"
    "caller_user_id": "u_999", "callee_user_id": "u_123" } }
```

**List (inline) — `GET /messaging/conversations/{conversation_id}/messages?limit=30&before={cursor}`** → `200` body is a **JSON array** of `MessageOut` (no `{items,next_cursor}` wrapper). Filter client-side for `kind == "voicemail"` when a voicemail-only view is needed. [CORRECTED — cursor param is `before`; there is no top-level list and no wrapper object.]

**Mark seen — `POST .../messages/{message_id}/view`** (`ViewMessageIn` → `ViewAckOut`) and/or **`POST .../messages/{message_id}/attachment/consume`** (`ConsumeAttachmentIn{consumption_attempt_id, trigger:"open"|"play", playback_seconds?}` → `ConsumeAttachmentOut`); conversation-level **`POST .../read`** (`MarkReadIn`) also exists. [CORRECTED — no `POST /voicemail/{id}/read`.]

**Delete — `DELETE .../messages/{message_id}`** (delete-for-me) or **`DELETE .../messages/{message_id}/revoke`** (revoke-for-all). [CORRECTED — no `DELETE /voicemail/{id}`.]

**Errors:** validation failures return `422 HTTPValidationError` (`{ "detail": [ { "loc": [...], "msg": "...", "type": "..." } ] }`); message endpoints also document `400/401/403/429`. Map the FastAPI `detail` (string | `[{msg}]` | `{...}`) via the shared parser into `ApiResult.Error(code, message)`. `audio_url`/`video_url`/`upload_url` are short-lived presigned URLs; never persist them as canonical (see §8).

## 6. Data & State Management

**Domain models (`core-model`):** [CORRECTED to match `MessageOut`/`Message.voicemail` — fields renamed: `playbackUrl`→`mediaUrl` (`audio_url`/`video_url`), `recipientId`→`calleeUserId`, `durationMs`→`durationSeconds`, `waveformPeaks`→`waveformData`, added `callId`/`mode`/`callState`/`callerUserId`; `unread` derived from `consumptionState`.]
```kotlin
enum class VoicemailMode { AUDIO, VIDEO }

data class Voicemail(
    val messageId: String,                 // m_<32 hex> (the message id)
    val conversationId: String,
    val callId: String,
    val senderId: String,                  // == callerUserId
    val mode: VoicemailMode,
    val mediaUrl: String?,                  // audio_url or video_url (presigned, transient)
    val contentType: String,
    val sizeBytes: Long,
    val durationSeconds: Double,            // [0.5, 60]
    val waveformData: List<Double>,         // 10..200 samples
    val callState: String,                  // "missed" | "declined" | "busy"
    val callerUserId: String,
    val calleeUserId: String,
    val consumptionState: String?,          // pending|consumed|expired|failed (null => treat as unseen)
    val createdAt: Long,                    // epoch SECONDS (not ISO-8601)
) {
    val unread: Boolean get() = consumptionState == null || consumptionState == "pending"
}

data class VoicemailDraft(
    val file: File, val contentType: String, val sizeBytes: Long,
    val durationSeconds: Double, val waveformData: List<Double>,
    val conversationId: String, val callId: String, val mode: VoicemailMode,
    // populated after presign so a failed create can retry without re-upload:
    val messageId: String? = null, val s3Key: String? = null,
)
```

**Room (`core-data`):** `VoicemailEntity` (PK `messageId`, indexed `conversationId`, `createdAt`, `consumptionState`) + `VoicemailRemoteKeys` for the Paging 3 `RemoteMediator` (keyed off the `before` cursor of the conversation message list). `mediaUrl` is stored as **nullable/transient** and refreshed by re-fetching the message if expired; `s3_key`/`messageId` are the durable handles. DAO exposes `PagingSource<Int, VoicemailEntity>` and `Flow<Int>` for unread count. [CORRECTED field names.]

**DataStore:** `lastInboxSyncAt` (for the stale banner threshold) only. No audio in DataStore.

**Local audio files:** drafts live in `context.cacheDir/voicemail-drafts/`; deleted on send-success or explicit discard. Played remote audio is cached by ExoPlayer's `SimpleCache` (configured in AND-133).

**UI state:**
```kotlin
sealed interface InboxUiState {
    data object Loading : InboxUiState
    data class Content(val playingId: String?, val isStale: Boolean) : InboxUiState // rows via PagingData
    data class Error(val message: String) : InboxUiState
}
sealed interface ComposeUiState {
    data object Idle : ComposeUiState
    data class Recording(val elapsedMs: Long, val peaks: List<Int>) : ComposeUiState
    data class Review(val draft: VoicemailDraft) : ComposeUiState
    data class Sending(val draft: VoicemailDraft) : ComposeUiState
    data class SendFailed(val draft: VoicemailDraft, val message: String) : ComposeUiState
    data object Sent : ComposeUiState
}
```
Read state updates optimistically: flip `consumptionState="consumed"` in Room immediately, reconcile with the `view`/`consume` ack, revert on error. [CORRECTED — reconciled against message view/consume endpoints, not a voicemail `markRead`.]

## 7. Error Handling & Resilience

- **Timeouts:** OkHttp call timeout ~20s (dev host is unreliable). The S3 PUT gets a longer write timeout (~40s) sized for clip upload.
- **Retries:** bounded exponential backoff (max 3, jitter) for **idempotent GETs only** — `GET .../messages`. `presign`, `POST .../voicemail` (create), and the `view`/`consume` POSTs are **not** auto-retried (non-idempotent); the upload PUT is retried only if the presign URL is still valid, otherwise re-presign (which yields a new `message_id`/`s3_key`). [CORRECTED endpoint names.]
- **Send pipeline failure mapping:** presign fail → `SendFailed("Couldn't prepare upload")`; PUT fail → retain draft, `SendFailed("Upload failed — tap retry")`; create fail after successful PUT → retain `messageId`+`s3Key`, retry `create` only (do not re-upload). [CORRECTED — handle is `messageId`/`s3Key`.]
- **401:** handled by the shared interceptor (single `/ui/session/refresh` then retry); if refresh fails, surface re-auth effect.
- **Expired audio_url/video_url:** on ExoPlayer `PlaybackException` with HTTP 403, transparently re-fetch the message (`GET .../messages`, locate by `message_id`) once to obtain a fresh presigned `audio_url`/`video_url` and re-`play()`. [CORRECTED field names; no dedicated refresh endpoint exists.]
- **Offline:** inbox shows cached rows + stale banner using `lastInboxSyncAt`; compose allows recording, send fails fast with retry affordance.
- **Empty inbox:** dedicated empty state ("No voicemails").

## 8. Security & Privacy

- **No cookies to S3:** the `@Named("plain")` OkHttp client used for the presigned PUT must omit the cookie jar and CSRF interceptor; assert this in tests.
- **CSRF:** all `/messaging/conversations/*` mutations (presign, create, view, consume, delete) carry `X-CSRF-Token` from the `ui_csrf` cookie (shared interceptor). Verified against `src/api/client.ts` (`X-CSRF-Token` set from `getCookie("ui_csrf")`, `credentials: "include"`). [CORRECTED path glob.]
- **Plaintext dev host:** the app talks HTTP to the FastAPI dev host; `usesCleartextTraffic` is gated to the dev host via a network-security-config domain allowlist (shared infra). Presigned S3 URLs are HTTPS.
- **Presigned URLs are secrets:** `upload_url`/`audio_url`/`video_url` are time-limited bearer URLs — never log them in full, never persist `audio_url`/`video_url` as authoritative; redact query strings in logs.
- **Media at rest:** draft clips (audio and video) in `cacheDir` (app-private); deleted promptly after send. No export/sharing of voicemail media in this ticket.
- **Permissions:** audio voicemail requires `RECORD_AUDIO` (reuses AND-133's flow); **video voicemail also requires `CAMERA`**. Both are runtime permissions; the feature degrades gracefully if denied (the relevant capture mode disabled with rationale). [CORRECTED — added CAMERA for the video mode the original spec omitted.]

## 9. Accessibility & i18n

- All controls have `contentDescription`: record ("Record voicemail"), play/pause (state-dependent), scrub bar exposes position/duration via `stateDescription`.
- Touch targets ≥48dp; play/pause and list rows are single focusable nodes for TalkBack with a row label combining sender, duration, relative time, and unread status.
- Waveform is decorative (`contentDescription = null`) — duration text carries the meaning.
- Live region announces "Sending voicemail…", "Voicemail sent", and "Send failed".
- All strings in `feature-voicemail/src/main/res/values/strings.xml`; no concatenation — use plurals for durations and parameterized strings for "from {name}". Timestamps via `DateUtils.getRelativeTimeSpanString` (locale-aware). RTL-safe layouts (start/end, not left/right).

## 10. Telemetry & Logging

- Events (via shared analytics): `voicemail_record_started`, `voicemail_send_attempt`, `voicemail_send_success {duration_ms, byte_size}`, `voicemail_send_failed {stage: presign|put|create, error_code}`, `voicemail_play {id, unread_before}`, `voicemail_marked_read {source: play|manual}`.
- Structured logs at each pipeline stage with **redacted** URLs (host + path only, query stripped). Log `presign expires_in` and whether a re-presign occurred.
- No PII (audio bytes, full names) in analytics payloads — use ids and counts only.
- Debug-only timing log around the S3 PUT to diagnose dev-host flakiness.

## 11. Testing Strategy

**Unit (core-testing + JUnit + Turbine + MockWebServer):**
- `VoicemailUploaderTest`: presign→PUT→create happy path; PUT failure retains draft and does **not** call `create`; create failure after PUT retries `create` only; asserts the PUT request carries **no** `Cookie`/`X-CSRF-Token` header and the create request **does**.
- `VoicemailRepositoryImplTest`: optimistic read flip + revert on error; `ApiResult` mapping of the three `detail` shapes; cursor paging keys.
- `VoicemailInboxViewModelTest` / `VoicemailComposeViewModelTest`: state transitions (Idle→Recording→Review→Sending→Sent / →SendFailed→retry), `playingId` switching stops prior playback (fake `AudioPlayerController`).

**Instrumented / Compose UI tests:**
- Inbox renders rows, unread indicator, empty state, stale banner; tapping a row enters Playing state and marks read.
- Compose screen: record→review→send shows Sending then navigates back; SendFailed shows retry.
- TalkBack semantics assertions on row label and play/pause descriptions.

**Integration:** MockWebServer scripts the full `POST .../voicemail/presign`, the upload PUT (separate mock server URL from the presign response), `POST .../voicemail`, `GET .../messages`, and `POST .../messages/{id}/view`. One slow-response (20s) test asserts timeout + retryable error for the messages GET and fail-fast for the POSTs. [CORRECTED endpoint names.]

**Acceptance gate:** an end-to-end test proving **record → presign → upload → POST .../voicemail → appears as kind=voicemail in GET .../messages → play** (send/play round-trip).

## 12. Dependencies & Sequencing

- **Hard dependency: AND-133 (Voice messages)** — must land first; provides `AudioRecorder`, `WaveformCapture`, `AudioPlayerController`, ExoPlayer `SimpleCache`, and `RECORD_AUDIO` permission flow. This ticket is blocked until those APIs are stable.
- **Transitively** relies on the shared OkHttp/auth stack (cookie jar, CSRF interceptor, single-refresh-on-401), `core-network` Retrofit/Moshi setup, and the `ApiResult`/`detail`-parser utilities — all assumed delivered by earlier core tickets.
- **Sequencing within ticket:** (1) `core-model` + Moshi models validated against `/openapi.json`; (2) `VoicemailApi` + `VoicemailUploader` + unit tests; (3) `VoicemailRepository` + Room + Paging; (4) Compose/Inbox screens + VMs; (5) playback wiring; (6) E2E acceptance test.
- **Blocks:** none recorded in backlog.

## 13. Risks & Open Questions

- **[RESOLVED] OpenAPI shapes confirmed.** The §5 contract is now verified against `/openapi.json` (`PresignVoicemailRequest`, `CreateVoicemailRequest`, `MessageOut`) and the web reference (`src/api/endpoints/messaging.ts`). No top-level `/voicemail` namespace exists.
- **[RESOLVED] Voicemail IS modeled as a message.** A voicemail is `MessageOut` with `kind: "voicemail"` and a nested `voicemail` object; it is tied to a `call_id` and a conversation. It is distinct from `voice_message` (AND-133) but shares the message/consumption lifecycle. The dedicated `VoicemailApi` should wrap the conversation-scoped endpoints, not a standalone namespace.
- **No background send queue:** offline/failed sends are user-retried in-screen this ticket; a durable WorkManager upload queue is out of scope (candidate follow-up).
- **[PARTIALLY RESOLVED] Seen semantics.** "Mark read" maps to message `view`/`attachment/consume`; `consumption_policy: listen_once` may apply to voicemail media (consume-once). **Open:** whether to mark consumed on play-start vs completion, and whether voicemail attachments actually carry `listen_once` in practice — confirm with product/backend before wiring the consume call.
- **[RESOLVED] Delete support:** use generic `DELETE .../messages/{message_id}` (delete-for-me) / `.../revoke` (for-all). No voicemail-specific delete.
- **Presigned URL expiry vs ExoPlayer caching:** long playback sessions could outlive `audio_url`/`video_url`; mitigated by 403-triggered message re-fetch (§7). No dedicated refresh endpoint — re-fetch via `GET .../messages`.
- **[OPEN] Video voicemail scope/effort.** The contract supports `mode: "video"`; original spec ignored it. Confirm whether video capture/playback is in scope for this ticket or deferred — it materially affects size (CAMERA permission, video capture UI, ExoPlayer video surface).
- **[OPEN] Messages list params.** `GET .../messages` documents `limit`/`before` (and no response wrapper schema). Confirm `before` cursor semantics and page ordering against the running backend before locking the `RemoteMediator`.

## 14. Acceptance Criteria

AC-1 A recorded clip is sent via the full pipeline: `POST .../voicemail/presign` → `PUT {upload_url}` → `POST .../voicemail` (using the presign-allocated `message_id`/`s3_key`), and on success the recorder shows **Sent** and returns to the conversation. (Backlog: *send works*.) [CORRECTED endpoints.]

AC-2 A received voicemail (`kind: "voicemail"`) renders inline in the conversation (newest-first within the thread) with sender, call-state label, duration, relative time, and an unread/unconsumed indicator. [CORRECTED — inline message, not a dedicated inbox.]

AC-3 Tapping a voicemail plays its `audio_url` (or `video_url`) through Media3/ExoPlayer with working play/pause and scrub; only one plays at a time. (Backlog: *play works*.) [CORRECTED field names.]

AC-4 Playing (or explicit mark-seen) clears the unread indicator and issues the message `POST .../messages/{message_id}/view` (and/or `.../attachment/consume`), with optimistic UI and revert on failure. [CORRECTED — no `/voicemail/{id}/read`.]

AC-5 The upload PUT request contains **no** session `Cookie` or `X-CSRF-Token` header; the `presign`/`create`/`view`/`consume` requests **do** carry `X-CSRF-Token`. (Verified by test.) [CORRECTED endpoint list.]

AC-6 Failure at any stage leaves a retryable state: a failed upload retains the local draft for retry; a `create` failure after a successful PUT retries `create` only (reusing the same `message_id`/`s3_key`, no re-upload).

AC-7 Offline: the conversation shows cached messages with a stale banner; `GET .../messages` uses ~20s timeout with bounded retry, while presign/create/view do not auto-retry. [CORRECTED endpoints.]

AC-8 TalkBack reads each row as a single labeled node and announces send progress; all interactive controls meet ≥48dp and have content descriptions.

## 15. Definition of Done

- All §14 acceptance criteria pass, including the end-to-end **record→send→play** test.
- `feature-voicemail`, `core-data` repo, `core-network` API, and `core-model` types implemented per §4 under `com.testlogon.android.*`, building on Kotlin 2.0.21 / AGP 8.7.3 / Gradle 8.9, minSdk 24 / target 35, JDK 17.
- Unit + Compose + integration tests (§11) green in CI; ktlint/detekt clean; no new lint errors.
- All Moshi models verified against `/openapi.json`; any deviation from §5 documented and reflected in code.
- No presigned URLs logged in full; `@Named("plain")` S3 client confirmed cookie/CSRF-free by test.
- Strings externalized and TalkBack-verified; RTL spot-checked.
- Open questions in §13 resolved or explicitly ticketed as follow-ups — note that voicemail-vs-voice-message modeling, delete support, and namespace shape are now RESOLVED (see §16); remaining open items are seen-on-play-vs-completion, video scope, and messages-list cursor semantics.
- Merged to `android-port` with the feature reachable from the call/conversation entry point (post missed/declined/busy call) and voicemails rendering inline in the conversation thread.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources: **OAPI-IDX** = `reference/openapi.index.txt`; **OAPI** = `reference/openapi.pretty.json` (`components.schemas.<Name>`); frontend paths are under `reference/src/`.

1. **Presign endpoint is `POST /messaging/conversations/{conversation_id}/voicemail/presign`.** VERDICT: Corrected (was `POST /voicemail/presign`). SOURCE: OAPI-IDX `POST /messaging/conversations/{conversation_id}/voicemail/presign | op=presign_voicemail... | req=PresignVoicemailRequest`; `src/api/endpoints/messaging.ts: presignVoicemail`.
2. **Create endpoint is `POST /messaging/conversations/{conversation_id}/voicemail`, response `MessageOut`.** VERDICT: Corrected (was `POST /voicemail` → `Voicemail`). SOURCE: OAPI-IDX `POST .../voicemail | req=CreateVoicemailRequest | resp=200:MessageOut`; `src/api/endpoints/messaging.ts: createVoicemail`.
3. **`PresignVoicemailRequest` fields = `{call_id, content_type, size_bytes, mode}`; `content_type` matches `^(audio|video)/(webm|mp4|ogg|wav)`; `size_bytes` ≤ 52428800; `mode` default `audio`.** VERDICT: Corrected (spec had `{content_type, byte_size, duration_ms}`). SOURCE: OAPI `components.schemas.PresignVoicemailRequest`.
4. **Presign response = `{message_id, upload_url, s3_key}` (server pre-allocates `message_id` & `s3_key`).** VERDICT: Corrected (spec had `{object_key, upload_url, expires_in, headers}`). SOURCE: `src/api/endpoints/messaging.ts: presignVoicemail` return type. NOTE: OAPI declares the presign 200 with no body schema, so field names come from the frontend (authoritative client contract).
5. **`CreateVoicemailRequest` fields = `{message_id (^m_[a-f0-9]{32}$), call_id, s3_key, content_type, size_bytes, duration_seconds (0.5–60), waveform_data (10–200 numbers), mode}`.** VERDICT: Corrected (spec had `{object_key, recipient_id, conversation_id, duration_ms, waveform_peaks}`). SOURCE: OAPI `components.schemas.CreateVoicemailRequest`; `src/api/endpoints/messaging.ts: CreateVoicemailReq`.
6. **Voicemail is a Message with `kind: "voicemail"` (not a standalone entity).** VERDICT: Corrected. SOURCE: OAPI `components.schemas.MessageOut.properties.kind.enum` (includes `voicemail`); `src/api/types.ts: Message.kind`.
7. **`MessageOut` carries nested `voicemail` object = `{call_id, mode, audio_url?, video_url?, content_type, size_bytes, duration_seconds, waveform_data, call_state, caller_user_id, callee_user_id}`.** VERDICT: Corrected (spec's flat `Voicemail` shape). SOURCE: `src/api/types.ts: Message.voicemail`; OAPI `MessageOut.properties.voicemail` (additionalProperties object).
8. **Playback media field is `audio_url` / `video_url` (presigned), not `playback_url`.** VERDICT: Corrected. SOURCE: `src/pages/messages/VoicemailBubble.tsx` (`vm.audio_url`, `vm.video_url`); `src/api/types.ts: Message.voicemail`.
9. **Voicemail supports `mode: "audio" | "video"` (video in contract).** VERDICT: Corrected/Added (spec was audio-only). SOURCE: OAPI `CreateVoicemailRequest.properties.mode`, `PresignVoicemailRequest.properties.mode`; `src/pages/messages/VoicemailRecorder.tsx` (Record Audio / Record Video).
10. **Voicemail is call-centric (tied to `call_id`; `call_state` ∈ missed/declined/busy).** VERDICT: Corrected (spec framed it as recipient-addressed async mail). SOURCE: `src/pages/messages/VoicemailRecorder.tsx` (`callId` prop, "Leave a voicemail?" after call); `src/pages/messages/VoicemailBubble.tsx` (`call_state` labels); OAPI `MessageOut.voicemail.call_state` via frontend type.
11. **No top-level `/voicemail`, no `GET /voicemail` inbox; inline list = `GET /messaging/conversations/{conversation_id}/messages` (`limit`,`before`; 200 body is an array).** VERDICT: Corrected (spec had `GET /voicemail?cursor=&limit=` → `{items,next_cursor}`). SOURCE: OAPI-IDX `GET .../messages | params=conversation_id,limit,before...`; no `/voicemail` GET in OAPI-IDX.
12. **No `POST /voicemail/{id}/read`; seen = `POST .../messages/{message_id}/view` (`ViewMessageIn`→`ViewAckOut`) and/or `.../attachment/consume` (`ConsumeAttachmentIn`→`ConsumeAttachmentOut`); conversation-level `POST .../read`.** VERDICT: Corrected. SOURCE: OAPI-IDX lines for `.../messages/{message_id}/view`, `.../attachment/consume`, `.../read`; `src/api/types.ts: ConsumeAttachmentReq/Resp`.
13. **Consumption lifecycle on the message: `consumption_policy` (none|view_once|listen_once), `consumption_state` (pending|consumed|expired|failed), `consumed_at`, `read_by_count`, `read_by_user_ids`.** VERDICT: Verified (and used to replace the spec's `unread` flag). SOURCE: OAPI `MessageOut.properties.{consumption_policy,consumption_state,consumed_at,read_by_count,read_by_user_ids}`; `src/api/types.ts`.
14. **No `DELETE /voicemail/{id}`; deletion = `DELETE .../messages/{message_id}` (for me) or `.../messages/{message_id}/revoke` (for all).** VERDICT: Corrected. SOURCE: OAPI-IDX `DELETE .../messages/{message_id}` and `.../revoke`.
15. **Auth/CSRF: session cookies + `X-CSRF-Token` from `ui_csrf` cookie; `credentials: include`; single `/ui/session/refresh` on 401.** VERDICT: Verified. SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` → `X-CSRF-Token`, `credentials:"include"`, `/ui/session/refresh` retry). NOTE: the web client also sends a `Bearer` access token + optional `X-IMPERSONATION-TOKEN`; OAPI params list `authorization,X-SESSION-ID,X-API-Key`. The Android cookie-based session assumption is shared infra (AND-133) — Unverified for these specific endpoints beyond the web client's cookie+CSRF behavior.
16. **Upload PUT carries no cookies/CSRF; `Content-Type` = the request content type; success 200/204.** VERDICT: Verified. SOURCE: `src/api/endpoints/messaging.ts: sendVoicemail` (plain `fetch(upload_url, {method:"PUT", body: blob, headers:{Content-Type}})`, no credentials).
17. **`created_at` is epoch seconds (integer), not ISO-8601.** VERDICT: Corrected (spec used `"2026-06-05T14:02:11Z"` / `Instant`). SOURCE: OAPI `MessageOut.properties.created_at` (integer); `src/api/types.ts: Message.created_at: number`.
18. **Validation errors return `422 HTTPValidationError` (`detail: [{loc,msg,type}]`); message endpoints also document 400/401/403/429.** VERDICT: Verified. SOURCE: OAPI-IDX `resp=...;422:HTTPValidationError;400;401;403;429` on the messaging endpoints; OAPI `components.schemas.HTTPValidationError`.
19. **Media3/ExoPlayer for playback; AND-133 supplies `AudioRecorder`/`AudioPlayerController`.** VERDICT: Unverified-assumption (Android-side design; not in web sources). SOURCE: framework ref — Media3 ExoPlayer (https://developer.android.com/media/media3/exoplayer); cross-ticket dependency AND-133.
20. **`CAMERA` runtime permission required for video voicemail; `RECORD_AUDIO` for audio.** VERDICT: Verified (contract requires video) + framework ref. SOURCE: contract `mode:"video"` (claim 9); framework ref — runtime permissions (https://developer.android.com/training/permissions/requesting), CameraX (https://developer.android.com/training/camerax).

### Corrections made
- Endpoint base path: `/voicemail*` → conversation-scoped `/messaging/conversations/{conversation_id}/voicemail*` (presign + create); list/read/delete reuse generic message endpoints (claims 1,2,11,12,14).
- Entity model: standalone `Voicemail` → `MessageOut` with `kind:"voicemail"` + nested `voicemail` object (claims 6,7).
- Presign request/response fields and create request fields rewritten to the real schemas; server pre-allocates `message_id`/`s3_key` (claims 3,4,5).
- Field renames throughout: `playback_url`→`audio_url`/`video_url`; `byte_size`/`byteSizeBytes`→`size_bytes`; `duration_ms`→`duration_seconds`; `waveform_peaks`→`waveform_data`; `object_key`→`s3_key`; `recipient_id`→`call_id`+conversation-in-path; `created_at` ISO→epoch seconds (claims 4,5,8,17).
- Read/seen mechanism: `POST /voicemail/{id}/read` → message `view`/`consume`; `unread` boolean → `consumption_state` (claims 12,13).
- Added video voicemail as in-contract scope + `CAMERA` permission (claims 9,20). Reframed feature as call-centric (claim 10).
- Frontmatter: `status: draft` → `status: reviewed`; added `reviewed_on: 2026-06-06`.

### Open assumptions
- **Android cookie-session transport for these endpoints (claim 15):** the web client uses cookie + CSRF; OAPI lists `authorization/X-SESSION-ID/X-API-Key`. The exact header set the Android app must send is owned by shared auth infra (AND-133) and not fully verifiable from these sources.
- **`listen_once` applies to voicemail media:** `consumption_policy` is generic; whether voicemail attachments are consume-once in practice (and whether to consume on play-start vs completion) is unconfirmed — product/backend decision.
- **`before` cursor semantics & ordering for `GET .../messages`:** OAPI documents the param names but the 200 has no response-body schema; pagination ordering must be confirmed against the running backend before locking the `RemoteMediator`.
- **Presign 200 response field names (claim 4):** taken from the frontend client because OAPI declares no body schema for the presign 200. Treat as the de-facto contract; verify against the live dev host.
- **Media3/ExoPlayer + AND-133 collaborators (claim 19):** Android-side design choices, not present in the web/OpenAPI sources.

## 17. Test Plan

IDs `TC-AND-134-NN`. "Traces" link to §14 acceptance criteria. Test targets: **JVM** (local JUnit/Robolectric), **MockWebServer** (contract, local), **emulator `test35`** (API 35 x86_64), **physical** (Samsung Galaxy A15 5G, SM-A156U, API 34, arm64) for real hardware (camera/mic capture).

**TC-AND-134-01 — Send pipeline happy path (audio).** Type: contract/MockWebServer (JVM). Target: MockWebServer. Preconditions: server scripts `POST .../voicemail/presign` → `{message_id:"m_<32hex>", upload_url:<mock2>, s3_key}`, the upload PUT (separate mock server) → 204, `POST .../voicemail` → `MessageOut{kind:"voicemail"}`. Steps: invoke `VoicemailUploader.upload(draft mode=audio)`. Expected: three calls in order; create body = `{message_id,call_id,s3_key,content_type,size_bytes,duration_seconds,waveform_data,mode:"audio"}` with the presign-allocated `message_id`/`s3_key`; result `ApiResult.Success(Voicemail)` with `kind=voicemail`. Traces: AC-1, AC-6.

**TC-AND-134-02 — Create request schema conformance.** Type: contract/MockWebServer (JVM). Target: MockWebServer. Preconditions: as 01. Steps: capture the create `RecordedRequest` body; assert against `CreateVoicemailRequest`. Expected: `message_id` matches `^m_[a-f0-9]{32}$`; `duration_seconds` ∈ [0.5,60]; `waveform_data` length ∈ [10,200]; `size_bytes` ≤ 52428800; `content_type` matches `^(audio|video)/(webm|mp4|ogg|wav)`; no `recipient_id`/`object_key`/`duration_ms`/`waveform_peaks` keys present. Traces: AC-1.

**TC-AND-134-03 — No cookies/CSRF on upload PUT; present on API calls.** Type: contract/MockWebServer (JVM). Target: MockWebServer. Preconditions: cookie jar seeded with session + `ui_csrf`; `@Named("plain")` client for PUT. Steps: run full send; inspect headers of each recorded request. Expected: the PUT to `upload_url` has **no** `Cookie` and **no** `X-CSRF-Token`; presign + create requests carry `X-CSRF-Token` and `Cookie`. Traces: AC-5.

**TC-AND-134-04 — Upload (PUT) failure retains draft, skips create.** Type: unit + contract (JVM). Target: MockWebServer. Preconditions: presign → 200; PUT → 500. Steps: `upload(draft)`. Expected: `create` is **never** called; result `ApiResult.Error`; draft retained with `messageId`+`s3Key` set; ViewModel → `SendFailed("Upload failed — tap retry")`. Traces: AC-6.

**TC-AND-134-05 — Create failure after successful PUT retries create only.** Type: unit + contract (JVM). Target: MockWebServer. Preconditions: presign → 200; PUT → 204; first create → 500, retry create → 200. Steps: `upload`, then user-triggered retry. Expected: exactly one PUT total; create called twice with the **same** `message_id`/`s3_key`; no re-presign; final `Success`. Traces: AC-6.

**TC-AND-134-06 — 422 validation error mapping.** Type: contract/MockWebServer (JVM). Target: MockWebServer. Preconditions: create → `422 {"detail":[{"loc":["body","duration_seconds"],"msg":"...","type":"..."}]}`. Steps: `upload` with out-of-range duration. Expected: parsed into `ApiResult.Error` with a user-facing message; no crash; `SendFailed` surfaced. Traces: AC-1, AC-6.

**TC-AND-134-07 — Inline voicemail render + consumption mapping.** Type: unit (JVM). Target: JVM. Preconditions: feed a `MessageOut{kind:"voicemail", voicemail:{call_state:"missed", mode:"audio", audio_url, waveform_data, duration_seconds}, consumption_state:"pending"}` through the mapper. Steps: map to domain `Voicemail`. Expected: `unread==true` (state pending), `mediaUrl==audio_url`, `callState=="missed"`, `createdAt` parsed as epoch seconds. Traces: AC-2.

**TC-AND-134-08 — Mark-seen uses message view/consume (optimistic + revert).** Type: contract/MockWebServer (JVM). Target: MockWebServer. Preconditions: list returns one pending voicemail; `POST .../messages/{id}/view` → first 500 then 200. Steps: trigger play → mark seen; observe state via Turbine. Expected: local `consumptionState` flips to `consumed` optimistically; on 500 it reverts to `pending`; on retry 200 it stays `consumed`; **no** request to any `/voicemail/{id}/read` path. Traces: AC-4.

**TC-AND-134-09 — Offline cached render + flaky-host retry policy.** Type: integration/MockWebServer (JVM). Target: MockWebServer + Robolectric. Preconditions: Room seeded with cached voicemail rows; `GET .../messages` delayed 20s; presign scripted to fail fast. Steps: open conversation offline/slow. Expected: cached rows render with stale banner; `GET .../messages` honors ~20s timeout with bounded retry; a send attempt fails fast with retry affordance (presign/create NOT auto-retried). Traces: AC-7, AC-2.

**TC-AND-134-10 — Expired media URL triggers 403 re-fetch.** Type: integration (Robolectric/JVM with fake player). Target: emulator `test35`. Preconditions: ExoPlayer raises `PlaybackException` HTTP 403 on first `play()`; `GET .../messages` returns a fresh `audio_url`. Steps: tap play. Expected: exactly one transparent re-fetch by `message_id`, then successful re-`play()`; no infinite loop. Traces: AC-3.

**TC-AND-134-11 — Single-playback invariant.** Type: Compose-UI/instrumented. Target: emulator `test35`. Preconditions: two voicemail bubbles rendered. Steps: tap row A (plays), then tap row B. Expected: row A stops, row B plays; UI `playingId` reflects B only. Traces: AC-3.

**TC-AND-134-12 — Recorder flow + Sent navigation.** Type: Compose-UI/instrumented. Target: emulator `test35`. Preconditions: fake recorder + stubbed uploader (Success). Steps: enter compose → record → review → Send. Expected: states Idle→Recording→Review→Sending→Sent; on Sent it returns to the conversation; SendFailed path shows a retry control. Traces: AC-1, AC-6.

**TC-AND-134-13 — Accessibility: bubble semantics & touch targets.** Type: Compose-UI/instrumented. Target: emulator `test35`. Preconditions: one unread audio voicemail. Steps: assert semantics tree. Expected: bubble is a single focusable node labeled with sender + call-state + duration + relative time + unread; play/pause has state-dependent `contentDescription`; waveform `contentDescription==null`; all controls ≥48dp; "Sending voicemail…/sent/failed" announced via live region. Traces: AC-8.

**TC-AND-134-14 — Real audio capture + end-to-end round-trip (hardware).** Type: instrumented/e2e. Target: **PHYSICAL device (SM-A156U)** — MUST run on hardware (real mic; arm64/API-34). Preconditions: `RECORD_AUDIO` granted; backend (or on-device MockWebServer) scripts presign/PUT/create/list. Steps: record real audio → send → confirm it appears as `kind=voicemail` in `GET .../messages` → play back. Expected: full record→presign→upload→create→list→play succeeds; audible playback; duration/waveform populated. Traces: AC-1, AC-2, AC-3.

**TC-AND-134-15 — Video voicemail capture + permission (hardware).** Type: instrumented/e2e + security/permission. Target: **PHYSICAL device (SM-A156U)** — MUST run on hardware (real camera). Preconditions: `mode:"video"` path enabled. Steps: (a) deny `CAMERA` → assert video capture is disabled with rationale and audio still works; (b) grant `CAMERA` → record video voicemail → send (`content_type` video/mp4|webm) → render inline `video_url` and play. Expected: graceful degrade on denial; on grant, video upload uses `mode:"video"` and inline video playback works. Traces: AC-1, AC-3, AC-8.

### Coverage matrix
| AC (§14) | Covered by |
| --- | --- |
| AC-1 (send pipeline) | TC-01, TC-02, TC-06, TC-12, TC-14, TC-15 |
| AC-2 (inline render) | TC-07, TC-09, TC-14 |
| AC-3 (playback, single-at-a-time) | TC-10, TC-11, TC-14, TC-15 |
| AC-4 (mark-seen optimistic/revert) | TC-08 |
| AC-5 (no cookies/CSRF on PUT) | TC-03 |
| AC-6 (retryable failure states) | TC-01, TC-04, TC-05, TC-06, TC-12 |
| AC-7 (offline + retry policy) | TC-09 |
| AC-8 (accessibility) | TC-13, TC-15 |
