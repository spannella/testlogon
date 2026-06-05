---
id: AND-134
title: Voicemail
milestone: M3
epic: E19
priority: P2
size: M
status: draft
depends_on: [AND-133]
blocks: []
---

# AND-134 — Voicemail

## 1. Overview & Goal

Implement the **Voicemail** feature for the TestLogon native Android app: a user can leave an asynchronous audio voicemail for another user (or a conversation) and can play back voicemails left for them. Unlike inline voice messages (AND-133), voicemails are a distinct entity surfaced through the `/voicemail` API namespace, are addressed to a recipient who may be offline, and have their own inbox/list semantics, read/unread state, and an optional caller-context payload.

This ticket reuses the recording, waveform-capture, and presigned-upload machinery delivered by AND-133, but adds: (a) the voicemail-specific send flow (`POST /voicemail` after a presigned S3 PUT), (b) a voicemail inbox list with playback, and (c) the read/seen lifecycle. The deliverable lives in a new `feature-voicemail` module and a `core-data` repository, with playback driven by Media3/ExoPlayer.

**Done = a recorded audio clip can be uploaded via presign and sent as a voicemail to a recipient, and a received voicemail appears in the inbox and plays back correctly (send/play works).**

## 2. Context & References

- **Backlog:** AND-134 — Voicemail · Feature · P2 · Deps: AND-133. Scope: `/voicemail(+presign)` flow. Acceptance: *Voicemail send/play works.*
- **Upstream dependency AND-133 (Voice messages):** owns `AudioRecorder`, `WaveformCapture`, the `presign → S3 PUT → confirm` upload pipeline, and the shared `AudioPlayerController` over Media3. AND-134 consumes these as collaborators; it does **not** re-implement recording or waveform rendering.
- **Repo:** `spannella/testlogon`, branch `android-port`, app under `android/`. Web reference under `frontend/` — API layer `frontend/src/api/endpoints/*.ts` (look for `voicemail.ts`), shared types `frontend/src/api/types.ts`.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`; confirm the exact `/voicemail` and presign shapes against it before locking the Moshi models.
- **Module layering:** `app -> feature-voicemail -> core-{network,model,data,ui,testing}`. ViewModels expose `StateFlow<UiState>`; all network returns typed `ApiResult<T>`.
- **Auth:** cookie-based session with `X-CSRF-Token` echoed from the `ui_csrf` cookie; the OkHttp stack (persistent cookie jar + CSRF + single `/ui/session/refresh` retry on 401) is shared infrastructure and is assumed present.

## 3. Functional Requirements

FR-1 **Record & send.** From a recipient/conversation context the user records audio (via AND-133 `AudioRecorder`), reviews it (duration + waveform), and sends it as a voicemail. Sending performs: request presign → PUT bytes to the presigned URL → `POST /voicemail` with the returned object key and metadata.

FR-2 **Recipient addressing.** A voicemail targets a `recipient_id` (and/or `conversation_id`). The recipient is passed into the feature via navigation args; the screen does not include recipient search (owned elsewhere).

FR-3 **Voicemail inbox.** A list screen shows received voicemails newest-first, paged (Paging 3), each row showing caller display name/avatar (Coil), duration, relative timestamp, and unread indicator.

FR-4 **Playback.** Tapping a row plays the voicemail audio through Media3/ExoPlayer with play/pause and a scrub bar; only one voicemail plays at a time. Playing a voicemail marks it **read** (FR-6).

FR-5 **Re-send / discard before send.** Before upload the user may discard and re-record, or cancel. After a failed upload the user may retry the send without re-recording (the local file is retained until success or explicit discard).

FR-6 **Read state.** A voicemail has `unread`/`read`. Playback (or an explicit "mark read") issues `POST /voicemail/{id}/read`; the list reflects the new state optimistically.

FR-7 **Offline/stale states.** Inbox renders cached rows when offline (Room), with a stale banner; recording is allowed offline and the send is surfaced as failed-retryable (no background queue in this ticket — see Risks).

FR-8 **Deletion (if backend supports).** If `DELETE /voicemail/{id}` exists in OpenAPI, support swipe-to-delete with optimistic removal + undo; otherwise omit and note as deferred.

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
Single-Activity Navigation-Compose. Routes:

```kotlin
object VoicemailRoutes {
    const val INBOX = "voicemail/inbox"
    const val COMPOSE = "voicemail/compose/{recipientId}?conversationId={conversationId}"
    fun compose(recipientId: String, conversationId: String? = null): String
}

fun NavGraphBuilder.voicemailGraph(nav: NavController)
```

### Retrofit interface
```kotlin
interface VoicemailApi {
    @GET("voicemail")
    suspend fun list(
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = 20,
    ): Response<VoicemailPage>

    @POST("voicemail/presign")
    suspend fun presign(@Body body: PresignRequest): Response<PresignResponse>

    @POST("voicemail")
    suspend fun create(@Body body: CreateVoicemailRequest): Response<Voicemail>

    @POST("voicemail/{id}/read")
    suspend fun markRead(@Path("id") id: String): Response<Voicemail>

    @DELETE("voicemail/{id}")
    suspend fun delete(@Path("id") id: String): Response<Unit> // gate on OpenAPI
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
    // 1) api.presign(PresignRequest(contentType, byteSize, durationMs))
    // 2) s3Client PUT draft.file to PresignResponse.uploadUrl with Content-Type header
    // 3) api.create(CreateVoicemailRequest(objectKey, recipientId, conversationId, durationMs, waveformPeaks))
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

Base: `${BASE_URL}/` (dev `http://18.222.237.167:8000/`). All calls carry session cookies + `X-CSRF-Token`; **except** the S3 PUT. Validate every shape below against `/openapi.json` before implementation — treat these as the expected contract.

**Presign — `POST /voicemail/presign`**
```json
// request
{ "content_type": "audio/mp4", "byte_size": 48211, "duration_ms": 7400 }
// response
{ "object_key": "voicemail/2026/06/ab12.m4a",
  "upload_url": "https://s3.amazonaws.com/...&X-Amz-Signature=...",
  "expires_in": 900,
  "headers": { "Content-Type": "audio/mp4" } }
```

**Upload — `PUT {upload_url}`** (no cookies/CSRF): body = raw audio bytes, header `Content-Type` from `headers`. Success = `200`/`204`.

**Create — `POST /voicemail`**
```json
// request
{ "object_key": "voicemail/2026/06/ab12.m4a",
  "recipient_id": "u_123", "conversation_id": null,
  "duration_ms": 7400, "waveform_peaks": [3,7,12,...] }
// response (Voicemail)
{ "id": "vm_456", "object_key": "voicemail/2026/06/ab12.m4a",
  "playback_url": "https://.../ab12.m4a?sig=...",
  "sender": { "id": "u_999", "display_name": "Sam", "avatar_url": null },
  "recipient_id": "u_123", "conversation_id": null,
  "duration_ms": 7400, "waveform_peaks": [3,7,12,...],
  "unread": true, "created_at": "2026-06-05T14:02:11Z" }
```

**List — `GET /voicemail?cursor=&limit=20`**
```json
{ "items": [ /* Voicemail[] */ ], "next_cursor": "eyJrIjoi..." }
```

**Mark read — `POST /voicemail/{id}/read`** → updated `Voicemail` (`unread:false`).

**Delete — `DELETE /voicemail/{id}`** → `204` (only if present in OpenAPI).

**Error envelope (FastAPI `detail`):** map `string | [{msg}] | {code,...}` via the shared `detail` parser into `ApiResult.Error(code, message)`. `playback_url`/`upload_url` may be short-lived presigned URLs; never persist them as canonical (see §8).

## 6. Data & State Management

**Domain models (`core-model`):**
```kotlin
data class Voicemail(
    val id: String, val objectKey: String, val playbackUrl: String?,
    val sender: UserRef, val recipientId: String, val conversationId: String?,
    val durationMs: Long, val waveformPeaks: List<Int>,
    val unread: Boolean, val createdAt: Instant,
)
data class VoicemailDraft(
    val file: File, val contentType: String, val byteSizeBytes: Long,
    val durationMs: Long, val waveformPeaks: List<Int>,
    val recipientId: String, val conversationId: String?,
)
```

**Room (`core-data`):** `VoicemailEntity` (PK `id`, indexed `createdAt`, `unread`) + `VoicemailRemoteKeys` for the Paging 3 `RemoteMediator`. `playbackUrl` is stored as **nullable/transient** and refreshed on play if expired; `objectKey` is the durable handle. DAO exposes `PagingSource<Int, VoicemailEntity>` and `Flow<Int>` for unread count.

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
Read state updates optimistically: flip `unread=false` in Room immediately, reconcile with `markRead` response, revert on error.

## 7. Error Handling & Resilience

- **Timeouts:** OkHttp call timeout ~20s (dev host is unreliable). The S3 PUT gets a longer write timeout (~40s) sized for clip upload.
- **Retries:** bounded exponential backoff (max 3, jitter) for **idempotent GETs only** — `GET /voicemail`. `presign`, `POST /voicemail`, and `POST /read` are **not** auto-retried (non-idempotent); the S3 PUT is retried only if the presign URL is still valid, otherwise re-presign.
- **Send pipeline failure mapping:** presign fail → `SendFailed("Couldn't prepare upload")`; PUT fail → retain draft, `SendFailed("Upload failed — tap retry")`; create fail after successful PUT → retain `objectKey`, retry `create` only (do not re-upload).
- **401:** handled by the shared interceptor (single `/ui/session/refresh` then retry); if refresh fails, surface re-auth effect.
- **Expired playback_url:** on ExoPlayer `PlaybackException` with HTTP 403, transparently re-fetch the row (or call a refresh endpoint) once and re-`play()`.
- **Offline:** inbox shows cached rows + stale banner using `lastInboxSyncAt`; compose allows recording, send fails fast with retry affordance.
- **Empty inbox:** dedicated empty state ("No voicemails").

## 8. Security & Privacy

- **No cookies to S3:** the `@Named("plain")` OkHttp client used for the presigned PUT must omit the cookie jar and CSRF interceptor; assert this in tests.
- **CSRF:** all `/voicemail*` mutations carry `X-CSRF-Token` from the `ui_csrf` cookie (shared interceptor).
- **Plaintext dev host:** the app talks HTTP to the FastAPI dev host; `usesCleartextTraffic` is gated to the dev host via a network-security-config domain allowlist (shared infra). Presigned S3 URLs are HTTPS.
- **Presigned URLs are secrets:** `upload_url`/`playback_url` are time-limited bearer URLs — never log them in full, never persist `playback_url` as authoritative; redact query strings in logs.
- **Audio at rest:** draft clips in `cacheDir` (app-private); deleted promptly after send. No export/sharing of voicemail audio in this ticket.
- **Permissions:** `RECORD_AUDIO` runtime permission is requested by AND-133's recorder; this feature reuses that flow and degrades gracefully if denied (compose disabled with rationale).

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

**Integration:** MockWebServer scripts the full `/voicemail/presign`, S3 PUT (separate mock server URL from presign response), `POST /voicemail`, `GET /voicemail`, `POST /{id}/read`. One slow-response (20s) test asserts timeout + retryable error for GET and fail-fast for POST.

**Acceptance gate:** an end-to-end test proving **record → presign → upload → POST /voicemail → appears in GET /voicemail → play** (send/play round-trip).

## 12. Dependencies & Sequencing

- **Hard dependency: AND-133 (Voice messages)** — must land first; provides `AudioRecorder`, `WaveformCapture`, `AudioPlayerController`, ExoPlayer `SimpleCache`, and `RECORD_AUDIO` permission flow. This ticket is blocked until those APIs are stable.
- **Transitively** relies on the shared OkHttp/auth stack (cookie jar, CSRF interceptor, single-refresh-on-401), `core-network` Retrofit/Moshi setup, and the `ApiResult`/`detail`-parser utilities — all assumed delivered by earlier core tickets.
- **Sequencing within ticket:** (1) `core-model` + Moshi models validated against `/openapi.json`; (2) `VoicemailApi` + `VoicemailUploader` + unit tests; (3) `VoicemailRepository` + Room + Paging; (4) Compose/Inbox screens + VMs; (5) playback wiring; (6) E2E acceptance test.
- **Blocks:** none recorded in backlog.

## 13. Risks & Open Questions

- **OpenAPI shape uncertainty:** the exact `/voicemail`, `/voicemail/presign`, and read/delete paths and field names must be confirmed against `/openapi.json` and `frontend/src/api/endpoints/voicemail.ts`. The JSON in §5 is the expected contract pending that check.
- **Voicemail vs voice-message overlap:** if the backend actually models voicemail as a flavor of voice-message (AND-133), the dedicated `/voicemail` namespace may not exist — resolve before building `VoicemailApi`. **Open question.**
- **No background send queue:** offline/failed sends are user-retried in-screen this ticket; a durable WorkManager upload queue is out of scope (candidate follow-up).
- **Read semantics:** does playback auto-mark read, or only after N seconds / completion? Assumed on play-start; confirm with product.
- **Delete support:** gated on `DELETE /voicemail/{id}` existing; if absent, swipe-to-delete is deferred.
- **Presigned URL expiry vs ExoPlayer caching:** long playback sessions could outlive `playback_url`; mitigated by 403-triggered refresh (§7) but needs a refresh endpoint or row re-fetch confirmed.

## 14. Acceptance Criteria

AC-1 A recorded clip is sent via the full pipeline: `POST /voicemail/presign` → `PUT {upload_url}` → `POST /voicemail`, and on success the compose screen shows **Sent** and returns to the inbox. (Backlog: *send works*.)

AC-2 A received voicemail appears in the inbox list (newest-first) with sender, duration, relative time, and an unread indicator.

AC-3 Tapping a voicemail plays it through Media3/ExoPlayer with working play/pause and scrub; only one plays at a time. (Backlog: *play works*.)

AC-4 Playing (or explicit mark-read) clears the unread indicator and issues `POST /voicemail/{id}/read`, with optimistic UI and revert on failure.

AC-5 The S3 PUT request contains **no** session `Cookie` or `X-CSRF-Token` header; the `presign`/`create`/`read` requests **do** carry `X-CSRF-Token`. (Verified by test.)

AC-6 Failure at any stage leaves a retryable state: a failed upload retains the local draft for retry; a `create` failure after a successful PUT retries `create` only (no re-upload).

AC-7 Offline: inbox shows cached rows with a stale banner; `GET /voicemail` uses ~20s timeout with bounded retry, while POST/presign do not auto-retry.

AC-8 TalkBack reads each row as a single labeled node and announces send progress; all interactive controls meet ≥48dp and have content descriptions.

## 15. Definition of Done

- All §14 acceptance criteria pass, including the end-to-end **record→send→play** test.
- `feature-voicemail`, `core-data` repo, `core-network` API, and `core-model` types implemented per §4 under `com.testlogon.android.*`, building on Kotlin 2.0.21 / AGP 8.7.3 / Gradle 8.9, minSdk 24 / target 35, JDK 17.
- Unit + Compose + integration tests (§11) green in CI; ktlint/detekt clean; no new lint errors.
- All Moshi models verified against `/openapi.json`; any deviation from §5 documented and reflected in code.
- No presigned URLs logged in full; `@Named("plain")` S3 client confirmed cookie/CSRF-free by test.
- Strings externalized and TalkBack-verified; RTL spot-checked.
- Open questions in §13 (voicemail-vs-voice-message modeling, read semantics, delete support) resolved or explicitly ticketed as follow-ups.
- Merged to `android-port` with the feature reachable via `VoicemailRoutes.INBOX` from its entry point.
