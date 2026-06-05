---
id: AND-132
title: File messages / share
milestone: M3
epic: E19
priority: P1
size: M
status: draft
depends_on: [AND-129]
blocks: []
---

# AND-132 — File messages / share

## 1. Overview & Goal

This ticket delivers the file-message capability for the TestLogon native Android
client: a user can attach an arbitrary file to a conversation, send it as a
**file message**, and the recipient can **download and open** that file. It also
covers the **share** variant (`/messages/file-share`), where a file is shared into
a conversation with an explicit grant/consume access flow rather than an inline
upload-and-attach.

Concretely, AND-132 wires the reusable attachment uploader from AND-129
(presign → PUT → confirm) into the messaging surface to produce a `file` message,
renders that message bubble in the conversation timeline, and implements the
**download + open** path on the receiving side. The download path must respect the
backend's **consume/grant** semantics: a file attachment is fetched via a
short-lived, server-issued download grant that the client consumes exactly once to
obtain the bytes, then opens the result with an Android `Intent.ACTION_VIEW`
through a `FileProvider`.

Success means: a sender selects a file, it uploads with progress (AND-129), a
`file` message appears in both participants' timelines, and the recipient taps the
bubble, the bytes download to app-private storage, and the system "open with"
chooser launches the appropriate viewer. The end-to-end round trip is covered by
an instrumented/MockWebServer test.

Out of scope: the generic uploader itself (owned by AND-129), inline image/video
preview rendering and thumbnails (owned by the media-message tickets in E19),
voice/audio messages, and message composition UI chrome unrelated to the
attach-file affordance.

## 2. Context & References

- **Stack:** Kotlin 2.0.21, Jetpack Compose + Material 3, single-Activity
  Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 +
  Moshi 1.15, Room 2.6, DataStore, Coil, Paging 3. minSdk 24, compileSdk/targetSdk 35,
  JDK 17, Gradle 8.9, AGP 8.7.3.
- **Namespace / applicationId base:** `com.testlogon.android`.
- **Module layering:** `app -> feature-messaging -> core-network, core-model,
  core-data, core-ui, core-testing`. ViewModels expose `StateFlow<UiState>`; all API
  calls return typed `ApiResult<T>`; FastAPI `detail` errors are mapped
  (string | `[{msg}]` | `{code,...}`).
- **Backend:** FastAPI + DynamoDB; dev host `http://18.222.237.167:8000`
  (PLAINTEXT HTTP, unreliable). OpenAPI at `/openapi.json`. Web reference under
  `frontend/` — endpoint layer `frontend/src/api/endpoints/*.ts`, shared types
  `frontend/src/api/types.ts`.
- **Auth:** cookie-based session with `ui_csrf` cookie echoed as `X-CSRF-Token`;
  persistent cookie jar; on `401` call `POST /ui/session/refresh` once then retry.
- **Upstream dependency — AND-129 (P0):** "Attachment pipeline
  (presign → PUT → confirm)". Provides the reusable uploader contract this ticket
  consumes. AND-132 MUST NOT reimplement presign/PUT/confirm; it depends on the
  `AttachmentUploader` interface and the `confirm` result (an `attachment_id`).
- **Endpoints owned here:** `/messages/file`, `/messages/file-share`, plus the
  download grant/consume endpoints described in §5.
- **Reference:** verify exact shapes against `/openapi.json` and
  `frontend/src/api/endpoints/messages.ts` before implementation; if shapes differ
  from §5, the OpenAPI spec is authoritative and §5 must be reconciled.

## 3. Functional Requirements

FR-1 **Attach affordance.** The conversation composer exposes an "attach file"
action (Material 3 icon button) that launches the system document picker via
`ActivityResultContracts.OpenDocument` with a wildcard MIME filter (`*/*`). The
client takes a persistable read permission on the returned `content://` URI long
enough to perform the upload.

FR-2 **Upload + send (file message).** On selection, the client invokes the
AND-129 `AttachmentUploader` to presign, PUT, and confirm, producing an
`attachment_id`. It then calls `POST /messages/file` with the conversation id and
`attachment_id` to materialize a `file` message. Upload progress and cancel/retry
are surfaced by AND-129; this ticket renders an optimistic "sending" bubble keyed
to the local upload until the server message id is returned.

FR-3 **Share variant.** `POST /messages/file-share` shares an
**existing/owned** file (identified by a file/attachment reference) into a
conversation, producing a `file` message that grants the recipient access without
re-uploading bytes. The composer's share entry point is reached via the system
share sheet target and via an in-app "share existing file" action.

FR-4 **Render file bubble.** A `file` message renders a bubble showing file name,
human-readable size, MIME-derived icon, and a download/open control. State of the
control reflects: not-downloaded, downloading (determinate progress), downloaded
(open), and failed (retry).

FR-5 **Download + open (consume/grant).** Tapping the control on a not-downloaded
bubble requests a download grant for the attachment, consumes it to stream bytes
to app-private cache, then exposes the file to an external viewer via
`FileProvider` + `Intent.ACTION_VIEW` with `FLAG_GRANT_READ_URI_PERMISSION`.

FR-6 **Cache reuse.** A previously downloaded file (verified by attachment id +
size/etag) is opened directly without re-downloading.

FR-7 **Failure states.** Picker cancellation, upload failure, message-create
failure, grant expiry, download failure, and "no app to open this type" each
produce a specific, recoverable UI state (see §7).

FR-8 **Idempotency.** Re-tapping send during an in-flight upload does not create
duplicate messages; the message-create call carries a client-generated
idempotency key.

## 4. Technical Design

New code lives in `feature-messaging` with data types in `core-model` and the
network interface in `core-network`.

**Models (`core-model`):**

```kotlin
data class FileMessageContent(
    val attachmentId: String,
    val fileName: String,
    val mimeType: String,
    val sizeBytes: Long,
    val downloadState: FileDownloadState = FileDownloadState.NotDownloaded,
)

sealed interface FileDownloadState {
    data object NotDownloaded : FileDownloadState
    data class Downloading(val fraction: Float) : FileDownloadState
    data class Downloaded(val localUri: String) : FileDownloadState
    data class Failed(val reason: FileError) : FileDownloadState
}
```

**Repository (`core-data`):**

```kotlin
interface FileMessageRepository {
    suspend fun sendFileMessage(
        conversationId: String,
        attachmentId: String,
        idempotencyKey: String,
    ): ApiResult<MessageDto>

    suspend fun shareFile(
        conversationId: String,
        fileRef: String,
        idempotencyKey: String,
    ): ApiResult<MessageDto>

    /** Requests grant, consumes it, streams bytes to app cache, returns local file. */
    fun downloadAttachment(
        attachmentId: String,
    ): Flow<DownloadProgress>   // emits Progress(fraction) then Done(File) or throws
}
```

**Download service (`core-data`):** `AttachmentDownloader` orchestrates the
grant/consume flow against `core-network`, writing to
`context.cacheDir/attachments/<attachmentId>/<fileName>` and resolving a content
URI via `FileProvider`. Streaming uses OkHttp `ResponseBody.source()` with
chunked reads to emit determinate progress from `Content-Length`.

**FileProvider:** declared in `feature-messaging` manifest with authority
`com.testlogon.android.fileprovider` and a `cache-path` root limited to
`attachments/`. Opening uses:

```kotlin
val uri = FileProvider.getUriForFile(context, "$applicationId.fileprovider", file)
val intent = Intent(Intent.ACTION_VIEW)
    .setDataAndType(uri, mimeType)
    .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
```

**ViewModel (`feature-messaging`):**

```kotlin
@HiltViewModel
class FileMessageViewModel @Inject constructor(
    private val uploader: AttachmentUploader,          // AND-129
    private val repo: FileMessageRepository,
) : ViewModel() {
    val uiState: StateFlow<FileMessageUiState>
    fun onFilePicked(uri: Uri, conversationId: String)
    fun onShareFile(fileRef: String, conversationId: String)
    fun onDownloadTap(message: MessageDto)
    fun onOpen(localUri: String, mimeType: String)
    fun onRetry()
    fun onCancel()
}
```

The ViewModel composes the AND-129 upload flow (`uploader.upload(uri)` returning
progress + final `attachmentId`) with `repo.sendFileMessage`. Optimistic message
state is held in a `MutableStateFlow` map keyed by `idempotencyKey` and reconciled
with the server message id on success.

**Compose (`feature-messaging`):** `FileMessageBubble(content, onTap)` renders the
four download states; `AttachFileButton(onClick)` integrates with the existing
composer row. The "open with" chooser is launched from a side-effect
(`LaunchedEffect` / `ActivityResultLauncher`) so it survives recomposition.

## 5. API Contract

All requests carry session cookies and `X-CSRF-Token`; mutations include
`Idempotency-Key`. Verify against `/openapi.json`.

**Send file message —** `POST /messages/file`

```json
// request
{
  "conversation_id": "conv_123",
  "attachment_id": "att_abc",       // from AND-129 confirm
  "client_message_id": "uuid-v4"    // idempotency
}
// 201 response (MessageDto)
{
  "id": "msg_789",
  "conversation_id": "conv_123",
  "type": "file",
  "sender_id": "user_1",
  "created_at": "2026-06-05T12:00:00Z",
  "file": {
    "attachment_id": "att_abc",
    "file_name": "report.pdf",
    "mime_type": "application/pdf",
    "size_bytes": 482113
  }
}
```

**Share file —** `POST /messages/file-share`

```json
// request
{
  "conversation_id": "conv_123",
  "file_ref": "file_xyz",           // owned file reference, no re-upload
  "client_message_id": "uuid-v4"
}
// 201 response: same MessageDto shape, type "file"
```

**Request download grant —** `POST /messages/file/{attachment_id}/grant`

```json
// 200 response
{
  "grant_id": "grant_55",
  "download_url": "/messages/file/att_abc/consume?grant=grant_55",
  "expires_at": "2026-06-05T12:05:00Z",
  "size_bytes": 482113,
  "mime_type": "application/pdf"
}
```

**Consume grant (fetch bytes) —** `GET` the returned `download_url`
(`/messages/file/{attachment_id}/consume?grant={grant_id}`). Returns the raw bytes
with `Content-Type` and `Content-Length`. The grant is single-use; a second
consume returns `410 Gone`.

**Error envelope (FastAPI `detail`):** mapped per project convention —
`string | [{ "msg": "..." }] | { "code": "...", ... }`. Notable codes:
`403` (not a participant / not owner for share), `404` (attachment/message gone),
`410` (grant expired or already consumed), `413` (size over limit, surfaced from
AND-129 confirm), `422` (validation).

If the OpenAPI spec exposes a single pre-signed GET URL instead of grant/consume,
collapse §4's `AttachmentDownloader` to a direct authenticated GET and treat the
URL's expiry as the grant; the consume/grant terminology in the ticket maps to
whichever the backend implements.

## 6. Data & State Management

- **Transient UI state:** `FileMessageUiState` (sealed) held in `StateFlow`;
  per-message download state held in a keyed map and merged into the Paging 3
  message stream by attachment id so scroll/recompose does not lose progress.
- **Persistence (Room, `core-data`):** the messages table (owned by the timeline
  ticket) gains no new table here; file metadata travels inside the cached
  `MessageDto` JSON / columns. A small `AttachmentCacheEntry(attachmentId,
  localPath, sizeBytes, etag, downloadedAt)` table (added by this ticket) records
  which attachments are already on disk for cache-reuse (FR-6).
- **DataStore:** no new prefs. (Max-cache-size policy, if any, deferred to a future
  housekeeping ticket.)
- **Disk:** downloaded bytes live under `cacheDir/attachments/<attachmentId>/`;
  these are eligible for OS cache eviction, and `AttachmentCacheEntry` rows are
  validated against file existence on read (stale rows pruned lazily).
- **Idempotency:** `client_message_id` (UUID v4) generated once per send attempt
  and reused across retries.

## 7. Error Handling & Resilience

- **Timeouts/retry:** consume `GET` and grant requests use the project's ~20s
  timeout. The **grant** request (`POST`) is non-idempotent and is NOT
  auto-retried. The **consume** `GET` is idempotent only until consumed; bounded
  backoff retry (max 2) applies to transport-level failures (connection reset),
  but a `410` is terminal → re-request a fresh grant.
- **401 handling:** inherited interceptor calls `POST /ui/session/refresh` once
  then retries the original request.
- **Grant expiry (`410`/`expires_at` passed):** auto-request a new grant once,
  transparently; if the second grant also fails, surface
  `FileError.GrantExpired`.
- **Upload failure:** delegated to AND-129; this ticket maps its terminal error to
  `FileError.UploadFailed` with a Retry action that restarts upload from the
  original picked URI (re-acquiring read permission if needed).
- **No viewer app:** `ActivityNotFoundException` from `ACTION_VIEW` →
  `FileError.NoViewer`, with a snackbar offering "Share" (`ACTION_SEND`) fallback.
- **Picker cancelled:** no-op, no error toast.
- **Network offline:** download control shows an offline state and re-enables when
  connectivity returns; cached files remain openable offline.
- **413 over-limit:** surfaced at send time from AND-129 confirm; non-retryable
  message explaining the size cap.

```kotlin
sealed interface FileError {
    data object UploadFailed : FileError
    data object GrantExpired : FileError
    data object DownloadFailed : FileError
    data object NoViewer : FileError
    data class Server(val message: String) : FileError
}
```

## 8. Security & Privacy

- **Transport:** dev backend is plaintext HTTP; the OkHttp `cleartextTraffic`
  allowance is scoped to the dev host only via network-security-config. Production
  builds MUST require HTTPS for all file traffic. Pre-signed/consume URLs are never
  logged.
- **FileProvider over file://:** external viewers receive a content URI with a
  transient read grant only; no `file://` URIs leave the app. The `cache-path`
  root is limited to `attachments/` so only downloaded message files are
  shareable.
- **SAF permissions:** the inbound picked URI uses a take-permission only for the
  duration of upload; persistable permission is released after confirm to avoid
  long-lived grants.
- **Grant single-use & expiry:** the consume grant is single-use and short-lived;
  the client does not cache `download_url`/`grant_id` beyond the active download.
- **CSRF/cookies:** all mutations send `X-CSRF-Token`; cookie jar is the shared
  persistent jar — no per-feature credential storage.
- **PII:** file names and sizes are user content; they appear in the timeline but
  are excluded from telemetry payloads (§10).

## 9. Accessibility & i18n

- All controls have `contentDescription`: attach button ("Attach file"), download
  control ("Download <fileName>"), open control ("Open <fileName>").
- Download progress exposes `Modifier.progressSemantics(fraction)` for
  TalkBack live announcement.
- Bubble tap targets are ≥48dp; download/open is keyboard- and switch-accessible.
- File size formatting uses `android.text.format.Formatter.formatShortFileSize`
  (locale-aware). All visible strings live in `strings.xml`
  (`feature-messaging`), no hardcoded literals. RTL layouts mirror the bubble.
- Errors are announced via `Snackbar` with accessible action labels.

## 10. Telemetry & Logging

- Events (via the app's analytics abstraction, no PII / no file names / no URLs):
  `file_message_send_started`, `file_message_send_succeeded`,
  `file_message_send_failed{error_code}`, `file_message_download_started`,
  `file_message_download_succeeded{bytes_bucketed}`,
  `file_message_download_failed{error_code}`, `file_message_open_no_viewer`.
- Properties limited to: conversation id (hashed), attachment id, mime category
  (e.g. `pdf`/`image`/`other`), size bucket, latency ms, retry count.
- Logging: structured `Timber` at debug for state transitions; URLs, grant ids,
  and cookies are redacted by the existing OkHttp logging redactor. Errors logged
  at warn with mapped `FileError`, not raw response bodies.

## 11. Testing Strategy

- **Unit (JVM, `core-testing` + MockWebServer):**
  - `sendFileMessage` posts correct body incl. `client_message_id`; maps `201`
    → `MessageDto`; maps `403/404/410/413/422` → correct `FileError`.
  - `shareFile` posts `file_ref` and produces a `file` message.
  - `AttachmentDownloader`: grant → consume happy path streams to file and emits
    monotonic progress fractions ending at 1.0; `410` on consume triggers exactly
    one grant re-request; second `410` → `GrantExpired`.
  - Idempotency: two `onFilePicked`-driven sends with the same in-flight upload
    create one message.
- **ViewModel:** `StateFlow` emissions for picked→uploading→sent and
  tap→downloading→downloaded→opened using a fake `AttachmentUploader` and fake
  repo with Turbine.
- **Compose UI test:** `FileMessageBubble` renders all four states; download
  control invokes callback; semantics/contentDescription assertions.
- **Instrumented / end-to-end (acceptance):** with MockWebServer scripting
  presign/PUT/confirm (AND-129) + `/messages/file` + grant/consume, assert a file
  uploads, a `file` message appears, and tapping triggers a download that lands
  bytes in cache and fires an `ACTION_VIEW` intent (verified via Espresso-Intents
  `intended(hasAction(ACTION_VIEW))`).
- **Coverage gate:** new `core-data`/`core-model` logic ≥80% line coverage.

## 12. Dependencies & Sequencing

- **Hard dependency — AND-129 (P0):** the `AttachmentUploader` interface and
  confirm-returns-`attachment_id` contract must be merged first. AND-132 consumes
  it directly and does not duplicate presign/PUT/confirm.
- **Transitive:** AND-129 depends on AND-117 (network/session foundations);
  AND-132 inherits the cookie jar, CSRF interceptor, and `ApiResult` mapping from
  that chain.
- **Soft:** the conversation timeline / Paging message list (sibling E19 tickets)
  provides the surface that renders `FileMessageBubble`; if not yet merged, develop
  the bubble behind a feature-flagged preview screen and integrate on merge.
- **Sequencing:** (1) models + repo + downloader with MockWebServer tests →
  (2) ViewModel + state reconciliation → (3) Compose bubble + composer attach
  button + FileProvider → (4) end-to-end instrumented test.
- **Blocks:** nothing currently listed.

## 13. Risks & Open Questions

- **R1 — Grant model uncertainty.** Backend may expose a single pre-signed GET
  URL instead of explicit grant/consume. Resolve by inspecting `/openapi.json` and
  `frontend/src/api/endpoints/messages.ts`; §5 fallback covers either shape.
- **R2 — `file-share` semantics.** Whether `file_ref` is an `attachment_id`, a
  separate file id, or a prior message id is unconfirmed. Confirm against OpenAPI
  before fixing the request schema.
- **R3 — Single-use consume + cache.** If a cached download is evicted by the OS,
  re-download needs a fresh grant; ensure `AttachmentCacheEntry` validates file
  existence before claiming "downloaded".
- **R4 — Unreliable dev host.** Large-file consume over flaky HTTP may stall;
  partial files must be deleted on failure (write to `.part`, atomic rename on
  success).
- **R5 — Open Q:** Is there a server-enforced size/MIME allowlist for `file`
  messages distinct from AND-129's upload limits? Affects pre-send validation.
- **R6 — Open Q:** Does `file-share` create a new attachment grant for the
  recipient or reuse the owner's? Impacts whether recipients hit `403` on consume.

## 14. Acceptance Criteria

AC-1 A user selects a file via the system picker, it uploads with progress
(AND-129), and `POST /messages/file` succeeds → a `file` message bubble appears in
the sender's timeline. (tested)

AC-2 The recipient sees the same `file` message; tapping the download control
performs grant → consume, streams bytes to app cache with determinate progress,
and the control transitions to "open". (tested)

AC-3 Tapping "open" launches an `ACTION_VIEW` chooser via `FileProvider`; verified
with Espresso-Intents. A type with no handler shows `NoViewer` with a Share
fallback. (tested)

AC-4 `POST /messages/file-share` with a valid file reference produces a `file`
message visible to recipients without re-uploading bytes. (tested)

AC-5 A consumed/expired grant (`410`) triggers exactly one transparent re-grant;
a second failure surfaces `GrantExpired`. (tested via MockWebServer)

AC-6 Duplicate send taps during one in-flight upload create exactly one message
(idempotency key). (tested)

AC-7 A previously downloaded file opens from cache without a network call. (tested)

AC-8 All `403/404/410/413/422` responses map to the correct `FileError` and
recoverable UI. (tested)

## 15. Definition of Done

- All §14 acceptance criteria pass in CI (JVM unit + instrumented).
- Code merged to `android-port` under `feature-messaging`/`core-data`/`core-model`/
  `core-network` following module layering; no presign/PUT/confirm duplication of
  AND-129.
- `FileProvider` declared with authority `com.testlogon.android.fileprovider`,
  scoped to `attachments/`; no `file://` URIs leave the app.
- New data-layer logic ≥80% line coverage; MockWebServer-backed tests for send,
  share, grant/consume, idempotency, and error mapping.
- Telemetry events emit with no PII (no file names/URLs); OkHttp redaction verified.
- Strings externalized, contentDescriptions present, RTL verified, tap targets
  ≥48dp.
- Cleartext HTTP restricted to dev host via network-security-config; production
  enforces HTTPS.
- Lint, detekt, and ktlint clean; PR reviewed and approved.
