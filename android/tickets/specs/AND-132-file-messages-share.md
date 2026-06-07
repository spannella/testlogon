---
id: AND-132
title: File messages / share
milestone: M3
epic: E19
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-129]
blocks: []
---

# AND-132 — File messages / share

## 1. Overview & Goal

This ticket delivers the file-message capability for the TestLogon native Android
client: a user can attach an arbitrary file to a conversation, send it as a
**file message**, and the recipient can **download and open** that file. It also
covers the **share** variant (`.../messages/file-share`), where a file is shared into
a conversation with an explicit grant/consume access flow rather than an inline
upload-and-attach.

Concretely, AND-132 wires the reusable attachment uploader from AND-129
(presign → PUT → confirm) into the messaging surface to produce a `file` message,
renders that message bubble in the conversation timeline, and implements the
**download + open** path on the receiving side. The download path must respect the
backend's **grant/consume** semantics: a recipient first creates a single-use
attachment **grant** (`POST .../attachment/grant`, returning a `grant_token`),
optionally **consumes** it (`POST .../attachment/consume`, which records the
consumption for `view_once`/`listen_once` policy messages and returns metadata, NOT
the bytes), and then fetches the raw bytes via `GET .../attachment?grant_token=...`.
The result is opened with an Android `Intent.ACTION_VIEW` through a `FileProvider`.

> **Reviewer note (2026-06-06, AND-132 amendment):** This spec was originally
> drafted against an assumed `attachment_id`-based contract. Verification against
> the live OpenAPI (`/openapi.json`) and the web reference (`src/api/endpoints/messaging.ts`,
> `src/api/types.ts`) shows the real contract differs substantially: the send/share
> endpoints are nested under `/messaging/conversations/{conversation_id}/...`, the
> file payload is identified by a **virtual-filesystem `path`** (not an
> `attachment_id`), the download/grant/consume flow is keyed by **`message_id`**,
> and `created_at`/`expires_at` are **integer epoch seconds**. All such claims have
> been corrected inline and audited in §16.

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
  `frontend/src/api/types.ts`. **Note:** the file/messaging calls live in
  `src/api/endpoints/messaging.ts` (there is no `messages.ts`).
- **Auth:** cookie-based session with `ui_csrf` cookie echoed as `X-CSRF-Token`;
  persistent cookie jar; on `401` call `POST /ui/session/refresh` once then retry.
- **Upstream dependency — AND-129 (P0):** "Attachment pipeline
  (presign → PUT → confirm)". Provides the reusable uploader contract this ticket
  consumes. AND-132 MUST NOT reimplement presign/PUT/confirm; it depends on the
  `AttachmentUploader` interface and the `confirm` result. **Correction:** the
  `POST .../messages/file` request body takes a virtual-filesystem **`path`**
  (string), NOT an `attachment_id` (verified: `CreateFileMessageIn.path`,
  `SendFileMessageReq.path`). The image-message flow in the web reference uploads
  via presign and then references the uploaded object by `storage_key`/`path` (see
  `messaging.ts` `sendImageMessage`). AND-129's confirm result MUST therefore yield
  the server-side **path/storage key** that this ticket passes as `path`; whether
  AND-129 exposes that as `attachment_id` or `path` is an integration point to
  reconcile with the AND-129 author (see §16 Open assumptions).
- **Endpoints owned here (corrected, verified 2026-06-06):**
  `POST /messaging/conversations/{conversation_id}/messages/file`,
  `POST /messaging/conversations/{conversation_id}/messages/file-share`, plus the
  download grant/consume endpoints described in §5 (all nested under the
  conversation and keyed by `message_id`).
- **Reference:** shapes were verified against `/openapi.json` and
  `frontend/src/api/endpoints/messaging.ts` / `src/api/types.ts`; the OpenAPI spec
  is authoritative and §5 has been reconciled to it (see §16).

## 3. Functional Requirements

FR-1 **Attach affordance.** The conversation composer exposes an "attach file"
action (Material 3 icon button) that launches the system document picker via
`ActivityResultContracts.OpenDocument` with a wildcard MIME filter (`*/*`). The
client takes a persistable read permission on the returned `content://` URI long
enough to perform the upload.

FR-2 **Upload + send (file message).** On selection, the client invokes the
AND-129 `AttachmentUploader` to presign, PUT, and confirm, producing a server-side
**path/storage key**. It then calls
`POST /messaging/conversations/{conversation_id}/messages/file` with body
`{ "path": "<key>", "kind": "file" }` (the conversation id is a path param, NOT in
the body) to materialize a `file` message. Upload progress and cancel/retry are
surfaced by AND-129; this ticket renders an optimistic "sending" bubble keyed to
the local upload until the server `message_id` is returned.

FR-3 **Share variant.** `POST /messaging/conversations/{conversation_id}/messages/file-share`
shares an **existing/owned** file (identified by `file_path`, a virtual-filesystem
path) into a conversation, with a `permission` of `"read"` (default) or `"write"`
and an optional `text` caption and `send_at` (epoch). It produces a `file_share`
message that grants the recipient access without re-uploading bytes. The composer's
share entry point is reached via the system share sheet target and via an in-app
"share existing file" action. (Verified: `CreateFileShareMessageIn`,
`SendFileShareReq`, and `src/pages/files/ShareDialog.tsx`.)

FR-4 **Render file bubble.** A `file` message renders a bubble showing file name,
human-readable size, MIME-derived icon, and a download/open control. State of the
control reflects: not-downloaded, downloading (determinate progress), downloaded
(open), and failed (retry).

FR-5 **Download + open (grant/consume).** Tapping the control on a not-downloaded
bubble (1) creates a grant via `POST .../messages/{message_id}/attachment/grant`
(empty body → `grant_token`, `expires_at`); (2) for `view_once`/`listen_once`
policy messages, records consumption via
`POST .../messages/{message_id}/attachment/consume` (body
`{ consumption_attempt_id, trigger: "open" }`, `grant_token` passed as a query
param); (3) streams the bytes via `GET .../messages/{message_id}/attachment?grant_token=...`
to app-private cache; then exposes the file to an external viewer via `FileProvider`
+ `Intent.ACTION_VIEW` with `FLAG_GRANT_READ_URI_PERMISSION`. **Correction:** the
flow is keyed by `message_id`, not `attachment_id`; and `consume` returns metadata
(`ConsumeAttachmentOut`), not the file bytes — the bytes come from the GET.

FR-6 **Cache reuse.** A previously downloaded file (keyed by `message_id` +
size/etag) is opened directly without re-downloading. **Caveat:** for
`view_once`/`listen_once` consumption-policy messages a re-open is server-gated
(consumption is single-use); cache reuse therefore applies only to
`consumption_policy: "none"` file messages (see §16 Open assumptions).

FR-7 **Failure states.** Picker cancellation, upload failure, message-create
failure, grant expiry, download failure, and "no app to open this type" each
produce a specific, recoverable UI state (see §7).

FR-8 **Idempotency.** Re-tapping send during an in-flight upload does not create
duplicate messages. **Correction:** the file/file-share endpoints do NOT accept a
`client_message_id` body field, and the web reference does not send an idempotency
key on these calls. Idempotency in this backend is conveyed via an
`Idempotency-Key` **HTTP header** on the endpoints that support it (see
`messaging.ts` drafts/lottery). For file send, idempotency is therefore enforced
**client-side** (gate the send button / dedupe in-flight by local upload id);
sending an `Idempotency-Key` header is best-effort and unverified for these two
endpoints (see §16 Open assumptions).

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
    // NOTE (corrected): body carries `path` (a VFS path/storage key), not attachment_id;
    // conversationId is a URL path segment. No idempotencyKey body field exists; pass an
    // Idempotency-Key header only if confirmed supported (see §16) — otherwise omit.
    suspend fun sendFileMessage(
        conversationId: String,
        path: String,                 // server-side path/storage key from AND-129 confirm
        kind: String = "file",        // "file" | "audio" | "video"
        consumptionPolicy: String = "none", // "none" | "view_once" | "listen_once"
    ): ApiResult<MessageDto>

    suspend fun shareFile(
        conversationId: String,
        filePath: String,             // VFS path of an owned file
        permission: String = "read",  // "read" | "write"
        text: String? = null,
    ): ApiResult<MessageDto>

    /** grant -> (optional) consume -> GET bytes to app cache, keyed by messageId. */
    fun downloadAttachment(
        conversationId: String,
        messageId: String,
    ): Flow<DownloadProgress>   // emits Progress(fraction) then Done(File) or throws
}
```

**Download service (`core-data`):** `AttachmentDownloader` orchestrates the
grant → (optional) consume → GET-bytes flow against `core-network`, writing to
`context.cacheDir/attachments/<messageId>/<fileName>` and resolving a content
URI via `FileProvider`. Streaming uses OkHttp `ResponseBody.source()` with
chunked reads to emit determinate progress from `Content-Length`. (Cache is keyed
by `message_id`; `grant_token` is a query param on the GET, and `consume` is a
separate metadata-only POST issued only for `view_once`/`listen_once` policies.)

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

All requests carry session cookies and `X-CSRF-Token` (from the `ui_csrf` cookie).
The following shapes are **verified against `/openapi.json` and
`src/api/endpoints/messaging.ts` / `src/api/types.ts` (2026-06-06)**. All
timestamps are **integer epoch seconds**, not ISO-8601 strings.

**Send file message —** `POST /messaging/conversations/{conversation_id}/messages/file`
(op `create_file_message`, req `CreateFileMessageIn`, resp `200:MessageOut`)

```json
// request (CreateFileMessageIn) — `path` is REQUIRED; conversation_id is a URL path param
{
  "path": "users/user_1/files/report.pdf",  // VFS path / storage key; NOT attachment_id
  "kind": "file",                            // "file" | "audio" | "video" (default "file")
  "consumption_policy": "none",              // "none" | "view_once" | "listen_once"
  "duration_seconds": null,                  // optional (audio/video)
  "reply_to_message_id": null,               // optional
  "signature_packet_id": null,               // optional
  "preview": null                            // optional LinkPreviewIn
}
// 200 response (MessageOut) — id field is `message_id`; created_at is epoch int
{
  "message_id": "msg_789",
  "conversation_id": "conv_123",
  "sender_id": "user_1",
  "created_at": 1749124800,
  "kind": "file",
  "file": { /* free-form object; subfields not pinned by schema — see §16 */ }
}
```

**Share file —** `POST /messaging/conversations/{conversation_id}/messages/file-share`
(op `create_file_share_message`, req `CreateFileShareMessageIn`, resp `200:MessageOut`)

```json
// request (CreateFileShareMessageIn) — `file_path` is REQUIRED
{
  "file_path": "users/user_1/files/report.pdf", // VFS path of an owned file
  "permission": "read",                         // "read" | "write" (default "read")
  "text": null,                                 // optional caption, <= 2000 chars
  "send_at": null                               // optional epoch schedule
}
// 200 response: MessageOut, kind "file_share" (file payload under `file_share`)
```

**Create download grant —** `POST /messaging/conversations/{conversation_id}/messages/{message_id}/attachment/grant`
(op `create_once_media_attachment_grant`, empty body `{}`, resp `200:AttachmentGrantOut`)

```json
// 200 response (AttachmentGrantOut)
{
  "grant_token": "g_55abc...",
  "expires_at": 1749125100,     // epoch seconds
  "conversation_id": "conv_123",
  "message_id": "msg_789"
}
```

**Consume grant (metadata only) —** `POST /messaging/conversations/{conversation_id}/messages/{message_id}/attachment/consume`
(op `consume_once_media_attachment`, req `ConsumeAttachmentIn`, resp `200:ConsumeAttachmentOut`;
`grant_token` is a QUERY param). This records single-use consumption for
`view_once`/`listen_once` policies — it does **not** return file bytes.

```json
// request (ConsumeAttachmentIn)
{
  "consumption_attempt_id": "att-8-128-chars", // required, 8..128 chars
  "trigger": "open",                            // "open" | "play"
  "playback_seconds": null                      // optional, >= 0
}
// 200 response (ConsumeAttachmentOut)
{
  "ok": true,
  "conversation_id": "conv_123",
  "message_id": "msg_789",
  "consumption_state": "consumed",
  "consumed_at": 1749124900,
  "consumption_attempt_id": "att-8-128-chars"
}
```

**Fetch bytes —** `GET /messaging/conversations/{conversation_id}/messages/{message_id}/attachment?grant_token={grant_token}`
(op `download_message_attachment`; also accepts `X-Request-Id`). Returns the raw
bytes with `Content-Type` and `Content-Length`. (Web reference builds this URL via
`buildAttachmentDownloadUrl` in `messaging.ts`.)

**Error envelope (FastAPI `detail`):** mapped per project convention —
`string | [{ "msg": "..." }] | { "code": "...", ... }`. **Documented** response
codes for the send `file` endpoint are `400, 401, 403, 422, 429`; grant/consume
expose `422` (plus the standard `401/403/404` for participant/ownership/missing).
**Correction:** `410 Gone` and `413 Payload Too Large` are **NOT documented** in
the OpenAPI for these endpoints — treat them as defensive client handling
(plausible for an expired/already-consumed grant and an over-limit upload) and
mark them as unverified assumptions (see §16). `429` (rate limit) IS documented and
should be handled with backoff.

## 6. Data & State Management

- **Transient UI state:** `FileMessageUiState` (sealed) held in `StateFlow`;
  per-message download state held in a keyed map and merged into the Paging 3
  message stream by `message_id` so scroll/recompose does not lose progress.
- **Persistence (Room, `core-data`):** the messages table (owned by the timeline
  ticket) gains no new table here; file metadata travels inside the cached
  `MessageDto` JSON / columns. A small `AttachmentCacheEntry(messageId,
  localPath, sizeBytes, etag, downloadedAt)` table (added by this ticket) records
  which attachments are already on disk for cache-reuse (FR-6). Keying by
  `message_id` matches the grant/consume/download API surface.
- **DataStore:** no new prefs. (Max-cache-size policy, if any, deferred to a future
  housekeeping ticket.)
- **Disk:** downloaded bytes live under `cacheDir/attachments/<messageId>/`;
  these are eligible for OS cache eviction, and `AttachmentCacheEntry` rows are
  validated against file existence on read (stale rows pruned lazily).
- **Idempotency:** enforced client-side (a per-send-attempt local upload id gates
  the send button and dedupes in-flight retries). The endpoints carry no
  `client_message_id` body field; an `Idempotency-Key` header may be attached if
  confirmed supported (see §16).

## 7. Error Handling & Resilience

- **Timeouts/retry:** the download `GET`, grant `POST`, and consume `POST` use the
  project's ~20s timeout. The **grant** request (`POST`, empty body) is
  non-idempotent and is NOT auto-retried. The **consume** `POST` records single-use
  consumption (carries a client-generated `consumption_attempt_id`) and must NOT be
  blindly retried. The bytes **`GET`** (`...?grant_token=...`) is safe to retry
  while the grant is valid; bounded backoff retry (max 2) applies to
  transport-level failures (connection reset). If the grant is rejected (e.g. an
  undocumented `410`, or `403/404`), treat it as terminal → re-request a fresh
  grant. **Note:** `410` is not a documented response for these endpoints (§5/§16);
  the handler should key off whatever status the server actually returns for an
  expired/consumed grant and fall back to a fresh-grant retry.
- **401 handling:** inherited interceptor calls `POST /ui/session/refresh` once
  then retries the original request.
- **Grant expiry (grant rejected, or local clock past `expires_at`):** auto-request
  a new grant once, transparently; if the second grant also fails, surface
  `FileError.GrantExpired`. (`expires_at` is epoch seconds.)
- **Upload failure:** delegated to AND-129; this ticket maps its terminal error to
  `FileError.UploadFailed` with a Retry action that restarts upload from the
  original picked URI (re-acquiring read permission if needed).
- **No viewer app:** `ActivityNotFoundException` from `ACTION_VIEW` →
  `FileError.NoViewer`, with a snackbar offering "Share" (`ACTION_SEND`) fallback.
- **Picker cancelled:** no-op, no error toast.
- **Network offline:** download control shows an offline state and re-enables when
  connectivity returns; cached files remain openable offline.
- **413 over-limit:** surfaced at send time from AND-129 confirm; non-retryable
  message explaining the size cap. (Undocumented on the file endpoints themselves —
  see §16; the authoritative size enforcement is AND-129's upload limit.)
- **429 rate-limited:** documented on the send `file` endpoint; back off and retry
  with jitter, surfacing a transient "try again" state (not a terminal error).

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
  - `sendFileMessage` posts `{path, kind}` to
    `/messaging/conversations/{id}/messages/file`; maps `200` → `MessageDto`
    (`message_id`, epoch `created_at`); maps `400/401/403/422/429` → correct
    `FileError`/transient state.
  - `shareFile` posts `{file_path, permission}` and produces a `file_share` message.
  - `AttachmentDownloader`: grant → (consume for once-policies) → GET-bytes happy
    path streams to file and emits monotonic progress fractions ending at 1.0; a
    rejected grant on the bytes GET triggers exactly one grant re-request; a second
    rejection → `GrantExpired`.
  - Idempotency: two `onFilePicked`-driven sends with the same in-flight upload
    create one message.
- **ViewModel:** `StateFlow` emissions for picked→uploading→sent and
  tap→downloading→downloaded→opened using a fake `AttachmentUploader` and fake
  repo with Turbine.
- **Compose UI test:** `FileMessageBubble` renders all four states; download
  control invokes callback; semantics/contentDescription assertions.
- **Instrumented / end-to-end (acceptance):** with MockWebServer scripting
  presign/PUT/confirm (AND-129) + `.../messages/file` + grant/consume/GET, assert a file
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

- **R1 — Grant model (RESOLVED 2026-06-06).** The backend uses explicit
  grant/consume keyed by `message_id`: `POST .../attachment/grant` →
  `AttachmentGrantOut`, optional `POST .../attachment/consume` (metadata only), and
  `GET .../attachment?grant_token=...` for bytes. §5 reflects this; no pre-signed
  single-GET fallback is needed.
- **R2 — `file-share` semantics (RESOLVED 2026-06-06).** The request field is
  `file_path` (a virtual-filesystem path of an owned file), plus a `permission`
  (`read`/`write`). It is NOT an `attachment_id`, file id, or message id. Confirmed
  via `CreateFileShareMessageIn`/`SendFileShareReq` and `ShareDialog.tsx`.
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
(AND-129), and `POST /messaging/conversations/{id}/messages/file` (body
`{path, kind}`) succeeds → a `file` message bubble appears in the sender's
timeline. (tested)

AC-2 The recipient sees the same `file` message; tapping the download control
performs grant → (consume for once-policies) → bytes `GET`, streams bytes to app
cache with determinate progress, and the control transitions to "open". (tested)

AC-3 Tapping "open" launches an `ACTION_VIEW` chooser via `FileProvider`; verified
with Espresso-Intents. A type with no handler shows `NoViewer` with a Share
fallback. (tested)

AC-4 `POST /messaging/conversations/{id}/messages/file-share` with a valid
`file_path` (+ `permission`) produces a `file_share` message visible to recipients
without re-uploading bytes. (tested)

AC-5 A rejected/expired grant triggers exactly one transparent re-grant; a second
failure surfaces `GrantExpired`. (tested via MockWebServer)

AC-6 Duplicate send taps during one in-flight upload create exactly one message
(client-side idempotency gate; no server `client_message_id`). (tested)

AC-7 A previously downloaded `consumption_policy: "none"` file opens from cache
without a network call. (tested)

AC-8 The documented error responses (`400/401/403/422/429`) and defensively-handled
`404` map to the correct `FileError`/transient state and recoverable UI. (tested)

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

## 16. Citations & Assumption Audit

Each key technical claim with its VERDICT and exact SOURCE pointer. Verified
2026-06-06 against `reference/openapi.index.txt`, `reference/openapi.pretty.json`
(`components.schemas.<Name>`), and `reference/src/`.

1. **Send-file endpoint path.** Spec originally said `POST /messages/file`.
   VERDICT: **Corrected** → `POST /messaging/conversations/{conversation_id}/messages/file`.
   SOURCE: OpenAPI `POST /messaging/conversations/{conversation_id}/messages/file`
   (op `create_file_message`); frontend `src/api/endpoints/messaging.ts: sendFileMessage`.
2. **Send-file request body.** Spec said `{conversation_id, attachment_id, client_message_id}`.
   VERDICT: **Corrected** → required `path` (VFS path/storage key) plus optional
   `kind` (`file`/`audio`/`video`), `consumption_policy`, `duration_seconds`,
   `reply_to_message_id`, `signature_packet_id`, `preview`; conversation id is a URL
   path param; no `attachment_id`, no `client_message_id`. SOURCE: schema
   `CreateFileMessageIn`; `src/api/types.ts: SendFileMessageReq`.
3. **Send-file success status/shape.** Spec said `201` with `{id, type, created_at: ISO}`.
   VERDICT: **Corrected** → `200:MessageOut`; id field is `message_id`; `created_at`
   is an integer (epoch seconds); discriminator is `kind` (not `type`). SOURCE:
   OpenAPI index line for the endpoint (`resp=200:MessageOut`); schema `MessageOut`
   (`required: conversation_id, message_id, sender_id, created_at, kind`).
4. **MessageOut.file subfields** (`file_name`, `mime_type`, `size_bytes`).
   VERDICT: **Unverified-assumption** → `MessageOut.file` and `.file_share` are
   free-form objects (`additionalProperties: true`); exact subfield names are not
   pinned by the schema. SOURCE: schema `MessageOut.file` / `.file_share`. The
   client should parse defensively and confirm field names against a live response.
5. **Share endpoint path & body.** Spec said `POST /messages/file-share` with
   `{conversation_id, file_ref, client_message_id}`. VERDICT: **Corrected** →
   `POST /messaging/conversations/{conversation_id}/messages/file-share`, body
   required `file_path` plus `permission` (`read`/`write`, default `read`), optional
   `text` (<=2000), `send_at` (epoch). Response `200:MessageOut`, `kind: "file_share"`.
   SOURCE: OpenAPI `... /messages/file-share` (op `create_file_share_message`),
   schema `CreateFileShareMessageIn`; `src/api/types.ts: SendFileShareReq`;
   `src/pages/files/ShareDialog.tsx` (`shareFile({path, to_user, permission})`).
6. **Download grant endpoint.** Spec said `POST /messages/file/{attachment_id}/grant`
   returning `{grant_id, download_url, expires_at: ISO, size_bytes, mime_type}`.
   VERDICT: **Corrected** →
   `POST /messaging/conversations/{conversation_id}/messages/{message_id}/attachment/grant`
   (empty body), returns `AttachmentGrantOut {grant_token, expires_at (int epoch),
   conversation_id, message_id}` — no `download_url`/`size_bytes`/`mime_type`, keyed
   by `message_id`. SOURCE: OpenAPI op `create_once_media_attachment_grant`; schema
   `AttachmentGrantOut`; `messaging.ts: createOnceMediaAttachmentGrant`,
   `types.ts: CreateAttachmentGrantResp`.
7. **Consume = fetch bytes via GET.** Spec said `GET .../consume?grant=...` returns
   raw bytes. VERDICT: **Corrected** → consume is a separate
   `POST .../attachment/consume` (req `ConsumeAttachmentIn {consumption_attempt_id,
   trigger: open|play, playback_seconds?}`, `grant_token` as a query param) that
   returns **metadata** `ConsumeAttachmentOut {ok, consumption_state:"consumed",
   consumed_at, ...}`, NOT bytes. Bytes come from
   `GET .../attachment?grant_token=...`. SOURCE: OpenAPI ops
   `consume_once_media_attachment` and `download_message_attachment`; schemas
   `ConsumeAttachmentIn`/`ConsumeAttachmentOut`; `messaging.ts:
   consumeOnceMediaAttachment` (passes `grant_token` as 3rd-arg query) and
   `buildAttachmentDownloadUrl`; `types.ts: ConsumeAttachmentReq/Resp`.
8. **Auth: CSRF.** Spec: `ui_csrf` cookie echoed as `X-CSRF-Token`. VERDICT:
   **Verified**. SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` →
   `headers.set("X-CSRF-Token", csrf)`, lines ~168-170).
9. **Auth: 401 refresh.** Spec: on `401` call `POST /ui/session/refresh` once then
   retry. VERDICT: **Verified** (single-flight via `refreshPromise`; on refresh
   failure the auth store logs out). SOURCE: `src/api/client.ts: refreshSession`
   (POST `/ui/session/refresh`, lines ~119-130).
10. **Idempotency via `client_message_id` body.** VERDICT: **Corrected /
    Unverified-assumption** → no such body field exists on the file endpoints; the
    web reference sends no idempotency key on `sendFileMessage`/`sendFileShareMessage`.
    Where idempotency is supported elsewhere it uses an `Idempotency-Key` **header**
    (e.g. drafts/lottery). AND-132 enforces idempotency client-side. SOURCE:
    `CreateFileMessageIn`/`CreateFileShareMessageIn` (no such field); `messaging.ts:
    sendFileMessage`/`sendFileShareMessage` (no header); contrast
    `messaging.ts: createConversationDraft` (`Idempotency-Key` header).
11. **Error codes `410`/`413`.** Spec relied on `410 Gone` (grant) and `413`
    (size). VERDICT: **Unverified-assumption** → neither is documented in OpenAPI
    for these endpoints. Documented codes: send `file` = `400,401,403,422,429`;
    grant/consume = `422` (+ standard `401/403/404`). SOURCE: OpenAPI index lines
    for `.../messages/file`, `.../attachment/grant`, `.../attachment/consume`.
12. **`429` rate limiting.** VERDICT: **Verified** (documented on send `file`).
    SOURCE: OpenAPI index `resp=...;429` on `create_file_message`.
13. **AND-129 confirm yields `attachment_id` that is passed to send.** VERDICT:
    **Unverified-assumption** → the send body needs a `path`/storage key, not an
    `attachment_id`. The image flow uploads via presign then references the object
    by storage key. The AND-129 ⇄ AND-132 hand-off field must be reconciled with the
    AND-129 author. SOURCE: `messaging.ts: sendImageMessage` (presign → reference by
    key); schema `CreateFileMessageIn.path`.
14. **Framework choices** (Compose, `ActivityResultContracts.OpenDocument`,
    `FileProvider` + `ACTION_VIEW` + `FLAG_GRANT_READ_URI_PERMISSION`, persistable
    URI permission, `progressSemantics`). VERDICT: **Verified (framework ref)** —
    standard Android APIs, not backend contract. SOURCE (framework ref):
    developer.android.com/reference/androidx/core/content/FileProvider,
    developer.android.com/training/data-storage/shared/documents-files,
    developer.android.com/reference/android/content/Intent#ACTION_VIEW.

### Corrections made
- Endpoint paths re-rooted under `/messaging/conversations/{conversation_id}/...`
  (§1, §2, §3, §5, §11, §14) — items 1, 5, 6, 7.
- Send body changed from `attachment_id`+`client_message_id` to `path`(+`kind`,
  `consumption_policy`, …); share body from `file_ref` to `file_path`+`permission`
  (§3, §4, §5) — items 2, 5.
- Response status `201`→`200`; `id`→`message_id`; ISO timestamps → epoch integers
  (§5, §14) — item 3.
- Grant/consume flow rewritten: grant (POST, empty) → consume (POST, metadata only,
  `grant_token` query param) → bytes via GET; keyed by `message_id` not
  `attachment_id` (§1, §4, §5, §6, §7) — items 6, 7.
- Idempotency reframed as client-side / header-based; removed reliance on a
  `client_message_id` body field (§3 FR-8, §6, §14 AC-6) — item 10.
- Error handling: `410`/`413` demoted to defensive/undocumented; `429` added as a
  documented, retryable case (§5, §7, §11, §14 AC-8) — items 11, 12.
- R1 and R2 marked RESOLVED with the verified contract (§13).
- Reference filename corrected `messages.ts` → `messaging.ts` (§2).

### Open assumptions
- **AC item 4 — `MessageOut.file` subfields.** The schema is free-form; `file_name`,
  `mime_type`, `size_bytes` are assumed. Why unverifiable: `additionalProperties:
  true` with no nested schema; needs a live response sample or backend confirmation.
- **AC item 13 — AND-129 ⇄ AND-132 hand-off field.** Whether AND-129 surfaces the
  send `path`/storage key directly. Why unverifiable: AND-129 is a separate ticket
  not present in these sources.
- **`view_once`/`listen_once` cache reuse (FR-6).** Whether once-policy files may be
  re-opened from local cache without a fresh consume is server-gated; assumed NOT
  reusable. Why unverifiable: consumption-enforcement behavior is server-side.
- **`410`/`413` semantics (items 11).** The actual status returned for an
  expired/already-consumed grant or an over-limit send is not documented; the client
  handles by status-agnostic fresh-grant retry and AND-129 pre-send size checks.
- **`X-API-Key` / `X-SESSION-ID` headers** appear in some endpoint param lists.
  Assumed handled by the inherited transport/session layer (AND-117/AND-129), not by
  this feature. Why noted: not exercised by the web reference's cookie-based client.

## 17. Test Plan

Test-target legend — **JVM** (local Robolectric/JUnit), **MWS** (MockWebServer
contract), **Emu35** (headless AVD `test35`, x86_64/API 35), **Dev-A15** (physical
Samsung Galaxy A15 5G, SM-A156U, serial R5CX821TA9R, API 34/arm64-v8a). Cases that
must run on the physical device are flagged; everything else runs on Emu35 in CI.

**TC-AND-132-01 — Send file: happy path (contract).**
Type: contract/MockWebServer (JVM+MWS). Target: `FileMessageRepository.sendFileMessage`.
Preconditions: MWS scripts `POST /messaging/conversations/c1/messages/file` →
`200 MessageOut`. Steps: call `sendFileMessage("c1", path="users/u1/files/r.pdf",
kind="file")`. Expected: request URL is the nested path; JSON body has `path` and
`kind`, and contains NO `attachment_id`/`client_message_id`/`conversation_id`;
parsed result exposes `message_id` and integer `created_at`, `kind == "file"`.
Traces: AC-1.

**TC-AND-132-02 — Share file: happy path (contract).**
Type: contract/MockWebServer (JVM+MWS). Target: `FileMessageRepository.shareFile`.
Preconditions: MWS scripts `.../messages/file-share` → `200 MessageOut`
(`kind:"file_share"`). Steps: call `shareFile("c1", filePath="users/u1/files/r.pdf",
permission="read")`. Expected: body has `file_path` + `permission` (no `file_ref`);
result `kind == "file_share"`; no presign/PUT call is made. Traces: AC-4.

**TC-AND-132-03 — Download: grant → GET bytes (no consume) for policy "none".**
Type: contract/MockWebServer (JVM+MWS). Target: `AttachmentDownloader`.
Preconditions: message `m1` has `consumption_policy:"none"`; MWS scripts
`POST .../m1/attachment/grant` → `AttachmentGrantOut{grant_token:"g1", expires_at}`
and `GET .../m1/attachment?grant_token=g1` → 200 bytes with `Content-Length`.
Steps: collect `downloadAttachment("c1","m1")`. Expected: grant POST has empty
body; bytes GET carries `grant_token=g1` as query; NO consume POST is sent for
policy "none"; progress fractions are monotonic and end at 1.0; file written under
`cacheDir/attachments/m1/`. Traces: AC-2.

**TC-AND-132-04 — Download: grant → consume → GET for "view_once".**
Type: contract/MockWebServer (JVM+MWS). Target: `AttachmentDownloader`.
Preconditions: message `m2` has `consumption_policy:"view_once"`; MWS scripts grant,
`POST .../m2/attachment/consume` (`grant_token` query) → `ConsumeAttachmentOut`, and
bytes GET. Steps: collect `downloadAttachment("c1","m2")`. Expected: consume body
carries `consumption_attempt_id` (8..128 chars) and `trigger:"open"`; `grant_token`
is a query param on consume; bytes GET follows; result `Done(File)`. Traces: AC-2.

**TC-AND-132-05 — Grant rejected → exactly one re-grant, then GrantExpired.**
Type: contract/MockWebServer (JVM+MWS). Target: `AttachmentDownloader` retry logic.
Preconditions: MWS scripts first bytes GET (or grant) → rejection (e.g. 403/410),
second grant → rejection. Steps: collect `downloadAttachment`. Expected: exactly
ONE transparent re-grant attempt; second failure surfaces
`FileError.GrantExpired`; no infinite retry; the consume `consumption_attempt_id`
is not reused across attempts. Traces: AC-5.

**TC-AND-132-06 — Error-code mapping.**
Type: contract/MockWebServer (JVM+MWS). Target: repo error mapping.
Preconditions: MWS returns, per sub-case, `400`, `401`, `403`, `404`, `422`
(FastAPI `detail` as string / `[{msg}]` / `{code}`), and `429`. Steps: invoke send
/ download for each. Expected: `403` → not-participant/owner error; `404` →
gone/not-found; `422` → validation (detail parsed in all three shapes); `429` →
transient retryable state (not terminal); `401` triggers the inherited
`/ui/session/refresh`-then-retry path. Traces: AC-8.

**TC-AND-132-07 — Client-side idempotency (no server key).**
Type: unit (JVM). Target: `FileMessageViewModel` send gating.
Preconditions: fake uploader with a controllable in-flight upload; fake repo
counting send calls. Steps: invoke `onFilePicked` then trigger send twice while the
upload is still in-flight. Expected: exactly ONE `sendFileMessage` call; no
`client_message_id` is fabricated into the body; optimistic bubble is keyed by the
local upload id. Traces: AC-6.

**TC-AND-132-08 — Cache reuse for policy "none"; no reuse for once-policy.**
Type: unit (JVM, Robolectric). Target: `AttachmentDownloader` + `AttachmentCacheEntry`.
Preconditions: a valid cached file exists for `m1` (policy "none") and `m2`
("view_once"). Steps: request open for each. Expected: `m1` opens from cache with
NO network call; `m2` does NOT reuse cache (re-runs grant/consume). Cache row whose
file is missing on disk is pruned and falls back to download. Traces: AC-7.

**TC-AND-132-09 — ViewModel state stream.**
Type: unit (JVM, Turbine). Target: `FileMessageViewModel.uiState`.
Preconditions: fake uploader + fake repo. Steps: drive picked→uploading→sent, then
tap→downloading→downloaded→opened. Expected: emissions in order; download fraction
strictly increasing to 1.0; terminal failure maps to the right `FileError`.
Traces: AC-1, AC-2.

**TC-AND-132-10 — FileMessageBubble Compose states + a11y.**
Type: Compose-UI (Emu35). Target: `FileMessageBubble`.
Preconditions: composable rendered with each `FileDownloadState`. Steps: assert
the four states (NotDownloaded/Downloading/Downloaded/Failed); click download
control; verify callback. Expected: each state renders its control; tap targets
>=48dp; `contentDescription` present ("Attach file", "Download <name>",
"Open <name>"); `progressSemantics(fraction)` exposed during download; RTL mirrors
the bubble. Traces: AC-2, AC-3 (a11y), AC-7.

**TC-AND-132-11 — Open via FileProvider/ACTION_VIEW + NoViewer fallback.**
Type: instrumented/e2e (Emu35, Espresso-Intents). Target: open flow.
Preconditions: a downloaded file in `cacheDir/attachments/m1/`. Steps: tap "open";
then repeat for a MIME with no installed handler. Expected:
`intended(hasAction(ACTION_VIEW))` with a `content://com.testlogon.android.fileprovider/`
URI and `FLAG_GRANT_READ_URI_PERMISSION`; no `file://` URI; the no-handler case
surfaces `FileError.NoViewer` with an `ACTION_SEND` "Share" fallback. Traces: AC-3.

**TC-AND-132-12 — End-to-end round trip (instrumented).**
Type: instrumented/e2e (Emu35, MWS). Target: full feature.
Preconditions: MWS scripts presign/PUT/confirm (AND-129 fakes) + send `file` +
grant + bytes GET. Steps: pick a file → upload with progress → `file` bubble
appears → tap download → bytes land in cache → "open" fires ACTION_VIEW. Expected:
optimistic bubble reconciles to server `message_id`; determinate progress; cache
file present; ACTION_VIEW intent captured. Traces: AC-1, AC-2, AC-3.

**TC-AND-132-13 — Flaky-host / offline / partial-download resilience.**
Type: instrumented (Emu35, MWS with throttling + mid-stream disconnect; airplane
toggle). Target: `AttachmentDownloader` + offline UI.
Preconditions: MWS drops the bytes connection mid-stream; then device toggled
offline. Steps: start download; force a connection reset; then go offline and back
online. Expected: bounded backoff retry (max 2) on transport reset; partial file
written to `.part` and deleted (no truncated file under `attachments/`); offline
state shown and download re-enabled on reconnect; cached files remain openable
offline. Traces: AC-2, AC-7.

**TC-AND-132-14 — SAF permission lifecycle & cleartext scoping (security).**
Type: instrumented (Dev-A15, MUST run on physical device). Target: picker
permission + network-security-config.
Rationale for device: exercises the real Storage Access Framework
document-picker grant/release and the on-device cleartext policy against the real
dev host; ABI/API differences (arm64/API 34 vs x86/API 35) in URI-permission
handling are best caught on hardware. Preconditions: dev host configured.
Steps: pick a `content://` document; perform upload; after confirm, verify the
persistable read permission is released; attempt a cleartext request to a non-dev
host. Expected: read permission held only for the upload then released; cleartext
allowed ONLY to the configured dev host (others blocked by
network-security-config); no pre-signed/grant URL or `grant_token` appears in
logs (OkHttp redactor verified). Traces: AC-1 (security), AC-8.

### Coverage matrix

| AC | Covered by |
| --- | --- |
| AC-1 (send → bubble) | TC-01, TC-09, TC-12, TC-14 |
| AC-2 (download grant→bytes) | TC-03, TC-04, TC-09, TC-10, TC-12, TC-13 |
| AC-3 (open / NoViewer) | TC-10, TC-11, TC-12 |
| AC-4 (file-share) | TC-02 |
| AC-5 (re-grant / GrantExpired) | TC-05 |
| AC-6 (idempotency) | TC-07 |
| AC-7 (cache reuse) | TC-08, TC-10, TC-13 |
| AC-8 (error mapping) | TC-06, TC-14 |
