---
id: AND-129
title: Attachment pipeline (presign→PUT→confirm)
milestone: M3
epic: E19
priority: P0
size: L
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-117]
blocks: [AND-130, AND-074]
---

# AND-129 — Attachment pipeline (presign→PUT→confirm)

## 1. Overview & Goal

Build a reusable, feature-agnostic file-upload pipeline that takes a local
content URI and drives it through the canonical three-step backend flow:
**presign** (ask the API for a storage URL + headers), **PUT** (stream the
bytes directly to object storage), and **confirm** (notify the API that the
object is committed and obtain a durable attachment id/descriptor). The
pipeline must surface live byte-level progress, support user cancellation, and
support retry of a failed attempt without re-selecting the file.

The deliverable is a `core-data` component — `AttachmentUploader` plus its
supporting DTOs, API interface, and a `Flow`-based progress model — that any
feature can call. The first consumers are AND-130 (image messages) and AND-074
(profile media upload); this ticket ships the engine and its MockWebServer test
suite, not any screen. The acceptance bar is a file uploading end-to-end with
observable progress, verified against MockWebServer.

## 2. Context & References

- **Stack:** Kotlin 2.0.21, Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 +
  Moshi 1.15, Hilt (KSP). Module: `core-data` (depends on `core-network`,
  `core-model`). minSdk 24 / targetSdk 35, JDK 17.
- **Package root:** `com.testlogon.android`. This pipeline lives under
  `com.testlogon.android.core.data.upload`.
- **Backend:** FastAPI + DynamoDB with object storage (S3-compatible presigned
  PUT). Dev host `http://18.222.237.167:8000` is **plaintext HTTP and
  unreliable**; design for ~20s timeouts and treat the storage PUT as a
  long-running, network-fragile operation. OpenAPI at `/openapi.json`; web
  reference `frontend/src/api/endpoints/*.ts`.
- **Auth/session:** All API calls (presign, confirm) ride the cookie jar
  (AND-011), echo the `ui_csrf` cookie as `X-CSRF-Token` (AND-012), and are
  subject to the single 401→refresh→retry authenticator (AND-013). The storage
  **PUT must NOT** carry app cookies or the CSRF header (it is a different
  origin; auth is in the presigned signature).
- **Dependencies:** AND-117 (stale/reconnect UX hooks) — the pipeline reports
  reconnect/offline-aware states consistent with that contract.
- **Shared types:** `ApiResult<T>` (AND-018), error `detail` mapping (AND-015),
  bounded backoff for idempotent GETs (AND-016) — note: PUT/POST here are NOT
  auto-retried; retry is user-driven (§7).
- **Downstream owners:** AND-130 owns `/messages/image` + `images/presign`
  specialization; AND-074 owns avatar/cover crop + confirm wiring. This ticket
  exposes the generic surface they call.

## 3. Functional Requirements

FR-1. Given a content URI (`android.net.Uri`), MIME type, and a logical
`category` (e.g. `"message"`, `"avatar"`, `"cover"`), the uploader resolves the
file size and an optional checksum, then requests a presigned upload.

FR-2. The uploader streams the file bytes via HTTP `PUT` to the presigned URL
using exactly the method, headers, and (optional) form fields returned by the
presign response. It does not buffer the whole file in memory.

FR-3. Progress is reported as monotonically increasing `bytesSent / totalBytes`
across the PUT phase, emitted no more often than ~10 Hz (throttled) to avoid
flooding collectors.

FR-4. On successful PUT, the uploader calls **confirm/complete** (when the
consumer supplies a `confirmPath`) and returns an `AttachmentRef`. Note: the
backend confirm/complete does **not** return an `attachment_id`/`url`/`width`/
`height`; `AttachmentRef` is an app-side projection built from the presign
`bucket`/`key`/`content_type` plus the confirm result (`{ok, path, size,
content_type}` for fs) — see §5.3. `width`/`height` come from the caller (read
locally before upload), not the API.

FR-5. **Cancel:** the caller can cancel at any phase; the in-flight HTTP call is
aborted (coroutine cancellation → OkHttp `Call.cancel()`), no confirm is sent,
and the terminal state is `Cancelled`.

FR-6. **Retry:** after a failed attempt the same `UploadRequest` can be
re-submitted without re-picking the file. Retry restarts from presign (presigned
URLs are short-lived and may be expired) unless the failure was at confirm and
the storage object is known-present, in which case it resumes at confirm.

FR-7. The uploader is **reusable and stateless per call**: each `upload()`
returns its own cold `Flow<UploadProgress>`; multiple concurrent uploads are
supported and independent.

FR-8. No UI is delivered. The component is exercised only by tests in this
ticket.

## 4. Technical Design

Module location: `core-data/src/main/kotlin/com/testlogon/android/core/data/upload/`.

### 4.1 Public surface

```kotlin
package com.testlogon.android.core.data.upload

data class UploadRequest(
    val uri: Uri,
    val mimeType: String,
    val category: String,          // "message" | "avatar" | "cover" | ...
    val displayName: String? = null,
    val sizeBytes: Long,           // resolved by caller or via UriMetadata
    // Consumer-supplied concrete routes (no generic /ui/attachments/* exists;
    // see §5). e.g. presignPath = "v1/fs/presign-upload",
    // confirmPath = "v1/fs/complete-upload". confirmPath may be null for the
    // image flow, which "confirms" via a send-message POST owned by AND-130.
    val presignPath: String,
    val confirmPath: String? = null,
    val remotePath: String? = null, // logical fs path for presign/complete bodies
)

sealed interface UploadProgress {
    data object Preparing : UploadProgress              // presign in flight
    data class Uploading(                                // PUT in flight
        val bytesSent: Long,
        val totalBytes: Long,
    ) : UploadProgress {
        val fraction: Float get() =
            if (totalBytes <= 0) 0f else (bytesSent.toFloat() / totalBytes).coerceIn(0f, 1f)
    }
    data object Confirming : UploadProgress              // confirm in flight
    data class Succeeded(val attachment: AttachmentRef) : UploadProgress
    data class Failed(val error: ApiError, val phase: UploadPhase) : UploadProgress
    data object Cancelled : UploadProgress
}

enum class UploadPhase { PRESIGN, PUT, CONFIRM }

interface AttachmentUploader {
    /** Cold flow; collection starts the upload. Cancelling collection cancels the upload. */
    fun upload(request: UploadRequest): Flow<UploadProgress>
}
```

### 4.2 Implementation

```kotlin
class DefaultAttachmentUploader @Inject constructor(
    private val api: AttachmentApi,
    private val storageClient: StorageUploadClient,   // wraps a cookieless OkHttpClient
    private val contentResolver: ContentResolver,
    private val errorMapper: ApiErrorMapper,           // AND-015
    @IoDispatcher private val io: CoroutineDispatcher,
) : AttachmentUploader {

    override fun upload(request: UploadRequest): Flow<UploadProgress> = channelFlow {
        send(UploadProgress.Preparing)
        val presign = runApi(UploadPhase.PRESIGN) {
            api.presign(request.presignPath, request.toPresignBody())
        }.getOrEmit(this, UploadPhase.PRESIGN) ?: return@channelFlow

        val body = ProgressRequestBody(
            contentResolver, request.uri, request.mimeType, request.sizeBytes,
        ) { sent -> trySend(UploadProgress.Uploading(sent, request.sizeBytes)) }

        // method is always "PUT" and the only header is Content-Type — presign
        // does not return these (see §5.1 correction).
        val putOk = runStorage(UploadPhase.PUT) {
            storageClient.put(
                url = presign.uploadUrl,
                method = "PUT",
                headers = mapOf("Content-Type" to presign.contentType),
                body = body,
            )
        }.getOrEmit(this, UploadPhase.PUT) ?: return@channelFlow

        send(UploadProgress.Confirming)
        val ref = runApi(UploadPhase.CONFIRM) {
            api.confirm(
                path = request.confirmPath,
                body = ConfirmBody(
                    path = presign.path ?: request.remotePath,
                    key = presign.key,
                    ticketId = presign.ticketId.orEmpty(),
                    contentType = presign.contentType,
                ),
            )
        }.getOrEmit(this, UploadPhase.CONFIRM) ?: return@channelFlow

        send(UploadProgress.Succeeded(ref.toAttachmentRef()))
    }.flowOn(io)
     .conflateProgress()        // custom operator: drop intermediate Uploading at >10Hz
}
```

`ProgressRequestBody` extends `okhttp3.RequestBody`, opens an `InputStream` from
`contentResolver.openInputStream(uri)`, copies in 8 KB chunks into the OkHttp
`BufferedSink`, and invokes the progress callback after each chunk. `contentLength()`
returns `sizeBytes` so OkHttp emits a `Content-Length` (no chunked transfer).

Cancellation: because `upload()` is a cold `channelFlow`, when the collector's
scope is cancelled the underlying coroutine is cancelled; `StorageUploadClient`
registers the OkHttp `Call` and cancels it on `CancellationException`, then the
flow emits `UploadProgress.Cancelled` from a `finally`/`onCompletion` guard
(only if no terminal value was sent).

### 4.3 Storage client (cookieless)

```kotlin
@Singleton
class StorageUploadClient @Inject constructor(
    @StorageOkHttp private val client: OkHttpClient,  // no CookieJar, no CSRF/auth interceptors
) {
    suspend fun put(url: String, method: String, headers: Map<String, String>, body: RequestBody): Unit
}
```

A dedicated `@StorageOkHttp` qualifier provides an `OkHttpClient` with no cookie
jar and no auth/CSRF interceptors, with `callTimeout` disabled (large files) but
`connectTimeout`/`writeTimeout` set to 20s/120s respectively.

### 4.4 Hilt wiring

```kotlin
@Module @InstallIn(SingletonComponent::class)
abstract class UploadModule {
    @Binds abstract fun bindUploader(impl: DefaultAttachmentUploader): AttachmentUploader

    companion object {
        @Provides @StorageOkHttp
        fun storageClient(): OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(20, SECONDS).writeTimeout(120, SECONDS)
            .callTimeout(0, SECONDS).build()

        @Provides fun attachmentApi(retrofit: Retrofit): AttachmentApi =
            retrofit.create(AttachmentApi::class.java)
    }
}
```

## 5. API Contract

Two **app-API** calls go through the authenticated Retrofit (`core-network`);
one **storage** call goes through the cookieless client.

> **CORRECTION (review 2026-06-06):** The backend exposes **no** generic
> `/ui/attachments/presign` or `/ui/attachments/confirm` route — those paths and
> their `upload_id`/`object_key`/`method`/`headers`/`expires_in` shapes were an
> unverified invention. Presign/confirm are **domain-specific** in the real API.
> The closest contracts (verified against OpenAPI + the web client) are:
> - **Image (AND-130's consumer):** `POST /messaging/conversations/{conversation_id}/images/presign`
>   (`SendImagePresignIn` → `PresignOut`). There is **no separate confirm
>   endpoint**; the web client "confirms" by posting the message with
>   `bucket`/`key`/`content_type`/`filename`/`filesize` (see
>   `src/api/endpoints/messaging.ts`).
> - **Generic filesystem (the truest "presign→PUT→confirm" triple):**
>   `POST /v1/fs/presign-upload` (`PresignUploadIn` → `PresignUploadOut`) then
>   `POST /v1/fs/complete-upload` (`CompleteUploadIn`).
> - **Video:** `POST /ui/videos/upload/presign` → `POST /ui/videos/upload/complete`.
>
> This ticket's `AttachmentApi` therefore models the **fs presign/complete**
> shape as the canonical generic contract and lets each consumer (AND-130,
> AND-074) inject its concrete path + presign/confirm bodies. The §5.1–§5.4
> samples below are corrected to real field names. Concrete route selection per
> `category` remains owned by the downstream tickets (§13).

### 5.1 Presign — generic `POST {presignPath}` (canonical: `POST /v1/fs/presign-upload`)

Request (`PresignUploadIn`; image variant uses `SendImagePresignIn` =
`{content_type, filename}` only — **no `size_bytes`, no `category`**):
```json
{ "path": "/att/2026/06/IMG_0421.jpg", "content_type": "image/jpeg" }
```
Response `200` (`PresignUploadOut`):
```json
{ "upload_url": "https://store.example/att/…?X-Amz-Signature=…",
  "bucket": "tl-uploads", "key": "att/2026/06/u_8c2.jpg",
  "ticket_id": "tkt_8c2…", "path": "/att/2026/06/IMG_0421.jpg",
  "content_type": "image/jpeg" }
```
The image `PresignOut` is the subset `{upload_url, bucket, key, content_type}`.
**Note:** presign responses do **not** return `method` or a `headers` map; the
HTTP method (`PUT`) and the lone `Content-Type` header are client conventions.
Only the **video** presign (`VideoUploadPresignOut`) returns expiry fields, and
they are named `expires_in_seconds`/`expires_at` (plus `max_size_bytes`) — there
is no `expires_in`.

### 5.2 Storage PUT — `PUT {upload_url}`

Body = raw file bytes; the only header set is `Content-Type` (the web client
hardcodes `method: "PUT"` and a single `Content-Type` header — see
`src/api/endpoints/messaging.ts: uploadToPresignedUrl` and
`src/api/endpoints/files.ts`). **No cookies, no `X-CSRF-Token`.** Success =
`200`/`201`/`204`. An expired/invalid signature returns `403` → treat as presign
re-needed.

### 5.3 Confirm/complete — generic `POST {confirmPath}` (canonical: `POST /v1/fs/complete-upload`)

Request (`CompleteUploadIn`; required `path`, `key`, `ticket_id`):
```json
{ "path": "/att/2026/06/IMG_0421.jpg", "key": "att/2026/06/u_8c2.jpg",
  "ticket_id": "tkt_8c2…", "content_type": "image/jpeg",
  "encrypted": false, "enc_meta": null }
```
Response `200`:
```json
{ "ok": true, "path": "/att/2026/06/IMG_0421.jpg",
  "size": 482133, "content_type": "image/jpeg" }
```
**Note:** there is no generic `attachment_id`/`url`/`width`/`height` confirm
response. The fs `complete-upload` returns `{ok, path, size, content_type}`. The
image flow has no confirm step at all — the "confirm" is the subsequent
send-image-message POST carrying `{bucket, key, content_type, filename,
filesize}`. `AttachmentRef` (§5.4) is therefore an **app-side domain
projection** the uploader synthesizes from presign `key`/`bucket` + confirm
result, not a 1:1 backend DTO.

### 5.4 Retrofit interface & DTOs

DTOs corrected to the real backend field names. Routes are passed in by the
consumer (`@Url`) so the same interface serves fs/image/video presign without a
hardcoded `/ui/attachments/*` path that does not exist.

```kotlin
interface AttachmentApi {
    // Consumer supplies the concrete presign route (e.g.
    // "messaging/conversations/{id}/images/presign" or "v1/fs/presign-upload").
    @POST
    suspend fun presign(@Url path: String, @Body body: PresignBody): PresignResponse

    @POST
    suspend fun confirm(@Url path: String, @Body body: ConfirmBody): ConfirmResponse
}

// Superset body; image presign (SendImagePresignIn) only reads content_type +
// filename, fs presign (PresignUploadIn) only reads path + content_type. Nulls
// are omitted by Moshi so each consumer sends only what its route requires.
@JsonClass(generateAdapter = true)
data class PresignBody(
    @Json(name = "path") val path: String? = null,        // fs presign
    @Json(name = "content_type") val contentType: String,
    @Json(name = "filename") val filename: String? = null, // image presign
)

// Superset of PresignOut / PresignUploadOut. bucket+key+content_type are always
// present; ticket_id+path only on fs/video. NO method, NO headers, NO expires_in.
@JsonClass(generateAdapter = true)
data class PresignResponse(
    @Json(name = "upload_url") val uploadUrl: String,
    @Json(name = "bucket") val bucket: String,
    @Json(name = "key") val key: String,
    @Json(name = "content_type") val contentType: String,
    @Json(name = "ticket_id") val ticketId: String? = null,
    @Json(name = "path") val path: String? = null,
)

// CompleteUploadIn. Required: path, key, ticket_id (image flow has no confirm
// body and instead posts a message — see §5.3 note).
@JsonClass(generateAdapter = true)
data class ConfirmBody(
    @Json(name = "path") val path: String,
    @Json(name = "key") val key: String,
    @Json(name = "ticket_id") val ticketId: String,
    @Json(name = "content_type") val contentType: String? = null,
    @Json(name = "encrypted") val encrypted: Boolean = false,
    @Json(name = "enc_meta") val encMeta: Map<String, Any?>? = null,
)

// fs complete-upload response: {ok, path, size, content_type}.
@JsonClass(generateAdapter = true)
data class ConfirmResponse(
    @Json(name = "ok") val ok: Boolean = true,
    @Json(name = "path") val path: String? = null,
    @Json(name = "size") val size: Long? = null,
    @Json(name = "content_type") val contentType: String? = null,
)
```

`AttachmentRef` is the `core-model` domain type returned to callers:
```kotlin
data class AttachmentRef(
    val id: String, val url: String, val contentType: String,
    val sizeBytes: Long, val width: Int?, val height: Int?,
)
```

FastAPI error bodies (`detail` = string | `[{msg}]` | `{code,...}`) are mapped
to `ApiError` via the shared `ApiErrorMapper` (AND-015) for presign/confirm.
Storage PUT failures are HTTP-status-only (no FastAPI body) and map to a
synthetic `ApiError(kind = Storage, httpStatus = …)`.

## 6. Data & State Management

- The pipeline is **stateless and cacheless**; it persists nothing to Room or
  DataStore. The returned `AttachmentRef` is owned by the calling feature
  (message send, profile save) which decides what to store. No DAO is added here.
- In-flight state is held only in the cold `Flow` per call. Callers (ViewModels)
  collect into their own `StateFlow<UiState>`.
- Progress model: `UploadProgress` is the single source of truth a collector
  observes. The terminal states (`Succeeded`/`Failed`/`Cancelled`) complete the
  flow; the flow never emits after a terminal value.
- Concurrency: each `upload()` call is independent; a caller managing a queue is
  responsible for limiting parallelism (out of scope here).
- A small `UriMetadata` helper (`resolveSize`, `resolveMime`, `resolveName` via
  `ContentResolver.query` on `OpenableColumns`) is provided so callers can build
  `UploadRequest` from a picked `Uri`.

## 7. Error Handling & Resilience

- **Timeouts:** presign/confirm use the app client's 20s timeouts; PUT uses
  20s connect / 120s write, no overall call timeout. A timeout → `Failed(phase)`
  with `ApiError.kind = Timeout`.
- **No automatic retry of writes.** Per AND-016 only idempotent GETs auto-retry;
  presign POST, storage PUT, and confirm POST are **not** auto-retried. Retry is
  user/caller-driven via re-submitting the `UploadRequest`.
- **Expired presign (403 on PUT):** classified as `Failed(PUT, kind=Expired)`;
  caller-driven retry restarts at presign.
- **Confirm-after-PUT failure:** if PUT succeeded but confirm fails, the flow
  emits `Failed(CONFIRM)` carrying `presign.key`/`ticketId` (and `path`) so retry
  can resume at confirm — **assuming** the backend `complete-upload` is
  idempotent on `ticket_id` (unverified; see §13 / §16 open assumptions) —
  rather than re-uploading bytes.
- **Offline / host down:** `IOException`/no connectivity → `Failed` with
  `kind = Network`; consistent with AND-117 reconnect hooks so the consuming
  screen can show a "reconnecting / retry" affordance.
- **Cancellation** is not an error: `CancellationException` is rethrown for
  structured concurrency but the flow emits `Cancelled` (distinct from `Failed`).
- **401 on presign/confirm:** handled transparently by the shared
  authenticator (AND-013) — one refresh + retry; if it still fails, `Failed`.

## 8. Security & Privacy

- The storage PUT goes to a **third-party origin**; app session cookies and the
  `ui_csrf` token must never be attached (enforced by the cookieless
  `@StorageOkHttp` client). A test asserts the PUT request carries no `Cookie`
  or `X-CSRF-Token` header.
- Presigned URLs are **secrets with TTL**; never logged in full (§10), never
  persisted. Redact the query string when logging.
- File access is via the granted content URI only; no broad storage permission
  is requested by this component. The caller is responsible for obtaining the URI
  (SAF / photo picker).
- The dev backend is plaintext HTTP; presign/confirm therefore travel
  unencrypted in dev. Storage URLs returned are expected to be HTTPS; if a
  presign returns an `http://` upload URL the uploader logs a warning but
  proceeds (dev-only), gated behind `BuildConfig.DEBUG`.
- No PII beyond filename is sent in presign; callers should avoid sensitive
  filenames.

## 9. Accessibility & i18n

No UI is shipped in this ticket, so there are no direct a11y surfaces. The
component supports downstream a11y/i18n by:
- Exposing structured `ApiError` (with stable `kind`) rather than raw strings,
  so consuming screens (AND-130, AND-074) can render localized, screen-reader-
  friendly progress/error text from `i18n` catalogs (AND-111/112).
- Emitting numeric `fraction` so consumers can set Compose `progress` semantics
  and `stateDescription` (e.g. "Uploading, 40 percent").
User-facing strings, RTL, and locale formatting are owned by the consuming
tickets.

## 10. Telemetry & Logging

- Emit a redacted structured log per phase transition: `upload_start`
  (category, sizeBytes, mime), `upload_presigned` (uploadId, expiresIn),
  `upload_put_done` (durationMs), `upload_confirmed` (attachmentId),
  `upload_failed` (phase, error.kind, httpStatus), `upload_cancelled`.
- **Never log** the full presigned URL, cookies, or CSRF token. URLs are logged
  host-only with query stripped. Follow the redaction policy from AND-052.
- Optional debug-only progress logging is throttled and gated by
  `BuildConfig.DEBUG`.
- No analytics SDK dependency is added here; logging uses the project logger.

## 11. Testing Strategy

All tests in `core-data` (and `core-testing` fixtures), JUnit + MockWebServer
(AND-046 harness) + Turbine for `Flow` assertions + OkHttp `MockWebServer` for
both the app API and a second `MockWebServer` instance acting as object storage.

- **Happy path (acceptance):** enqueue presign `200`, storage PUT `204`,
  confirm `200`; collect `upload()` and assert the emission sequence
  `Preparing → Uploading(…)* → Confirming → Succeeded(ref)`, that at least one
  `Uploading` with `fraction` strictly increasing toward `1.0` is observed, and
  that `Succeeded.attachment` is populated from the presign `key`/`bucket` +
  confirm result (e.g. `attachment.id == presign.key`). (Satisfies AND-129
  acceptance.)
- **Progress correctness:** upload a ~512 KB fixture; assert final
  `bytesSent == totalBytes` and emissions are monotonic and throttled (count
  bounded).
- **Request shape:** assert presign request body JSON, PUT method == response
  `method`, PUT carries exactly the presign `headers` and the correct
  `Content-Length`.
- **Security:** assert the storage PUT `RecordedRequest` has no `Cookie` and no
  `X-CSRF-Token`; assert presign/confirm DO carry the CSRF header.
- **Cancel:** start upload, cancel the collecting scope mid-PUT (use a slow
  `MockWebServer` dispatcher), assert terminal `Cancelled`, assert no confirm
  request was received by the server.
- **Retry — expired presign:** PUT returns `403`; assert `Failed(PUT, Expired)`;
  resubmit and assert a fresh presign is requested.
- **Retry — confirm resume:** PUT `204`, confirm `503`; assert `Failed(CONFIRM)`
  carrying ids; resubmit and assert no second PUT, only a confirm.
- **Error mapping:** presign `422` with FastAPI `detail` list → `Failed(PRESIGN)`
  with mapped message; confirm `500` → `Failed(CONFIRM, Server)`.
- **Timeout/offline:** dispatcher with no response / socket policy DISCONNECT →
  `Failed(kind=Timeout|Network)`.
- **UriMetadata:** robolectric/`ContentResolver` fake returns size/mime/name.

Target: deterministic, no real network; runs in the unit-test CI job (AND-050).

## 12. Dependencies & Sequencing

- **Hard dependency:** AND-117 (stale/reconnect UX hooks) — error `kind`s align
  with its reconnect affordances. Also relies on already-landed infra: AND-010
  (Retrofit/Moshi), AND-011 (cookie jar), AND-012 (CSRF interceptor), AND-013
  (401 authenticator), AND-015 (error mapping), AND-016/018 (`ApiResult`),
  AND-046 (MockWebServer harness).
- **Blocks / downstream consumers:** AND-130 (image messages — specializes
  `images/presign` + `/messages/image`, adds compression/thumbnail/viewer) and
  AND-074 (profile avatar/cover upload + crop). Both call this `AttachmentUploader`.
- **Sequencing:** land DTOs + `AttachmentApi` → `StorageUploadClient` +
  `ProgressRequestBody` → `DefaultAttachmentUploader` + Hilt module → test suite.

## 13. Risks & Open Questions

- **Presign route naming (RESOLVED in review):** confirmed against OpenAPI —
  the backend uses **category-specific** routes
  (`/messaging/conversations/{id}/images/presign`, `/v1/fs/presign-upload`,
  `/ui/videos/upload/presign`). There is **no** generic `/ui/attachments/presign`.
  The uploader now takes the concrete route via `UploadRequest.presignPath`
  (`@Url`); AND-130/AND-074 supply theirs.
- **Storage response semantics:** all observed presign responses return a plain
  `upload_url` consumed with `method: "PUT"` and a single `Content-Type` header
  (`messaging.ts`, `files.ts`). No POST-form/multipart presign was found; if one
  appears, `StorageUploadClient` would need a `POST`+`fields` branch. **The
  presign response carries neither `method` nor a `headers` map** — both are
  client conventions.
- **Confirm idempotency:** resume-at-confirm assumes `/v1/fs/complete-upload` is
  idempotent on `ticket_id`. **Not verifiable from OpenAPI/frontend** (no
  documented idempotency guarantee); if not idempotent, fall back to full
  re-upload on confirm failure.
- **Checksum:** whether the backend requires `Content-MD5`/`x-amz-content-sha256`
  in presign headers — currently we forward whatever presign returns; if a
  client-computed digest is required, add a streaming digest pass.
- **Large files / memory:** streaming via `InputStream` avoids OOM; verify
  `contentLength` is reliably resolvable from SAF URIs (fallback to reading
  `OpenableColumns.SIZE`).

## 14. Acceptance Criteria

AC-1. A file uploads end-to-end (presign → PUT → confirm) against MockWebServer,
emitting `Preparing → Uploading* → Confirming → Succeeded` and returning a valid
`AttachmentRef`. (Primary backlog acceptance.)
AC-2. Progress is observable: at least one `Uploading` emission, `fraction`
increases monotonically, final `bytesSent == totalBytes`.
AC-3. Cancellation mid-upload yields terminal `Cancelled`, aborts the HTTP call,
and sends no confirm.
AC-4. A failed attempt can be retried by re-submitting the same `UploadRequest`
without re-selecting the file (both expired-presign and confirm-resume paths
covered by tests).
AC-5. The storage PUT carries no app cookies and no `X-CSRF-Token`; presign and
confirm do carry CSRF.
AC-6. Presign/confirm errors map to `ApiError` via AND-015; storage failures map
to a `Storage` error kind; all surface as `Failed(phase, error)`.
AC-7. The component is in `core-data`, exposed as `AttachmentUploader`, Hilt-
bound, with no UI and no persistence added.
AC-8. Presigned URLs/cookies/CSRF are never logged in full.

## 15. Definition of Done

- `AttachmentUploader` + `DefaultAttachmentUploader`, `AttachmentApi`, DTOs,
  `StorageUploadClient`, `ProgressRequestBody`, `UriMetadata`, and `UploadModule`
  merged under `com.testlogon.android.core.data.upload` on `android-port`.
- All §11 tests pass in the unit CI job (AND-050); MockWebServer-based, no real
  network; ktlint/detekt (AND-005) clean.
- Code review confirms cookieless storage client, no auto-retry of writes,
  redacted logging, and streaming (non-buffering) upload.
- Public API documented with KDoc so AND-130 and AND-074 can consume without
  reading the implementation.
- No new permissions added to the manifest; no Room/DataStore changes.
- Verified against `/openapi.json` that presign/confirm field names match the
  real per-domain schemas (`PresignOut`/`PresignUploadOut`/`CompleteUploadIn`) —
  the original generic `/ui/attachments/*` shapes were corrected in this review
  (see §16). Any remaining per-route deviation is a follow-up to the owning
  downstream ticket.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. "OpenAPI"
refers to `reference/openapi.index.txt` / `reference/openapi.pretty.json`;
frontend paths are under `reference/src/`.

1. **A generic `POST /ui/attachments/presign` + `POST /ui/attachments/confirm`
   pair exists.** — **Corrected.** No such route in OpenAPI. Real presign/confirm
   are per-domain. Source: OpenAPI index has no `attachments/presign|confirm`;
   nearest are `POST /messaging/conversations/{conversation_id}/images/presign`,
   `POST /v1/fs/presign-upload`, `POST /v1/fs/complete-upload`,
   `POST /ui/videos/upload/presign`, `POST /ui/videos/upload/complete`.
2. **Image presign route/contract.** — **Verified.**
   `POST /messaging/conversations/{conversation_id}/images/presign`, req
   `SendImagePresignIn`, resp `PresignOut`. Source: OpenAPI
   `op=presign_image_upload_...`; schema `components.schemas.PresignOut` =
   `{upload_url, bucket, key, content_type}`; `SendImagePresignIn` =
   `{content_type(default image/jpeg), filename(default image.jpg)}`; frontend
   `src/api/endpoints/messaging.ts` (`/images/presign` POST + `uploadToPresignedUrl`).
3. **Generic fs presign/complete contract (canonical triple).** — **Verified.**
   `POST /v1/fs/presign-upload` (`PresignUploadIn`→`PresignUploadOut`) +
   `POST /v1/fs/complete-upload` (`CompleteUploadIn`). Source: OpenAPI
   `op=presign_fs_upload_...`, `op=complete_fs_upload_...`; schemas
   `PresignUploadOut` = `{upload_url, bucket, key, ticket_id, path, content_type}`,
   `CompleteUploadIn` required `{path, key, ticket_id}` (+`content_type,
   encrypted, enc_meta`); frontend `src/api/endpoints/files.ts: fsPresignUpload /
   fsCompleteUpload`.
4. **Presign response field names `upload_id`, `object_key`, `method`, `headers`,
   `expires_in`.** — **Corrected.** Real fields are `bucket`, `key`,
   `content_type`, `upload_url` (image) / `+ ticket_id, path` (fs). There is **no**
   `method` and **no** `headers` map in any presign response; the only expiry
   fields appear on `VideoUploadPresignOut` and are named `expires_in_seconds` /
   `expires_at` (+`max_size_bytes`). Source: schemas `PresignOut`,
   `PresignUploadOut`, `VideoUploadPresignOut`.
5. **Confirm response `{attachment_id, url, content_type, size_bytes, width,
   height}`.** — **Corrected.** fs `complete-upload` returns
   `{ok, path, size, content_type}` (frontend `files.ts: fsCompleteUpload`
   return type). The image flow has **no confirm endpoint** — it sends a message
   carrying `{bucket, key, content_type, filename, filesize}` (frontend
   `messaging.ts`). `AttachmentRef`/`width`/`height` are app-side projections,
   not API fields. Source: `src/api/endpoints/files.ts`,
   `src/api/endpoints/messaging.ts`.
6. **HTTP method for storage upload is PUT; body is raw bytes; only `Content-Type`
   header set.** — **Verified.** Frontend hardcodes `method: "PUT"` with a single
   `Content-Type` header (or `application/octet-stream` for encrypted blobs).
   Source: `src/api/endpoints/messaging.ts: uploadToPresignedUrl` (lines ~322-328,
   406-410, 947-950); `src/api/endpoints/files.ts`.
7. **Storage PUT carries no app cookies and no CSRF.** — **Verified.** The
   presigned upload uses bare `fetch(upload_url, {method:"PUT", body, headers})`
   with **no** `credentials: "include"` and no CSRF header, unlike the app client.
   Source: `src/api/endpoints/messaging.ts: uploadToPresignedUrl` vs
   `src/api/client.ts` (which adds `credentials:"include"` + `X-CSRF-Token`).
8. **App API sends CSRF as `X-CSRF-Token` echoed from the `ui_csrf` cookie.** —
   **Verified.** Source: `src/api/client.ts:168-170` (`getCookie("ui_csrf")` →
   `headers.set("X-CSRF-Token", csrf)`).
9. **App API rides a cookie jar (`credentials: include`).** — **Verified.**
   Source: `src/api/client.ts:183, 220` (`credentials: "include"`).
10. **Single 401 → refresh → retry authenticator.** — **Verified.** One refresh
    via `POST /ui/session/refresh`, then a single retry; a second 401 throws.
    Source: `src/api/client.ts:121-128` (`refreshSession`), `:194-224`.
11. **Expired/invalid presigned URL → 403 on PUT.** — **Unverified-assumption**
    (S3 convention). The frontend only checks `resp.ok` and throws a generic
    error on PUT failure; no specific 403/expiry classification exists in the
    sources. Treated as an S3-standard behavior, not a documented contract.
    Source: `src/api/endpoints/messaging.ts` (`if (!resp.ok) throw ...`).
12. **FastAPI `422` error body shape `{detail:[{loc,msg,type}]}`.** — **Verified.**
    Source: schemas `HTTPValidationError` (`detail: ValidationError[]`) and
    `ValidationError` (`{loc, msg, type}` all required). Most upload routes list
    `resp=...;422:HTTPValidationError` in OpenAPI index.
13. **`detail` may be string | list | object — mapped via AND-015.** —
    **Verified (frontend behavior).** Client normalizes `detail` generically.
    Source: `src/api/client.ts: normalizeErrorDetail` (used at `:200`).
14. **Confirm/complete is idempotent on `ticket_id` (enables resume-at-confirm).**
    — **Unverified-assumption.** No idempotency guarantee documented in OpenAPI or
    frontend. Source: `CompleteUploadIn` schema (no idempotency annotation).
15. **No client-computed checksum (`Content-MD5`/`x-amz-content-sha256`) is
    required.** — **Unverified-assumption.** No checksum field in any presign req
    schema; frontend sends none. Cannot confirm the storage backend does not
    enforce one server-side. Source: `SendImagePresignIn`, `PresignUploadIn`,
    `src/api/endpoints/messaging.ts`.
16. **Streaming/non-buffering upload, OkHttp `Call.cancel()` on cancellation,
    Hilt/Retrofit/Moshi stack, `core-data` module layout, dispatcher/timeout
    choices.** — **Unverified-assumption (Android design choices).** Not derivable
    from backend/frontend; these are framework decisions. framework ref: OkHttp
    `RequestBody`/`BufferedSink` streaming + `Call.cancel()`
    (https://square.github.io/okhttp/), Retrofit `@Url` dynamic URLs
    (https://square.github.io/retrofit/), Kotlin `channelFlow`/`flowOn`
    (https://kotlinlang.org/api/kotlinx.coroutines/).

### Corrections made

- §5.1/§5.4: presign request/response corrected — removed nonexistent
  `category`/`size_bytes` from presign body (image uses `{content_type,
  filename}`, fs uses `{path, content_type}`); removed `upload_id`/`object_key`/
  `method`/`headers`/`expires_in` from the response and replaced with the real
  `{upload_url, bucket, key, content_type(, ticket_id, path)}` (claims 1, 4).
- §5.1/§5.3: replaced the invented generic `/ui/attachments/presign|confirm`
  routes with the real per-domain routes and made `AttachmentApi` route-agnostic
  via `@Url` (claims 1, 2, 3).
- §5.3/§5.4: confirm corrected to `CompleteUploadIn`
  (`{path, key, ticket_id, ...}`) → `{ok, path, size, content_type}`; documented
  that the image flow has no confirm endpoint and that `AttachmentRef` is an
  app-side projection (claim 5).
- §4.1/§4.2: `UploadRequest` gained `presignPath`/`confirmPath`/`remotePath`; the
  PUT now hardcodes `method = "PUT"` + `Content-Type` (presign no longer carries
  them); confirm body uses `key`/`ticket_id`/`path` (claims 4, 6).
- §5.2/§13: storage PUT header set narrowed to `Content-Type` only; §13 risk
  about route naming marked RESOLVED.
- §3 FR-4, §11 happy-path: confirm-return expectations corrected to the
  projection model (claim 5).
- §7: confirm-resume now keyed on `key`/`ticket_id` and flagged as relying on the
  unverified idempotency assumption (claim 14).

### Open assumptions

- **403-on-expired-presign classification** (claim 11): frontend only checks
  `resp.ok`; S3 403/expiry semantics assumed, not documented. Validate against a
  real storage backend before relying on the auto-restart-at-presign path.
- **Confirm/complete idempotency on `ticket_id`** (claim 14): no guarantee in
  sources; resume-at-confirm may double-commit. Fallback = full re-upload.
- **No required client checksum** (claim 15): storage may enforce a digest
  server-side; not visible in OpenAPI/frontend.
- **Android framework choices** (claim 16): streaming, cancellation, timeouts,
  module layout are design decisions, not backend-derived.
- **`X-SESSION-ID` / `authorization` query/header params** appear on the image
  presign route in the OpenAPI index (`params=conversation_id,authorization,
  X-SESSION-ID`). Whether the Android client must send these explicitly or they
  are covered by the cookie/CSRF transport (AND-011/012) is unverified for the
  native client; assume the shared `core-network` transport supplies them.

## 17. Test Plan

All cases live in `core-data` unit/contract suites unless noted. MockWebServer
provides two servers: one for the app API (presign/confirm) and a second acting
as object storage (the PUT target). Turbine asserts `Flow` emissions. Error
bodies use the **real** FastAPI shape `{"detail":[{"loc":[...],"msg":"...",
"type":"..."}]}` (schema `HTTPValidationError`/`ValidationError`). Most cases run
on **JVM unit/Robolectric** (no device); device/emulator targets are called out
explicitly where real I/O or ABI behavior matters.

- **TC-AND-129-01 — Happy path end-to-end.** Type: contract/MockWebServer.
  Target: JVM unit/Robolectric. Preconditions: app server enqueues presign `200`
  (`PresignUploadOut`-shaped `{upload_url→storage server, bucket, key, ticket_id,
  path, content_type}`); storage server enqueues PUT `204`; app server enqueues
  complete `200` `{ok:true, path, size, content_type}`. Steps: build
  `UploadRequest` (presignPath=`v1/fs/presign-upload`,
  confirmPath=`v1/fs/complete-upload`, ~256 KB fixture); collect `upload()`.
  Expected: emission order `Preparing → Uploading(*) → Confirming → Succeeded`;
  `Succeeded.attachment` populated from presign `key`/`bucket` + confirm result.
  Traces: AC-1.
- **TC-AND-129-02 — Progress monotonic, throttled, reaches total.** Type: unit.
  Target: JVM unit/Robolectric. Preconditions: ~512 KB fixture, PUT `204`.
  Steps: collect all `Uploading` emissions. Expected: ≥1 `Uploading`;
  `bytesSent` non-decreasing; final `bytesSent == totalBytes` and
  `fraction == 1.0`; emission count bounded (throttle ≤ ~10 Hz). Traces: AC-2.
- **TC-AND-129-03 — Request shape: presign body, PUT method/headers/length.**
  Type: contract/MockWebServer. Target: JVM unit/Robolectric. Preconditions:
  full happy-path queue. Steps: inspect recorded presign request and PUT
  request. Expected: presign JSON contains only the route's real fields (fs:
  `{path, content_type}`; image: `{content_type, filename}`) and **no**
  `category`/`size_bytes`; PUT method == `PUT`; PUT headers contain exactly
  `Content-Type` (== presign `content_type`) and a correct `Content-Length`
  matching `sizeBytes` (no chunked transfer); PUT has **no** `method`/`headers`
  echoed from a (nonexistent) presign field. Traces: AC-1, AC-6.
- **TC-AND-129-04 — Storage PUT is cookieless and CSRF-less; app calls carry
  CSRF.** Type: contract/MockWebServer + security. Target: JVM unit/Robolectric.
  Preconditions: cookie jar populated, `ui_csrf` set; full happy-path queue.
  Steps: capture `RecordedRequest` for presign, PUT, complete. Expected: PUT has
  no `Cookie` and no `X-CSRF-Token`; presign and complete both carry `Cookie`
  and `X-CSRF-Token`. Traces: AC-5, AC-8.
- **TC-AND-129-05 — Cancel mid-PUT yields Cancelled, no confirm.** Type:
  contract/MockWebServer. Target: JVM unit/Robolectric. Preconditions: storage
  server uses a slow/throttled dispatcher so PUT is in-flight. Steps: start
  collecting, cancel the collecting scope during `Uploading`. Expected: terminal
  `Cancelled` (not `Failed`); underlying OkHttp `Call` cancelled; storage server
  shows an aborted PUT; app server received **no** complete request;
  `CancellationException` propagates for structured concurrency. Traces: AC-3.
- **TC-AND-129-06 — Retry after expired presign (403 on PUT) restarts at
  presign.** Type: contract/MockWebServer. Target: JVM unit/Robolectric.
  Preconditions: presign `200`, storage PUT `403`. Steps: collect → assert
  `Failed(PUT, kind=Expired/Storage, httpStatus=403)`; re-submit the same
  `UploadRequest`. Expected: a **fresh** presign request is sent on retry (count
  increments), then PUT/complete proceed. Traces: AC-4, AC-6.
- **TC-AND-129-07 — Retry resumes at confirm when PUT succeeded.** Type:
  contract/MockWebServer. Target: JVM unit/Robolectric. Preconditions: presign
  `200`, PUT `204`, complete `503`. Steps: collect → assert `Failed(CONFIRM)`
  carrying `key`/`ticketId`/`path`; re-submit. Expected: on retry **no second
  PUT** and **no second presign** are issued — only a complete request with the
  retained `ticket_id`/`key`. (Validity depends on backend idempotency — open
  assumption §16.14; test asserts client behavior only.) Traces: AC-4.
- **TC-AND-129-08 — Error mapping: presign 422 (real `detail` list).** Type:
  contract/MockWebServer. Target: JVM unit/Robolectric. Preconditions: presign
  returns `422` body `{"detail":[{"loc":["body","content_type"],"msg":"field
  required","type":"value_error.missing"}]}`. Steps: collect. Expected:
  `Failed(PRESIGN)` with `ApiError` carrying the mapped `msg`; no PUT issued.
  Traces: AC-6.
- **TC-AND-129-09 — Error mapping: confirm 500 → Server kind; storage 5xx →
  Storage kind.** Type: contract/MockWebServer. Target: JVM unit/Robolectric.
  Preconditions: (a) presign 200, PUT 204, complete `500`; (b) presign 200, PUT
  `500`. Steps: collect each. Expected: (a) `Failed(CONFIRM, kind=Server,
  httpStatus=500)`; (b) `Failed(PUT, kind=Storage, httpStatus=500)` with a
  synthetic `ApiError` (no FastAPI body parsed). Traces: AC-6.
- **TC-AND-129-10 — Timeout / offline classification.** Type:
  contract/MockWebServer. Target: JVM unit/Robolectric. Preconditions: (a) PUT
  dispatcher never responds within the write timeout; (b) `SocketPolicy.
  DISCONNECT_AT_START` on the storage server. Steps: collect. Expected: (a)
  `Failed(kind=Timeout)`; (b) `Failed(kind=Network)` — error `kind`s align with
  AND-117 reconnect affordances. Traces: AC-6.
- **TC-AND-129-11 — 401 on presign refreshes once then retries.** Type:
  contract/MockWebServer. Target: JVM unit/Robolectric. Preconditions: presign
  `401`, then `POST /ui/session/refresh` `200`, then presign `200`. Steps:
  collect. Expected: exactly one refresh, one presign retry, upload proceeds; a
  persistent `401` (refresh fails) → `Failed(PRESIGN)`. Traces: AC-1, AC-6.
- **TC-AND-129-12 — `UriMetadata` resolves size/mime/name.** Type:
  unit/Robolectric. Target: JVM unit/Robolectric (fake `ContentResolver` over
  `OpenableColumns`). Steps: query a content URI. Expected: returns size, mime,
  display name; falls back gracefully when `SIZE` is null. Traces: AC-2, AC-7.
- **TC-AND-129-13 — Redacted logging: no full presigned URL / cookie / CSRF.**
  Type: unit. Target: JVM unit/Robolectric (capture project logger). Steps: run
  happy path with a fake log sink. Expected: emitted logs contain host-only URLs
  with query stripped; no `X-Amz-Signature`, no `Cookie`, no `ui_csrf`/
  `X-CSRF-Token` value. Traces: AC-8.
- **TC-AND-129-14 — Real-device large-file streaming PUT (no OOM, real SAF
  URI).** Type: instrumented/e2e. **Target: PHYSICAL DEVICE — Samsung Galaxy A15
  5G (SM-A156U, serial R5CX821TA9R), Android 14 / API 34, arm64-v8a.** Rationale:
  exercises real `ContentResolver`/SAF `openInputStream`, real `Content-Length`
  resolution from a photo-picker URI, and streaming a large (~50 MB) file under
  real memory pressure on arm64 (vs x86 emulator) — must run on hardware, not the
  emulator. Preconditions: a large media file present; a local MockWebServer (or
  the dev host) reachable from the device over adb-forwarded port. Steps: pick a
  large file, run `upload()`. Expected: completes with `Succeeded`, heap stays
  bounded (no full-file buffering), progress monotonic to total. Traces: AC-1,
  AC-2. (Emulator `test35` may run a smaller-fixture smoke variant for CI.)

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
| --- | --- |
| AC-1 (end-to-end presign→PUT→confirm) | TC-01, TC-03, TC-11, TC-14 |
| AC-2 (observable progress, reaches total) | TC-02, TC-12, TC-14 |
| AC-3 (cancel → Cancelled, no confirm) | TC-05 |
| AC-4 (retry: expired-presign + confirm-resume) | TC-06, TC-07 |
| AC-5 (PUT cookieless/CSRF-less; app calls CSRF) | TC-04 |
| AC-6 (error mapping presign/confirm/storage) | TC-03, TC-06, TC-08, TC-09, TC-10, TC-11 |
| AC-7 (core-data, AttachmentUploader, no UI/persistence) | TC-12 (+ all run against the `core-data` component) |
| AC-8 (URLs/cookies/CSRF never logged in full) | TC-04, TC-13 |
