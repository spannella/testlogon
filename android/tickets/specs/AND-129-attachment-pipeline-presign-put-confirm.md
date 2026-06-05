---
id: AND-129
title: Attachment pipeline (presign→PUT→confirm)
milestone: M3
epic: E19
priority: P0
size: L
status: draft
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

FR-4. On successful PUT, the uploader calls **confirm** and returns the
resulting `AttachmentRef` (durable `attachment_id`, `url`, `content_type`,
`size`, optional `width`/`height`).

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
        val presign = runApi(UploadPhase.PRESIGN) { api.presign(request.toPresignBody()) }
            .getOrEmit(this, UploadPhase.PRESIGN) ?: return@channelFlow

        val body = ProgressRequestBody(
            contentResolver, request.uri, request.mimeType, request.sizeBytes,
        ) { sent -> trySend(UploadProgress.Uploading(sent, request.sizeBytes)) }

        val putOk = runStorage(UploadPhase.PUT) {
            storageClient.put(presign.uploadUrl, presign.method, presign.headers, body)
        }.getOrEmit(this, UploadPhase.PUT) ?: return@channelFlow

        send(UploadProgress.Confirming)
        val ref = runApi(UploadPhase.CONFIRM) {
            api.confirm(ConfirmBody(uploadId = presign.uploadId, objectKey = presign.objectKey))
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
one **storage** call goes through the cookieless client. The exact presign route
for images is owned by AND-130 (`images/presign`); this ticket defines the
generic shape and a default `/ui/attachments/presign` path that downstream
tickets specialize via `category`.

### 5.1 Presign — `POST /ui/attachments/presign`

Request:
```json
{ "category": "message", "content_type": "image/jpeg",
  "size_bytes": 482133, "filename": "IMG_0421.jpg" }
```
Response `200`:
```json
{ "upload_id": "u_8c2…", "object_key": "att/2026/06/u_8c2.jpg",
  "method": "PUT", "upload_url": "https://store.example/att/…?X-Amz-Signature=…",
  "headers": { "Content-Type": "image/jpeg" }, "expires_in": 900 }
```

### 5.2 Storage PUT — `PUT {upload_url}`

Body = raw file bytes; headers = exactly `headers` from §5.1. **No cookies, no
`X-CSRF-Token`.** Success = `200`/`201`/`204`. The signed URL expires after
`expires_in` seconds (→ `403 SignatureDoesNotMatch`/expired → treat as presign
re-needed).

### 5.3 Confirm — `POST /ui/attachments/confirm`

Request:
```json
{ "upload_id": "u_8c2…", "object_key": "att/2026/06/u_8c2.jpg" }
```
Response `200`:
```json
{ "attachment_id": "att_19f…", "url": "https://cdn.example/att_19f.jpg",
  "content_type": "image/jpeg", "size_bytes": 482133,
  "width": 1290, "height": 1720 }
```

### 5.4 Retrofit interface & DTOs

```kotlin
interface AttachmentApi {
    @POST("ui/attachments/presign")
    suspend fun presign(@Body body: PresignBody): PresignResponse

    @POST("ui/attachments/confirm")
    suspend fun confirm(@Body body: ConfirmBody): ConfirmResponse
}

@JsonClass(generateAdapter = true)
data class PresignBody(
    @Json(name = "category") val category: String,
    @Json(name = "content_type") val contentType: String,
    @Json(name = "size_bytes") val sizeBytes: Long,
    @Json(name = "filename") val filename: String?,
)

@JsonClass(generateAdapter = true)
data class PresignResponse(
    @Json(name = "upload_id") val uploadId: String,
    @Json(name = "object_key") val objectKey: String,
    @Json(name = "method") val method: String,
    @Json(name = "upload_url") val uploadUrl: String,
    @Json(name = "headers") val headers: Map<String, String> = emptyMap(),
    @Json(name = "expires_in") val expiresIn: Int,
)

@JsonClass(generateAdapter = true)
data class ConfirmBody(
    @Json(name = "upload_id") val uploadId: String,
    @Json(name = "object_key") val objectKey: String,
)

@JsonClass(generateAdapter = true)
data class ConfirmResponse(
    @Json(name = "attachment_id") val attachmentId: String,
    @Json(name = "url") val url: String,
    @Json(name = "content_type") val contentType: String,
    @Json(name = "size_bytes") val sizeBytes: Long,
    @Json(name = "width") val width: Int? = null,
    @Json(name = "height") val height: Int? = null,
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
  emits `Failed(CONFIRM)` carrying `presign.uploadId`/`objectKey` so retry can
  resume at confirm (idempotent on the backend) rather than re-uploading bytes.
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
  that `Succeeded.attachment.id == "att_19f…"`. (Satisfies AND-129 acceptance.)
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

- **Presign route naming:** backend may expose category-specific routes
  (`images/presign`) rather than a generic `/ui/attachments/presign`. AND-130 is
  the canonical owner; confirm exact paths against `/openapi.json` before merge.
  The uploader keeps the route resolution behind `category` to absorb this.
- **Storage response semantics:** S3-compatible vs. POST-form-upload presign —
  if backend returns POST + form fields instead of PUT, `StorageUploadClient`
  needs a multipart branch (`method == "POST"` with `fields`). Design already
  carries `method`; add `fields` handling if confirmed.
- **Confirm idempotency:** resume-at-confirm assumes the backend confirm is
  idempotent on `upload_id`. Verify; if not, fall back to full re-upload on
  confirm failure.
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
- Verified against `/openapi.json` that presign/confirm field names match (or
  the deviation is recorded as a follow-up to the owning downstream ticket).
