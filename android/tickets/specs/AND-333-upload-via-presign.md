---
id: AND-333
title: Upload via presign
milestone: M7
epic: E43
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-331, AND-129]
blocks: []
---

# AND-333 — Upload via presign

## 1. Overview & Goal

This ticket delivers the user-facing **file upload** capability inside the Files feature
of the TestLogon native Android app. A user browsing a folder can pick one or more local
files (from the system document picker or share sheet), see per-item upload progress, and
have the resulting objects placed into the folder they are currently viewing (or an
explicitly chosen target folder). Each upload follows the three-leg
**presign → PUT → confirm** protocol so that bytes flow directly to object storage (S3 via
DynamoDB-backed FastAPI metadata) and never transit the FastAPI app server.

> **Review note (AND-333):** Placement in this backend is **path-based**, not `folderId`-based.
> The verified contract (web client `frontend/src/api/endpoints/files.ts`, OpenAPI
> `POST /v1/fs/presign-upload`) keys everything off a full object **`path`** (e.g.
> `/<currentFolder>/<filename>`). There is no `folder_id` field on presign or confirm, and no
> `FileNode`/`FolderNode` DTO — the listing item type is **`FileEntry`** (path/name/type/size).
> All references below to `folderId`, `FileNode`, `/ui/files/*`, `upload_id`, and `etag` are
> corrected in §5 and audited in §16; the Kotlin model names in §4 are this ticket's internal
> Android naming and may be kept, but they must map onto the path-based wire contract.

The reusable transport mechanics — requesting a presigned URL, streaming the PUT to storage
with progress, and confirming — are owned by **AND-129** (`AttachmentUploader`). The Files
API surface and DTOs (browse/CRUD/search, presign request shapes) are owned by **AND-331**
(`files.ts` parity). AND-333 is the **integration and UX layer**: it wires the uploader and
the Files API into the `feature-files` module, adds the folder-placement logic, the upload
queue UI, and the progress/cancel/retry surface, and proves the end-to-end path with an
instrumented/MockWebServer test. The goal is: *a selected file uploads to completion into the
current folder with visible progress, and appears in the folder listing on confirm.*

## 2. Context & References

- **Repo:** `spannella/testlogon`, Android app in `android/`, branch `android-port`.
- **Namespace / applicationId base:** `com.testlogon.android`. Feature lives in
  `feature-files` (`com.testlogon.android.feature.files`); upload UI in
  `com.testlogon.android.feature.files.upload`.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow,
  Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, DataStore, Paging 3, WorkManager (for resumable
  background uploads). minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Module layering:** `app -> feature-files -> core-{network,model,data,ui,testing}`.
- **Dependencies:**
  - **AND-331 — Files API + DTOs** (P0): provides `FilesApi` Retrofit interface, the
    **`FileEntry`** model (the verified web type; the draft's `FileNode`/`FolderNode` names do
    not exist in the backend — see §16), and the presign/confirm DTOs this ticket consumes.
  - **AND-129 — Attachment pipeline** (P0): provides the reusable `AttachmentUploader` that
    performs presign→PUT→confirm with progress, cancel, and retry. AND-333 calls it; it does
    not reimplement the transport.
- **Backend:** FastAPI + DynamoDB; dev host `http://18.222.237.167:8000` (plaintext HTTP,
  unreliable). OpenAPI at `/openapi.json`. Web reference: `frontend/src/api/endpoints/files.ts`.
- **Auth (verified against `src/api/client.ts`):** the web client sends, on every app-server
  call, **(a)** `Authorization: Bearer <accessToken>` from the auth store, **(b)** the
  `X-CSRF-Token` header echoed from the `ui_csrf` cookie, and **(c)** `credentials: include`
  (the session cookie jar). The original spec said "cookie-based session with `X-CSRF-Token`"
  and omitted the Bearer token — **corrected**: the Android client must also send the Bearer
  access token (parity with `client.ts`). The PUT to storage is a **bare** request (no app
  cookies, no CSRF header, no Bearer) — verified: `FilesPage.tsx` issues the PUT with
  `fetch(upload_url, { method: "PUT", headers: { "Content-Type": presign.content_type } })`
  and **no** `credentials: "include"`.

## 3. Functional Requirements

FR-1. From a folder listing, the user can invoke **Upload** (FAB / overflow action) which
opens the Android system picker (`ActivityResultContracts.OpenMultipleDocuments`) and the app
also accepts files routed in via the system **share sheet** (`Intent.ACTION_SEND` /
`ACTION_SEND_MULTIPLE`).

FR-2. The selected file(s) are enqueued as upload jobs targeting the **current folder** by
default. The user may change the target folder via a folder picker before or after selection;
the chosen `folderId` is attached to every job.

FR-3. Each job shows **live progress** (0–100%) derived from bytes transferred during the
PUT leg, plus a textual state (Queued, Preparing, Uploading, Confirming, Done, Failed,
Cancelled).

FR-4. The user can **cancel** an in-flight or queued job and **retry** a failed job. Cancel
is immediate; retry restarts from the presign leg (uploads are not assumed resumable on the
unreliable dev host).

FR-5. Uploads run **concurrently up to a bounded limit** (default 2) with the remainder
queued; queue is FIFO.

FR-6. On confirm success, the new `FileEntry` is **inserted into the folder listing** for the
target folder without requiring a manual refresh (cache invalidation / optimistic insert).

FR-7. Filenames, MIME type, and byte size are read from the content URI via
`ContentResolver`; the original filename is preserved as the object's display name.

FR-8. Duplicate-name handling defers to backend behavior (server returns the canonical name
on confirm); the client renders whatever name the confirm response returns.

## 4. Technical Design

### Module placement

```
feature-files/
  upload/
    UploadJob.kt              // domain model for one upload
    UploadQueue.kt            // bounded-concurrency coordinator (calls AttachmentUploader)
    FilesUploadViewModel.kt   // StateFlow<UploadUiState>; picker + folder placement
    UploadSheet.kt            // Compose bottom sheet: job list, progress, cancel/retry
    FolderPickerDialog.kt     // choose target folder
```

### Domain model

```kotlin
data class UploadJob(
    val id: String,                 // UUID, stable across retry
    val sourceUri: Uri,
    val displayName: String,
    val mimeType: String,
    val sizeBytes: Long,
    val targetFolderId: String,
    val state: UploadState,
    val progress: Float = 0f,       // 0f..1f, valid during UPLOADING
    val error: UiError? = null,
    val resultFileId: String? = null,
)

enum class UploadState { QUEUED, PREPARING, UPLOADING, CONFIRMING, DONE, FAILED, CANCELLED }
```

### Reusing AND-129's uploader

AND-333 depends on the `AttachmentUploader` contract from AND-129. The expected surface
consumed here:

```kotlin
interface AttachmentUploader {
    /** Emits transfer progress and terminal state for one file. */
    fun upload(request: UploadRequest): Flow<UploadEvent>
}

data class UploadRequest(
    val sourceUri: Uri,
    val displayName: String,
    val mimeType: String,
    val sizeBytes: Long,
    val folderId: String,           // placement target — passed into the presign body
)

sealed interface UploadEvent {
    data object Preparing : UploadEvent
    data class Progress(val fraction: Float) : UploadEvent
    data object Confirming : UploadEvent
    data class Completed(val file: FileEntry) : UploadEvent  // built from confirm {ok,path,size,content_type}
    data class Failed(val error: UiError, val retryable: Boolean) : UploadEvent
}
```

If AND-129 lands without a `folderId` field on `UploadRequest`, this ticket adds it (it is the
sole consumer that needs folder placement) and the presign DTO from AND-331 carries it through.

### Queue coordinator

`UploadQueue` runs in a `viewModelScope`-derived `CoroutineScope` and bounds concurrency with a
`Semaphore(permits = MAX_CONCURRENT)`. Each job is launched as a child coroutine collecting the
`AttachmentUploader.upload(...)` flow; cancellation cancels that coroutine, which propagates an
OkHttp call cancel through the uploader.

```kotlin
class UploadQueue @Inject constructor(
    private val uploader: AttachmentUploader,
    private val dispatchers: AppDispatchers,
) {
    private val sem = Semaphore(MAX_CONCURRENT)
    fun enqueue(scope: CoroutineScope, job: UploadJob, onEvent: (UploadJob) -> Unit): Job
    fun cancel(jobId: String)
    companion object { const val MAX_CONCURRENT = 2 }
}
```

### ViewModel

```kotlin
@HiltViewModel
class FilesUploadViewModel @Inject constructor(
    private val queue: UploadQueue,
    private val contentResolver: ContentResolver,
    private val filesRepository: FilesRepository,   // from AND-331 for cache insert
    private val telemetry: Telemetry,
) : ViewModel() {
    val uiState: StateFlow<UploadUiState>
    fun onFilesPicked(uris: List<Uri>, targetFolderId: String)
    fun setTargetFolder(folderId: String)
    fun cancel(jobId: String)
    fun retry(jobId: String)
    fun dismissCompleted()
}

data class UploadUiState(
    val jobs: List<UploadJob> = emptyList(),
    val targetFolder: FolderRef? = null,
    val anyInFlight: Boolean = false,
)
```

`onFilesPicked` resolves metadata via `ContentResolver.query(uri, [DISPLAY_NAME, SIZE])` and
`contentResolver.getType(uri)`, builds `UploadJob`s, and enqueues each. On `Completed`, it calls
`filesRepository.insertUploaded(folderId, file)` to update the Paging/Room-backed listing.

### Compose UI

`UploadSheet` is a Material 3 `ModalBottomSheet` showing a `LazyColumn` of job rows; each row
renders a `LinearProgressIndicator` for `UPLOADING` (determinate from `progress`), an
indeterminate indicator for `PREPARING`/`CONFIRMING`, and trailing cancel/retry icon buttons.
The Files screen exposes a `FloatingActionButton` that launches the picker via
`rememberLauncherForActivityResult(OpenMultipleDocuments())`.

## 5. API Contract

This ticket **consumes** the presign/confirm endpoints; the DTOs are formally owned by
**AND-331** (presign shapes) and **AND-129** (transport).

> **CORRECTED (AND-333):** The endpoint paths, request/response field names, and response
> shapes in the original draft were wrong. They have been replaced below with the **verified**
> contract from OpenAPI (`POST /v1/fs/presign-upload` → `PresignUploadIn`/`PresignUploadOut`;
> `POST /v1/fs/complete-upload` → `CompleteUploadIn`) and the web client
> (`frontend/src/api/endpoints/files.ts: fsPresignUpload`, `completeUpload`;
> `frontend/src/pages/files/FilesPage.tsx` for the PUT leg). Key fixes:
> the routes are `/v1/fs/...` not `/ui/files/...`; placement is by **`path`** not `folder_id`;
> presign does **not** take `filename`/`size_bytes`; the presign response uses **`upload_url`**
> (not `url`) and **`ticket_id`** (no `upload_id`, no `method`, no `headers`); confirm uses
> **`key` + `ticket_id`** and carries **no `etag`**; and the confirm response is
> `{ ok, path, size, content_type }` — **not** a `FileNode`.

**Leg 1 — Presign (app server; Bearer + cookies + CSRF):**
`POST /v1/fs/presign-upload`  (OpenAPI: `req=PresignUploadIn`, `resp=200:PresignUploadOut`)

```json
// request  (PresignUploadIn) — path is the FULL object path = <targetFolder>/<filename>
{ "path": "/reports/report.pdf", "content_type": "application/pdf" }
// response (PresignUploadOut)
{ "upload_url": "https://s3.amazonaws.com/bucket/key?...",
  "bucket": "tl-user-files",
  "key": "users/u1/reports/report.pdf",
  "ticket_id": "tkt_abc",
  "path": "/reports/report.pdf",
  "content_type": "application/pdf" }
```
`content_type` is optional on the request (`anyOf string|null`); `size_bytes` and `filename`
are **not** request fields — the filename is encoded in `path`, and size is determined by the
PUT body. The server returns the canonical `content_type` to use on the PUT.

**Leg 2 — PUT to storage (bare request; NO Bearer, NO app cookies, NO X-CSRF-Token):**
`PUT {upload_url}` with body = file bytes and header `Content-Type: {presign.content_type}`
(send the value the presign returned verbatim — the S3 signature may bind it; see R5).
Verified web client: `fetch(presign.upload_url, { method: "PUT", headers: { "Content-Type":
presign.content_type }, body })` with **no** `credentials: "include"`. Success = HTTP 200/204.
**No `ETag` is read or forwarded** — confirm is keyed by `ticket_id`+`key`, not an etag.

**Leg 3 — Confirm (app server; Bearer + cookies + CSRF):**
`POST /v1/fs/complete-upload`  (OpenAPI: `req=CompleteUploadIn`, `resp=200:` untyped JSON)

```json
// request  (CompleteUploadIn) — path, key, ticket_id are REQUIRED
{ "path": "/reports/report.pdf",
  "key": "users/u1/reports/report.pdf",
  "ticket_id": "tkt_abc",
  "content_type": "application/pdf",
  "encrypted": false,
  "enc_meta": null }
// response (web client type for completeUpload; OpenAPI marks 200 untyped)
{ "ok": true, "path": "/reports/report.pdf", "size": 482133,
  "content_type": "application/pdf" }
```
The confirm response is **not** a `FileNode` and has **no `id`/`folder_id`/`created_at`**. To
render/insert the uploaded item into the listing, build a `FileEntry` from the known `path`
(its `name` is the path basename) plus the returned `size`/`content_type`, or re-list the
folder via `GET /v1/fs/list?path=<folder>` (see §6).

Retrofit signatures (in `FilesApi`, from AND-331; corrected to the verified contract):

```kotlin
@POST("v1/fs/presign-upload")
suspend fun presignUpload(@Body body: PresignUploadRequest): ApiResult<PresignUploadResponse>
// PresignUploadRequest(path: String, content_type: String?)
// PresignUploadResponse(upload_url, bucket, key, ticket_id, path, content_type)

@POST("v1/fs/complete-upload")
suspend fun completeUpload(@Body body: CompleteUploadRequest): ApiResult<CompleteUploadResponse>
// CompleteUploadRequest(path, key, ticket_id, content_type?, encrypted=false, enc_meta?)
// CompleteUploadResponse(ok: Boolean, path: String, size: Long?, content_type: String)
```

> **Simpler alternative (informational):** for files below a size threshold the web client
> bypasses presign entirely and uses the single-shot multipart route `POST /v1/fs/upload`
> (`uploadFile()` in `files.ts`, params `path,encrypted,overwrite,enc_meta`). AND-333 implements
> the **presign path** as scoped, but reviewers should be aware the presign flow is only
> exercised by the web client above `PRESIGN_THRESHOLD`.

## 6. Data & State Management

- **Source of truth:** `FilesUploadViewModel.uiState: StateFlow<UploadUiState>`; the sheet
  collects it with `collectAsStateWithLifecycle()`.
- **Job identity:** each `UploadJob.id` is a UUID minted at enqueue and preserved across retry
  so the row keeps its position and progress bar.
- **Progress source:** `UploadEvent.Progress.fraction`, computed by the uploader as
  bytesWritten / sizeBytes during the PUT leg via an OkHttp `RequestBody.writeTo` counter.
- **Folder placement:** the active `targetFolderId` is held in state and copied into each job;
  default is the folder the user is browsing (passed by the Files screen route arg).
- **Listing integration:** on `Completed`, `FilesRepository.insertUploaded(folderPath, entry)`
  (AND-331) writes the new **`FileEntry`** into the Room cache for that folder path so the
  Paging 3 flow re-emits; if the cache for that folder is not present, it invalidates the page
  source so the next browse fetches fresh via `GET /v1/fs/list?path=<folder>`. **Note (review):**
  the confirm response is `{ ok, path, size, content_type }` (not a `FileNode`), so the
  inserted `FileEntry` is constructed from `path` (name = basename), `size`, and `content_type`;
  if any field is needed that confirm omits, fall back to re-listing the folder.
- **Persistence scope:** the upload queue is **process-scoped** in v1 (not persisted across
  process death). Background/foreground-service resumable uploads via WorkManager are noted as
  a follow-up (see §13); v1 keeps the upload alive while the user remains in the app.
- **No DataStore writes** are required by this ticket.

## 7. Error Handling & Resilience

- **Per-leg failures map to `UiError`** via the shared FastAPI `detail` mapper
  (string | `[{msg}]` | `{code,...}`). Presign/confirm errors surface a retryable failed state.
- **PUT leg:** the storage PUT is **not** an idempotent app-server GET, so it is **not**
  auto-retried by the global OkHttp backoff interceptor; failures bubble up as
  `UploadEvent.Failed(retryable = true)` and the user retries manually (restarts from presign,
  since the presigned URL may have expired). The PUT response body/headers are ignored — there
  is **no `ETag` to capture** (confirm is keyed by `ticket_id`+`key`, verified against
  `CompleteUploadIn` and the web client).
- **Timeouts:** large PUTs use an extended write timeout (e.g. 60s write / per-call) distinct
  from the default ~20s app-call timeout; the presign and confirm calls keep the standard ~20s
  timeout with bounded backoff *only if* they are retried as idempotent (presign POST is not
  retried automatically).
- **401 on presign/confirm:** handled by the global auth interceptor — one
  `POST /ui/session/refresh` then retry (path **verified** against `src/api/client.ts:
  refreshSession`); if refresh fails the job moves to FAILED and the user is routed to re-auth.
- **Validation errors (422):** FastAPI returns `HTTPValidationError` =
  `{ "detail": [ { "loc": [...], "msg": "...", "type": "..." } ] }` (verified:
  OpenAPI `components.schemas.HTTPValidationError` / `ValidationError`). The shared `detail`
  mapper (string | `[{msg}]` | `{code,...}`) handles this; surfaced as a non-retryable mapped
  error (parity with `src/api/client.ts: normalizeErrorDetail`).
- **Presigned-URL expiry (403/expired):** treated as retryable; retry re-presigns.
- **Cancel:** cancels the coroutine → OkHttp call cancel; job → CANCELLED, no confirm sent.
- **Offline:** if no connectivity, jobs sit in QUEUED with an offline banner; they start when
  connectivity returns (observed via the connectivity flow from core-data).
- **Partial batch:** independent jobs; one failure does not fail siblings.

## 8. Security & Privacy

- **Content URI access:** read selected files via `ContentResolver` using the temporary URI
  permission granted by the picker; do not persist URI grants beyond the session and do not
  copy file bytes to app-private storage unless required for retry buffering.
- **CSRF/cookies/Bearer:** presign and confirm carry the session cookie jar + `X-CSRF-Token`
  (from `ui_csrf`) **and** the `Authorization: Bearer` access token (verified parity with
  `src/api/client.ts`). The storage PUT must **strip** app cookies, the CSRF header, and the
  Bearer token — enforce via a dedicated bare OkHttp client / `@Tag`-based interceptor skip so
  credentials are never leaked to the S3 host.
- **No secrets in logs:** never log presigned URLs (they embed signed credentials), cookies, or
  CSRF tokens; redact query strings of storage URLs in telemetry (§10).
- **Transport:** dev backend is plaintext HTTP (cleartext allowed only for the dev host via a
  scoped network-security-config); the S3 presigned URL is HTTPS.
- **MIME/size validation:** client passes the resolver-reported `content_type` and
  `size_bytes`; the server is authoritative for accept/reject.

## 9. Accessibility & i18n

- Every progress row exposes `contentDescription` / `stateDescription` reflecting state and
  percent (e.g. "Uploading report.pdf, 42 percent"); progress announced via
  `Modifier.semantics { stateDescription = ... }` so TalkBack reads updates without spam
  (throttle announcements to ~10% steps).
- Cancel/retry icon buttons have descriptive labels and ≥48dp touch targets.
- All strings (`Upload`, `Queued`, `Uploading`, `Confirming`, `Failed`, `Cancelled`,
  `Choose folder`, error messages) live in `strings.xml`; percentages formatted via
  `NumberFormat.getPercentInstance()` for locale correctness.
- Bottom sheet supports dynamic font scaling and respects reduced-motion (indeterminate
  spinners only where determinate progress is unavailable).

## 10. Telemetry & Logging

- Events (via `Telemetry`):
  `upload_started` { jobCount, totalBytes, folderId },
  `upload_progress_tick` (sampled, not per-byte),
  `upload_succeeded` { jobId, bytes, durationMs },
  `upload_failed` { jobId, leg: presign|put|confirm, errorCode, retryable },
  `upload_cancelled` { jobId }, `upload_retried` { jobId }.
- Logging uses the structured logger at DEBUG for leg transitions; **storage URLs are logged
  with query string redacted**; cookies/CSRF/filenames-with-PII are never logged at INFO+.
- Aggregate success rate and median duration are the headline metrics for validating the
  unreliable dev host.

## 11. Testing Strategy

- **Unit (core-testing + MockWebServer):**
  - `AttachmentUploader` end-to-end against MockWebServer queuing presign → PUT (dispatcher
    asserts no cookie/CSRF/Bearer header on the PUT) → confirm; assert progress fractions are
    monotonic and reach 1.0, and `Completed(FileEntry)` is emitted (built from the confirm
    `{ ok, path, size, content_type }`). **This is the ticket's acceptance test.**
  - `UploadQueue`: bounded concurrency (only `MAX_CONCURRENT` active given N>limit jobs),
    FIFO ordering, cancel removes from active set.
  - `FilesUploadViewModel`: `onFilesPicked` resolves metadata (fake `ContentResolver`),
    folder placement copies `targetFolderId`, `retry` re-enqueues with same id, `Completed`
    triggers `insertUploaded`.
  - Error mapping: presign 500, PUT 403 (expired), confirm 409 → correct `UploadState` and
    `retryable` flags; 401 triggers refresh-once path.
- **Compose UI test:** progress bar renders determinate during UPLOADING, indeterminate during
  PREPARING/CONFIRMING; cancel/retry buttons invoke ViewModel; semantics assertions for
  TalkBack labels.
- **Instrumented (optional, dev host):** real upload of a small fixture file end-to-end,
  guarded behind a manual/CI-nightly tag due to host unreliability.

## 12. Dependencies & Sequencing

- **Blocks on AND-331 (P0):** `FilesApi`, `FileEntry`, presign/confirm DTOs, and
  `FilesRepository.insertUploaded`. Must merge first.
- **Blocks on AND-129 (P0):** `AttachmentUploader` (presign→PUT→confirm with progress, cancel,
  retry) and its `UploadRequest`/`UploadEvent` contract. This ticket extends `UploadRequest`
  with `folderId` if not already present.
- **Sequencing:** AND-331 → AND-129 → **AND-333**. AND-333 contributes only the queue,
  ViewModel, folder-placement logic, and UI; it must not reimplement transport from AND-129.
- **Blocks:** none currently recorded.

## 13. Risks & Open Questions

- **R1 — Process death during upload:** v1 is process-scoped; a backgrounded/killed app loses
  in-flight uploads. *Mitigation/follow-up:* WorkManager + foreground service for resumable/
  background uploads (propose as a new M7 ticket; not in this scope).
- **R2 — Presigned URL expiry on slow/unreliable dev host:** long PUTs may outlive the URL
  TTL. Handled by retryable re-presign; large-file multipart presign is out of scope.
- **R3 — `folderId` placement on the presign DTO:** open question whether AND-331's
  presign request already carries `folder_id` or whether placement is decided at confirm.
  Resolve against `/openapi.json`; spec assumes presign carries it (confirm echoes it).
- **R4 — MIME/size from `ContentResolver`:** some providers return null type/size; fall back to
  `application/octet-stream` and stream-count bytes during PUT.
- **R5 — Storage host requires exact `Content-Type`:** S3 signature may bind the header; must
  send precisely the value returned in presign `headers`, not a re-derived one.

## 14. Acceptance Criteria

AC-1. Selecting a file via the picker (or share sheet) enqueues an upload targeted at the
current folder; the upload sheet shows the job with live, monotonic progress reaching 100%.
AC-2. **A file uploads end-to-end (presign → PUT → confirm) with progress, verified by a
MockWebServer-backed test**, and the PUT request carries no app cookies, no `X-CSRF-Token`,
and no `Authorization: Bearer` header.
AC-3. On confirm, the uploaded item (a `FileEntry` built from the confirm
`{ ok, path, size, content_type }` response) appears in the target folder's listing without a
manual refresh.
AC-4. The user can choose a different target folder; the uploaded file lands in that folder.
AC-5. Cancel stops an in-flight upload immediately (no confirm sent, job → CANCELLED); retry
restarts a failed job from presign and can succeed.
AC-6. Concurrency is bounded to `MAX_CONCURRENT`; extra jobs queue FIFO.
AC-7. Presign/confirm 401 triggers exactly one `session/refresh` then retry; persistent
failure moves the job to FAILED with a mapped error message.
AC-8. Progress and controls are TalkBack-accessible; all visible strings are localized.

## 15. Definition of Done

- Code merged to `android-port` under `feature-files/upload/` in `com.testlogon.android`.
- AND-331 and AND-129 contracts consumed (no transport reimplementation); `UploadRequest`
  carries `folderId`.
- Unit + Compose tests above pass in CI; the MockWebServer end-to-end upload test (AC-2) is
  green and is the gating test.
- No cookies/CSRF/secrets in logs; storage URLs redacted in telemetry; cleartext limited to
  the scoped dev host.
- Lint/detekt/ktlint clean; strings externalized; accessibility checks pass.
- Telemetry events emitted and verified; PR description links AND-331, AND-129, and resolves
  R3 against `/openapi.json`.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact authoritative source. Source pointers are
either OpenAPI `METHOD /path` + schema names (from `reference/openapi.index.txt` /
`reference/openapi.pretty.json`), frontend paths under `reference/src/`, or framework refs.

1. **Presign endpoint is `POST /ui/files/presign-upload`.** — **Corrected** → actual is
   `POST /v1/fs/presign-upload`.
   Source: OpenAPI `POST /v1/fs/presign-upload` (`op=presign_fs_upload_v1_fs_presign_upload_post`,
   `req=PresignUploadIn`, `resp=200:PresignUploadOut`); `src/api/endpoints/files.ts: fsPresignUpload`.
   No `/ui/files/*` path exists in the index.
2. **Confirm endpoint is `POST /ui/files/confirm-upload`.** — **Corrected** → actual is
   `POST /v1/fs/complete-upload`.
   Source: OpenAPI `POST /v1/fs/complete-upload` (`req=CompleteUploadIn`, `resp=200:`);
   `src/api/endpoints/files.ts: completeUpload`.
3. **Both legs are POST with JSON body.** — **Verified.**
   Source: OpenAPI index (both `POST`); `src/api/client.ts: api.post` sets JSON body + headers.
4. **Presign request fields = `folder_id, filename, content_type, size_bytes`.** — **Corrected**
   → `PresignUploadIn` has only `path` (required) and `content_type` (optional `string|null`).
   No `folder_id`, `filename`, or `size_bytes`. Placement is via the full `path`
   (`<folder>/<filename>`).
   Source: `components.schemas.PresignUploadIn`; `src/api/endpoints/files.ts: fsPresignUpload(path, contentType)`;
   `src/pages/files/FilesPage.tsx` builds `targetPath = currentPath + "/" + file.name`.
5. **Presign response = `{upload_id, url, method, headers, key}`.** — **Corrected** →
   `PresignUploadOut = {upload_url, bucket, key, ticket_id, path, content_type}` (all required).
   No `upload_id` (it is `ticket_id`), no `url` (it is `upload_url`), no `method`, no `headers`.
   Source: `components.schemas.PresignUploadOut`; `src/api/endpoints/files.ts: fsPresignUpload` return type.
6. **PUT leg is a bare request with no app cookies / no `X-CSRF-Token`.** — **Verified** (and
   extended: also no `Authorization: Bearer`).
   Source: `src/pages/files/FilesPage.tsx` —
   `fetch(presign.upload_url, { method: "PUT", headers: { "Content-Type": presign.content_type }, body })`
   with **no** `credentials: "include"` and no auth headers.
7. **PUT `Content-Type` must equal the presign-returned value.** — **Verified** (supports R5).
   Source: `src/pages/files/FilesPage.tsx` sends `headers: { "Content-Type": presign.content_type }`.
8. **An `ETag` is returned by the PUT and echoed to confirm.** — **Corrected** → no etag is
   read or sent; confirm is keyed by `ticket_id` + `key`. `CompleteUploadIn` has no `etag` field.
   Source: `components.schemas.CompleteUploadIn`; `src/api/endpoints/files.ts: completeUpload`
   (no etag param); `FilesPage.tsx` ignores the PUT response.
9. **Confirm request = `{upload_id, folder_id, etag}`.** — **Corrected** →
   `CompleteUploadIn = {path, key, ticket_id (required), content_type?, encrypted=false, enc_meta?}`.
   Source: `components.schemas.CompleteUploadIn`; `src/api/endpoints/files.ts: completeUpload`.
10. **Confirm response is a `FileNode` `{id, name, folder_id, size_bytes, content_type, created_at}`.**
    — **Corrected** → OpenAPI marks `200` untyped; the web client types it as
    `{ ok, path, size, content_type }`. There is **no `FileNode`** schema and no `id`/`folder_id`.
    Source: OpenAPI `POST /v1/fs/complete-upload` `resp=200:` (no schema);
    `src/api/endpoints/files.ts: completeUpload` return type.
11. **Listing item type is `FileNode`/`FolderNode`.** — **Corrected** → it is **`FileEntry`**
    (`{name, path, type:"file"|"folder", size?, content_type?, updated_at?, created_at?, ...}`),
    and folder listing is `FileListResp = {path, items: FileEntry[], cursor?}`.
    Source: `src/api/types.ts: FileEntry` (line ~1545), `FileListResp` (line ~1573).
12. **Folder listing fetched via path.** — **Verified** → `GET /v1/fs/list?path=<folder>`.
    Source: OpenAPI `GET /v1/fs/list`; `src/api/endpoints/files.ts: listFiles(path, ...)`.
13. **App-server auth = session cookie + `X-CSRF-Token` from `ui_csrf`.** — **Corrected/extended**
    → also `Authorization: Bearer <accessToken>`; all three are sent on every app call.
    Source: `src/api/client.ts` (sets `Authorization`, `X-CSRF-Token` from `getCookie("ui_csrf")`,
    `credentials: "include"`).
14. **401 triggers exactly one `POST /ui/session/refresh` then retry.** — **Verified.**
    Source: `src/api/client.ts: refreshSession` (`fetch("/ui/session/refresh", {method:"POST"})`)
    and the single-flight `refreshPromise` 401 handler.
15. **Validation/error detail shape (string | `[{msg}]` | `{code,...}`).** — **Verified.**
    Source: `components.schemas.HTTPValidationError` =
    `{detail: ValidationError[]}`, `ValidationError = {loc, msg, type}`;
    `src/api/client.ts: normalizeErrorDetail` handles string / array-of-`{msg}` / `{code}`.
16. **A direct single-shot multipart upload route exists (`POST /v1/fs/upload`).** — **Verified**
    (informational; the web client uses it below `PRESIGN_THRESHOLD`).
    Source: OpenAPI `POST /v1/fs/upload`; `src/api/endpoints/files.ts: uploadFile`;
    `FilesPage.tsx` branch `if (uploadFileObj.size > PRESIGN_THRESHOLD) {...presign...} else {...uploadFile...}`.
17. **Android stack choices** (Compose/Material 3, Hilt+KSP, Retrofit/OkHttp/Moshi,
    Paging 3, WorkManager, `ActivityResultContracts.OpenMultipleDocuments`, `ContentResolver`
    metadata, `ModalBottomSheet`, `collectAsStateWithLifecycle`). — **Unverified-assumption**
    (not derivable from backend/frontend sources; standard AOSP/AndroidX APIs).
    framework ref: developer.android.com (ActivityResultContracts, Jetpack Compose Material 3,
    Paging 3, WorkManager, ContentResolver) — owned by AND-331/AND-129 conventions.

### Corrections made

- Endpoints retargeted from `/ui/files/presign-upload` and `/ui/files/confirm-upload` to the
  verified `POST /v1/fs/presign-upload` and `POST /v1/fs/complete-upload` (§2, §5, §11).
- Placement model changed from `folder_id` to **path-based** (`path = <folder>/<filename>`);
  removed `filename`/`size_bytes` from the presign request (§1, §5, §6).
- Presign response fields corrected: `url→upload_url`, `upload_id→ticket_id`; removed
  non-existent `method`/`headers`; added `bucket`/`path`/`content_type` (§5).
- Confirm request corrected to `{path, key, ticket_id, content_type?, encrypted, enc_meta?}`;
  removed `upload_id`, `folder_id`, and the non-existent `etag` (§5, §7).
- Confirm response corrected to `{ok, path, size, content_type}`; eliminated the fictional
  `FileNode` return shape (§5, §6, §11, §14 AC-3).
- Listing/model type changed `FileNode`/`FolderNode` → **`FileEntry`** / `FileListResp`
  throughout (§1, §2, §4, §6, §12).
- Auth corrected to include `Authorization: Bearer` (in addition to cookie + CSRF) on app-server
  calls, and the bare-PUT requirement extended to strip the Bearer token too (§2, §5, §8, §14 AC-2).
- Added the verified `422 HTTPValidationError` shape to error handling (§7).

### Open assumptions

- **Confirm response exact JSON** — OpenAPI marks `POST /v1/fs/complete-upload` `200` as
  untyped; the `{ok, path, size, content_type}` shape is taken from the **web client type
  annotation** (`completeUpload`), not from the schema. Treat as the best-available contract;
  reconcile against a live response during integration. (`size` may be `null`.)
- **Presigned-URL TTL / expiry status code** — not expressed in OpenAPI; the 403/expired
  retry behavior (R2) is an assumption based on standard S3 presign semantics.
- **`folderId` on AND-129's `UploadRequest`** (R3) — moot under the corrected contract: the
  uploader needs a **`path`**, not a `folderId`. AND-333 must pass a full target `path` into the
  uploader; if AND-129 only exposes `folderId`, it must be changed to `path` (or `path` derived
  as `<folder>/<displayName>`). This supersedes the original R3 question.
- **MAX_CONCURRENT = 2, PRESIGN_THRESHOLD** — product/tuning choices, not backend-defined; the
  web client's exact `PRESIGN_THRESHOLD` value is not exported in the reviewed source.
- **Android framework APIs** (claim 17) — assumed standard AndroidX; not verifiable from the
  backend/frontend reference sources.

## 17. Test Plan

Test-target legend: **JVM** = local JVM/Robolectric (no device); **emu35** = headless emulator
AVD `test35` (x86_64, API 35) on the CI build server; **deviceA15** = physical Samsung Galaxy
A15 5G (SM-A156U, serial `R5CX821TA9R`, API 34, arm64-v8a) on the build host. Prefer the
physical device only for true hardware/ABI behavior; this ticket is mostly JVM/contract +
Compose-UI, with one ABI/API-parity case routed to the device.

- **TC-AND-333-01** — Type: contract/MockWebServer (JVM).
  Target: `AttachmentUploader` + `FilesApi`.
  Preconditions: MockWebServer enqueues, in order, (1) presign `200 PresignUploadOut`
  `{upload_url=<mock>/blob, bucket, key, ticket_id, path, content_type}`, (2) PUT `200`,
  (3) complete `200 {ok:true, path, size, content_type}`.
  Steps: upload a small in-memory fixture targeting `path="/docs/report.pdf"`; collect the
  `UploadEvent` flow.
  Expected: requests hit `POST /v1/fs/presign-upload` → `PUT {upload_url}` → `POST
  /v1/fs/complete-upload`; presign body = `{path, content_type}` only; complete body =
  `{path, key, ticket_id, content_type, encrypted=false, enc_meta=null}`; progress fractions
  are monotonic and reach `1.0`; terminal `Completed(FileEntry)` with name `report.pdf`.
  **This is the ticket's gating acceptance test.** Traces: AC-1, AC-2, AC-3.

- **TC-AND-333-02** — Type: contract/MockWebServer (JVM).
  Target: bare-PUT client / interceptor skip.
  Preconditions: same happy-path queue; MockWebServer `RecordedRequest` inspection enabled;
  a session cookie, `ui_csrf` cookie, and Bearer token are all set on the app client.
  Steps: run one upload; capture the PUT `RecordedRequest`.
  Expected: the PUT carries **no** `Cookie`, **no** `X-CSRF-Token`, **no** `Authorization`
  header; its `Content-Type` exactly equals `PresignUploadOut.content_type`. The presign and
  complete requests **do** carry Cookie + `X-CSRF-Token` + `Authorization: Bearer`.
  Traces: AC-2.

- **TC-AND-333-03** — Type: contract/MockWebServer (JVM).
  Target: folder placement (path construction).
  Preconditions: target folder set to `/projects/q2`; picked file display name `notes.txt`.
  Steps: enqueue via `onFilesPicked` with target folder `/projects/q2`.
  Expected: presign request `path == "/projects/q2/notes.txt"` (folder + basename); on
  complete, the inserted `FileEntry.path == "/projects/q2/notes.txt"`. Changing the target
  folder before enqueue changes the `path` accordingly. Traces: AC-4.

- **TC-AND-333-04** — Type: unit (JVM).
  Target: `UploadQueue` bounded concurrency + FIFO.
  Preconditions: `MAX_CONCURRENT=2`; enqueue 5 jobs whose uploader flows suspend on a latch.
  Steps: observe active vs queued sets; release latches in order.
  Expected: never more than 2 active simultaneously; remaining 3 start FIFO as slots free;
  `cancel(jobId)` removes a queued/active job from the active set. Traces: AC-6, AC-5.

- **TC-AND-333-05** — Type: unit (JVM).
  Target: `FilesUploadViewModel` metadata resolution + retry identity.
  Preconditions: fake `ContentResolver` returning `DISPLAY_NAME="a.pdf"`, `SIZE=1234`,
  `getType="application/pdf"`.
  Steps: `onFilesPicked([uri], "/docs")`; force the job to FAILED; call `retry(jobId)`.
  Expected: `UploadJob` built with correct name/mime/size and `targetFolderId`/path `/docs`;
  retry re-enqueues with the **same** `UploadJob.id` (row keeps position) and restarts from the
  presign leg. Traces: AC-1, AC-5.

- **TC-AND-333-06** — Type: unit (JVM).
  Target: null-metadata fallback (R4).
  Preconditions: fake `ContentResolver` returns null type and null size.
  Steps: `onFilesPicked` with that uri.
  Expected: `mimeType` falls back to `application/octet-stream`; presign sends
  `content_type` accordingly (or omits → server default); upload still proceeds and size is
  determined by the streamed PUT body. Traces: AC-1.

- **TC-AND-333-07** — Type: contract/MockWebServer (JVM).
  Target: error mapping for presign/PUT/confirm failures.
  Preconditions: parametrized — (a) presign `500`, (b) PUT `403` (expired URL), (c) complete
  `422 {detail:[{loc,msg,type}]}`, (d) complete `409`.
  Steps: run upload per variant; inspect terminal event.
  Expected: each maps to `UploadEvent.Failed` with a human message from the `detail` mapper;
  (a)/(b)/(d) `retryable=true` (retry re-presigns), (c) surfaces the `422` `msg` text;
  no confirm is sent when the PUT fails. Traces: AC-5, AC-7.

- **TC-AND-333-08** — Type: contract/MockWebServer (JVM).
  Target: 401 → single refresh → retry.
  Preconditions: presign returns `401` once, then `POST /ui/session/refresh` returns `200`,
  then presign retry returns `200`; happy path thereafter.
  Steps: run one upload.
  Expected: exactly one `POST /ui/session/refresh` is issued, the presign is retried once and
  succeeds, upload completes. Second variant: refresh returns `401` → job → FAILED with a
  mapped auth error and re-auth routing. Traces: AC-7.

- **TC-AND-333-09** — Type: unit (JVM).
  Target: cancel semantics.
  Preconditions: an in-flight job suspended mid-PUT (uploader flow blocked on a latch).
  Steps: call `cancel(jobId)`.
  Expected: the collecting coroutine is cancelled → OkHttp call cancel; job state → CANCELLED;
  **no** `complete-upload` request is ever sent (assert via MockWebServer no-3rd-request).
  Traces: AC-5.

- **TC-AND-333-10** — Type: unit/integration (JVM, Robolectric for connectivity flow).
  Target: offline/flaky-dev-host queueing.
  Preconditions: connectivity flow reports offline; jobs enqueued.
  Steps: enqueue 2 jobs offline; then flip connectivity to online.
  Expected: while offline, jobs sit in QUEUED with an offline banner and no network calls are
  made; on reconnect, presign starts automatically; a mid-upload network drop yields
  `Failed(retryable=true)` (one failure does not fail sibling jobs). Traces: AC-1, AC-5, AC-6.

- **TC-AND-333-11** — Type: Compose-UI (emu35).
  Target: `UploadSheet` rendering + controls.
  Preconditions: fake `UploadUiState` with jobs in PREPARING, UPLOADING(0.42), CONFIRMING,
  FAILED, DONE.
  Steps: render the sheet; click cancel on the UPLOADING row and retry on the FAILED row.
  Expected: determinate `LinearProgressIndicator` for UPLOADING (value ≈0.42), indeterminate
  for PREPARING/CONFIRMING; cancel/retry icon buttons invoke the ViewModel callbacks; rows are
  keyed by `UploadJob.id`. Traces: AC-1, AC-5.

- **TC-AND-333-12** — Type: Compose-UI / accessibility (emu35).
  Target: TalkBack semantics + i18n.
  Preconditions: UPLOADING job at 42%; non-default locale set; large font scale.
  Steps: assert semantics; toggle locale.
  Expected: row exposes `stateDescription` like "Uploading report.pdf, 42 percent" (percent via
  `NumberFormat.getPercentInstance()`); cancel/retry have `contentDescription` and ≥48dp touch
  targets; all visible labels resolve from `strings.xml` (no hardcoded text); layout survives
  font scaling. Traces: AC-8.

- **TC-AND-333-13** — Type: security (JVM).
  Target: log/telemetry redaction.
  Preconditions: capturing logger + telemetry sink; run a full upload.
  Steps: inspect emitted logs/telemetry.
  Expected: presigned `upload_url` query string is redacted; cookies, `X-CSRF-Token`, and the
  Bearer token never appear at INFO+; `upload_failed` telemetry includes `leg` ∈
  {presign,put,confirm} and `retryable`. Traces: AC-2 (security posture), AC-7.

- **TC-AND-333-14** — Type: instrumented/e2e (deviceA15 — MUST run on the physical device).
  Target: end-to-end real upload + ABI/API-34 parity.
  Preconditions: build host reachable via adb to serial `R5CX821TA9R`; signed-in session
  against the dev host `http://18.222.237.167:8000` (cleartext via scoped
  network-security-config); small fixture file present via SAF. Tagged CI-nightly/manual due to
  dev-host unreliability.
  Steps: pick a real file via the system document picker; upload into the current folder;
  observe progress to 100%; verify it appears in the listing; relist via `GET /v1/fs/list`.
  Expected: presign→PUT(HTTPS S3)→complete all succeed on arm64-v8a/API 34; uploaded
  `FileEntry` is visible without manual refresh. Runs on the **physical device** to validate the
  real SAF/`ContentResolver` document-picker grant and arm64-vs-x86 / API-34-vs-35 behavior that
  the x86_64/API-35 emulator cannot represent. (An emu35 variant may run in CI for speed, but
  the device run is authoritative for sign-off.) Traces: AC-1, AC-2, AC-3.

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 | TC-01, TC-05, TC-06, TC-10, TC-11, TC-14 |
| AC-2 | TC-01, TC-02, TC-13, TC-14 |
| AC-3 | TC-01, TC-14 |
| AC-4 | TC-03 |
| AC-5 | TC-04, TC-05, TC-07, TC-09, TC-10, TC-11 |
| AC-6 | TC-04, TC-10 |
| AC-7 | TC-07, TC-08, TC-13 |
| AC-8 | TC-12 |
