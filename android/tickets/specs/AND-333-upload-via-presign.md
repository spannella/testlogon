---
id: AND-333
title: Upload via presign
milestone: M7
epic: E43
priority: P1
size: M
status: draft
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
  - **AND-331 — Files API + DTOs** (P0): provides `FilesApi` Retrofit interface, `FileNode`
    / `FolderNode` models, and the presign request/response DTOs that this ticket consumes.
  - **AND-129 — Attachment pipeline** (P0): provides the reusable `AttachmentUploader` that
    performs presign→PUT→confirm with progress, cancel, and retry. AND-333 calls it; it does
    not reimplement the transport.
- **Backend:** FastAPI + DynamoDB; dev host `http://18.222.237.167:8000` (plaintext HTTP,
  unreliable). OpenAPI at `/openapi.json`. Web reference: `frontend/src/api/endpoints/files.ts`.
- **Auth:** cookie-based session with `X-CSRF-Token` echoed from the `ui_csrf` cookie;
  persistent cookie jar. Presign and confirm calls are app-server calls and therefore carry
  cookies + CSRF; the PUT to storage is a **bare** request (no app cookies, no CSRF header).

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

FR-6. On confirm success, the new `FileNode` is **inserted into the folder listing** for the
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
    data class Completed(val file: FileNode) : UploadEvent
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
**AND-331** (presign shapes) and **AND-129** (transport). Endpoint paths and shapes below are
the contract this integration relies on; mismatches discovered against `/openapi.json` are
reconciled with AND-331.

**Leg 1 — Presign (app server, cookies + CSRF):**
`POST /ui/files/presign-upload`

```json
// request
{ "folder_id": "fld_123", "filename": "report.pdf",
  "content_type": "application/pdf", "size_bytes": 482133 }
// response
{ "upload_id": "up_abc", "url": "https://s3.amazonaws.com/bucket/key?...",
  "method": "PUT", "headers": { "Content-Type": "application/pdf" },
  "key": "users/u1/fld_123/report.pdf" }
```

**Leg 2 — PUT to storage (bare request, NO app cookies, NO X-CSRF-Token):**
`PUT {url}` with body = file bytes, `Content-Type` from `headers`. Success = HTTP 200/204; an
`ETag` may be returned and echoed to confirm.

**Leg 3 — Confirm (app server, cookies + CSRF):**
`POST /ui/files/confirm-upload`

```json
// request
{ "upload_id": "up_abc", "folder_id": "fld_123", "etag": "\"9f8e...\"" }
// response (a FileNode per AND-331)
{ "id": "file_789", "name": "report.pdf", "folder_id": "fld_123",
  "size_bytes": 482133, "content_type": "application/pdf",
  "created_at": "2026-06-05T12:00:00Z" }
```

Retrofit signatures (in `FilesApi`, from AND-331; referenced here):

```kotlin
@POST("ui/files/presign-upload")
suspend fun presignUpload(@Body body: PresignUploadRequest): ApiResult<PresignUploadResponse>

@POST("ui/files/confirm-upload")
suspend fun confirmUpload(@Body body: ConfirmUploadRequest): ApiResult<FileNode>
```

## 6. Data & State Management

- **Source of truth:** `FilesUploadViewModel.uiState: StateFlow<UploadUiState>`; the sheet
  collects it with `collectAsStateWithLifecycle()`.
- **Job identity:** each `UploadJob.id` is a UUID minted at enqueue and preserved across retry
  so the row keeps its position and progress bar.
- **Progress source:** `UploadEvent.Progress.fraction`, computed by the uploader as
  bytesWritten / sizeBytes during the PUT leg via an OkHttp `RequestBody.writeTo` counter.
- **Folder placement:** the active `targetFolderId` is held in state and copied into each job;
  default is the folder the user is browsing (passed by the Files screen route arg).
- **Listing integration:** on `Completed`, `FilesRepository.insertUploaded(folderId, file)`
  (AND-331) writes the new `FileNode` into the Room cache for that folder so the Paging 3
  flow re-emits; if the cache for that folder is not present, it invalidates the page source so
  the next browse fetches fresh.
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
  since the presigned URL may have expired).
- **Timeouts:** large PUTs use an extended write timeout (e.g. 60s write / per-call) distinct
  from the default ~20s app-call timeout; the presign and confirm calls keep the standard ~20s
  timeout with bounded backoff *only if* they are retried as idempotent (presign POST is not
  retried automatically).
- **401 on presign/confirm:** handled by the global auth interceptor — one
  `POST /ui/session/refresh` then retry; if refresh fails the job moves to FAILED and the user
  is routed to re-auth.
- **Presigned-URL expiry (403/expired):** treated as retryable; retry re-presigns.
- **Cancel:** cancels the coroutine → OkHttp call cancel; job → CANCELLED, no confirm sent.
- **Offline:** if no connectivity, jobs sit in QUEUED with an offline banner; they start when
  connectivity returns (observed via the connectivity flow from core-data).
- **Partial batch:** independent jobs; one failure does not fail siblings.

## 8. Security & Privacy

- **Content URI access:** read selected files via `ContentResolver` using the temporary URI
  permission granted by the picker; do not persist URI grants beyond the session and do not
  copy file bytes to app-private storage unless required for retry buffering.
- **CSRF/cookies:** presign and confirm carry the session cookie jar + `X-CSRF-Token` (from
  `ui_csrf`). The storage PUT must **strip** app cookies and the CSRF header — enforce via a
  dedicated bare OkHttp client / `@Tag`-based interceptor skip so credentials are never leaked
  to the S3 host.
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
    asserts no cookie/CSRF header on the PUT) → confirm; assert progress fractions are
    monotonic and reach 1.0, and `Completed(FileNode)` is emitted. **This is the ticket's
    acceptance test.**
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

- **Blocks on AND-331 (P0):** `FilesApi`, `FileNode`, presign/confirm DTOs, and
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
MockWebServer-backed test**, and the PUT request carries no app cookies and no `X-CSRF-Token`.
AC-3. On confirm, the returned `FileNode` appears in the target folder's listing without a
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
