---
id: AND-334
title: Download / open
milestone: M7
epic: E43
priority: P1
size: M
status: draft
depends_on: [AND-331]
blocks: []
---

# AND-334 — Download / open

## 1. Overview & Goal

This ticket implements file download and "open-with" for the native Android
file-manager feature. A user browsing files (AND-332) taps a file row or a
"Download" action; the app fetches the file's authenticated bytes from the
TestLogon backend, streams them to a managed on-disk cache under the app's
private storage, exposes the saved file via a `FileProvider` content URI, and
launches a system `ACTION_VIEW` (or chooser) intent so the user can open it in
the appropriate external app (PDF viewer, image gallery, document editor, etc.).

The download path must behave correctly against the unreliable dev backend
(`http://18.222.237.167:8000`, plaintext HTTP): long-running streamed transfers
with progress, a ~20s connect/read timeout per chunk, cancellation, resumption
of interrupted downloads where the server supports `Range`, and a bounded
content-addressed cache so repeated opens of the same file version are instant
and offline-tolerant.

Goal / done condition (from backlog Acceptance "Download + open work"): from a
file detail or list row, a user can download any file they have read access to,
see deterministic progress, and have it open in an external app via the system
open-with surface — with the bytes cached so a second open requires no network.

Out of scope: browsing/listing/search (AND-332), uploads (AND-333), public
share-link downloads (AND-335), Google Drive import (AND-336). This ticket owns
only the authenticated download + cache + open-with flow for files the signed-in
user already has access to.

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, monorepo subfolder `android/`,
  branch `android-port`. New code lands in `feature-files` (UI + ViewModel) and
  `core-data` (download/cache repository), backed by `core-network`
  (`FilesApi`, `OkHttpClient`) and `core-model` (DTOs from AND-331).
- **Namespace / applicationId base:** `com.testlogon.android`. New packages:
  `com.testlogon.android.feature.files.download`,
  `com.testlogon.android.core.data.files.download`.
- **Depends on AND-331 (Files API + DTOs):** provides the `FilesApi` Retrofit
  interface and `FileDto` / `FileDownloadDto` models. AND-334 adds the streaming
  download method and download-token call to that interface but reuses its DTOs.
- **Web reference:** `frontend/src/api/endpoints/files.ts` (download URL
  construction, `getDownloadUrl`/`downloadFile`) and `frontend/src/api/types.ts`
  (file shape). Mirror its endpoint contract; the web app downloads via a
  browser-resolved presigned/streamed URL with cookies.
- **OpenAPI:** `http://18.222.237.167:8000/openapi.json` — confirm the exact
  download route, whether it returns a 302 redirect to a presigned URL or a
  direct streamed body, and `Range`/`Accept-Ranges` support at integration time
  (see Open Questions).
- **Auth context:** cookie-based session + `ui_csrf` cookie echoed as
  `X-CSRF-Token`; persistent cookie jar (established by the auth epic). On 401
  the OkHttp authenticator calls `POST /ui/session/refresh` once then retries —
  the download client must reuse that same shared `OkHttpClient` so refresh and
  cookies apply to byte transfers too.

## 3. Functional Requirements

FR-1. From a file row/detail, the user can trigger **Download** for any file
they have read access to. If the file is already cached for its current version,
Download is a no-op fetch and proceeds straight to step FR-5.

FR-2. Download streams bytes to disk (not buffered fully in memory) and emits
progress: `bytesDownloaded`, `totalBytes` (nullable when the server omits
`Content-Length`), and a derived `fraction` (0f–1f, or indeterminate).

FR-3. The user can **cancel** an in-flight download; cancellation tears down the
HTTP call and deletes the partial temp file (unless resumable, see FR-7).

FR-4. On success the file is committed to the content-addressed cache keyed by
`(fileId, version/etag)` and the original filename + MIME type are preserved for
the open intent.

FR-5. **Open / open-with:** after a successful download (or on tapping a
cached file), the app exposes the file through `FileProvider` and launches
`Intent.ACTION_VIEW` with the file's MIME type and `FLAG_GRANT_READ_URI_PERMISSION`.
If no app can handle the MIME type, the app falls back to a chooser
(`Intent.createChooser`) and, if still unresolvable, shows a "No app can open
this file" message with a "Share" alternative (`ACTION_SEND`).

FR-6. A separate **"Save to Downloads"** action copies the cached file into the
public `Downloads/` collection via MediaStore (Android 10+) / SAF, distinct
from the private app cache. (Open-with does NOT require public storage.)

FR-7. **Resume:** if the server advertises `Accept-Ranges: bytes`, an
interrupted download keeps its `.part` temp file and resumes with a
`Range: bytes=<offset>-` header on retry; otherwise it restarts from 0.

FR-8. The cache is **bounded** (default 256 MB, LRU eviction) and survives
process death; eviction never deletes a file that is currently being opened.

FR-9. All states are reflected in `FileDownloadUiState`: `Idle`, `InProgress`,
`Success(openable)`, `Cancelled`, `Error(retryable)`.

## 4. Technical Design

### 4.1 Layering

```
feature-files (UI/VM)
  FileActionsViewModel  ──► DownloadRepository (core-data)
                              ├─► FilesApi (core-network, streamed)
                              ├─► FileCacheStore (DataStore index + disk)
                              └─► OpenWithLauncher (FileProvider + Intent)
```

### 4.2 Repository

```kotlin
package com.testlogon.android.core.data.files.download

sealed interface DownloadStatus {
    data class InProgress(
        val bytesDownloaded: Long,
        val totalBytes: Long?,        // null when Content-Length absent
    ) : DownloadStatus {
        val fraction: Float? get() =
            totalBytes?.takeIf { it > 0 }?.let { bytesDownloaded.toFloat() / it }
    }
    data class Success(val cached: CachedFile) : DownloadStatus
    data object Cancelled : DownloadStatus
    data class Failed(val error: ApiError, val retryable: Boolean) : DownloadStatus
}

data class CachedFile(
    val fileId: String,
    val version: String,            // etag / version used as cache key part
    val displayName: String,
    val mimeType: String,
    val sizeBytes: Long,
    val absolutePath: String,       // file in app cacheDir/files/
)

interface DownloadRepository {
    /** Cold flow; collecting starts the transfer, cancelling collection cancels it. */
    fun download(fileId: String): Flow<DownloadStatus>

    /** Returns a cached file if present & matching current version, else null. */
    suspend fun cached(fileId: String): CachedFile?

    suspend fun evict(fileId: String)
    suspend fun clearCache()
}
```

`download()` flow logic:
1. Resolve metadata (`FileDto` already in browse cache, or `GET /ui/files/{id}`)
   to get `displayName`, `mimeType`, `etag/version`, `size`.
2. Cache hit check via `FileCacheStore.lookup(fileId, version)`; if hit emit
   `Success` immediately.
3. Open streamed response (see §5). Write to `cacheDir/files/.tmp/<id>.part`.
   If a `.part` exists and `Accept-Ranges: bytes`, send `Range` and append.
4. Emit `InProgress` throttled to ~10 Hz (avoid recomposition storms) using a
   `conflate()`-friendly emit cadence (min 100 ms or 1% delta).
5. On full read, fsync, atomically `rename` `.part` → final cache path, update
   the cache index (DataStore + LRU), emit `Success`.
6. `catch`/`onCompletion`: map exceptions, on cooperative cancellation emit
   `Cancelled` and keep `.part` only if resumable, else delete.

### 4.3 Streaming on OkHttp

Use the shared `OkHttpClient` (cookie jar + CSRF + refresh authenticator) but
override the **call timeout** to 0 (unbounded total) while keeping connect/read
timeouts at 20s so a stalled socket still fails fast:

```kotlin
val streamClient = baseClient.newBuilder()
    .callTimeout(Duration.ZERO)
    .connectTimeout(20, SECONDS)
    .readTimeout(20, SECONDS)
    .build()
```

Read the body via `ResponseBody.source()` (Okio `BufferedSource`) into an
`8 KiB` buffer in a loop, checking `currentCoroutineContext().isActive` each
iteration for cooperative cancellation; all I/O runs on `Dispatchers.IO`.

### 4.4 ViewModel

```kotlin
package com.testlogon.android.feature.files.download

@HiltViewModel
class FileActionsViewModel @Inject constructor(
    private val repo: DownloadRepository,
    private val launcher: OpenWithLauncher,
) : ViewModel() {

    private val _state = MutableStateFlow<FileDownloadUiState>(FileDownloadUiState.Idle)
    val state: StateFlow<FileDownloadUiState> = _state.asStateFlow()

    private var job: Job? = null

    fun downloadAndOpen(fileId: String) {
        job?.cancel()
        job = viewModelScope.launch {
            repo.download(fileId).collect { st ->
                _state.value = st.toUiState()
                if (st is DownloadStatus.Success) launcher.open(st.cached)
            }
        }
    }
    fun cancel() { job?.cancel() }
    fun saveToDownloads(fileId: String) { /* MediaStore copy of cached file */ }
}
```

### 4.5 Open-with launcher + FileProvider

`AndroidManifest.xml` (feature-files) declares:

```xml
<provider
    android:name="androidx.core.content.FileProvider"
    android:authorities="com.testlogon.android.fileprovider"
    android:exported="false"
    android:grantUriPermissions="true">
    <meta-data android:name="android.support.FILE_PROVIDER_PATHS"
        android:resource="@xml/file_provider_paths"/>
</provider>
```

`res/xml/file_provider_paths.xml` exposes `cache-path` subdir `files/`.

```kotlin
class OpenWithLauncher @Inject constructor(@ApplicationContext ctx: Context) {
    fun open(file: CachedFile) {
        val uri = FileProvider.getUriForFile(
            ctx, "${ctx.packageName}.fileprovider", File(file.absolutePath))
        val view = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, file.mimeType)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        val chooser = Intent.createChooser(view, /* title */ null)
        // resolve: if none, surface SEND fallback / no-app error
        ctx.startActivity(chooser)
    }
}
```

## 5. API Contract

Authoritative route to be confirmed against `/openapi.json` at integration
(Open Question OQ-1); design assumes the web reference shape in
`frontend/src/api/endpoints/files.ts`.

**Streamed download (primary):**

```
GET /ui/files/{file_id}/download
Headers: Cookie: <session>; X-CSRF-Token: <ui_csrf>
         Range: bytes=<offset>-            (only on resume)
→ 200 OK  (or 206 Partial Content on resume)
   Content-Type: <file mime, e.g. application/pdf>
   Content-Length: 1048576                  (may be absent)
   Accept-Ranges: bytes                     (when resumable)
   Content-Disposition: attachment; filename="report.pdf"
   <binary body stream>
```

If the backend instead returns a presigned redirect:

```
GET /ui/files/{file_id}/download  → 302 Found
   Location: https://<bucket>.s3.amazonaws.com/...&X-Amz-Signature=...
```

The repository must `followRedirects(true)` and stream from the resolved
`Location`. The presigned URL is unauthenticated, so cookies/CSRF are NOT sent
on the redirected leg (OkHttp drops cross-host auth headers by default; verify).

**Retrofit signature (added to AND-331's `FilesApi`):**

```kotlin
@Streaming
@GET("ui/files/{fileId}/download")
suspend fun downloadFile(
    @Path("fileId") fileId: String,
    @Header("Range") range: String? = null,
): Response<ResponseBody>
```

`@Streaming` is mandatory so Retrofit does not buffer the whole body.

**Error bodies** follow the project's FastAPI `detail` mapping (string |
`[{msg}]` | `{code,...}`): `404` file not found / no access, `403` forbidden,
`401` expired session (→ refresh+retry once via authenticator), `5xx`/timeout
treated as retryable transport errors.

Filename/MIME resolution precedence: `Content-Disposition` filename →
`FileDto.name` from AND-331 → `fileId`; MIME: response `Content-Type` →
`FileDto.contentType` → `MimeTypeMap` from extension → `application/octet-stream`.

## 6. Data & State Management

**UI state (StateFlow<UiState> per project convention):**

```kotlin
sealed interface FileDownloadUiState {
    data object Idle : FileDownloadUiState
    data class InProgress(val fraction: Float?, val bytes: Long, val total: Long?) : FileDownloadUiState
    data class Success(val cached: CachedFile) : FileDownloadUiState
    data object Cancelled : FileDownloadUiState
    data class Error(val message: String, val retryable: Boolean) : FileDownloadUiState
}
```

**Cache index (DataStore Preferences, not Room — small key/value index):**
store a JSON-serialized map `fileId → CacheEntry(version, path, size, mime,
displayName, lastAccessEpochMs)`. Bytes live on disk in
`context.cacheDir/files/`. Rationale: Room (AND-331/AND-332 use it for the
browse list cache) is overkill for the blob index and the blobs themselves must
not live in SQLite. LRU eviction sorts by `lastAccessEpochMs`, evicting until
total ≤ 256 MB; an entry whose path has an active open `FileLock`/in-flight
reference is skipped.

Cache key = `fileId` + `version` (etag). A new version invalidates the old
cached blob (deleted on next eviction pass / on overwrite).

Progress is held only in the ViewModel `StateFlow`; it is not persisted. A
download interrupted by process death is restarted (resumed from `.part` if
present and resumable) when the user re-triggers.

## 7. Error Handling & Resilience

- **Timeouts:** connect/read = 20s (per the unreliable dev host); total call
  timeout disabled so large files on a slow link are not killed.
- **Retry:** GET download is idempotent → bounded backoff (e.g. 3 attempts,
  250ms → 1s → 4s + jitter) on `IOException`/`5xx`/timeout. With resumable
  support, retries resume from `.part` offset rather than restart.
- **401:** delegated to the shared OkHttp authenticator (`/ui/session/refresh`
  once, then retry); if refresh fails the flow emits `Error(retryable=false)`
  and the UI routes the user to re-auth.
- **Cancellation:** cooperative via coroutine cancellation; partial `.part`
  retained only when resumable, else deleted in `onCompletion`.
- **Disk full / IOException on write:** emit `Error(retryable=false,
  "Not enough space")`; delete `.part`.
- **Integrity:** if server sends `Content-Length`, verify final size matches;
  mismatch → discard and `Error(retryable=true)`. If an `ETag`/checksum header
  is present, validate (best-effort, OQ-2).
- **Offline / cache fallback:** if there is no connectivity but a valid cached
  version exists, skip the network entirely and open from cache; if not cached,
  emit `Error(retryable=true, "You're offline")`.
- **No-app-to-open:** not an error state — `Success` is still emitted; the
  launcher surfaces a chooser/Share fallback message.

## 8. Security & Privacy

- Downloaded bytes are written to **app-private** `cacheDir` (no READ/WRITE
  external storage permission needed for open-with). Public export
  (FR-6 "Save to Downloads") uses scoped MediaStore — still no legacy storage
  permission on minSdk 24+ targets via MediaStore on Q+, with a runtime
  `WRITE_EXTERNAL_STORAGE` request only on API ≤ 28 for the public-save path.
- Files are shared to external apps strictly via `FileProvider` content URIs
  with `FLAG_GRANT_READ_URI_PERMISSION` (read-only, transient grant). No
  `file://` URIs (would throw `FileUriExposedException`). `exported="false"`.
- The download request carries the session cookie + `X-CSRF-Token`; **plaintext
  HTTP** on the dev host means bytes traverse the network unencrypted. This is
  acceptable only for the dev backend; `usesCleartextTraffic` is restricted to
  the dev host via a network-security-config domain allowlist (owned by the
  networking epic). Production must be HTTPS — flagged as a release gate.
- Never log file contents, cookies, CSRF token, or presigned `Location` URLs
  (presigned URLs are bearer credentials). Cache index stores no auth material.
- `clearCache()` is invoked on logout (hook into the session/auth-clear path) so
  one user's downloaded files are not readable after sign-out.

## 9. Accessibility & i18n

- Progress UI: a determinate `LinearProgressIndicator` when `fraction != null`,
  indeterminate otherwise, with `Modifier.semantics { progressBarRangeInfo }`
  and a `contentDescription` like "Downloading report.pdf, 42 percent".
- Cancel/Download/Open/Share controls have `contentDescription`s and ≥ 48 dp
  touch targets; chooser is the system surface (already accessible).
- All user-facing strings (`Download`, `Open`, `Save to Downloads`,
  `Downloading…`, `No app can open this file`, `You're offline`, error
  messages, percent format) live in `core-ui`/`feature-files` `strings.xml`;
  percentages formatted via `NumberFormat.getPercentInstance(locale)`. File
  sizes formatted with `Formatter.formatShortFileSize(context, bytes)` for
  locale-aware units.
- Announce terminal states (Success/Error/Cancelled) via a `Snackbar`/live
  region so screen-reader users get the outcome.

## 10. Telemetry & Logging

Emit structured analytics events (through the app's existing analytics
abstraction; no PII, no filenames in payloads — use `fileId` hash):
`file_download_start{fileId, sizeBytes?, cacheHit:Boolean}`,
`file_download_complete{fileId, durationMs, bytes, resumed:Boolean}`,
`file_download_cancel{fileId, bytesDownloaded}`,
`file_download_error{fileId, httpStatus?, errorClass, retryable}`,
`file_open_with{fileId, mime, resolvedAppPresent:Boolean}`,
`file_save_to_downloads{fileId, ok:Boolean}`.
Debug-build `Timber` logs for transfer lifecycle and cache eviction; redact
cookies/CSRF/Location. No raw bytes ever logged.

## 11. Testing Strategy

**Unit (JVM, `core-testing` fakes):**
- `DownloadRepository` against `MockWebServer`: 200 streamed body → `Success`
  with correct size/mime/name; `Content-Length` absent → indeterminate progress;
  size mismatch → `Error(retryable)`; `404/403` → mapped non-retryable error;
  `5xx`/socket-timeout → retryable, retried with backoff.
- Resume: serve 206 with `Range` honored; assert `.part` reused and final bytes
  equal full reference file.
- Cancellation: cancel the collecting scope mid-stream; assert `Cancelled` and
  `.part` cleanup/retention per resumable flag.
- Cache: hit returns without network; LRU eviction respects 256 MB bound and
  skips in-use entries; version change invalidates.
- DTO/header parsing: `Content-Disposition` filename + MIME precedence.

**Instrumented (`androidTest`):**
- `FileProvider.getUriForFile` returns a content URI for a cached file and the
  `ACTION_VIEW` intent carries the read grant + correct type (assert via
  `Intents`/Espresso-Intents without launching a real external app).
- "Save to Downloads" writes to MediaStore and the file is readable back.

**Compose UI:** state-driven snapshot/behavior tests for Idle → InProgress
(determinate & indeterminate) → Success/Error/Cancelled, and Cancel button
invokes `cancel()`.

Backlog acceptance "Download + open work" is verified by the end-to-end
`MockWebServer` download → cache → `Intents` open-with assertion.

## 12. Dependencies & Sequencing

- **Hard dependency: AND-331 (Files API + DTOs)** — supplies `FilesApi`,
  `FileDto`/`FileDownloadDto`, and the file-metadata fetch. The `@Streaming`
  download method is added to that interface here.
- **Soft / sibling:** AND-332 (browse) provides the entry point UI (row/detail)
  that triggers this flow; AND-334 can be developed in parallel with a stub
  trigger but integrates into AND-332's screens.
- **Reuses:** shared `OkHttpClient` (cookie jar + CSRF + refresh authenticator)
  and network-security-config cleartext allowlist from the networking/auth
  epics; analytics abstraction; `core-ui` components.
- **Not blocked by:** AND-333 (upload), AND-335 (share-link download — separate
  public/unauthenticated path), AND-336 (Drive). Public share-link downloads are
  explicitly owned by AND-335, not here.
- This ticket **blocks** nothing in the source bullets.

## 13. Risks & Open Questions

- **OQ-1:** Exact download route and whether the backend streams the body
  directly or returns a 302 to a presigned S3 URL — confirm via `/openapi.json`
  and `frontend/src/api/endpoints/files.ts`. Affects redirect handling and
  whether auth headers ride the byte transfer.
- **OQ-2:** Does the server send `Accept-Ranges: bytes` and a stable `ETag`/
  checksum? Determines resumability (FR-7) and integrity validation. If absent,
  downloads restart on retry.
- **OQ-3:** Is there a server-side max file size / does the dev host reliably
  send `Content-Length`? Drives determinate-vs-indeterminate progress and the
  256 MB cache bound default.
- **Risk:** plaintext HTTP dev host can stall mid-stream; mitigated by 20s
  socket timeouts + resumable retry, but very large files on flaky links may
  repeatedly fail — surface a clear retryable error.
- **Risk:** device fragmentation in open-with handling (OEMs that ignore
  `createChooser`); mitigated by `ACTION_SEND` fallback and explicit no-app
  messaging.
- **Risk:** presigned `Location` is a bearer credential — must never be logged
  or persisted in the cache index.

## 14. Acceptance Criteria

AC-1. Triggering Download on an accessible file streams its bytes to the private
cache and the UI shows determinate progress when `Content-Length` is present,
indeterminate otherwise. (FR-2)

AC-2. On completion the file opens in an external app via a `FileProvider`
content URI + `ACTION_VIEW`/chooser; when no app can handle the MIME type, a
chooser/`ACTION_SEND` fallback or a clear "No app can open this file" message is
shown. (FR-5) — satisfies backlog "Download + open work".

AC-3. A second open of the same file version performs **no network request** and
opens directly from cache, including when offline. (FR-1, FR-8, §7 offline)

AC-4. Cancellation stops the transfer promptly, emits `Cancelled`, and cleans up
the partial file (or retains it for resume when the server is resumable). (FR-3,
FR-7)

AC-5. `404/403` map to a non-retryable error; timeouts/`5xx` are retried with
bounded backoff; `401` triggers exactly one `/ui/session/refresh` + retry. (§7)

AC-6. The cache stays within its 256 MB bound via LRU eviction without deleting a
file currently being opened, and a version change invalidates the stale blob.
(FR-8)

AC-7. "Save to Downloads" copies the cached file into the public Downloads
collection via MediaStore and it is readable afterward. (FR-6)

AC-8. No `file://` URIs are exposed (no `FileUriExposedException`); cookies,
CSRF token, and presigned URLs never appear in logs or analytics. (§8, §10)

AC-9. Unit + instrumented tests in §11 pass in CI, including the end-to-end
MockWebServer-download → cache → open-with `Intents` assertion.

## 15. Definition of Done

- `DownloadRepository`, `FileCacheStore`, `OpenWithLauncher`,
  `FileActionsViewModel`, and the `@Streaming` `downloadFile` method on
  AND-331's `FilesApi` are implemented under `com.testlogon.android.*` packages
  and wired via Hilt (KSP).
- `FileProvider` is declared (`com.testlogon.android.fileprovider`,
  `exported=false`) with `file_provider_paths.xml` scoping `cacheDir/files/`.
- All FRs and ACs (§3, §14) are met; backlog acceptance "Download + open work"
  is demonstrably satisfied.
- Unit, Compose, and instrumented tests (§11) are written and green in CI;
  coverage includes streamed download, resume, cancel, cache LRU, error mapping,
  and the open-with intent.
- No `file://` exposure; security review of cleartext scope, FileProvider grants,
  logout cache-clear, and log/analytics redaction is complete (§8).
- Strings externalized and accessibility annotations applied (§9).
- ktlint/detekt clean; PR reviewed and merged to `android-port`; OQ-1–OQ-3
  resolved against the live backend or filed as follow-ups with safe defaults.
