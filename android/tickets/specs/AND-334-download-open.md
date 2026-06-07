---
id: AND-334
title: Download / open
milestone: M7
epic: E43
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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
- **Web reference (CORRECTED):** `frontend/src/api/endpoints/files.ts` exposes
  `downloadUrl(path)` returning `` `/v1/fs/download?path=${encodeURIComponent(path)}` ``
  (NOT `getDownloadUrl`/`downloadFile`, which do not exist), and
  `frontend/src/api/types.ts` `FileEntry` (NOT `FileDto`/`FileDownloadDto`). The
  web app downloads by `fetch(downloadUrl, { credentials: "include" })` to that
  URL (`frontend/src/pages/files/FilesPage.tsx: performDownload`), reads the full
  body as a Blob, then triggers a synthetic `<a download>` click. There is **no
  presigned-redirect / 302** path in the file API; presign exists only for
  *upload* (`fsPresignUpload`). Note: the web client decrypts encrypted files
  (`FileEntry.is_encrypted`) client-side after fetching — see §7/Open Questions.
- **OpenAPI (CORRECTED):** route is `GET /v1/fs/download` with a **required
  `path` query param** (string). Documented responses are `200`, `400`, `401`,
  `403`, `422`, `429` — there is **no documented 404 and no documented 5xx**, and
  the 200 response advertises only `application/json` content (no `Range`/
  `Accept-Ranges`/`Content-Disposition`/`Content-Length` headers are specified).
  Resumability and content-disposition behavior are therefore **unverified
  assumptions** (see Open Questions OQ-1/OQ-2). Spec endpoints `GET /ui/files/{file_id}/download`
  and the 302-presigned variant do **not exist** in the backend.
- **Auth context (CORRECTED):** the shared transport sends
  `Authorization: Bearer <accessToken>` (from the auth store) **and** the
  `ui_csrf` cookie echoed as `X-CSRF-Token`, with cookies via
  `credentials: include` (`frontend/src/api/client.ts`). The download endpoint
  also accepts `X-API-Key` as an alternative credential (per OpenAPI), but the UI
  path uses Bearer+cookie+CSRF. On 401 the client refreshes once via
  `POST /ui/session/refresh` (returns `StatusResp`) then retries — the Android
  download client must reuse the same shared `OkHttpClient` so refresh, Bearer,
  cookies, and CSRF apply to byte transfers too.

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
1. Resolve metadata (`FileEntry` already in browse cache, or `GET /v1/fs/info?path=<path>`)
   to get `name` (displayName), `content_type` (mimeType), `size`, and
   `updated_at`. NOTE: `FileEntry` has **no `etag`/`version` field**; the cache
   key derives from `path` + `updated_at` (see §6 correction). Files are
   identified by their `path` string, not an opaque `fileId`.
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

Route **verified** against OpenAPI and the web client. CORRECTION: the prior
draft assumed `GET /ui/files/{file_id}/download`; the actual backend route is
`GET /v1/fs/download` with a required `path` **query** parameter.

**Streamed download (primary, VERIFIED route/method/param):**

```
GET /v1/fs/download?path=<url-encoded file path>
Headers: Authorization: Bearer <accessToken>; Cookie: <session>;
         X-CSRF-Token: <ui_csrf>
         (alternatively X-API-Key: <key> — UI uses Bearer+cookie)
         Range: bytes=<offset>-            (ASSUMPTION — see OQ-2; not in OpenAPI)
→ 200 OK
   Content-Type: <file mime, e.g. application/pdf>   (ASSUMPTION; OpenAPI
                  declares application/json for 200 — verify at integration)
   Content-Length: 1048576                  (ASSUMPTION — may be absent)
   Accept-Ranges: bytes                     (ASSUMPTION — not documented)
   Content-Disposition: attachment; filename="report.pdf"  (ASSUMPTION)
   <binary body stream>
```

There is **NO presigned-redirect (302) download path** in the file API
(verified: presign exists only for *upload*, `fsPresignUpload`). The previous
302/S3 design has been removed. `followRedirects` may stay enabled defensively
but no cross-host auth-drop handling is required for the documented contract.

**Web client behavior (VERIFIED, `FilesPage.tsx: performDownload`):** the web
app does `fetch("/v1/fs/download?path=...", { credentials: "include" })`, buffers
the **entire body to a Blob**, and for `FileEntry.is_encrypted == true` decrypts
client-side before saving. The web app does NOT chunk/stream progress and does
NOT use `Range`. Android's streamed/progress/resume design is an Android-side
enhancement, not a mirror of web — call this out so reviewers don't expect
parity. **Encrypted files are unaddressed by this spec** (see OQ-4).

**Retrofit signature (added to AND-331's `FilesApi`, CORRECTED):**

```kotlin
@Streaming
@GET("v1/fs/download")
suspend fun downloadFile(
    @Query("path") path: String,
    @Header("Range") range: String? = null,   // sent only if server honors ranges
): Response<ResponseBody>
```

`@Streaming` is mandatory so Retrofit does not buffer the whole body. The path
identifier is a **filesystem path string**, not an opaque id.

**Error bodies (CORRECTED to documented shapes):** OpenAPI documents `400`,
`401`, `403`, `422`, `429` for this route — **no 404 and no 5xx are documented**.
Detail is the object form `{ "detail": { "code", "reason", ... } }` (e.g. `403`
→ `code: api_key_scope_denied, required_scopes: ["filemanager:read"]`; `429`
→ `code: api_limit_exceeded`; `400` → `code: api_key_dual_credential_conflict`).
A missing/invalid path most likely returns `422 HTTPValidationError`
(`detail: [{msg,...}]`) or `400`, NOT `404` — map "not found / no access" from
`403`/`422`/`400` rather than `404`. `401` → refresh+retry once via authenticator;
`429` is retryable with backoff (honor `Retry-After` if present); transport
`IOException`/timeout treated as retryable (even though 5xx is undocumented,
the flaky dev host can still produce them).

Filename/MIME resolution precedence: `Content-Disposition` filename (if present —
ASSUMPTION) → `FileEntry.name` from AND-331 → last path segment; MIME: response
`Content-Type` → `FileEntry.content_type` → `MimeTypeMap` from extension →
`application/octet-stream`.

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

Cache key = `path` + a version token. CORRECTION: `FileEntry` exposes **no
`etag`** field, so the version token is derived from `updated_at` (and `size` as
a tiebreaker); a stable server `ETag` is an unverified assumption (OQ-2). A
changed `updated_at` invalidates the old cached blob (deleted on next eviction
pass / on overwrite). (The `fileId`/`version` naming in §4.2's `CachedFile` is
retained for code shape but is populated from `path`/`updated_at`.)

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

- **OQ-1 (RESOLVED):** Download route is `GET /v1/fs/download?path=<path>`
  (verified in OpenAPI + `files.ts: downloadUrl`). There is **no** 302/presigned
  download path; the body is returned directly. Remaining unknown: whether the
  live server sets a binary `Content-Type` (OpenAPI declares `application/json`
  for 200) and a `Content-Disposition` filename — verify at integration.
- **OQ-2:** Does the server send `Accept-Ranges: bytes` and a stable `ETag`/
  checksum? Determines resumability (FR-7) and integrity validation. If absent,
  downloads restart on retry.
- **OQ-3:** Is there a server-side max file size / does the dev host reliably
  send `Content-Length`? Drives determinate-vs-indeterminate progress and the
  256 MB cache bound default.
- **OQ-4 (NEW, from review):** The web client decrypts files where
  `FileEntry.is_encrypted` is true **client-side** after download
  (`FilesPage.tsx`, with `enc_metadata`/`FileEncryptionMetadata`). This spec does
  NOT cover client-side decryption. Decide whether Android must (a) refuse to
  open encrypted files for now, (b) reach decryption parity, or (c) defer to a
  follow-up ticket. Until resolved, opening an encrypted blob would hand the
  external app ciphertext.
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
- ktlint/detekt clean; PR reviewed and merged to `android-port`; OQ-1–OQ-4
  resolved against the live backend or filed as follow-ups with safe defaults.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer.

1. **Download route is `GET /v1/fs/download` with a required `path` query param.**
   VERDICT: Corrected (spec said `GET /ui/files/{file_id}/download`).
   SOURCE: OpenAPI `GET /v1/fs/download` (op `download_fs_file_v1_fs_download_get`,
   `params=path,X-API-Key`); `src/api/endpoints/files.ts: downloadUrl`.
2. **HTTP method is GET and the body is returned directly (no 302/presigned
   redirect).** VERDICT: Corrected (spec offered a 302→S3 presigned variant).
   SOURCE: OpenAPI `GET /v1/fs/download` (single 200 response, no redirect);
   presign exists only for upload — `src/api/endpoints/files.ts: fsPresignUpload`.
3. **File identifier is a path string, not an opaque `fileId`.**
   VERDICT: Corrected. SOURCE: `src/api/types.ts: FileEntry` (has `path`, `name`,
   `type`, `size`, `content_type`, `updated_at`; no `id`); OpenAPI `path` param.
4. **DTO is `FileEntry` (not `FileDto`/`FileDownloadDto`); metadata via
   `GET /v1/fs/info?path=`.** VERDICT: Corrected. SOURCE: `src/api/types.ts:
   FileEntry`, `FileListResp`; `src/api/endpoints/files.ts: getFileInfo`
   (`/v1/fs/info`); OpenAPI `GET /v1/fs/info`.
5. **Web reference exports `downloadUrl(path)`, not `getDownloadUrl`/`downloadFile`.**
   VERDICT: Corrected. SOURCE: `src/api/endpoints/files.ts: downloadUrl`
   (grep for `getDownloadUrl`/`downloadFile` in `src/api/` returns nothing).
6. **Auth is `Authorization: Bearer <accessToken>` + `X-CSRF-Token` (from
   `ui_csrf` cookie) + cookies (`credentials: include`); `X-API-Key` is an
   accepted alternative.** VERDICT: Corrected (spec said cookie-only; missed
   Bearer). SOURCE: `src/api/client.ts` (sets `Authorization: Bearer`, reads
   `ui_csrf` → `X-CSRF-Token`, `credentials: "include"`); OpenAPI `X-API-Key`
   header param on the route.
7. **CSRF: `ui_csrf` cookie echoed as `X-CSRF-Token` header.** VERDICT: Verified.
   SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`).
8. **On 401 the client refreshes once via `POST /ui/session/refresh`, then
   retries; on refresh failure it logs out.** VERDICT: Verified.
   SOURCE: `src/api/client.ts: refreshSession`/401 branch;
   `src/api/endpoints/auth.ts: refreshSession` (`POST /ui/session/refresh`).
9. **Documented error statuses are 400/401/403/422/429; NO 404 and NO 5xx are
   documented.** VERDICT: Corrected (spec mapped a `404` not-found and `5xx`).
   SOURCE: OpenAPI `GET /v1/fs/download` (`resp=200;422:HTTPValidationError;400;401;403;429`).
10. **Error detail uses object form `{detail:{code,reason,...}}` (e.g. 403
    `api_key_scope_denied` + `required_scopes:["filemanager:read"]`, 429
    `api_limit_exceeded`, 400 `api_key_dual_credential_conflict`); validation
    errors use `HTTPValidationError` (`detail:[{msg,...}]`).** VERDICT: Verified.
    SOURCE: OpenAPI `GET /v1/fs/download` response examples;
    `src/api/client.ts: normalizeErrorDetail` (handles string | `[{msg}]` | `{code}`).
11. **Web client buffers the full body to a Blob and triggers `<a download>`; it
    does not stream progress or use `Range`.** VERDICT: Verified.
    SOURCE: `src/pages/files/FilesPage.tsx: performDownload`
    (`fetch(downloadUrl,{credentials:"include"})` → `resp.blob()` → anchor click).
12. **Encrypted files (`FileEntry.is_encrypted`) are decrypted client-side by the
    web app.** VERDICT: Verified (and unhandled by this spec — see OQ-4).
    SOURCE: `src/pages/files/FilesPage.tsx: performDownload`;
    `src/api/types.ts: FileEntry.is_encrypted`/`enc_metadata`/`FileEncryptionMetadata`.
13. **`Range`/`Accept-Ranges`/`Content-Disposition`/`Content-Length` support and
    a binary `Content-Type` on the download response.** VERDICT:
    Unverified-assumption (OpenAPI 200 declares only `application/json` content
    and specifies no response headers; web client never uses ranges).
    SOURCE: OpenAPI `GET /v1/fs/download` 200 (no headers/`application/octet-stream`).
14. **Stable server `ETag`/checksum usable as a cache-version token.** VERDICT:
    Unverified-assumption — `FileEntry` exposes no `etag`; version derived from
    `updated_at`. SOURCE: `src/api/types.ts: FileEntry`.
15. **`FileProvider` content-URI sharing with `FLAG_GRANT_READ_URI_PERMISSION`;
    raw `file://` URIs throw `FileUriExposedException`.** VERDICT: Verified
    (framework). SOURCE (framework ref):
    https://developer.android.com/reference/androidx/core/content/FileProvider ,
    https://developer.android.com/reference/android/os/FileUriExposedException .
16. **`Intent.ACTION_VIEW`/`Intent.createChooser` open-with; `ACTION_SEND`
    fallback.** VERDICT: Verified (framework). SOURCE (framework ref):
    https://developer.android.com/training/sharing/send ,
    https://developer.android.com/reference/android/content/Intent#ACTION_VIEW .
17. **Public "Save to Downloads" via MediaStore on Android 10+ needs no storage
    permission; `WRITE_EXTERNAL_STORAGE` only on API ≤ 28.** VERDICT: Verified
    (framework). SOURCE (framework ref):
    https://developer.android.com/training/data-storage/shared/media .
18. **OkHttp `@Streaming` + `ResponseBody.source()` streaming and per-call
    timeout override.** VERDICT: Verified (framework). SOURCE (framework ref):
    https://square.github.io/retrofit/2.x/retrofit/retrofit2/http/Streaming.html ,
    https://square.github.io/okhttp/recipes/#timeouts-kt-java .

### Corrections made

- §2, §5, Retrofit signature: route corrected from `GET /ui/files/{file_id}/download`
  to `GET /v1/fs/download?path=<path>` (query param; `@Query("path")`).
- §2/§5: removed the 302/presigned-S3 download variant (no such path; presign is
  upload-only).
- §2/§4.2/§5/§6: `FileDto`/`FileDownloadDto` → `FileEntry`; identifier `fileId` →
  `path`; metadata fetch `GET /ui/files/{id}` → `GET /v1/fs/info?path=`.
- §2: web export names corrected (`getDownloadUrl`/`downloadFile` →
  `downloadUrl`); web download behavior documented (Blob buffer, not streamed).
- §2: auth corrected to include `Authorization: Bearer` (plus cookie + CSRF) and
  the `X-API-Key` alternative.
- §5: error mapping corrected to documented statuses (400/401/403/422/429); the
  non-existent `404`/`5xx` mappings reframed — treat not-found/no-access as
  403/422/400 and keep transport timeout/IOException as retryable.
- §6: cache version token derived from `updated_at` (no `etag` field exists).
- §13: OQ-1 marked resolved; OQ-4 (client-side decryption gap) added.

### Open assumptions

- Response headers `Content-Length`, `Content-Disposition`, `Accept-Ranges`, and
  a binary `Content-Type` are assumed but NOT in the OpenAPI (200 declares
  `application/json`, no headers). Why unverifiable: only resolvable by hitting
  the live dev host with a real file; the static spec does not describe them.
- `Range`/206 resumability (FR-7) is unverified for the same reason; if the
  server ignores `Range`, downloads restart from 0.
- A stable `ETag`/checksum for integrity + cache versioning is unverified;
  `FileEntry` has none, so `updated_at` is the fallback version token.
- 5xx handling: server 5xx is undocumented for this route but retained as a
  retryable case because the flaky plaintext dev host can still emit transport
  failures/timeouts.
- Client-side decryption of `is_encrypted` files (OQ-4) is out of scope here;
  behavior for encrypted files is an open product decision.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **emu35** =
headless emulator AVD `test35` (x86_64, Android 15/API 35); **deviceA15** =
physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a, serial
R5CX821TA9R). Most cases here are device-agnostic; the few requiring real
open-with app resolution / OEM chooser behavior are flagged for **deviceA15**.

- **TC-AND-334-01** — Happy-path streamed download → cache → Success.
  Type: contract/MockWebServer. Target: JVM. Preconditions: MockWebServer serves
  a known binary body for `GET /v1/fs/download?path=/docs/report.pdf` with
  `Content-Type: application/pdf` and `Content-Length`. Steps: collect
  `repo.download("/docs/report.pdf")`. Expected: emits `InProgress` then
  `Success(CachedFile)` with `mimeType=application/pdf`, `sizeBytes` == body
  length, `displayName` resolved (Content-Disposition → name → last segment), and
  bytes on disk equal the served body. Verify the request used `@Query("path")`
  (URL `/v1/fs/download?path=%2Fdocs%2Freport.pdf`) and carried
  `Authorization: Bearer`, `X-CSRF-Token`, cookie. Traces: AC-1, AC-9.

- **TC-AND-334-02** — Indeterminate progress when `Content-Length` absent.
  Type: contract/MockWebServer. Target: JVM. Preconditions: server omits
  `Content-Length`. Steps: collect the flow. Expected: `InProgress.totalBytes ==
  null` and `fraction == null` throughout; final `Success` with correct on-disk
  size. Traces: AC-1.

- **TC-AND-334-03** — Cache hit performs no network request (incl. offline).
  Type: contract/MockWebServer + unit. Target: JVM. Preconditions: file already
  cached for current version token (`path` + `updated_at`); MockWebServer enqueues
  NO response (or connectivity reports offline). Steps: call `repo.cached(path)`
  then `repo.download(path)`. Expected: immediate `Success` from cache;
  `mockWebServer.requestCount` unchanged (zero new requests). Traces: AC-3, AC-6.

- **TC-AND-334-04** — Offline with no cache → retryable error.
  Type: unit. Target: JVM. Preconditions: connectivity offline, file not cached.
  Steps: collect the flow. Expected: `Error(retryable=true)` with "You're offline"
  message; no `.part` left behind. Traces: AC-3, AC-5.

- **TC-AND-334-05** — Auth/error mapping for documented statuses.
  Type: contract/MockWebServer. Target: JVM. Preconditions: server returns each
  of 403 (`{detail:{code:"api_key_scope_denied",required_scopes:["filemanager:read"]}}`),
  422 (`HTTPValidationError` `{detail:[{msg,...}]}`), 400, 429
  (`{detail:{code:"api_limit_exceeded"}}`). Steps: collect per case. Expected:
  403/422/400 → `Error(retryable=false)` with a normalized message (object
  `code`/`msg` parsed like `normalizeErrorDetail`); 429 → `Error(retryable=true)`,
  honoring `Retry-After` when present. NO assumption of a 404 path. Traces: AC-5.

- **TC-AND-334-06** — 401 triggers exactly one `/ui/session/refresh` + retry.
  Type: contract/MockWebServer. Target: JVM. Preconditions: download returns 401
  once; `POST /ui/session/refresh` returns 200 (`StatusResp`); retried download
  returns 200 body. Steps: collect the flow through the shared OkHttp
  authenticator. Expected: exactly one refresh call, one download retry, terminal
  `Success`; if refresh returns non-2xx → `Error(retryable=false)` and re-auth
  routing, with NO second refresh attempt. Traces: AC-5.

- **TC-AND-334-07** — Resume from `.part` via `Range` (when server is resumable).
  Type: contract/MockWebServer. Target: JVM. Preconditions: server advertises
  `Accept-Ranges: bytes`; first attempt is cut off mid-body, leaving `<id>.part`;
  retry sends `Range: bytes=<offset>-` and server replies `206 Partial Content`.
  Steps: simulate interruption then retry. Expected: `.part` reused (request
  carried correct `Range`), appended bytes complete the file, final bytes equal
  the full reference. Marked ASSUMPTION-dependent (OQ-2): if server lacks
  `Accept-Ranges`, a sibling assertion verifies restart-from-0. Traces: AC-4.

- **TC-AND-334-08** — Cancellation tears down the call and cleans up.
  Type: unit/coroutines. Target: JVM. Preconditions: a slow MockWebServer body.
  Steps: cancel the collecting scope mid-stream. Expected: `Cancelled` emitted,
  the HTTP call is cancelled, and `.part` is deleted when non-resumable / retained
  when resumable (per FR-7). Traces: AC-4.

- **TC-AND-334-09** — Integrity: Content-Length mismatch → retryable error.
  Type: contract/MockWebServer. Target: JVM. Preconditions: server declares
  `Content-Length: N` but sends fewer bytes. Steps: collect the flow. Expected:
  `Error(retryable=true)`, partial blob discarded, final cache unchanged.
  Traces: AC-1, AC-5.

- **TC-AND-334-10** — LRU eviction respects 256 MB bound and skips in-use entry.
  Type: unit. Target: JVM. Preconditions: cache pre-populated past the bound;
  one entry flagged as actively-open. Steps: trigger an eviction pass; also store
  a new version of an existing `path`. Expected: total ≤ 256 MB after eviction,
  least-recently-accessed evicted first, the in-use entry is never deleted, and a
  changed `updated_at` invalidates the stale blob. Traces: AC-6.

- **TC-AND-334-11** — FileProvider content URI + ACTION_VIEW grant (no `file://`).
  Type: instrumented. Target: emu35 (device-agnostic; runs on deviceA15 too).
  Preconditions: a cached file under `cacheDir/files/`. Steps: build the open
  intent via `OpenWithLauncher`; capture with Espresso-Intents (`Intents.intended`)
  without launching a real app. Expected: data URI is a `content://
  com.testlogon.android.fileprovider/...` URI (NOT `file://`), type == the file's
  MIME, and `FLAG_GRANT_READ_URI_PERMISSION` is set; no `FileUriExposedException`.
  Traces: AC-2, AC-8.

- **TC-AND-334-12** — Real open-with resolution / chooser + no-app fallback.
  Type: instrumented/e2e (manual confirmation of chooser UI). Target:
  **deviceA15 (MUST)** — needs real installed handler apps and OEM chooser
  behavior the emulator lacks. Preconditions: a PDF cached (a real viewer
  installed) and a file with an unhandleable MIME. Steps: open each. Expected:
  PDF resolves to an external viewer via chooser; unhandleable MIME shows the
  `ACTION_SEND` fallback / "No app can open this file" message; `Success` is still
  emitted in the no-app case. Traces: AC-2.

- **TC-AND-334-13** — "Save to Downloads" via MediaStore is readable back.
  Type: instrumented. Target: emu35 for API 35 path; **deviceA15 (MUST)** for the
  API ≤ 28 `WRITE_EXTERNAL_STORAGE` runtime-permission branch and the API-34
  MediaStore behavior. Preconditions: a cached file. Steps: invoke
  `saveToDownloads(path)`; re-open the MediaStore `Downloads` URI. Expected: file
  appears in public `Downloads` and its bytes read back equal the cached blob; on
  API ≤ 28, the permission request is exercised. Traces: AC-7.

- **TC-AND-334-14** — Secret redaction in logs/analytics.
  Type: unit. Target: JVM. Preconditions: a fake logger/analytics sink; a download
  carrying cookie + `X-CSRF-Token` + Bearer. Steps: run a download lifecycle and
  an error case; capture all emitted log lines and analytics payloads. Expected:
  no cookie, CSRF token, Bearer token, or any URL query (the `path` carries no
  secret, but presigned URLs—if ever introduced—must not log); analytics use a
  hashed `fileId` and no filenames; no raw bytes. Traces: AC-8.

- **TC-AND-334-15** — Compose UI state rendering + Cancel wiring + a11y.
  Type: Compose-UI. Target: emu35. Preconditions: `FileActionsViewModel` driven
  through `Idle → InProgress(determinate) → InProgress(indeterminate) →
  Success / Error / Cancelled`. Steps: render each state; tap Cancel. Expected:
  determinate `LinearProgressIndicator` exposes `progressBarRangeInfo` semantics
  and a "Downloading <name>, NN percent" contentDescription; indeterminate when
  `fraction==null`; Cancel invokes `viewModel.cancel()`; controls have
  contentDescriptions and ≥ 48 dp targets; terminal states announced via
  Snackbar/live region. Traces: AC-1, AC-4, plus §9 accessibility.

### Coverage matrix (section-14 acceptance criteria → test cases)

| AC | Covered by |
|----|------------|
| AC-1 (progress determinate/indeterminate to cache) | TC-01, TC-02, TC-09, TC-15 |
| AC-2 (open-with via FileProvider/ACTION_VIEW + chooser/SEND fallback) | TC-11, TC-12 |
| AC-3 (second open = no network, incl. offline) | TC-03, TC-04 |
| AC-4 (cancellation cleanup / resume retention) | TC-07, TC-08, TC-15 |
| AC-5 (error mapping: 403/422/400 non-retryable, 429/timeout retryable, one 401 refresh) | TC-04, TC-05, TC-06, TC-09 |
| AC-6 (256 MB LRU bound, no delete of in-use, version invalidation) | TC-03, TC-10 |
| AC-7 ("Save to Downloads" via MediaStore, readable) | TC-13 |
| AC-8 (no `file://`; secrets never logged/analytics) | TC-11, TC-14 |
| AC-9 (unit + instrumented incl. e2e download→cache→open-with) | TC-01, TC-03, TC-11 |
