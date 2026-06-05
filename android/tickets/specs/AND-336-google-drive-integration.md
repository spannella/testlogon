---
id: AND-336
title: Google Drive integration
milestone: M7
epic: E43
priority: P2
size: M
status: draft
depends_on: [AND-331]
blocks: []
---

# AND-336 — Google Drive integration

## 1. Overview & Goal

Add an optional "Import from Google Drive" capability to the TestLogon native
Android app. The user authorizes a read-only Google Drive scope via the system
account / Credential Manager flow, picks a file with the Google Drive picker (or
an in-app file list backed by the Drive REST API), downloads the bytes, and
uploads them into the TestLogon backend through the existing Files API surface
established in AND-331 (`files.ts` parity: browse/CRUD/search DTOs).

This ticket is the Android counterpart of the web reference module
`frontend/src/api/endpoints/googleDrive.ts`, which performs OAuth + import. On
Android we do **not** reimplement OAuth from scratch; we use Google Identity
Services (Credential Manager + `AuthorizationClient` from
`play-services-auth`) to obtain an OAuth 2.0 access token for the Drive scope,
then call the public Google Drive v3 REST API directly with Retrofit.

Goal: a user on the Files screen can tap "Import from Drive", complete the
Google authorization consent, select one Drive file, and see that file appear in
their TestLogon file list. Success is defined by the acceptance bullet:
**Connect + import a Drive file.**

Non-goals: bidirectional sync, exporting TestLogon files back to Drive, folder
tree import, Google Docs/Sheets native-format conversion beyond a single
export-MIME mapping, and offline queueing of imports. Those are explicitly out
of scope for AND-336.

## 2. Context & References

- Web reference: `frontend/src/api/endpoints/googleDrive.ts` (OAuth + import),
  `frontend/src/api/endpoints/files.ts`, shared types `frontend/src/api/types.ts`.
- Backend: FastAPI + DynamoDB; OpenAPI at `/openapi.json`; dev host
  `http://18.222.237.167:8000` (plaintext, unreliable — ~20s timeouts, bounded
  retry for idempotent GETs only).
- Upstream dependency **AND-331 — Files API + DTOs**: provides
  `FilesApi` (Retrofit), `FileDto`/`FileUploadRequest` Moshi models, and
  `FilesRepository`. AND-336 consumes the upload path of that repository and
  MUST NOT redefine file DTOs.
- Auth note: TestLogon's own session is cookie-based (`/ui/session/*`,
  `X-CSRF-Token`). Google Drive auth is **entirely separate** — a Google OAuth
  bearer token used only against `https://www.googleapis.com`. The two auth
  systems share no cookie jar, no interceptor, and no token store.
- Module layering: `app -> feature-files -> core-*`. New code lands in a thin
  `feature-files` sub-package plus a `core-network` Retrofit service for Google.
- Stack: Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow,
  Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, minSdk 24, targetSdk 35.

Libraries added by this ticket:
`androidx.credentials:credentials:1.3.0`,
`androidx.credentials:credentials-play-services-auth:1.3.0`,
`com.google.android.gms:play-services-auth:21.2.0` (provides
`AuthorizationClient` / `AuthorizationRequest`),
`com.google.android.libraries.identity.googleid:googleid:1.1.1`.

## 3. Functional Requirements

FR-1. A "Import from Google Drive" affordance is present on the Files screen
(an entry in the add/import menu). It is hidden when Google Play Services is
unavailable (`GoogleApiAvailability.isGooglePlayServicesAvailable != SUCCESS`).

FR-2. Tapping the affordance starts the authorization flow requesting the scope
`https://www.googleapis.com/auth/drive.readonly`. If the user has not previously
granted consent, the system consent UI is shown. On success the app holds a
short-lived access token (in memory only).

FR-3. After authorization, the user is presented a list of their Drive files
(name, MIME type, size, modified time), fetched via Drive `files.list`. The list
supports a search query (`q` parameter) and forward pagination via
`nextPageToken` (Paging 3).

FR-4. Selecting a file downloads its content (`files.get?alt=media` for binary
files; `files.export` for Google-native MIME types) and uploads it to TestLogon
through `FilesRepository.upload(...)` from AND-331.

FR-5. On import success the TestLogon Files list refreshes and the imported file
is visible. The import sheet dismisses with a success snackbar showing the file
name.

FR-6. The user can cancel at any stage (consent, list, download/upload). Cancel
leaves no partial TestLogon file.

FR-7. A single Drive file per invocation (multi-select is out of scope).

## 4. Technical Design

New package `com.testlogon.android.feature.files.drive`.

Authorization wrapper (Credential Manager + AuthorizationClient):

```kotlin
class GoogleDriveAuthClient @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    private val authClient = Identity.getAuthorizationClient(context)

    /** Returns a valid access token, launching consent UI via [launcher] if needed. */
    suspend fun authorize(
        launcher: (IntentSenderRequest) -> Unit,
    ): DriveAuthState

    /** Completes the flow after the consent Activity result. */
    fun onAuthorizationResult(result: ActivityResult): String? // access token or null
}

sealed interface DriveAuthState {
    data class Authorized(val accessToken: String) : DriveAuthState
    data class NeedsConsent(val pendingIntent: PendingIntent) : DriveAuthState
    data class Failed(val cause: Throwable) : DriveAuthState
}
```

`AuthorizationRequest.builder().setRequestedScopes(listOf(Scope(DRIVE_READONLY)))`
is used; the resulting `AuthorizationResult.accessToken` is the bearer token.
The token lives only in `DriveImportViewModel` state — never persisted to
DataStore/Room.

Google Drive Retrofit service (in `core-network`, distinct base URL):

```kotlin
interface GoogleDriveApi {
    @GET("drive/v3/files")
    suspend fun listFiles(
        @Header("Authorization") bearer: String,
        @Query("q") query: String?,
        @Query("pageToken") pageToken: String?,
        @Query("pageSize") pageSize: Int = 50,
        @Query("fields") fields: String =
            "nextPageToken,files(id,name,mimeType,size,modifiedTime)",
        @Query("spaces") spaces: String = "drive",
    ): DriveFileList

    @Streaming
    @GET("drive/v3/files/{id}")
    suspend fun download(
        @Header("Authorization") bearer: String,
        @Path("id") fileId: String,
        @Query("alt") alt: String = "media",
    ): ResponseBody

    @Streaming
    @GET("drive/v3/files/{id}/export")
    suspend fun export(
        @Header("Authorization") bearer: String,
        @Path("id") fileId: String,
        @Query("mimeType") exportMime: String,
    ): ResponseBody
}
```

Hilt provides this with `@Named("googleDrive")` Retrofit, base URL
`https://www.googleapis.com/`, its own `OkHttpClient` (TestLogon's
cookie-jar / CSRF / session-refresh interceptors are explicitly NOT installed).

Repository orchestrating import:

```kotlin
class GoogleDriveRepository @Inject constructor(
    private val api: GoogleDriveApi,
    private val filesRepository: FilesRepository, // from AND-331
) {
    fun pager(token: String, query: String?): Flow<PagingData<DriveFile>>

    suspend fun import(
        token: String,
        file: DriveFile,
        targetFolderId: String?,
    ): ApiResult<FileDto>
}
```

`import` streams the Drive `ResponseBody` to a temp file in `cacheDir`, then
hands a `FileUploadRequest` (multipart) to `filesRepository.upload`. The temp
file is deleted in a `finally` block. For Google-native MIME types it picks an
export MIME via `GOOGLE_EXPORT_MAP` (e.g.
`application/vnd.google-apps.document -> application/pdf`,
`application/vnd.google-apps.spreadsheet -> text/csv`); unsupported native types
surface a typed error rather than uploading garbage.

UI: `DriveImportSheet` (Material 3 `ModalBottomSheet`) driven by
`DriveImportViewModel : ViewModel` exposing `StateFlow<DriveImportUiState>`.
The list uses `collectAsLazyPagingItems()`. The consent step is launched via
`rememberLauncherForActivityResult(StartIntentSenderForResult)`.

```kotlin
sealed interface DriveImportUiState {
    data object NotConnected : DriveImportUiState
    data object Connecting : DriveImportUiState
    data class Browsing(val query: String, val importing: String?) : DriveImportUiState
    data class Error(val message: String) : DriveImportUiState
}
```

## 5. API Contract

Two external surfaces.

(a) Google Drive v3 (consumed). `GET /drive/v3/files` response:

```json
{
  "nextPageToken": "~!!~AI9...",
  "files": [
    { "id": "1AbC...", "name": "report.pdf",
      "mimeType": "application/pdf", "size": "20481",
      "modifiedTime": "2026-05-30T12:01:02.000Z" }
  ]
}
```

```kotlin
@JsonClass(generateAdapter = true)
data class DriveFileList(
    @Json(name = "nextPageToken") val nextPageToken: String?,
    @Json(name = "files") val files: List<DriveFile>,
)

@JsonClass(generateAdapter = true)
data class DriveFile(
    val id: String,
    val name: String,
    val mimeType: String,
    val size: String? = null,           // bytes as string; absent for native docs
    val modifiedTime: String? = null,   // RFC3339
)
```

`GET /drive/v3/files/{id}?alt=media` and
`GET /drive/v3/files/{id}/export?mimeType=...` return raw bytes
(`@Streaming ResponseBody`). Google errors are JSON
`{"error":{"code":401,"message":"...","status":"UNAUTHENTICATED"}}` — mapped to
`ApiResult.Error` (see §7).

(b) TestLogon Files upload (consumed, owned by **AND-331**). This ticket does
not define the request/response shape; it calls `FilesRepository.upload(
FileUploadRequest(name, bytes/uri, mimeType, folderId))` and consumes the
returned `FileDto`. The FastAPI `detail` error mapping (string | `[{msg}]` |
`{code,...}`) is handled inside AND-331's repository and reused unchanged.

## 6. Data & State Management

- Google access token: in-memory only (`DriveImportViewModel`). Not stored in
  Room or DataStore. Lost on process death (re-authorize is cheap/silent if
  consent already granted).
- A single DataStore boolean preference `drive_import_seen` (under existing
  `core-data` prefs) records whether the user has used the feature, used only to
  decide first-run copy. No tokens, no file metadata persisted.
- Drive file listing is not cached in Room — it is fetched live via Paging 3
  `RemoteMediator`-free `PagingSource` keyed on `nextPageToken`. Rationale: Drive
  contents are remote-of-record and listing must reflect the live account.
- The imported TestLogon file is persisted by AND-331's Files Room cache; AND-336
  triggers `filesRepository.refresh()` after a successful import so the cached
  list updates.
- Temp download bytes live in `context.cacheDir/drive-import/`; deleted after
  upload (success or failure) and on ViewModel `onCleared`.

## 7. Error Handling & Resilience

- Auth errors: `NeedsConsent` -> launch consent; user denial -> `NotConnected`
  with a non-blocking message. Token 401 from Drive during list/download ->
  invalidate cached token, re-run `authorize`, retry the request once.
- Network: the Drive `OkHttpClient` uses a 20s call timeout consistent with the
  unreliable-dev posture. `files.list` (idempotent GET) gets bounded retry
  (max 2, exponential backoff with jitter, base 500ms) via an interceptor.
  Downloads are streamed and NOT auto-retried (avoid duplicate partials); a
  failed download offers a manual "Retry".
- Upload failures bubble up AND-331's `ApiResult.Error` and show its message;
  the temp file is still cleaned up.
- Mapping helper:

```kotlin
fun Throwable.toDriveError(): String = when (this) {
    is HttpException -> when (code()) {
        401, 403 -> "Google sign-in expired. Tap to reconnect."
        429      -> "Google Drive is rate-limiting. Try again shortly."
        in 500..599 -> "Google Drive is unavailable. Try again."
        else     -> "Couldn't reach Google Drive (${code()})."
    }
    is IOException -> "Network problem reaching Google Drive."
    else          -> "Import failed."
}
```

- Cancellation is cooperative (`CancellationException` propagated); partial temp
  files are removed in `finally`.

## 8. Security & Privacy

- Scope is least-privilege read-only (`drive.readonly`). No write/append scope.
- Access token never written to disk, logs, crash reports, or Room/DataStore;
  redacted in any logging interceptor via a header-redaction rule on
  `Authorization`.
- Drive traffic is HTTPS to `googleapis.com` (TLS enforced; cleartext not
  permitted for this host even though the TestLogon dev host is cleartext —
  network security config scopes cleartext to `18.222.237.167` only).
- The TestLogon session cookie jar and `X-CSRF-Token` are NOT attached to Google
  requests (separate OkHttpClient), preventing cookie/CSRF leakage cross-origin.
- OAuth client ID (Web client ID for `AuthorizationRequest`) is a public
  identifier and may live in resources/BuildConfig; no client secret ships in
  the app.
- Consent screen and requested scope are surfaced to the user by Google; the app
  shows a one-line rationale before launching consent.

## 9. Accessibility & i18n

- All new strings in `res/values/strings.xml` (`drive_import_action`,
  `drive_import_connect`, `drive_import_searching`, `drive_import_success`,
  `drive_import_error_*`). Success snackbar uses a formatted resource with the
  file name placeholder.
- `DriveImportSheet` list rows expose `contentDescription` combining file name,
  type, and size; file-type icons are decorative (`null` description).
- Min touch target 48dp for list rows and the import button; the bottom sheet is
  keyboard/TalkBack focusable and supports drag + accessible dismiss.
- Sizes/dates formatted with `android.text.format.Formatter.formatShortFileSize`
  and locale-aware `DateUtils`; no hard-coded date formats.
- Color is not the sole status indicator (importing state shows a spinner +
  text).

## 10. Telemetry & Logging

- Analytics events via existing `core-data` analytics facade:
  `drive_import_started`, `drive_consent_granted`, `drive_consent_denied`,
  `drive_file_selected` (props: `mimeType`, size bucket), `drive_import_success`
  (prop: duration ms), `drive_import_failure` (prop: reason category, no PII).
- File names and tokens are NOT included in any event.
- Debug-only `Timber` logs around state transitions; `Authorization` header
  redacted. No verbose logging in release builds.

## 11. Testing Strategy

Unit (JVM, `core-testing` + MockWebServer):
- `GoogleDriveApi` deserialization: `DriveFileList` maps `nextPageToken` and all
  `DriveFile` fields, including absent `size` for native docs.
- `GoogleDriveRepository.import` happy path: streams MockWebServer body to temp
  file, invokes a fake `FilesRepository.upload`, returns `ApiResult.Success`,
  and deletes the temp file (assert cacheDir empty).
- Export-MIME mapping: native doc -> `export` call with correct `mimeType`;
  unsupported native type -> typed error, no upload.
- 401 on list triggers re-authorize + single retry; second 401 surfaces error.
- `toDriveError` covers 401/403/429/5xx/IOException/other.

ViewModel: `DriveImportViewModel` state machine
(`NotConnected -> Connecting -> Browsing -> Browsing(importing) -> success`),
using `kotlinx-coroutines-test` and a fake auth client.

Instrumented/UI (Compose test): sheet renders paged list from a fake
`PagingSource`; tapping a row shows importing spinner; success dismisses sheet
and emits snackbar. Consent launcher is faked.

Acceptance verification ("Connect + import a Drive file"): an instrumented test
with a stubbed `GoogleDriveApi` (MockWebServer) and stubbed Files upload proves
the end-to-end path produces a `FileDto` and refreshes the Files list. A manual
QA pass against a real Google account on the dev backend confirms the live flow.

## 12. Dependencies & Sequencing

- Hard dependency: **AND-331 — Files API + DTOs** (P0). `FilesRepository.upload`,
  `FileDto`, and `FileUploadRequest` must exist and be tested before AND-336's
  import path can be wired. This ticket consumes them and adds no Files DTOs.
- Indirect: AND-027 (HTTP/session core) via AND-331; not directly touched here
  since Google uses a separate client.
- Gradle: add Credential Manager + play-services-auth + googleid dependencies;
  register the Web OAuth client ID; update network security config to keep
  cleartext scoped to the dev host only.
- Sequencing: implement `GoogleDriveApi` + DTOs + repository first (unit
  testable without UI), then `GoogleDriveAuthClient`, then the
  `DriveImportSheet`/ViewModel and Files-screen entry point.
- Blocks: nothing in the provided backlog (`blocks: []`).

## 13. Risks & Open Questions

- R1: `play-services-auth` `AuthorizationClient` requires Play Services; on
  devices without it (some emulators, AOSP) the feature is hidden (FR-1). Accept.
- R2: Google-native doc conversion is lossy; the `GOOGLE_EXPORT_MAP` is a fixed
  policy. OPEN: confirm the desired default export MIME per native type with
  product (PDF for Docs, CSV for Sheets assumed).
- R3: Drive download size — large files streamed to cacheDir could exhaust
  storage. Mitigation: enforce a size cap (e.g. reject `size` > 100MB) before
  download; OPEN: confirm cap with backend upload limit from AND-331.
- R4: OAuth client ID provisioning (Google Cloud console, SHA-1 of signing keys
  for debug/release) is an infra task outside code. OPEN: who owns console
  config.
- R5: Token lifetime — `AuthorizationResult` tokens are short-lived; the
  re-authorize-on-401 path must be silent when consent already granted. Verify
  no consent re-prompt loop on token expiry.

## 14. Acceptance Criteria

AC-1. From the Files screen, "Import from Google Drive" launches Google consent
for `drive.readonly` and, on grant, shows a list of the account's Drive files
with name, type, size, and modified time. (Maps to ticket: **Connect**.)

AC-2. Selecting one Drive file downloads it and uploads it via AND-331's
`FilesRepository`, after which the imported file appears in the TestLogon Files
list and a success snackbar with the file name is shown. (Maps to ticket:
**import a Drive file**.)

AC-3. `DriveFileList`/`DriveFile` Moshi mapping is unit-tested, including absent
`size` for Google-native types.

AC-4. A Drive 401 during list/download re-authorizes and retries once; a second
401 surfaces a user-actionable reconnect message.

AC-5. No Google access token is persisted to disk, logs, Room, or DataStore
(verified by test/inspection); temp download files are deleted after import.

AC-6. The feature is hidden when Google Play Services is unavailable, and Google
traffic uses a separate OkHttpClient with no TestLogon cookies/CSRF attached.

AC-7. Import can be cancelled at any stage with no partial TestLogon file left.

## 15. Definition of Done

- All AC-1..AC-7 met and demonstrated by the acceptance instrumented test plus a
  manual QA run against a real Google account and the dev backend.
- Code merged to `android-port` under `com.testlogon.android.feature.files.drive`
  and `core-network` Google service; layering (`app -> feature-files -> core-*`)
  respected.
- Unit + ViewModel + Compose UI tests green in CI; coverage for repository,
  mapping, error mapper, and state machine.
- New dependencies pinned to the versions in §2; network security config keeps
  cleartext scoped to the dev host; release build proguard/R8 keeps Drive Moshi
  models.
- Strings externalized; TalkBack pass on the import sheet; no token/PII in
  telemetry or logs (redaction verified).
- Open questions R2/R3/R4 resolved or explicitly deferred with owner; spec
  `status` advanced from `draft`.
