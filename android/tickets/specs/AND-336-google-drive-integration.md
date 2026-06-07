---
id: AND-336
title: Google Drive integration
milestone: M7
epic: E43
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-331]
blocks: []
---

# AND-336 — Google Drive integration

## 1. Overview & Goal

> **REVIEW CORRECTION (2026-06-06): architecture reversed.** The web reference
> (`src/api/endpoints/googleDrive.ts`) does **not** call the public Google Drive
> REST API from the client, and does **not** perform client-side OAuth. The
> entire integration is **backend-mediated** through TestLogon's own
> `/ui/integrations/google-drive/*` endpoints (verified in
> `reference/openapi.index.txt` lines 1521-1526 and `src/api/endpoints/
> googleDrive.ts`). OAuth is performed server-side: the client asks the backend
> for an `auth_url`, opens it, and posts the returned `code` back to the
> backend, which exchanges it for tokens and stores the credential. Browse and
> import are then plain authenticated calls to the TestLogon backend, which
> proxies Drive on the server. The original design below (Credential Manager +
> `AuthorizationClient` + direct `https://www.googleapis.com` Retrofit calls)
> has been corrected to match this contract; affected sections are annotated.

Add an optional "Import from Google Drive" capability to the TestLogon native
Android app. To match the web contract, OAuth and Drive access are
**backend-mediated**: the user connects their Google account by opening a
backend-issued authorization URL in a browser (Custom Tab), the backend stores
the credential, and the user then browses and imports Drive files via
TestLogon's own backend endpoints. The selected file is imported by a single
backend call (`POST /ui/integrations/google-drive/import`) — the Android client
does **not** download Drive bytes itself, and does **not** re-upload through the
AND-331 Files upload path. The imported file lands in the user's TestLogon file
tree server-side; the Android client then refreshes the Files list (AND-331).

This ticket is the Android counterpart of the web reference module
`src/api/endpoints/googleDrive.ts` (OAuth + browse + import) and the picker UI
`src/components/shared/GoogleDrivePickerDialog.tsx`. On Android we do **not**
reimplement OAuth and do **not** call the Google Drive REST API directly; we
call the same TestLogon backend endpoints the web client uses, attaching the
TestLogon session cookie + `X-CSRF-Token` exactly as for every other TestLogon
request.

Goal: a user on the Files screen can tap "Import from Drive", complete the
Google authorization consent (backend-mediated, in a browser/Custom Tab), select
one Drive file, and see that file appear in their TestLogon file list. Success is
defined by the acceptance bullet: **Connect + import a Drive file.**

Non-goals: bidirectional sync, exporting TestLogon files back to Drive,
client-side Drive byte download / re-upload (the backend `import` endpoint does
the transfer server-side), Google Docs/Sheets native-format conversion policy
(owned by the backend `import` endpoint, not the client), and offline queueing of
imports. Those are explicitly out of scope for AND-336.

> **REVIEW CORRECTION:** Folder navigation IS supported by the contract — the
> browse endpoint accepts `folder_id` and the web picker navigates folders via
> breadcrumbs (`src/components/shared/GoogleDrivePickerDialog.tsx`). The
> original spec listed "folder tree import" as a non-goal; folder *browsing* is
> in scope (importing a whole folder tree in one action remains out of scope).

## 2. Context & References

- Web reference: `src/api/endpoints/googleDrive.ts` (status / connect / callback /
  disconnect / browse / import), picker UI
  `src/components/shared/GoogleDrivePickerDialog.tsx`, transport
  `src/api/client.ts`, shared types `src/api/types.ts`.
- Backend: FastAPI + DynamoDB; OpenAPI at `/openapi.json`; dev host
  `http://18.222.237.167:8000` (plaintext, unreliable — ~20s timeouts, bounded
  retry for idempotent GETs only). Backend endpoints (verified
  `reference/openapi.index.txt` 1521-1526):
  `GET /ui/integrations/google-drive/status` (→ `DriveStatusResp`),
  `GET /ui/integrations/google-drive/connect` (→ `{auth_url, mock?}`),
  `POST /ui/integrations/google-drive/callback` (req `DriveCallbackReq`),
  `POST /ui/integrations/google-drive/disconnect`,
  `GET /ui/integrations/google-drive/files` (params `folder_id,q,page_token,
  page_size` → `DriveFilesResp`),
  `POST /ui/integrations/google-drive/import` (req `DriveImportReq` →
  `DriveImportResp`). In dev, the backend proxies a mock Drive at
  `/mock/google-drive/...` (`google_drive_mock_enabled`).
- Upstream dependency **AND-331 — Files API + DTOs**: provides
  `FilesApi` (Retrofit), `FileDto` Moshi model, and `FilesRepository`. AND-336
  consumes AND-331 ONLY to **refresh** the Files list after a successful
  server-side import; it does **not** use AND-331's upload path (the backend
  `import` endpoint performs the Drive→TestLogon transfer server-side). MUST NOT
  redefine file DTOs.
- Auth note (**CORRECTED**): all Drive endpoints are TestLogon's own backend
  endpoints under `/ui/integrations/google-drive/*`. They are authenticated with
  the **same** TestLogon session cookie + `X-CSRF-Token` as every other request
  (`src/api/client.ts` attaches `credentials: include` and the `ui_csrf` cookie
  header uniformly). There is **no** separate Google OAuth bearer token in the
  client and **no** separate OkHttpClient; Google credentials live server-side.
  (The original spec's claim of a fully separate Google auth system was wrong.)
- Module layering: `app -> feature-files -> core-*`. New code lands in a thin
  `feature-files` sub-package plus a `core-network` Retrofit service that hangs
  off the **existing TestLogon Retrofit/OkHttp** (cookie jar + CSRF interceptor),
  not a new Google client.
- Stack: Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow,
  Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, minSdk 24, targetSdk 35.

Libraries added by this ticket (**CORRECTED**): the backend-mediated design needs
**no** Google Identity / Play Services / Credential Manager dependencies. The
only addition is a browser Custom Tab for the consent URL:
`androidx.browser:browser:1.8.0`. The previously-listed
`androidx.credentials:*`, `com.google.android.gms:play-services-auth:*`, and
`com.google.android.libraries.identity.googleid:*` are **removed** — they were
predicated on the incorrect client-side-OAuth design. (Versions/coordinates of
the credential libs were not verified against any source; they are moot.)

## 3. Functional Requirements

FR-1 (**CORRECTED**). An "Import from Google Drive" affordance is present on the
Files screen (an entry in the add/import menu). Visibility is **not** gated on
Google Play Services (the backend-mediated flow needs none); instead the
affordance may optionally check connection state via
`GET /ui/integrations/google-drive/status` to decide between "Connect" and
"Import" labels. (The original Play-Services gate was an artifact of the
client-side-OAuth design and is removed.)

FR-2 (**CORRECTED**). If the account is not yet connected
(`DriveStatusResp.connected == false`), tapping "Connect" calls
`GET /ui/integrations/google-drive/connect`, receives `{auth_url, mock?}`, and
opens `auth_url` in a Custom Tab. After Google consent, the redirect delivers a
`code`; the app posts it to `POST /ui/integrations/google-drive/callback`
(`DriveCallbackReq{code, redirect_uri, state}`) which stores the credential
server-side. No OAuth scope string is requested by the client; the backend owns
the scope. In dev (`mock: true`) the connect URL is a mock auto-grant.

FR-3 (**CORRECTED**). Once connected, the user is presented a list of their Drive
files (name, MIME type, size, modified time), fetched via
`GET /ui/integrations/google-drive/files` with optional `folder_id` (folder
navigation), `q` (search), `page_token`, and `page_size`. Pagination is forward
via `DriveFilesResp.nextPageToken` (Paging 3). Folders (`mimeType ==
application/vnd.google-apps.folder`) are navigable, not importable.

FR-4 (**CORRECTED**). Selecting a file calls
`POST /ui/integrations/google-drive/import`
(`DriveImportReq{file_id, destination_path?}`). The **backend** downloads from
Drive and writes the file into the TestLogon tree; the client receives
`DriveImportResp{ok, node_id, path}`. The client does **not** download Drive
bytes or call AND-331's upload path.

FR-5. On import success the TestLogon Files list refreshes (AND-331
`filesRepository.refresh()`) and the imported file is visible. The import sheet
dismisses with a success snackbar showing the file name.

FR-6. The user can cancel at any stage (consent, list, import request). Cancel
leaves no partial TestLogon file (the backend import is atomic per file).

FR-7. A single Drive file per invocation. (Note: the web picker supports
multi-select and loops `importDriveFile` per file; multi-select remains out of
scope for AND-336 by product decision, not a contract limit.)

## 4. Technical Design

New package `com.testlogon.android.feature.files.drive`.

> **REVIEW CORRECTION:** the original design (Credential Manager +
> `AuthorizationClient`, a `@Named("googleDrive")` Retrofit pointed at
> `https://www.googleapis.com/`, and a repository that streams Drive bytes to
> cacheDir and re-uploads via AND-331) is **deleted** — it does not match the
> backend-mediated contract. The corrected design below calls TestLogon's own
> endpoints through the **existing** TestLogon Retrofit/OkHttp (session cookie +
> CSRF), and a Custom Tab for the one-time consent URL.

Retrofit service on the **existing TestLogon Retrofit** (in `core-network`; uses
the shared cookie-jar + CSRF interceptor — no new base URL, no new client):

```kotlin
interface GoogleDriveApi {
    @GET("ui/integrations/google-drive/status")
    suspend fun status(): DriveStatusResp

    @GET("ui/integrations/google-drive/connect")
    suspend fun connect(): DriveConnectResp // { auth_url, mock? }

    @POST("ui/integrations/google-drive/callback")
    suspend fun callback(@Body req: DriveCallbackReq): DriveCallbackResp // { ok, connected }

    @POST("ui/integrations/google-drive/disconnect")
    suspend fun disconnect(): DriveDisconnectResp // { ok }

    @GET("ui/integrations/google-drive/files")
    suspend fun browse(
        @Query("folder_id") folderId: String?,
        @Query("q") query: String?,
        @Query("page_token") pageToken: String?,
        @Query("page_size") pageSize: Int? = 100,
    ): DriveFilesResp

    @POST("ui/integrations/google-drive/import")
    suspend fun import(@Body req: DriveImportReq): DriveImportResp
}
```

Consent: `connect()` returns `auth_url`; open it in an
`androidx.browser.customtabs.CustomTabsIntent`. The OAuth redirect must target an
app-registered redirect (deep link / `redirect_uri`) that delivers `code` (+
`state`) back to the app, which then posts `DriveCallbackReq` to `callback()`. In
dev, `connect().mock == true` and the URL auto-grants. **OPEN:** the exact
redirect URI / deep-link scheme is backend-config-dependent and not derivable
from the sources (see §16 open assumptions).

Repository orchestrating connect + browse + import:

```kotlin
class GoogleDriveRepository @Inject constructor(
    private val api: GoogleDriveApi,
    private val filesRepository: FilesRepository, // from AND-331 — refresh only
) {
    suspend fun status(): ApiResult<DriveStatusResp>
    suspend fun connectUrl(): ApiResult<DriveConnectResp>
    suspend fun completeConnect(code: String, redirectUri: String, state: String?): ApiResult<Unit>
    fun pager(folderId: String?, query: String?): Flow<PagingData<DriveFile>>
    suspend fun import(fileId: String, destinationPath: String?): ApiResult<DriveImportResp>
}
```

`import` is a single backend POST; on success it calls
`filesRepository.refresh()`. There is **no** client-side download, temp file,
multipart upload, or `GOOGLE_EXPORT_MAP` — Google-native MIME handling and any
export conversion are owned by the backend `import` endpoint, not the client.

UI: `DriveImportSheet` (Material 3 `ModalBottomSheet`) driven by
`DriveImportViewModel : ViewModel` exposing `StateFlow<DriveImportUiState>`.
The list uses `collectAsLazyPagingItems()`. The consent step is launched as a
Custom Tab (browser), with the redirect handled by an intent-filter Activity
(**CORRECTED** from the original `StartIntentSenderForResult` consent launcher,
which was tied to the removed `AuthorizationClient` design). State includes a
`folderId`/breadcrumb stack to mirror the web picker's folder navigation.

```kotlin
sealed interface DriveImportUiState {
    data object NotConnected : DriveImportUiState
    data object Connecting : DriveImportUiState
    data class Browsing(val folderId: String?, val query: String, val importing: String?) : DriveImportUiState
    data class Error(val message: String) : DriveImportUiState
}
```

## 5. API Contract

**REVISED (CORRECTED): one surface — TestLogon's backend.** There is no
client-to-`googleapis.com` traffic. All shapes below are verified against
`reference/openapi.index.txt` (1521-1526), `reference/openapi.pretty.json`
(`components.schemas.Drive*`), and `src/api/endpoints/googleDrive.ts`.

Endpoints (base = TestLogon API base; relative paths used with the existing
Retrofit):

- `GET /ui/integrations/google-drive/status` → `DriveStatusResp`
  (`{connected: bool, email?: str, scopes?: str[], connected_at?: str}`).
- `GET /ui/integrations/google-drive/connect` → `{auth_url: str, mock?: bool}`
  (OpenAPI response is an untyped `object`; shape per `googleDrive.ts:
  initiateGoogleDriveConnect`).
- `POST /ui/integrations/google-drive/callback`, body `DriveCallbackReq`
  (`{code: str (1..2048, required), redirect_uri: str (default ""), state:
  str|null}`) → `{ok: bool, connected: bool}` (OpenAPI: untyped object;
  shape per `googleDrive.ts: completeGoogleDriveConnect`).
- `POST /ui/integrations/google-drive/disconnect` → `{ok: bool}`.
- `GET /ui/integrations/google-drive/files`, query `folder_id?`, `q?`,
  `page_token?`, `page_size?` → `DriveFilesResp` (`{files: DriveFile[],
  nextPageToken?: str}`). NOTE: query params are snake_case `folder_id` /
  `page_token` / `page_size` (verified `googleDrive.ts: browseGoogleDriveFiles`
  and the index `params=folder_id,q,page_token,page_size`) — NOT the Drive-native
  `pageToken`/`pageSize`/`spaces`/`fields` the original spec used.
- `POST /ui/integrations/google-drive/import`, body `DriveImportReq`
  (`{file_id: str (1..256, required), destination_path: str|null (max 1024)}`)
  → `DriveImportResp` (`{ok: bool, node_id: str, path: str}`).

```kotlin
@JsonClass(generateAdapter = true)
data class DriveFilesResp(
    @Json(name = "files") val files: List<DriveFile>,
    @Json(name = "nextPageToken") val nextPageToken: String? = null,
)

@JsonClass(generateAdapter = true)
data class DriveFile(                    // shape per googleDrive.ts: DriveFile
    val id: String,
    val name: String,
    val mimeType: String,
    val size: String? = null,           // bytes as string; absent for native docs/folders
    val modifiedTime: String? = null,   // RFC3339
    val parents: List<String>? = null,
    val kind: String? = null,
)

@JsonClass(generateAdapter = true)
data class DriveStatusResp(
    val connected: Boolean,
    val email: String? = null,
    val scopes: List<String>? = null,
    @Json(name = "connected_at") val connectedAt: String? = null,
)

@JsonClass(generateAdapter = true)
data class DriveCallbackReq(
    val code: String,
    @Json(name = "redirect_uri") val redirectUri: String = "",
    val state: String? = null,
)

@JsonClass(generateAdapter = true)
data class DriveImportReq(
    @Json(name = "file_id") val fileId: String,
    @Json(name = "destination_path") val destinationPath: String? = null,
)

@JsonClass(generateAdapter = true)
data class DriveImportResp(
    val ok: Boolean,
    @Json(name = "node_id") val nodeId: String,
    val path: String,
)
```

Errors are FastAPI-shaped: `422` returns `HTTPValidationError`
(`{detail: [{loc, msg, type}]}`); other failures return `{detail: ...}` where
`detail` is `string | [{msg}] | {code,...}` — normalized exactly as
`src/api/client.ts: normalizeErrorDetail`. 401 triggers the standard TestLogon
session refresh + single retry (`src/api/client.ts`), NOT a Google-token
re-auth. (The original spec's Google `{"error":{...}}` shape and Google-token 401
handling do not apply — those responses never reach the client.)

AND-331 is consumed **only** via `filesRepository.refresh()` after a successful
import; this ticket defines no upload request and does not call any AND-331
upload method.

## 6. Data & State Management

- Google access/refresh tokens (**CORRECTED**): held **server-side** by the
  backend after `callback`; the Android client never sees, holds, or persists any
  Google token. The original "in-memory access token" bullet does not apply.
- Connection state is read on demand from `GET .../status`; optionally cached in
  the ViewModel for the sheet's lifetime. A single DataStore boolean
  `drive_import_seen` (existing `core-data` prefs) records first-run copy only.
- Drive file listing is not cached in Room — fetched live via a Paging 3
  `PagingSource` keyed on `nextPageToken` (and `folder_id` for navigation).
  Rationale: Drive contents are remote-of-record.
- The imported TestLogon file is persisted server-side and surfaced by AND-331's
  Files cache; AND-336 triggers `filesRepository.refresh()` after a successful
  import.
- No temp download files exist on device (**CORRECTED**): the byte transfer
  happens server-side inside the `import` endpoint, so there is no
  `cacheDir/drive-import/` directory to manage or clean up.

## 7. Error Handling & Resilience

- Connection errors (**CORRECTED**): if `status.connected == false`, show the
  "Connect" CTA. If the Custom Tab consent is dismissed/denied (no `code`
  returned) → stay `NotConnected` with a non-blocking message. A backend
  "not connected" response on browse/import (the backend signals this; exact
  code is **unverified** — likely 401/403 with a `detail`) re-shows the Connect
  CTA.
- Network/transport: Drive endpoints go through the **existing TestLogon
  OkHttp**, inheriting its ~20s timeout, cookie-jar, CSRF, and the standard 401
  session-refresh-then-single-retry from `src/api/client.ts` (mirrored in the
  Android transport). There is no separate Google client and no Google-token
  401 path. Idempotent GETs (`status`, `files`) may use the existing bounded
  retry; `import` (POST, non-idempotent) is NOT auto-retried — a failure offers a
  manual "Retry".
- Import/backend failures surface the normalized FastAPI `detail` message
  (`normalizeErrorDetail` semantics).
- Mapping helper (**CORRECTED** — these are TestLogon backend statuses, not
  Google's; the friendly copy should reflect "Drive connection", and 401/403 are
  reconnect-worthy because the backend lost/never-had the credential):

```kotlin
fun Throwable.toDriveError(): String = when (this) {
    is HttpException -> when (code()) {
        401, 403 -> "Your Google Drive connection expired. Reconnect to continue."
        404      -> "That Drive file is no longer available."
        422      -> "Couldn't import that file." // normalize detail where present
        429      -> "Google Drive is busy. Try again shortly."
        in 500..599 -> "Drive import is unavailable right now. Try again."
        else     -> "Drive request failed (${code()})."
    }
    is IOException -> "Network problem reaching the server."
    else          -> "Import failed."
}
```

- Cancellation is cooperative (`CancellationException` propagated). Because the
  transfer is server-side, cancelling before the `import` response means the
  import may or may not have completed; the post-import `refresh()` reconciles
  the true server state. There are no client temp files to remove.

## 8. Security & Privacy

- Scope (**CORRECTED**): the requested OAuth scope is chosen by the **backend**,
  not the client; `DriveStatusResp.scopes` reports what was granted. The client
  cannot and does not set `drive.readonly`. (Whether the backend requests
  read-only is a backend concern; **unverified** from these sources.)
- No Google token exists on device, so there is nothing to redact/persist on the
  client side. The TestLogon session cookie + `X-CSRF-Token` are the only
  sensitive material and are handled by the existing transport (already redacted
  by AND-027/AND-331 logging rules).
- Drive endpoints are TestLogon backend endpoints, reached over the **same**
  transport as all TestLogon traffic; on the dev host that is cleartext to
  `18.222.237.167` (network security config). There is no client→`googleapis.com`
  connection. (**CORRECTED** from "HTTPS to googleapis.com"; that traffic is now
  server-side only.)
- The session cookie jar and `X-CSRF-Token` **ARE** attached to these requests —
  they must be, because the endpoints are TestLogon's own and require auth/CSRF
  (`src/api/client.ts`). The original "NOT attached / separate OkHttpClient"
  guidance was wrong and is reversed.
- No OAuth client ID or secret ships in the app — OAuth is performed entirely by
  the backend.
- The consent screen is Google's, opened via the backend `auth_url` in a Custom
  Tab; the app shows a one-line rationale before opening it.
- CSRF on the redirect/`callback`: pass through the backend-issued `state` from
  `auth_url` to `callback` to bind the OAuth round-trip (the web client forwards
  `state`; see `googleDrive.ts`).

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
- File names are NOT included in any event (no client-held Google tokens exist to
  leak; **CORRECTED** — the prior token-redaction concern is moot client-side).
- Debug-only `Timber` logs around state transitions; the TestLogon session
  cookie / `X-CSRF-Token` redaction from the existing transport applies. No
  verbose logging in release builds.

## 11. Testing Strategy

(See §17 Test Plan for enumerated, AC-traced cases; this section is the strategy
summary, **CORRECTED** to the backend-mediated design.)

Unit (JVM, `core-testing` + MockWebServer):
- `GoogleDriveApi` deserialization: `DriveFilesResp` maps `nextPageToken` and all
  `DriveFile` fields, including absent `size` for native docs/folders; snake_case
  query params (`folder_id`, `page_token`, `page_size`) serialize correctly.
- `GoogleDriveRepository.import` happy path: POST `DriveImportReq` →
  `DriveImportResp`, returns `ApiResult.Success`, calls
  `filesRepository.refresh()` (verify via fake). No temp file / no upload call.
- Browse pagination: `nextPageToken` drives the next page; folder navigation
  passes `folder_id`.
- Error mapping: 422 `HTTPValidationError` and `detail` variants normalize per
  `normalizeErrorDetail`; `toDriveError` covers 401/403/404/422/429/5xx/IOError.

ViewModel: `DriveImportViewModel` state machine
(`NotConnected -> Connecting -> Browsing -> Browsing(importing) -> success`),
using `kotlinx-coroutines-test` and a fake repository (fake `status`/`connectUrl`/
`completeConnect`).

Instrumented/UI (Compose test): sheet renders paged list from a fake
`PagingSource`; tapping a row shows importing spinner; success dismisses sheet
and emits snackbar. The Custom Tab consent is faked (callback injected directly).

Acceptance verification ("Connect + import a Drive file"): an instrumented test
with a MockWebServer-stubbed backend proves connect→browse→import produces a
`DriveImportResp` and refreshes the Files list. A manual QA pass against a real
Google account on the dev backend (mock or live) confirms the live flow.

## 12. Dependencies & Sequencing

- Hard dependency (**CORRECTED**): **AND-331 — Files API + DTOs** (P0). AND-336
  needs `FilesRepository.refresh()` (to re-list after server-side import) — NOT
  the upload path. `FileUploadRequest` is not used by this ticket. Adds no Files
  DTOs.
- Direct dependency on AND-027 (HTTP/session core): the Drive endpoints use the
  **same** TestLogon transport (cookie jar + CSRF + 401 refresh), so AND-027's
  client is required, not bypassed. (**CORRECTED** — there is no separate Google
  client.)
- Gradle: add only `androidx.browser:browser` (Custom Tab). Do NOT add Credential
  Manager / play-services-auth / googleid. No OAuth client ID is registered in the
  app (backend-owned). Network security config keeps cleartext scoped to the dev
  host only.
- Sequencing: implement `GoogleDriveApi` + DTOs + repository on the existing
  Retrofit first (unit testable without UI), then the connect/Custom-Tab +
  redirect handling, then the `DriveImportSheet`/ViewModel and Files-screen entry
  point.
- Blocks: nothing in the provided backlog (`blocks: []`).

## 13. Risks & Open Questions

- R1 (**REVISED**): the backend-mediated design needs no Play Services; R1's
  Play-Services dependency risk is obsolete. New risk: the OAuth redirect /
  deep-link wiring (redirect URI registered with the backend's Google client)
  must round-trip `code`+`state` back to the app. OPEN: confirm the redirect URI
  / deep-link scheme with backend infra.
- R2 (**REVISED**): Google-native doc conversion (Docs/Sheets export MIME) is a
  **backend** policy owned by the `import` endpoint, not the client. No
  `GOOGLE_EXPORT_MAP` ships on Android. OPEN only for the backend team.
- R3 (**REVISED**): large-file handling and any size cap live server-side in the
  `import` endpoint; the client streams nothing. The client should surface the
  backend's error if an import is rejected for size. OPEN: confirm backend size
  limit/behavior so the client copy is accurate.
- R4 (**REVISED**): OAuth client provisioning (Google Cloud console, client
  ID/secret) is entirely a **backend** infra task; nothing ships in the APK.
  OPEN: who owns backend console config + redirect URI registration.
- R5 (**REVISED**): Google token lifetime is managed server-side; the client only
  observes `status.connected`. Risk: a server-side credential can expire/revoke,
  surfacing as a 401/403 on browse/import → client must re-show Connect without a
  loop. Verify the reconnect path is single-shot.

## 14. Acceptance Criteria

AC-1 (**CORRECTED**). From the Files screen, "Import from Google Drive" — when not
connected — calls `connect`, opens the backend `auth_url` in a Custom Tab,
completes via `callback`, and then `status.connected == true`; when connected, it
shows a list of the account's Drive files (via `GET .../files`) with name, type,
size, and modified time, including folder navigation. (Maps to ticket:
**Connect**.)

AC-2 (**CORRECTED**). Selecting one Drive file calls `POST .../import`
(`DriveImportReq{file_id, destination_path?}`) and, on `DriveImportResp{ok:true}`,
the TestLogon Files list refreshes (AND-331) so the imported file appears, and a
success snackbar with the file name is shown. (Maps to ticket: **import a Drive
file**.) The client does not download/upload bytes itself.

AC-3. `DriveFilesResp`/`DriveFile` Moshi mapping is unit-tested, including absent
`size` for Google-native types and folders, and snake_case browse query params.

AC-4 (**CORRECTED**). A 401/403 from `browse`/`import` (lost server-side
credential) routes through the standard transport refresh+single-retry; if still
unauthorized, the client re-shows a user-actionable "Reconnect" CTA (no
consent-loop). There is no Google-token re-auth on the client.

AC-5 (**CORRECTED**). No Google token exists on the client at all (verified by
design/inspection — the client never receives one); the TestLogon session/CSRF
are handled by the existing transport. No client temp download files are created.

AC-6 (**CORRECTED**). The feature does NOT depend on Google Play Services and is
not gated on it; Drive endpoints reuse the existing TestLogon OkHttp WITH session
cookies + `X-CSRF-Token` attached (they are required). The original separate-
client / no-cookie criterion is reversed.

AC-7. Import can be cancelled at any stage with no partial TestLogon file left;
the post-import `refresh()` reconciles server state.

## 15. Definition of Done

- All AC-1..AC-7 met and demonstrated by the acceptance instrumented test plus a
  manual QA run against a real Google account and the dev backend.
- Code merged to `android-port` under `com.testlogon.android.feature.files.drive`
  and `core-network` Google service; layering (`app -> feature-files -> core-*`)
  respected.
- Unit + ViewModel + Compose UI tests green in CI; coverage for repository,
  mapping, error mapper, and state machine.
- New dependency (`androidx.browser:browser` for the consent Custom Tab) pinned
  per §2; the removed Credential Manager / play-services-auth / googleid deps are
  NOT added; network security config keeps cleartext scoped to the dev host;
  release build proguard/R8 keeps the Drive Moshi models (`Drive*`).
- Strings externalized; TalkBack pass on the import sheet; no token/PII in
  telemetry or logs (redaction verified).
- Open questions R2/R3/R4 resolved or explicitly deferred with owner; spec
  `status` advanced from `draft`.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Drive integration is backend-mediated via `/ui/integrations/google-drive/*`,
   not direct googleapis.com calls.** VERDICT: Corrected (spec originally said
   client calls Drive REST directly). SOURCE: `src/api/endpoints/googleDrive.ts`
   (all functions call `api.get/post("/ui/integrations/google-drive/...")`);
   `reference/openapi.index.txt` lines 1521-1526.
2. **`GET /ui/integrations/google-drive/status` → `DriveStatusResp{connected,
   email?, scopes?, connected_at?}`.** VERDICT: Verified. SOURCE: OpenAPI `GET
   /ui/integrations/google-drive/status` (resp `DriveStatusResp`);
   `components.schemas.DriveStatusResp` (openapi.pretty.json ~29867);
   `googleDrive.ts: DriveStatusResp`.
3. **`GET /ui/integrations/google-drive/connect` → `{auth_url, mock?}`.** VERDICT:
   Verified (response is an untyped object in OpenAPI; field shape from frontend).
   SOURCE: OpenAPI `GET /ui/integrations/google-drive/connect` (description:
   "Generate OAuth authorization URL (or mock connect URL in dev mode)",
   openapi.pretty.json ~214532); `googleDrive.ts: initiateGoogleDriveConnect`.
4. **`POST /ui/integrations/google-drive/callback` body `DriveCallbackReq{code
   (req, 1..2048), redirect_uri (default ""), state?}` → `{ok, connected}`.**
   VERDICT: Verified. SOURCE: OpenAPI op
   `complete_google_drive_connect_*` (req `DriveCallbackReq`);
   `components.schemas.DriveCallbackReq` (openapi.pretty.json ~29808);
   `googleDrive.ts: completeGoogleDriveConnect`.
5. **`GET /ui/integrations/google-drive/files` query `folder_id,q,page_token,
   page_size` → `DriveFilesResp{files, nextPageToken?}`.** VERDICT: Corrected
   (spec used Drive-native `pageToken`/`pageSize`/`spaces`/`fields`). SOURCE:
   OpenAPI `GET /ui/integrations/google-drive/files` (`params=folder_id,q,
   page_token,page_size`); `googleDrive.ts: browseGoogleDriveFiles` and
   `DriveFilesResp`.
6. **`POST /ui/integrations/google-drive/import` body `DriveImportReq{file_id
   (req, 1..256), destination_path? (max 1024)}` → `DriveImportResp{ok, node_id,
   path}`.** VERDICT: Corrected (spec returned `FileDto` after a client
   download+upload). SOURCE: OpenAPI op `import_drive_file_*` (req
   `DriveImportReq`); `components.schemas.DriveImportReq` (openapi.pretty.json
   ~29840); `googleDrive.ts: importDriveFile` and `DriveImportResp`.
7. **`DriveFile` fields: `id, name, mimeType, size?, modifiedTime?, parents?,
   kind?`; `size` absent for native docs/folders.** VERDICT: Verified (Corrected
   to add `parents`/`kind`). SOURCE: `googleDrive.ts: DriveFile`;
   `src/components/shared/GoogleDrivePickerDialog.tsx` (uses `size`/`modifiedTime`
   conditionally; folder mime `application/vnd.google-apps.folder`).
8. **The client attaches the TestLogon session cookie + `X-CSRF-Token` to Drive
   requests (same transport as all calls).** VERDICT: Corrected (spec said no
   cookie/CSRF, separate OkHttpClient). SOURCE: `src/api/client.ts` (`credentials:
   "include"`, `X-CSRF-Token` from `ui_csrf` cookie set on every request); Drive
   endpoints go through the same `api` wrapper in `googleDrive.ts`.
9. **401 handling = standard session refresh (`/ui/session/refresh`) + single
   retry, not Google-token re-auth.** VERDICT: Corrected. SOURCE: `src/api/
   client.ts` (refreshSession + retry on 401); OpenAPI `/ui/session/*` family.
10. **Error bodies are FastAPI `detail` (string | `[{msg}]` | `{code,...}`); 422 =
    `HTTPValidationError`.** VERDICT: Verified. SOURCE: `components.schemas.
    HTTPValidationError`/`ValidationError` (openapi.pretty.json ~37133);
    `src/api/client.ts: normalizeErrorDetail`.
11. **Folder navigation is part of the contract/UX (breadcrumbs).** VERDICT:
    Corrected (spec listed folder import as a flat non-goal). SOURCE:
    `GoogleDrivePickerDialog.tsx` (breadcrumb stack, `navigateToFolder`,
    `browseGoogleDriveFiles({folder_id})`).
12. **Web picker supports multi-select; AND-336 chooses single-select by product
    decision.** VERDICT: Verified (claim reframed). SOURCE:
    `GoogleDrivePickerDialog.tsx` (`selectedFiles: Set`, loops `importDriveFile`).
13. **Dev backend runs a mock Drive at `/mock/google-drive/...`
    (`google_drive_mock_enabled`).** VERDICT: Verified. SOURCE:
    `reference/openapi.index.txt` lines 439-447; callback op description
    (openapi.pretty.json ~214438).
14. **Backend owns OAuth scope / token lifetime / native-doc export / size
    limits.** VERDICT: Unverified-assumption for the *specifics* (the endpoints
    exist and are server-side, but the source does not expose the scope string,
    export-MIME map, or size cap). SOURCE: inferred from server-side ownership in
    `googleDrive.ts` + OpenAPI; no schema exposes these values.
15. **Custom Tab (`androidx.browser:browser`) for the consent URL; redirect
    delivers `code`+`state` to an app deep link.** VERDICT: Unverified-assumption
    (framework choice + redirect wiring). SOURCE: framework ref —
    https://developer.android.com/develop/ui/views/layout/webapps/customtabs ;
    redirect URI is backend-config-dependent and not in the sources.
16. **AND-331 provides `FilesRepository.refresh()` and `FileDto`; AND-336 uses
    refresh only (no upload).** VERDICT: Unverified-assumption (AND-331 is an
    upstream ticket not present in these sources; the web client invalidates the
    `["files"]` query after import, the analogue of a refresh — see
    `GoogleDrivePickerDialog.tsx` `queryClient.invalidateQueries`). SOURCE:
    `GoogleDrivePickerDialog.tsx` handleImport; AND-331 ticket (not in repo).

### Corrections made

- **Architecture reversed**: client-side OAuth (Credential Manager /
  `AuthorizationClient`) + direct `googleapis.com` Retrofit + client download/
  re-upload via AND-331 → **backend-mediated** TestLogon endpoints (connect/
  callback/status/disconnect/browse/import) over the existing transport. (§1, §2,
  §4, §5)
- **Auth/CSRF reversed**: "no cookies/CSRF, separate OkHttpClient" → session
  cookie + `X-CSRF-Token` ARE attached via the shared transport. (§2, §8, §14
  AC-6)
- **Browse params**: Drive-native `pageToken/pageSize/spaces/fields` → backend
  snake_case `folder_id/q/page_token/page_size`. (§4, §5)
- **Import return**: `FileDto` from client download+upload → `DriveImportResp`
  from a single server-side import POST. (§4, §5, §14 AC-2)
- **DTO names**: `DriveFileList` → `DriveFilesResp`; added `DriveStatusResp/
  DriveCallbackReq/DriveImportReq/DriveImportResp` and `DriveFile.parents/kind`.
- **Removed deps**: Credential Manager / play-services-auth / googleid removed;
  added `androidx.browser:browser`. (§2, §12, §15)
- **Removed client mechanics**: in-memory access token, cacheDir temp files,
  `GOOGLE_EXPORT_MAP`, 401-Google re-auth, Play-Services gating — all deleted as
  not applicable. (§3, §6, §7, §13)
- **Folder navigation** added to scope; **R1-R5** rewritten to backend-mediated
  risks.

### Open assumptions

- Redirect URI / deep-link scheme that returns `code`+`state` to the app:
  backend-config-dependent; not derivable from the provided sources. (Blocks the
  connect-callback wiring.)
- OAuth scope actually requested, native-doc export policy, and import size cap:
  owned by the backend `connect`/`import` endpoints; not exposed in OpenAPI or the
  frontend. Client copy must defer to backend error messages.
- The "not connected" failure status code on browse/import (assumed 401/403 with
  a `detail`): not documented in the index/spec; verify against a live/mock
  backend.
- AND-331's exact `FilesRepository.refresh()` API and `FileDto`: upstream ticket,
  not in this repo snapshot; assumed to exist per the dependency.
- `connect`/`callback`/`disconnect` precise response bodies: OpenAPI types them as
  untyped objects; field shapes taken from the frontend types (treated as the
  authoritative client contract).

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **MWS** =
contract via MockWebServer (JVM); **emu35** = headless emulator AVD `test35`
(x86_64, API 35); **A15** = physical Samsung Galaxy A15 5G (SM-A156U, API 34,
arm64). UI/instrumented cases default to **emu35**; cases needing the real
Custom-Tab/browser + Google consent round-trip or ABI/API-34 behavior call out
**A15**.

- **TC-AND-336-01** — Type: unit (JVM/Moshi). Target: JVM. Pre: Moshi configured
  with `Drive*` adapters. Steps: parse a `DriveFilesResp` JSON with one binary
  file (with `size`), one native doc (no `size`), and one folder; assert fields +
  `nextPageToken`. Expected: all fields map; absent `size` → null; `parents/kind`
  optional. Traces: AC-3.
- **TC-AND-336-02** — Type: unit (JVM). Target: JVM. Pre: Retrofit/Moshi. Steps:
  serialize a `browse(folderId, q, pageToken, pageSize)` call and a
  `DriveImportReq`/`DriveCallbackReq`. Expected: query keys are snake_case
  `folder_id/q/page_token/page_size`; bodies use `file_id`, `destination_path`,
  `redirect_uri`. Traces: AC-2, AC-3.
- **TC-AND-336-03** — Type: contract/MockWebServer. Target: MWS. Pre: stubbed
  backend. Steps: `status` → `{connected:false}`; `connect` → `{auth_url, mock}`;
  inject `code`; `callback` → `{ok:true,connected:true}`; `status` →
  `{connected:true}`. Expected: ViewModel transitions NotConnected→Connecting→
  Browsing; CSRF/session headers present on requests. Traces: AC-1, AC-6.
- **TC-AND-336-04** — Type: contract/MockWebServer. Target: MWS. Pre: connected.
  Steps: `browse` page 1 returns `nextPageToken`; request page 2 with
  `page_token`; navigate into a folder (`folder_id`). Expected: pager advances;
  folder rows navigable not importable; second request carries the token + folder.
  Traces: AC-1.
- **TC-AND-336-05** — Type: contract/MockWebServer (happy import). Target: MWS.
  Pre: connected, file selected. Steps: `import {file_id}` → `DriveImportResp{ok:
  true, node_id, path}`; assert `filesRepository.refresh()` invoked (fake) and NO
  upload/download call occurs. Expected: success; Files list refresh triggered.
  Traces: AC-2.
- **TC-AND-336-06** — Type: unit/contract. Target: MWS. Pre: connected. Steps:
  `import` returns 422 `HTTPValidationError` and separately a `{detail:"..."}`
  500. Expected: `normalizeErrorDetail`-equivalent message surfaced; no refresh;
  no crash. Traces: AC-2, AC-4.
- **TC-AND-336-07** — Type: contract/MockWebServer (reconnect path). Target: MWS.
  Pre: connected. Steps: `browse` returns 401; transport attempts
  `/ui/session/refresh` then retries once; retry still 401/403. Expected: client
  surfaces "Reconnect" CTA, re-runs connect flow, NO consent loop, no Google-token
  logic. Traces: AC-4, AC-6.
- **TC-AND-336-08** — Type: unit (JVM). Target: JVM. Pre: `toDriveError`. Steps:
  feed `HttpException` 401/403/404/422/429/503, `IOException`, generic. Expected:
  each maps to the corrected user copy (401/403 → reconnect). Traces: AC-4.
- **TC-AND-336-09** — Type: Compose-UI. Target: emu35. Pre: fake `PagingSource`
  with mixed files/folders. Steps: open `DriveImportSheet`; assert list renders;
  tap a file row → importing spinner; success → sheet dismiss + snackbar with
  file name. Expected: state machine drives UI; spinner+text (not color-only).
  Traces: AC-1, AC-2.
- **TC-AND-336-10** — Type: Compose-UI (accessibility). Target: emu35. Pre: sheet
  open. Steps: TalkBack/semantics assertions: row `contentDescription` combines
  name+type+size; icons decorative; touch targets ≥48dp; sheet focusable +
  accessible dismiss. Expected: all a11y assertions pass. Traces: AC-1.
- **TC-AND-336-11** — Type: Compose-UI (cancel). Target: emu35. Pre: import
  in-flight (delayed MWS). Steps: cancel/dismiss the sheet mid-import. Expected:
  coroutine cancelled; on reopen, post-import `refresh()` reflects true server
  state; no partial-file assumption baked into UI. Traces: AC-7.
- **TC-AND-336-12** — Type: instrumented/e2e (real consent). Target: **A15
  (required)**. Pre: dev backend reachable, real Google account. Steps: tap
  Connect → real Custom Tab opens `auth_url` → grant Google consent → redirect
  delivers `code` → `callback` → browse → import one file. Expected: file appears
  in TestLogon Files list; success snackbar. MUST run on A15: needs the device
  browser + Google consent round-trip and the real redirect deep link (not
  reproducible on a headless emulator). Traces: AC-1, AC-2, AC-7.
- **TC-AND-336-13** — Type: integration (security/no-token + headers). Target:
  MWS + JVM. Pre: full flow run. Steps: capture all outbound requests; inspect app
  storage (DataStore/Room/files) after import. Expected: every Drive request
  carries the TestLogon session cookie + `X-CSRF-Token`; no request to
  `googleapis.com`; no Google token anywhere on device; no `cacheDir/drive-import`
  created. Traces: AC-5, AC-6.
- **TC-AND-336-14** — Type: instrumented (ABI/API parity). Target: **A15 vs
  emu35**. Pre: same APK. Steps: run TC-09 + TC-13 on emu35 (x86_64/API35) and
  A15 (arm64/API34). Expected: identical behavior; Moshi/Retrofit and Custom-Tab
  intent resolution work on API 34 arm64. Traces: AC-1, AC-2, AC-5, AC-6.

### Coverage matrix

| AC | Covered by |
| --- | --- |
| AC-1 (connect + list, folders) | TC-03, TC-04, TC-09, TC-10, TC-12, TC-14 |
| AC-2 (import → refresh + snackbar) | TC-02, TC-05, TC-06, TC-09, TC-12, TC-14 |
| AC-3 (Moshi mapping, absent size) | TC-01, TC-02 |
| AC-4 (401/403 reconnect, no loop) | TC-06, TC-07, TC-08 |
| AC-5 (no client Google token / temp files) | TC-13, TC-14 |
| AC-6 (no Play-Services gate; cookies+CSRF attached) | TC-03, TC-07, TC-13, TC-14 |
| AC-7 (cancel, no partial file) | TC-11, TC-12 |
