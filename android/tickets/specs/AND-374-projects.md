---
id: AND-374
title: Projects
milestone: M8
epic: E48
priority: P2
size: M
depends_on: [AND-027]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
---

# AND-374 — Projects

## 1. Overview & Goal

Add a **Projects** area to the TestLogon native Android app: a paged list of the
authenticated user's projects and a project **detail** screen, plus the
**Google Drive provider connection** flow (start + callback) that lets a project
link a Google Drive folder/account as a storage provider.

This ticket is the Android counterpart of the web reference module
`frontend/src/api/endpoints/projects.ts`. It ports the list/detail read surface
and the Drive provider `start`/`callback` handshake. Crucially, the Drive
connection here is **server-mediated OAuth**: the backend owns the OAuth client
and token exchange. The app asks the backend for an authorization URL
(`start`), opens it in a Custom Tab, and the backend completes the exchange and
redirects back to the app via a deep link (`callback`). The app never sees a
Google client secret or holds a Google access token — this is materially
different from a client-side Google Identity flow.

Goal, per the acceptance bullets: **Projects render** (the list loads and shows
the user's projects with paging/empty/error/offline states) and **detail opens**
(tapping a project navigates to a detail screen that loads and displays the
project, including its connected providers and a "Connect Google Drive" action
that completes the start/callback round-trip).

Non-goals for AND-374: project create/edit/delete (write mutations), provider
disconnect/revoke, browsing Drive folder contents, file import (that lives in
the Files epic, AND-336), multi-provider beyond Google Drive, and project
sharing/collaboration. Those are out of scope and named where relevant below.

## 2. Context & References

- Web reference: `frontend/src/api/endpoints/projects.ts` (list/detail + Drive
  provider start/callback), shared types `frontend/src/api/types.ts`.
- Backend: FastAPI + DynamoDB. OpenAPI at `/openapi.json`. Dev host
  `http://18.222.237.167:8000` is plaintext HTTP and unreliable — design for
  ~20s timeouts, bounded backoff retry for **idempotent GETs only**, and
  offline/stale UI states.
- **Hard dependency AND-027 — AuthApi (session endpoints)**: provides the
  Retrofit/OkHttp core that this ticket rides on — the persistent cookie jar,
  the `ui_csrf` → `X-CSRF-Token` interceptor, the single-shot `401 → POST
  /ui/session/refresh → retry` authenticator, the `ApiResult<T>` type, and the
  FastAPI `detail` error mapping (string | `[{msg}]` | `{code,...}`). Projects
  endpoints are authenticated session reads and reuse this stack unchanged.
- Auth model: cookie-based TestLogon session (`/ui/session/*`). All Projects
  endpoints require an established session and send the session cookies + CSRF.
- Module layering: `app -> feature-projects -> core-*` (`core-network`,
  `core-model`, `core-ui`, `core-data`, `core-testing`). New code lands in a new
  `feature-projects` module plus a `ProjectsApi` in `core-network` and DTO/domain
  models in `core-model`.
- Stack: Kotlin 2.0.21, Compose + Material 3, single-Activity Navigation-Compose,
  Hilt (KSP), Coroutines/Flow, Retrofit 2.11 + OkHttp 4.12 + Moshi 1.15, Room 2.6
  (cache), DataStore (prefs), Paging 3, Coil. minSdk 24, target/compileSdk 35,
  JDK 17.

Library added by this ticket: `androidx.browser:browser:1.8.0` (Chrome Custom
Tabs) for the server-mediated Drive OAuth `start` redirect. No Google SDK is
added — the OAuth client lives on the backend.

## 3. Functional Requirements

FR-1. A **Projects** list screen shows the authenticated user's projects: each
row shows the project name, the short `description`, the `tags`, and the
`updated_at` time. The list is paged (Paging 3) and supports pull-to-refresh.
CORRECTION (§16): `ProjectOut` has no `status` and no per-project provider list,
so the list does **not** render a status field or Drive connection chips; Drive
connection is an account-scoped state surfaced on the detail screen via the
`/v1/projects/providers/google_drive/credentials` read.

FR-2. The list renders the standard state set from `core-ui` (AND-021 family):
loading (shimmer/spinner), populated, **empty** ("No projects yet"), **error**
(with retry), and **offline/stale** (cached data with a stale banner when the
backend is unreachable).

FR-3. Tapping a project row navigates to the **Project detail** screen
(`projects/{projectId}`), which loads the project via
`GET /v1/projects/{projectId}/detail` and displays name, description, tags,
timestamps, and the Drive connection state (read from the provider-credentials
endpoint, since the project object itself carries no provider list — §16).

FR-4. The detail screen shows a **"Connect Google Drive"** action when no Drive
provider is connected for the project. Tapping it begins the server-mediated
OAuth flow: the app calls the provider `start` endpoint, receives an
authorization URL, and opens it in a Chrome Custom Tab.

FR-5. After the user authorizes in the browser, the backend redirects to the
app's registered deep link (`testlogon://projects/{projectId}/providers/google_drive/callback?...`).
The app forwards the callback parameters to the provider `callback` endpoint,
which finalizes the connection. On success the detail screen refreshes and shows
the Drive provider as connected.

FR-6. The detail screen renders detail-scoped loading/error/offline states
independently of the list, with a retry affordance.

FR-7. The provider flow is cancelable: dismissing the Custom Tab or returning
without a callback leaves the project unchanged (no partial provider record from
the app side; the backend treats an unfinished `start` as a no-op).

## 4. Technical Design

New module `feature-projects` with package
`com.testlogon.android.feature.projects`. Sub-packages: `data`, `domain`, `ui`,
`ui.detail`, `provider`.

Retrofit service (in `core-network`):

```kotlin
// CORRECTED (§16): paths are /v1/projects, not /ui/projects; the Drive OAuth
// start/callback are account-scoped (no {projectId} segment) and live under
// /v1/projects/providers/google_drive/oauth/{start,callback}. The detail read
// surface used by the web app is GET /v1/projects/{id}/detail (returns
// {project, files[], cursor}); GET /v1/projects/{id} returns a bare ProjectOut.
interface ProjectsApi {
    @GET("v1/projects")
    suspend fun listProjects(
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = 20,
    ): ProjectPageDto

    @GET("v1/projects/{projectId}")
    suspend fun getProject(
        @Path("projectId") projectId: String,
    ): ProjectDto

    // Detail used by the web reference (projects.ts: getProjectDetail).
    @GET("v1/projects/{projectId}/detail")
    suspend fun getProjectDetail(
        @Path("projectId") projectId: String,
        @Query("limit") limit: Int = 20,
        @Query("cursor") cursor: String? = null,
    ): ProjectDetailDto

    // Account-scoped (NOT per-project). Empty request body.
    @POST("v1/projects/providers/google_drive/oauth/start")
    suspend fun startGoogleDrive(): ProviderStartResponse

    @POST("v1/projects/providers/google_drive/oauth/callback")
    suspend fun completeGoogleDrive(
        @Body body: ProviderCallbackRequest,
    ): ProviderCredentialDto

    // Connected-provider status is read separately, not embedded in ProjectOut.
    @GET("v1/projects/providers/{provider}/credentials")
    suspend fun getProviderCredential(
        @Path("provider") provider: String,
        @Query("org") org: String? = null,
    ): ProviderCredentialDto
}
```

These calls reuse the AND-027 OkHttpClient (cookie jar + CSRF + refresh
authenticator). `listProjects`/`getProject` are idempotent GETs and eligible for
the bounded-backoff retry interceptor; the `start`/`callback` POSTs are **not**
retried automatically.

Repository:

```kotlin
class ProjectsRepository @Inject constructor(
    private val api: ProjectsApi,
    private val dao: ProjectDao,                 // Room cache (core-data)
    private val errorMapper: ApiErrorMapper,     // AND-027 detail mapping
    @IoDispatcher private val io: CoroutineDispatcher,
) {
    fun projectsPager(): Flow<PagingData<Project>>      // Paging 3 + cache
    fun observeProject(id: String): Flow<Project?>      // Room-backed, SWR
    suspend fun refreshProject(id: String): ApiResult<Project>
    // CORRECTED: Drive OAuth is account-scoped — no project id is sent to the
    // backend. completeGoogleDrive returns a ProviderCredential, not a Project;
    // the repo then re-reads the credentials/detail to refresh the screen.
    suspend fun startGoogleDrive(): ApiResult<ProviderStart>
    suspend fun completeGoogleDrive(
        params: ProviderCallbackParams,
    ): ApiResult<ProviderCredential>
    suspend fun isDriveConnected(): ApiResult<Boolean>   // via credentials GET
}
```

Paging uses a `RemoteMediator` (`ProjectsRemoteMediator`) over the Room cache so
the list survives reconnects (offline/stale per FR-2). Detail follows
stale-while-revalidate: `observeProject` emits the cached `Project` immediately,
`refreshProject` fetches and upserts.

ViewModels expose `StateFlow<UiState>`:

```kotlin
@HiltViewModel
class ProjectsListViewModel @Inject constructor(
    repo: ProjectsRepository,
) : ViewModel() {
    val items: Flow<PagingData<Project>> = repo.projectsPager().cachedIn(viewModelScope)
}

@HiltViewModel
class ProjectDetailViewModel @Inject constructor(
    private val repo: ProjectsRepository,
    savedState: SavedStateHandle,
) : ViewModel() {
    private val projectId: String = savedState["projectId"]!!
    val state: StateFlow<ProjectDetailUiState>
    fun retry()
    fun connectGoogleDrive()                 // -> emits LaunchAuth(url)
    fun onProviderCallback(params: ProviderCallbackParams)
}

sealed interface ProjectDetailUiState {
    data object Loading : ProjectDetailUiState
    data class Content(
        val project: Project,
        val isStale: Boolean,
        val connecting: Boolean,
        val launchAuthUrl: String? = null,   // one-shot, consumed by UI
    ) : ProjectDetailUiState
    data class Error(val message: String) : ProjectDetailUiState
}
```

Compose UI: `ProjectsListScreen` (LazyColumn + `collectAsLazyPagingItems()`,
`PullToRefreshBox`) and `ProjectDetailScreen`. Navigation routes are registered
in the authenticated nav graph (AND-024):
`projects` and `projects/{projectId}`.

Provider flow: `connectGoogleDrive()` calls `repo.startGoogleDrive(id)`, then
emits `launchAuthUrl`; the screen opens it via Custom Tabs:

```kotlin
fun openCustomTab(context: Context, url: String) {
    CustomTabsIntent.Builder().setShowTitle(true).build()
        .launchUrl(context, Uri.parse(url))
}
```

The deep link `testlogon://projects/{projectId}/providers/google_drive/callback`
is the app-internal route the Activity uses to resume the detail screen. NOTE
(§16): the `redirect_uri` actually registered with the backend Drive OAuth client
is NOT supplied by the `start` request (the request body is empty — see §5);
whatever redirect the backend uses must land back in the app. R2 in §13 captures
the open question of whether the backend supports a `testlogon://` redirect or
requires an https App Link bounce. The deep link is declared as a
`<nav-deep-link>` / intent filter on the single Activity; on
resume the Activity routes the `Uri` to the detail destination, which calls
`viewModel.onProviderCallback(parse(uri))` → `repo.completeGoogleDrive(...)` →
refresh.

## 5. API Contract

All paths are session-authenticated (cookies + `X-CSRF-Token`). The shapes below
have been reconciled against `reference/openapi.index.txt` /
`reference/openapi.pretty.json` (`components.schemas.*`) and the web reference
`reference/src/api/endpoints/projects.ts` + `types.ts`. Corrections vs. the
original draft are audited in §16.

**List** — `GET /v1/projects?cursor=&limit=20` (CORRECTED path: `/v1/`, not
`/ui/`). Returns `ProjectListOut`. Note the cursor field is `cursor`, **not**
`next_cursor`, and `ProjectOut` has **no** `providers[]` and **no** `status`
field:

```json
{
  "items": [
    {
      "id": "prj_01H...",
      "owner": "usr_01H...",
      "name": "Spring Campaign",
      "description": "Q2 assets",
      "tags": ["q2", "campaign"],
      "settings": {},
      "created_at": "2026-05-01T10:00:00Z",
      "updated_at": "2026-05-30T12:01:02Z"
    }
  ],
  "cursor": "eyJwayI6..."
}
```

**Detail** — two options exist; the web app uses
`GET /v1/projects/{projectId}/detail` (CORRECTED) which returns
`ProjectDetailOut` = `{ "project": ProjectOut, "files": TrackedFileOut[],
"cursor": string|null }`. `GET /v1/projects/{projectId}` returns a bare
`ProjectOut`. This ticket renders the project object; `files[]` belongs to the
Files epic (AND-336) and is ignored here.

**Drive start** — `POST /v1/projects/providers/google_drive/oauth/start`
(CORRECTED: account-scoped, no `{projectId}` in the path; OAuth lives under
`.../oauth/start`). The request body is **empty** (the OpenAPI index lists
`req=` for this op — there is no `redirect_uri` field). Response is
`ProviderOAuthStartOut`:

```json
{ "provider": "google_drive",
  "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth?...",
  "state": "st_9f2a...",
  "expires_at": "2026-06-06T12:10:00Z" }
```

(All four fields are `required`. The draft omitted `provider` and `expires_at`.)

**Drive callback** —
`POST /v1/projects/providers/google_drive/oauth/callback` (CORRECTED path)
request `ProviderOAuthCallbackIn` = `{ "code": "4/0Ax...", "state": "st_9f2a..."
}` (both required, 1..8192 chars). The response is `ProviderCredentialOut`
(CORRECTED — it does **not** return an updated project), shape:
`{ "provider": "google_drive", "org": null, "scopes": ["..."], "metadata": {},
"created_at": "...", "updated_at": "..." }`. There is no `account_email` or
`folder_id` field. If the deep link instead carries an error
(`?error=access_denied`), the app does **not** call `callback`; it surfaces a
cancel/denied message.

**Connected-provider status** — because `ProjectOut` carries no provider list,
the "is Drive connected" state is read via
`GET /v1/projects/providers/{provider}/credentials` (returns
`ProviderCredentialOut`; a 404 / error indicates not connected).

Moshi models (`core-model`):

```kotlin
// CORRECTED to match ProjectListOut / ProjectOut / ProviderOAuthStartOut /
// ProviderOAuthCallbackIn / ProviderCredentialOut (see §16).
@JsonClass(generateAdapter = true)
data class ProjectPageDto(
    @Json(name = "items") val items: List<ProjectDto> = emptyList(),
    @Json(name = "cursor") val cursor: String? = null,   // was next_cursor
)

@JsonClass(generateAdapter = true)
data class ProjectDto(
    val id: String,
    val owner: String,
    val name: String,
    val description: String? = null,
    val tags: List<String> = emptyList(),
    val settings: Map<String, Any?> = emptyMap(),
    @Json(name = "created_at") val createdAt: String,    // required by schema
    @Json(name = "updated_at") val updatedAt: String,    // required by schema
)
// NOTE: ProjectOut has no `status` and no `providers[]`. Removed ProviderDto
// (account_email/folder_id/connected do not exist on the project object).

@JsonClass(generateAdapter = true)
data class ProjectDetailDto(
    val project: ProjectDto,
    val files: List<Any> = emptyList(),   // TrackedFileOut[] — out of scope (AND-336)
    val cursor: String? = null,
)

// start request has NO body; no request DTO is needed.
@JsonClass(generateAdapter = true)
data class ProviderStartResponse(
    val provider: String,
    @Json(name = "authorization_url") val authorizationUrl: String,
    val state: String,
    @Json(name = "expires_at") val expiresAt: String,
)

@JsonClass(generateAdapter = true)
data class ProviderCallbackRequest(val code: String, val state: String)

// callback returns ProviderCredentialOut, NOT a project.
@JsonClass(generateAdapter = true)
data class ProviderCredentialDto(
    val provider: String,
    val org: String? = null,
    val scopes: List<String> = emptyList(),
    val metadata: Map<String, Any?> = emptyMap(),
    @Json(name = "created_at") val createdAt: String,
    @Json(name = "updated_at") val updatedAt: String,
)
```

Domain mappers convert `ProjectDto` to a `Project` domain type, and
`ProviderCredentialDto` (or a 404 from the credentials GET) to a
"Drive connected?" boolean used by ViewModels/UI. Error responses are mapped
through AND-027's `ApiErrorMapper` (FastAPI `detail`: string | `[{msg}]` |
`{code,message,details}`; the latter matches the `ErrorDetail` schema).

## 6. Data & State Management

- Room cache (`core-data`): `ProjectEntity` (PK `id`, columns mirroring the
  corrected DTO — `owner`, `name`, `description`, `tags` and `settings`
  serialized as JSON columns via Moshi `TypeConverter`s, `created_at`,
  `updated_at`; there is no `status`/`providers` column, per §16) and a
  `RemoteKeysEntity` (cursor) for the `RemoteMediator`. `ProjectDao` exposes
  `pagingSource()`, `observeById(id)`, `upsert`, `clearAll`, and a
  `RemoteKeysDao`.
- The list and detail share the Room cache (single source of truth). List paging
  is cache-backed (`RemoteMediator`); detail observes `observeById` for SWR.
- The OAuth `state` returned by `start` is held **in `SavedStateHandle`** of the
  `ProjectDetailViewModel` so it survives the Custom Tab excursion / process
  death, and is matched against the `state` in the callback before calling
  `completeGoogleDrive`. It is not persisted to DataStore/Room beyond
  SavedStateHandle's bundle.
- No Google token is stored anywhere on device — the backend holds Drive tokens.
- DataStore: no new persistent prefs required (last-viewed could be added later;
  out of scope here).
- Cache TTL/eviction follows the shared cache policy (AND-118); Projects sets a
  modest TTL and refreshes on screen entry.
- `launchAuthUrl` and provider-callback results are one-shot UI effects consumed
  via state-flag-reset (`onAuthLaunchHandled()`) to avoid re-launching on
  recomposition/config change.

## 7. Error Handling & Resilience

- All calls return `ApiResult<T>`; the UI maps `ApiResult.Error` to user copy via
  AND-027's mapper (FastAPI `detail`: string | `[{msg}]` | `{code,...}`).
- GET list/detail use the 20s timeout + bounded backoff (max 2 retries,
  exponential w/ jitter, base 500ms) for idempotent GETs only (AND-016). On
  failure with a cached copy present, the UI shows cached data + a stale banner
  (offline/stale state).
- `401` is handled transparently by the AND-027 authenticator (one refresh +
  retry); a second 401 surfaces a re-auth path (logout/login) rather than a
  Projects-specific error.
- Provider `start`/`callback` POSTs are **not** auto-retried (non-idempotent).
  Failures show an inline error with a manual "Try again".
- Deep-link callback robustness: validate `state` matches the stored value
  (CSRF/replay protection); if it mismatches or is missing, abort without
  calling `callback` and show a "Connection couldn't be verified" message. If the
  link carries `error=access_denied`/user cancel, show a neutral "Connection
  canceled" message.
- Custom Tab dismissal without callback leaves state `Content(connecting=false)`.
- Error mapper helper:

```kotlin
fun ApiResult.Error.toProjectsMessage(): String = when (this) {
    is ApiResult.Error.Network -> "You're offline. Showing saved projects."
    is ApiResult.Error.Timeout -> "The server is slow to respond. Try again."
    is ApiResult.Error.Http    -> detailMessage ?: "Couldn't load projects (${code})."
    is ApiResult.Error.Unknown -> "Something went wrong."
}
```

## 8. Security & Privacy

- Server-mediated OAuth: the app never holds a Google client secret or Google
  access/refresh token. The backend performs the code-for-token exchange.
- CSRF/replay: the `state` value from `start` is validated against the callback
  `state` before `completeGoogleDrive`. Mismatch aborts the flow.
- The deep-link scheme `testlogon://` callback is handled only by the app's
  single Activity; the `code`/`state` are read once and not logged.
- TestLogon session cookies + `X-CSRF-Token` ride on the Projects calls via the
  shared OkHttpClient (AND-027); the Custom Tab is a separate browser context and
  does not receive the app's cookie jar.
- Cleartext: Projects calls go to the dev host over plaintext HTTP, permitted
  only because network-security-config scopes cleartext to `18.222.237.167`. The
  Google authorization URL is HTTPS (opened in the browser).
- No tokens, `code`, or `state` are written to logs, crash reports, or analytics
  (see §10). NOTE (§16): the corrected contract exposes no `account_email`/
  `folder_id` on the project or credential objects, so there is no provider email
  rendered or logged; if a future provider response adds an email it must be
  treated as PII (not logged).

## 9. Accessibility & i18n

- All copy in `res/values/strings.xml`:
  `projects_title`, `projects_empty`, `projects_error`, `projects_offline_banner`,
  `project_detail_title`, `project_connect_drive`, `project_drive_connected`,
  `project_connect_canceled`, `project_connect_unverified`. Provider/connect
  state strings are formatted resources (no concatenation).
- List rows expose a combined `contentDescription` (name, status, "Drive
  connected" when applicable); provider/status icons are decorative
  (`contentDescription = null`).
- Min 48dp touch targets for rows and the connect button; pull-to-refresh and the
  detail retry are TalkBack-operable.
- Dates formatted via locale-aware `DateUtils.getRelativeTimeSpanString`; no
  hardcoded formats. RTL-ready layouts (start/end paddings). Status is conveyed by
  text + icon, not color alone.

## 10. Telemetry & Logging

- Analytics via the `core-data` analytics facade:
  `projects_list_viewed`, `project_detail_opened` (prop: `has_drive` boolean),
  `drive_connect_started`, `drive_connect_succeeded` (prop: duration ms),
  `drive_connect_canceled`, `drive_connect_failed` (prop: reason category).
- Never log/emit project ids beyond an opaque hash if needed, never log
  `account_email`, OAuth `code`, or `state`.
- Debug-only `Timber` around state transitions; the logging interceptor
  (AND-009) redacts cookies, `X-CSRF-Token`, and any `code`/`state` query params.
  No verbose logging in release.

## 11. Testing Strategy

Unit (JVM, `core-testing` + MockWebServer):
- `ProjectsApi` deserialization: `ProjectPageDto` maps `items` + `cursor`
  (CORRECTED from `next_cursor`); `ProjectDto` maps snake_case fields
  (`created_at`/`updated_at` required, `description` optional, `tags`/`settings`
  present). No `status`/`providers` on the project (§16).
- `ProjectsRepository`: list happy path upserts cache and returns paged data;
  `getProject` SWR emits cache then refreshed value; error path returns mapped
  `ApiResult.Error` and preserves cached data.
- `startGoogleDrive` returns `provider`+`authorization_url`+`state`+`expires_at`;
  `completeGoogleDrive` posts `code`+`state` and returns a `ProviderCredential`
  (CORRECTED — not an updated project); the screen then re-reads the credentials
  endpoint to flip "Drive connected".
- `state` mismatch in callback aborts without calling `completeGoogleDrive`.
- Idempotent-GET retry/backoff applies to list/detail; POSTs are not retried.
- `toProjectsMessage` covers network/timeout/http/unknown.

ViewModel (`kotlinx-coroutines-test`, Turbine):
- `ProjectDetailViewModel` state machine: `Loading → Content`, retry on error,
  `connectGoogleDrive` emits `launchAuthUrl` (consumed once), `onProviderCallback`
  → `connecting=true` → refreshed `Content` with Drive connected.

Instrumented/UI (Compose test):
- List renders paged items from a fake `PagingSource`; empty/error/offline
  states render; tapping a row navigates to detail (nav controller assertion).
- Detail renders project + providers; "Connect Google Drive" triggers the
  launch effect (Custom Tab launch faked); a simulated deep-link callback updates
  the screen to "Drive connected".

Acceptance verification:
- **Projects render**: instrumented test with MockWebServer-stubbed `GET
  /v1/projects` shows the list populated. (Maps to ticket: *Projects render*.)
- **Detail opens**: tapping a row navigates to `projects/{id}` and renders the
  stubbed `GET /v1/projects/{id}/detail`. (Maps to ticket: *detail opens*.)
- Manual QA: full Drive `start`/Custom Tab/`callback` round-trip against the dev
  backend with a real Google account.

## 12. Dependencies & Sequencing

- **Hard dependency: AND-027 — AuthApi (session endpoints)** (P0). Provides the
  cookie jar, CSRF interceptor, 401-refresh authenticator, `ApiResult`, and
  FastAPI `detail` error mapping that all Projects calls reuse. Projects cannot be
  wired until AND-027 (and its transitive HTTP/session core) is in place.
- Indirect: `core-ui` state composables (AND-021), authenticated nav graph
  (AND-024) for route registration, idempotent-GET retry (AND-016), cache TTL
  policy (AND-118). These are expected present in M8; if AND-024 lacks a Projects
  entry, this ticket adds the routes.
- Gradle: add `androidx.browser:browser:1.8.0`; register the `testlogon://`
  callback intent filter / nav deep link on the single Activity; keep cleartext
  scoped to the dev host in network-security-config.
- Sequencing: implement `ProjectsApi` + DTOs + mappers (unit-testable) → Room
  cache + `RemoteMediator` + repository → list ViewModel/screen → detail
  ViewModel/screen → Drive `start`/`callback` provider flow + deep link.
- Blocks: nothing in the provided backlog (`blocks: []`). File import from a
  connected Drive provider is a separate concern owned by the Files epic
  (AND-336) and is explicitly out of scope here.

## 13. Risks & Open Questions

- R1: RESOLVED in this review (§16). Paths are `/v1/projects*`; Drive OAuth is
  account-scoped under `/v1/projects/providers/google_drive/oauth/{start,callback}`;
  list cursor field is `cursor` (not `next_cursor`); `ProjectOut` carries no
  `status`/`providers`; callback returns `ProviderCredentialOut`. Contract in §5
  updated accordingly.
- R2: Deep-link redirect URI registration — the backend's allowed `redirect_uri`
  for the Drive OAuth client must include the app scheme
  `testlogon://.../callback`. If the backend only supports an https redirect, we
  need an App Link / intermediate redirect. OPEN: confirm redirect strategy with
  backend.
- R3: `state` lifetime across process death — held in `SavedStateHandle`; verify
  it survives the Custom Tab excursion on low-memory devices, else fall back to a
  short-lived encrypted DataStore entry keyed by project.
- R4: RESOLVED (§16). Pagination is cursor-based; the response field is `cursor`
  (opaque) and the request takes `cursor`+`limit`. `ProjectsApi`/`RemoteMediator`
  use `cursor` (not `next_cursor`).
- R5: Provider model generality — current scope is Google Drive only; the
  `kind`-keyed model leaves room for future providers without a redesign.
- R6: Cancel semantics — confirm an abandoned `start` requires no server cleanup
  (assumed no-op until `callback`).

## 14. Acceptance Criteria

AC-1. The Projects list screen loads the user's projects via `GET /v1/projects`,
renders rows (name, description, tags, updated time) with Paging 3, and
shows correct loading/empty/error/offline states. (Maps to ticket: **Projects
render**.) (CORRECTED §16: `/v1/projects`; no status/provider chips on rows.)

AC-2. Tapping a project row navigates to `projects/{projectId}` and the detail
screen loads and displays the project via `GET /v1/projects/{projectId}/detail`.
(Maps to ticket: **detail opens**.) (CORRECTED §16: `/v1/.../detail`.)

AC-3. On the detail screen with no Drive provider connected, "Connect Google
Drive" calls `POST /v1/projects/providers/google_drive/oauth/start` (empty body),
opens the returned `authorization_url` in a Custom Tab, and on the deep-link
callback posts `code`+`state` to
`POST /v1/projects/providers/google_drive/oauth/callback`; on success
(`ProviderCredentialOut`) the screen re-reads connection state and shows the
Drive provider connected. (CORRECTED §16: account-scoped OAuth paths; callback
returns a credential, not a project.)

AC-4. The callback `state` is validated against the stored `start` `state`;
mismatch/missing aborts without calling `callback` and shows a verification
error. A user-canceled/`access_denied` redirect shows a neutral canceled message
and leaves the project unchanged.

AC-5. DTO ↔ domain Moshi mapping is unit-tested, including snake_case fields,
absent optionals, and a `providers[]` entry; `ApiResult.Error` paths map to user
copy via AND-027's `detail` mapper.

AC-6. List/detail GETs use 20s timeout + bounded retry for idempotent GETs and
fall back to cached data with a stale banner when offline; `start`/`callback`
POSTs are not auto-retried.

AC-7. No Google token, OAuth `code`, `state`, or `account_email` is written to
logs/crash reports/analytics; TestLogon session cookies/CSRF are not leaked to
the Custom Tab; cleartext stays scoped to the dev host.

## 15. Definition of Done

- AC-1..AC-7 met and demonstrated by the acceptance instrumented tests (list
  renders, detail opens) plus a manual QA run of the Drive start/callback
  round-trip against the dev backend.
- Code merged to `android-port` under `feature-projects` (package
  `com.testlogon.android.feature.projects`), `ProjectsApi` in `core-network`, and
  DTO/domain models in `core-model`; layering `app -> feature-projects -> core-*`
  respected and the AND-027 HTTP/session stack reused (no duplicate cookie
  jar/CSRF/refresh).
- Unit + ViewModel + Compose UI tests green in CI; coverage for repository,
  mapping, error mapper, paging/cache, state machine, and state validation.
- `androidx.browser` pinned to the §2 version; `testlogon://` callback deep link
  registered; network-security-config keeps cleartext scoped to the dev host; R8
  keeps Projects Moshi models.
- All strings externalized; TalkBack pass on list and detail; no token/PII in
  telemetry or logs (redaction verified).
- Open questions R1/R2/R4 resolved against `/openapi.json` + backend, or
  explicitly deferred with an owner; spec `status` advanced from `draft`.

## 16. Citations & Assumption Audit

Sources are exact pointers. OpenAPI index = `reference/openapi.index.txt`;
OpenAPI spec = `reference/openapi.pretty.json` (`components.schemas.*`); frontend
= `reference/src/...`.

1. **Projects list path is `GET /v1/projects` (not `/ui/projects`).**
   VERDICT: Corrected. SOURCE: OpenAPI `GET /v1/projects | resp=200:ProjectListOut`;
   `src/api/endpoints/projects.ts: listProjects` (`api.get("/v1/projects")`).

2. **Project detail used by the web app is `GET /v1/projects/{project_id}/detail`
   returning `ProjectDetailOut = {project, files[], cursor}`; a bare
   `GET /v1/projects/{project_id}` returns `ProjectOut`.**
   VERDICT: Corrected (draft used `/ui/projects/{id}` and claimed the detail
   equals a list item). SOURCE: OpenAPI `GET /v1/projects/{project_id}/detail |
   resp=200:ProjectDetailOut` and `GET /v1/projects/{project_id} |
   resp=200:ProjectOut`; `projects.ts: getProjectDetail` / `getProject`;
   schema `ProjectDetailOut` (`project`, `files`, `cursor`).

3. **List pagination field is `cursor`, not `next_cursor`; request params are
   `cursor` + `limit`.** VERDICT: Corrected. SOURCE: schema `ProjectListOut`
   (`items`, `cursor`); `src/api/types.ts: ProjectListResp` (`items`, `cursor`);
   OpenAPI index params `limit,cursor` on `GET /v1/projects`.

4. **`ProjectOut` has fields `id, owner, name, description?, tags[], settings{},
   created_at, updated_at` — and NO `status`, NO `providers[]`.**
   VERDICT: Corrected (draft added `status` and an embedded `providers[]`).
   SOURCE: schema `ProjectOut` (required `id, owner, name, created_at,
   updated_at`); `src/api/types.ts: Project`.

5. **Per-project provider chips / `connected`/`account_email`/`folder_id` do not
   exist on the project object.** VERDICT: Corrected. SOURCE: schema `ProjectOut`
   (no such fields); connection state instead comes from
   `GET /v1/projects/providers/{provider}/credentials` → `ProviderCredentialOut`.

6. **Drive OAuth start = `POST /v1/projects/providers/google_drive/oauth/start`
   with an EMPTY request body (no `redirect_uri`).** VERDICT: Corrected (draft
   used `/ui/projects/{id}/providers/google_drive/start` with a `redirect_uri`
   body). SOURCE: OpenAPI index `POST /v1/projects/providers/google_drive/oauth/start
   | req= | resp=200:ProviderOAuthStartOut` (empty `req`).

7. **`ProviderOAuthStartOut` = `{provider, authorization_url, state, expires_at}`
   (all required).** VERDICT: Corrected (draft returned only
   `authorization_url` + `state`). SOURCE: schema `ProviderOAuthStartOut`.

8. **Drive OAuth callback = `POST /v1/projects/providers/google_drive/oauth/callback`,
   request `ProviderOAuthCallbackIn = {code, state}` (both required, 1..8192),
   response `ProviderCredentialOut` (NOT a project).** VERDICT: Corrected (draft
   path was `/ui/projects/{id}/.../callback` and claimed an updated project
   response). SOURCE: OpenAPI index `POST .../oauth/callback |
   req=ProviderOAuthCallbackIn | resp=200:ProviderCredentialOut`; schemas
   `ProviderOAuthCallbackIn`, `ProviderCredentialOut`.

9. **The Drive OAuth start/callback are account-scoped — there is no
   `{project_id}` segment in the path.** VERDICT: Corrected. SOURCE: OpenAPI
   index lines for `/v1/projects/providers/google_drive/oauth/{start,callback}`
   (no path param; `params=user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN`).

10. **`ProviderCredentialOut` = `{provider, org?, scopes[], metadata{},
    created_at, updated_at}` — no `account_email`/`folder_id`.** VERDICT:
    Corrected. SOURCE: schema `ProviderCredentialOut`; `src/api/types.ts:
    ProviderCredential`.

11. **The web app's account-level Drive integration (`/ui/integrations/google-drive/*`)
    is a SEPARATE flow from the project-provider OAuth and is out of scope here.**
    VERDICT: Verified. SOURCE: `src/api/endpoints/googleDrive.ts`
    (`initiateGoogleDriveConnect` → `/ui/integrations/google-drive/connect`,
    `completeGoogleDriveConnect` → `/ui/integrations/google-drive/callback`);
    OpenAPI index lines 1521-1526. This ticket targets the project-provider OAuth
    endpoints (items 6-8), matching the ticket scope "Google Drive provider
    start/callback".

12. **Auth/CSRF/refresh transport (AND-027): CSRF is read from the `ui_csrf`
    cookie and sent as `X-CSRF-Token`; cookies via `credentials: include`; a 401
    triggers one `POST /ui/session/refresh` then a single retry.** VERDICT:
    Verified. SOURCE: `src/api/client.ts` (CSRF `getCookie("ui_csrf")` →
    `X-CSRF-Token`, lines 168-171; `refreshSession()` → `/ui/session/refresh`,
    line 122; single-flight 401 refresh + retry, lines 204-237).

13. **FastAPI error `detail` mapping handles string | array of `{msg}` |
    object `{code, message, details}`.** VERDICT: Verified. SOURCE:
    `src/api/client.ts: normalizeErrorDetail` (lines 66-102) + `mapAuthorizationError`;
    schemas `HTTPValidationError` (`detail: ValidationError[]` with `msg`) and
    `ErrorDetail` (`code`, `message`, `details?`).

14. **Projects endpoints document `422:HTTPValidationError` for validation
    errors.** VERDICT: Verified. SOURCE: OpenAPI index — every `/v1/projects*`
    line lists `resp=...;422:HTTPValidationError`. (Note: unlike many other
    endpoints these lines do NOT enumerate `ErrorEnvelope`; runtime 401/403/404/5xx
    still occur and are mapped via AND-027 by status + `detail`.)

15. **Cleartext dev host `http://18.222.237.167:8000`.** VERDICT:
    Unverified-assumption (carried from AND-027/§2; not derivable from the
    reference sources, which use a build-time `VITE_API_BASE_URL`). SOURCE:
    framework ref — Android `network-security-config`
    (https://developer.android.com/privacy-and-security/security-config); host
    value must be confirmed with the backend/AND-027.

16. **Chrome Custom Tabs (`androidx.browser:browser:1.8.0`) for the OAuth
    redirect.** VERDICT: Unverified-assumption (Android framework choice; not in
    the reference sources). SOURCE: framework ref — Custom Tabs
    (https://developer.android.com/develop/ui/views/layout/webapps/customtabs).

17. **App deep link `testlogon://projects/{projectId}/providers/google_drive/callback`
    as the post-OAuth landing route.** VERDICT: Unverified-assumption — the
    `start` request sends no `redirect_uri`, so the backend-registered redirect
    is unknown from the sources (see R2). SOURCE: framework ref — Navigation deep
    links (https://developer.android.com/guide/navigation/navigation-deep-link).

### Corrections made

- C1: List/detail/OAuth base path `/ui/projects*` → `/v1/projects*` (§4, §5, §6,
  §11, §14 AC-1/AC-2/AC-3). [items 1, 2, 6, 8, 9]
- C2: Detail endpoint set to `/v1/projects/{id}/detail` (`ProjectDetailOut`); the
  bare project GET returns `ProjectOut`. [item 2]
- C3: List cursor field `next_cursor` → `cursor`; DTO/RemoteMediator updated.
  [item 3]
- C4: Removed non-existent `status` and embedded `providers[]`/`ProviderDto`
  (`connected`/`account_email`/`folder_id`) from `ProjectDto`; added real fields
  `owner`, `tags`, `settings`; `created_at`/`updated_at` made required. [items 4,
  5, 10]
- C5: Drive OAuth made account-scoped (`/v1/projects/providers/google_drive/oauth/
  {start,callback}`); `start` request body removed (empty); `start` response
  expanded to `{provider, authorization_url, state, expires_at}`; callback
  response corrected to `ProviderCredentialOut`. [items 6, 7, 8, 9, 10]
- C6: Repository/ViewModel/connection-state design reworked to read
  connection via the provider-credentials GET (since the project carries no
  provider list). [item 5]
- C7: §8 security and AC-7 de-referenced `account_email` (field does not exist).
  [item 10]
- C8: §13 R1 and R4 marked RESOLVED with the verified contract.

### Open assumptions

- A1 (item 15): Dev host + cleartext scope inherited from AND-027/§2; not present
  in the reference sources (web build uses `VITE_API_BASE_URL`). Confirm with
  backend/AND-027 before pinning `network-security-config`.
- A2 (items 16-17, R2): The backend-registered OAuth `redirect_uri` is unknown —
  `start` sends no redirect and the sources show only the web flow. Whether a
  `testlogon://` app scheme is accepted, or an https App Link bounce is required,
  must be confirmed with the backend. Custom Tabs + deep-link routing are Android
  framework choices, not contract-derived.
- A3 (R3): `state` survival across process death during the Custom Tab excursion
  is a device-runtime behavior, verifiable only by instrumented test (see §17),
  not by the static sources.
- A4 (R6): Whether an abandoned `start` needs server cleanup is not specified by
  the OpenAPI (no documented side effect); assumed no-op until `callback`.

## 17. Test Plan

IDs `TC-AND-374-NN`. "Traces" link to §14 acceptance criteria. Test targets:
JVM/Robolectric (local), emulator AVD `test35` (API 35 x86_64), or the physical
**Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a)**.
Most cases run on JVM or the emulator; cases needing a real Chrome Custom Tab /
real browser OAuth redirect handoff MUST run on the physical device.

- **TC-AND-374-01** — Type: contract/MockWebServer (JVM). Target: JVM unit.
  Preconditions: MockWebServer queued with a `ProjectListOut` body (2 items,
  `cursor` set; `ProjectOut` with `owner/tags/settings`, no `status`/`providers`).
  Steps: call `ProjectsApi.listProjects(cursor=null, limit=20)`; assert request
  line is `GET /v1/projects?...limit=20`. Expected: `ProjectPageDto` maps `items`
  + `cursor` (NOT `next_cursor`); each `ProjectDto` has `owner`, `tags`,
  `settings`, required `createdAt/updatedAt`; deserialization does not fail on the
  absent `status`/`providers`. Traces: AC-1, AC-5.

- **TC-AND-374-02** — Type: contract/MockWebServer (JVM). Target: JVM unit.
  Preconditions: MockWebServer queued with `ProjectDetailOut`
  (`{project, files:[...], cursor}`). Steps: call
  `getProjectDetail(projectId, limit=20)`; assert path
  `GET /v1/projects/{id}/detail`. Expected: `ProjectDetailDto.project` maps to a
  `ProjectDto`; `files[]` is ignored by the domain mapper (AND-336 scope). Traces:
  AC-2, AC-5.

- **TC-AND-374-03** — Type: unit (JVM). Target: JVM unit. Preconditions: fake API
  returning a `ProjectListOut` page then a second page. Steps: drive
  `ProjectsRepository.projectsPager()` through `RemoteMediator` LOAD/APPEND.
  Expected: items upserted into the Room cache (single source of truth); the
  `cursor` from page 1 is used as the next request's `cursor` query; APPEND with a
  null `cursor` ends pagination. Traces: AC-1, AC-6.

- **TC-AND-374-04** — Type: unit (JVM/Robolectric). Target: JVM unit.
  Preconditions: cached project present in Room; API set to fail (IOException).
  Steps: collect `observeProject(id)` then call `refreshProject(id)`. Expected:
  cached `Project` emitted immediately (SWR); on refresh failure the cached value
  is preserved and an `ApiResult.Error.Network` is returned and mapped to "You're
  offline. Showing saved projects." (stale banner). Traces: AC-6.

- **TC-AND-374-05** — Type: contract/MockWebServer (JVM). Target: JVM unit.
  Preconditions: MockWebServer queued with `ProviderOAuthStartOut`
  (`provider, authorization_url, state, expires_at`). Steps: call
  `startGoogleDrive()`; inspect the request. Expected: request is
  `POST /v1/projects/providers/google_drive/oauth/start` with an EMPTY body and no
  `redirect_uri`; response maps all four fields incl. `expiresAt`. Traces: AC-3.

- **TC-AND-374-06** — Type: contract/MockWebServer (JVM). Target: JVM unit.
  Preconditions: MockWebServer queued with `ProviderCredentialOut`. Steps: call
  `completeGoogleDrive(ProviderCallbackParams(code, state))`. Expected: request is
  `POST /v1/projects/providers/google_drive/oauth/callback` with body
  `{code, state}`; response maps to `ProviderCredentialDto` (NOT a project); the
  POST is NOT auto-retried on 5xx (one attempt only). Traces: AC-3, AC-6.

- **TC-AND-374-07** — Type: unit (JVM). Target: JVM unit. Preconditions: stored
  `start` `state = "st_A"` in `SavedStateHandle`; callback `Uri` carries
  `state = "st_B"`. Steps: call `onProviderCallback(parse(uri))`. Expected: state
  mismatch aborts WITHOUT calling `completeGoogleDrive` (verify no MockWebServer
  request); UI shows the "Connection couldn't be verified" message. Repeat with
  `?error=access_denied`: no callback POST, neutral "Connection canceled" message,
  project unchanged. Traces: AC-4.

- **TC-AND-374-08** — Type: unit (JVM). Target: JVM unit. Preconditions: build
  each `ApiResult.Error` subtype (Network, Timeout, Http with/without
  `detailMessage`, Unknown), plus error bodies for the three FastAPI `detail`
  shapes (string; `[{msg}]` 422 `HTTPValidationError`; `{code,message,details}`
  `ErrorDetail`). Steps: run `toProjectsMessage()` and the AND-027 mapper.
  Expected: each maps to the documented copy; the 422 array yields joined `msg`
  strings; `{code,message}` yields `message`. Traces: AC-5.

- **TC-AND-374-09** — Type: unit/ViewModel (kotlinx-coroutines-test + Turbine).
  Target: JVM unit. Preconditions: fake repo. Steps: collect
  `ProjectDetailViewModel.state`: `Loading → Content`; on error then `retry()` →
  `Content`; `connectGoogleDrive()` emits `launchAuthUrl` exactly once (consumed
  via `onAuthLaunchHandled()`, not re-emitted on recomposition);
  `onProviderCallback` → `connecting=true` → refreshed `Content` with Drive shown
  connected. Expected: state machine matches; `launchAuthUrl` is a one-shot.
  Traces: AC-2, AC-3, AC-4.

- **TC-AND-374-10** — Type: Compose-UI (instrumented). Target: emulator `test35`.
  Preconditions: fake `PagingSource`/MockWebServer stub for `GET /v1/projects`.
  Steps: render `ProjectsListScreen`; assert populated rows (name, description,
  tags, updated time); then drive empty, error (with retry), and offline/stale
  (cached + banner) states. Expected: all four state renders correct; rows expose
  no status/Drive chip. Traces: AC-1, AC-6.

- **TC-AND-374-11** — Type: Compose-UI / integration (instrumented). Target:
  emulator `test35`. Preconditions: MockWebServer stubs for
  `GET /v1/projects` and `GET /v1/projects/{id}/detail`. Steps: tap a row; assert
  the NavController navigates to `projects/{id}` and the detail screen renders the
  stubbed project. Expected: detail opens and displays name/description/tags/
  timestamps. Traces: AC-2 (acceptance: "Projects render" + "detail opens").

- **TC-AND-374-12** — Type: Compose-UI (instrumented). Target: emulator `test35`.
  Preconditions: detail screen, Drive not connected; Custom Tab launch faked;
  MockWebServer stubs for `start`, then a simulated deep-link callback Uri with a
  matching `state`, then the `callback` + credentials read. Steps: tap "Connect
  Google Drive" → assert the launch effect fires with the `authorization_url`;
  deliver the deep link → assert `code/state` posted to the callback endpoint and
  the screen flips to "Drive connected". Expected: full faked round-trip updates
  the UI. Traces: AC-3, AC-4.

- **TC-AND-374-13** — Type: instrumented/e2e. Target: **physical device
  (SM-A156U)** — REQUIRED. Rationale: needs a real Chrome Custom Tab and real
  browser→app deep-link handoff (process may be backgrounded/killed during the
  excursion), which the headless emulator cannot exercise faithfully.
  Preconditions: dev backend reachable; a real Google account for authorization;
  `testlogon://` intent filter installed. Steps: tap "Connect Google Drive",
  authorize in the Custom Tab, allow the redirect back to the app; also run a
  low-memory variant (force-stop / "Don't keep activities") to verify the `start`
  `state` survives via `SavedStateHandle`. Expected: callback posts `code/state`,
  Drive shows connected; on cancel/back the project is unchanged; `state`
  validated across process death (R3). Traces: AC-3, AC-4.

- **TC-AND-374-14** — Type: instrumented security + redaction. Target: emulator
  `test35` (logging) + cross-check on physical device for the Custom Tab cookie
  boundary. Preconditions: logging interceptor (AND-009) enabled; run the
  start/callback flow. Steps: capture Logcat / interceptor output and the Custom
  Tab request. Expected: no `code`, `state`, session cookie, or `X-CSRF-Token`
  appears in logs/analytics; the Custom Tab (separate browser context) does NOT
  receive the app's cookie jar; cleartext stays scoped to the dev host while the
  Google authorization URL is HTTPS. Traces: AC-7.

- **TC-AND-374-15** — Type: Compose-UI accessibility (instrumented). Target:
  emulator `test35`. Preconditions: list + detail rendered. Steps: run TalkBack /
  semantics assertions. Expected: list rows expose a combined `contentDescription`
  (name + updated time; status/provider icons absent or decorative
  `contentDescription=null`); pull-to-refresh, detail retry, and "Connect Google
  Drive" are TalkBack-operable with ≥48dp touch targets; dates use locale-aware
  formatting; status conveyed by text+icon (no color-only). Traces: AC-1, AC-2,
  AC-3.

### Coverage matrix

| AC   | Covered by |
|------|------------|
| AC-1 | TC-01, TC-03, TC-10, TC-15 |
| AC-2 | TC-02, TC-09, TC-11, TC-15 |
| AC-3 | TC-05, TC-06, TC-09, TC-12, TC-13, TC-15 |
| AC-4 | TC-07, TC-09, TC-12, TC-13 |
| AC-5 | TC-01, TC-02, TC-08 |
| AC-6 | TC-03, TC-04, TC-06, TC-10 |
| AC-7 | TC-14 |
