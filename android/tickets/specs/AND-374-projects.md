---
id: AND-374
title: Projects
milestone: M8
epic: E48
priority: P2
size: M
status: draft
depends_on: [AND-027]
blocks: []
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
row shows the project name, a short description/status, the project's connected
provider chips (e.g. a Drive icon when connected), and updated time. The list is
paged (Paging 3) and supports pull-to-refresh.

FR-2. The list renders the standard state set from `core-ui` (AND-021 family):
loading (shimmer/spinner), populated, **empty** ("No projects yet"), **error**
(with retry), and **offline/stale** (cached data with a stale banner when the
backend is unreachable).

FR-3. Tapping a project row navigates to the **Project detail** screen
(`projects/{projectId}`), which loads the full project and displays name,
description, status, timestamps, and the list of connected storage providers.

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
interface ProjectsApi {
    @GET("ui/projects")
    suspend fun listProjects(
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = 20,
    ): ProjectPageDto

    @GET("ui/projects/{projectId}")
    suspend fun getProject(
        @Path("projectId") projectId: String,
    ): ProjectDto

    @POST("ui/projects/{projectId}/providers/google_drive/start")
    suspend fun startGoogleDrive(
        @Path("projectId") projectId: String,
        @Body body: ProviderStartRequest,
    ): ProviderStartResponse

    @POST("ui/projects/{projectId}/providers/google_drive/callback")
    suspend fun completeGoogleDrive(
        @Path("projectId") projectId: String,
        @Body body: ProviderCallbackRequest,
    ): ProjectDto
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
    suspend fun startGoogleDrive(id: String): ApiResult<ProviderStart>
    suspend fun completeGoogleDrive(
        id: String, params: ProviderCallbackParams,
    ): ApiResult<Project>
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
is declared as a `<nav-deep-link>` / intent filter on the single Activity; on
resume the Activity routes the `Uri` to the detail destination, which calls
`viewModel.onProviderCallback(parse(uri))` → `repo.completeGoogleDrive(...)` →
refresh.

## 5. API Contract

All paths are session-authenticated (cookies + `X-CSRF-Token`). Exact paths and
field names are reconciled against `/openapi.json` and
`frontend/src/api/endpoints/projects.ts` during implementation; the shapes below
are the contract this ticket targets.

**List** — `GET /ui/projects?cursor=&limit=20`:

```json
{
  "items": [
    {
      "id": "prj_01H...",
      "name": "Spring Campaign",
      "description": "Q2 assets",
      "status": "active",
      "providers": [
        { "kind": "google_drive", "connected": true,
          "account_email": "user@example.com", "folder_id": "1AbC..." }
      ],
      "created_at": "2026-05-01T10:00:00Z",
      "updated_at": "2026-05-30T12:01:02Z"
    }
  ],
  "next_cursor": "eyJwayI6..."
}
```

**Detail** — `GET /ui/projects/{projectId}` → a single project object (same
shape as a list `items[]` element).

**Drive start** — `POST /ui/projects/{projectId}/providers/google_drive/start`
request `{ "redirect_uri": "testlogon://projects/{id}/providers/google_drive/callback" }`
response:

```json
{ "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth?...",
  "state": "st_9f2a..." }
```

**Drive callback** —
`POST /ui/projects/{projectId}/providers/google_drive/callback` request
`{ "code": "4/0Ax...", "state": "st_9f2a..." }` → the updated `ProjectDto` with
`providers[].connected == true`. If the deep link instead carries an error
(`?error=access_denied`), the app does **not** call `callback`; it surfaces a
cancel/denied message.

Moshi models (`core-model`):

```kotlin
@JsonClass(generateAdapter = true)
data class ProjectPageDto(
    @Json(name = "items") val items: List<ProjectDto>,
    @Json(name = "next_cursor") val nextCursor: String?,
)

@JsonClass(generateAdapter = true)
data class ProjectDto(
    val id: String,
    val name: String,
    val description: String? = null,
    val status: String? = null,
    val providers: List<ProviderDto> = emptyList(),
    @Json(name = "created_at") val createdAt: String? = null,
    @Json(name = "updated_at") val updatedAt: String? = null,
)

@JsonClass(generateAdapter = true)
data class ProviderDto(
    val kind: String,                       // "google_drive"
    val connected: Boolean = false,
    @Json(name = "account_email") val accountEmail: String? = null,
    @Json(name = "folder_id") val folderId: String? = null,
)

@JsonClass(generateAdapter = true)
data class ProviderStartRequest(@Json(name = "redirect_uri") val redirectUri: String)

@JsonClass(generateAdapter = true)
data class ProviderStartResponse(
    @Json(name = "authorization_url") val authorizationUrl: String,
    val state: String,
)

@JsonClass(generateAdapter = true)
data class ProviderCallbackRequest(val code: String, val state: String)
```

Domain mappers convert `ProjectDto`/`ProviderDto` to `Project`/`Provider`
(`core-model` domain types) used by ViewModels/UI. Error responses are mapped
through AND-027's `ApiErrorMapper` (FastAPI `detail`).

## 6. Data & State Management

- Room cache (`core-data`): `ProjectEntity` (PK `id`, columns mirroring the DTO;
  `providers` serialized as a JSON column via a Moshi `TypeConverter`) and a
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
- No tokens, `code`, `state`, or account emails are written to logs, crash
  reports, or analytics (see §10). `account_email` is shown in UI but treated as
  PII (not logged).

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
- `ProjectsApi` deserialization: `ProjectPageDto` maps `items` + `next_cursor`;
  `ProjectDto` maps snake_case fields and a `providers[]` with `google_drive`;
  absent optionals (`description`, `status`, `account_email`) tolerated.
- `ProjectsRepository`: list happy path upserts cache and returns paged data;
  `getProject` SWR emits cache then refreshed value; error path returns mapped
  `ApiResult.Error` and preserves cached data.
- `startGoogleDrive` returns `authorization_url` + `state`; `completeGoogleDrive`
  posts `code`+`state` and returns the updated project with
  `providers[kind=google_drive].connected == true`.
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
  /ui/projects` shows the list populated. (Maps to ticket: *Projects render*.)
- **Detail opens**: tapping a row navigates to `projects/{id}` and renders the
  stubbed `GET /ui/projects/{id}`. (Maps to ticket: *detail opens*.)
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

- R1: Exact endpoint paths and field names must be confirmed against
  `/openapi.json` and `projects.ts` — the web app may namespace Drive under a
  generic `providers/{kind}/...` route or use different body keys. OPEN: verify
  before freezing the contract in §5.
- R2: Deep-link redirect URI registration — the backend's allowed `redirect_uri`
  for the Drive OAuth client must include the app scheme
  `testlogon://.../callback`. If the backend only supports an https redirect, we
  need an App Link / intermediate redirect. OPEN: confirm redirect strategy with
  backend.
- R3: `state` lifetime across process death — held in `SavedStateHandle`; verify
  it survives the Custom Tab excursion on low-memory devices, else fall back to a
  short-lived encrypted DataStore entry keyed by project.
- R4: Pagination contract — assumed cursor-based (`next_cursor`); if the API is
  offset/page-based, adjust `ProjectsApi`/`RemoteMediator`. OPEN: confirm.
- R5: Provider model generality — current scope is Google Drive only; the
  `kind`-keyed model leaves room for future providers without a redesign.
- R6: Cancel semantics — confirm an abandoned `start` requires no server cleanup
  (assumed no-op until `callback`).

## 14. Acceptance Criteria

AC-1. The Projects list screen loads the user's projects via `GET /ui/projects`,
renders rows (name, status, provider chips, updated time) with Paging 3, and
shows correct loading/empty/error/offline states. (Maps to ticket: **Projects
render**.)

AC-2. Tapping a project row navigates to `projects/{projectId}` and the detail
screen loads and displays the project via `GET /ui/projects/{projectId}`,
including its connected providers. (Maps to ticket: **detail opens**.)

AC-3. On the detail screen with no Drive provider connected, "Connect Google
Drive" calls the `start` endpoint, opens the returned `authorization_url` in a
Custom Tab, and on the deep-link callback posts `code`+`state` to the `callback`
endpoint; on success the screen refreshes and shows the Drive provider connected.

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
