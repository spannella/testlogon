---
id: AND-273
title: Google Calendar integration
milestone: M6
epic: E37
priority: P2
size: M
status: draft
depends_on: [AND-270]
blocks: []
---

# AND-273 — Google Calendar integration

## 1. Overview & Goal

This ticket lets a signed-in TestLogon user **connect their Google Calendar
account to TestLogon and list the external (Google) calendars** that the
connection exposes. The integration is performed entirely **server-side via
TestLogon's backend** — the Android client never talks to Google's OAuth or
Calendar APIs directly and never holds Google tokens. The client drives the
backend's OAuth-connect flow, observes connection state, and renders the list of
synced external calendars returned by the backend.

Scope, verbatim from the backlog: *OAuth (dev `/mock/google-calendar`), sync
calendars.* Acceptance, verbatim: *Connect + list external calendars.*

Concretely this ticket delivers:

- A `feature-calendar` integrations sub-area with a **Calendar Integrations**
  screen (`GoogleCalendarConnectScreen`) reachable from calendar settings.
- A `GoogleCalendarRepository` + `GoogleCalendarViewModel` that drive the
  server-mediated OAuth connect flow, observe connection status, and load the
  list of external Google calendars.
- The thin transport surface specific to this integration
  (`IntegrationsApi`/`GoogleCalendarApi`) plus its DTOs and mappers, reusing the
  shared Retrofit/OkHttp/cookie/CSRF stack and the canonical `Calendar`
  domain type from **AND-270**.
- A Custom Tabs based authorization hand-off that opens the backend's OAuth
  start URL (in `dev` the mock endpoint `/mock/google-calendar`) and returns to
  the app via a deep link, after which the client polls/refreshes connection
  status.

Out of scope: client-side Google OAuth, two-way write sync, per-event sync into
the local calendar UI (the connected external calendars feed the existing
calendar views from AND-271 once `external = true` calendars are merged; that
merge is a thin follow-up, not part of the acceptance here), and disconnect
analytics beyond the basic telemetry below.

## 2. Context & References

- **Repo / location:** `spannella/testlogon`, monorepo subfolder `android/`,
  branch `android-port`. Production code lands in module **`feature-calendar`**
  under `com.testlogon.android.feature.calendar.integrations` (screen,
  ViewModel) and in **`core-network`** under
  `com.testlogon.android.core.network.integrations` (API, DTOs, mappers, Hilt
  module). Connection state persists via **`core-data`**
  (`com.testlogon.android.core.data.integrations`).
- **Canonical package:** `com.testlogon.android` everywhere.
- **Stack pins relevant here:** Kotlin 2.0.21, Jetpack Compose + Material 3,
  single-Activity Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit
  2.11.0 + OkHttp 4.12.0 + Moshi 1.15.x (codegen via KSP), DataStore (prefs),
  AndroidX Browser (Custom Tabs) `1.8.0`. minSdk 24, compile/target 35, JDK 17,
  AGP 8.7.3, Gradle 8.9.
- **Module layering:** `app -> feature-* -> core-*`. The ViewModel exposes
  `StateFlow<GoogleCalendarUiState>`; the repository returns `ApiResult<T>`
  (AND-018); FastAPI error `detail` is mapped per AND-015.
- **Backend:** FastAPI + DynamoDB. Dev base `http://18.222.237.167:8000/`
  (plaintext HTTP, unreliable: ~20s timeouts, bounded backoff for idempotent
  GETs only, offline/stale UI states). OpenAPI at `/openapi.json`. The dev OAuth
  mock is **`/mock/google-calendar`**, which short-circuits the real Google
  consent screen and returns to the app's redirect with a success marker.
- **Web reference (authoritative for shapes):**
  `frontend/src/api/endpoints/calendar.ts` and the integrations slice of
  `frontend/src/api/types.ts` (`Integration`, `IntegrationProvider`,
  `IntegrationStatus`, external `Calendar` with `external`/`provider`/
  `accountEmail`). OpenAPI is the final authority; any deviation here is
  reconciled before merge.
- **Upstream dependency — AND-270 (Calendar API + DTOs):** owns the canonical
  `core-model` calendar types (`Calendar`, `SharePermission`) and the shared
  `CalendarApi`. This ticket reuses `Calendar` for the external-calendar list
  (extending it minimally with provider/account metadata via a thin
  `ExternalCalendar` wrapper, not by editing AND-270's type). Blocking per the
  backlog `Deps: AND-270`.
- **Auth machinery (transitive):** cookie jar (AND-011), CSRF interceptor
  (AND-012), 401-refresh authenticator (AND-013), `ApiResult` (AND-018), error
  mapping (AND-015), shared Retrofit/OkHttp (AND-009/AND-010), idempotent-GET
  backoff (AND-016), deep-link routing (AND-108 patterns), connectivity probe
  (AND-017).

## 3. Functional Requirements

FR-1. The user reaches a **Calendar Integrations** screen from calendar
settings. It shows the Google Calendar connection card with one of three states:
**Disconnected**, **Connecting**, **Connected** (with the connected account
email).

FR-2. From the Disconnected state, tapping **Connect Google Calendar** calls the
backend to obtain an OAuth authorization URL and opens it in a **Custom Tab**. In
`dev`, the URL is the backend's mock (`/mock/google-calendar`) which completes
without real Google consent.

FR-3. The authorization flow returns to the app via a deep link
(`testlogon://integrations/google-calendar/callback`). On return, the client
finalizes the connection (if the backend requires a finalize call carrying the
returned `state`) and refreshes connection status.

FR-4. When **Connected**, the screen displays the connected Google account email
and a **list of external calendars** synced from that account (name, color,
read-only/permission badge, and an enabled/visible toggle if the backend exposes
one). This list satisfies the acceptance "list external calendars."

FR-5. The user can **Disconnect** from the Connected state (with a confirmation
dialog). On success the screen returns to Disconnected and the external-calendar
list is cleared.

FR-6. The screen renders standard states from AND-021: loading (initial status
fetch), empty (connected but zero external calendars), error (with retry for the
idempotent status/list reads), and offline/stale (cached last-known status).

FR-7. Connection status reads (`GET` status, `GET` external calendars) are
idempotent and retried with bounded backoff (AND-016); the connect/finalize/
disconnect mutations are **not** auto-retried.

FR-8. If the user cancels the Custom Tab (returns without completing), the screen
returns to its prior state and shows a non-blocking "Connection cancelled"
message; no partial connection is recorded.

FR-9. Connection status survives process death: last-known status + account email
are cached in DataStore and shown immediately on next launch, then refreshed.

FR-10. All calls ride the cookie session + `X-CSRF-Token` (mutations). The
feature adds no manual auth headers.

## 4. Technical Design

### 4.1 Domain types (core-model, integrations slice)

```kotlin
package com.testlogon.android.core.model.integrations

import com.testlogon.android.core.model.calendar.Calendar

enum class IntegrationProvider { GOOGLE_CALENDAR, UNKNOWN }

enum class IntegrationStatus { DISCONNECTED, CONNECTING, CONNECTED, ERROR, UNKNOWN }

data class GoogleCalendarConnection(
    val status: IntegrationStatus,
    val accountEmail: String?,        // populated when CONNECTED
    val connectedAt: java.time.Instant?,
    val scopes: List<String>,
)

/** A Google calendar exposed through the connection; wraps the canonical AND-270 Calendar. */
data class ExternalCalendar(
    val calendar: Calendar,           // id/name/color/permission from AND-270
    val provider: IntegrationProvider,
    val accountEmail: String?,
    val syncEnabled: Boolean,         // viewer's visible/sync toggle
    val primary: Boolean,
)
```

### 4.2 DTOs (core-network)

```kotlin
package com.testlogon.android.core.network.integrations

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.core.network.calendar.CalendarDto
import java.time.Instant

@JsonClass(generateAdapter = true)
data class OAuthStartRespDto(
    @Json(name = "authorize_url") val authorizeUrl: String,
    val state: String,                                 // CSRF/state nonce for callback
)

@JsonClass(generateAdapter = true)
data class OAuthFinalizeReqDto(
    val state: String,
    val code: String? = null,                          // null for dev mock
)

@JsonClass(generateAdapter = true)
data class IntegrationStatusDto(
    val provider: String? = null,                      // "google_calendar"
    val status: String? = null,                        // "connected" | "disconnected" | ...
    @Json(name = "account_email") val accountEmail: String? = null,
    @Json(name = "connected_at") val connectedAt: Instant? = null,
    val scopes: List<String>? = null,
)

@JsonClass(generateAdapter = true)
data class ExternalCalendarDto(
    val calendar: CalendarDto,                         // reuse AND-270 DTO
    val provider: String? = null,
    @Json(name = "account_email") val accountEmail: String? = null,
    @Json(name = "sync_enabled") val syncEnabled: Boolean = true,
    val primary: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class ExternalCalendarsRespDto(
    val items: List<ExternalCalendarDto>,
)

@JsonClass(generateAdapter = true)
data class SyncToggleReqDto(@Json(name = "sync_enabled") val syncEnabled: Boolean)
```

### 4.3 API interface (core-network)

```kotlin
package com.testlogon.android.core.network.integrations

import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.PATCH
import retrofit2.http.Path

interface GoogleCalendarApi {

    /** Begin OAuth: returns the provider authorize URL (dev: /mock/google-calendar). Mutation. */
    @Headers("Content-Type: application/json")
    @POST("integrations/google-calendar/oauth/start")
    suspend fun startOAuth(): OAuthStartRespDto

    /** Finalize after redirect (exchanges code / confirms mock). Mutation. */
    @Headers("Content-Type: application/json")
    @POST("integrations/google-calendar/oauth/finalize")
    suspend fun finalizeOAuth(@Body body: OAuthFinalizeReqDto): IntegrationStatusDto

    /** Current connection status. Idempotent GET. */
    @GET("integrations/google-calendar/status")
    suspend fun status(): IntegrationStatusDto

    /** External calendars exposed by the connection. Idempotent GET. */
    @GET("integrations/google-calendar/calendars")
    suspend fun listExternalCalendars(): ExternalCalendarsRespDto

    /** Toggle a single external calendar's sync/visibility. Mutation. */
    @Headers("Content-Type: application/json")
    @PATCH("integrations/google-calendar/calendars/{calendarId}")
    suspend fun setSync(
        @Path("calendarId") calendarId: String,
        @Body body: SyncToggleReqDto,
    ): ExternalCalendarDto

    /** Disconnect the integration. Mutation. */
    @DELETE("integrations/google-calendar")
    suspend fun disconnect(): Unit
}
```

Paths are declared without a leading slash (AND-010 convention); the exact path
set and the dev mock wiring are reconciled against `/openapi.json` +
`calendar.ts` before coding (Q-1). The mock host base in `dev` is
`/mock/google-calendar`; `startOAuth()` returns it as `authorizeUrl` rather than
the client hard-coding it.

### 4.4 Mappers

```kotlin
package com.testlogon.android.core.network.integrations

import com.testlogon.android.core.model.integrations.*
import com.testlogon.android.core.network.calendar.toDomain // AND-270

fun IntegrationStatusDto.toDomain() = GoogleCalendarConnection(
    status = status.toIntegrationStatus(),
    accountEmail = accountEmail,
    connectedAt = connectedAt,
    scopes = scopes.orEmpty(),
)

fun ExternalCalendarDto.toDomain() = ExternalCalendar(
    calendar = calendar.toDomain(),                    // reuse AND-270 mapper
    provider = provider.toProvider(),
    accountEmail = accountEmail,
    syncEnabled = syncEnabled,
    primary = primary,
)

private fun String?.toIntegrationStatus() = when (this?.lowercase()) {
    "connected" -> IntegrationStatus.CONNECTED
    "connecting" -> IntegrationStatus.CONNECTING
    "disconnected", null -> IntegrationStatus.DISCONNECTED
    "error" -> IntegrationStatus.ERROR
    else -> IntegrationStatus.UNKNOWN
}

private fun String?.toProvider() = when (this?.lowercase()) {
    "google_calendar", "google" -> IntegrationProvider.GOOGLE_CALENDAR
    else -> IntegrationProvider.UNKNOWN
}
```

Mappers are pure, tolerate unknown enum strings (→ `UNKNOWN`) and absent
optionals (Kotlin defaults), and never throw.

### 4.5 Repository (core-data)

```kotlin
package com.testlogon.android.core.data.integrations

interface GoogleCalendarRepository {
    suspend fun startConnect(): ApiResult<OAuthStart>             // url + state
    suspend fun finalizeConnect(state: String, code: String?): ApiResult<GoogleCalendarConnection>
    suspend fun refreshStatus(): ApiResult<GoogleCalendarConnection>
    fun observeStatus(): Flow<GoogleCalendarConnection>          // DataStore-backed, SWR
    suspend fun listExternalCalendars(): ApiResult<List<ExternalCalendar>>
    suspend fun setSync(calendarId: String, enabled: Boolean): ApiResult<ExternalCalendar>
    suspend fun disconnect(): ApiResult<Unit>
}
```

The implementation persists last-known status + `accountEmail` to DataStore
(`integrations_prefs`), emits cached value first then refreshes (stale-while-
revalidate, AND-116 hooks), and stashes the in-flight OAuth `state` nonce in
DataStore so the deep-link callback can validate it after process death.

### 4.6 ViewModel + UI state (feature-calendar)

```kotlin
package com.testlogon.android.feature.calendar.integrations

sealed interface GoogleCalendarUiState {
    data object Loading : GoogleCalendarUiState
    data class Disconnected(val error: UiText? = null) : GoogleCalendarUiState
    data object Connecting : GoogleCalendarUiState                 // Custom Tab open
    data class Connected(
        val accountEmail: String,
        val calendars: List<ExternalCalendarUi>,
        val listState: ListState,                                 // Loading/Empty/Error/Offline/Loaded
        val stale: Boolean,
    ) : GoogleCalendarUiState
    data class Error(val message: UiText) : GoogleCalendarUiState
}

@HiltViewModel
class GoogleCalendarViewModel @Inject constructor(
    private val repo: GoogleCalendarRepository,
) : ViewModel() {
    val uiState: StateFlow<GoogleCalendarUiState>
    fun onConnectClicked()                 // -> startConnect(), emits authorizeUrl as one-shot effect
    fun onCallback(uri: Uri)               // deep-link return: validate state, finalizeConnect()
    fun onConnectCancelled()
    fun onRetry()
    fun onToggleSync(calendarId: String, enabled: Boolean)
    fun onDisconnect()
    val effects: SharedFlow<GoogleCalendarEffect>   // OpenCustomTab(url), ShowSnackbar(...)
}
```

The Custom Tab launch is a one-shot **effect** (not state) consumed by the
Composable, which uses `CustomTabsIntent`. Deep-link `onCallback` is wired
through the single-Activity Navigation graph (AND-022/AND-108): the manifest
intent filter for scheme `testlogon`, host `integrations`, path
`/google-calendar/callback` routes to this screen and forwards the `Uri`.

### 4.7 Composable

```kotlin
@Composable
fun GoogleCalendarConnectScreen(
    viewModel: GoogleCalendarViewModel = hiltViewModel(),
    onBack: () -> Unit,
)
```

Renders the connection card per state, the external-calendar list (Material 3
`ListItem` with leading color dot, trailing `Switch` for sync, permission badge),
state composables from AND-021, and a disconnect confirmation `AlertDialog`.

### 4.8 Hilt + Gradle

A `@Module @InstallIn(SingletonComponent::class)` provides `GoogleCalendarApi`
from the shared `Retrofit` (AND-010) and binds `GoogleCalendarRepository`. New
dependency: `androidx.browser:browser:1.8.0` in `feature-calendar`. No new
Retrofit/OkHttp instance.

## 5. API Contract

Base (`dev`): `http://18.222.237.167:8000/`. All reads ride the cookie session;
mutations additionally send `X-CSRF-Token`. Shapes below are the working
contract, reconciled against `/openapi.json` + `calendar.ts` before merge.

### POST `integrations/google-calendar/oauth/start`
Response `200`:
```json
{ "authorize_url": "http://18.222.237.167:8000/mock/google-calendar?state=abc123",
  "state": "abc123" }
```
In `staging`/`prod` `authorize_url` is a real Google consent URL (HTTPS).

### POST `integrations/google-calendar/oauth/finalize`
Request: `{ "state": "abc123", "code": null }` (dev mock; `code` present for real
OAuth). Response `200`: an `IntegrationStatusDto` (now `connected`).

### GET `integrations/google-calendar/status`
Response `200`:
```json
{ "provider": "google_calendar", "status": "connected",
  "account_email": "user@example.com",
  "connected_at": "2026-06-05T12:00:00Z",
  "scopes": ["https://www.googleapis.com/auth/calendar.readonly"] }
```
When not connected: `{ "provider": "google_calendar", "status": "disconnected" }`.

### GET `integrations/google-calendar/calendars`
Response `200`:
```json
{
  "items": [
    { "calendar": { "id": "gcal_primary", "name": "user@example.com",
        "owner_display_name": "User", "permission": "owner", "color": "#039BE5" },
      "provider": "google_calendar", "account_email": "user@example.com",
      "sync_enabled": true, "primary": true },
    { "calendar": { "id": "gcal_team", "name": "Team", "permission": "viewer",
        "color": "#0B8043" },
      "provider": "google_calendar", "account_email": "user@example.com",
      "sync_enabled": false, "primary": false }
  ]
}
```

### PATCH `integrations/google-calendar/calendars/{calendarId}`
Request: `{ "sync_enabled": true }`. Response `200`: updated `ExternalCalendarDto`.

### DELETE `integrations/google-calendar`
Response `200`/`204` (empty body). Disconnects and revokes server-side tokens.

**Error envelope (all endpoints):** FastAPI `detail` union
(`string | [{msg,type,loc}] | {code,...}`), mapped to typed `ApiError` by
AND-015. Non-2xx surfaces as `HttpException` into the repository, which wraps it
in `ApiResult.Error`.

## 6. Data & State Management

- **Source of truth:** the backend connection state. The client caches a
  projection (status, account email, connected_at) in **DataStore**
  (`integrations_prefs`: `gcal_status`, `gcal_account_email`,
  `gcal_oauth_state`) for instant render and process-death survival.
- **UI state:** `GoogleCalendarViewModel.uiState: StateFlow<GoogleCalendarUiState>`
  produced by combining `repo.observeStatus()` with on-demand external-calendar
  loads. One-shot navigation/Custom-Tab/snackbar signals go through
  `effects: SharedFlow<GoogleCalendarEffect>`, never state, to avoid replay on
  recomposition/rotation.
- **OAuth state nonce:** `startOAuth().state` is written to DataStore before the
  Custom Tab opens; the deep-link callback compares the returned `state` against
  it (R-2) and clears it after finalize. A mismatch aborts finalize.
- **External calendars** are not separately persisted in Room for this ticket
  (small, viewer-scoped list; re-fetched on entering Connected). The optional
  merge of `sync_enabled` external calendars into the calendar views (AND-271)
  is a downstream follow-up.
- **Threading:** repository suspend calls run on an injected IO dispatcher;
  `StateFlow` is collected on the main dispatcher in Compose.

## 7. Error Handling & Resilience

- **Idempotent GETs** (`status`, `listExternalCalendars`) use the shared ~20s
  timeout + bounded backoff (AND-016). On failure they surface
  `ApiResult.Error` mapped to a localized message with **Retry**; if a cached
  status exists, the Connected/Disconnected card is shown **stale** with a
  refresh affordance (AND-021/AND-117).
- **Mutations** (`startOAuth`, `finalizeOAuth`, `setSync`, `disconnect`) are
  **never** auto-retried. Failures show an inline error / snackbar; the card
  reverts to its prior state.
- **Custom Tab cancel / no callback:** if the user dismisses the Custom Tab and
  returns to the app without a callback `Uri`, the ViewModel (on `onResume`
  without a pending callback) treats it as cancelled, clears the stored OAuth
  state, and returns to the prior state with "Connection cancelled" (FR-8).
- **State mismatch / replay:** a callback whose `state` does not match the stored
  nonce is rejected; finalize is not called; a generic "Connection failed,
  please try again" message is shown.
- **401:** intercepted by AND-013's authenticator (refresh once, retry); a second
  401 routes to login (AND-025).
- **Transport failures** (`SocketTimeoutException`, `UnknownHostException`) map
  via the connectivity probe (AND-017) to the offline state.
- **Provider-side errors** (Google denied consent, expired grant) come back as
  `status:"error"` from `status`/`finalize`; rendered as the `Error` state with a
  reconnect action.

## 8. Security & Privacy

- **No Google tokens on device.** All OAuth token exchange, storage, and refresh
  happen server-side. The client only handles the opaque `authorize_url`, the
  `state` nonce, and the post-redirect status. This is the central security
  property of this ticket.
- **State nonce** binds the start and callback to prevent OAuth CSRF / fixation;
  validated client-side against the DataStore value and (authoritatively)
  server-side on finalize.
- **Custom Tabs** (not a `WebView`) are used so credentials are entered in the
  system browser with its own cookie/credential isolation; no JS bridge, no
  cookie sharing with the app's session, no `WebView` token interception surface.
- **App session CSRF:** mutating verbs send `X-CSRF-Token` via AND-012; cookies
  via the persistent jar (AND-011). No manual auth headers in the interface.
- **Cleartext on dev:** the mock OAuth and all integration calls ride plaintext
  HTTP on the dev host — a known, dev-only risk under the scoped cleartext config
  (AND-006). `staging`/`prod` are HTTPS-only, and the real `authorize_url` is
  HTTPS.
- **PII:** the connected Google **account email** is shown and cached in
  DataStore (app-private storage). It must never appear in logs (Section 10).
- **Deep-link safety:** the callback intent filter accepts only
  `testlogon://integrations/google-calendar/callback`; the callback carries no
  secret beyond the `state` echo, which is single-use and validated.

## 9. Accessibility & i18n

- All actions (Connect, Disconnect, per-calendar sync `Switch`) have
  `contentDescription`/`stateDescription`; the sync `Switch` announces
  on/off and the calendar name. Color dots are decorative
  (`contentDescription = null`) — color is never the sole signal; a
  permission/primary badge carries the meaning.
- Connection-state text and account email meet Material 3 contrast and scale with
  font size; the screen is usable at 200% font scale and in landscape.
- Custom Tab inherits the system browser's accessibility.
- **i18n:** all visible strings (state labels, "Connect Google Calendar",
  "Disconnect", confirmation dialog, error/empty/offline copy, "Connection
  cancelled") live in `strings.xml` via the AND-111 plumbing; no concatenation;
  RTL-safe layouts (AND-114). The account email is data, not translated.

## 10. Telemetry & Logging

- **Events** (via the app analytics layer, redacted per AND-052): 
  `gcal_connect_started`, `gcal_connect_succeeded`, `gcal_connect_failed`
  (with coarse reason: `cancelled` | `state_mismatch` | `network` | `provider`),
  `gcal_disconnected`, `gcal_external_calendars_loaded` (count only),
  `gcal_sync_toggled` (`enabled` bool, no calendar id/name). **No account email,
  no calendar names, no ids** in any event.
- **HTTP logging** inherited from AND-009's redacting interceptor (debug only);
  the `account_email`, `authorize_url`, and `state` fields must be redacted. A
  code-review check confirms no email/token/state reaches logcat in any build.
- No `Timber` payload dumps of integration responses.

## 11. Testing Strategy

**Unit / JVM (`core-network`, `core-data`) with MockWebServer:**

- **T-1** `startOAuth` issues `POST integrations/google-calendar/oauth/start`,
  decodes `authorize_url` + `state`.
- **T-2** `finalizeOAuth` issues `POST .../oauth/finalize` with
  `{state, code}` body; decodes a `connected` status.
- **T-3** `status` issues `GET .../status`, maps `connected` →
  `IntegrationStatus.CONNECTED` with `accountEmail`; `disconnected` payload (no
  email) maps to `DISCONNECTED`; unknown status → `UNKNOWN` (no throw).
- **T-4** `listExternalCalendars` issues `GET .../calendars`, decodes the
  `{items:[...]}` envelope, and maps each `ExternalCalendarDto` (reusing the
  AND-270 `CalendarDto.toDomain`) including `primary`/`syncEnabled`/permission.
- **T-5** `setSync` issues `PATCH .../calendars/gcal_team` with
  `{"sync_enabled":true}` and decodes the updated item.
- **T-6** `disconnect` issues `DELETE integrations/google-calendar`, tolerates
  empty `204` (returns `Unit`).
- **T-7** error propagation: `401`/`500` from `status` surfaces as
  `HttpException` → `ApiResult.Error` (not swallowed).
- **T-8** repository: `observeStatus()` emits the DataStore-cached value first,
  then the refreshed value (SWR); OAuth `state` is persisted on `startConnect`
  and cleared on `finalizeConnect`.

**ViewModel (coroutines test, fake repository):**

- **T-9** `onConnectClicked` emits an `OpenCustomTab(authorizeUrl)` effect and
  moves to `Connecting`.
- **T-10** `onCallback` with a **matching** `state` calls `finalizeConnect` and
  transitions to `Connected(accountEmail, calendars)`; **mismatched** state
  emits a failure snackbar and reverts (no finalize call).
- **T-11** `onConnectCancelled` reverts to the prior state and shows "Connection
  cancelled"; no partial connection persisted.
- **T-12** `onDisconnect` confirms then transitions Connected → Disconnected and
  clears the external-calendar list.
- **T-13** Connected with zero items → `ListState.Empty`; status fetch failure
  with cached value → `stale = true`.

**Compose UI tests (`feature-calendar`):**

- **T-14** Disconnected state shows **Connect Google Calendar**; tapping invokes
  the connect path (effect asserted via test double / Espresso-Intents stub for
  the Custom Tab intent).
- **T-15** Connected state renders the account email and the external-calendar
  list with sync switches; toggling a switch calls `onToggleSync`.
- **T-16** Error and Offline states render the AND-021 composables with Retry.

Coverage target ≥85% on the new surface (API binding, mappers, repository,
ViewModel). The pair (T-1/T-2 + T-9/T-10) proves **Connect**; T-4 + T-15 prove
**list external calendars** — the two backlog acceptance items.

## 12. Dependencies & Sequencing

**Hard upstream (must merge first):**
- **AND-270** — Calendar API + DTOs. Supplies the canonical `Calendar`
  domain type + `CalendarDto`/mapper that `ExternalCalendar`/`ExternalCalendarDto`
  reuse. Blocking per backlog `Deps: AND-270`.

**Transitive upstream (already required):** AND-009/AND-010 (shared
OkHttp/Retrofit/Moshi), AND-011/AND-012/AND-013 (cookies/CSRF/refresh), AND-015
(error mapping), AND-016 (idempotent-GET backoff), AND-017 (connectivity),
AND-018 (`ApiResult`), AND-021 (state composables), AND-022/AND-024/AND-025 +
AND-108 (navigation + deep-link routing), AND-111/AND-114 (i18n/RTL), AND-052
(redacted telemetry), AND-116/AND-117 (SWR/stale hooks), AND-006
(`BuildConfig`/cleartext config).

**Soft sibling:** **AND-271** (calendar views) — the visual surface into which
`sync_enabled` external calendars are eventually merged; that merge is a
follow-up after this ticket lands, not part of this acceptance. This ticket does
not block AND-271 (`blocks: []`).

**Sequencing within the ticket:** (1) confirm endpoint paths, the dev mock
wiring, the finalize contract, and field names against `/openapi.json` +
`calendar.ts`; (2) DTOs + mappers + `GoogleCalendarApi` + Hilt module
(`core-network`); (3) `GoogleCalendarRepository` + DataStore cache (`core-data`);
(4) ViewModel + UI state/effects; (5) Composable + navigation/deep-link wiring +
manifest intent filter; (6) tests T-1..T-16.

## 13. Risks & Open Questions

- **R-1 Finalize required?** The backend mock may auto-finalize on redirect (no
  client `finalize` call needed) or require `POST .../oauth/finalize` with the
  echoed `state`. *Mitigation:* implement finalize; if the backend auto-finalizes,
  `onCallback` simply calls `refreshStatus`. Guarded by T-2/T-10.
- **R-2 Callback delivery / state validation.** Custom Tab redirect must land on
  the app's deep link reliably and carry the `state`. *Mitigation:* manifest
  intent filter + DataStore-stored nonce; validate and reject mismatches; treat
  no-callback-on-resume as cancel.
- **R-3 Real vs mock divergence.** Only the dev mock (`/mock/google-calendar`) is
  exercisable now; real Google consent (HTTPS, real `code`) is untested until
  staging. *Mitigation:* keep `authorize_url`/`code` server-supplied and opaque so
  the client path is identical; flag staging verification.
- **R-4 External-calendar shape.** The `calendars` endpoint may inline a flat
  calendar object rather than nest `CalendarDto`. *Mitigation:* match OpenAPI;
  default to the nested `{calendar:{...}}` shape; mapper isolates the difference.
- **R-5 Account email PII.** Caching/showing the email is required for UX but is
  PII. *Mitigation:* app-private DataStore, redaction in logs/telemetry (Section
  8/10), confirmed in review.
- **Q-1** Exact paths and verbs (`oauth/start` vs `connect`; `DELETE
  integrations/google-calendar` vs `.../disconnect`)? *Proposed:* match OpenAPI;
  spec assumes the paths in Section 5.
- **Q-2** Does `setSync` exist, or is sync all-or-nothing per connection?
  *Proposed:* implement per-calendar `PATCH`; if absent, drop the per-row switch
  and show calendars read-only (acceptance still met by listing).
- **Q-3** Does `status` distinguish `connecting` (server still exchanging) from
  `connected`? *Proposed:* map `connecting` to the `Connecting` state; otherwise
  the client owns `Connecting` purely while the Custom Tab is open.
- **Q-4** Is the redirect URI registered server-side as the app scheme, or an
  https App Link? *Proposed:* confirm; spec assumes custom scheme
  `testlogon://...`.

## 14. Acceptance Criteria

- **AC-1 (backlog — Connect).** From the Disconnected state, the user can connect
  Google Calendar: `startOAuth` opens the authorize URL (dev:
  `/mock/google-calendar`) in a Custom Tab, the deep-link callback finalizes with
  the validated `state`, and the screen transitions to Connected showing the
  account email (T-1, T-2, T-9, T-10, T-14).
- **AC-2 (backlog — list external calendars).** In the Connected state, the
  external Google calendars are listed (name, color, permission, sync toggle),
  decoded from `GET .../calendars` and mapped via the AND-270 `Calendar` type
  (T-4, T-15).
- **AC-3.** Disconnect returns the screen to Disconnected and clears the list
  (T-12).
- **AC-4.** Idempotent reads (`status`, `calendars`) retry with bounded backoff
  and degrade to error-with-retry / stale-cached states; mutations are not
  auto-retried (T-7, T-13, T-16).
- **AC-5.** OAuth `state` is generated server-side, stored client-side, validated
  on callback, and a mismatch aborts finalize (T-10).
- **AC-6.** No Google tokens are stored on device; only cookie session + CSRF are
  used for app calls; Custom Tabs (not WebView) carry the consent (Section 8,
  review).
- **AC-7.** Cancelling the Custom Tab returns to the prior state with a
  non-blocking message and no partial connection (T-11).
- **AC-8.** Connection status + account email survive process death via DataStore
  and render immediately, then refresh (T-8).
- **AC-9.** No account email / calendar names / ids appear in logs or telemetry;
  events follow AND-052 redaction (Section 10, review).
- **AC-10.** All tests pass in CI; modules build clean under AGP 8.7.3 / Gradle
  8.9 / JDK 17 with KSP adapters present and no detekt/lint regressions.

## 15. Definition of Done

- DTOs, `GoogleCalendarApi`, mappers, and Hilt module live in `core-network`
  (`com.testlogon.android.core.network.integrations`); domain types in
  `core-model` (`...core.model.integrations`); `GoogleCalendarRepository` +
  DataStore cache in `core-data`; `GoogleCalendarViewModel` +
  `GoogleCalendarConnectScreen` in `feature-calendar`
  (`...feature.calendar.integrations`).
- Open questions Q-1..Q-4 resolved against `/openapi.json` and
  `frontend/src/api/endpoints/calendar.ts` + `types.ts`; paths/verbs, the
  finalize contract, the redirect URI, and field names reflect the confirmed
  contract.
- Navigation route + manifest deep-link intent filter
  (`testlogon://integrations/google-calendar/callback`) wired through the
  single-Activity graph; `androidx.browser:browser:1.8.0` added to
  `feature-calendar`.
- Tests T-1..T-16 implemented and green in CI; ≥85% line coverage on the new
  surface; Connect and list-external-calendars each covered by ≥1 end-to-end
  ViewModel/UI test plus mapper/endpoint tests.
- No second `OkHttpClient`/`Retrofit`; no Google tokens on device; no manual
  cookie/CSRF headers; no account email / token / state in logs (verified in
  review).
- `./gradlew :core-model:assemble :core-network:assemble
  :core-data:assemble :feature-calendar:assemble
  :core-network:testDebugUnitTest :feature-calendar:testDebugUnitTest` passes
  locally and in CI with no new lint/detekt violations (AND-005 config).
- Code reviewed and merged to `android-port`; the follow-up to merge
  `sync_enabled` external calendars into the AND-271 calendar views is filed.
