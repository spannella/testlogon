---
id: AND-273
title: Google Calendar integration
milestone: M6
epic: E37
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
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
  GETs only, offline/stale UI states). OpenAPI at `/openapi.json`. The dev Google
  mock is rooted at **`/mock/google-calendar/...`** and stands in for Google's
  own APIs (`/oauth/token`, `/oauth/userinfo`, `/oauth/revoke`,
  `/calendar/v3/users/me/calendarList`, plus `/seed` and `/reset` test hooks).
  The client never calls these directly — the backend's `connect/start`
  endpoint returns an `authorization_url` (in dev pointing at this mock) which
  the client opens; the mock short-circuits real Google consent and redirects
  back to the backend callback. **Correction:** the backlog phrase "dev
  `/mock/google-calendar`" denotes this mock *server root*, not a client-facing
  connect path; the app-facing endpoints live under
  `/ui/calendar/integrations/google/...` (verified, see §5/§16).
- **Web reference (authoritative for shapes):**
  `frontend/src/api/endpoints/calendar.ts` (the Google integration helpers:
  `getGoogleCalendarIntegrationStatus`, `startGoogleCalendarConnect`,
  `completeGoogleCalendarConnect`, `disconnectGoogleCalendar`,
  `getGoogleCalendarProviderCalendars`, `createGoogleCalendarMapping`,
  `runGoogleCalendarSync`) and the matching slice of
  `frontend/src/api/types.ts` (`GoogleCalendarIntegrationStatus`,
  `GoogleCalendarConnectStart`, `GoogleCalendarConnectCallback`,
  `GoogleCalendarDisconnect`, `GoogleCalendarProviderCalendar(s)`,
  `GoogleCalendarMappingCreateIn`/`GoogleCalendarMapping`,
  `GoogleCalendarSyncRun`). The web client (`src/pages/calendar/
  GoogleCalendarIntegration.tsx`) is the behavioral reference. OpenAPI is the
  final authority; the shapes in this spec have now been reconciled against it
  (see §16). **Correction:** earlier drafts referenced an abstract
  `Integration`/`IntegrationProvider`/`IntegrationStatus` slice and an external
  `Calendar` with `external`/`accountEmail` fields — no such types exist; the
  real contract is Google-specific and is documented in §5/§16.
- **Upstream dependency — AND-270 (Calendar API + DTOs):** owns the canonical
  `core-model` calendar types (`Calendar`, `SharePermission`) and the shared
  `CalendarApi`. **Correction:** the Google provider-calendar list does NOT
  reuse AND-270's `Calendar`/`CalendarDto` — the backend returns a flat,
  Google-specific `GoogleCalendarProviderCalendarOut`
  (`google_calendar_id`, `summary`, `access_role`, `primary`,
  `mapped_internal_calendar_id`) with no nested calendar object. This ticket
  defines its own `ProviderCalendar` domain type. AND-270 remains a dependency,
  but only because the *mapping* feature (`POST .../mappings`) targets an
  `internal_calendar_id` that must come from AND-270's `getCalendars`; that
  internal-calendar list is rendered via the AND-270 `Calendar` type. Blocking
  per the backlog `Deps: AND-270`.
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

FR-2. From the Disconnected state, tapping **Connect Google Calendar** calls
`POST /ui/calendar/integrations/google/connect/start`, which returns an
`authorization_url` (plus `state`, `nonce`, `expires_at_utc`), and opens that URL
in a **Custom Tab**. In `dev`, the URL points at the backend's Google mock
(`/mock/google-calendar/...`) which completes without real Google consent.

FR-3. The authorization flow ultimately reaches the **backend** callback
`GET /ui/calendar/integrations/google/connect/callback?code=&state=&error=`,
which exchanges the code server-side and returns
`{connection_id, account_email, linked, updated_at_utc}`. **Correction (vs
earlier draft):** there is no separate `POST .../oauth/finalize` JSON endpoint —
finalize *is* this GET callback, and it is normally handled server-side off the
provider redirect. The redirect URI is therefore expected to be the backend
callback (an HTTPS App Link / web URL), not the app's custom scheme; see R-2/Q-4.
The Android client opens the Custom Tab, then on return to the app (or via a deep
link if one is wired) re-reads `GET .../status` to observe the now-active
connection. If product wants the app to drive the callback directly, it must pass
`code`+`state` to the GET endpoint itself.

FR-4. When **Connected** (`status.connection_active == true`), the screen
displays a **list of the account's Google provider calendars** from
`GET /ui/calendar/integrations/google/calendars` — each item exposes
`summary` (display name), `primary`, `access_role`, and
`mapped_internal_calendar_id`. This list satisfies the acceptance "list external
calendars." **Correction:** the status endpoint does NOT return the connected
account email (no `account_email` field on `GoogleCalendarIntegrationStatusOut`);
the email is only available from the connect-callback / disconnect responses, so
the app must cache it from the callback if it wants to display it. There is no
per-calendar color or read-only/visible toggle in the provider-calendar payload;
the only mutation per row is **mapping** the Google calendar to an internal
calendar (FR-4a).

FR-4a. **Correction:** there is no per-calendar `sync_enabled` toggle. The
per-row control is a **mapping**: `POST /ui/calendar/integrations/google/mappings`
with `{internal_calendar_id, google_calendar_id}`. The web client renders a
`Select` letting the user map each Google calendar to one internal calendar
(from AND-270 `getCalendars`). Acceptance ("list external calendars") is met by
the list alone; mapping is the value-add and matches the web reference.

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

> **Corrected to the real contract.** The backend has no abstract
> `IntegrationProvider`/`IntegrationStatus` and the status payload carries no
> string status / email / scopes. Connection state is the boolean
> `connection_active`; the account email comes only from the connect-callback.

```kotlin
package com.testlogon.android.core.model.integrations

// Derived (client-side) connection phase; the backend status is a set of
// booleans/strings (see GoogleCalendarStatus), not a single enum.
enum class ConnectPhase { DISCONNECTED, CONNECTING, CONNECTED, REAUTH_REQUIRED, UNKNOWN }

/** Mirrors GoogleCalendarIntegrationStatusOut (verified against OpenAPI). */
data class GoogleCalendarStatus(
    val connectionActive: Boolean,        // connection_active (default false)
    val syncEnabled: Boolean,             // sync_enabled (required)
    val writebackEnabled: Boolean,        // writeback_enabled (required)
    val reauthRequired: Boolean,          // reauth_required (default false)
    val syncHealth: String,               // sync_health (default "unknown")
    val lastSyncStatus: String,           // last_sync_status (default "never_synced")
    val lastSyncAtUtc: String,            // last_sync_at_utc (default "")
    val rolloutMode: String,              // "all" | "cohort" | "off"
    val rolloutPercent: Int,
    val inRolloutCohort: Boolean,
    // account email is NOT in status; cached from the connect callback:
    val accountEmail: String?,
)

/** Mirrors GoogleCalendarProviderCalendarOut (verified). Flat, NOT AND-270 Calendar. */
data class ProviderCalendar(
    val googleCalendarId: String,            // google_calendar_id (required)
    val summary: String,                     // display name (default "")
    val accessRole: String?,                 // access_role (nullable)
    val primary: Boolean,                    // default false
    val mappedInternalCalendarId: String?,   // mapped_internal_calendar_id (nullable)
)
```

### 4.2 DTOs (core-network)

> **Corrected to the verified OpenAPI schemas.** Note the field-name fixes
> (`authorization_url` not `authorize_url`), the GET-with-query callback (no
> finalize body DTO), the status booleans (no `status`/`account_email`/`scopes`),
> the flat provider-calendar (no nested `CalendarDto`), the `{calendars:[...]}`
> envelope (not `{items:[...]}`), and mapping (not a sync toggle).

```kotlin
package com.testlogon.android.core.network.integrations

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

// POST /ui/calendar/integrations/google/connect/start -> GoogleCalendarConnectStartOut
@JsonClass(generateAdapter = true)
data class ConnectStartDto(
    @Json(name = "authorization_url") val authorizationUrl: String,
    val state: String,
    val nonce: String,
    @Json(name = "expires_at_utc") val expiresAtUtc: String,
    val provider: String = "google",
)

// GET /ui/calendar/integrations/google/connect/callback?code=&state=&error=
//   -> GoogleCalendarConnectCallbackOut  (no request BODY; params are query)
@JsonClass(generateAdapter = true)
data class ConnectCallbackDto(
    @Json(name = "connection_id") val connectionId: String,
    @Json(name = "account_email") val accountEmail: String,
    val linked: Boolean,
    @Json(name = "updated_at_utc") val updatedAtUtc: String,
    val provider: String = "google",
)

// GET /ui/calendar/integrations/google/status -> GoogleCalendarIntegrationStatusOut
@JsonClass(generateAdapter = true)
data class IntegrationStatusDto(
    @Json(name = "connection_active") val connectionActive: Boolean = false,
    @Json(name = "sync_enabled") val syncEnabled: Boolean,          // required
    @Json(name = "writeback_enabled") val writebackEnabled: Boolean, // required
    @Json(name = "reauth_required") val reauthRequired: Boolean = false,
    @Json(name = "sync_health") val syncHealth: String = "unknown",
    @Json(name = "last_sync_status") val lastSyncStatus: String = "never_synced",
    @Json(name = "last_sync_at_utc") val lastSyncAtUtc: String = "",
    @Json(name = "rollout_mode") val rolloutMode: String,           // all|cohort|off
    @Json(name = "rollout_percent") val rolloutPercent: Int,
    @Json(name = "in_rollout_cohort") val inRolloutCohort: Boolean,
    val provider: String = "google",
)

// GET /ui/calendar/integrations/google/calendars -> GoogleCalendarProviderCalendarsOut
@JsonClass(generateAdapter = true)
data class ProviderCalendarDto(
    @Json(name = "google_calendar_id") val googleCalendarId: String,  // required
    val summary: String = "",
    @Json(name = "access_role") val accessRole: String? = null,
    val primary: Boolean = false,
    @Json(name = "mapped_internal_calendar_id") val mappedInternalCalendarId: String? = null,
)

@JsonClass(generateAdapter = true)
data class ProviderCalendarsDto(
    val calendars: List<ProviderCalendarDto>,            // key is "calendars"
)

// POST /ui/calendar/integrations/google/mappings  body=GoogleCalendarMappingCreateIn
@JsonClass(generateAdapter = true)
data class MappingCreateDto(
    @Json(name = "internal_calendar_id") val internalCalendarId: String,
    @Json(name = "google_calendar_id") val googleCalendarId: String,
)

// -> GoogleCalendarMappingOut
@JsonClass(generateAdapter = true)
data class MappingDto(
    @Json(name = "mapping_id") val mappingId: String,
    @Json(name = "user_sub") val userSub: String,
    @Json(name = "internal_calendar_id") val internalCalendarId: String,
    @Json(name = "google_calendar_id") val googleCalendarId: String,
    val active: Boolean,
    @Json(name = "created_at_utc") val createdAtUtc: String,
    @Json(name = "updated_at_utc") val updatedAtUtc: String,
    @Json(name = "unmapped_at_utc") val unmappedAtUtc: String,
    val provider: String = "google",
)

// POST /ui/calendar/integrations/google/disconnect?connection_id= -> GoogleCalendarDisconnectOut
@JsonClass(generateAdapter = true)
data class DisconnectDto(
    @Json(name = "connection_id") val connectionId: String,
    @Json(name = "account_email") val accountEmail: String,
    val active: Boolean,
    val revoked: Boolean,
    @Json(name = "revoke_status") val revokeStatus: String,
    @Json(name = "disconnected_at_utc") val disconnectedAtUtc: String,
    val provider: String = "google",
)

// POST /ui/calendar/integrations/google/sync/run?mode= -> GoogleCalendarSyncRunOut
@JsonClass(generateAdapter = true)
data class SyncRunDto(
    val accepted: Boolean,                               // required
    val mode: String = "incremental",                   // incremental|full
    @Json(name = "rate_limited") val rateLimited: Boolean = false,
    val metrics: Map<String, Any?> = emptyMap(),
)
```

### 4.3 API interface (core-network)

> **Corrected paths/verbs/params** — all verified against the OpenAPI index and
> `calendar.ts`. Real base path is `ui/calendar/integrations/google/...` (not
> `integrations/google-calendar/...`); disconnect is `POST` (not `DELETE`);
> there is no PATCH sync toggle (use `POST .../mappings`); callback is a `GET`
> with `code`/`state`/`error` query params (no finalize body).

```kotlin
package com.testlogon.android.core.network.integrations

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Query

interface GoogleCalendarApi {

    /** Begin OAuth: returns authorization_url + state + nonce. Mutation. */
    @POST("ui/calendar/integrations/google/connect/start")
    suspend fun connectStart(): ConnectStartDto

    /**
     * Backend OAuth callback (exchanges code, links account). GET with query
     * params; normally hit server-side off the provider redirect. Idempotent.
     */
    @GET("ui/calendar/integrations/google/connect/callback")
    suspend fun connectCallback(
        @Query("code") code: String? = null,
        @Query("state") state: String? = null,
        @Query("error") error: String? = null,
    ): ConnectCallbackDto

    /** Current integration status (booleans, rollout, sync health). Idempotent GET. */
    @GET("ui/calendar/integrations/google/status")
    suspend fun status(): IntegrationStatusDto

    /** Google provider calendars exposed by the connection. Idempotent GET. */
    @GET("ui/calendar/integrations/google/calendars")
    suspend fun listProviderCalendars(): ProviderCalendarsDto

    /** Map a Google calendar to an internal calendar. Mutation. */
    @Headers("Content-Type: application/json")
    @POST("ui/calendar/integrations/google/mappings")
    suspend fun createMapping(@Body body: MappingCreateDto): MappingDto

    /** Disconnect (optionally a specific connection). Mutation (POST, not DELETE). */
    @POST("ui/calendar/integrations/google/disconnect")
    suspend fun disconnect(@Query("connection_id") connectionId: String? = null): DisconnectDto

    /** Trigger a manual sync run. Mutation. */
    @POST("ui/calendar/integrations/google/sync/run")
    suspend fun runSync(@Query("mode") mode: String = "incremental"): SyncRunDto
}
```

Paths are declared without a leading slash (AND-010 convention). The full
verified path/verb/param set is in §5. Note: `connect/start`, `disconnect`,
`mappings`, and `sync/run` are POSTs with **empty JSON bodies** in the web client
(`api.post(path, {})`); only `mappings` carries a real body. The
`authorization_url` is server-supplied (dev: a `/mock/google-calendar/...` URL);
the client never hard-codes it.

### 4.4 Mappers

```kotlin
package com.testlogon.android.core.network.integrations

import com.testlogon.android.core.model.integrations.*

fun IntegrationStatusDto.toDomain(cachedAccountEmail: String? = null) = GoogleCalendarStatus(
    connectionActive = connectionActive,
    syncEnabled = syncEnabled,
    writebackEnabled = writebackEnabled,
    reauthRequired = reauthRequired,
    syncHealth = syncHealth,
    lastSyncStatus = lastSyncStatus,
    lastSyncAtUtc = lastSyncAtUtc,
    rolloutMode = rolloutMode,
    rolloutPercent = rolloutPercent,
    inRolloutCohort = inRolloutCohort,
    accountEmail = cachedAccountEmail,    // status carries no email
)

fun IntegrationStatusDto.toPhase(): ConnectPhase = when {
    reauthRequired -> ConnectPhase.REAUTH_REQUIRED
    connectionActive -> ConnectPhase.CONNECTED
    else -> ConnectPhase.DISCONNECTED
}

fun ProviderCalendarDto.toDomain() = ProviderCalendar(
    googleCalendarId = googleCalendarId,
    summary = summary,
    accessRole = accessRole,
    primary = primary,
    mappedInternalCalendarId = mappedInternalCalendarId,
)
```

Mappers are pure, tolerate absent optionals (Kotlin/Moshi defaults), and never
throw. **Correction:** there is no string `status` enum or `provider` enum to
parse — connection phase is derived from booleans, and the only `provider` value
is the constant `"google"`.

### 4.5 Repository (core-data)

```kotlin
package com.testlogon.android.core.data.integrations

interface GoogleCalendarRepository {
    suspend fun startConnect(): ApiResult<ConnectStart>           // authorization_url + state + nonce
    /** Hits the GET callback if the app drives finalize; usually we just refreshStatus(). */
    suspend fun completeConnect(code: String, state: String): ApiResult<GoogleCalendarStatus>
    suspend fun refreshStatus(): ApiResult<GoogleCalendarStatus>
    fun observeStatus(): Flow<GoogleCalendarStatus>              // DataStore-backed, SWR
    suspend fun listProviderCalendars(): ApiResult<List<ProviderCalendar>>
    suspend fun createMapping(internalCalendarId: String, googleCalendarId: String): ApiResult<ProviderCalendar>
    suspend fun runSync(mode: String = "incremental"): ApiResult<Unit>
    suspend fun disconnect(connectionId: String? = null): ApiResult<Unit>
}
```

The implementation persists last-known status + `accountEmail` (captured from the
connect callback / disconnect responses, since status omits it) to DataStore
(`integrations_prefs`), emits cached value first then refreshes (stale-while-
revalidate, AND-116 hooks), and stashes the in-flight OAuth `state`/`nonce` in
DataStore so a returning callback can be validated after process death.
**Correction:** the old `setSync(calendarId, enabled)` is replaced by
`createMapping(...)` — the backend models per-calendar selection as a mapping to
an internal calendar, not a boolean sync toggle.

### 4.6 ViewModel + UI state (feature-calendar)

```kotlin
package com.testlogon.android.feature.calendar.integrations

sealed interface GoogleCalendarUiState {
    data object Loading : GoogleCalendarUiState
    data class Disconnected(val error: UiText? = null) : GoogleCalendarUiState
    data object Connecting : GoogleCalendarUiState                 // Custom Tab open
    data class Connected(
        val accountEmail: String?,                                // cached from callback; status omits it
        val calendars: List<ProviderCalendarUi>,                  // flat Google calendars
        val internalCalendars: List<CalendarUi>,                  // AND-270, for the mapping picker
        val listState: ListState,                                 // Loading/Empty/Error/Offline/Loaded
        val reauthRequired: Boolean,
        val stale: Boolean,
    ) : GoogleCalendarUiState
    data class Error(val message: UiText) : GoogleCalendarUiState
}

@HiltViewModel
class GoogleCalendarViewModel @Inject constructor(
    private val repo: GoogleCalendarRepository,
) : ViewModel() {
    val uiState: StateFlow<GoogleCalendarUiState>
    fun onConnectClicked()                 // -> startConnect(), emits authorization_url as one-shot effect
    fun onReturnedFromCustomTab()          // re-read status; if active -> Connected, else cancelled
    fun onCallback(uri: Uri)               // optional deep-link return: validate state, completeConnect()
    fun onConnectCancelled()
    fun onRetry()
    fun onMapCalendar(googleCalendarId: String, internalCalendarId: String)  // POST .../mappings
    fun onRunSync()                        // optional: POST .../sync/run
    fun onDisconnect()
    val effects: SharedFlow<GoogleCalendarEffect>   // OpenCustomTab(url), ShowSnackbar(...)
}
```

The Custom Tab launch is a one-shot **effect** (not state) consumed by the
Composable, which uses `CustomTabsIntent`. **Correction/clarification:** the
server's redirect target is its own callback endpoint
(`GET /ui/calendar/integrations/google/connect/callback`, an HTTPS web URL), so
the primary return path is `onReturnedFromCustomTab()` → `refreshStatus()`
(observe `connection_active`). A custom-scheme deep link
(`testlogon://...`) is only viable if the backend registers it as the redirect
URI (unverified — Q-4); if wired, `onCallback(uri)` validates the echoed `state`
against the stored nonce and may call the GET callback with `code`+`state`. The
deep-link host/path used by earlier drafts (`integrations` /
`/google-calendar/callback`) is a client-side convention, not a backend-verified
value.

### 4.7 Composable

```kotlin
@Composable
fun GoogleCalendarConnectScreen(
    viewModel: GoogleCalendarViewModel = hiltViewModel(),
    onBack: () -> Unit,
)
```

Renders the connection card per state and the Google provider-calendar list.
**Correction:** the payload has no color or sync boolean, so each row shows
`summary` (name), a primary/access-role badge, a "Mapped/Unmapped" badge, and a
**mapping picker** (Material 3 `ExposedDropdownMenuBox` of internal calendars
from AND-270) rather than a color dot + sync `Switch`. Also renders the AND-021
state composables, an optional "Run Sync" action, and a disconnect confirmation
`AlertDialog`.

### 4.8 Hilt + Gradle

A `@Module @InstallIn(SingletonComponent::class)` provides `GoogleCalendarApi`
from the shared `Retrofit` (AND-010) and binds `GoogleCalendarRepository`. New
dependency: `androidx.browser:browser:1.8.0` in `feature-calendar`. No new
Retrofit/OkHttp instance.

## 5. API Contract

Base (`dev`): `http://18.222.237.167:8000/`. All reads ride the cookie session;
mutations additionally send `X-CSRF-Token` (sourced from the `ui_csrf` cookie —
verified in `src/api/client.ts`). **The whole §5 below has been corrected against
the OpenAPI index and `calendar.ts`; the previous paths/methods/fields were
wrong.** All endpoints additionally accept `params=user_sub,X-SESSION-ID,
X-IMPERSONATION-TOKEN` per the index — these are web/admin transport concerns;
the Android client relies on the cookie session and does not set them.

### POST `/ui/calendar/integrations/google/connect/start`
(op `google_calendar_connect_start_...`; web `startGoogleCalendarConnect`, posts
`{}`.) Response `200` `GoogleCalendarConnectStartOut`:
```json
{ "provider": "google",
  "authorization_url": "http://18.222.237.167:8000/mock/google-calendar/...",
  "state": "abc123", "nonce": "n-xyz", "expires_at_utc": "2026-06-06T12:05:00Z" }
```
In `staging`/`prod` `authorization_url` is a real Google consent URL (HTTPS).

### GET `/ui/calendar/integrations/google/connect/callback`
(op `google_calendar_connect_callback_...`; web `completeGoogleCalendarConnect`.)
Query params: `code`, `state`, `error` (all optional in the schema). **GET, not a
POST with a JSON body.** Response `200` `GoogleCalendarConnectCallbackOut`:
```json
{ "provider": "google", "connection_id": "conn_1",
  "account_email": "user@example.com", "linked": true,
  "updated_at_utc": "2026-06-06T12:00:00Z" }
```
This is the finalize step; it is usually reached server-side off the provider
redirect. `account_email` first appears here (status does not return it).

### GET `/ui/calendar/integrations/google/status`
(op `google_calendar_integration_status_...`.) Response `200`
`GoogleCalendarIntegrationStatusOut` — **booleans + rollout, no status string /
email / scopes:**
```json
{ "provider": "google", "connection_active": true,
  "sync_enabled": true, "writeback_enabled": false,
  "reauth_required": false, "sync_health": "healthy",
  "last_sync_status": "ok", "last_sync_at_utc": "2026-06-06T11:00:00Z",
  "rollout_mode": "cohort", "rollout_percent": 25, "in_rollout_cohort": true }
```
Required fields: `sync_enabled`, `writeback_enabled`, `rollout_mode`,
`rollout_percent`, `in_rollout_cohort`. When not connected, `connection_active`
is `false` (its default). If the integration is disabled for the account/env, the
web treats an error/empty status as "integration unavailable."

### GET `/ui/calendar/integrations/google/calendars`
(op `google_calendar_provider_calendars_...`.) Response `200`
`GoogleCalendarProviderCalendarsOut` — **`{ "calendars": [...] }` (not
`items`), each item flat (not a nested AND-270 calendar):**
```json
{ "calendars": [
    { "google_calendar_id": "gcal_primary", "summary": "user@example.com",
      "access_role": "owner", "primary": true,
      "mapped_internal_calendar_id": "cal_internal_1" },
    { "google_calendar_id": "gcal_team", "summary": "Team",
      "access_role": "reader", "primary": false,
      "mapped_internal_calendar_id": null }
  ] }
```
Only `google_calendar_id` is required; `summary` defaults `""`, `primary`
defaults `false`, `access_role`/`mapped_internal_calendar_id` are nullable.
No `color`, no `sync_enabled`, no `permission` field.

### POST `/ui/calendar/integrations/google/mappings`
(op `google_calendar_create_mapping_...`; web `createGoogleCalendarMapping`.)
Request `GoogleCalendarMappingCreateIn`:
`{ "internal_calendar_id": "cal_internal_1", "google_calendar_id": "gcal_team" }`.
Response `200` `GoogleCalendarMappingOut`:
```json
{ "mapping_id": "map_1", "provider": "google", "user_sub": "u_1",
  "internal_calendar_id": "cal_internal_1", "google_calendar_id": "gcal_team",
  "active": true, "created_at_utc": "...", "updated_at_utc": "...",
  "unmapped_at_utc": "" }
```
This replaces the (non-existent) per-calendar PATCH sync toggle.

### POST `/ui/calendar/integrations/google/disconnect`
(op `google_calendar_disconnect_...`; web `disconnectGoogleCalendar`, posts `{}`.)
Optional query param `connection_id`. **POST, not DELETE.** Response `200`
`GoogleCalendarDisconnectOut`:
```json
{ "provider": "google", "connection_id": "conn_1",
  "account_email": "user@example.com", "active": false, "revoked": true,
  "revoke_status": "revoked", "disconnected_at_utc": "2026-06-06T12:10:00Z" }
```

### POST `/ui/calendar/integrations/google/sync/run`
(op `google_calendar_manual_sync_run_...`; web `runGoogleCalendarSync`.) Query
param `mode` = `incremental` | `full`. Response `200` `GoogleCalendarSyncRunOut`:
`{ "accepted": true, "mode": "incremental", "rate_limited": false, "metrics": {} }`.
Optional for acceptance, included to match the web reference.

**Error envelope (all endpoints):** every op lists `422:HTTPValidationError`
(FastAPI `detail` array of `{loc,msg,type}`); other non-2xx use the FastAPI
`detail` union (`string | [{msg,type,loc}] | {code,...}`), mapped to typed
`ApiError` by AND-015. Non-2xx surfaces as `HttpException` into the repository,
which wraps it in `ApiResult.Error`.

## 6. Data & State Management

- **Source of truth:** the backend connection state. The client caches a
  projection (`connection_active`, account email — captured from the callback,
  not status — and `last_sync_at_utc`) in **DataStore**
  (`integrations_prefs`: `gcal_connection_active`, `gcal_account_email`,
  `gcal_oauth_state`, `gcal_oauth_nonce`) for instant render and process-death
  survival.
- **UI state:** `GoogleCalendarViewModel.uiState: StateFlow<GoogleCalendarUiState>`
  produced by combining `repo.observeStatus()` with on-demand provider-calendar
  loads. One-shot navigation/Custom-Tab/snackbar signals go through
  `effects: SharedFlow<GoogleCalendarEffect>`, never state, to avoid replay on
  recomposition/rotation.
- **OAuth state/nonce:** `connectStart()` returns both `state` and `nonce`;
  whichever the redirect echoes is written to DataStore before the Custom Tab
  opens and compared on return (R-2), then cleared. A mismatch aborts a
  client-driven callback. (Server-side validation is authoritative regardless.)
- **Provider calendars** are not persisted in Room for this ticket (small,
  viewer-scoped list; re-fetched on entering Connected). The optional merge of
  **mapped** calendars into the calendar views (AND-271) is a downstream
  follow-up. **Correction:** the merge key is the mapping
  (`mapped_internal_calendar_id`), not a `sync_enabled` flag.
- **Threading:** repository suspend calls run on an injected IO dispatcher;
  `StateFlow` is collected on the main dispatcher in Compose.

## 7. Error Handling & Resilience

- **Idempotent GETs** (`status`, `listProviderCalendars`, and the `callback` GET
  when the app drives it) use the shared ~20s timeout + bounded backoff
  (AND-016). On failure they surface `ApiResult.Error` mapped to a localized
  message with **Retry**; if a cached status exists, the Connected/Disconnected
  card is shown **stale** with a refresh affordance (AND-021/AND-117).
- **Mutations** (`connectStart`, `createMapping`, `disconnect`, `runSync`) are
  **never** auto-retried. Failures show an inline error / snackbar; the card
  reverts to its prior state. (`callback` is a GET but, when app-driven, is
  treated as a connect step and not blindly auto-retried either.)
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
  (AND-006). `staging`/`prod` are HTTPS-only, and the real `authorization_url` is
  HTTPS.
- **PII:** the connected Google **account email** is shown and cached in
  DataStore (app-private storage). **Correction:** it is sourced from the connect
  *callback* / disconnect responses (the status payload omits it). It must never
  appear in logs (Section 10).
- **Deep-link safety:** *if* a custom-scheme deep link is wired (Q-4,
  unverified), the intent filter must accept only the single registered callback
  path and the callback carries no secret beyond the `state`/`nonce` echo, which
  is single-use and validated. The verified backend redirect target is the HTTPS
  `GET .../connect/callback` web URL.

## 9. Accessibility & i18n

- All actions (Connect, Disconnect, per-calendar mapping picker, Run Sync) have
  `contentDescription`/`stateDescription`; the mapping picker announces the
  Google calendar name and its currently mapped internal calendar (or
  "Unmapped"). **Correction:** there is no per-calendar sync `Switch` (the
  backend has no `sync_enabled` per calendar); the row control is a mapping
  dropdown. The Mapped/Unmapped and primary/access-role badges carry meaning in
  text, not color alone.
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
  `gcal_disconnected`, `gcal_provider_calendars_loaded` (count only),
  `gcal_calendar_mapped` (no calendar id/name), `gcal_sync_run` (`mode` only).
  **No account email, no calendar names, no ids** in any event. **Correction:**
  the old `gcal_sync_toggled` event is renamed to `gcal_calendar_mapped` since
  the action is a mapping, not a sync toggle.
- **HTTP logging** inherited from AND-009's redacting interceptor (debug only);
  the `account_email`, `authorization_url`, `state`, and `nonce` fields must be redacted. A
  code-review check confirms no email/token/state reaches logcat in any build.
- No `Timber` payload dumps of integration responses.

## 11. Testing Strategy

> **Corrected to the verified contract.** T-cases below were updated to the real
> endpoints/shapes; the executable, traceable test plan is §17 (which supersedes
> any residual phrasing here).

**Unit / JVM (`core-network`, `core-data`) with MockWebServer:**

- **T-1** `connectStart` issues `POST ui/calendar/integrations/google/connect/start`,
  decodes `authorization_url` + `state` + `nonce`.
- **T-2** `connectCallback` issues `GET ui/calendar/integrations/google/connect/callback`
  with `code`/`state` query params; decodes `{connection_id, account_email,
  linked, updated_at_utc}`.
- **T-3** `status` issues `GET .../status`; `connection_active:true` →
  `ConnectPhase.CONNECTED`; `false` → `DISCONNECTED`; `reauth_required:true` →
  `REAUTH_REQUIRED`; missing optionals fall back to defaults (no throw).
- **T-4** `listProviderCalendars` issues `GET .../calendars`, decodes the
  `{calendars:[...]}` envelope, mapping each flat `ProviderCalendarDto`
  (`google_calendar_id`/`summary`/`access_role`/`primary`/
  `mapped_internal_calendar_id`).
- **T-5** `createMapping` issues `POST .../mappings` with
  `{"internal_calendar_id":...,"google_calendar_id":"gcal_team"}` and decodes
  `GoogleCalendarMappingOut`.
- **T-6** `disconnect` issues `POST .../disconnect` (optional `connection_id`
  query), decodes `GoogleCalendarDisconnectOut`; `runSync` issues
  `POST .../sync/run?mode=incremental`.
- **T-7** error propagation: `401`/`422`/`500` from `status` surfaces as
  `HttpException` → `ApiResult.Error` (not swallowed); `422` decodes
  `HTTPValidationError.detail`.
- **T-8** repository: `observeStatus()` emits the DataStore-cached value first,
  then the refreshed value (SWR); OAuth `state`/`nonce` persisted on
  `startConnect` and cleared after a successful callback; `accountEmail` cached
  from the callback response.

**ViewModel (coroutines test, fake repository):**

- **T-9** `onConnectClicked` emits an `OpenCustomTab(authorizationUrl)` effect and
  moves to `Connecting`.
- **T-10** `onReturnedFromCustomTab` after a successful connect re-reads status
  and transitions to `Connected`; a `onCallback` with **mismatched** `state`
  (when deep-link path is used) emits a failure snackbar and does not finalize.
- **T-11** `onConnectCancelled` reverts to the prior state and shows "Connection
  cancelled"; no partial connection persisted.
- **T-12** `onDisconnect` confirms then transitions Connected → Disconnected and
  clears the provider-calendar list.
- **T-13** Connected with zero items → `ListState.Empty`; status fetch failure
  with cached value → `stale = true`.

**Compose UI tests (`feature-calendar`):**

- **T-14** Disconnected state shows **Connect Google Calendar**; tapping invokes
  the connect path (effect asserted via test double / Espresso-Intents stub for
  the Custom Tab intent).
- **T-15** Connected state renders the cached account email (if present) and the
  Google provider-calendar list with mapping pickers; choosing an internal
  calendar calls `onMapCalendar`.
- **T-16** Error and Offline states render the AND-021 composables with Retry.

Coverage target ≥85% on the new surface (API binding, mappers, repository,
ViewModel). The pair (T-1/T-3 + T-9/T-10) proves **Connect**; T-4 + T-15 prove
**list external calendars** — the two backlog acceptance items.

## 12. Dependencies & Sequencing

**Hard upstream (must merge first):**
- **AND-270** — Calendar API + DTOs. **Correction:** the provider-calendar list
  does NOT reuse `CalendarDto`; AND-270 is needed because the *mapping* feature
  targets an `internal_calendar_id` drawn from AND-270's `getCalendars`, and that
  internal-calendar list renders via the AND-270 `Calendar` type in the mapping
  picker. Blocking per backlog `Deps: AND-270`.

**Transitive upstream (already required):** AND-009/AND-010 (shared
OkHttp/Retrofit/Moshi), AND-011/AND-012/AND-013 (cookies/CSRF/refresh), AND-015
(error mapping), AND-016 (idempotent-GET backoff), AND-017 (connectivity),
AND-018 (`ApiResult`), AND-021 (state composables), AND-022/AND-024/AND-025 +
AND-108 (navigation + deep-link routing), AND-111/AND-114 (i18n/RTL), AND-052
(redacted telemetry), AND-116/AND-117 (SWR/stale hooks), AND-006
(`BuildConfig`/cleartext config).

**Soft sibling:** **AND-271** (calendar views) — the visual surface into which
**mapped** external calendars are eventually merged; that merge is a follow-up
after this ticket lands, not part of this acceptance. This ticket does not block
AND-271 (`blocks: []`).

**Sequencing within the ticket:** (1) ✅ endpoint paths/verbs, the dev mock
wiring, the callback (finalize) contract, and field names are now confirmed
against the OpenAPI index + `calendar.ts` (see §5/§16); (2) DTOs + mappers +
`GoogleCalendarApi` + Hilt module
(`core-network`); (3) `GoogleCalendarRepository` + DataStore cache (`core-data`);
(4) ViewModel + UI state/effects; (5) Composable + navigation/deep-link wiring +
manifest intent filter; (6) tests T-1..T-16.

## 13. Risks & Open Questions

- **R-1 Finalize mechanism (RESOLVED).** Finalize is `GET .../connect/callback`
  with `code`/`state` query params, normally executed server-side off the
  provider redirect — there is **no** `POST .../oauth/finalize`. *Mitigation:*
  on return to the app, call `refreshStatus()` and read `connection_active`; only
  drive the GET callback from the client if a custom-scheme redirect is wired.
  Guarded by T-2/T-3/T-10.
- **R-2 Callback delivery / state validation (PARTLY OPEN).** The verified
  redirect is the backend's HTTPS callback URL, so the default path is
  Custom-Tab-return → `refreshStatus()`. A custom-scheme deep link is only viable
  if the backend registers it (Q-4). *Mitigation:* DataStore-stored `state`/
  `nonce`; if a deep link is used, validate and reject mismatches; treat
  no-callback-on-resume as cancel.
- **R-3 Real vs mock divergence.** Only the dev mock (`/mock/google-calendar/...`)
  is exercisable now; real Google consent (HTTPS, real `code`) is untested until
  staging. *Mitigation:* keep `authorization_url`/`code` server-supplied and
  opaque so the client path is identical; flag staging verification.
- **R-4 Provider-calendar shape (RESOLVED).** The endpoint returns a **flat**
  `GoogleCalendarProviderCalendarOut` (no nested `CalendarDto`) under a
  `calendars` key. The spec now matches OpenAPI; the earlier "nested
  `{calendar:{...}}`" default was wrong and has been removed.
- **R-5 Account email PII.** Caching/showing the email is required for UX but is
  PII. *Mitigation:* app-private DataStore, redaction in logs/telemetry (Section
  8/10), confirmed in review. Note the email comes from the *callback*, not
  status.
- **Q-1 (RESOLVED)** Paths/verbs confirmed against OpenAPI: base
  `ui/calendar/integrations/google/...`; connect=`POST .../connect/start`,
  callback=`GET .../connect/callback`, disconnect=`POST .../disconnect`
  (not DELETE).
- **Q-2 (RESOLVED)** No `setSync`/PATCH and no per-calendar sync boolean. The
  per-calendar control is `POST .../mappings`
  (`internal_calendar_id`+`google_calendar_id`). Listing alone still satisfies
  acceptance; mapping is the value-add matching the web client.
- **Q-3 (RESOLVED)** Status has no `connecting`/`connected` string — it exposes
  `connection_active` (+ `reauth_required`). The client owns the transient
  `Connecting` state purely while the Custom Tab is open, then reads
  `connection_active`.
- **Q-4 (OPEN)** Is the redirect URI the backend HTTPS callback (verified to
  exist) or a registered custom scheme? *Proposed:* default to the backend HTTPS
  callback + Custom-Tab-return refresh; confirm with backend before wiring any
  `testlogon://` intent filter. Not resolvable from the provided sources.

## 14. Acceptance Criteria

- **AC-1 (backlog — Connect).** From the Disconnected state, the user can connect
  Google Calendar: `connectStart` (`POST .../connect/start`) opens the
  `authorization_url` (dev: a `/mock/google-calendar/...` URL) in a Custom Tab;
  after the backend callback completes the link, `status` reports
  `connection_active:true` and the screen transitions to Connected (account email
  cached from the callback) (T-1, T-3, T-9, T-10, T-14).
- **AC-2 (backlog — list external calendars).** In the Connected state, the
  Google provider calendars are listed (`summary`/name, primary/access-role
  badge, mapped/unmapped), decoded from the `{calendars:[...]}` envelope of
  `GET .../calendars` as flat `ProviderCalendar` items (T-4, T-15).
- **AC-3.** Disconnect returns the screen to Disconnected and clears the list
  (T-12).
- **AC-4.** Idempotent reads (`status`, `calendars`) retry with bounded backoff
  and degrade to error-with-retry / stale-cached states; mutations are not
  auto-retried (T-7, T-13, T-16).
- **AC-5.** OAuth `state`/`nonce` are generated server-side (`connect/start`),
  stored client-side; server-side validation on the callback is authoritative,
  and any client-driven callback validates the echoed `state` and aborts on
  mismatch (T-10).
- **AC-6.** No Google tokens are stored on device; only cookie session + CSRF are
  used for app calls; Custom Tabs (not WebView) carry the consent (Section 8,
  review).
- **AC-7.** Cancelling the Custom Tab returns to the prior state with a
  non-blocking message and no partial connection (T-11).
- **AC-8.** `connection_active` + cached account email survive process death via
  DataStore and render immediately, then refresh (T-8).
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
- Open questions Q-1..Q-3 resolved against `/openapi.json` and
  `frontend/src/api/endpoints/calendar.ts` + `types.ts` (see §16); Q-4 (redirect
  URI scheme) confirmed with backend before any deep-link wiring; paths/verbs,
  the callback (finalize) contract, and field names reflect the confirmed
  contract.
- Navigation route wired through the single-Activity graph; the Custom-Tab-return
  → `refreshStatus()` path is the default. A manifest deep-link intent filter is
  added only if/when the backend confirms a custom-scheme redirect URI (Q-4).
  `androidx.browser:browser:1.8.0` added to `feature-calendar`.
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
- Code reviewed and merged to `android-port`; the follow-up to merge **mapped**
  external calendars into the AND-271 calendar views is filed.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources:
OpenAPI index = `reference/openapi.index.txt`; OpenAPI spec =
`reference/openapi.pretty.json` (`components.schemas.<Name>`); frontend paths are
under `reference/src/`.

1. **Connect-start endpoint is `POST /ui/calendar/integrations/google/connect/start`.**
   VERDICT: Corrected (was `POST integrations/google-calendar/oauth/start`).
   SOURCE: OpenAPI `POST /ui/calendar/integrations/google/connect/start`
   (op `google_calendar_connect_start_...`); `src/api/endpoints/calendar.ts:
   startGoogleCalendarConnect`.
2. **Connect-start response is `GoogleCalendarConnectStartOut` with
   `authorization_url`, `state`, `nonce`, `expires_at_utc`, `provider`.**
   VERDICT: Corrected (was `authorize_url` + `state` only).
   SOURCE: schema `GoogleCalendarConnectStartOut`;
   `src/api/types.ts: GoogleCalendarConnectStart`.
3. **Finalize is `GET /ui/calendar/integrations/google/connect/callback` with
   `code`/`state`/`error` query params — there is no `POST .../oauth/finalize`.**
   VERDICT: Corrected. SOURCE: OpenAPI
   `GET /ui/calendar/integrations/google/connect/callback`
   (params `code,state,error,...`); `src/api/endpoints/calendar.ts:
   completeGoogleCalendarConnect`. (No `oauth/finalize` path exists in the index.)
4. **Callback response `GoogleCalendarConnectCallbackOut`:
   `connection_id`, `account_email`, `linked`, `updated_at_utc`, `provider`.**
   VERDICT: Verified. SOURCE: schema `GoogleCalendarConnectCallbackOut`;
   `src/api/types.ts: GoogleCalendarConnectCallback`.
5. **Status is `GET /ui/calendar/integrations/google/status` returning booleans
   (`connection_active`, `sync_enabled`, `writeback_enabled`, `reauth_required`,
   …) — NOT a `status` string, `account_email`, `connected_at`, or `scopes`.**
   VERDICT: Corrected. SOURCE: OpenAPI
   `GET /ui/calendar/integrations/google/status`; schema
   `GoogleCalendarIntegrationStatusOut`; `src/api/types.ts:
   GoogleCalendarIntegrationStatus`.
6. **Provider calendars: `GET /ui/calendar/integrations/google/calendars`
   returns `{ "calendars": [...] }` (not `items`); each item is a flat
   `GoogleCalendarProviderCalendarOut` (`google_calendar_id`, `summary`,
   `access_role`, `primary`, `mapped_internal_calendar_id`) — NOT a nested
   AND-270 `CalendarDto`, no `color`/`sync_enabled`/`permission`.**
   VERDICT: Corrected. SOURCE: OpenAPI
   `GET /ui/calendar/integrations/google/calendars`; schemas
   `GoogleCalendarProviderCalendarsOut` / `GoogleCalendarProviderCalendarOut`;
   `src/api/types.ts: GoogleCalendarProviderCalendar(s)`.
7. **Per-calendar control is mapping, not a sync toggle:
   `POST /ui/calendar/integrations/google/mappings` with
   `{internal_calendar_id, google_calendar_id}` → `GoogleCalendarMappingOut`.
   There is no `PATCH .../calendars/{id}` and no `sync_enabled` per calendar.**
   VERDICT: Corrected. SOURCE: OpenAPI
   `POST /ui/calendar/integrations/google/mappings`; schemas
   `GoogleCalendarMappingCreateIn` / `GoogleCalendarMappingOut`;
   `src/api/endpoints/calendar.ts: createGoogleCalendarMapping`;
   `src/pages/calendar/GoogleCalendarIntegration.tsx` (mapping `Select`).
8. **Disconnect is `POST /ui/calendar/integrations/google/disconnect` (optional
   `connection_id` query) → `GoogleCalendarDisconnectOut` — NOT
   `DELETE integrations/google-calendar`.**
   VERDICT: Corrected. SOURCE: OpenAPI
   `POST /ui/calendar/integrations/google/disconnect` (params `connection_id,...`);
   schema `GoogleCalendarDisconnectOut`; `src/api/endpoints/calendar.ts:
   disconnectGoogleCalendar`.
9. **Manual sync exists: `POST /ui/calendar/integrations/google/sync/run?mode=`
   (`incremental`|`full`) → `GoogleCalendarSyncRunOut`.**
   VERDICT: Verified (was omitted from the draft). SOURCE: OpenAPI
   `POST /ui/calendar/integrations/google/sync/run`; schema
   `GoogleCalendarSyncRunOut`; `src/api/endpoints/calendar.ts:
   runGoogleCalendarSync`.
10. **Auth: cookie session + `X-CSRF-Token` on mutations; CSRF token read from
    the `ui_csrf` cookie; requests sent with credentials.**
    VERDICT: Verified. SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` →
    `headers.set("X-CSRF-Token", csrf)`, `credentials: "include"`).
11. **`/mock/google-calendar/...` is the Google-API mock root (oauth token/
    userinfo/revoke, `calendar/v3/...`, seed/reset) — not a client connect path.**
    VERDICT: Corrected/clarified. SOURCE: OpenAPI index lines for
    `POST /mock/google-calendar/oauth/token`,
    `GET /mock/google-calendar/oauth/userinfo`,
    `GET /mock/google-calendar/calendar/v3/users/me/calendarList`,
    `POST /mock/google-calendar/seed|reset`.
12. **Web client opens `authorization_url` in a new browser context and has no
    explicit client-side `state` comparison (server handles the callback).**
    VERDICT: Verified. SOURCE: `src/pages/calendar/GoogleCalendarIntegration.tsx`
    (`window.open(data.authorization_url, ...)`); no client `state` check present.
13. **Error envelope: `422 HTTPValidationError` on every op; FastAPI `detail`
    union otherwise; mapped by AND-015.**
    VERDICT: Verified. SOURCE: OpenAPI index (`resp=...;422:HTTPValidationError`
    on each Google op); schema `HTTPValidationError`.
14. **Custom Tabs via AndroidX Browser for the consent hand-off.**
    VERDICT: Unverified-assumption (Android implementation choice; not in
    backend/web sources). SOURCE: framework ref —
    https://developer.android.com/develop/ui/views/layout/webapps/customtabs .
15. **AND-270 supplies the internal `Calendar` list used by the mapping picker
    (`getCalendars`).** VERDICT: Verified (web usage). SOURCE:
    `src/api/endpoints/calendar.ts: getCalendars` (`GET /ui/calendars`);
    `GoogleCalendarIntegration.tsx` populates the picker from it. The AND-270
    Android types themselves are an upstream dependency (not in these sources).

### Corrections made

- Endpoint base path: `integrations/google-calendar/...` → `ui/calendar/integrations/google/...` (all endpoints). [#1,#3,#5,#6,#7,#8,#9]
- Connect-start field `authorize_url` → `authorization_url`; added `nonce`, `expires_at_utc`. [#2]
- Finalize: removed the invented `POST .../oauth/finalize` JSON endpoint; replaced with the real `GET .../connect/callback?code=&state=&error=`. [#3]
- Status DTO: removed `status`/`account_email`/`connected_at`/`scopes`; replaced with the real boolean/rollout fields; connection phase now derived from `connection_active`/`reauth_required`. [#5]
- Provider calendars: `{items:[{calendar:{…}}]}` → `{calendars:[{…flat…}]}`; dropped reuse of AND-270 `CalendarDto`; added the flat `ProviderCalendar` type. [#6]
- Per-calendar sync toggle (`PATCH .../calendars/{id}`, `sync_enabled`) → mapping (`POST .../mappings`). UI switch → mapping picker; telemetry `gcal_sync_toggled` → `gcal_calendar_mapped`. [#7]
- Disconnect: `DELETE integrations/google-calendar` → `POST .../disconnect?connection_id=`. [#8]
- Added the omitted `POST .../sync/run` endpoint and DTO. [#9]
- Account email re-sourced from the connect callback (status omits it); §6/§8/§14 updated. [#4,#5]
- Field-name fixes in §10 (`authorize_url` → `authorization_url`, add `nonce`).
- Resolved Q-1/Q-2/Q-3 and R-1/R-4; reframed R-2/Q-4 around the verified HTTPS backend callback.

### Open assumptions

- **Redirect URI scheme (Q-4).** Whether the OAuth redirect is the backend HTTPS
  callback (verified to exist) or a registered `testlogon://` custom scheme is
  not determinable from the provided sources (the web client never returns to an
  app; the backend handles the redirect). Spec defaults to Custom-Tab-return →
  `refreshStatus()` and gates any deep-link intent filter on backend confirmation.
- **Custom Tabs / AndroidX Browser choice (#14).** A native-Android decision with
  no backend/web equivalent; cited to Android docs, not the repo.
- **`connecting` server state.** No server-side "connecting" phase exists
  (status is boolean); the transient `Connecting` UI state is purely client-owned
  while the Custom Tab is open — an interaction-design assumption.
- **AND-270 Android type shapes.** `Calendar`/`getCalendars` are confirmed in the
  web reference, but the AND-270 *Android* DTO/domain shapes are an upstream
  dependency not present in these sources; mapping-picker integration assumes
  AND-270 lands as specified.

## 17. Test Plan

Test targets: **JVM** (local Robolectric/JUnit, no device); **emulator** = AVD
`test35` (x86_64, API 35); **device** = Samsung Galaxy A15 5G (SM-A156U,
`R5CX821TA9R`, API 34, arm64-v8a). MockWebServer drives contract tests on JVM.
Cases trace to §14 acceptance criteria.

- **TC-AND-273-01 — Connect-start contract.** Type: contract/MockWebServer.
  Target: JVM. Preconditions: MockWebServer enqueues a `200`
  `GoogleCalendarConnectStartOut`. Steps: call `GoogleCalendarApi.connectStart()`.
  Expected: request is `POST ui/calendar/integrations/google/connect/start` with
  an empty/`{}` JSON body and `X-CSRF-Token` header; response decodes
  `authorizationUrl`, `state`, `nonce`, `expiresAtUtc`. Traces: AC-1, AC-6.

- **TC-AND-273-02 — Callback (finalize) contract.** Type: contract/MockWebServer.
  Target: JVM. Preconditions: enqueue `200`
  `GoogleCalendarConnectCallbackOut`. Steps: call
  `connectCallback(code="c", state="abc123")`. Expected: request is
  `GET ui/calendar/integrations/google/connect/callback?code=c&state=abc123`;
  decodes `connectionId`/`accountEmail`/`linked=true`/`updatedAtUtc`. Traces:
  AC-1, AC-5.

- **TC-AND-273-03 — Status mapping (3 phases).** Type: unit + contract. Target:
  JVM. Preconditions: enqueue `connection_active:true`; then
  `connection_active:false`; then `reauth_required:true`. Steps: call `status()`
  + `toPhase()` for each. Expected: `CONNECTED`, `DISCONNECTED`,
  `REAUTH_REQUIRED`; missing optional fields use schema defaults; no exception.
  Traces: AC-1, AC-4.

- **TC-AND-273-04 — Provider-calendars decode/map.** Type: contract/MockWebServer.
  Target: JVM. Preconditions: enqueue `200`
  `{calendars:[{google_calendar_id,summary,access_role,primary,
  mapped_internal_calendar_id}, …]}`. Steps: call `listProviderCalendars()`.
  Expected: request `GET .../calendars`; `calendars` envelope decoded; each flat
  item mapped to `ProviderCalendar` with `primary`/`accessRole`/`mapped…`
  preserved; nullable `access_role`/`mapped_internal_calendar_id` tolerated.
  Traces: AC-2.

- **TC-AND-273-05 — Create mapping.** Type: contract/MockWebServer. Target: JVM.
  Preconditions: enqueue `200` `GoogleCalendarMappingOut`. Steps: call
  `createMapping(internalCalendarId="cal_1", googleCalendarId="gcal_team")`.
  Expected: request `POST .../mappings` body
  `{"internal_calendar_id":"cal_1","google_calendar_id":"gcal_team"}` with
  `X-CSRF-Token`; decodes `mappingId`/`active`. Traces: AC-2.

- **TC-AND-273-06 — Disconnect + sync-run verbs/params.** Type:
  contract/MockWebServer. Target: JVM. Preconditions: enqueue `200`
  `GoogleCalendarDisconnectOut`, then `200` `GoogleCalendarSyncRunOut`. Steps:
  call `disconnect("conn_1")` then `runSync("incremental")`. Expected: requests
  are `POST .../disconnect?connection_id=conn_1` and
  `POST .../sync/run?mode=incremental` (both POST, not DELETE/GET); responses
  decode. Traces: AC-3.

- **TC-AND-273-07 — Error envelopes propagate.** Type: contract/MockWebServer.
  Target: JVM. Preconditions: enqueue `401`, then `422`
  (`{"detail":[{"loc":["query","state"],"msg":"field required","type":"value_error"}]}`),
  then `500` for `status()`. Steps: call `status()` three times via the
  repository. Expected: each surfaces `ApiResult.Error` (not swallowed); the
  `422` body decodes to the validation `detail` list per AND-015. Traces: AC-4.

- **TC-AND-273-08 — SWR cache + nonce/email persistence (process death).**
  Type: unit (DataStore, coroutines). Target: JVM. Preconditions: DataStore
  pre-seeded with `gcal_connection_active=true`, `gcal_account_email`. Steps:
  collect `observeStatus()` while the network status call is delayed/failing.
  Expected: cached value emits first (`stale=true`), then the refreshed value;
  `state`/`nonce` written on `startConnect` and cleared after a successful
  callback; `accountEmail` captured from the callback response. Traces: AC-8,
  AC-5, AC-4.

- **TC-AND-273-09 — ViewModel connect effect.** Type: unit (ViewModel, fake
  repo). Target: JVM. Preconditions: repo returns a `ConnectStart`. Steps: call
  `onConnectClicked()`. Expected: emits one `OpenCustomTab(authorizationUrl)`
  effect (not state) and moves to `Connecting`; no replay on re-collection.
  Traces: AC-1, AC-7.

- **TC-AND-273-10 — Return/callback success vs state mismatch.** Type: unit
  (ViewModel, fake repo). Target: JVM. Preconditions: stored `state="abc123"`.
  Steps: (a) `onReturnedFromCustomTab()` with repo status `connection_active:true`
  → `Connected`; (b) `onCallback(uri with state="zzz")` (deep-link path) →
  failure snackbar, no finalize/connection. Expected: (a) transitions to
  Connected; (b) mismatch rejected, prior state retained. Traces: AC-1, AC-5,
  AC-7.

- **TC-AND-273-11 — Cancel Custom Tab.** Type: unit (ViewModel) + manual.
  Target: JVM (logic); device (real Custom Tab dismissal). Preconditions: in
  `Connecting`. Steps: `onConnectCancelled()` (JVM) / dismiss the Custom Tab and
  return to the app (device). Expected: reverts to the prior state, shows a
  non-blocking "Connection cancelled", clears stored `state`/`nonce`, persists no
  partial connection. Traces: AC-7. (Device run validates real Chrome Custom Tab
  back-navigation on API 34/arm64.)

- **TC-AND-273-12 — Disconnect clears list.** Type: unit (ViewModel, fake repo).
  Target: JVM. Preconditions: `Connected` with ≥1 provider calendar. Steps:
  `onDisconnect()`, confirm the dialog. Expected: repo `disconnect()` called;
  state → `Disconnected`; provider-calendar list cleared. Traces: AC-3.

- **TC-AND-273-13 — Compose: list + mapping picker + a11y.** Type: Compose-UI.
  Target: emulator `test35`. Preconditions: ViewModel seeded `Connected` with two
  provider calendars (one mapped, one unmapped) and internal calendars. Steps:
  assert each row shows `summary`, a primary/access-role badge, a Mapped/Unmapped
  badge, and a mapping dropdown; open the dropdown and select an internal
  calendar; run accessibility assertions (every actionable node has a
  non-empty content/state description; no color-only signaling; usable at 200%
  font scale). Expected: selection invokes `onMapCalendar(googleId, internalId)`;
  a11y assertions pass. Traces: AC-2, AC-9.

- **TC-AND-273-14 — Compose: Disconnected connect + Error/Offline states.** Type:
  Compose-UI (+ Espresso-Intents). Target: emulator `test35`. Preconditions:
  Disconnected state; later Error and Offline states. Steps: assert "Connect
  Google Calendar" is shown; tap it and assert a Custom-Tab `Intent` (ACTION_VIEW
  with the authorization URL) is launched via an Espresso-Intents stub; then
  render Error and Offline and assert the AND-021 composables with Retry. Expected:
  connect intent fired; Retry re-invokes the idempotent reads. Traces: AC-1,
  AC-4, AC-6.

- **TC-AND-273-15 — Security: no Google tokens / PII not logged; HTTPS in
  release.** Type: instrumented + manual review. Target: device (real network +
  logcat) and JVM. Steps: run a full connect→list→disconnect on the device
  against dev; capture logcat and inspect DataStore; in a release build, assert
  cleartext is disabled and the integration calls require HTTPS. Expected: no
  Google access/refresh token anywhere on device (only cookie session + CSRF);
  `account_email`/`authorization_url`/`state`/`nonce` never appear in logcat;
  telemetry events carry no email/name/id; release build rejects cleartext.
  Traces: AC-6, AC-9. (MUST run on the physical device: real network + system
  Custom Tab + on-device storage inspection.)

- **TC-AND-273-16 — Flaky-dev-host / offline path.** Type: integration +
  instrumented. Target: JVM (MockWebServer throttle/timeout) and device (airplane
  mode). Preconditions: cached Connected status in DataStore. Steps: induce a
  ~20s timeout / `SocketTimeoutException` on `status`/`calendars` (MockWebServer)
  and toggle airplane mode (device). Expected: idempotent GETs back off (AND-016)
  then surface error-with-Retry while the cached card renders `stale=true`;
  mutations are not auto-retried; recovery on reconnect refreshes the card.
  Traces: AC-4, AC-8.

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 (Connect) | TC-01, TC-02, TC-03, TC-09, TC-10, TC-14 |
| AC-2 (List external calendars) | TC-04, TC-05, TC-13 |
| AC-3 (Disconnect clears) | TC-06, TC-12 |
| AC-4 (Idempotent retry / no mutation retry / stale) | TC-03, TC-07, TC-16, TC-14 |
| AC-5 (state/nonce validation) | TC-02, TC-08, TC-10 |
| AC-6 (No tokens; cookie+CSRF; Custom Tabs) | TC-01, TC-14, TC-15 |
| AC-7 (Cancel) | TC-09, TC-10, TC-11 |
| AC-8 (Process-death survival) | TC-08, TC-16 |
| AC-9 (No PII in logs/telemetry) | TC-13, TC-15 |
| AC-10 (CI build/tests green) | All TC run in CI (TC-13/14 on `test35`; TC-11/15/16 device legs are manual/nightly) |
