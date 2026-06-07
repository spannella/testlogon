---
id: AND-391
title: "Public event (`/event/:calendarId/:eventId`)"
milestone: M8
epic: E51
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-272]
blocks: []
---

# AND-391 — Public event (`/event/:calendarId/:eventId`)

## 1. Overview & Goal

This ticket delivers the **public event view** for TestLogon Android: a read-only, deep-linkable screen that renders a single calendar event addressed by the pair `(calendarId, eventId)` and is reachable by tapping the web URL `https://<host>/event/<calendarId>/<eventId>`. The canonical web behaviour is the contract — the route `/event/:calendarId/:eventId` renders the public-facing projection of an event (title, time window, location/host, description, and a public RSVP/attendance affordance where the backend exposes one) without requiring an authenticated session.

AND-272 (M6) already introduced event detail **and** a first cut of the public `/event/:calendarId/:eventId` App Link as part of the authenticated calendar feature. This M8/E51 ticket is the **public-distribution hardening** pass: it owns the standalone public entry point so that a shared event link opens the native app cleanly even for a logged-out or never-logged-in user, formalizes the three terminal UI states (loaded / not-found / private-or-restricted), the App Link host split for the plaintext dev backend, and the cold-start back-stack behaviour. The point of the ticket per the backlog is narrow and testable: **a public event opens via link.**

This ticket does **not** introduce the calendar network/DTO layer (AND-270) nor the NavHost/route plumbing (AND-022); it consumes the `EventRepository` / `EventApi` and route registration that AND-272 already wired. It reuses, does not duplicate, the event-detail rendering composables — the public view is a thin, unauthenticated, deep-link-first wrapper over the same domain model with private/restricted fields stripped.

Out of scope: editing events, creating/scheduling events (AND-275), Google Calendar sync (AND-273), ICS export (AND-276), and the authenticated calendar month/week/agenda views (AND-271). Those are separate E37 tickets. This screen renders the **public** projection of one event only.

## 2. Context & References

- **Module**: the existing `feature-calendar` module under `android/feature/feature-calendar/`, namespace `com.testlogon.android.feature.calendar`. New public-view sources live in `…/feature/calendar/event/public/`. Layering: `app -> feature-calendar -> core-network, core-model, core-ui, core-data, core-testing`.
- **Upstream deps**:
  - **AND-272 — Event detail (+ public event)**: provides `EventApi`, `EventRepository.getPublicEvent(calendarId, eventId)`, the `CalendarEvent` domain model + DTO mapping, the in-app `EventDetailScreen` rendering composables, and the first registration of the `/event/:calendarId/:eventId` deep link in the AND-022 `NavHost`. This ticket extends that registration for the public/unauthenticated path and reuses the rendering composables.
  - **AND-270 — Calendar API + DTOs** (transitive, via AND-272): defines the event payload shapes (`events`, recurrence).
  - **AND-022 — Navigation host & routes** (transitive, via AND-272): the single-Activity `NavHost` and typed deep-link mechanism.
- **Web reference**: `src/api/endpoints/calendar.ts` (`getPublicEvent` / `getPublicIcalUrl`), `src/api/types.ts` (`CalendarEventAttachment` — the actual public-event DTO), `src/api/client.ts` (transport/auth/CSRF), `src/pages/calendar/PublicEventPage.tsx` (screen behaviour), and the route `/event/:calendarId/:eventId` registered in `src/App.tsx`. **CORRECTED**: the verified backend endpoint is `GET /calendar/public/event/{calendar_id}/{event_id}` (OpenAPI op `get_public_event_...`), **not** `/ui/calendar/{calendarId}/event/{eventId}` — that path does not exist in the OpenAPI spec. Note it is **not** under the `/ui/` prefix, so it carries no `X-SESSION-ID`/`user_sub` UI params.
- **Stack**: Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow, Coil (cover image/avatar), Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6 cache. minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3.
- **Backend reality**: dev host `18.222.237.167:8000` is **plaintext HTTP** and unreliable (~20s timeouts, bounded backoff for idempotent GETs only). App Links require HTTPS + Digital Asset Links verification → see §8 for the dev-vs-prod host split.

## 3. Functional Requirements

FR-1 **Route**: The public view is registered as a typed route `EventRoute.Public(calendarId: String, eventId: String)` rendering at in-app path `event/public/{calendarId}/{eventId}`.

FR-2 **App Link**: Tapping `https://<verified-host>/event/<calendarId>/<eventId>` opens the app directly to this screen with both path segments extracted. The link is an **autoVerified** App Link in `release`. A custom-scheme fallback `testlogon://event/<calendarId>/<eventId>` is accepted on all builds for share flows and for `debug`/`internal`.

FR-3 **Unauthenticated entry**: The screen loads and renders **without** requiring a session. If a cookie jar/session exists it is attached opportunistically (CSRF header echoed), but absence of a session must never block the public read or force a login wall.

FR-4 **Load**: On entry the screen fetches the public event via `GET /calendar/public/event/{calendarId}/{eventId}` (CORRECTED path — verified against OpenAPI + `calendar.ts:getPublicEvent`) and shows a skeleton/loading state until the result resolves.

FR-5 **Loaded state**: Render the fields the verified `CalendarEventAttachment` DTO actually exposes: `name` (title), `start_utc`/`end_utc` (timezone-aware), `all_day` flag + `all_day_date`, `description`, and `timezone`. The DTO also carries `owner` (a user-sub string, not a display profile) and the `event_id`/`calendar_id`. Null/absent optional fields (`start_utc`, `end_utc`, `description`, `all_day_date`) are omitted, never rendered as empty rows. **CORRECTED — removed unverifiable fields**: the DTO has **no** `host`/organizer profile, `location`/`join_url`, `recurrence`, or `rsvp` object, so this ticket does **not** render an organizer card, location row, recurrence summary, RSVP/going count, or join CTA — those were spec assumptions not present in the contract. The verified public affordances (mirroring the web `PublicEventPage`) are a **"Download .ics"** action (opens `GET /calendar/public/event/{calendarId}/{eventId}/ical`) and, only when a session exists, an **"Add to my calendar"** action (`POST /ui/calendars/{calendarId}/events`); logged-out users see a "Sign in to add to calendar" affordance instead.

FR-6 **Not-found / error state**: Any error from the public GET (HTTP 404, other non-2xx, or network failure) renders a single "Event not found" empty state ("This event may have been removed or is no longer public.") with a Back/"Go home" action. **CORRECTED**: the web reference treats *all* errors as one not-found state (`isError || !evt`) with `retry: false` (no retry). This Android ticket MAY add a Retry affordance for transient (network/5xx) failures as a deliberate enhancement (see §7) — that retry behaviour is an **app-layer addition, not a web-reference behaviour**.

FR-7 **Private/restricted state**: **CORRECTED / DOWNGRADED TO ASSUMPTION** — the verified contract exposes no `is_public`/`visibility` field and the web app implements no distinct "private" UI; private/removed events simply surface as the not-found/error state (the backend either returns the event publicly or returns an error). A dedicated "This event is private" state is therefore an **unverified speculative state**. If retained, it must be driven solely by an observed HTTP status (e.g. 403) and never by DTO fields that do not exist; otherwise fold it into FR-6. Default: treat 403 the same as the not-found/error state unless backend behaviour is confirmed.

FR-8 **Offline/stale**: If the request fails due to connectivity and a cached copy exists (Room cache via AND-272's layer keyed by `(calendarId, eventId)`), render the cached event with a non-blocking "Showing saved copy" banner. If no cache, show an offline error state with **Retry**.

FR-9 **Retry**: Generic/transient errors (timeout, 5xx, network) show an error state with a Retry action that re-issues the idempotent GET.

FR-10 **Back / cold start**: System Back and the top-app-bar up affordance pop the screen. If the screen is the deep-link cold-start entry point (empty back stack), Back routes to the app's home/start destination rather than exiting the app.

FR-11 **Identifier passthrough**: `calendarId` and `eventId` are treated as opaque; each is URL-decoded once on extraction and passed verbatim to the API. No client-side normalization or validation beyond non-empty.

## 4. Technical Design

### Module & files

```
feature-calendar/
  src/main/kotlin/com/testlogon/android/feature/calendar/event/public/
    PublicEventScreen.kt
    PublicEventViewModel.kt
    PublicEventUiState.kt
    PublicEventNav.kt
  src/main/AndroidManifest.xml          // intent-filter merged into app manifest
  src/main/res/values/strings.xml       // public-event string keys (additions)
```

### Route registration (consumes AND-022 / AND-272)

```kotlin
// PublicEventNav.kt
@Serializable
data class PublicEventRoute(val calendarId: String, val eventId: String)

fun NavGraphBuilder.publicEventScreen(onBack: () -> Unit) {
    composable<PublicEventRoute>(
        deepLinks = listOf(
            navDeepLink<PublicEventRoute>(
                basePath = "https://${'$'}{BuildConfig.APP_LINK_HOST}/event"
            ),
            navDeepLink<PublicEventRoute>(basePath = "testlogon://event"),
        ),
    ) {
        PublicEventScreen(onBack = onBack)
    }
}

fun NavController.navigateToPublicEvent(calendarId: String, eventId: String) =
    navigate(PublicEventRoute(calendarId, eventId))
```

The `{calendarId}` and `{eventId}` path segments map onto the route fields via type-safe Navigation-Compose deep linking. `APP_LINK_HOST` is a per-build-type `BuildConfig` field (§8). This `publicEventScreen(...)` builder is registered in the AND-022 `NavHost` alongside (and reusing the same deep-link host as) the AND-272 in-app event-detail route; the public builder must be reachable from the **unauthenticated** nav graph so logged-out cold starts resolve.

### ViewModel

```kotlin
@HiltViewModel
class PublicEventViewModel @Inject constructor(
    private val eventRepository: EventRepository,   // from AND-272 / core-data
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val args = savedStateHandle.toRoute<PublicEventRoute>()
    val calendarId: String = args.calendarId
    val eventId: String = args.eventId

    private val _uiState = MutableStateFlow<PublicEventUiState>(PublicEventUiState.Loading)
    val uiState: StateFlow<PublicEventUiState> = _uiState.asStateFlow()

    init { load() }

    fun load() {
        if (calendarId.isBlank() || eventId.isBlank()) {
            _uiState.value = PublicEventUiState.NotFound; return
        }
        viewModelScope.launch {
            _uiState.value = PublicEventUiState.Loading
            _uiState.value = when (val r = eventRepository.getPublicEvent(calendarId, eventId)) {
                is ApiResult.Success -> PublicEventUiState.Loaded(r.data, stale = false)
                is ApiResult.Stale   -> PublicEventUiState.Loaded(r.data, stale = true)
                is ApiResult.Error   -> r.toUiState()
            }
        }
    }

    fun retry() = load()
}
```

`EventRepository.getPublicEvent(calendarId, eventId): ApiResult<CalendarEvent>` and the `CalendarEvent` domain model are owned by **AND-272**; this ticket only consumes them. If AND-272 has not yet exposed an `ApiResult.Stale` variant, map a cache hit during network failure to `Success(stale=true)` via a repository flag. `r.toUiState()` is the shared error→state mapper (§7) that classifies by HTTP status before extracting a human message.

### UI state

```kotlin
sealed interface PublicEventUiState {
    data object Loading : PublicEventUiState
    data class Loaded(val event: CalendarEvent, val stale: Boolean) : PublicEventUiState
    data object NotFound : PublicEventUiState
    data class Private(val stub: PublicEventStub?) : PublicEventUiState
    data class Error(val message: String, val retryable: Boolean) : PublicEventUiState
}

data class PublicEventStub(val title: String?, val hostName: String?, val coverUrl: String?)
```

### Composable

```kotlin
@Composable
fun PublicEventScreen(
    onBack: () -> Unit,
    viewModel: PublicEventViewModel = hiltViewModel(),
)
```

A single `Scaffold` + `TopAppBar` (title = event `name` once known, up icon → `onBack`) hosts a `when (state)` dispatch into `LoadingSkeleton`, `LoadedEventContent`, `NotFoundState`, `ErrorState` (and `PrivateState` **only if** a 403-driven private state is actually built — see FR-7; otherwise omit). `LoadedEventContent` **reuses AND-272's** event-detail body composables (e.g. `EventHeader`, `EventTimeRow`, `EventDescription`) in a read-only configuration — note there is **no** location/host/recurrence row to render (those fields are not in the verified DTO) — hiding any owner/edit affordances, and renders the stale banner when `stale == true`. (Composable names are design intent against AND-272; verify the exact symbols when AND-272 lands.) Cover/host images load via Coil `AsyncImage`. Times render via `DateTimeFormatter` honouring the event's `timezone` and the device locale (consistent with AND-271 timezone handling). State collected with `collectAsStateWithLifecycle()`.

## 5. API Contract

Single endpoint, owned by AND-272/AND-270, consumed here.

**Request** (CORRECTED path + auth)
```
GET /calendar/public/event/{calendarId}/{eventId}
Headers: X-CSRF-Token: <ui_csrf cookie>   (attached opportunistically if a session exists; public reads also work fully unauthenticated)
         Authorization: Bearer <accessToken>   (also attached opportunistically when a session exists; not required)
```
`{calendarId}` and `{eventId}` are URL-encoded path segments. (Verified: `calendar.ts:getPublicEvent` calls `api.get('/calendar/public/event/${calendarId}/${eventId}')`; `client.ts` attaches `X-CSRF-Token` from the `ui_csrf` cookie and `Authorization` from the auth store whenever present, with `credentials: "include"`. The endpoint is **not** under `/ui/`, so no `X-SESSION-ID`/`user_sub` UI params apply.)

**200 — public event** (CORRECTED shape — verified `CalendarEventAttachment`, `types.ts:921`)
```json
{
  "event_id": "evt_900",
  "calendar_id": "cal_42",
  "name": "Live Q&A: Ada on Analytical Engines",
  "start_utc": "2026-07-01T18:00:00Z",
  "end_utc": "2026-07-01T19:00:00Z",
  "all_day": false,
  "all_day_date": null,
  "timezone": "America/New_York",
  "description": "Open session. Bring questions.",
  "owner": "user_abc123"
}
```
> NOTE: The OpenAPI 200 response schema for this op is an **empty/untyped `{}`** (no documented JSON schema). The field list above is taken from the **frontend** TypeScript `CalendarEventAttachment` type, which is the de-facto contract the web client relies on. Field names `name`, `start_utc`, `end_utc`, `all_day_date`, `owner` are authoritative from that source. The previously-claimed `title`, `start_at`/`end_at`, `location`, `host`, `recurrence`, `visibility`, `is_public`, and `rsvp` fields **do not exist** in the verified DTO and were removed.

**iCal download** (verified affordance):
```
GET /calendar/public/event/{calendarId}/{eventId}/ical    → .ics file (public, no auth)
```

**Errors** — The web `PublicEventPage` collapses *every* error (404, other non-2xx, parse, or network) into one "Event not found" state and disables retry (`retry: false`). FastAPI bodies on error are `{"detail": ...}` where `detail` is `string` | `[{ "msg": ... }]` (422 `HTTPValidationError`, the only documented error code) | `{ "code", ... }`, normalized by `client.ts:normalizeErrorDetail` / core-network's mapper. **No documented "private" (403 + stub) response exists** in the contract; if the backend ever returns 403 it is classified by status before message extraction. The GET is idempotent → an *app-layer* bounded-backoff retry on transient failures (timeout/5xx/network) is permissible (this ticket's addition, beyond the web's no-retry behaviour); 404 is **never** retried.

## 6. Data & State Management

- **Source of truth**: `EventRepository` (core-data, AND-272). It performs the network GET, maps DTO→`CalendarEvent`, and reads/writes a Room cache keyed by `(calendarId, eventId)`. This ticket adds **no** new persistence.
- **Cache key**: composite `(calendarId, eventId)`. TTL/eviction are AND-272/AND-118's concern; this ticket relies on `ApiResult.Stale`/cache-hit semantics for FR-8.
- **UI state holder**: `PublicEventViewModel` exposes a single immutable `StateFlow<PublicEventUiState>`; collected with `collectAsStateWithLifecycle()`.
- **Process death**: `calendarId`/`eventId` recovered from `SavedStateHandle.toRoute()`; the screen re-fetches in `init`. No transient UI fields need saving beyond the route args.
- **Recomposition**: image URL stability prevents Coil reload on unrelated recompositions; the `Loaded` data class is value-equal, so identical payloads cause no recomposition.

## 7. Error Handling & Resilience

| Condition | Classification | UI |
|---|---|---|
| 404 / any non-2xx error | terminal (web folds *all* errors here) | `NotFound`/error empty state, no retry (web is `retry:false`) |
| 403 (if ever returned) | terminal | treat as `NotFound`/error; a `Private(stub)` state is **unverified** — no `is_public`/`visibility` field exists in the DTO |
| Timeout (~20s), 5xx, conn reset | transient | `Error(retryable=true)` + Retry; or `Loaded(stale=true)` on cache hit |
| Offline, no cache | transient | `Error(retryable=true)` |
| Offline, cache present | degraded | `Loaded(stale=true)` + "Showing saved copy" banner |
| Malformed body / parse error | terminal | `Error("Couldn't load event", retryable=true)` (allow one retry) |

- Honour the **~20s** OkHttp timeout and the network-layer **bounded backoff** for the idempotent GET; this screen implements no retry loop beyond the user-driven Retry button.
- On 401 the network layer performs the single `POST /ui/session/refresh` + retry transparently; this public screen never handles 401 directly and must not surface a login wall (FR-3).
- Retry is debounced (taps ignored while `Loading`).

## 8. Security & Privacy

- **App Link host split**: App Links require HTTPS + Digital Asset Links verification. The dev backend (`18.222.237.167:8000`) is plaintext HTTP and **cannot** be an autoVerified App Link host. `APP_LINK_HOST` is defined per build type: production verified host for `release` (`autoVerify="true"`); `debug`/`internal` builds rely on the `testlogon://event/...` custom scheme only and set `android:autoVerify="false"`. Cleartext is restricted to the dev API host via the existing network-security-config; the App Link host is always HTTPS. This is the **same** host/asset-links arrangement AND-272 and AND-073 use — reuse it, do not introduce a second host.
- Intent-filter (release):
```xml
<intent-filter android:autoVerify="true">
  <action android:name="android.intent.action.VIEW"/>
  <category android:name="android.intent.category.DEFAULT"/>
  <category android:name="android.intent.category.BROWSABLE"/>
  <data android:scheme="https" android:host="@string/app_link_host" android:pathPrefix="/event/"/>
</intent-filter>
```
A matching `/.well-known/assetlinks.json` on the production host is a release-ops prerequisite (tracked in the release/CI ticket, not here).
- **Privacy**: (CORRECTED — no `is_public`/`visibility` field exists; the backend decides what the public endpoint returns) The client renders only what the endpoint returns. If the backend stops returning an event (error/404), show the not-found state; the repository must not serve a richer stale cached payload for an event that is now erroring out. Treat `owner` as a user-sub identifier — do not surface it as a display name without a verified profile lookup.
- **No PII/secret logging**: never log full event payloads or the `owner` user-sub; log only `calendarId`, `eventId`, and HTTP status. (`join_url` does not exist in the DTO.)
- Public GET works unauthenticated; the cookie/CSRF header is attached opportunistically when a session exists but is not required (FR-3).

## 9. Accessibility & i18n

- All strings in `feature-calendar/src/main/res/values/strings.xml`; no hardcoded text. New keys (CORRECTED to match verified affordances): `event_not_found_title`, `event_not_found_body`, `event_error_retry`, `event_stale_banner`, `event_all_day`, `event_download_ics`, `event_add_to_calendar`, `event_sign_in_to_add`. (~~`event_private_title`/`event_private_body`/`event_going_count`/`event_join_cta`~~ removed — no private/RSVP/join in the verified contract; keep `event_private_*` only if a 403-driven Private state is actually built.)
- Decorative icons/dividers `contentDescription = null`. (CORRECTED: the verified DTO has no host avatar or cover image, so no avatar `contentDescription` is needed; if AND-272 composables render an icon, keep it decorative.)
- ~~RSVP/going counts~~ removed — no RSVP field in the verified DTO. Use locale-aware `NumberFormat.getInstance()` only if any count is ever shown.
- Touch targets (Back, Download .ics, Retry-if-present, "Add to my calendar"/"Sign in") ≥ 48dp; TalkBack reading order: title (`name`) → stale banner (if any) → time → description → actions. Error/empty states announced via `liveRegion = Polite`.
- **Timezone**: `start_utc`/`end_utc` (CORRECTED field names) rendered with `DateTimeFormatter` using the event's `timezone` field plus the device locale. The web reference always emits the short timezone name (`timeZoneName: "short"`); matching that is the safe default. (Showing an abbreviation only when it differs from the device zone is an optional UX nicety, not web-verified.)
- Dynamic type and dark theme via Material 3 tokens from `core-ui`; no fixed font sizes. RTL-ready layouts (start/end, not left/right).

## 10. Telemetry & Logging

- Events via the core analytics facade:
  - `event_public_viewed { source: "applink"|"in_app"|"deep_scheme", result: "loaded"|"private"|"not_found"|"error", stale: Boolean }` — `source` derived from the launching intent (App Link vs in-app navigate vs custom scheme).
  - `event_public_retry_tapped { ids_present: Boolean }`.
  - `event_public_ics_downloaded` / `event_public_add_to_calendar_tapped` (verified affordances). (~~`event_public_join_tapped`~~ removed — no join CTA in the verified contract.)
- Logging at `DEBUG` only: `tag=PublicEvent`, fields `calendarId`, `eventId`, `httpStatus`, `elapsedMs`. No payload bodies, no `join_url`, no tokens/cookies. Errors logged at `WARN` with classification (`transient`/`terminal`).

## 11. Testing Strategy

**Unit (core-testing: JUnit + Turbine + coroutines-test)** — `PublicEventViewModelTest`, fake `EventRepository` returning seeded `ApiResult`s:
- 200 public (`CalendarEventAttachment` with `name`/`start_utc`/`end_utc`) → `Loaded(stale=false)`.
- 403 (if backend ever returns it) → not-found/error state (or `Private` only if that state is built). (CORRECTED: there is no `is_public`/`visibility` DTO field to test against.)
- 404 → `NotFound`/error state.
- timeout/5xx → `Error(retryable=true)`.
- cache hit on network failure → `Loaded(stale=true)`.
- blank `calendarId` or `eventId` → `NotFound` without a network call (verify repository not invoked).
- `retry()` re-invokes repository and transitions `Error → Loading → Loaded`.

**Compose UI (createAndroidComposeRule)**:
- Each state renders its hallmark node (not-found title; Retry present only when `retryable`; stale banner visible iff `stale`; "Download .ics" present; "Add to my calendar" vs "Sign in to add" gated by session). (CORRECTED: no join-CTA/RSVP nodes — not in the contract.)
- Retry click invokes `viewModel.retry()`.
- `contentDescription` assertions for Back and any decorative icons.

**Deep-link / instrumentation**:
- `adb shell am start -W -a android.intent.action.VIEW -d "https://<host>/event/cal_42/evt_900"` opens `PublicEventScreen` with `calendarId == "cal_42"`, `eventId == "evt_900"`.
- `testlogon://event/cal_42/evt_900` resolves the same route on all builds.
- URL-encoded segments (`/event/a%2Fb/evt%20900`) decode correctly.
- Deep-link cold start while **logged out** lands on the public screen (no login wall).
- Back from deep-link cold start routes to home, not app exit.

**MockWebServer** (AND-046 harness) for the repository/error-mapper path with 200/403/404/5xx fixtures (if the contract test is not already covered by AND-272).

**Acceptance mapping**: the `https`/custom-scheme deep-link tests cover "Public event opens via link" (the sole backlog acceptance bullet); private/404 tests guard against regressions.

## 12. Dependencies & Sequencing

- **Blocked by AND-272** (Event detail + public event): must land first — provides `EventApi`, `EventRepository.getPublicEvent`, the `CalendarEvent` model + cache, the reusable event-detail body composables, and the initial `/event/:calendarId/:eventId` deep-link registration. This M8 ticket extends that into a standalone, unauthenticated, distribution-ready public entry point. If AND-272 slips, this screen can be built against a fake `EventRepository` and rewired on merge.
- **Transitive**: AND-270 (Calendar API + DTOs), AND-271 (timezone rendering conventions), AND-022 (NavHost + typed deep links), all via AND-272.
- **Blocks**: none recorded in backlog. Keep `navigateToPublicEvent(calendarId, eventId)` and the `PublicEventRoute` type stable/public for future consumers (event share sheet, message event-share cards from AND-138).
- **External prerequisite**: release/CI must publish `/.well-known/assetlinks.json` on the production HTTPS host for App Link autoVerify (shared with AND-073/AND-272; not a code dependency of this ticket).

## 13. Risks & Open Questions

- **R1 — App Link verification on plaintext dev host**: cannot autoVerify HTTP. Mitigation: per-build `APP_LINK_HOST` + custom scheme for non-release. *Open*: confirm the production HTTPS host and the assetlinks-publishing owner (shared with AND-073/AND-272).
- **R2 — Private vs not-found ambiguity**: backend may return 404 for private events to avoid existence leakage. *Open*: confirm whether private events return 403+stub or 404. Handle both regardless; if always 404, the Private state is unreachable but harmless.
- **R3 — Endpoint path shape**: ~~spec assumes `GET /ui/calendar/{calendarId}/event/{eventId}`~~ **RESOLVED**: verified endpoint is `GET /calendar/public/event/{calendarId}/{event_id}` (OpenAPI op `get_public_event_...`; `calendar.ts:getPublicEvent`). It is unauthenticated and **not** under `/ui/`. Ensure AND-272's `EventApi` binds this exact path.
- **R4 — Stale private data**: ensure the repository never serves a richer cached payload for a now-private event (privacy regression). Covered by §8 but depends on AND-272/AND-118 cache semantics.
- **R5 — Public RSVP/join scope**: **RESOLVED (out of scope)** — there is no `rsvp`/`going_count`/join field in the verified `CalendarEventAttachment` DTO and no RSVP affordance in the web `PublicEventPage`. RSVP is not part of this contract; do not build it. The verified secondary affordances are "Download .ics" and (session-gated) "Add to my calendar".
- **R6 — Overlap with AND-272**: avoid duplicating the deep-link host/intent-filter. Consolidate into one `pathPrefix="/event/"` filter; this ticket owns the unauthenticated reachability and states, AND-272 owns the in-app/authenticated detail.

## 14. Acceptance Criteria

- **AC-1** Tapping a verified `https://<host>/event/<calendarId>/<eventId>` link (release build) opens the app on `PublicEventScreen` with the correct `calendarId` and `eventId`; `testlogon://event/<calendarId>/<eventId>` does the same on all builds. *(Source: "Public event opens via link.")*
- **AC-2** A deep-link cold start while **logged out** lands on the public event screen and renders without a login wall (FR-3).
- **AC-3** A valid public event renders `name` (title), timezone-aware `start_utc`/`end_utc` (+ `all_day`/`all_day_date`), and `description`, from `GET /calendar/public/event/{calendarId}/{eventId}`. (CORRECTED fields/path; no host/location/recurrence — not in DTO.) The "Download .ics" affordance opens the public iCal URL.
- **AC-4** (CORRECTED) A missing/removed/private event renders the not-found/error empty state ("Event not found / may have been removed or is no longer public") — the web reference has no distinct Private UI and folds all errors into this state. If a dedicated Private state is built, it must be triggered strictly by an observed 403 status, never by non-existent `is_public`/`visibility` fields.
- **AC-5** A missing event (404) renders the not-found/error state (web default has no Retry; an app-layer Retry, if added, is shown only for transient network/5xx failures — not for 404).
- **AC-6** Transient failures render an Error state with a working Retry; a cache hit during failure renders the stale-copy banner.
- **AC-7** Back from a deep-link cold start navigates to home, not app exit.
- **AC-8** All listed unit, Compose, and deep-link instrumentation tests pass in CI.

## 15. Definition of Done

- `feature-calendar` extended with `PublicEventScreen`, `PublicEventViewModel`, `PublicEventUiState`, `PublicEventStub`, and route/deep-link registration under `com.testlogon.android.feature.calendar.event.public`.
- Public route registered in the AND-022 `NavHost` and reachable from the **unauthenticated** nav graph; `navigateToPublicEvent(calendarId, eventId)` exposed as stable public API.
- App Link intent-filter consolidated with AND-272 (`autoVerify` on the release host, custom scheme on all builds); `APP_LINK_HOST` `BuildConfig` field set per build type; no duplicate `/event/` host filter.
- All five UI states implemented, accessible (TalkBack-verified), timezone-correct, and fully externalized strings.
- Loaded content reuses AND-272 event-detail body composables in read-only mode (no duplicate rendering logic).
- Unit + Compose + deep-link (logged-out + back-to-home) tests written and green; all §11 branches covered.
- Telemetry emitted with no PII/payload/`join_url`/token logging.
- Code review approved; merged to `android-port`; CI (build + lint + tests) green.
- Open questions R1–R3 (and R6 consolidation) resolved or explicitly deferred with owners before release tagging.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer.

1. **Public event endpoint path** is `GET /calendar/public/event/{calendar_id}/{event_id}`. — **Corrected** (spec originally said `/ui/calendar/{calendarId}/event/{eventId}`, which does not exist). Source: OpenAPI `GET /calendar/public/event/{calendar_id}/{event_id}` (op `get_public_event_calendar_public_event__calendar_id___event_id__get`); `src/api/endpoints/calendar.ts: getPublicEvent`.
2. **HTTP method is GET, path params `calendar_id` + `event_id` (both string, required).** — **Verified**. Source: OpenAPI `GET /calendar/public/event/{calendar_id}/{event_id}` parameters block; `src/api/endpoints/calendar.ts: getPublicEvent`.
3. **Endpoint is unauthenticated / public** (works with no session). — **Verified**. Source: `src/api/endpoints/calendar.ts` comment "Public Event (no auth)"; `src/pages/calendar/PublicEventPage.tsx` (no auth guard, `retry:false`); path is outside the `/ui/` (session) prefix and OpenAPI lists no security/`X-SESSION-ID` params for this op.
4. **CSRF header `X-CSRF-Token` is sourced from the `ui_csrf` cookie and attached opportunistically when present.** — **Verified**. Source: `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`), applied to all requests including GET.
5. **An `Authorization: Bearer <accessToken>` header is also attached opportunistically when a session exists (not only a cookie jar).** — **Corrected/clarified** (spec implied cookie-only). Source: `src/api/client.ts` (`accessToken` from `useAuthStore` → `Authorization` header) with `credentials:"include"`.
6. **200 response DTO is `CalendarEventAttachment` with fields `event_id`, `calendar_id`, `name`, `start_utc?`, `end_utc?`, `all_day`, `all_day_date?`, `timezone`, `description?`, `owner`.** — **Verified (frontend-authoritative)**. Source: `src/api/types.ts: CalendarEventAttachment` (lines ~921–932); used as `api.get<CalendarEventAttachment>` in `calendar.ts: getPublicEvent`. NOTE: OpenAPI documents the 200 schema as empty `{}` (untyped), so the frontend type is the de-facto contract.
7. **Fields `title`, `start_at`/`end_at`, `location`/`join_url`, `host`/organizer profile, `recurrence`, `visibility`, `is_public`, `rsvp`/`going_count` exist on the response.** — **Corrected: these do NOT exist.** Source: absence from `src/api/types.ts: CalendarEventAttachment` and from `src/pages/calendar/PublicEventPage.tsx` rendering (which reads only `name`, `start_utc`, `end_utc`, `all_day`, `all_day_date`, `timezone`, `description`).
8. **Correct field names are `name` (title), `start_utc`/`end_utc` (times), `all_day_date`.** — **Verified/Corrected**. Source: `src/api/types.ts: CalendarEventAttachment`; `src/pages/calendar/PublicEventPage.tsx: formatEventTime` + render block.
9. **No distinct "Private" UI state exists in the web reference; all errors collapse into one "Event not found" state, with retry disabled.** — **Corrected** (spec asserted a 403/`is_public==false` Private state). Source: `src/pages/calendar/PublicEventPage.tsx` (`if (isError || !evt) { … "Event not found" … }`, `useQuery({ retry: false })`).
10. **Public iCal download is `GET /calendar/public/event/{calendarId}/{eventId}/ical`.** — **Verified**. Source: OpenAPI `GET /calendar/public/event/{calendar_id}/{event_id}/ical` (op `download_public_ical_...`); `src/api/endpoints/calendar.ts: getPublicIcalUrl`.
11. **Secondary affordances are "Download .ics" (always) and "Add to my calendar" (logged-in) / "Sign in to add to calendar" (logged-out).** — **Verified/Corrected** (spec implied RSVP/join CTA). Source: `src/pages/calendar/PublicEventPage.tsx` (`handleDownloadIcal`, `handleAddToCalendar` gated by `isLoggedIn`).
12. **"Add to my calendar" calls `POST /ui/calendars/{calendarId}/events` (create event).** — **Verified**. Source: `src/pages/calendar/PublicEventPage.tsx: handleAddToCalendar` → `createEvent`; OpenAPI `POST /ui/calendars/{calendar_id}/events` (op `create_event_...`, req `EventCreateIn`, resp `EventOut`).
13. **On 401 the network layer performs `POST /ui/session/refresh` + single retry.** — **Verified**. Source: `src/api/client.ts: refreshSession` (`POST /ui/session/refresh`) and the 401 branch (refresh-once-then-retry). NOTE: a public read should rarely hit 401; this is shared transport behaviour.
14. **Error bodies follow FastAPI `{"detail": …}` with `string` | `[{msg}]` | `{code}` shapes; 422 is `HTTPValidationError`.** — **Verified**. Source: `src/api/client.ts: normalizeErrorDetail`; OpenAPI 422 `$ref: HTTPValidationError` on the public-event op.
15. **Web route is `/event/:calendarId/:eventId` (App Link surface).** — **Verified**. Source: `src/App.tsx` (`<Route path="/event/:calendarId/:eventId" element={<PublicEventPage />} />`). Distinct from the API path (item 1).
16. **Message bubbles deep-link to `/event/{calendar_id}/{event_id}` and to the public iCal URL.** — **Verified**. Source: `src/pages/messages/MessageBubble.tsx` (`href={/event/${ev.calendar_id}/${ev.event_id}}` and the `/calendar/public/event/.../ical` href).
17. **App Links require HTTPS + Digital Asset Links verification; cleartext dev host cannot autoVerify, so a per-build `APP_LINK_HOST` + `testlogon://` custom-scheme fallback is used.** — **Verified (framework ref)**. Source: Android docs https://developer.android.com/training/app-links/verify-android-applinks and https://developer.android.com/training/app-links#android-app-links (autoVerify + assetlinks.json). Host-split arrangement itself is an internal convention (see Open assumptions).
18. **Type-safe Navigation-Compose deep links via `navDeepLink<T>` / `composable<T>` and `SavedStateHandle.toRoute<T>()`.** — **Verified (framework ref)**. Source: Android docs https://developer.android.com/guide/navigation/design/type-safety and https://developer.android.com/guide/navigation/design/deep-link.
19. **`collectAsStateWithLifecycle()` for lifecycle-aware state collection.** — **Verified (framework ref)**. Source: Android docs https://developer.android.com/topic/libraries/architecture/compose#collectasstatewithlifecycle.
20. **Identifiers are opaque, URL-decoded once on extraction, passed verbatim.** — **Unverified-assumption** (sensible, but the web client interpolates raw `useParams` values without explicit decode/validation; Android Navigation decodes path args once by default). Source: inferred from `src/pages/calendar/PublicEventPage.tsx` (`useParams` passthrough) + Android Navigation arg decoding behaviour.

### Corrections made

- **C1 (items 1, 4 in §2/§5/FR-4/§13-R3/AC-3):** Endpoint path corrected from `/ui/calendar/{calendarId}/event/{eventId}` → `/calendar/public/event/{calendarId}/{eventId}`; noted it is outside the `/ui/` prefix and carries no `X-SESSION-ID`/`user_sub`.
- **C2 (items 6–8 in §5/FR-5/§9/AC-3):** Response DTO/fields corrected to the verified `CalendarEventAttachment` (`name`, `start_utc`, `end_utc`, `all_day_date`, `owner`); removed non-existent `title`/`start_at`/`end_at`/`location`/`host`/`recurrence`/`visibility`/`is_public`/`rsvp`.
- **C3 (item 9 in FR-6/FR-7/§7/§11/AC-4/AC-5):** Removed the asserted "Private" state as contract fact; folded all errors into the web's single not-found/error state; flagged any 403-driven Private UI as speculative.
- **C4 (item 11 in FR-5/§9/§10):** Replaced RSVP/join CTA with the verified "Download .ics" and session-gated "Add to my calendar"/"Sign in to add" affordances; updated string keys and telemetry events.
- **C5 (item 5 in §5):** Clarified that auth is a Bearer token from the auth store in addition to cookies/CSRF, attached opportunistically.
- **C6 (§13-R5):** Marked RSVP scope resolved/out-of-scope (no such field/affordance).

### Open assumptions

- **OA1 — Stale/offline cache + `ApiResult.Stale`:** FR-8/§6 assume a Room cache keyed by `(calendarId, eventId)` and an `ApiResult.Stale` variant from AND-272. Unverifiable here — AND-272 source is not in this repo and the web reference uses no offline cache (`retry:false`, React-Query only). Carry as an AND-272-dependent assumption.
- **OA2 — App-layer bounded-backoff retry:** The web reference disables retry entirely (`retry:false`). Any Android Retry/backoff is a deliberate app-layer enhancement, not web-verified. Acceptable but flagged.
- **OA3 — 403 / private behaviour:** Whether the backend ever returns 403 (vs always 404 or always-public) for a non-public event is unconfirmed; OpenAPI documents only 200 + 422 for this op. Until confirmed, treat 403 as the not-found/error state.
- **OA4 — Production App Link host + `assetlinks.json` owner:** The verified-HTTPS production host value and the team that publishes `/.well-known/assetlinks.json` are an internal release-ops detail not present in these sources (shared with AND-073/AND-272). Carry as R1.
- **OA5 — AND-272 composable symbol names** (`EventHeader`, `EventTimeRow`, `EventDescription`, `EventRepository.getPublicEvent`): design intent; the exact Kotlin symbols cannot be verified from the backend/frontend sources and must be confirmed against AND-272 on merge.
- **OA6 — `owner` semantics:** The DTO `owner` is a string (user-sub). Whether it should be resolved to a display name for the UI is unverified; the web app does not render it. Treated as non-displayed PII.

## 17. Test Plan

Test-target legend: **JVM** = local JUnit/Robolectric (no device); **EMU** = headless emulator AVD `test35` (x86_64, API 35); **DEV** = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, Android 14 / API 34, arm64-v8a). Cases that exercise real App Link autoVerify, real-network flakiness, or ABI/API-level differences PREFER **DEV**; deterministic UI/instrumented suites run on **EMU**.

- **TC-AND-391-01** — Happy-path load → Loaded state.
  - Type: unit (JVM). Target: `PublicEventViewModelTest` with a fake `EventRepository`.
  - Preconditions: repository returns `ApiResult.Success(CalendarEvent(name="…", start_utc, end_utc, timezone, description))`.
  - Steps: construct VM with valid `calendarId`/`eventId`; collect `uiState` via Turbine.
  - Expected: emits `Loading` then `Loaded(stale=false)` carrying the mapped `name`/times/`description`; repository called exactly once with the verbatim ids.
  - Traces: AC-3.

- **TC-AND-391-02** — Contract: 200 body deserializes to `CalendarEventAttachment`.
  - Type: contract/MockWebServer (JVM/Robolectric, AND-046 harness). Target: `EventApi`/repository mapping for `GET /calendar/public/event/{calendarId}/{eventId}`.
  - Preconditions: MockWebServer enqueues 200 with the verified JSON (`event_id`,`calendar_id`,`name`,`start_utc`,`end_utc`,`all_day`,`all_day_date`,`timezone`,`description`,`owner`).
  - Steps: call `getPublicEvent("cal_42","evt_900")`; assert the recorded request path is exactly `/calendar/public/event/cal_42/evt_900` and method GET.
  - Expected: success with all fields mapped; **no** request requires auth headers (request succeeds without `Authorization`/`X-SESSION-ID`); unknown/absent optional fields tolerated.
  - Traces: AC-2, AC-3.

- **TC-AND-391-03** — Contract: opportunistic CSRF/Bearer attached when a session exists, omitted when not.
  - Type: contract/MockWebServer (JVM). Target: OkHttp interceptor + `EventApi`.
  - Preconditions: (a) no session, (b) session with `ui_csrf` cookie + access token.
  - Steps: issue the public GET in each state; inspect recorded headers.
  - Expected: (a) no `X-CSRF-Token`/`Authorization` sent, request still 200; (b) `X-CSRF-Token` and `Authorization: Bearer …` present; neither is required for success.
  - Traces: AC-2, AC-3. (Source basis: `src/api/client.ts`.)

- **TC-AND-391-04** — 404 → not-found/error state, no Retry.
  - Type: unit (JVM) + contract/MockWebServer. Target: `PublicEventViewModelTest` + error mapper.
  - Preconditions: repository/server returns 404 `{"detail":"Event not found"}`.
  - Steps: load; collect state.
  - Expected: terminal not-found state; `retryable=false` (no Retry affordance); repository not auto-retried.
  - Traces: AC-4, AC-5.

- **TC-AND-391-05** — Transient failure (timeout/5xx/network) → error with Retry; `retry()` recovers.
  - Type: unit (JVM). Target: `PublicEventViewModelTest`.
  - Preconditions: first call returns `ApiResult.Error(transient)`, second returns `Success`.
  - Steps: load → assert `Error(retryable=true)`; call `retry()`; assert `Loading → Loaded`.
  - Expected: error state offers Retry; retry re-invokes repository and transitions to Loaded.
  - Traces: AC-6.

- **TC-AND-391-06** — Offline with cache hit → stale banner; offline without cache → retryable error.
  - Type: unit (JVM). Target: `PublicEventViewModelTest` (depends on AND-272 cache/`ApiResult.Stale`; see OA1).
  - Preconditions: (a) network fails + cache present → `ApiResult.Stale(event)`; (b) network fails + no cache → `Error(transient)`.
  - Steps: load in each scenario.
  - Expected: (a) `Loaded(stale=true)` with "Showing saved copy" banner; (b) `Error(retryable=true)`.
  - Traces: AC-6.

- **TC-AND-391-07** — Blank/whitespace identifiers short-circuit without a network call.
  - Type: unit (JVM). Target: `PublicEventViewModelTest`.
  - Preconditions: `calendarId=""` or `eventId="  "`.
  - Steps: construct VM; collect state.
  - Expected: not-found/error state immediately; fake repository never invoked.
  - Traces: AC-4. (Security: avoids issuing malformed/empty-id requests.)

- **TC-AND-391-08** — Loaded-state UI renders verified fields and affordances; absent fields omitted.
  - Type: Compose-UI (EMU, `createAndroidComposeRule`). Target: `PublicEventScreen`.
  - Preconditions: VM seeded with `Loaded` (name, times, description present; no host/location/recurrence — those nodes must not exist).
  - Steps: assert title=`name`, time row, description; assert "Download .ics" present; assert no location/host/recurrence/RSVP nodes.
  - Expected: only verified content rendered; `all_day_date` path renders when `all_day=true`.
  - Traces: AC-3.

- **TC-AND-391-09** — Session-gated "Add to my calendar" vs "Sign in to add".
  - Type: Compose-UI (EMU). Target: `PublicEventScreen` Loaded state.
  - Preconditions: toggle a fake auth state (logged-in / logged-out).
  - Steps: render Loaded in each; check action button.
  - Expected: logged-in shows "Add to my calendar"; logged-out shows "Sign in to add to calendar". Neither blocks viewing the event.
  - Traces: AC-2, AC-3. (Source: `PublicEventPage.tsx` isLoggedIn branch.)

- **TC-AND-391-10** — Error/not-found state UI + accessibility.
  - Type: Compose-UI (EMU). Target: `NotFoundState`/`ErrorState`.
  - Preconditions: VM in not-found state and in `Error(retryable=true)`.
  - Steps: assert not-found has no Retry; error has Retry and clicking it invokes `viewModel.retry()`; assert Back has a `contentDescription`; assert empty/error containers expose `liveRegion = Polite`; verify touch targets ≥ 48dp.
  - Expected: correct affordances + a11y semantics per §9.
  - Traces: AC-5, AC-6, AC-8.

- **TC-AND-391-11** — App Link cold start (verified HTTPS) opens the screen with correct args while logged out.
  - Type: instrumented/e2e — **MUST run on DEV** (real App Link autoVerify + Digital Asset Links is hardware/OS-verification dependent; emulator cannot validate the production assetlinks reliably). Target: deep-link entry → `PublicEventScreen`.
  - Preconditions: release-config build installed on DEV; logged-out app state; production host assetlinks published.
  - Steps: `adb -s R5CX821TA9R shell am start -W -a android.intent.action.VIEW -d "https://<verified-host>/event/cal_42/evt_900"`.
  - Expected: app (not browser) opens `PublicEventScreen`; `calendarId=="cal_42"`, `eventId=="evt_900"`; no login wall; event loads.
  - Traces: AC-1, AC-2.

- **TC-AND-391-12** — Custom-scheme deep link + URL-encoded segment decoding on all builds.
  - Type: instrumented (EMU acceptable; deterministic intent resolution). Target: deep-link routing.
  - Preconditions: any build installed.
  - Steps: `am start -a android.intent.action.VIEW -d "testlogon://event/cal_42/evt_900"`; then `…-d "testlogon://event/a%2Fb/evt%20900"`.
  - Expected: both resolve `PublicEventScreen`; encoded segments decode once to `a/b` and `evt 900` and pass verbatim to the API.
  - Traces: AC-1.

- **TC-AND-391-13** — Back from deep-link cold start routes to home, not app exit.
  - Type: instrumented/e2e (EMU). Target: nav back-stack behaviour.
  - Preconditions: app launched solely via the deep link (empty back stack).
  - Steps: on `PublicEventScreen`, press system Back and the top-bar up affordance.
  - Expected: navigates to the home/start destination; app does not exit to launcher.
  - Traces: AC-7.

- **TC-AND-391-14** — Real-network flaky dev host: load over the cleartext dev backend.
  - Type: integration/manual — **PREFER DEV** (real arm64 build + real-network ~20s timeouts/backoff against the plaintext dev host `18.222.237.167:8000`; exercises API34/arm64 path vs EMU API35/x86_64).
  - Preconditions: debug/internal build (cleartext allowed via network-security-config) on DEV, real Wi-Fi/cellular.
  - Steps: open `testlogon://event/<real cal>/<real evt>` against the dev host; induce a timeout (toggle airplane mode mid-request); recover and Retry.
  - Expected: timeout surfaces a retryable error (or stale banner if cached); Retry succeeds once connectivity returns; no crash; no payload/`owner` logged (verify logcat shows only `calendarId`/`eventId`/status).
  - Traces: AC-6, AC-8. (Security: confirms no PII/payload logging on the real device.)

### Coverage matrix

| AC | Covered by |
|---|---|
| AC-1 (opens via verified https + custom scheme link) | TC-11, TC-12 |
| AC-2 (logged-out cold start, no login wall) | TC-02, TC-03, TC-09, TC-11 |
| AC-3 (renders verified fields + .ics) | TC-01, TC-02, TC-03, TC-08, TC-09 |
| AC-4 (missing/private → not-found/error; no false Private from absent fields) | TC-04, TC-07 |
| AC-5 (404 → not-found, no Retry) | TC-04, TC-10 |
| AC-6 (transient error → Retry; cache hit → stale banner) | TC-05, TC-06, TC-10, TC-14 |
| AC-7 (Back from cold start → home) | TC-13 |
| AC-8 (unit + Compose + deep-link suites green in CI) | TC-01…TC-13 (+ TC-14 device sign-off) |
