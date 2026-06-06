---
id: AND-391
title: "Public event (`/event/:calendarId/:eventId`)"
milestone: M8
epic: E51
priority: P2
size: M
status: draft
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
- **Web reference**: `frontend/src/api/endpoints/calendar.ts` (endpoint shapes), `frontend/src/api/types.ts` (shared `CalendarEvent` / `PublicEvent` / error types), and the route `/event/:calendarId/:eventId` in the web router. OpenAPI: `GET http://18.222.237.167:8000/openapi.json` (path `/ui/calendar/{calendarId}/event/{eventId}`).
- **Stack**: Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow, Coil (cover image/avatar), Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6 cache. minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3.
- **Backend reality**: dev host `18.222.237.167:8000` is **plaintext HTTP** and unreliable (~20s timeouts, bounded backoff for idempotent GETs only). App Links require HTTPS + Digital Asset Links verification → see §8 for the dev-vs-prod host split.

## 3. Functional Requirements

FR-1 **Route**: The public view is registered as a typed route `EventRoute.Public(calendarId: String, eventId: String)` rendering at in-app path `event/public/{calendarId}/{eventId}`.

FR-2 **App Link**: Tapping `https://<verified-host>/event/<calendarId>/<eventId>` opens the app directly to this screen with both path segments extracted. The link is an **autoVerified** App Link in `release`. A custom-scheme fallback `testlogon://event/<calendarId>/<eventId>` is accepted on all builds for share flows and for `debug`/`internal`.

FR-3 **Unauthenticated entry**: The screen loads and renders **without** requiring a session. If a cookie jar/session exists it is attached opportunistically (CSRF header echoed), but absence of a session must never block the public read or force a login wall.

FR-4 **Load**: On entry the screen fetches the public event via `GET /ui/calendar/{calendarId}/event/{eventId}` and shows a skeleton/loading state until the result resolves.

FR-5 **Loaded state**: Render title, start/end (timezone-aware), all-day flag, location (physical or virtual/join URL when public), host/organizer display name + avatar, description, and a recurrence summary line when `recurrence` is present. Null/absent optional fields are omitted, never rendered as empty rows. If the backend exposes a public RSVP/attendance count or a join CTA, render it; otherwise render none.

FR-6 **Not-found state**: HTTP 404 (or backend `detail` indicating no such event/calendar) renders a dedicated empty state ("This event doesn't exist or was removed") with a Back action and **no** Retry button (retrying a 404 is pointless).

FR-7 **Private/restricted state**: HTTP 403 (or a payload marked `is_public == false` / `visibility != "public"`) renders a "This event is private" state showing only the minimal stub the backend returns (title and/or host if provided) plus an explanatory message. No description, location, join URL, or attendee data is shown.

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

A single `Scaffold` + `TopAppBar` (title = event title once known, up icon → `onBack`) hosts a `when (state)` dispatch into `LoadingSkeleton`, `LoadedEventContent`, `NotFoundState`, `PrivateState`, and `ErrorState`. `LoadedEventContent` **reuses AND-272's** event-detail body composables (e.g. `EventHeader`, `EventTimeRow`, `EventLocationRow`, `EventDescription`) in a read-only configuration, hiding any owner/edit affordances, and renders the stale banner when `stale == true`. Cover/host images load via Coil `AsyncImage`. Times render via `DateTimeFormatter` honouring the event's `timezone` and the device locale (consistent with AND-271 timezone handling). State collected with `collectAsStateWithLifecycle()`.

## 5. API Contract

Single endpoint, owned by AND-272/AND-270, consumed here.

**Request**
```
GET /ui/calendar/{calendarId}/event/{eventId}
Headers: X-CSRF-Token: <ui_csrf cookie>   (attached opportunistically if a session jar exists; public reads also work unauthenticated)
```
`{calendarId}` and `{eventId}` are URL-encoded path segments.

**200 — public event**
```json
{
  "calendar_id": "cal_42",
  "event_id": "evt_900",
  "title": "Live Q&A: Ada on Analytical Engines",
  "description": "Open session. Bring questions.",
  "start_at": "2026-07-01T18:00:00Z",
  "end_at": "2026-07-01T19:00:00Z",
  "all_day": false,
  "timezone": "America/New_York",
  "location": { "kind": "virtual", "join_url": "https://meet.testlogon.dev/evt_900" },
  "host": { "display_name": "Ada Lovelace", "handle": "ada", "avatar_url": "https://cdn.testlogon.dev/a/ada.png" },
  "recurrence": null,
  "visibility": "public",
  "is_public": true,
  "rsvp": { "going_count": 134, "can_rsvp": false }
}
```

**200/403 — private/restricted**
```json
{ "calendar_id": "cal_42", "event_id": "evt_900", "title": "Private event", "is_public": false, "visibility": "private" }
```
Treat either a 403 **or** a 200 with `"is_public": false` / `visibility != "public"` as the Private state; map only `title`/`host`/`cover` into `PublicEventStub`.

**404 — not found**
```json
{ "detail": "Event not found" }
```

**FastAPI `detail` mapping** (`string` | `[{ "msg": ... }]` | `{ "code", ... }`) is normalized by core-network's error mapper; this screen needs only the resulting human string for the generic Error state. 404 and 403 are classified by status code **before** message extraction. The GET is **idempotent** → eligible for the bounded backoff retry on transient failures (timeout/5xx); 404/403 are **never** retried.

## 6. Data & State Management

- **Source of truth**: `EventRepository` (core-data, AND-272). It performs the network GET, maps DTO→`CalendarEvent`, and reads/writes a Room cache keyed by `(calendarId, eventId)`. This ticket adds **no** new persistence.
- **Cache key**: composite `(calendarId, eventId)`. TTL/eviction are AND-272/AND-118's concern; this ticket relies on `ApiResult.Stale`/cache-hit semantics for FR-8.
- **UI state holder**: `PublicEventViewModel` exposes a single immutable `StateFlow<PublicEventUiState>`; collected with `collectAsStateWithLifecycle()`.
- **Process death**: `calendarId`/`eventId` recovered from `SavedStateHandle.toRoute()`; the screen re-fetches in `init`. No transient UI fields need saving beyond the route args.
- **Recomposition**: image URL stability prevents Coil reload on unrelated recompositions; the `Loaded` data class is value-equal, so identical payloads cause no recomposition.

## 7. Error Handling & Resilience

| Condition | Classification | UI |
|---|---|---|
| 404 / `detail` "not found" | terminal | `NotFound`, no retry |
| 403 / `is_public==false` / `visibility!="public"` | terminal | `Private(stub)`, no retry |
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
- **Privacy**: respect `is_public`/`visibility` strictly — never render description, location/join URL, or attendee data for a private event, even if a stale cache holds richer data. The Private state renders from the stub only, and the repository must not serve a richer cached payload for a now-private event.
- **No PII/secret logging**: never log full event payloads or `join_url`; log only `calendarId`, `eventId`, and HTTP status.
- Public GET works unauthenticated; the cookie/CSRF header is attached opportunistically when a session exists but is not required (FR-3).

## 9. Accessibility & i18n

- All strings in `feature-calendar/src/main/res/values/strings.xml`; no hardcoded text. New keys: `event_not_found_title`, `event_private_title`, `event_private_body`, `event_error_retry`, `event_stale_banner`, `event_going_count`, `event_join_cta`, `event_all_day`.
- Host avatar / cover `AsyncImage` has `contentDescription` (e.g. "Host: <display name>"); decorative dividers `contentDescription = null`.
- RSVP/going counts use `quantityString` plurals and locale-aware `NumberFormat.getInstance()`.
- Touch targets (Back, Retry, Join CTA) ≥ 48dp; TalkBack reading order: title → stale banner (if any) → time → location → host → description → RSVP. Error/empty states announced via `liveRegion = Polite`.
- **Timezone**: `start_at`/`end_at` rendered with `DateTimeFormatter` using the event's `timezone` field plus the device locale; show the timezone abbreviation when it differs from the device zone (consistent with AND-271).
- Dynamic type and dark theme via Material 3 tokens from `core-ui`; no fixed font sizes. RTL-ready layouts (start/end, not left/right).

## 10. Telemetry & Logging

- Events via the core analytics facade:
  - `event_public_viewed { source: "applink"|"in_app"|"deep_scheme", result: "loaded"|"private"|"not_found"|"error", stale: Boolean }` — `source` derived from the launching intent (App Link vs in-app navigate vs custom scheme).
  - `event_public_retry_tapped { ids_present: Boolean }`.
  - `event_public_join_tapped` (only when a public join CTA is rendered and tapped).
- Logging at `DEBUG` only: `tag=PublicEvent`, fields `calendarId`, `eventId`, `httpStatus`, `elapsedMs`. No payload bodies, no `join_url`, no tokens/cookies. Errors logged at `WARN` with classification (`transient`/`terminal`).

## 11. Testing Strategy

**Unit (core-testing: JUnit + Turbine + coroutines-test)** — `PublicEventViewModelTest`, fake `EventRepository` returning seeded `ApiResult`s:
- 200 public → `Loaded(stale=false)`.
- 200 `is_public=false` (or `visibility="private"`) → `Private(stub)`.
- 403 → `Private`.
- 404 → `NotFound`.
- timeout/5xx → `Error(retryable=true)`.
- cache hit on network failure → `Loaded(stale=true)`.
- blank `calendarId` or `eventId` → `NotFound` without a network call (verify repository not invoked).
- `retry()` re-invokes repository and transitions `Error → Loading → Loaded`.

**Compose UI (createAndroidComposeRule)**:
- Each state renders its hallmark node (private body text; not-found title; Retry present only when `retryable`; stale banner visible iff `stale`; join CTA visible iff `rsvp.can_rsvp`/public join present).
- Retry click invokes `viewModel.retry()`.
- `contentDescription` assertions for cover/avatar and Back.
- Private state asserts description/location/join URL nodes are **absent**.

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
- **R3 — Endpoint path shape**: spec assumes `GET /ui/calendar/{calendarId}/event/{eventId}`. *Open*: confirm against `calendar.ts` / `/openapi.json` — the public read may be a distinct unauthenticated path (e.g. `/ui/public/event/...`). Align with AND-272's actual `EventApi` binding before merge.
- **R4 — Stale private data**: ensure the repository never serves a richer cached payload for a now-private event (privacy regression). Covered by §8 but depends on AND-272/AND-118 cache semantics.
- **R5 — Public RSVP/join scope**: whether a logged-out user can RSVP or only view a `going_count` is backend-driven. Render the CTA only when `rsvp.can_rsvp == true`; the **action** flow (if any) is deferred to a follow-up E37/E51 ticket — this ticket is view-only.
- **R6 — Overlap with AND-272**: avoid duplicating the deep-link host/intent-filter. Consolidate into one `pathPrefix="/event/"` filter; this ticket owns the unauthenticated reachability and states, AND-272 owns the in-app/authenticated detail.

## 14. Acceptance Criteria

- **AC-1** Tapping a verified `https://<host>/event/<calendarId>/<eventId>` link (release build) opens the app on `PublicEventScreen` with the correct `calendarId` and `eventId`; `testlogon://event/<calendarId>/<eventId>` does the same on all builds. *(Source: "Public event opens via link.")*
- **AC-2** A deep-link cold start while **logged out** lands on the public event screen and renders without a login wall (FR-3).
- **AC-3** A valid public event renders title, timezone-aware start/end, location/host, description, and recurrence summary (when present) from `GET /ui/calendar/{calendarId}/event/{eventId}`.
- **AC-4** A private/restricted event renders the Private state (message + stub only; no description/location/join URL/attendees), whether signalled by 403 or `is_public==false`/`visibility!="public"`.
- **AC-5** A missing event (404) renders the NotFound state with no Retry button.
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
