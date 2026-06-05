---
id: AND-272
title: Event detail (+ public event)
milestone: M6
epic: E37
priority: P1
size: L
status: draft
depends_on: [AND-271, AND-022]
blocks: []
---

# AND-272 — Event detail (+ public event)

## 1. Overview & Goal

Deliver the **Event detail** screen for the TestLogon native Android app and the **public event App Link** that opens a single calendar event from an external URL: `https://<host>/event/{calendarId}/{eventId}`. The detail screen renders one event's full metadata (title, time range in the effective display zone, recurrence summary, location, description, organizer, attendees, attachments, and the source calendar) and exposes event actions (add-to-device-calendar, share public link, open in maps). The public-link path must resolve the same event when launched from outside the app — including a browser, another app, or a notification — handling the unauthenticated/limited-visibility case the FastAPI backend returns for public events.

This ticket owns: the `feature-calendar` detail route/screen, its `EventDetailViewModel`, the navigation wiring from the calendar views (AND-271's `onEventClick`) into the typed detail route (AND-022's `NavHost`), the `AndroidManifest` App Link `intent-filter` + Digital Asset Links verification, and the deep-link parsing that maps a public URL to the typed route. It explicitly does **not** own the calendar list/grid views (AND-271) or the Retrofit/DTO layer (AND-270); it consumes both. Acceptance is concrete: the event detail screen renders correctly for an authenticated in-app event, and a public `/event/{calendarId}/{eventId}` link opens that event from a cold start.

## 2. Context & References

- **Module:** `feature-calendar` (created in AND-271); this ticket adds the detail sub-package `com.testlogon.android.feature.calendar.detail`.
- **Package root:** `com.testlogon.android.feature.calendar`. Layering unchanged: `app -> feature-calendar -> core-*` (`core-model`, `core-ui`, `core-data`, `core-network`, `core-testing`).
- **Upstream AND-271 (Calendar views):** exposes `onEventClick(calendarId: String, eventId: String, occurrenceStart: Instant)`; this ticket consumes that callback and routes to detail. Reuses `SlottedEvent`/`CalendarEvent` domain models and the `CalendarZonePreferences` display-zone resolution defined there.
- **Upstream AND-022 (Navigation host & routes):** single-Activity `NavHost`, typed route definitions, transitions. This ticket registers a new typed destination and a `navDeepLink` for the public URL.
- **Upstream AND-270 (transitive):** `CalendarRepository` and Moshi DTO mapping; this ticket adds a single-event read method (see §5). FastAPI error `detail` mapping and `ApiResult<T>` come from `core-network`.
- **Web reference:** `frontend/src/api/endpoints/calendar.ts` (single-event + public-event endpoint shapes) and `frontend/src/api/types.ts` (event/attendee/recurrence types). The web route `/event/:calendarId/:eventId` is the canonical public URL shape to mirror.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. Cookie + `ui_csrf`/`X-CSRF-Token` auth handled by `core-network`; 401 triggers one `POST /ui/session/refresh` + retry.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP), Coroutines/Flow, Coil (organizer/attendee avatars + attachment thumbnails), `java.time` via core library desugaring. minSdk 24, compileSdk/targetSdk 35, AGP 8.7.3, Gradle 8.9, JDK 17, branch `android-port`.

## 3. Functional Requirements

FR-1 **Detail entry (in-app).** Tapping any event in Month/Week/Agenda (AND-271 `onEventClick`) navigates to `EventDetail` with `calendarId`, `eventId`, and `occurrenceStart` (epoch millis). The detail screen loads and renders that occurrence.

FR-2 **Rendered fields.** Title; date/time range formatted in the effective display zone with an explicit zone label; all-day and multi-day rendered as date spans (no time); recurrence summary (e.g., "Repeats weekly on Mon"); location (tappable → maps intent); description (rich text rendered as plain/linkified text); organizer (avatar + name); attendee list with RSVP status; source calendar name + color; attachments (Coil thumbnails, tap to open).

FR-3 **Actions.** (a) **Add to device calendar** via `Intent(Intent.ACTION_INSERT, CalendarContract.Events.CONTENT_URI)` prefilled with title/time/location/description. (b) **Share public link** via `ACTION_SEND` with the canonical `https://<host>/event/{calendarId}/{eventId}` URL. (c) **Open location in maps** via `geo:` / maps query intent. (d) **Open organizer profile** if a `u-identifier` is present (delegates to public profile route, AND-073). All actions are no-ops/hidden when their backing data is absent.

FR-4 **Public App Link (cold/warm start).** An `https` App Link for path `/event/{calendarId}/{eventId}` on the production/staging hosts opens the app directly (verified Digital Asset Links → no disambiguation dialog) to the same `EventDetail` destination. From a cold start the deep link rebuilds a sensible back stack: `EventDetail` with the calendar root as parent so Back returns into the app rather than exiting.

FR-5 **Public (unauthenticated/limited) event.** When the event is public, the backend may return a reduced payload (no attendee PII) and may not require a session. The screen renders whatever fields are returned and hides absent ones. If the event requires auth and the user is unauthenticated, the screen routes through the existing auth gate (AND-025) preserving the deep link as a post-login redirect, then returns to the event.

FR-6 **Not-found / forbidden.** A `404` (event/calendar missing or expired public link) shows a dedicated "Event unavailable" state with a Back action. A `403` (private event, insufficient visibility) shows a "You don't have access" state. Neither shows a raw error.

FR-7 **Timezone handling.** Reuse AND-271's display-zone resolution (precedence: DataStore user override → `ZoneId.systemDefault()`). Show a zone-mismatch hint when the display zone differs from the device zone. All-day events are date-anchored and never shift across zones.

FR-8 **Loading/stale/error states.** Skeleton while loading; if a cached copy exists (from AND-270's Room cache) render it immediately with a stale badge while refreshing; inline retry on transient error (§7) preserving any last-good content.

## 4. Technical Design

New sub-package `com.testlogon.android.feature.calendar.detail`. Public entry `EventDetailRoute` (Composable) observes a single `StateFlow<EventDetailUiState>` from `EventDetailViewModel` (Hilt). The route arguments are decoded by Navigation-Compose from either an in-app `navigate(...)` call or the public `navDeepLink`.

```kotlin
package com.testlogon.android.feature.calendar.detail

// Typed route (Navigation-Compose). occurrenceStart is epoch millis (-1 = not specified, e.g. public link).
const val EVENT_DETAIL_ROUTE = "calendar/event/{calendarId}/{eventId}?occurrenceStart={occurrenceStart}"

object EventDetailArgs {
    const val CALENDAR_ID = "calendarId"
    const val EVENT_ID = "eventId"
    const val OCCURRENCE_START = "occurrenceStart"
    fun route(calendarId: String, eventId: String, occurrenceStart: Instant?): String
}

sealed interface EventDetailUiState {
    data object Loading : EventDetailUiState
    data class Content(
        val event: EventDetailModel,
        val displayZone: ZoneId,
        val deviceZone: ZoneId,
        val zoneMismatch: Boolean,
        val isPublic: Boolean,        // limited/unauthenticated payload
        val isStale: Boolean,
        val publicShareUrl: String,   // canonical https link for ACTION_SEND
    ) : EventDetailUiState
    data class Error(val cause: EventDetailError, val cached: Content?) : EventDetailUiState
}

enum class EventDetailError { NETWORK, SERVER, NOT_FOUND, FORBIDDEN, AUTH_REQUIRED, UNKNOWN }
```

```kotlin
data class EventDetailModel(
    val calendarId: String,
    val eventId: String,
    val occurrenceStart: Instant?,
    val title: String,
    val start: Instant,
    val end: Instant,
    val isAllDay: Boolean,
    val eventTimezone: ZoneId,           // authoring zone (from DTO)
    val recurrenceSummary: String?,      // human text built from RecurrenceRule (AND-270)
    val location: EventLocation?,        // address + optional lat/lng
    val description: String?,
    val organizer: EventPerson?,
    val attendees: List<EventAttendee>,  // empty for public/limited payloads
    val calendarName: String,
    val colorKey: String,
    val attachments: List<EventAttachment>,
)
data class EventLocation(val label: String, val lat: Double?, val lng: Double?)
data class EventPerson(val displayName: String, val uIdentifier: String?, val avatarUrl: String?)
data class EventAttendee(val person: EventPerson, val rsvp: RsvpStatus)
enum class RsvpStatus { ACCEPTED, DECLINED, TENTATIVE, NEEDS_ACTION }
data class EventAttachment(val id: String, val name: String, val url: String, val thumbnailUrl: String?, val mimeType: String?)
```

```kotlin
@HiltViewModel
class EventDetailViewModel @Inject constructor(
    private val repo: CalendarRepository,           // AND-270 (+ single-event read, §5)
    private val zonePrefs: CalendarZonePreferences,  // AND-271, DataStore-backed
    private val publicUrlBuilder: PublicEventUrlBuilder,
    private val savedState: SavedStateHandle,
    private val clock: Clock,
) : ViewModel() {
    val uiState: StateFlow<EventDetailUiState>       // started WhileSubscribed(5_000)
    fun retry()
}

// Builds the canonical https link from BuildConfig host (flavor-aware: staging/prod), never the plaintext dev host.
class PublicEventUrlBuilder @Inject constructor(@PublicWebHost private val host: String) {
    fun build(calendarId: String, eventId: String): String   // "https://$host/event/$calendarId/$eventId"
}
```

Composables: `EventDetailRoute`, `EventDetailScreen`, `EventHeader` (title + color + calendar name), `EventWhenRow` (formatted range + zone label + recurrence), `EventLocationRow`, `EventDescription` (linkified), `OrganizerRow`, `AttendeeList`, `AttachmentGrid` (Coil), `EventActionBar` (TopAppBar overflow + bottom actions), `EventUnavailable`/`EventForbidden` states, and a `DetailSkeleton`. Maps/calendar/share intents wrapped in a thin `EventIntents` helper guarded by `resolveActivity`/try-catch so missing handler apps fail gracefully.

**Navigation registration (AND-022 NavHost):**

```kotlin
fun NavGraphBuilder.eventDetailDestination(navController: NavController) {
    composable(
        route = EVENT_DETAIL_ROUTE,
        arguments = listOf(
            navArgument(EventDetailArgs.CALENDAR_ID) { type = NavType.StringType },
            navArgument(EventDetailArgs.EVENT_ID) { type = NavType.StringType },
            navArgument(EventDetailArgs.OCCURRENCE_START) { type = NavType.LongType; defaultValue = -1L },
        ),
        deepLinks = listOf(
            navDeepLink { uriPattern = "https://${BuildConfig.PUBLIC_WEB_HOST}/event/{calendarId}/{eventId}" },
            navDeepLink { uriPattern = "https://${BuildConfig.PUBLIC_WEB_HOST_STAGING}/event/{calendarId}/{eventId}" },
        ),
    ) { EventDetailRoute(onBack = navController::navigateUp, onOpenProfile = { /* AND-073 */ }) }
}
```

**Manifest App Link (`app/src/main/AndroidManifest.xml`):**

```xml
<intent-filter android:autoVerify="true">
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="https" android:host="@string/public_web_host" android:pathPrefix="/event/" />
</intent-filter>
```

`android:autoVerify="true"` requires a published `/.well-known/assetlinks.json` for the host (release SHA-256 signing cert). The single-Activity host (`launchMode="singleTop"`) routes the VIEW intent into the `NavHost` via `onNewIntent` → `navController.handleDeepLink(intent)`.

## 5. API Contract

This ticket adds a **single-event read** to the AND-270-owned `CalendarRepository`; it performs no direct Retrofit calls itself. Confirm exact paths against `/openapi.json` and `frontend/src/api/endpoints/calendar.ts` before build.

```kotlin
interface CalendarRepository {
    fun events(window: DateWindow, zone: ZoneId): Flow<ApiResult<CachedList<CalendarEvent>>>   // AND-271/270
    // Added by this ticket (idempotent GET: bounded backoff retry + cache per project policy):
    fun event(calendarId: String, eventId: String, occurrenceStart: Instant?, zone: ZoneId)
        : Flow<ApiResult<Cached<CalendarEventDetail>>>
}
```

**Authenticated single event** (occurrence resolved via optional query param):

```
GET /ui/calendar/{calendarId}/events/{eventId}?occurrence_start=2026-06-08T13:30:00Z&tz=America/New_York
```

**Public event** (no session required; reduced payload):

```
GET /ui/calendar/public/{calendarId}/events/{eventId}
```

Expected response shape (superset; public variant omits `attendees`/private fields):

```json
{
  "id": "evt_01H...",
  "calendar_id": "cal_main",
  "calendar_name": "Team",
  "title": "Standup",
  "start": "2026-06-08T13:30:00Z",
  "end": "2026-06-08T14:00:00Z",
  "timezone": "America/New_York",
  "all_day": false,
  "color": "blue",
  "description": "Daily sync",
  "location": { "label": "HQ Room 4", "lat": 40.7128, "lng": -74.0060 },
  "recurrence": { "freq": "WEEKLY", "interval": 1, "byday": ["MO"] },
  "occurrence_start": "2026-06-08T13:30:00Z",
  "organizer": { "display_name": "Sam", "u_identifier": "u-sam", "avatar_url": "https://.../a.jpg" },
  "attendees": [ { "person": { "display_name": "Lee", "u_identifier": "u-lee" }, "rsvp": "accepted" } ],
  "attachments": [ { "id": "att_1", "name": "agenda.pdf", "url": "https://.../agenda.pdf", "thumbnail_url": null, "mime_type": "application/pdf" } ],
  "is_public": true
}
```

The repository chooses the public vs. authenticated endpoint based on session state and a `404→403` fallback (try authenticated; on `404` for a known public link, retry public). FastAPI `detail` (`string | [{msg}] | {code,...}`) is mapped by `core-network` to `ApiResult.Failure`; this ticket maps `Failure` → `EventDetailError` (HTTP `404`→`NOT_FOUND`, `403`→`FORBIDDEN`, terminal `401`→`AUTH_REQUIRED`, `5xx`→`SERVER`, IO/timeout→`NETWORK`).

## 6. Data & State Management

- **Single source of truth:** `EventDetailViewModel.uiState: StateFlow<EventDetailUiState>`, started `WhileSubscribed(5_000)`.
- **Args ingestion:** `calendarId`/`eventId`/`occurrenceStart` read from `SavedStateHandle` (populated identically for in-app navigation and deep-link). `occurrenceStart == -1L` → `null` (public links omit occurrence; the backend returns the next/base occurrence).
- **Reactive load:** `zonePrefs.displayZone().flatMapLatest { zone -> repo.event(calendarId, eventId, occurrenceStart, zone) }`, mapped to `Content`/`Error`. `displayZone = override ?: ZoneId.systemDefault()`; `zoneMismatch = displayZone != deviceZone`.
- **Caching (stale-while-revalidate):** AND-270's Room cache yields `Cached<CalendarEventDetail>` with `isStale`; a cache hit renders immediately (`isStale=true` badge) while the network refresh runs. Public-event responses are cached keyed by `(calendarId, eventId, isPublic)` so the authenticated and public variants don't collide.
- **Recurrence summary** built once in the ViewModel from `RecurrenceRule` (AND-270) using a localized formatter; stored on `EventDetailModel.recurrenceSummary`.
- **publicShareUrl** computed eagerly by `PublicEventUrlBuilder` from the flavor host (staging/prod from `BuildConfig`), never the dev plaintext host.
- No new persisted UI prefs; display-zone override reuses AND-271's `calendar_display_zone` DataStore key.

## 7. Error Handling & Resilience

- **Transport policy** (≈20s timeouts, bounded exponential backoff for idempotent GETs only) owned by `core-network`/AND-270. This ticket never blind-retries; `retry()` is user-initiated.
- **`EventDetailError` taxonomy** (§5 mapping). `NOT_FOUND`/`FORBIDDEN` are terminal, rendered as dedicated states (FR-6), not the generic error banner; `NETWORK`/`SERVER`/`UNKNOWN` show a dismissible inline error with Retry.
- **Stale-while-error:** `Error(cause, cached)` retains the last good `Content` so a refresh failure keeps the event visible with a banner rather than blanking.
- **Deep-link robustness:** malformed/empty `calendarId`/`eventId` from a public URL → immediate `NOT_FOUND` state (no network call). Unknown/extra path segments fall through to the in-app 404 route, never a crash.
- **Auth interplay:** terminal `401` (after `core-network`'s single refresh) on an auth-required event → `AUTH_REQUIRED`; the screen hands off to the auth gate (AND-025) with the original deep link as redirect, returning to the event post-login.
- **Intent safety:** add-to-calendar/maps/share intents guarded so a device with no handling app shows a Snackbar instead of an `ActivityNotFoundException`.
- **Boundary safety:** `end <= start` clamped to a 1-minute display range; `DateTimeException` on zone conversion falls back to UTC with a logged warning.

## 8. Security & Privacy

- **Public-link exposure:** the public endpoint is intentionally unauthenticated and returns a **reduced** payload; the client must never request or display attendee PII for `is_public` events even if a field is present — gate attendee rendering on `!isPublic`.
- **Canonical share URL** is always `https` on the prod/staging web host; the plaintext dev host (`18.222.237.167:8000`) is never placed in a shareable/exported link.
- **App Link verification:** `autoVerify="true"` + a published `assetlinks.json` (release signing SHA-256) prevents link hijacking and the disambiguation dialog. Staging uses a separate host/asset-links entry.
- **Intent hardening:** the single-Activity host is `exported="true"` only for the declared `https` `intent-filter`; deep-link args are treated as untrusted and validated before use. No implicit intent carries credentials/cookies; outbound `ACTION_SEND`/maps intents contain only the public URL or location label.
- **No new at-rest secrets;** auth rides existing cookie + `ui_csrf`/`X-CSRF-Token` plumbing and the required persistent cookie jar (`core-network`). Cleartext permitted only for the dev host via existing network-security config.

## 9. Accessibility & i18n

- Every interactive element (Back, overflow actions, action bar buttons, location row, attachment items, organizer/attendee rows) has a `contentDescription`; touch targets ≥ 48dp.
- The when-row announces the full localized start–end range with zone and all-day/multi-day status as a single semantics node; recurrence summary is read after it.
- TalkBack order: title → calendar/color → when → location → description → organizer → attendees → attachments → actions. Attachment items expose a custom "open" action.
- i18n: all strings in `strings.xml`; dates/times via `DateTimeFormatter.ofLocalizedDateTime`/`ofLocalizedDate` with `Locale.getDefault()`; recurrence summary built from localized plurals (`plurals.xml`), no concatenation. RTL mirroring for the action bar, nav, and rows. No hardcoded date/time formats. RSVP statuses and the zone-mismatch hint are localized.

## 10. Telemetry & Logging

- Analytics via the `core-data` analytics facade: `event_detail_shown {source: in_app|deeplink, is_public, has_recurrence}`, `event_detail_action {action: add_calendar|share|maps|open_organizer}`, `event_detail_deeplink_opened {verified}`, `event_detail_load_error {error_type}`, `event_detail_auth_redirect`.
- Logging via the shared logger: DEBUG for arg parsing, endpoint-variant selection (auth vs public), and load-state transitions; INFO for deep-link resolution. **Never** log event title, description, location, organizer/attendee identity, or full payloads. Error logs carry `EventDetailError` + HTTP status only.
- App Link verification status logged once at startup (DEBUG) to aid field triage of unverified-host disambiguation issues.

## 11. Testing Strategy

**Unit (JVM, core-testing + Turbine):**
- `EventDetailViewModel`: `Loading→Content`; cache hit emits `Content(isStale=true)` then fresh; `Error(cached)` preserves last-good; `retry()` re-emits.
- Error mapping: `404→NOT_FOUND`, `403→FORBIDDEN`, terminal `401→AUTH_REQUIRED`, `5xx→SERVER`, IO→`NETWORK`.
- Public vs authenticated selection logic and the `404→public` fallback; `is_public` payload suppresses attendees.
- `occurrenceStart` arg decoding (`-1L → null`); malformed args → `NOT_FOUND` without a network call.
- Timezone formatting: a `13:30Z` event shows 09:30 in `America/New_York`, 22:30 in `Asia/Tokyo`; all-day events show a date range with no time and no zone shift; DST-day formatting correct. Injected `Clock`/fixed `ZoneId`.
- `PublicEventUrlBuilder` produces `https://<prod-host>/event/{cal}/{evt}` and never the dev host.
- Recurrence summary localization from `RecurrenceRule`.

**Instrumented (Compose UI, AndroidJUnit4 + Hilt test + fake `CalendarRepository`):**
- Seeded event renders all fields in the correct zone (assert via semantics) — the in-app half of the acceptance bar.
- Action bar: add-to-calendar, share (assert `ACTION_SEND` extras via `Intents`/Espresso-Intents), maps, open-organizer; intent-absent → Snackbar.
- `NOT_FOUND`/`FORBIDDEN`/error-banner-with-retry/stale-badge states render correctly.
- Accessibility: semantics labels, custom actions, 48dp targets.

**Deep-link / App Link:**
- `navController.handleDeepLink` with `https://<host>/event/cal_main/evt_1` resolves `EventDetail` with correct args and a back stack returning into the app (the public-link half of the acceptance bar).
- Cold-start `Intent(ACTION_VIEW, uri)` launched at the Activity routes to detail (Espresso-Intents).
- Malformed path → in-app 404, no crash.
- Manifest/asset-links lint check (no instrumented network): verify `autoVerify` + `pathPrefix` present.

## 12. Dependencies & Sequencing

- **Hard upstream — AND-271 (Calendar views):** provides `onEventClick(calendarId, eventId, occurrenceStart)` and the `feature-calendar` module + `CalendarZonePreferences`. Must land first; until then, wire from a stub caller.
- **Hard upstream — AND-022 (Navigation host & routes):** typed `NavHost`; this ticket registers the `EventDetail` destination + `navDeepLink`.
- **Transitive — AND-270:** `CalendarRepository` (extended here with `event(...)`), `CalendarEvent(Detail)` DTO/mapping, Room cache, recurrence model. Develop against `FakeCalendarRepository` (core-testing) mirroring §5 until merged.
- **Soft — AND-073 (public profile `u-identifier`):** organizer/attendee profile open; behind a capability check, no-op if unavailable.
- **Soft — AND-025 (auth-gated routing):** post-login redirect for auth-required events opened via deep link.
- **Build:** declare `public_web_host`/staging host strings + `BuildConfig.PUBLIC_WEB_HOST`; reuse AND-271's core library desugaring; Coil already available (`core-ui`). Publish `/.well-known/assetlinks.json` with the release SHA-256 (ops task, called out in §13).
- **Sequencing:** (1) extend repo + fake, (2) ViewModel + state + error mapping, (3) detail composables, (4) typed route + in-app nav from AND-271, (5) action intents, (6) App Link manifest + deep-link parsing, (7) public/limited payload + auth redirect, (8) instrumented + deep-link tests.

## 13. Risks & Open Questions

- **R1 (asset-links publication):** App Link auto-verification requires `/.well-known/assetlinks.json` on the prod/staging hosts with the correct release cert SHA-256. If unpublished, links open via the disambiguation dialog. **OQ:** who owns asset-links deployment, and is staging's host verifiable? Until verified, accept the chooser dialog as a known gap.
- **R2 (public endpoint shape):** §5 assumes a distinct `/ui/calendar/public/...` route returning `is_public` and a reduced payload. **OQ:** confirm the public endpoint exists and its exact field omissions against `/openapi.json` and `calendar.ts`; if there is no public endpoint, the public-link path collapses to "auth required" and FR-5 narrows.
- **R3 (occurrence resolution on public links):** public URLs carry no `occurrence_start`; behavior for recurring public events (next vs. base occurrence) is server-defined. **OQ:** confirm which occurrence the backend returns.
- **R4 (timezone field semantics):** as in AND-271, whether `timezone` is the authoring vs. viewing zone; spec assumes authoring zone + separate display zone.
- **R5 (dev backend instability):** flaky plaintext host makes live deep-link verification unreliable; tests use fakes and `handleDeepLink`, manual verification uses cached/stale paths.
- **OQ:** does add-to-device-calendar need recurrence (RRULE → `CalendarContract` rule) in M6, or single-occurrence insert only? Spec ships single-occurrence insert; recurring insert deferred.

## 14. Acceptance Criteria

AC-1 **Event detail renders** (source-ticket acceptance, in-app half): tapping an event in any AND-271 view opens `EventDetail` showing title, correctly-zoned time range, recurrence summary, location, description, organizer/attendees, calendar, and attachments for a seeded event — asserted via Compose semantics.

AC-2 **Public link works** (source-ticket acceptance, public half): a `https://<host>/event/{calendarId}/{eventId}` intent (cold start) opens the app directly to the same event with a back stack that returns into the app; verified via `handleDeepLink` and Espresso-Intents.

AC-3 Time/zone display is correct: `13:30Z` shows 09:30 in `America/New_York` and 22:30 in `Asia/Tokyo`; all-day events show a date range with no time and no zone shift; a zone-mismatch hint appears when display ≠ device zone — covered by passing tests.

AC-4 Actions work: add-to-calendar prefills the device calendar insert; Share emits `ACTION_SEND` with the canonical `https` public URL (never the dev host); maps and open-organizer route correctly; missing-handler apps show a Snackbar, not a crash.

AC-5 Error/edge states: `404`→"Event unavailable", `403`→"You don't have access", transient errors show a dismissible Retry banner preserving last-good content, cache hits show a stale badge, malformed deep-link args → 404 with no network call and no crash.

AC-6 Public/limited payload: when `is_public`, attendee PII is never displayed; auth-required events opened via deep link route through the auth gate and return to the event after login.

AC-7 No event PII appears in logs; all interactive elements expose content descriptions and meet the 48dp target.

## 15. Definition of Done

- `EventDetailRoute`/`EventDetailScreen`/`EventDetailViewModel` and the `detail` sub-package implemented under `com.testlogon.android.feature.calendar.detail`; typed `EventDetail` destination + `navDeepLink` registered in the AND-022 `NavHost`; in-app navigation wired from AND-271's `onEventClick`.
- `CalendarRepository.event(...)` (and fake) implemented per §5; public vs authenticated selection + `404→public` fallback working; error mapping complete.
- App Link `intent-filter` (`autoVerify`, `pathPrefix="/event/"`, prod + staging hosts) added to `AndroidManifest.xml`; `onNewIntent`→`handleDeepLink` routing in place; asset-links publication tracked as an ops follow-up (R1).
- All FRs and ACs implemented; unit + instrumented + deep-link tests pass in CI, including timezone/all-day/DST and the cold-start public-link case.
- Lint and detekt clean; no hardcoded strings/date formats; desugaring reused; builds on `android-port` with AGP 8.7.3 / Gradle 8.9 / JDK 17.
- Telemetry events emitted; no event PII logged; accessibility semantics verified by test.
- Code reviewed and merged; spec status moved from `draft` to `accepted` once AC-1–AC-7 are demonstrated.
