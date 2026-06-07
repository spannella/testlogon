---
id: AND-272
title: Event detail (+ public event)
milestone: M6
epic: E37
priority: P1
size: L
depends_on: [AND-271, AND-022]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
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
- **Web reference:** `src/api/endpoints/calendar.ts` (`getEvent`, `getPublicEvent`, `getPublicIcalUrl`), `src/api/types.ts` (`CalendarEvent`, `CalendarEventAttachment`, `RecurrenceRule`), and `src/pages/calendar/PublicEventPage.tsx` (the only screen that consumes a single event). The web route `/event/:calendarId/:eventId` (verified `src/App.tsx`) is the canonical public URL shape to mirror. **Note (verified):** the web app does NOT have an authenticated single-event detail screen — `getEvent` is defined but unused; calendar views render from the list endpoint, and the only single-event consumer is the public page. The Android authenticated detail screen is therefore an Android-specific design; see §16 for the endpoint-availability caveat.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. Cookie + `ui_csrf`/`X-CSRF-Token` auth handled by `core-network`; 401 triggers one `POST /ui/session/refresh` + retry.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP), Coroutines/Flow, Coil (organizer/attendee avatars + attachment thumbnails), `java.time` via core library desugaring. minSdk 24, compileSdk/targetSdk 35, AGP 8.7.3, Gradle 8.9, JDK 17, branch `android-port`.

## 3. Functional Requirements

FR-1 **Detail entry (in-app).** Tapping any event in Month/Week/Agenda (AND-271 `onEventClick`) navigates to `EventDetail` with `calendarId`, `eventId`, and `occurrenceStart` (epoch millis). The detail screen loads and renders that occurrence.

FR-2 **Rendered fields.** **Verified against the API (`EventOut`/`CalendarEvent`, `CalendarEventAttachment`):** name (the `name` field — there is no `title`); date/time range from `start_utc`/`end_utc` formatted in the effective display zone with an explicit zone label; all-day rendered from `all_day`/`all_day_date` as a date (no time); recurrence summary built from `recurrence_rule` (freq ∈ DAILY|WEEKLY|MONTHLY, optional `interval`/`byday`/`bymonthday`/`bysetpos`/`count`/`until_utc`); description (`description`, linkified plain text); status/category. **NOT backed by the current API — render only if/when the backend adds them (see §16 Open assumptions):** location with lat/lng + maps tap, organizer avatar/name, attendee list **with RSVP status**, source-calendar display name + color, and attachments with thumbnails. The DTO exposes `attendees` only as a `string[]` (sub identifiers, no RSVP/person/avatar), `calendar_id` (no `calendar_name`/`color`), and no organizer/location/attachment fields. Implement these UI rows behind a "field present?" guard so they no-op until the contract grows; do not block M6 on them.

FR-3 **Actions.** (a) **Add to device calendar** via `Intent(Intent.ACTION_INSERT, CalendarContract.Events.CONTENT_URI)` prefilled with name/time/description (location omitted unless the API later returns one). NB: this is an Android-specific affordance; the web equivalent on `PublicEventPage.tsx` is server-side (`createEvent`) plus a "Download .ics" link (`getPublicIcalUrl`) — see §16. (b) **Share public link** via `ACTION_SEND` with the canonical `https://<host>/event/{calendarId}/{eventId}` URL — verified to match the web route `/event/:calendarId/:eventId` (`src/App.tsx`). Optionally offer "Download .ics" mirroring web via `GET /calendar/public/event/{calendarId}/{eventId}/ical` (verified endpoint). (c) **Open location in maps** via `geo:` / maps query intent — **gated off until the API returns a location** (no location field exists today; see §16). (d) **Open organizer profile** — **gated off until the API returns an organizer/`u-identifier`** (no such field today; AND-073 integration is aspirational). All actions are no-ops/hidden when their backing data is absent.

FR-4 **Public App Link (cold/warm start).** An `https` App Link for path `/event/{calendarId}/{eventId}` on the production/staging hosts opens the app directly (verified Digital Asset Links → no disambiguation dialog) to the same `EventDetail` destination. From a cold start the deep link rebuilds a sensible back stack: `EventDetail` with the calendar root as parent so Back returns into the app rather than exiting.

FR-5 **Public (unauthenticated/limited) event.** **Verified:** the public endpoint `GET /calendar/public/event/{calendar_id}/{event_id}` requires no session and returns the reduced `CalendarEventAttachment` shape — `event_id, calendar_id, name, start_utc?, end_utc?, all_day, all_day_date?, timezone, description?, owner` only (no attendees, organizer, location, color, recurrence, or attachments). **Correction:** there is NO `is_public` flag in any payload; "public" is determined by which endpoint succeeds, not by a response field. The detail UI must distinguish public vs. authenticated by the endpoint/path used, not by parsing `is_public`. The screen renders whatever fields are returned and hides absent ones. If the event requires auth and the user is unauthenticated, the screen routes through the existing auth gate (AND-025) preserving the deep link as a post-login redirect, then returns to the event.

FR-6 **Not-found / forbidden.** A `404` (event/calendar missing or expired public link) shows a dedicated "Event unavailable" state with a Back action. A `403` (private event, insufficient visibility) shows a "You don't have access" state. **Verified caveat:** the OpenAPI spec only documents `200` and `422` (`HTTPValidationError`) for both the public and single-event endpoints; `403`/`404` are FastAPI runtime responses with a `{ "detail": ... }` body and are not in the schema. Treat a `422` (malformed/invalid id) like `NOT_FOUND` for display, matching the web page which renders any error as "Event not found" (`PublicEventPage.tsx`, `retry:false`). Neither shows a raw error.

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

> **Contract note (verified 2026-06-06):** several fields below (`location`, `organizer`, `attendees` with RSVP, `colorKey`, `calendarName`, `attachments`) are NOT present in the current API (`EventOut`/`CalendarEventAttachment`); `attendees` from the API is a bare `string[]` of sub identifiers. These model fields are retained as the *target* shape but must be populated defensively (null/empty) and their UI guarded until the backend grows the contract. The id/title/time fields map to `event_id`/`name`/`start_utc`/`end_utc`. See §16 Open assumptions.

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

This ticket adds a **single-event read** to the AND-270-owned `CalendarRepository`; it performs no direct Retrofit calls itself. Paths below were verified against `reference/openapi.index.txt`, `reference/openapi.pretty.json`, and `src/api/endpoints/calendar.ts` during this review (2026-06-06); corrections are flagged inline and audited in §16.

```kotlin
interface CalendarRepository {
    fun events(window: DateWindow, zone: ZoneId): Flow<ApiResult<CachedList<CalendarEvent>>>   // AND-271/270
    // Added by this ticket (idempotent GET: bounded backoff retry + cache per project policy).
    // Maps EventOut/CalendarEvent (auth) or CalendarEventAttachment (public) → domain model.
    // occurrenceStart is a client-only hint for which occurrence to format; it is NOT sent to the
    // server (no such query param exists — see §5/§16).
    fun event(calendarId: String, eventId: String, occurrenceStart: Instant?, zone: ZoneId)
        : Flow<ApiResult<Cached<CalendarEventDetail>>>   // CalendarEventDetail is an AND-270 domain type mapped from the DTOs above
}
```

**Authenticated single event.** **Corrected path** (spec previously had `/ui/calendar/{calendarId}/events/{eventId}` — wrong: singular `calendar`, and the occurrence/tz query params do not exist):

```
GET /ui/calendars/{calendar_id}/events/{event_id}
```

> **Verification caveat (important):** `src/api/endpoints/calendar.ts: getEvent` calls exactly this path with NO query params and returns `CalendarEvent`. However, the **OpenAPI spec does NOT document a GET on `/ui/calendars/{calendar_id}/events/{event_id}`** — only `DELETE`, `PATCH`, and a `/ical` GET sub-path are present. So the authenticated single-event GET is *frontend-attested but undocumented*. **Plan:** call this GET; if the deployed backend returns 404/405 for it, fall back to the list endpoint `GET /ui/calendars/{calendar_id}/events?start_utc=..&end_utc=..` (verified, returns `EventsPageOut` of `EventOut`) and filter by `event_id` client-side. There is **no** `occurrence_start` or `tz` query param on any single-event GET; recurring-occurrence resolution and zone formatting are entirely client-side from `recurrence_rule` + `timezone`.

**Public event** (no session required; reduced payload). **Corrected path** (spec previously had `/ui/calendar/public/{calendarId}/events/{eventId}` — wrong host prefix and shape):

```
GET /calendar/public/event/{calendar_id}/{event_id}
```
Verified in `openapi.index.txt` (op `get_public_event_...`), `openapi.pretty.json`, and `src/api/endpoints/calendar.ts: getPublicEvent`. Path params only; no query params. Optional companion: `GET /calendar/public/event/{calendar_id}/{event_id}/ical` (verified) for the "Download .ics" action.

**Actual authenticated response shape** — `EventOut` (≡ frontend `CalendarEvent`), verified field-by-field against `openapi.pretty.json` and `src/api/types.ts`. Field names differ substantially from the previous spec draft (see §16 Corrections):

```json
{
  "event_id": "evt_01H...",
  "calendar_id": "cal_main",
  "name": "Standup",
  "description": "Daily sync",
  "timezone": "America/New_York",
  "start_utc": "2026-06-08T13:30:00Z",
  "end_utc": "2026-06-08T14:00:00Z",
  "all_day": false,
  "all_day_date": null,
  "attendees": ["u-lee", "u-sam"],
  "booking_enabled": false,
  "approval_required": false,
  "status": "confirmed",
  "category": null,
  "recurrence_rule": { "freq": "WEEKLY", "interval": 1, "byday": ["MO"] },
  "exdates_utc": [],
  "recurrence_overrides": {},
  "created_at_utc": "2026-06-01T00:00:00Z",
  "sync_state": null
}
```

Notes on the corrected shape: the id field is **`event_id`** (not `id`); the title field is **`name`** (not `title`); the times are **`start_utc`/`end_utc`** (both optional/nullable, not `start`/`end`); recurrence is **`recurrence_rule`** (not `recurrence`), with `freq ∈ {DAILY, WEEKLY, MONTHLY}` only; **`attendees` is `string[]`** of sub identifiers (NO RSVP, person, or avatar objects); and there is **no** `color`, `calendar_name`, `location`, `organizer`, `attachments`, `occurrence_start`, or `is_public` field. Any of those rendered by the UI (FR-2/FR-3) must be guarded as "not yet in contract" (see §16 Open assumptions).

**Actual public response shape** — `CalendarEventAttachment` (per `getPublicEvent`'s return type; the OpenAPI 200 schema is untyped `{}`), verified in `src/api/types.ts`:

```json
{
  "event_id": "evt_01H...",
  "calendar_id": "cal_main",
  "name": "Standup",
  "start_utc": "2026-06-08T13:30:00Z",
  "end_utc": "2026-06-08T14:00:00Z",
  "all_day": false,
  "all_day_date": null,
  "timezone": "America/New_York",
  "description": "Daily sync",
  "owner": "u-sam"
}
```

The repository chooses the public vs. authenticated endpoint based on session state (public path when unauthenticated or when the in-app GET 404s for a known public link). FastAPI documents only `200`/`422` (`HTTPValidationError`, shape `{ "detail": [ { "loc": [...], "msg": "...", "type": "..." } ] }`) for these endpoints; `401`/`403`/`404`/`5xx` are runtime FastAPI errors with a `{ "detail": ... }` body. `core-network` maps these to `ApiResult.Failure`; this ticket maps `Failure` → `EventDetailError` (HTTP `404`→`NOT_FOUND`, `403`→`FORBIDDEN`, `422`→`NOT_FOUND` for display, terminal `401`→`AUTH_REQUIRED`, `5xx`→`SERVER`, IO/timeout→`NETWORK`).

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

- **Public-link exposure:** the public endpoint (`GET /calendar/public/event/{calendar_id}/{event_id}`, verified) is intentionally unauthenticated and returns the **reduced** `CalendarEventAttachment` shape, which already omits attendees/organizer entirely. The client must never display attendee PII on the public path; gate attendee rendering on "loaded via the public endpoint" (there is no `is_public` response flag — public vs. authenticated is known from which endpoint was called, see §5). The `owner` field IS present in the public payload — treat it as an opaque identifier, do not surface it as PII unless the backend later attaches profile data.
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
- **R2 (public endpoint shape):** **RESOLVED (verified 2026-06-06).** The public endpoint exists at `GET /calendar/public/event/{calendar_id}/{event_id}` (NOT the `/ui/calendar/public/...` the draft assumed) and returns the reduced `CalendarEventAttachment` (name, times, all-day, timezone, description, owner) with NO `is_public` flag. FR-5 is correct in spirit but corrected for path/shape; the public path does not collapse. Remaining gap: the **authenticated** single-event GET (`/ui/calendars/{id}/events/{eventId}`) is used by the web client but is NOT in OpenAPI — see §16 Open assumptions and the §5 list-endpoint fallback.
- **R3 (occurrence resolution on public links):** **PARTIALLY RESOLVED.** Verified that neither the public nor the authenticated single-event GET accepts an `occurrence_start` query param, so the backend returns the base event (`recurrence_rule` + base `start_utc`); per-occurrence selection is client-side from the rule. The web `PublicEventPage` formats only the base `start_utc`/`end_utc`. **OQ remaining:** whether the backend ever expands occurrences server-side for recurring public events (no evidence it does).
- **R4 (timezone field semantics):** as in AND-271, whether `timezone` is the authoring vs. viewing zone; the web `PublicEventPage.formatEventTime` formats `start_utc` *in the event's `timezone`* (treats `timezone` as the display zone for the public view). Spec assumes authoring zone + separate user display-zone override; reconcile with AND-271. **Unverified** beyond the web behavior just cited.
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

## 16. Citations & Assumption Audit

Reviewed 2026-06-06 against `reference/openapi.index.txt`, `reference/openapi.pretty.json`, and `reference/src/`. Each key technical claim with VERDICT and exact SOURCE pointer.

1. **Public-event endpoint is `GET /calendar/public/event/{calendar_id}/{event_id}` (no session, path params only).** VERDICT: **Corrected** (draft said `GET /ui/calendar/public/{calendarId}/events/{eventId}`). SOURCE: OpenAPI `GET /calendar/public/event/{calendar_id}/{event_id}` (op `get_public_event_...`, params=calendar_id,event_id, resp 200/422); `src/api/endpoints/calendar.ts: getPublicEvent`.
2. **Public-event response is the reduced `CalendarEventAttachment` (event_id, calendar_id, name, start_utc?, end_utc?, all_day, all_day_date?, timezone, description?, owner).** VERDICT: **Corrected** (draft invented a superset with attendees/organizer/location/is_public). SOURCE: `src/api/types.ts: CalendarEventAttachment` (return type of `getPublicEvent`); OpenAPI 200 schema is untyped `{}`.
3. **There is no `is_public` flag in any payload; public vs. authenticated is determined by endpoint.** VERDICT: **Corrected** (draft keyed UI/cache/security on `is_public`). SOURCE: `EventOut` required/properties (`openapi.pretty.json` ll.32224–32403) and `CalendarEventAttachment` — neither has the field.
4. **Authenticated single-event read path is `GET /ui/calendars/{calendar_id}/events/{event_id}` (plural `calendars`).** VERDICT: **Corrected** (draft said singular `/ui/calendar/...`). SOURCE: `src/api/endpoints/calendar.ts: getEvent`.
5. **The authenticated single-event GET is NOT documented in OpenAPI (only DELETE + PATCH on that path, plus a `/ical` GET).** VERDICT: **Unverified-assumption** (frontend-attested only; endpoint may not exist on the deployed backend). SOURCE: `openapi.pretty.json` ll.192167–192460 — methods on `/ui/calendars/{calendar_id}/events/{event_id}` are `delete` (op `delete_event_...`) and `patch` (op `update_event_...`) only; the only GET in that block is `download_event_ical_...` on the `/ical` sub-path. Mitigation: list-endpoint fallback (claim 6).
6. **List endpoint `GET /ui/calendars/{calendar_id}/events` returns `EventsPageOut` of `EventOut` and is a valid fallback.** VERDICT: **Verified**. SOURCE: OpenAPI `GET /ui/calendars/{calendar_id}/events` (op `list_events_...`, resp 200:EventsPageOut, params=calendar_id,start_utc,end_utc,limit,cursor,...); `EventsPageOut` (`openapi.pretty.json` l.32647); `src/api/endpoints/calendar.ts: getEvents`.
7. **No `occurrence_start` or `tz` query param on any single-event GET.** VERDICT: **Corrected** (draft put `?occurrence_start=..&tz=..` on the auth GET). SOURCE: `getEvent` sends none (`calendar.ts:59`); OpenAPI documents no GET on the bare path; occurrence params exist only on the `/occurrences/{occurrence_start}` sub-routes (POST exclude/override, DELETE clear).
8. **Authenticated event DTO field names: `event_id`, `name`, `start_utc`/`end_utc`, `all_day`/`all_day_date`, `timezone`, `description`, `attendees` (string[]), `recurrence_rule`, `status`, `category`, `booking_enabled`, `approval_required`, `created_at_utc`.** VERDICT: **Corrected** (draft used `id`/`title`/`start`/`end`/`recurrence`). SOURCE: `EventOut` (`openapi.pretty.json` ll.32224–32401, required list ll.32389–32401); `src/api/types.ts: CalendarEvent` (ll.1788–1810).
9. **`attendees` is `string[]` with no RSVP/person/avatar.** VERDICT: **Corrected** (draft modeled attendee objects with `rsvp`). SOURCE: `EventOut.attendees` items type string (`openapi.pretty.json` ll.32245–32251); `CalendarEvent.attendees: string[]` (`types.ts` l.1798).
10. **No `color`/`calendar_name`/`location`/`organizer`/`attachments`/`occurrence_start` fields on the event DTO.** VERDICT: **Corrected** (draft's FR-2/§5/§4 model and example JSON included all of these). SOURCE: full `EventOut` property list (`openapi.pretty.json` ll.32225–32387) — absent.
11. **`recurrence_rule.freq ∈ {DAILY, WEEKLY, MONTHLY}`; optional `interval` (default 1), `byday` (MO..SU), `bymonthday`, `bysetpos`, `count`, `until_utc`.** VERDICT: **Verified** (and key corrected from `recurrence` → `recurrence_rule`). SOURCE: `RecurrenceRule` (`openapi.pretty.json` ll.62855–62951); `types.ts: RecurrenceRule` (ll.1740–1748).
12. **Public-event iCal companion endpoint `GET /calendar/public/event/{calendar_id}/{event_id}/ical` exists.** VERDICT: **Verified**. SOURCE: OpenAPI `download_public_ical_...`; `src/api/endpoints/calendar.ts: getPublicIcalUrl`.
13. **Web public URL route is `/event/:calendarId/:eventId`; Android App Link/share URL should mirror it.** VERDICT: **Verified**. SOURCE: `src/App.tsx:280` `<Route path="/event/:calendarId/:eventId" ...>`.
14. **Auth/transport: cookie session + CSRF via `ui_csrf` cookie → `X-CSRF-Token` header; one `POST /ui/session/refresh` + retry on 401; unauthenticated 401 is NOT refreshed.** VERDICT: **Verified**. SOURCE: `src/api/client.ts` (CSRF ll.167–170, `refreshSession` POST `/ui/session/refresh` ll.121–128, 401-once-refresh ll.191–224, `credentials:"include"`).
15. **Error envelope for documented failures is `422 HTTPValidationError` = `{ "detail": [ {loc,msg,type} ] }`; 401/403/404/5xx are runtime FastAPI `{ "detail": ... }` not in schema.** VERDICT: **Verified** (documented part) / **Unverified-assumption** (runtime 403/404 bodies). SOURCE: `HTTPValidationError`/`ValidationError` (`openapi.pretty.json` ll.37133–37145); endpoint `responses` blocks list only 200/422.
16. **Web `PublicEventPage` renders only name + formatted time + description, has "Download .ics" and a server-side "Add to my Calendar" (`createEvent`), and shows a generic "Event not found" on any error (`retry:false`).** VERDICT: **Verified**. SOURCE: `src/pages/calendar/PublicEventPage.tsx` (render ll.104–149, `handleAddToCalendar` ll.65–81, error ll.91–100, query `retry:false` l.57).
17. **Web app has no authenticated single-event detail screen; `getEvent` is defined but unused.** VERDICT: **Verified**. SOURCE: repo grep — `getEvent` referenced only at its definition (`calendar.ts:59`); the lone single-event consumer is `getPublicEvent` in `PublicEventPage.tsx`.
18. **App Link auto-verification requires `/.well-known/assetlinks.json` with the release SHA-256; `autoVerify="true"` + `BROWSABLE`/`DEFAULT` + `pathPrefix` intent-filter.** VERDICT: **Verified (framework ref)**. SOURCE: Android docs — Verify Android App Links (https://developer.android.com/training/app-links/verify-android-applinks) and App Links / Digital Asset Links (https://developer.android.com/training/app-links).
19. **Single-Activity deep-link routing via `onNewIntent` → `navController.handleDeepLink(intent)` and `navDeepLink { uriPattern = ... }`.** VERDICT: **Verified (framework ref)**. SOURCE: Navigation-Compose deep links (https://developer.android.com/jetpack/compose/navigation#deeplinks).
20. **Add-to-device-calendar via `Intent(ACTION_INSERT, CalendarContract.Events.CONTENT_URI)`.** VERDICT: **Verified (framework ref)**. SOURCE: Android Calendar provider intents (https://developer.android.com/guide/topics/providers/calendar-provider#intents).

### Corrections made
- §2/§5: public endpoint path `→ GET /calendar/public/event/{calendar_id}/{event_id}` (was `/ui/calendar/public/{calendarId}/events/{eventId}`).
- §5: authenticated path `→ GET /ui/calendars/{calendar_id}/events/{event_id}` (was singular `/ui/calendar/...`); removed the non-existent `?occurrence_start=..&tz=..` query params.
- §5/§3/§4: rewrote the example response to the real `EventOut` field names (`event_id`/`name`/`start_utc`/`end_utc`/`recurrence_rule`) and removed invented fields (`id`,`title`,`start`,`end`,`color`,`calendar_name`,`location{lat,lng}`,`organizer`,`attendees[].rsvp`,`attachments`,`occurrence_start`,`is_public`); documented the reduced public `CalendarEventAttachment`.
- §3 FR-2/FR-3, §4 model: flagged location/organizer/attendee-RSVP/color/attachments as not-in-contract and to be UI-guarded; corrected `attendees` to `string[]`.
- §5/§8: removed `is_public`-flag-based logic; public vs auth is determined by endpoint; `owner` is the only identifier in the public payload.
- §5: error mapping adds `422 → NOT_FOUND` for display, mirroring the web page.
- §13 R2/R3/R4: resolved/updated with verified findings.
- Frontmatter: removed duplicate `status`, set `status: reviewed`, added `reviewed_on: 2026-06-06`.

### Open assumptions (unverifiable from sources / deferred)
- **Authenticated GET single-event endpoint existence** (claim 5): used by the web client but absent from OpenAPI. Cannot confirm the deployed backend serves a GET there. Build MUST implement the list-endpoint fallback (claim 6) and treat 404/405 on the GET as "use list filter."
- **Runtime 403/404 response bodies** (claim 15): not in OpenAPI; assumed `{ "detail": ... }` per FastAPI convention. Confirm against a live response once the flaky dev host is reachable.
- **Recurring public-event occurrence expansion** (R3): no `occurrence_start` param exists; assumed the server returns the base event and the client formats occurrences from `recurrence_rule`. Unconfirmed whether the server ever expands occurrences.
- **`timezone` field semantics** (R4): web treats it as the display zone for the public view; spec assumes authoring zone + user override. Unverified beyond observed web behavior.
- **Rich detail fields** (location/lat-lng, organizer/avatar, attendee profile + RSVP, calendar color/name, attachments): not in the current contract; all corresponding UI/actions are aspirational and gated. Revisit if/when the backend extends `EventOut`.
- **Staging host + `assetlinks.json` ownership** (R1): an ops dependency, not verifiable from these sources.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **AVD test35** = headless emulator, API 35/x86_64 (CI UI/instrumented); **A15** = physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R), API 34/arm64-v8a (real hardware). MockWebServer runs on JVM. Cases note when the physical device is required.

- **TC-AND-272-01** — Type: unit (JVM, Turbine). Target: JVM. Preconditions: `FakeCalendarRepository` returns an authenticated `EventOut` (name, start_utc/end_utc, recurrence_rule WEEKLY/MO, timezone). Steps: collect `EventDetailViewModel.uiState`. Expected: `Loading → Content` with mapped name/time/recurrence summary; `isStale=false`, `isPublic=false`. Traces: AC-1.
- **TC-AND-272-02** — Type: unit (JVM). Target: JVM. Preconditions: cached `Cached<CalendarEventDetail>(isStale=true)` then a fresh network value. Steps: subscribe. Expected: emits `Content(isStale=true)` immediately, then `Content(isStale=false)` after refresh; `retry()` re-emits. Traces: AC-5.
- **TC-AND-272-03** — Type: unit (JVM). Target: JVM. Preconditions: error mapping fixtures. Steps: feed `Failure` with HTTP 404, 403, 422, terminal 401, 500, and an IOException. Expected: `NOT_FOUND`, `FORBIDDEN`, `NOT_FOUND` (422 display rule), `AUTH_REQUIRED`, `SERVER`, `NETWORK` respectively (per §5/§16 claim 15). Traces: AC-5, AC-6.
- **TC-AND-272-04** — Type: contract/MockWebServer (JVM). Target: JVM. Preconditions: MockWebServer scripted to return the real `CalendarEventAttachment` JSON on `GET /calendar/public/event/{cal}/{evt}` (no auth headers required). Steps: repository fetches the public event. Expected: request path is exactly `/calendar/public/event/{cal}/{evt}` with no query params and no Cookie/CSRF header; response parses into the reduced model (name/time/description/timezone/owner only); attendees/organizer/location empty. Traces: AC-2, AC-6. (§16 claims 1,2.)
- **TC-AND-272-05** — Type: contract/MockWebServer (JVM). Target: JVM. Preconditions: MockWebServer returns 404 for `GET /ui/calendars/{cal}/events/{evt}` then a 200 `EventsPageOut` for `GET /ui/calendars/{cal}/events?start_utc&end_utc`. Steps: repository fetches the authenticated event. Expected: on the GET 404/405 it falls back to the list endpoint and filters by `event_id`, returning the matching `EventOut`; verifies the undocumented-GET mitigation (§16 claims 5,6). Traces: AC-1.
- **TC-AND-272-06** — Type: contract/MockWebServer (JVM). Target: JVM. Preconditions: an authenticated request after a 401. Steps: server returns 401 once, expects a `POST /ui/session/refresh`, then 200 on retry. Expected: exactly one refresh + one retry; `X-CSRF-Token` taken from the `ui_csrf` cookie is present on mutating/auth requests; an unauthenticated 401 (no prior session) is NOT refreshed → `AUTH_REQUIRED`. Traces: AC-6. (§16 claim 14.)
- **TC-AND-272-07** — Type: unit (JVM, fixed `Clock`/`ZoneId`). Target: JVM. Preconditions: event `start_utc=2026-06-08T13:30:00Z`. Steps: format in `America/New_York` and `Asia/Tokyo`; format an all-day event (`all_day=true`, `all_day_date` set); format a DST-boundary date. Expected: 09:30 (NY), 22:30 (Tokyo); all-day shows the date with no time and no zone shift; DST date correct; zone-mismatch flag set when display ≠ device zone. Traces: AC-3.
- **TC-AND-272-08** — Type: unit (JVM). Target: JVM. Preconditions: `PublicEventUrlBuilder` with prod + staging hosts. Steps: build a share URL. Expected: `https://<prod-host>/event/{cal}/{evt}` mirroring the web route; never the plaintext dev host `18.222.237.167:8000`. Traces: AC-4. (§16 claim 13.)
- **TC-AND-272-09** — Type: unit (JVM). Target: JVM. Preconditions: route args. Steps: decode `occurrenceStart == -1L` and malformed/empty `calendarId`/`eventId`. Expected: `-1L → null` (no occurrence query is ever sent regardless); malformed args → `NOT_FOUND` with NO network call. Traces: AC-5. (§16 claim 7.)
- **TC-AND-272-10** — Type: Compose-UI (instrumented, Hilt + fake repo). Target: AVD test35. Preconditions: seeded `Content` event. Steps: render `EventDetailScreen`; assert via semantics name, zoned time range, recurrence summary, description, calendar id. Expected: all present fields render; absent-in-contract rows (organizer/attendees-RSVP/location/attachments) are hidden, not blank-crashing. Traces: AC-1, AC-7.
- **TC-AND-272-11** — Type: Compose-UI / Espresso-Intents (instrumented). Target: AVD test35. Preconditions: seeded event; `Intents.init()`. Steps: tap Share, tap Add-to-calendar, simulate no handler app for Add-to-calendar. Expected: `ACTION_SEND` carries the canonical `https` public URL (never dev host); Add-to-calendar fires `ACTION_INSERT` on `CalendarContract.Events.CONTENT_URI`; missing handler → Snackbar, no `ActivityNotFoundException`. Traces: AC-4. (§16 claims 13,20.)
- **TC-AND-272-12** — Type: instrumented deep-link (AndroidJUnit4). Target: AVD test35. Preconditions: NavHost with the `EventDetail` destination + `navDeepLink`. Steps: `navController.handleDeepLink(Intent(ACTION_VIEW, Uri.parse("https://<host>/event/cal_main/evt_1")))`. Expected: resolves `EventDetail` with `calendarId=cal_main`,`eventId=evt_1`, back stack returns into the app (not exit); a malformed path (`/event/`) routes to in-app 404 with no crash. Traces: AC-2, AC-5.
- **TC-AND-272-13** — Type: instrumented/e2e cold-start App Link (Espresso-Intents). Target: **A15 (physical device required)**. Preconditions: app installed; assetlinks reachable (or accept chooser per R1); MockWebServer or stub backing the public fetch. Steps: from a cold start, `adb shell am start -a android.intent.action.VIEW -d "https://<host>/event/cal_main/evt_1"`. Expected: with verified Digital Asset Links the app opens directly (no disambiguation dialog) to the event; Back returns into the app. MUST run on the physical device to exercise real App Link auto-verification and the system chooser behavior (emulator verification differs). Traces: AC-2. (§16 claims 18,19.)
- **TC-AND-272-14** — Type: Compose-UI accessibility (instrumented). Target: AVD test35. Preconditions: seeded event + error/forbidden/not-found states. Steps: assert content descriptions on Back/overflow/action buttons/rows; touch targets ≥ 48dp; the when-row is a single semantics node announcing range + zone + all-day; verify the `NOT_FOUND`/`FORBIDDEN`/stale-badge/retry-banner states render and that no event title/description/identity is emitted to logs (capture Logcat). Expected: all assertions pass; log capture contains only `EventDetailError` + HTTP status. Traces: AC-5, AC-7.
- **TC-AND-272-15** — Type: manual (flaky-dev-host / offline). Target: **A15** (real network). Preconditions: airplane mode or the unreliable dev host. Steps: open a previously-cached event offline, then trigger a failed refresh. Expected: cached `Content` stays visible with a stale badge and a dismissible Retry banner (stale-while-error); going fully offline on a never-cached event → `NETWORK` error with Retry, no crash. Traces: AC-5.

### Coverage matrix
- **AC-1** (in-app detail renders): TC-01, TC-05, TC-10.
- **AC-2** (public link works): TC-04, TC-12, TC-13.
- **AC-3** (time/zone correctness): TC-07.
- **AC-4** (actions + missing-handler Snackbar): TC-08, TC-11.
- **AC-5** (error/edge/stale/malformed): TC-02, TC-03, TC-09, TC-12, TC-14, TC-15.
- **AC-6** (public/limited payload + auth redirect): TC-03, TC-04, TC-06.
- **AC-7** (no PII logs + a11y/48dp): TC-10, TC-14.
