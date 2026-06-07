---
id: AND-277
title: Calendar tests
milestone: M6
epic: E37
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-271, AND-270]
blocks: []
---

# AND-277 — Calendar tests

## 1. Overview & Goal

This ticket delivers the consolidated **automated test suite for the calendar
feature**, pinning the two layers that the source ticket calls out — **repository
mapping/transport** (AND-270) and **calendar UI** (AND-271) — with explicit,
exhaustive coverage of the two failure-prone domains: **timezone handling** and
**recurrence**. The source backlog is terse ("Repo + UI tests
(timezone/recurrence). Acceptance: Pass."); this spec makes that concrete and
testable.

The goal is regression protection at the JVM and instrumented layers so that the
hard-won timezone-slotting math (`13:30Z` → 09:30 New York / 22:30 Tokyo,
midnight-crossing, DST, all-day non-shift) and recurrence handling
(client-side-expanded occurrences from a structured `recurrence_rule` rendered in
correct slots, with `exdates_utc`/`recurrence_overrides` honored) cannot silently
break. Tests are **hermetic and deterministic**:
no live backend, no emulator-network access, fixed `Clock`/`ZoneId` injection,
`MockWebServer` for transport and fakes for UI.

This ticket adds **test sources only** (`src/test/`, `src/androidTest/`, and
shared fixtures in `core-testing`); it does not modify production behavior. A
defect found in AND-270/AND-271 is filed against that ticket. Scope spans
`core-network` (transport/mappers), `core-model` (domain invariants), and
`feature-calendar` (`EventSlotter`, `CalendarViewModel`, `CalendarPagingSource`,
Compose UI).

## 2. Context & References

- **Modules under test:** `core-network` (`com.testlogon.android.core.network.calendar`),
  `core-model` (`com.testlogon.android.core.model.calendar`),
  `feature-calendar` (`com.testlogon.android.feature.calendar`).
- **Upstream AND-270 (Calendar API + DTOs):** provides `CalendarApi`,
  `CalendarEventDto`/`RecurrenceDto`, `CalendarMappers.kt`
  (`CalendarEventDto.toDomain()`, `RecurrenceDto.toDomain()`),
  `InstantJsonAdapter`, enum fallback to `UNKNOWN`/`PENDING`, and the Room cache.
- **Upstream AND-271 (Calendar views):** provides `EventSlotter` (pure slotting),
  `CalendarViewModel`/`CalendarUiState`, `CalendarPagingSource`, and the
  `CalendarRoute`/`MonthGrid`/`WeekTimeGrid`/`AgendaList` composables.
- **Test infra (reused):** `core-testing` MockWebServer harness + fixture
  loader (AND-046), Turbine for `StateFlow`/`Flow` assertions, Hilt test runner,
  Compose UI test (`createAndroidComposeRule`, `androidx.compose.ui.test`),
  Paging 3 `PagingSource.load` / `AsyncPagingDataDiffer` test utilities.
- **Web reference:** `frontend/src/api/endpoints/calendar.ts` and
  `frontend/src/api/types.ts` — fixtures must mirror real field names and
  timezone/recurrence semantics; capture sample payloads from `/openapi.json`
  and the dev host where shapes are uncertain.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext, unreliable). **No test touches the live host;** all wire behavior is
  served by `MockWebServer` with captured fixtures.
- **Stack:** Kotlin 2.0.21, JUnit4, JDK 17, `java.time` with core-library
  desugaring, Coroutines test (`runTest`, `StandardTestDispatcher`),
  MockWebServer (OkHttp 4.12), Moshi 1.15, Compose + Material 3, AGP 8.7.3 /
  Gradle 8.9 on branch `android-port`.

## 3. Functional Requirements

FR-1 **Repository/transport coverage (AND-270).** Contract tests exercise the
production `CalendarApi` + Retrofit/Moshi/OkHttp stack against `MockWebServer`,
asserting (a) the request path/query — **CORRECTED**: the real endpoint is
`GET /ui/calendars/{calendar_id}/events` with query params
`start_utc`/`end_utc`/`limit`/`cursor` (cursor-based pagination); there is **no
`tz` query param** and no `/ui/calendar/events` path (verified against OpenAPI
`GET /ui/calendars/{calendar_id}/events` op `list_events…` and
`src/api/endpoints/calendar.ts: getEvents`) — (b) DTO→domain mapping for every
field, and (c) FastAPI `detail` error mapping to `ApiResult.Failure`.

FR-2 **Mapper unit coverage (AND-270).** Pure `CalendarMappers` tests cover
timestamp parsing to `Instant`, all-day `LocalDate` population, IANA `timezone`
preservation, unknown-enum → `UNKNOWN`/`PENDING` fallback (never throws), and
absent-optional tolerance via defaults.

FR-3 **Recurrence coverage. CORRECTED — recurrence is structured + client-side
expanded, not server-expanded.** The backend returns a single `EventOut` per
recurring series carrying a structured `recurrence_rule` object — fields
`freq` (`DAILY`/`WEEKLY`/`MONTHLY`), `interval`, `until_utc`, `count`, `byday`
(`MO`..`SU`), `bymonthday`, `bysetpos` — plus `exdates_utc: string[]` and a
`recurrence_overrides` map keyed by occurrence-start ISO string. There is **no
verbatim `rrule` string, no camelCase `byDay`/`exDates`, and no
`recurrence_id`/`occurrence_start` field** on the event; the web reference
(`src/pages/calendar/CalendarView.tsx`) detects a series via
`!!ev.recurrence_rule` and renders by the event's single `start_utc`. Tests
therefore assert that `RecurrenceDto.toDomain()` maps the structured rule
fields, `exdates_utc`, and the overrides map; and — **because the server does
NOT pre-expand** — that whichever component AND-271 designates as the expander
produces individual occurrences in their own slots with no collapse/duplication,
honoring `exdates_utc` and `recurrence_overrides`. (If AND-271 does not actually
expand client-side, see R1 — the recurrence-rendering tests move to the owner of
expansion.) Verified against OpenAPI schema `RecurrenceRule` and `EventOut`,
`src/api/types.ts: RecurrenceRule`/`CalendarEvent`,
`src/pages/calendar/CalendarView.tsx: isRecurring`.

FR-4 **Timezone slotting coverage (AND-271).** `EventSlotter` unit tests assert
correct day/time placement across display zones, midnight-crossing after
conversion, DST-transition days, and all-day non-shift. This is the primary
acceptance surface.

FR-5 **ViewModel state coverage.** `CalendarViewModel` tests assert
Loading→Content→Error(cached) transitions, stale-badge on cache hit,
`flatMapLatest` cancellation of superseded windows, and `retry()` re-emission —
using injected `Clock` and a `FakeCalendarRepository`.

FR-6 **Paging coverage.** `CalendarPagingSource` tests cover refresh/append/
prepend and `(eventId, occurrenceStart)` de-duplication.

FR-7 **Compose UI coverage.** Instrumented tests assert that seeded events render
in the correct cell/block/row in Month/Week/Agenda (asserted via semantics /
`contentDescription`), that view selection persists across recreation, that
navigation re-queries, and that error/empty/stale states render.

FR-8 **Determinism.** Every test injects a fixed `Clock` and explicit `ZoneId`s;
no test reads wall-clock time, the network, or `ZoneId.systemDefault()` without
overriding it. Tests pass repeatably regardless of CI host locale/timezone (CI
sets `-Duser.timezone=UTC`; device-zone tests set the zone explicitly).

FR-9 **No production change.** This ticket adds only test/fixture/fake sources.
Any required test seam already exists (injectable `Clock`, `CalendarRepository`
interface, `EventSlotter` purity) per AND-270/AND-271; if a seam is missing it is
filed back against the owning ticket, not patched here.

## 4. Technical Design

Test sources are placed alongside the modules they cover:

```
core-model/src/test/kotlin/com/testlogon/android/core/model/calendar/
    CalendarEventInvariantsTest.kt
core-network/src/test/kotlin/com/testlogon/android/core/network/calendar/
    CalendarMappersTest.kt
    CalendarApiContractTest.kt
feature-calendar/src/test/kotlin/com/testlogon/android/feature/calendar/
    EventSlotterWindowTest.kt
    EventSlotterTimezoneTest.kt      // critical: timezone matrix
    EventSlotterRecurrenceTest.kt
    EventSlotterLaneTest.kt
    CalendarViewModelTest.kt
    CalendarPagingSourceTest.kt
feature-calendar/src/androidTest/kotlin/com/testlogon/android/feature/calendar/
    CalendarScreenRenderTest.kt
    CalendarNavigationTest.kt
    CalendarStatesTest.kt
    CalendarAccessibilityTest.kt
core-testing/src/main/kotlin/com/testlogon/android/core/testing/calendar/
    FakeCalendarRepository.kt
    CalendarFixtures.kt              // JSON + domain builders
```

**Fixture strategy.** `CalendarFixtures` exposes both raw JSON strings (for
MockWebServer / mapper tests) and typed builders for domain objects (for slotter/
ViewModel/UI tests). A single canonical event set is shared so UI and unit tests
assert against the same data.

```kotlin
package com.testlogon.android.core.testing.calendar

object CalendarFixtures {
    const val EVENTS_NY_STANDUP_JSON: String          // 13:30Z, tz America/New_York
    // CORRECTED: server returns ONE event carrying recurrence_rule (freq=WEEKLY,
    // byday=[MO,WE,FR]); occurrences are expanded client-side, not pre-expanded.
    const val EVENTS_RECURRING_WEEKLY_JSON: String     // 1 event + WEEKLY MO/WE/FR rule
    const val EVENTS_ALL_DAY_JSON: String              // all_day_date set, spanning DST
    const val EVENTS_DETAIL_ERROR_JSON: String         // {"detail":"calendar_not_found"}
    // CORRECTED fields to real EventOut shape (event_id/name/start_utc/all_day_date).
    fun event(
        eventId: String = "evt_1", calendarId: String = "cal_main",
        name: String = "Standup",
        startUtc: Instant?, endUtc: Instant?, allDay: Boolean = false,
        allDayDate: LocalDate? = null,
        timezone: String = "America/New_York",
        recurrenceRule: RecurrenceRule? = null,
    ): CalendarEvent
    fun slotted(/* SlottedEvent builder mirroring AND-271 */): SlottedEvent
}

class FakeCalendarRepository(
    private val responses: ArrayDeque<ApiResult<CachedList<CalendarEvent>>>,
) : CalendarRepository {
    val recordedWindows = mutableListOf<Pair<DateWindow, ZoneId>>()
    override fun events(window: DateWindow, zone: ZoneId)
        : Flow<ApiResult<CachedList<CalendarEvent>>> = flow {
        recordedWindows += window to zone
        emit(responses.removeFirstOrNull() ?: ApiResult.Success(CachedList(emptyList(), isStale = false)))
    }
}
```

**Determinism harness.** A `FixedClockRule` (or inline `Clock.fixed`) and a JUnit
rule that overrides the coroutine `Dispatchers.Main` (`MainDispatcherRule` from
`core-testing`) are applied to every JVM suite. UI tests use a Hilt test module
binding `CalendarRepository` to `FakeCalendarRepository` and `Clock` to a fixed
clock.

```kotlin
private val FIXED_NOW: Instant = Instant.parse("2026-06-08T12:00:00Z")
private val FIXED_CLOCK: Clock = Clock.fixed(FIXED_NOW, ZoneOffset.UTC)
private val NY = ZoneId.of("America/New_York")
private val TOKYO = ZoneId.of("Asia/Tokyo")
```

## 5. API Contract

This ticket defines no new endpoint; it **asserts** the AND-270 contract. The
`CalendarApiContractTest` enqueues fixtures on `MockWebServer`, points the shared
Retrofit at the mock base URL, and verifies request and response handling.

Request asserted (idempotent GET). **CORRECTED** — real path is
`/ui/calendars/{calendar_id}/events` with `start_utc`/`end_utc`/`limit`/`cursor`
query params (no `tz`):

```
GET /ui/calendars/cal_main/events?start_utc=2026-06-01T00:00:00Z&end_utc=2026-07-01T00:00:00Z&limit=200
```

(Verified: OpenAPI `GET /ui/calendars/{calendar_id}/events` op
`list_events_ui_calendars__calendar_id__events_get`, params
`calendar_id,start_utc,end_utc,limit,cursor`; `src/api/endpoints/calendar.ts:
getEvents`, which sends only `{ cursor }` and relies on path-scoped calendar id.)

- `RecordedRequest.path` matches the path + encoded query params (the contract
  test asserts the `start_utc`/`end_utc` window and the `calendar_id` path
  segment; param ordering is not asserted since the web client emits only a
  subset).
- **Auth/CSRF (verified against `src/api/client.ts`):** the primary auth is an
  `Authorization: Bearer <accessToken>` header plus cookies sent with
  `credentials: include`; in addition, when a `ui_csrf` cookie is present the
  client sets `X-CSRF-Token` to that value. The contract test asserts the
  calendar call carries `X-CSRF-Token` when a `ui_csrf` cookie is present in the
  jar (negative test: absent when no cookie) but does **not** re-test the
  interceptor internals (owned by AND-012). A 401 on a previously-authenticated
  session triggers a single `POST /ui/session/refresh` + one retry; this
  behavior is owned by AND-012 and only smoke-checked at the boundary here.

Success response fixture. **CORRECTED to the real `EventsPageOut`/`EventOut`
shape** (verified against OpenAPI schemas `EventsPageOut`+`EventOut` and
`src/api/types.ts: EventsPage`/`CalendarEvent`). The page is
`{ events: EventOut[], next_cursor?: string }` (cursor pagination, **no `range`
object**). Each event uses snake_case fields: `event_id` (not `id`), `name` (not
`title`), `start_utc`/`end_utc` (both optional/nullable strings, not
`start`/`end`), a single `all_day_date` (not `startDate`/`endDate`), `timezone`
(IANA, the event's authoring zone), and structured `recurrence_rule` /
`exdates_utc` / `recurrence_overrides`. **There is no `color`, no
`recurrence_id`, and no `occurrence_start` field.**

```json
{
  "events": [
    {
      "event_id": "evt_01H...",
      "calendar_id": "cal_main",
      "name": "Standup",
      "description": "",
      "timezone": "America/New_York",
      "start_utc": "2026-06-08T13:30:00Z",
      "end_utc": "2026-06-08T14:00:00Z",
      "all_day": false,
      "attendees": [],
      "booking_enabled": false,
      "approval_required": false,
      "status": "confirmed",
      "recurrence_rule": { "freq": "WEEKLY", "interval": 1, "byday": ["MO","WE","FR"] },
      "exdates_utc": [],
      "created_at_utc": "2026-05-01T00:00:00Z"
    }
  ],
  "next_cursor": null
}
```

Mapping assertions: `start_utc`/`end_utc` → nullable `Instant` (absent → null,
handled by default); `timezone` preserved verbatim; `recurrence_rule` →
structured domain rule, `recurrence_overrides` → map keyed by occurrence-start;
`all_day:true` fixture (`all_day_date` populated, `start_utc`/`end_utc` null) →
`allDay=true` with the date populated and no zone shift. `event_id`/`name` map to
the domain id/title fields chosen by AND-270.

Error envelope assertions (FastAPI `detail`, three shapes). **Verified** against
`src/api/client.ts: normalizeErrorDetail`, which handles exactly these three
forms (plain string; array of `{msg}` items; object with a `code` field):

```json
{ "detail": "calendar_not_found" }
{ "detail": [ { "msg": "invalid range", "loc": ["query","start_utc"], "type": "value_error" } ] }
{ "detail": { "code": "rate_limited" } }
```

The array form is the FastAPI `422 HTTPValidationError` shape (verified: OpenAPI
`HTTPValidationError.detail` = array of `ValidationError{loc,msg,type}`); every
`/ui/calendars/{calendar_id}/events` response documents `422:HTTPValidationError`.
Each maps to `ApiResult.Failure` and, in the ViewModel, to the correct
`CalendarError` (`Server`/`Network`/`Auth`/`Unknown`). A `503` fixture maps to
`Server`; a `401` maps to `Auth` (the web client attempts one
`POST /ui/session/refresh` + retry — see §5); a simulated
`SocketTimeoutException` (MockWebServer `SocketPolicy.NO_RESPONSE` with a short
client read timeout) maps to `Network` (mirrors `ApiError(0, "Network error")`
in `client.ts`).

## 6. Data & State Management

- **Test data is the source of truth.** All assertions reference
  `CalendarFixtures`; no test fabricates ad-hoc JSON inline except where the test
  is specifically about a malformed/edge payload.
- **State assertions** use Turbine on `CalendarViewModel.uiState`:
  - first emission `Loading`;
  - on cache hit → `Content(isStale = true)` then `Content(isStale = false)`
    after refresh;
  - on failure with prior content → `Error(cause, cached = lastContent)`;
  - `setMode`/`focusOn`/`stepForward`/`stepBackward`/`goToToday` each produce the
    expected new `DateWindow` recorded in `FakeCalendarRepository.recordedWindows`.
- **Window math** is asserted directly via `EventSlotter.windowFor` (no ViewModel
  needed) and indirectly via recorded repository windows, confirming the ±1-day
  UTC widening then client re-clip described in AND-271 §6.
- **Paging:** `CalendarPagingSource.load(Refresh/Append/Prepend)` returns
  `LoadResult.Page` with expected `prevKey`/`nextKey` `LocalDate` anchors; a
  duplicated `(eventId, occurrenceStart)` across adjacent pages appears once.
- **No persistence under test here:** the Room cache itself is AND-270's
  responsibility; this suite asserts only that `CachedList.isStale` flows through
  to `CalendarUiState`.

## 7. Error Handling & Resilience

The suite verifies the feature's error contract rather than introducing new
handling:

- **Mapper robustness. CORRECTED — the event schema has no `visibility`/`rsvp`
  fields.** `EventOut` exposes `status` (free string), `category` (nullable
  string), and `recurrence_rule.freq` (enum `DAILY`/`WEEKLY`/`MONTHLY`); the only
  enum on the calendar surface is `CalendarShare.permission` (`read`/`write`).
  Tests therefore assert: unknown `recurrence_rule.freq` (e.g. `freq:"bar"`) and
  unknown `permission` strings map to the AND-270 fallback (`UNKNOWN`/`PENDING`)
  rather than throwing; `status`/`category` pass through as raw strings (no enum);
  absent optionals (`end_utc`, `start_utc`, `recurrence_rule`, `category`,
  `next_cursor`) use Kotlin defaults/nulls; a malformed timestamp surfaces as a
  mapping failure (not a crash) — asserted with `assertFailsWith`/
  `ApiResult.Failure`, never an uncaught exception. (Verified: OpenAPI `EventOut`,
  `RecurrenceRule`, `CalendarShare`; `src/api/types.ts: CalendarEvent`.)
- **Boundary safety (slotter):** `end <= start` clamped to a 1-minute block;
  events fully outside the post-conversion window dropped; a `DateTimeException`
  path (e.g., invalid zone id) does not crash and yields an empty/skipped slot.
- **Stale-while-error:** Error keeps last-good `Content`; the UI test asserts the
  banner + working Retry while content remains visible.
- **Empty vs error:** an empty 200 window renders the empty placeholder, never the
  error UI (explicit assertion).
- **Timeout/offline:** simulated via MockWebServer socket policy → `Network`
  error; `retry()` (re-enqueued success) recovers to `Content`.
- **Flaky dev host:** N/A to the tests themselves — the suite never contacts the
  live host; resilience of the live path is exercised only through simulated
  fixtures.

## 8. Security & Privacy

- **No new credential handling.** Cookie/CSRF behavior is asserted at the contract
  boundary only (header present/absent); secret values used in tests are dummy
  fixtures, never real sessions.
- **No real PII in fixtures.** Event titles/attendees in fixtures are synthetic
  (`"Standup"`, `"Sync"`); no production data is committed.
- **Cleartext:** MockWebServer serves over loopback; no test enables cleartext to
  the real dev host. The network-security config is not modified.
- **Log-privacy assertion:** a JVM test (or a log-capturing rule) asserts that
  `CalendarViewModel`/error logging emits `CalendarError` type + HTTP status only
  and **never** logs event titles or payload bodies (guards AND-271 §10).

## 9. Accessibility & i18n

- **Instrumented a11y assertions** (`CalendarAccessibilityTest`): every
  interactive node (view toggle, nav arrows, day cells, event blocks, overflow
  chip) exposes a non-empty `contentDescription`; event blocks announce title +
  localized start–end time + all-day/multi-day status; touch targets ≥ 48dp
  (`assertHeightIsAtLeast(48.dp)` / `assertWidthIsAtLeast(48.dp)`); month-cell and
  overflow custom click actions are present and invokable.
- **i18n determinism:** UI tests run under a fixed `Locale` (en-US) and assert
  semantics labels via string resources, not hardcoded literals; a focused test
  flips `Locale`/`WeekFields` to confirm `weekStart` changes the Month grid layout
  and that `EventSlotter.windowFor` honors the locale week start. An RTL-direction
  test (`LayoutDirection.Rtl`) asserts nav controls mirror without crashing.

## 10. Telemetry & Logging

- **Telemetry assertions:** with a `FakeAnalytics` (`core-testing`) bound, tests
  assert the AND-271 events fire with correct params: `calendar_view_shown{mode}`,
  `calendar_nav{direction,mode}`, `calendar_today_tapped`,
  `calendar_zone_override_applied`, `calendar_event_opened{has_recurrence}` (true
  for an expanded instance, false for a one-off), and
  `calendar_load_error{error_type}` on simulated failure.
- **Logging:** the §8 privacy assertion doubles as the logging test; no test
  asserts log *format* beyond the no-PII guarantee. The `calendar_perf` tag is
  observational and not test-gated.

## 11. Testing Strategy

This *is* the testing ticket; the strategy is the deliverable.

**JVM unit (`src/test/`, `runTest` + Turbine):**

- `CalendarMappersTest` — field mapping, all-day `LocalDate` population, tz
  preservation, enum fallback, optional defaults, malformed-timestamp failure.
- `EventSlotterWindowTest` — `windowFor` for Month (4/5/6 visible weeks), Week
  (7 days from `weekStart`), Agenda (focus ± 7); locale-driven `weekStart`.
- `EventSlotterTimezoneTest` (**critical, acceptance-bearing**):
  - `13:30Z` → 09:30 in `America/New_York`, 22:30 in `Asia/Tokyo`;
  - event crossing local midnight after conversion appears on both correct local
    days (`23:00Z` in `America/Los_Angeles` → previous local day);
  - DST forward (2026-03-08 US) and backward (2026-11-01 US) transition days slot
    correctly; a fixed-instant event has no duplicate/missing hour;
  - all-day event does not shift across `NY`/`Tokyo`/`UTC`.
- `EventSlotterRecurrenceTest` — a single WEEKLY `recurrence_rule`
  (`byday=[MO,WE,FR]`) expands (client-side, per the corrected model in FR-3) into
  three occurrences that each slot on their own day; `exdates_utc` drops an
  occurrence; a `recurrence_overrides` entry shifts/edits one occurrence; no
  collapse/duplication; `has_recurrence` derivation (`recurrence_rule != null`,
  per `CalendarView.tsx: isRecurring`) correct.
- `EventSlotterLaneTest` — overlapping events split lanes; back-to-back
  (touching) events do not overlap; ≥3-way overlap assigns distinct lanes.
- `CalendarViewModelTest` — Loading→Content→Error(cached); stale badge;
  `flatMapLatest` cancels superseded window (assert only latest window queried);
  `retry()` recovery; nav recomputes window.
- `CalendarPagingSourceTest` — refresh/append/prepend keys + de-dup.
- `CalendarEventInvariantsTest` (`core-model`) — domain construction defaults and
  all-day/`startDate` invariants.

**Instrumented (`src/androidTest/`, AndroidJUnit4 + Hilt + Compose):**

- `CalendarScreenRenderTest` — seeded events render in correct Month cell / Week
  block / Agenda row for fixed display zone, asserted via `onNodeWithContentDescription`
  / `assertExists`; **this is the literal source-ticket acceptance check.**
- `CalendarNavigationTest` — toggle persists across `recreate()`/process-death
  simulation; prev/next/swipe/Today re-query (verified via recorded windows).
- `CalendarStatesTest` — skeleton on load, stale badge on cache hit, error banner
  + working Retry preserving content, empty placeholder.
- `CalendarAccessibilityTest` — see §9.

**Tooling:** Turbine, `kotlinx-coroutines-test`, MockWebServer, Compose UI test,
Paging `AsyncPagingDataDiffer`, Hilt testing, `FakeAnalytics`. CI runs
`./gradlew :feature-calendar:testDebugUnitTest :core-network:testDebugUnitTest
:core-model:testDebugUnitTest` and the connected/instrumented suite on the build
server (AND-008/AND-050 harness).

## 12. Dependencies & Sequencing

- **Hard upstream:** **AND-271** (Calendar views) — provides `EventSlotter`,
  `CalendarViewModel`, `CalendarPagingSource`, and composables under test; and
  **AND-270** (Calendar API + DTOs) — provides `CalendarApi`, DTOs, mappers, Room
  cache. Both must be merged (or at least API-stable) before this suite can be
  green; the `FakeCalendarRepository` here can be authored in parallel.
- **Transitive:** AND-046 (MockWebServer harness + fixtures), AND-018
  (`ApiResult`), AND-010/AND-012/AND-011 (Retrofit/CSRF/cookie jar — asserted at
  boundary only), `core-testing` (`MainDispatcherRule`, `FakeAnalytics`).
- **Downstream (this blocks):** none directly; it is a quality gate. Other
  calendar tickets (AND-272 event detail, AND-273 Google integration, AND-274
  content calendar, AND-275 scheduler, AND-276 ICS/reminders) carry their own
  tests and are out of scope here.
- **Sequencing:** (1) author `CalendarFixtures` + `FakeCalendarRepository` in
  `core-testing`; (2) mapper + contract tests (`core-network`); (3) `EventSlotter`
  timezone/recurrence/lane/window unit tests; (4) `CalendarViewModel` + paging
  tests; (5) instrumented render/nav/states/a11y tests; (6) wire into CI tasks.

## 13. Risks & Open Questions

- **R1 (recurrence expansion) — RESOLVED by this review:** the backend does **not**
  return RRULE-expanded occurrences. `EventOut` carries a structured
  `recurrence_rule` + `exdates_utc` + `recurrence_overrides`, and the web client
  expands per event (`CalendarView.tsx: isRecurring` → `!!ev.recurrence_rule`).
  Recurrence-rendering tests therefore target the **client-side expander** that
  AND-271 owns. Residual risk: AND-271's exact expander component/API is not in
  this review's sources — confirm its name before writing the expansion tests.
  (Verified against OpenAPI `RecurrenceRule`/`EventOut`,
  `src/api/types.ts`, `src/pages/calendar/CalendarView.tsx`.)
- **R2 (tz field semantics) — partly resolved:** `EventOut.timezone` is the
  event's authoring/IANA zone (per `CalendarCreateIn.timezone` and `EventCreateIn`,
  which set the calendar/event zone). The display zone is a separate client
  concern: the web reference renders by converting `start_utc` through the
  **browser local zone** (`new Date(start_utc)`) and sends **no `tz` query param**.
  Tests encode per-event authoring zone + an explicitly-injected display `ZoneId`.
  **OQ:** AND-271's chosen default display zone (device zone vs a picker) is not
  verifiable from these sources.
- **R3 (DST data correctness):** assertions depend on the JDK/desugared tz
  database matching the dates used (2026-03-08, 2026-11-01). Pin via
  core-library-desugaring tzdb; if the desugared tzdb diverges from device tzdb,
  device tests may differ from JVM tests. Run the DST cases in **both** layers.
- **R4 (instrumented flakiness):** Compose/Paging async + recreation tests can
  flake; mitigate with idling synchronization and `runTest` for VM-level logic,
  reserving instrumented tests for genuine UI rendering.
- **R5 (CI host timezone):** if CI does not set `user.timezone=UTC`, device-zone
  tests could pass/fail by accident; every test that depends on the device zone
  sets it explicitly rather than relying on the host.
- **OQ:** is a display-zone *picker* in scope for M6 (AND-271 deferred it)? If it
  ships later, an additional `calendar_zone_override_applied` UI test is needed.

## 14. Acceptance Criteria

AC-1 **Suite passes** (the source-ticket bar): all calendar JVM unit and
instrumented tests are green in CI on `android-port`, repeatably across runs and
independent of the CI host locale/timezone.

AC-2 **Timezone matrix proven:** `13:30Z` slots at 09:30 `America/New_York` and
22:30 `Asia/Tokyo`; a midnight-crossing event appears on both correct local days;
DST forward and backward transition days slot correctly; all-day events do not
shift across zones — each by a passing assertion.

AC-3 **Recurrence proven:** a structured `recurrence_rule` (expanded client-side,
per FR-3) yields individual occurrences in correct slots with no collapse or
duplication; `exdates_utc` and `recurrence_overrides` are honored; instances
derive from the same parent `event_id`; `has_recurrence` telemetry
(`recurrence_rule != null`) distinguishes recurring events from one-offs.

AC-4 **Mapping/transport proven:** `CalendarApiContractTest` asserts the exact
request path/query and maps the success payload; all three FastAPI `detail`
shapes map to `ApiResult.Failure`/correct `CalendarError`; enum fallback and
optional defaults verified; no mapper throws on bad input.

AC-5 **ViewModel/paging proven:** Loading→Content→Error(cached), stale badge,
superseded-window cancellation, `retry()` recovery, and paging refresh/append/
prepend + de-duplication all asserted.

AC-6 **UI rendering proven:** seeded events appear in the correct Month cell /
Week block / Agenda row for a fixed display zone (semantics assertions); view
selection persists across recreation; navigation re-queries the correct window.

AC-7 **States proven:** skeleton on load, stale badge on cache hit, dismissible
error banner with working Retry preserving last-good content, empty placeholder
for empty windows.

AC-8 **A11y, i18n, privacy proven:** content descriptions present, 48dp targets
met, custom day-cell actions invokable; locale week-start and RTL behavior
asserted; no event PII appears in captured logs.

## 15. Definition of Done

- Test sources added under `core-model`, `core-network`, and `feature-calendar`
  (`src/test/` + `src/androidTest/`) plus `CalendarFixtures`/`FakeCalendarRepository`/
  `FakeAnalytics` wiring in `core-testing`; **no production code changed** (any
  defect found is filed against AND-270/AND-271).
- AC-1–AC-8 demonstrated; the timezone, DST, midnight-crossing, all-day, and
  recurrence cases are explicitly present and green at the unit layer, with the
  rendering acceptance present at the instrumented layer.
- All suites are hermetic and deterministic: fixed `Clock`, explicit `ZoneId`s,
  MockWebServer/fakes only, no live-host or wall-clock dependence; pass under
  `user.timezone=UTC` CI.
- Wired into CI Gradle tasks (`:feature-calendar:testDebugUnitTest`,
  `:core-network:testDebugUnitTest`, `:core-model:testDebugUnitTest`, and the
  connected/instrumented suite) on the build server; green on `android-port`
  with AGP 8.7.3 / Gradle 8.9 / JDK 17.
- Lint and detekt clean on test sources; fixtures contain no real PII or real
  session secrets.
- Code reviewed and merged; spec status moved from `draft` to `accepted` once
  AC-1–AC-8 are demonstrated green in CI.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source.

1. **Calendar events are fetched at `GET /ui/calendars/{calendar_id}/events`.**
   VERDICT: Corrected (spec said `GET /ui/calendar/events`). SOURCE: OpenAPI
   `GET /ui/calendars/{calendar_id}/events` (op
   `list_events_ui_calendars__calendar_id__events_get`);
   `src/api/endpoints/calendar.ts: getEvents`.
2. **Query params are `start_utc`/`end_utc`/`limit`/`cursor`; there is no `tz`
   param.** VERDICT: Corrected (spec said `start`/`end`/`tz`). SOURCE: OpenAPI
   index params `calendar_id,start_utc,end_utc,limit,cursor`;
   `src/api/endpoints/calendar.ts: getEvents` (sends only `{ cursor }`),
   `getOpenings` (uses `start_utc`/`end_utc`).
3. **Pagination is cursor-based; the page is `{ events, next_cursor }` — there is
   no `range` object.** VERDICT: Corrected. SOURCE: OpenAPI schema `EventsPageOut`
   (`events`, `next_cursor`); `src/api/types.ts: EventsPage`.
4. **Event field names are `event_id`, `name`, `start_utc`, `end_utc`,
   `all_day`, `all_day_date`, `timezone`, `description`, `attendees`, `status`,
   `category`, `recurrence_rule`, `exdates_utc`, `recurrence_overrides`,
   `created_at_utc` — NOT `id`/`title`/`start`/`end`/`startDate`/`endDate`.**
   VERDICT: Corrected. SOURCE: OpenAPI schema `EventOut`;
   `src/api/types.ts: CalendarEvent`.
5. **There is no `color` field on events.** VERDICT: Corrected (spec fixture had
   `"color":"blue"`). SOURCE: OpenAPI `EventOut` (no color property);
   `src/api/types.ts: CalendarEvent`.
6. **Recurrence is a structured `recurrence_rule` object
   (`freq`∈{DAILY,WEEKLY,MONTHLY}, `interval`, `until_utc`, `count`, `byday`,
   `bymonthday`, `bysetpos`), not a verbatim `rrule` string and not camelCase
   `byDay`/`exDates`.** VERDICT: Corrected. SOURCE: OpenAPI schema
   `RecurrenceRule`; `src/api/types.ts: RecurrenceRule`.
7. **The server does NOT pre-expand RRULEs; there is no `recurrence_id` or
   `occurrence_start` field. One event per series carries the rule +
   `exdates_utc` + `recurrence_overrides` (map keyed by occurrence-start);
   expansion is client-side.** VERDICT: Corrected. SOURCE: OpenAPI `EventOut`;
   `src/pages/calendar/CalendarView.tsx: isRecurring` (`!!ev.recurrence_rule`),
   `isOverridden` (keys of `recurrence_overrides`).
8. **`has_recurrence` is derived as `recurrence_rule != null`.** VERDICT:
   Verified. SOURCE: `src/pages/calendar/CalendarView.tsx: isRecurring`.
9. **`timezone` is the event's authoring IANA zone; display conversion is a
   separate client concern.** VERDICT: Verified (server side) / Unverified-
   assumption (Android display-zone default). SOURCE: OpenAPI
   `EventOut.timezone` + `CalendarCreateIn`/`EventCreateIn.timezone`;
   `src/pages/calendar/CalendarView.tsx` converts via browser-local `new Date()`.
10. **All-day events use a single `all_day_date` (date-only) with
    `start_utc`/`end_utc` null — not separate `startDate`/`endDate`.** VERDICT:
    Corrected. SOURCE: OpenAPI `EventOut.all_day`/`all_day_date`;
    `src/pages/calendar/CalendarView.tsx: eventOnDay` (matches `all_day_date`).
11. **CSRF: client sends `X-CSRF-Token` from the `ui_csrf` cookie when present.**
    VERDICT: Verified. SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` →
    `headers.set("X-CSRF-Token", csrf)`).
12. **Primary auth is `Authorization: Bearer <accessToken>` + cookies
    (`credentials: include`), in addition to CSRF.** VERDICT: Verified
    (clarifies spec, which mentioned only cookie/CSRF). SOURCE:
    `src/api/client.ts` (Authorization header + `credentials: "include"`).
13. **A 401 on an authenticated session triggers one
    `POST /ui/session/refresh` + a single retry.** VERDICT: Verified. SOURCE:
    `src/api/client.ts: refreshSession` and the 401 branch.
14. **FastAPI error `detail` has three handled shapes: string; array of
    `{msg,loc,type}` (=422 `HTTPValidationError`); object with a `code` field.**
    VERDICT: Verified. SOURCE: `src/api/client.ts: normalizeErrorDetail`; OpenAPI
    schemas `HTTPValidationError`/`ValidationError`; every events response
    documents `422:HTTPValidationError`.
15. **A transport/offline failure surfaces as a network error
    (`ApiError(0,"Network error")` in the web client).** VERDICT: Verified.
    SOURCE: `src/api/client.ts` (catch around `fetch`).
16. **Occurrence override/exclude endpoints exist
    (`POST …/events/{event_id}/occurrences/{occurrence_start}/override` and
    `/exclude`, `DELETE …/occurrences/{occurrence_start}`).** VERDICT: Verified
    (supports the override/exdate test model). SOURCE: OpenAPI index lines for
    `override_event_occurrence…`, `exclude_event_occurrence…`,
    `clear_event_occurrence_exception…`; `src/api/endpoints/calendar.ts:
    overrideOccurrence`/`excludeOccurrence`/`clearOccurrenceOverride`.
17. **Android test framework choices (Robolectric/JVM, MockWebServer, Turbine,
    Compose UI test, Paging `AsyncPagingDataDiffer`, Hilt testing, fixed
    `Clock`/`ZoneId`, core-library desugaring tzdb).** VERDICT:
    Unverified-assumption (project-internal tooling, not in the API/web sources)
    — but each is a standard AndroidX/library API (framework refs:
    https://developer.android.com/jetpack/compose/testing ;
    https://developer.android.com/topic/libraries/architecture/paging/test ;
    https://developer.android.com/studio/write/java8-support-table for
    core-library desugaring tzdb).
18. **AND-271 internals under test (`EventSlotter`, `CalendarViewModel`,
    `CalendarPagingSource`, `windowFor`, ±1-day UTC window widening, telemetry
    event names, `CalendarError` taxonomy).** VERDICT: Unverified-assumption —
    AND-271/AND-270 source/spec are not provided to this review; these are
    consumed as given by the upstream tickets.

### Corrections made

- §FR-1, §5: endpoint path `GET /ui/calendar/events` → `GET
  /ui/calendars/{calendar_id}/events`; query params `start/end/tz` →
  `start_utc/end_utc/limit/cursor` (no `tz`).
- §5: success fixture rewritten to the real `EventsPageOut`/`EventOut` shape
  (`event_id`/`name`/`start_utc`/`end_utc`/`all_day_date`, structured
  `recurrence_rule`, `next_cursor`); removed nonexistent
  `color`/`recurrence_id`/`occurrence_start` and the fake `range` object.
- §FR-3, §Overview, §11, §AC-3, §R1: recurrence model corrected from
  "server-side RRULE-expanded occurrences with `occurrence_start`" to "structured
  `recurrence_rule` + `exdates_utc` + `recurrence_overrides`, expanded
  client-side"; `rrule`/`byDay`/`exDates` corrected to
  `recurrence_rule`/`byday`/`exdates_utc`.
- §7: removed nonexistent `visibility`/`rsvp` enum-fallback claims; scoped enum
  fallback to `recurrence_rule.freq` and `CalendarShare.permission`; `status`/
  `category` clarified as raw strings.
- §5: clarified auth = Bearer token + cookies + `X-CSRF-Token`; added the
  401→refresh→retry behavior; annotated the three `detail` shapes as verified and
  added the 401→`Auth` mapping.
- §4: fixture builder signature/consts updated to real field names; recurring
  fixture changed from "3 expanded instances" to "1 event + WEEKLY rule".

### Open assumptions

- **Display-zone default on Android** (device zone vs. an in-app picker) — not
  determinable from the API/web sources; the web uses browser-local. Tests inject
  an explicit display `ZoneId`. (Ties to §R2/§13 OQ.)
- **AND-271/AND-270 component surface** (`EventSlotter`/`CalendarViewModel`/
  `CalendarPagingSource` APIs, the client-side recurrence expander, window-widening
  math, telemetry event names, `CalendarError` enum) — owned upstream, not in this
  review's sources; consumed as given.
- **`±1-day UTC window widening then client re-clip`** (§6) — an AND-271 design
  claim, not verifiable here.
- **Test tooling/versions** (Kotlin 2.0.21, AGP 8.7.3, Gradle 8.9, OkHttp 4.12,
  Moshi 1.15, desugared tzdb DST data for 2026-03-08/2026-11-01) — build-config
  assumptions, not in the API/web sources; DST dates should be re-confirmed
  against the pinned tzdb at implementation time (§R3).

## 17. Test Plan

IDs `TC-AND-277-NN`. "Traces" link to §14 Acceptance Criteria. Device targets:
JVM = local Robolectric/unit; **test35** = headless API-35 emulator;
**A15** = physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64). Most cases are
hermetic JVM/MockWebServer; instrumented cases run on **test35**, with the
arm64/API-34 differential case pinned to **A15**.

- **TC-AND-277-01 — Contract: events request shape.** Type: contract/MockWebServer
  (JVM). Target: `CalendarApiContractTest`. Preconditions: MockWebServer enqueues
  `EVENTS_NY_STANDUP_JSON` (200). Steps: call the production `CalendarApi` for
  `cal_main` over window 2026-06-01..2026-07-01. Expected: `RecordedRequest`
  method = GET, path = `/ui/calendars/cal_main/events`, query contains
  `start_utc`/`end_utc` (and `limit`/`cursor` when paging) and **no `tz`**.
  Traces: AC-4.
- **TC-AND-277-02 — Contract/mapper: success payload → domain.** Type:
  contract/MockWebServer (JVM). Target: `CalendarApiContractTest` +
  `CalendarMappersTest`. Preconditions: 200 with the §5 `EventsPageOut` fixture.
  Steps: fetch + map. Expected: `event_id`/`name`/`start_utc`/`end_utc`→Instant,
  `timezone` verbatim, structured `recurrence_rule` mapped; `next_cursor` honored;
  no `range`/`color`/`occurrence_start` referenced. Traces: AC-4.
- **TC-AND-277-03 — Mapper robustness: enums, optionals, malformed.** Type: unit
  (JVM). Target: `CalendarMappersTest`. Preconditions: fixtures with unknown
  `recurrence_rule.freq`/`permission`, absent `end_utc`/`recurrence_rule`/
  `category`/`next_cursor`, and a malformed timestamp. Steps: map each. Expected:
  unknown enums → `UNKNOWN`/`PENDING` (no throw); absent optionals → Kotlin
  defaults/null; malformed timestamp → `ApiResult.Failure` via `assertFailsWith`,
  never an uncaught exception. Traces: AC-4.
- **TC-AND-277-04 — Contract: error `detail` shapes → CalendarError.** Type:
  contract/MockWebServer (JVM). Target: `CalendarApiContractTest`. Preconditions:
  enqueue `{"detail":"calendar_not_found"}` (404), a 422 array-of-`{msg,loc,type}`,
  `{"detail":{"code":"rate_limited"}}` (429), and a 503. Steps: fetch each.
  Expected: all → `ApiResult.Failure`; ViewModel maps to `Server`/`Unknown`/
  `Server` appropriately; 503 → `Server`. Traces: AC-4.
- **TC-AND-277-05 — Auth/CSRF header at the boundary.** Type:
  contract/MockWebServer (JVM). Target: `CalendarApiContractTest`. Preconditions:
  (a) jar holds a `ui_csrf` cookie; (b) jar empty. Steps: issue the events GET in
  each state. Expected: (a) request carries `X-CSRF-Token` = cookie value (and
  `Authorization: Bearer …` when a session token is set); (b) no `X-CSRF-Token`.
  Security check: no real session secret in fixtures. Traces: AC-4, AC-8.
- **TC-AND-277-06 — Timezone slotting matrix.** Type: unit (JVM, **critical**).
  Target: `EventSlotterTimezoneTest`. Preconditions: fixed `Clock`; display zones
  NY/Tokyo/UTC. Steps: slot a `13:30Z` event in each zone; slot a `23:00Z` event
  in `America/Los_Angeles`; slot events on 2026-03-08 (DST forward) and
  2026-11-01 (DST backward). Expected: 09:30 NY, 22:30 Tokyo; LA event lands on
  the previous local day; DST days have no duplicate/missing hour. Traces: AC-2.
- **TC-AND-277-07 — All-day non-shift.** Type: unit (JVM). Target:
  `EventSlotterTimezoneTest`. Preconditions: `all_day=true`, `all_day_date` set,
  `start_utc`/`end_utc` null. Steps: slot in NY/Tokyo/UTC. Expected: same calendar
  day in all zones; no time-of-day rendered. Traces: AC-2.
- **TC-AND-277-08 — Recurrence expansion (client-side).** Type: unit (JVM).
  Target: `EventSlotterRecurrenceTest`. Preconditions: one event,
  `recurrence_rule{freq:WEEKLY,byday:[MO,WE,FR]}` within a one-week window.
  Steps: expand + slot. Expected: 3 occurrences on Mon/Wed/Fri, no
  collapse/duplication; an `exdates_utc` entry removes one occurrence; a
  `recurrence_overrides` entry shifts/edits one; `has_recurrence` = true for
  instances, false for a one-off. Traces: AC-3.
- **TC-AND-277-09 — ViewModel state machine + retry.** Type: unit (JVM, Turbine).
  Target: `CalendarViewModelTest`. Preconditions: `FakeCalendarRepository` queued
  with cache-hit then refresh, then a failure-with-prior-content, then a
  retry-success. Steps: collect `uiState`. Expected:
  Loading→Content(stale=true)→Content(stale=false); failure →
  Error(cached=lastContent); `flatMapLatest` cancels a superseded window (only the
  latest window recorded); `retry()` recovers to Content. Traces: AC-5, AC-7.
- **TC-AND-277-10 — Paging keys + de-duplication.** Type: unit (JVM). Target:
  `CalendarPagingSourceTest`. Preconditions: fixtures with `next_cursor` across two
  pages sharing one duplicate `(event_id, occurrenceStart)`. Steps: `load`
  Refresh/Append/Prepend. Expected: `LoadResult.Page` with correct
  `prevKey`/`nextKey`; the duplicate appears once. Traces: AC-5.
- **TC-AND-277-11 — Offline/timeout → Network then recover.** Type:
  contract/MockWebServer (JVM). Target: `CalendarViewModelTest` +
  `CalendarApiContractTest`. Preconditions: `SocketPolicy.NO_RESPONSE` + short read
  timeout, then a queued success. Steps: load (times out), then `retry()`.
  Expected: first load → `Network` error preserving any prior content; retry →
  Content. (Hermetic simulation of the flaky dev host; the live host is never
  contacted.) Traces: AC-5, AC-7.
- **TC-AND-277-12 — UI render in correct slot (Month/Week/Agenda).** Type:
  Compose-UI / instrumented (**test35**). Target: `CalendarScreenRenderTest`.
  Preconditions: Hilt binds `FakeCalendarRepository` (seeded canonical events) +
  fixed `Clock`, fixed display zone, `Locale.US`. Steps: render each view. Expected:
  the standup renders in the correct Month cell / Week block / Agenda row, asserted
  via `onNodeWithContentDescription`/`assertExists`. (Literal source-ticket
  acceptance.) Traces: AC-6.
- **TC-AND-277-13 — Navigation persistence + re-query.** Type: instrumented
  (**test35**). Target: `CalendarNavigationTest`. Preconditions: as TC-12. Steps:
  toggle view, `recreate()` the activity, tap prev/next/Today. Expected: selected
  view survives recreation; each nav records the expected new `DateWindow` in
  `FakeCalendarRepository.recordedWindows`. Traces: AC-6.
- **TC-AND-277-14 — States: skeleton / stale / error+retry / empty.** Type:
  instrumented (**test35**). Target: `CalendarStatesTest`. Preconditions: fakes
  queued for each state. Steps: drive load→cache-hit→failure→empty. Expected:
  skeleton on load; stale badge on cache hit; dismissible error banner with a
  working Retry that preserves last-good content; empty placeholder (never the
  error UI) for an empty 200 window. Traces: AC-7.
- **TC-AND-277-15 — Accessibility, i18n, RTL.** Type: instrumented/Compose-UI
  (**test35**). Target: `CalendarAccessibilityTest`. Preconditions: `Locale.US`,
  then a flipped locale/`WeekFields` and `LayoutDirection.Rtl`. Steps: inspect
  semantics. Expected: every interactive node has a non-empty
  `contentDescription`; event blocks announce title + localized start–end +
  all-day/multi-day; touch targets ≥48dp; custom day-cell/overflow actions present
  and invokable; week-start changes the Month grid; RTL mirrors without crashing.
  Traces: AC-8.
- **TC-AND-277-16 — Log-privacy (no PII).** Type: unit (JVM, log-capturing rule).
  Target: `CalendarViewModelTest`. Preconditions: a logging capture rule; a load
  failure. Steps: trigger error logging. Expected: logs contain only
  `CalendarError` type + HTTP status; **no** event titles or payload bodies.
  Security check. Traces: AC-8.
- **TC-AND-277-17 — DST + ABI/API-34 differential on real hardware.** Type:
  instrumented/e2e (**A15 — MUST run on the physical device**). Target:
  `EventSlotterTimezoneTest` (instrumented variant) + render check. Preconditions:
  device set to a fixed zone; DST fixtures (2026-03-08/2026-11-01). Steps: run the
  DST slotting + render assertions on arm64/API-34. Expected: results match the
  JVM/`test35` (API-35) layer; the desugared tzdb on the device produces identical
  DST placement. Rationale: catches arm64-vs-x86 ABI and API-34-vs-35 / device-tzdb
  divergence (§R3) that emulator-only runs would miss. Traces: AC-1, AC-2.

### Coverage matrix

| AC (§14) | Test case(s) |
|----------|--------------|
| AC-1 Suite passes / deterministic | all; explicitly TC-01..17, hardware: TC-17 |
| AC-2 Timezone matrix (incl. DST, midnight-cross, all-day) | TC-06, TC-07, TC-17 |
| AC-3 Recurrence (rule expand, exdates, overrides, has_recurrence) | TC-08 |
| AC-4 Mapping/transport (path/query, payload, error shapes, enums) | TC-01, TC-02, TC-03, TC-04, TC-05 |
| AC-5 ViewModel/paging (states, cancellation, retry, paging+dedup) | TC-09, TC-10, TC-11 |
| AC-6 UI rendering (Month/Week/Agenda, persistence, re-query) | TC-12, TC-13 |
| AC-7 States (skeleton/stale/error+retry/empty) | TC-09, TC-11, TC-14 |
| AC-8 A11y/i18n/privacy (CSRF, descriptions, 48dp, RTL, no-PII) | TC-05, TC-15, TC-16 |
