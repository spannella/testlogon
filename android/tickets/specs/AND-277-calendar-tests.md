---
id: AND-277
title: Calendar tests
milestone: M6
epic: E37
priority: P2
size: M
status: draft
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
(RRULE-expanded occurrences rendered in correct slots, parent/instance linkage,
exception dates) cannot silently break. Tests are **hermetic and deterministic**:
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
asserting (a) the request path/query (`GET /ui/calendar/events?start=…&end=…&tz=…`),
(b) DTO→domain mapping for every field, and (c) FastAPI `detail` error mapping to
`ApiResult.Failure`.

FR-2 **Mapper unit coverage (AND-270).** Pure `CalendarMappers` tests cover
timestamp parsing to `Instant`, all-day `LocalDate` population, IANA `timezone`
preservation, unknown-enum → `UNKNOWN`/`PENDING` fallback (never throws), and
absent-optional tolerance via defaults.

FR-3 **Recurrence coverage.** Tests assert `RecurrenceDto.toDomain()` maps
`rrule` verbatim, `freq`/`interval`/`until`/`count`/`byDay`/`exDates`; that
expanded instances carry `recurringEventId`/`recurrence_id`; and that the UI
renders **each expanded occurrence** in its own slot (the feature does not
re-expand RRULEs — verify it does not collapse/duplicate occurrences).

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
    const val EVENTS_RECURRING_WEEKLY_JSON: String     // 3 expanded MO/WE/FR instances
    const val EVENTS_ALL_DAY_JSON: String              // date-only, spanning DST
    const val EVENTS_DETAIL_ERROR_JSON: String         // {"detail":"not_found"}
    fun event(
        id: String = "evt_1", calendarId: String = "cal_main",
        start: Instant, end: Instant?, allDay: Boolean = false,
        timezone: String? = null, recurringEventId: String? = null,
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

Request asserted (idempotent GET):

```
GET /ui/calendar/events?start=2026-06-01T00:00:00Z&end=2026-07-01T00:00:00Z&tz=America/New_York
```

- `RecordedRequest.path` matches the path + encoded query params in order.
- Cookie/CSRF headers are injected globally (AND-011/AND-012); the contract test
  asserts the calendar call carries `X-CSRF-Token` when a `ui_csrf` cookie is
  present in the jar (negative test: absent when no session) but does **not**
  re-test the interceptor internals (owned by AND-012).

Success response fixture (occurrences RRULE-expanded server-side):

```json
{
  "events": [
    {
      "id": "evt_01H...",
      "calendar_id": "cal_main",
      "title": "Standup",
      "start": "2026-06-08T13:30:00Z",
      "end": "2026-06-08T14:00:00Z",
      "timezone": "America/New_York",
      "all_day": false,
      "color": "blue",
      "recurrence_id": "rec_abc",
      "occurrence_start": "2026-06-08T13:30:00Z"
    }
  ],
  "range": { "start": "2026-06-01T00:00:00Z", "end": "2026-07-01T00:00:00Z" }
}
```

Mapping assertions: `start`/`end` → `Instant`; `timezone` preserved verbatim;
`recurrence_id`/`occurrence_start` → `recurringEventId` + occurrence instant;
`all_day:true` fixture → `allDay=true` with populated `startDate`/`endDate` and no
zone shift.

Error envelope assertions (FastAPI `detail`, three shapes):

```json
{ "detail": "calendar_not_found" }
{ "detail": [ { "msg": "invalid range" } ] }
{ "detail": { "code": "rate_limited" } }
```

Each maps to `ApiResult.Failure` and, in the ViewModel, to the correct
`CalendarError` (`Server`/`Network`/`Auth`/`Unknown`). A `503` fixture maps to
`Server`; a simulated `SocketTimeoutException` (MockWebServer
`SocketPolicy.NO_RESPONSE` with a short client read timeout) maps to `Network`.

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

- **Mapper robustness:** unknown enum strings (`visibility:"weird"`,
  `permission:"x"`, `rsvp:"foo"`, `freq:"bar"`) map to `UNKNOWN`/`PENDING`; absent
  optionals (no `end`, no `timezone`, no `recurrence`) use Kotlin defaults; a
  malformed timestamp surfaces as a mapping failure (not a crash) — asserted with
  `assertFailsWith`/`ApiResult.Failure`, never an uncaught exception.
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
- `EventSlotterRecurrenceTest` — three expanded weekly instances each slot on
  their own day; each carries `recurringEventId`; no collapse/duplication;
  `has_recurrence` derivation correct.
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

- **R1 (server-side expansion assumption):** the recurrence tests assume AND-270
  returns RRULE-expanded occurrences with `occurrence_start` (AND-271 §5/R1). If
  expansion is actually client-side, recurrence-rendering tests must move to
  whichever component expands. **OQ:** confirm against `/openapi.json` and
  `calendar.ts` before writing recurrence fixtures.
- **R2 (tz field semantics):** whether `timezone` is the event's authoring zone or
  the user's display zone affects expected slot values. Tests encode the AND-271
  assumption (per-event authoring zone + separate display zone); if wrong, the
  timezone matrix expected values change. **OQ:** verify with web reference.
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

AC-3 **Recurrence proven:** RRULE-expanded occurrences render as individual
occurrences in correct slots with no collapse or duplication; each instance
carries `recurringEventId`; `has_recurrence` telemetry distinguishes instances
from one-offs.

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
