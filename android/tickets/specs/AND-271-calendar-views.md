---
id: AND-271
title: Calendar views
milestone: M6
epic: E37
priority: P1
size: L
status: draft
depends_on: [AND-270]
blocks: [AND-272]
---

# AND-271 — Calendar views

## 1. Overview & Goal

Deliver the `feature-calendar` presentation layer for the TestLogon native Android app: three switchable calendar views — **Month**, **Week**, and **Agenda** — rendering events sourced from the repository introduced in AND-270 (`Calendar API + DTOs`). The screen must place every event in the correct day/time slot for the user's effective timezone, handle all-day and multi-day events, support fast navigation across date ranges, and degrade gracefully against the unreliable plaintext dev backend (offline/stale states, bounded retries on idempotent reads).

This ticket owns the UI, the view-state machine, the date-window paging logic, and timezone-correct slotting. It explicitly does **not** own DTO/Retrofit definitions or repository data access (AND-270), nor the event detail screen and public App Link (AND-272). The acceptance bar is concrete: events render in the correct slots and timezones across Month/Week/Agenda, verified by instrumented and unit tests.

## 2. Context & References

- **Module:** `feature-calendar` (new), layered `app -> feature-calendar -> core-* `. Consumes `core-model`, `core-ui`, `core-data`, `core-network`, `core-testing`.
- **Package root:** `com.testlogon.android.feature.calendar`.
- **Upstream dependency (AND-270):** provides `CalendarRepository`, `CalendarEvent`/`RecurrenceRule` domain models, and Moshi DTO mapping. This ticket consumes that API surface; see assumed contract in §5.
- **Downstream (AND-272):** navigates from a list/grid item to event detail and registers the public `/event/{calendarId}/{eventId}` App Link. This ticket exposes the navigation callback only.
- **Web reference:** `frontend/src/api/endpoints/calendar.ts` (endpoint shapes) and `frontend/src/api/types.ts` (event/recurrence types). Match field names and timezone semantics.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. Cookie + `ui_csrf`/`X-CSRF-Token` auth; on 401 the network layer refreshes once via `POST /ui/session/refresh` then retries (handled in `core-network`, not here).
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose (single-Activity), Hilt (KSP), Coroutines/Flow, `java.time` with desugaring, Paging 3 (for Agenda). minSdk 24, compileSdk/targetSdk 35.

## 3. Functional Requirements

FR-1 **Three views.** A segmented control toggles Month, Week, Agenda. The selected view persists across configuration changes (saved in `SavedStateHandle`) and across process death.

FR-2 **Month view.** A 6-row × 7-column grid for the focused month. Each day cell shows up to 3 event chips plus a "+N more" overflow indicator; tapping the cell or overflow opens the Agenda view scoped to that day. Days outside the focused month are dimmed. The current day is highlighted.

FR-3 **Week view.** A horizontally fixed 7-day header with a vertical 24-hour time grid (00:00–24:00). Timed events render as positioned blocks proportional to start/duration; overlapping events split the column width. All-day and multi-day events render in a pinned all-day lane above the time grid.

FR-4 **Agenda view.** A vertically scrolling, date-grouped list (sticky date headers) backed by Paging 3, loading forward and backward from the focus date. Empty days are collapsed; an "empty range" placeholder shows when no events exist in the loaded window.

FR-5 **Navigation.** Previous/next controls and horizontal swipe move the focus window by one month/week/day per the active view. A "Today" action returns the focus to the current date. Changing the focus date re-queries the repository window (§6).

FR-6 **Timezone handling.** Each event carries an IANA timezone (from AND-270 DTO). The view resolves an **effective display zone** (precedence: explicit user preference in DataStore → device default `ZoneId.systemDefault()`). All slotting math converts event instants to the display zone. All-day events are date-anchored (no zone shift). A banner appears when the display zone differs from the device zone.

FR-7 **Recurrence.** Recurring events expanded by AND-270 within the queried window are rendered as individual occurrences; this ticket does not re-expand RRULEs, but must render each expanded occurrence in its correct slot.

FR-8 **Selection callback.** Tapping a timed block, month chip, or agenda row invokes `onEventClick(calendarId: String, eventId: String, occurrenceStart: Instant)`. Routing is owned by AND-272.

FR-9 **Loading/empty/error states.** Each view shows skeletons while loading, a stale badge when serving cached data, and an inline retry affordance on error (§7).

## 4. Technical Design

Module `feature-calendar` with public entry point `CalendarRoute` (Composable) and `CalendarViewModel` (Hilt). Layering: Composables observe a single `StateFlow<CalendarUiState>`; the ViewModel orchestrates the repository and timezone resolution; pure slotting logic lives in testable kotlin functions with no Android deps.

```kotlin
package com.testlogon.android.feature.calendar

enum class CalendarViewMode { MONTH, WEEK, AGENDA }

sealed interface CalendarUiState {
    data object Loading : CalendarUiState
    data class Content(
        val mode: CalendarViewMode,
        val focusDate: LocalDate,
        val displayZone: ZoneId,
        val deviceZone: ZoneId,
        val window: DateWindow,
        val days: List<DaySlots>,          // month/agenda
        val timeGrid: WeekGrid?,           // week only
        val isStale: Boolean,
        val zoneMismatch: Boolean,
    ) : CalendarUiState
    data class Error(val cause: CalendarError, val cached: Content?) : CalendarUiState
}

data class DateWindow(val start: LocalDate, val endExclusive: LocalDate)
data class DaySlots(val date: LocalDate, val events: List<SlottedEvent>, val overflowCount: Int)
data class WeekGrid(val days: List<LocalDate>, val allDayLane: List<SlottedEvent>, val columns: List<DayColumn>)
data class DayColumn(val date: LocalDate, val blocks: List<TimedBlock>)
data class TimedBlock(
    val event: SlottedEvent,
    val startMinuteOfDay: Int, val endMinuteOfDay: Int,
    val laneIndex: Int, val laneCount: Int,   // overlap split
)
data class SlottedEvent(
    val calendarId: String, val eventId: String, val title: String,
    val start: Instant, val end: Instant, val isAllDay: Boolean, val colorKey: String,
)
```

```kotlin
@HiltViewModel
class CalendarViewModel @Inject constructor(
    private val repo: CalendarRepository,           // from AND-270
    private val zonePrefs: CalendarZonePreferences,  // DataStore-backed
    private val slotter: EventSlotter,
    private val savedState: SavedStateHandle,
    private val clock: Clock,                         // injectable for tests
) : ViewModel() {
    val uiState: StateFlow<CalendarUiState>
    fun setMode(mode: CalendarViewMode)
    fun focusOn(date: LocalDate)
    fun stepForward(); fun stepBackward(); fun goToToday()
    fun retry()
}
```

Pure slotting utilities (unit-tested, no Android):

```kotlin
object EventSlotter {
    fun windowFor(mode: CalendarViewMode, focus: LocalDate, weekStart: DayOfWeek): DateWindow
    fun toDaySlots(events: List<SlottedEvent>, window: DateWindow, zone: ZoneId, maxChips: Int): List<DaySlots>
    fun toWeekGrid(events: List<SlottedEvent>, weekStart: LocalDate, zone: ZoneId): WeekGrid
    fun assignLanes(timed: List<TimedBlock>): List<TimedBlock>   // greedy interval-graph coloring
}
```

Composables: `CalendarRoute`, `CalendarScreen`, `MonthGrid`, `WeekTimeGrid`, `AgendaList` (Paging 3 `LazyColumn` with `collectAsLazyPagingItems()`), `CalendarTopBar` (segmented control + nav). `java.time` via core library desugaring (required for minSdk 24); add `coreLibraryDesugaring` in `feature-calendar/build.gradle.kts`.

Month grid uses 6 weeks × 7 days padded from `weekStart` (DayOfWeek resolved from locale via `WeekFields.of(Locale.getDefault())`). Week view height = 24h × density-scaled hour height in a vertically scrollable container; blocks positioned with `Modifier.offset`/`layout`. Agenda uses Paging 3 with a `CalendarPagingSource` keyed by `LocalDate` page anchors, page size = 14 days, prefetch distance 1.

## 5. API Contract

This ticket performs **no direct HTTP**. All network access is owned by **AND-270**, consumed through `CalendarRepository`. The assumed (AND-270) repository surface and the underlying endpoint are documented here for integration only:

```kotlin
interface CalendarRepository {
    // Idempotent GET: bounded backoff retry + cache, per project policy.
    fun events(window: DateWindow, zone: ZoneId): Flow<ApiResult<CachedList<CalendarEvent>>>
}
```

Underlying endpoint (reference, owned by AND-270; confirm against `/openapi.json` and `frontend/src/api/endpoints/calendar.ts`):

```
GET /ui/calendar/events?start=2026-06-01T00:00:00Z&end=2026-07-01T00:00:00Z&tz=America/New_York
```

Expected response shape (occurrences already RRULE-expanded server-side):

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

Error envelope: FastAPI `detail` mapped by `core-network` to `ApiResult.Failure` (`detail` may be `string | [{msg}] | {code,...}`). 401 triggers one `POST /ui/session/refresh` + retry inside `core-network`. This ticket maps `ApiResult.Failure` → `CalendarError` for the UI.

## 6. Data & State Management

- **Single source of truth:** `CalendarViewModel.uiState: StateFlow<CalendarUiState>`, started `WhileSubscribed(5_000)`.
- **Window derivation:** on `mode`/`focusDate`/`zone` change, compute `DateWindow` via `EventSlotter.windowFor` (Month = full weeks covering the month; Week = 7 days from `weekStart`; Agenda = focus ± 7-day initial page). The window is widened by ±1 day in UTC before query to avoid boundary clipping when the display zone is east/west of UTC, then re-clipped client-side after zone conversion.
- **Reactive query:** `combine(modeFlow, focusFlow, zoneFlow) { ... }.flatMapLatest { repo.events(window, zone) }` so superseded windows are cancelled.
- **Caching:** AND-270's Room cache provides `CachedList` with `isStale`. Cache-hit renders immediately (`isStale=true` badge) while the network refresh runs.
- **Persisted UI prefs:** `mode` and `weekStart` persisted via `SavedStateHandle`; `displayZoneOverride` persisted in DataStore (`CalendarZonePreferences`, key `calendar_display_zone`, value = IANA id or null).
- **Agenda paging:** `Pager(PagingConfig(pageSize = 14, prefetchDistance = 1, enablePlaceholders = false))` with `CalendarPagingSource` materializing `DaySlots` per loaded sub-window; events de-duplicated by `(eventId, occurrenceStart)`.
- **Timezone resolution flow:** `zonePrefs.displayZone().map { it ?: ZoneId.systemDefault() }`; `zoneMismatch = displayZone != deviceZone`.

## 7. Error Handling & Resilience

- **Timeouts/retries:** owned by `core-network`/AND-270 (≈20s timeout, bounded exponential backoff for idempotent GETs only). This ticket never retries blindly; it surfaces a manual `retry()`.
- **`CalendarError` taxonomy:** `Network` (offline/timeout), `Server` (5xx/`detail`), `Auth` (terminal 401 after refresh), `Unknown`. Mapped from `ApiResult.Failure`.
- **Stale-while-error:** `CalendarUiState.Error(cause, cached)` keeps the last good `Content` so views stay populated with a dismissible error banner + Retry, rather than blanking.
- **Empty vs error:** an empty successful window shows the empty placeholder, never the error UI.
- **Boundary safety:** zone conversions guard against `DateTimeException`; events with `end <= start` are clamped to a 1-minute minimum block; events fully outside the post-conversion window are dropped.
- **Paging errors:** `LoadState.Error` renders an inline footer with retry; refresh errors fall back to cached pages where available.

## 8. Security & Privacy

- No new endpoints, tokens, or credential handling. Auth rides existing cookie + `ui_csrf`/`X-CSRF-Token` plumbing in `core-network`; the persistent cookie jar already required by the platform applies.
- No event data persisted beyond AND-270's existing Room cache; this ticket adds no new at-rest storage except the non-sensitive `calendar_display_zone` string in DataStore.
- Dev backend is plaintext HTTP; cleartext is permitted only for the dev host via the existing network-security config (owned by core-network). No PII is logged (see §10).
- Public event linking and any unauthenticated access path are out of scope here (AND-272).

## 9. Accessibility & i18n

- All interactive elements (view toggle, nav arrows, day cells, event blocks, overflow chip) carry `contentDescription`; event blocks announce title + localized start–end time + all-day/multi-day status.
- Touch targets ≥ 48dp; the week time grid supports large-font scaling without clipping (hour height scales with `LocalDensity`).
- TalkBack reading order: top bar → current focus label → grid/list in chronological order. Month cell and overflow expose a custom click action to open the day's agenda.
- i18n: all strings in `strings.xml`; dates/times via `java.time.format.DateTimeFormatter.ofLocalizedDateTime` with `Locale.getDefault()`; week start from `WeekFields`. RTL mirroring for nav arrows and grid layout direction. No hardcoded date formats.

## 10. Telemetry & Logging

- Analytics via `core-data` analytics facade: `calendar_view_shown {mode}`, `calendar_nav {direction, mode}`, `calendar_today_tapped`, `calendar_zone_override_applied`, `calendar_event_opened {has_recurrence}`, `calendar_load_error {error_type}`.
- Logging via the shared logger at DEBUG for window/zone computation and load-state transitions; INFO for view switches. **Never** log event titles, attendee data, or full payloads (privacy). Error logs include `CalendarError` type and HTTP status only.
- Performance: log Month grid first-frame and Agenda first-page render durations under a `calendar_perf` tag for triage.

## 11. Testing Strategy

**Unit (JVM, core-testing + Turbine):**
- `EventSlotter.windowFor` for each mode incl. month spanning 4/5/6 visible weeks and locale-driven `weekStart`.
- `toDaySlots`: chip cap + overflow count; multi-day event appears on each spanned day.
- `toWeekGrid` / `assignLanes`: overlapping events split lanes correctly; back-to-back (touching) events do not overlap.
- **Timezone math (critical for acceptance):** event at `13:30Z` slots at 09:30 in `America/New_York` and 22:30 in `Asia/Tokyo`; an event crossing local midnight after conversion appears on the correct two local days; all-day events do not shift across zones; DST transition day (e.g., 2026-03-08 US) slots correctly. Use injected `Clock` and fixed `ZoneId`s.
- `CalendarViewModel`: state transitions Loading→Content→Error(cached); stale badge on cache hit; `flatMapLatest` cancels superseded windows; `retry()` re-emits.

**Instrumented (Compose UI, AndroidJUnit4 + Hilt test + fake `CalendarRepository`):**
- Toggle Month/Week/Agenda; verify correct composable shown and persists across recreation.
- Seeded events render in expected cells/blocks/rows (assert via `contentDescription` and semantics) for a fixed display zone — the literal acceptance check.
- Swipe/next/prev/Today change focus and re-query.
- Error banner + retry; empty placeholder.
- Accessibility: semantics assertions for labels and custom actions.

**Paging:** `CalendarPagingSource` tested with `PagingSource.load` for refresh/append/prepend and de-duplication.

## 12. Dependencies & Sequencing

- **Hard upstream:** **AND-270** (Calendar API + DTOs) — must land first; provides `CalendarRepository`, `CalendarEvent`, recurrence expansion, Room cache, Moshi mapping. Until merged, develop against a `FakeCalendarRepository` in `core-testing` mirroring the §5 contract.
- **Transitive:** AND-027 (network/session foundation, via AND-270), `core-ui` theme/Material 3 tokens, `core-data` DataStore + analytics.
- **Downstream (this blocks):** **AND-272** (Event detail + public App Link) — consumes `onEventClick(calendarId, eventId, occurrenceStart)` exposed here.
- **Build:** add core library desugaring to `feature-calendar/build.gradle.kts` for `java.time` on minSdk 24; add Paging 3 (`androidx.paging:paging-compose`) dependency.
- **Sequencing:** (1) module scaffold + DI wiring, (2) `EventSlotter` + unit tests, (3) ViewModel + state, (4) Month, (5) Week, (6) Agenda/Paging, (7) timezone banner + prefs, (8) instrumented tests.

## 13. Risks & Open Questions

- **R1 (server-side expansion assumption):** §5 assumes AND-270 returns RRULE-expanded occurrences with `occurrence_start`. If expansion is client-side, this ticket gains expansion scope. **OQ:** confirm against `/openapi.json` and `calendar.ts` before build.
- **R2 (tz field semantics):** unclear whether `timezone` is the event's authoring zone vs. the user's. Verify with web reference; spec assumes per-event authoring zone with a separate display zone.
- **R3 (DST/all-day edge cases):** all-day events spanning a DST change must not visually shift; covered by tests but depends on DTO modeling all-day as date-only.
- **R4 (week-view density on small screens):** 24h grid may be cramped; mitigate with vertical scroll and pinch-free fixed hour height; revisit if UX feedback warrants zoom.
- **R5 (dev backend instability):** flaky host may make instrumented tests against live backend unreliable; tests use fakes, and manual verification uses cached/stale paths.
- **OQ:** does the product require a configurable user-facing display-zone picker now, or is device default sufficient for M6? Spec ships device default + optional DataStore override; picker UI deferred.

## 14. Acceptance Criteria

AC-1 Month, Week, and Agenda views are reachable via the segmented control; selection persists across rotation and process death.

AC-2 **Events render in the correct slot in each view** for a fixed seeded dataset (the source-ticket acceptance), asserted via Compose semantics in instrumented tests.

AC-3 **Timezone correctness:** a `13:30Z` event renders at 09:30 in `America/New_York` and 22:30 in `Asia/Tokyo`; all-day events do not shift across zones; an event crossing local midnight appears on both correct local days; a DST-transition day slots correctly — all covered by passing unit tests.

AC-4 Navigation (prev/next, swipe, Today) re-queries the correct `DateWindow` per active view, verified by test.

AC-5 Multi-day and all-day events appear in the all-day lane (Week) and on every spanned day (Month/Agenda); overlapping timed events split into lanes without visual overlap.

AC-6 Loading shows skeletons; cache hits show content with a stale badge; failures show a dismissible error banner with working Retry while preserving last-good content; empty windows show the empty placeholder.

AC-7 A zone-mismatch banner appears when the display zone differs from the device zone, and is suppressed otherwise.

AC-8 No event PII appears in logs; all interactive elements expose content descriptions and meet the 48dp target.

## 15. Definition of Done

- `feature-calendar` module created under `com.testlogon.android.feature.calendar`, wired into the app via Navigation-Compose and Hilt; builds on the `android-port` branch with AGP 8.7.3 / Gradle 8.9 / JDK 17.
- All FRs and ACs implemented; `EventSlotter`, ViewModel, Paging source, and all three views complete.
- Unit + instrumented + paging tests pass in CI; timezone/DST/midnight-crossing cases explicitly covered and green.
- Lint and detekt clean; no hardcoded strings/date formats; desugaring enabled.
- `onEventClick(calendarId, eventId, occurrenceStart)` callback exposed and documented for AND-272; no event-detail or public-link logic included here.
- Telemetry events emitted; no PII logged; accessibility semantics verified by test.
- Code reviewed and merged; spec status moved from `draft` to `accepted` once AC-1–AC-8 are demonstrated.
