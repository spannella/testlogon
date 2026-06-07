---
id: AND-271
title: Calendar views
milestone: M6
epic: E37
priority: P1
size: L
status: reviewed
reviewed_on: 2026-06-06
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
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000` (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. **Auth (verified against `src/api/client.ts`):** the web client sends `Authorization: Bearer <accessToken>`, the `ui_csrf` cookie value echoed as the `X-CSRF-Token` header, and `credentials: "include"` (so cookies flow); calendar endpoints additionally accept an `X-SESSION-ID` header (and optional `X-IMPERSONATION-TOKEN`) per the OpenAPI index. On 401 (only when already authenticated) the client refreshes **once** via `POST /ui/session/refresh` then retries the original request; a failed refresh logs out. `core-network` mirrors this; this ticket does not implement it.
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

Underlying endpoint (reference, owned by AND-270; **verified** against `openapi.index.txt` and `src/api/endpoints/calendar.ts: getEvents`):

```
GET /ui/calendars/{calendar_id}/events?start_utc=2026-06-01T00:00:00Z&end_utc=2026-07-01T00:00:00Z&limit=...&cursor=...
```

> **CORRECTED.** An earlier draft claimed `GET /ui/calendar/events?start=&end=&tz=`. That path/params do not exist. The real endpoint is **per-calendar** (`/ui/calendars/{calendar_id}/events`, op `list_events`, resp `EventsPageOut`), uses **`start_utc`/`end_utc`** (not `start`/`end`), supports **`limit`/`cursor`** cursor pagination, and has **no `tz` query param** — timezone is per-event in the DTO, and the client converts for display. The web `getEvents` helper currently passes only `cursor`; `start_utc`/`end_utc`/`limit` are valid query params per the OpenAPI index. Because events live under a `calendar_id`, AND-270 must fan-out across the user's calendars (`GET /ui/calendars`, op `list_calendars`) and merge — this ticket consumes the merged result via `CalendarRepository`.

Response shape is **`EventsPageOut`** = `{ events: EventOut[], next_cursor?: string }` (cursor pagination — there is **no** top-level `range` object). Each `EventOut` (verified against `components.schemas.EventOut`):

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
      "all_day_date": null,
      "attendees": [],
      "booking_enabled": false,
      "approval_required": false,
      "status": "confirmed",
      "category": null,
      "recurrence_rule": { "freq": "WEEKLY", "interval": 1, "until_utc": null },
      "exdates_utc": [],
      "recurrence_overrides": {},
      "created_at_utc": "2026-05-01T00:00:00Z"
    }
  ],
  "next_cursor": null
}
```

> **CORRECTED field names** (the earlier draft used web-style names that do not match the backend): `id`→**`event_id`**, `title`→**`name`**, `start`/`end`→**`start_utc`**/**`end_utc`** (both nullable; absent for all-day, where **`all_day_date`** carries the date-only anchor), and there is **no `color` field** (the UI must derive `colorKey` from `calendar_id`/`category`, not from the DTO). There is **no `occurrence_start`** and **no `recurrence_id`** field on `EventOut`. Required fields per schema: `event_id, calendar_id, name, description, timezone, all_day, attendees, booking_enabled, approval_required, status, created_at_utc`.
>
> **CORRECTED — server-side RRULE expansion is NOT supported by this contract.** `EventOut` carries `recurrence_rule` (`{freq: DAILY|WEEKLY|MONTHLY, interval?, until_utc?, ...}` per `components.schemas.RecurrenceRule` / `src/api/types.ts: RecurrenceRule`), `exdates_utc`, and `recurrence_overrides` — i.e. the **rule is returned, not expanded occurrences**. The `…/occurrences/{occurrence_start}/…` mutation endpoints further confirm occurrences are identified by `occurrence_start` derived client-side from the rule. This means **AND-270 (or this ticket) owns expansion** unless AND-270 adds it. See R1 (now elevated to a hard blocker) and §6.

Error envelope: FastAPI `detail` mapped by `core-network` to `ApiResult.Failure`. **Verified** against `src/api/client.ts: normalizeErrorDetail` — `detail` may be `string`, `[{msg}]` (422 validation, schema `HTTPValidationError`), or an object `{code, ...}` (e.g. `role_required`, `geo_blocked`). Validation failures return **HTTP 422** (`HTTPValidationError`) per every calendar op in the index; a transport/offline failure surfaces as `ApiError(0, "Network error")`. 401 triggers one `POST /ui/session/refresh` + retry inside `core-network` (verified). This ticket maps `ApiResult.Failure` → `CalendarError` for the UI.

## 6. Data & State Management

- **Single source of truth:** `CalendarViewModel.uiState: StateFlow<CalendarUiState>`, started `WhileSubscribed(5_000)`.
- **Window derivation:** on `mode`/`focusDate`/`zone` change, compute `DateWindow` via `EventSlotter.windowFor` (Month = full weeks covering the month; Week = 7 days from `weekStart`; Agenda = focus ± 7-day initial page). The window is widened by ±1 day in UTC before query to avoid boundary clipping when the display zone is east/west of UTC, then re-clipped client-side after zone conversion. The window's bounds map to the endpoint's **`start_utc`/`end_utc`** query params (corrected; see §5). Because the endpoint is per-`calendar_id` and cursor-paginated, AND-270's repo fans out across the user's calendars and follows `next_cursor` to assemble the full window.
- **Recurrence expansion:** the contract returns `recurrence_rule` + `exdates_utc` + `recurrence_overrides`, **not** pre-expanded occurrences (verified, §5). FR-7 assumes AND-270 expands within the window; if it does not, expansion must be added (to AND-270 or, as fallback, a pure `EventSlotter.expand(rule, window, exdates, overrides)` here). `occurrence_start` (used in FR-8/`SlottedEvent`) is therefore a **client-derived** value, not a DTO field.
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

- **R1 (server-side expansion — CONFIRMED FALSE; now a hard blocker):** verification (§5) shows `EventOut` returns `recurrence_rule`/`exdates_utc`/`recurrence_overrides`, i.e. the **rule, not expanded occurrences**, and `occurrence_start` is not a DTO field. Expansion is therefore NOT done server-side. **Action:** confirm with AND-270 whether it adds expansion; if not, this ticket gains a pure-Kotlin expander (DAILY/WEEKLY/MONTHLY + interval + until + exdates + overrides). This is the single largest scope risk.
- **R2 (tz field semantics):** `EventOut.timezone` is a required per-event string and `start_utc`/`end_utc` are UTC instants; there is no separate user-zone field on the DTO and no `tz` query param. Confirmed the display zone must be resolved client-side (DataStore override → `ZoneId.systemDefault()`); the per-event `timezone` is the authoring zone, relevant mainly for all-day anchoring (`all_day_date`). Spec assumption holds.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verification verdict, and the exact source pointer.

1. **Calendar events are fetched via `GET /ui/calendar/events?start=&end=&tz=`.** — **Corrected.** No such path. Real op is `list_events` = **`GET /ui/calendars/{calendar_id}/events`** with params `start_utc, end_utc, limit, cursor`; no `tz` param. Source: OpenAPI `GET /ui/calendars/{calendar_id}/events` (op `list_events`, resp `200:EventsPageOut`); frontend `src/api/endpoints/calendar.ts: getEvents`.
2. **Response is `{events:[...], range:{...}}`.** — **Corrected.** Real shape is **`EventsPageOut`** = `{ events: EventOut[], next_cursor?: string }` (cursor pagination, no `range`). Source: `components.schemas.EventsPageOut`; `src/api/types.ts: EventsPage`.
3. **Event fields `id`, `title`, `start`, `end`, `color`, `recurrence_id`, `occurrence_start`.** — **Corrected.** Real `EventOut` fields: `event_id`, `name`, `start_utc`, `end_utc`, `all_day`, `all_day_date`, `timezone`, `description`, `attendees`, `booking_enabled`, `approval_required`, `status`, `category`, `recurrence_rule`, `exdates_utc`, `recurrence_overrides`, `created_at_utc`. **No** `color`, `recurrence_id`, or `occurrence_start`. Source: `components.schemas.EventOut` (required list incl. `event_id, calendar_id, name, description, timezone, all_day, attendees, booking_enabled, approval_required, status, created_at_utc`); `src/api/types.ts: CalendarEvent`.
4. **Server returns RRULE-expanded occurrences with `occurrence_start`.** — **Corrected.** Contract returns the **rule** (`recurrence_rule`), `exdates_utc`, and `recurrence_overrides`, not expanded occurrences; `occurrence_start` is only a path param on the occurrence-mutation ops, i.e. client-derived. Source: `components.schemas.EventOut.recurrence_rule` → `components.schemas.RecurrenceRule`; OpenAPI `POST /ui/calendars/{calendar_id}/events/{event_id}/occurrences/{occurrence_start}/override`; `src/api/types.ts: RecurrenceRule` (`freq: "DAILY"|"WEEKLY"|"MONTHLY"`, `interval?`, `until_utc?`).
5. **`timezone` is a required per-event string; display zone resolved client-side.** — **Verified.** `EventOut.timezone` is required; `start_utc`/`end_utc` are UTC; no user-zone field or `tz` param exists. Source: `components.schemas.EventOut` (required), confirmed absence of `tz` in `list_events` params.
6. **All-day events are date-anchored, not zone-shifted.** — **Verified.** `EventOut` exposes `all_day: boolean` and a separate date-only `all_day_date`; `start_utc`/`end_utc` are nullable (absent for all-day). Source: `components.schemas.EventOut.all_day` / `all_day_date`; `src/api/types.ts: CalendarEvent` / `CalendarEventAttachment`.
7. **Auth: cookie + `ui_csrf`/`X-CSRF-Token`.** — **Corrected/expanded.** Client sends `Authorization: Bearer <accessToken>`, echoes the `ui_csrf` cookie as the `X-CSRF-Token` header, and uses `credentials:"include"`; calendar ops also accept `X-SESSION-ID` (+ optional `X-IMPERSONATION-TOKEN`). The "cookie-only" framing was incomplete. Source: `src/api/client.ts` (lines ~157–171, 182–184); OpenAPI `list_events` params `X-SESSION-ID, X-IMPERSONATION-TOKEN`.
8. **On 401 the layer refreshes once via `POST /ui/session/refresh` then retries.** — **Verified.** Single-flight `refreshSession()` → `POST /ui/session/refresh`, retried once; failed refresh logs out; unauthenticated 401 propagates. Source: `src/api/client.ts: refreshSession` / 401 branch (lines ~119–237); OpenAPI `POST /ui/session/refresh` (op `ui_session_refresh`, `resp 200`).
9. **Error `detail` may be `string | [{msg}] | {code,...}`; validation is 422.** — **Verified.** `normalizeErrorDetail` handles all three forms; 422 uses `HTTPValidationError`; transport failure → `ApiError(0,"Network error")`. Source: `src/api/client.ts: normalizeErrorDetail` / `ApiError`; OpenAPI `422:HTTPValidationError` on every calendar op.
10. **AND-272 registers public App Link `/event/{calendarId}/{eventId}`.** — **Corrected (informational, AND-272 scope).** Real public op is `get_public_event` = **`GET /calendar/public/event/{calendar_id}/{event_id}`** (and `/ical`). Source: OpenAPI `GET /calendar/public/event/{calendar_id}/{event_id}`; `src/api/endpoints/calendar.ts: getPublicEvent`.
11. **This ticket performs no direct HTTP; all network via `CalendarRepository` (AND-270).** — **Unverified-assumption** (architectural, internal to the Android port; AND-270 not yet merged). Reasonable per the layering in §2; no source can confirm an unbuilt module.
12. **Dev backend is plaintext HTTP at `http://18.222.237.167:8000`, unreliable.** — **Unverified-assumption.** Host/IP from the ticket context, not in the OpenAPI/frontend sources (frontend uses `VITE_API_BASE_URL`). Treated as an environment fact.
13. **Framework choices: Compose + Material 3, Navigation-Compose, Hilt/KSP, Paging 3, `java.time` via core-library desugaring (minSdk 24).** — **Unverified-assumption (framework ref).** Standard Android stack, not derivable from backend/frontend sources. Desugaring requirement for `java.time` on API <26: framework ref https://developer.android.com/studio/write/java8-support-table . Paging 3 Compose: framework ref https://developer.android.com/jetpack/androidx/releases/paging .

### Corrections made

- §2: auth description expanded from "cookie + CSRF" to the actual `Authorization: Bearer` + `X-CSRF-Token` (from `ui_csrf` cookie) + `credentials:include` + `X-SESSION-ID`, with the verified single-refresh-on-401 flow.
- §5: corrected endpoint path/params (`/ui/calendars/{calendar_id}/events`, `start_utc`/`end_utc`/`limit`/`cursor`, no `tz`), response shape (`EventsPageOut` with `next_cursor`, no `range`), and all event field names (`event_id`, `name`, `start_utc`/`end_utc`, `all_day_date`; removed `color`/`recurrence_id`/`occurrence_start`). Documented that the contract returns the recurrence **rule**, not expanded occurrences, and noted the per-calendar fan-out. Pinned the 422/`HTTPValidationError` validation shape.
- §6: query bounds mapped to `start_utc`/`end_utc`; added a recurrence-expansion note (client/AND-270 owns it); `occurrence_start` flagged as client-derived.
- §13: R1 reclassified from open question to a confirmed hard blocker (no server-side expansion); R2 resolved (per-event `timezone`, client-side display zone, no `tz` param).

### Open assumptions

- **AND-270 repository surface** (`CalendarRepository`, `CalendarEvent`/`RecurrenceRule` domain models, Room `CachedList`/`isStale`, recurrence expansion ownership): unverifiable — AND-270 is not yet merged and is not represented in the backend/frontend sources. Develop against a `FakeCalendarRepository` mirroring the corrected §5.
- **Whether RRULE expansion lands in AND-270 or this ticket:** open dependency decision (R1); affects scope/size materially.
- **Dev host plaintext/instability and cleartext network-security config** (owned by core-network): environment facts not in the verifiable sources.
- **Android framework/version choices** (Kotlin 2.0.21, AGP 8.7.3, Gradle 8.9, minSdk 24 / target 35): policy/toolchain decisions, not verifiable from backend/frontend; cited as framework refs only.

## 17. Test Plan

IDs `TC-AND-271-NN`. "Traces" link to §14 acceptance criteria. Targets: JVM/Robolectric (local), emulator AVD `test35` (API 35 x86_64), or PHYSICAL DEVICE (Samsung Galaxy A15 5G, SM-A156U, serial R5CX821TA9R, API 34 arm64-v8a).

**TC-AND-271-01 — Timezone slotting math (core acceptance)**
- Type: unit (JVM). Target: JVM/Robolectric (local).
- Preconditions: `EventSlotter` + injected fixed `Clock`; event `start_utc=2026-06-08T13:30:00Z`, `end_utc=…T14:00:00Z`.
- Steps: slot the event with `zone=America/New_York`; repeat with `zone=Asia/Tokyo`.
- Expected: renders at 09:30 local (NY) and 22:30 local (Tokyo); `startMinuteOfDay` = 570 and 1350 respectively.
- Traces: AC-3.

**TC-AND-271-02 — Midnight-crossing and DST-transition slotting**
- Type: unit (JVM). Target: JVM/Robolectric (local).
- Preconditions: (a) event whose UTC instants straddle local midnight after conversion; (b) timed event on US DST day 2026-03-08 in `America/New_York`.
- Steps: run `toDaySlots`/`toWeekGrid` for both.
- Expected: (a) the event appears on both correct adjacent local days; (b) the DST-day event slots at the correct wall-clock minute (no 1-hour drift); no `DateTimeException`.
- Traces: AC-3.

**TC-AND-271-03 — All-day events do not shift across zones**
- Type: unit (JVM). Target: JVM/Robolectric (local).
- Preconditions: `EventOut` with `all_day=true`, `all_day_date=2026-06-08`, `start_utc`/`end_utc` null.
- Steps: slot with `America/New_York` and with `Asia/Tokyo`.
- Expected: the all-day event is anchored to 2026-06-08 in both zones (no day shift, placed in the all-day lane / spanned day).
- Traces: AC-3, AC-5.

**TC-AND-271-04 — Overlap lane assignment**
- Type: unit (JVM). Target: JVM/Robolectric (local).
- Preconditions: three overlapping timed events plus one back-to-back (touching, non-overlapping) pair.
- Steps: call `assignLanes`.
- Expected: overlapping events get distinct `laneIndex` with correct `laneCount`; touching events share a lane (no false overlap).
- Traces: AC-5.

**TC-AND-271-05 — `windowFor` per mode incl. locale week start**
- Type: unit (JVM). Target: JVM/Robolectric (local).
- Preconditions: focus dates producing 4/5/6 visible month weeks; `weekStart` = SUNDAY and MONDAY.
- Steps: call `windowFor(MONTH|WEEK|AGENDA, focus, weekStart)`.
- Expected: Month spans full weeks covering the month; Week = 7 days from `weekStart`; Agenda = focus ±7 days; bounds are mapped to `start_utc`/`end_utc` query values (corrected §5).
- Traces: AC-4, AC-2.

**TC-AND-271-06 — Repository contract / DTO mapping (real shapes)**
- Type: contract / MockWebServer. Target: JVM/Robolectric (local).
- Preconditions: MockWebServer returns a real `EventsPageOut` body (`{events:[EventOut...], next_cursor}`) using `event_id`/`name`/`start_utc`/`end_utc`/`all_day_date`/`recurrence_rule`/`exdates_utc`.
- Steps: drive the AND-270 repo/fake against the queued response for `GET /ui/calendars/{calendar_id}/events?start_utc=…&end_utc=…`.
- Expected: request path/params match the corrected contract; `next_cursor` paging is followed; events map to domain `SlottedEvent` with derived `colorKey` (no `color` field consumed) and `occurrenceStart` derived client-side. No reliance on `id`/`title`/`start`/`end`/`range`.
- Traces: AC-2.

**TC-AND-271-07 — Error envelope mapping (422 / object / network)**
- Type: contract / MockWebServer. Target: JVM/Robolectric (local).
- Preconditions: queued responses — (a) 422 `HTTPValidationError` `{detail:[{msg}]}`, (b) 5xx `{detail:"..."}`, (c) 403 `{detail:{code:"role_required"}}`, (d) simulated transport failure.
- Steps: invoke repo→ViewModel for each.
- Expected: mapped to `CalendarError.Server`/`Server`/`Auth`-or-`Unknown`/`Network` respectively; UI shows dismissible banner + working Retry; last-good `Content` preserved.
- Traces: AC-6.

**TC-AND-271-08 — ViewModel state machine + superseded-window cancellation**
- Type: unit (JVM, Turbine). Target: JVM/Robolectric (local).
- Preconditions: fake repo with controllable emissions; injected `Clock`.
- Steps: observe `uiState` through Loading→Content; emit cache hit then refresh; rapidly change focus to verify `flatMapLatest` cancels superseded windows; call `retry()`.
- Expected: transitions Loading→Content→(Error with cached); `isStale=true` on cache hit; only the latest window's result is applied; `retry()` re-emits.
- Traces: AC-6, AC-4.

**TC-AND-271-09 — Paging source refresh/append/prepend + dedup**
- Type: unit (JVM). Target: JVM/Robolectric (local).
- Preconditions: `CalendarPagingSource` over a fake window; overlapping pages contain a duplicate `(eventId, occurrenceStart)`.
- Steps: exercise `PagingSource.load` for refresh, append, prepend.
- Expected: correct page keys; duplicates de-duplicated by `(eventId, occurrenceStart)`; `LoadState.Error` surfaces for a failing load.
- Traces: AC-2, AC-6.

**TC-AND-271-10 — View toggle + persistence across recreation/process death**
- Type: Compose-UI / instrumented. Target: emulator AVD `test35`.
- Preconditions: Hilt test app, fake `CalendarRepository`, seeded events.
- Steps: toggle Month→Week→Agenda; rotate; trigger Activity recreation and simulate process death (saved state restore).
- Expected: correct composable shown each time; selected mode restored after recreation and process death.
- Traces: AC-1.

**TC-AND-271-11 — Seeded events render in correct cells/blocks/rows (literal acceptance)**
- Type: Compose-UI / instrumented. Target: emulator AVD `test35`.
- Preconditions: fixed display zone, seeded dataset incl. a timed event, a multi-day event, and an all-day event.
- Steps: in each view, assert presence/position via semantics + `contentDescription`.
- Expected: Month places chips on correct days with "+N more" overflow; Week positions timed blocks proportionally and puts all-day/multi-day in the pinned all-day lane; Agenda groups under correct sticky date headers; multi-day appears on every spanned day.
- Traces: AC-2, AC-5.

**TC-AND-271-12 — Navigation re-queries correct window**
- Type: Compose-UI / instrumented. Target: emulator AVD `test35`.
- Preconditions: fake repo recording requested windows.
- Steps: tap next/prev and swipe in each mode; tap Today from a non-today focus.
- Expected: focus advances by one month/week/day per mode; Today returns to current date; each change issues a query for the expected `DateWindow` (start_utc/end_utc).
- Traces: AC-4.

**TC-AND-271-13 — Offline / flaky-dev-host stale-while-error path (real hardware)**
- Type: instrumented / e2e. Target: PHYSICAL DEVICE (SM-A156U) — MUST run on device to exercise real radio toggling (airplane mode) and real network timeouts against the flaky plaintext dev host.
- Preconditions: device has a prior successful load cached; app pointed at the dev host.
- Steps: load once (populate cache); enable airplane mode; navigate to force a refresh; tap Retry; restore connectivity and Retry again.
- Expected: cached `Content` stays rendered with stale badge + dismissible error banner (not blanked); Retry re-attempts; on reconnect, fresh data replaces stale and badge clears; an empty successful window shows the empty placeholder (never the error UI).
- Traces: AC-6.
- Note: emulator can approximate via network shaping, but real-radio behavior and the unreliable host are validated only on the physical device.

**TC-AND-271-14 — Zone-mismatch banner toggling**
- Type: Compose-UI / instrumented. Target: emulator AVD `test35` (device-zone override via test config).
- Preconditions: DataStore `calendar_display_zone` override set to a zone ≠ device zone; then cleared.
- Steps: render with override set, then with override null (display zone == device zone).
- Expected: banner shown when `displayZone != deviceZone`; suppressed when equal; all slotting uses the resolved display zone.
- Traces: AC-7.

**TC-AND-271-15 — Accessibility & no-PII security checks**
- Type: Compose-UI / instrumented + manual. Target: PHYSICAL DEVICE (SM-A156U) for real TalkBack; semantics assertions also run on emulator `test35`.
- Preconditions: TalkBack enabled (device); logcat capture during a full load/navigate/error cycle.
- Steps: verify `contentDescription` on toggle, nav arrows, day cells, event blocks, overflow chip; verify event-block announcement includes title + localized start–end + all-day/multi-day; verify 48dp touch targets; verify TalkBack reading order (top bar → focus label → grid/list chronological) and the month-cell/overflow custom click action; inspect logs.
- Expected: all interactive elements expose descriptions and meet 48dp; reading order correct; custom actions invocable; **no event titles/attendee data/full payloads in logs** (only `CalendarError` type + HTTP status).
- Traces: AC-8.

### Coverage matrix

| Acceptance criterion | Covered by |
| --- | --- |
| AC-1 (views reachable, selection persists) | TC-10 |
| AC-2 (events in correct slot, semantics) | TC-05, TC-06, TC-09, TC-11 |
| AC-3 (timezone correctness incl. DST/midnight/all-day) | TC-01, TC-02, TC-03 |
| AC-4 (navigation re-queries window) | TC-05, TC-08, TC-12 |
| AC-5 (multi-day/all-day lanes, overlap split) | TC-03, TC-04, TC-11 |
| AC-6 (loading/stale/error/empty states) | TC-07, TC-08, TC-09, TC-13 |
| AC-7 (zone-mismatch banner) | TC-14 |
| AC-8 (no PII logs, content descriptions, 48dp) | TC-15 |
