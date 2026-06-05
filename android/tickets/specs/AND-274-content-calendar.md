---
id: AND-274
title: Content calendar
milestone: M6
epic: E37
priority: P1
size: M
status: draft
depends_on: [AND-270]
blocks: [AND-275]
---

# AND-274 — Content calendar

## 1. Overview & Goal

This ticket delivers the **content calendar** feature on Android: a
scheduled-content view that renders authored/queued content items (posts,
campaigns, scheduled messages) on a date-indexed timeline so an operator can see
what is scheduled to publish on which day. It is the Kotlin/Compose port of the
web reference API layer file `frontend/src/api/endpoints/content-calendar.ts` and
the matching content-calendar screen.

Scope, verbatim from the backlog: *`content-calendar.ts`; scheduled content
view.* The single acceptance criterion is **"Content calendar renders."** — i.e.
a `ContentCalendarScreen` that fetches scheduled content for a selected period
and renders it grouped by scheduled date, with the standard loading / empty /
error / offline states.

This is a **feature ticket** (transport slice + repository + ViewModel + UI). It
owns:

- `ContentCalendarApi` (the Retrofit seam for `content-calendar.ts`), its Moshi
  DTOs, and DTO→domain mappers — modeled on AND-270's `CalendarApi` patterns but
  for the *content scheduling* shapes (`ScheduledContent`, publish status,
  channel/platform), which are distinct from raw calendar events.
- `ContentCalendarRepository` in `core-data`, returning `ApiResult<T>` (AND-018).
- `ContentCalendarViewModel` exposing `StateFlow<ContentCalendarUiState>`.
- `ContentCalendarScreen` (Compose, Material 3) and its date-grouped list, wired
  into the authenticated nav graph (AND-024).

It deliberately does **not** own: the raw calendar event domain (that is AND-270),
the month/week/agenda calendar views (AND-271), event detail (AND-272), the
scheduler create/edit flow (AND-275 — this ticket is read-only display), Google
Calendar sync (AND-273), or ICS/reminders (AND-276). It reuses the session
machinery (cookies/CSRF/refresh) and the shared network stack wired by upstream
tickets without re-declaring any of it.

The deliverable: a compiling, navigable `ContentCalendarScreen` that, given a
live (or mocked) session, fetches and renders scheduled content grouped by date,
backed by a tested API/repository/ViewModel chain.

## 2. Context & References

- **Repo / location:** `spannella/testlogon`, monorepo subfolder `android/`,
  branch `android-port`. The transport + DTOs land in **`core-network`** under
  `com.testlogon.android.core.network.contentcalendar`; the repository in
  **`core-data`** under `com.testlogon.android.core.data.contentcalendar`; the
  screen + ViewModel in **`feature-calendar`** under
  `com.testlogon.android.feature.calendar.content`. Domain types in **`core-model`**
  under `com.testlogon.android.core.model.contentcalendar`.
- **Canonical package:** `com.testlogon.android` everywhere.
- **Stack pins relevant here:** Kotlin 2.0.21, Jetpack Compose + Material 3,
  Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11.0 + OkHttp 4.12.0
  + Moshi 1.15.x (codegen via KSP), Coil (content thumbnails). `java.time`
  (`Instant`, `LocalDate`, `ZoneId`) via core-library desugaring (minSdk 24).
  compile/target 35, JDK 17, AGP 8.7.3, Gradle 8.9.
- **Module layering:** `app -> feature-* -> core-*`. UI/ViewModel in
  `feature-calendar`; repository in `core-data`; API/DTOs/mappers in `core-network`
  + domain in `core-model`. No `feature-*` symbols leak downward.
- **Upstream dependency — AND-270 (Calendar API + DTOs):** establishes the calendar
  domain conventions on Android (Moshi codegen DTOs, `InstantJsonAdapter`,
  enum-tolerant mappers, Hilt provider built on the shared Retrofit, unknown-value
  tolerance). This ticket follows those patterns and may reuse the shared
  `InstantJsonAdapter`. The backlog dependency is `Deps: AND-270`. Content-calendar
  items are scheduled *content*, not raw calendar `CalendarEvent`s, so this ticket
  defines its own `ScheduledContent` domain type rather than reusing `CalendarEvent`.
- **Transitive upstream (already required by AND-270/AND-027):** AND-027 (cookie
  session), AND-010 (shared Retrofit/Moshi), AND-009 (shared `OkHttpClient`, ~20s
  timeouts, redacting logger), AND-016 (bounded backoff for idempotent GETs),
  AND-015 (FastAPI `detail` → `ApiError`), AND-018 (`ApiResult`), AND-011/AND-012/
  AND-013 (cookie jar / CSRF / 401-refresh), AND-021 (loading/empty/error/offline
  state composables), AND-019/AND-020 (theme, core composables), AND-024
  (authenticated nav graph + bottom-nav), AND-006 (`BuildConfig.API_BASE_URL`).
- **Web reference (authoritative for shapes):**
  `frontend/src/api/endpoints/content-calendar.ts` (endpoints) and the
  content-calendar slice of `frontend/src/api/types.ts` (`ScheduledContent`,
  publish `status`, `channel`/platform). OpenAPI at `/openapi.json` is the final
  authority; any deviation here is reconciled against it before merge.
- **Sibling / downstream — AND-275 (Scheduler):** adds schedule/reschedule create
  and edit on top of the content domain. This read-only view is the surface AND-275
  mutates; tapping a content item should navigate toward the scheduler detail/edit
  route AND-275 owns. `blocks: [AND-275]` reflects that AND-275 builds on these
  domain types and this screen.

## 3. Functional Requirements

FR-1. Declare a Retrofit interface `ContentCalendarApi` covering the scheduled-
content operations exposed by `content-calendar.ts`: list scheduled content
within a date range (the primary read). Exact set reconciled against
`/openapi.json`; Section 5 is the working contract. All reads are `suspend`,
return typed DTO bodies, and are idempotent GETs.

FR-2. The range-list endpoint accepts typed `@Query` params (`from`, `to`,
`channel?`, `status?`, `page?`) as RFC-3339 / ISO-8601 strings on the wire. Paths
are declared **without** a leading slash (AND-010 convention).

FR-3. Define Moshi `@JsonClass(generateAdapter = true)` DTOs for every
content-calendar shape: `ScheduledContentDto`, `ContentCalendarRespDto` (paged
envelope). Wire fields are snake_case; Kotlin properties camelCase via
`@Json(name=...)` where codegen cannot infer.

FR-4. Provide pure DTO→domain mappers
(`ScheduledContentDto.toDomain(): ScheduledContent`) that map unknown enum strings
to `UNKNOWN` (never throw) and tolerate absent optional fields via Kotlin
defaults. Timestamps parse to `java.time.Instant` via the shared
`InstantJsonAdapter`.

FR-5. `ContentCalendarRepository` exposes a single read:
`suspend fun scheduledContent(range: DateRange, filter: ContentFilter):
ApiResult<List<ScheduledContent>>`, wrapping the API call in `ApiResult` (AND-018)
and mapping FastAPI errors via AND-015. GET is the only verb; bounded backoff
applies (AND-016).

FR-6. `ContentCalendarViewModel` exposes
`val uiState: StateFlow<ContentCalendarUiState>`. On init (and on retry / range
change / filter change) it loads the current period (default: the current month in
the device timezone) and reduces results into a **date-grouped** structure:
`Map<LocalDate, List<ScheduledContentItem>>` ordered ascending, each day's items
ordered by scheduled time.

FR-7. `ContentCalendarScreen` renders the grouped content as a vertically
scrolling list with **sticky date headers** (a "schedule"/agenda layout) — each
day header shows the localized date; under it, one row per scheduled content item
showing title, scheduled time, channel/platform badge, publish-status chip, and
an optional thumbnail (Coil). Tapping a row navigates toward the content/scheduler
detail route (AND-275). The screen MUST render the **loading**, **empty**
("No scheduled content for this period"), **error** (with Retry), and **offline /
stale** states via the AND-021 state composables.

FR-8. A period selector (previous / next month, plus a "Today" affordance) drives
range changes; changing the period re-queries. Period state survives
configuration changes (held in the ViewModel / `SavedStateHandle`).

FR-9. The screen is registered in the authenticated nav graph (AND-024) at route
`content_calendar` and reachable from the calendar area. It is **read-only** in
this ticket; create/edit affordances are stubs that route to AND-275 (or are
hidden until AND-275 lands).

FR-10. A Hilt provider `provideContentCalendarApi(retrofit: Retrofit)` constructs
the service from the **shared** Retrofit (AND-010). No new Retrofit/OkHttp
instance; CSRF/cookies are injected globally (AND-011/AND-012) and not declared
per-method.

## 4. Technical Design

### 4.1 Domain types (core-model)

```kotlin
package com.testlogon.android.core.model.contentcalendar

import java.time.Instant
import java.time.LocalDate

data class ScheduledContent(
    val id: String,
    val title: String,
    val summary: String?,
    val channel: ContentChannel,        // platform/destination
    val status: PublishStatus,
    val scheduledAt: Instant,           // when it is set to publish
    val scheduledDate: LocalDate,       // derived (in effective tz) for grouping
    val timezone: String?,              // IANA tz, if the item carries one
    val thumbnailUrl: String?,
    val author: String?,
    val updatedAt: Instant?,
)

enum class ContentChannel { EMAIL, SMS, PUSH, BLOG, SOCIAL, WEB, UNKNOWN }

enum class PublishStatus { DRAFT, SCHEDULED, PUBLISHING, PUBLISHED, FAILED, CANCELED, UNKNOWN }

data class DateRange(val from: Instant, val to: Instant) // [from, to)

data class ContentFilter(
    val channel: ContentChannel? = null,
    val status: PublishStatus? = null,
)
```

### 4.2 DTOs (core-network)

```kotlin
package com.testlogon.android.core.network.contentcalendar

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import java.time.Instant

@JsonClass(generateAdapter = true)
data class ScheduledContentDto(
    val id: String,
    val title: String,
    val summary: String? = null,
    val channel: String? = null,
    val status: String? = null,
    @Json(name = "scheduled_at") val scheduledAt: Instant? = null,
    @Json(name = "scheduled_date") val scheduledDate: String? = null, // ISO date fallback
    val timezone: String? = null,
    @Json(name = "thumbnail_url") val thumbnailUrl: String? = null,
    val author: String? = null,
    @Json(name = "updated_at") val updatedAt: Instant? = null,
)

@JsonClass(generateAdapter = true)
data class ContentCalendarRespDto(
    val items: List<ScheduledContentDto>,
    @Json(name = "next_page") val nextPage: String? = null,
)
```

`ScheduledContentDto` accepts either `scheduled_at` (`Instant`) or
`scheduled_date` (ISO date string); the mapper reconciles them (R-3). `Instant`
(de)serialization uses the shared `InstantJsonAdapter` from AND-026/AND-270.

### 4.3 The `ContentCalendarApi` interface

```kotlin
package com.testlogon.android.core.network.contentcalendar

import retrofit2.http.GET
import retrofit2.http.Query

interface ContentCalendarApi {

    /** Scheduled content overlapping [from, to). Idempotent GET; paged. */
    @GET("content-calendar")
    suspend fun listScheduledContent(
        @Query("from") from: String,            // RFC-3339, inclusive
        @Query("to") to: String,                // RFC-3339, exclusive
        @Query("channel") channel: String? = null,
        @Query("status") status: String? = null,
        @Query("page") page: String? = null,    // opaque cursor
    ): ContentCalendarRespDto
}
```

The exact path (`content-calendar` vs `content/calendar` vs
`calendar/content`) is confirmed against `/openapi.json` + `content-calendar.ts`
before coding (Q-1).

### 4.4 Mappers

```kotlin
package com.testlogon.android.core.network.contentcalendar

import com.testlogon.android.core.model.contentcalendar.*
import java.time.LocalDate
import java.time.ZoneId

fun ScheduledContentDto.toDomain(deviceZone: ZoneId): ScheduledContent {
    val instant = scheduledAt
        ?: scheduledDate?.let { LocalDate.parse(it).atStartOfDay(deviceZone).toInstant() }
        ?: error("scheduled content $id has neither scheduled_at nor scheduled_date")
    val zone = timezone?.let(ZoneId::of) ?: deviceZone
    return ScheduledContent(
        id = id,
        title = title,
        summary = summary,
        channel = channel.toContentChannel(),
        status = status.toPublishStatus(),
        scheduledAt = instant,
        scheduledDate = instant.atZone(zone).toLocalDate(),
        timezone = timezone,
        thumbnailUrl = thumbnailUrl,
        author = author,
        updatedAt = updatedAt,
    )
}

private fun String?.toPublishStatus(): PublishStatus = when (this?.lowercase()) {
    "draft" -> PublishStatus.DRAFT; "scheduled" -> PublishStatus.SCHEDULED
    "publishing" -> PublishStatus.PUBLISHING; "published" -> PublishStatus.PUBLISHED
    "failed" -> PublishStatus.FAILED; "canceled", "cancelled" -> PublishStatus.CANCELED
    else -> PublishStatus.UNKNOWN
}
// analogous String?.toContentChannel()
```

Mappers are pure and individually unit-tested; enum helpers centralize
unknown-value tolerance (never throw).

### 4.5 Repository (core-data)

```kotlin
package com.testlogon.android.core.data.contentcalendar

import com.testlogon.android.core.model.contentcalendar.*
import com.testlogon.android.core.network.ApiResult

interface ContentCalendarRepository {
    suspend fun scheduledContent(
        range: DateRange,
        filter: ContentFilter = ContentFilter(),
    ): ApiResult<List<ScheduledContent>>
}

class DefaultContentCalendarRepository @Inject constructor(
    private val api: ContentCalendarApi,
    @IoDispatcher private val io: CoroutineDispatcher,
    private val zone: ZoneId,
) : ContentCalendarRepository {

    override suspend fun scheduledContent(range: DateRange, filter: ContentFilter) =
        withContext(io) {
            apiCall { // AND-018 helper wrapping try/catch → ApiResult, AND-015 mapping
                api.listScheduledContent(
                    from = range.from.toString(),
                    to = range.to.toString(),
                    channel = filter.channel?.wire(),
                    status = filter.status?.wire(),
                ).items.map { it.toDomain(zone) }
                 .sortedBy { it.scheduledAt }
            }
        }
}
```

Paging beyond the first page is deferred (R-2): the dev range is a single month;
if `next_page` is present the repository may follow it eagerly within bounds, or a
Paging-3 source is a follow-up. The contract surface is page-cursor-ready.

### 4.6 UI state, ViewModel (feature-calendar)

```kotlin
package com.testlogon.android.feature.calendar.content

sealed interface ContentCalendarUiState {
    val period: YearMonth
    data class Loading(override val period: YearMonth) : ContentCalendarUiState
    data class Empty(override val period: YearMonth) : ContentCalendarUiState
    data class Error(
        override val period: YearMonth,
        val message: String,
        val isOffline: Boolean,
    ) : ContentCalendarUiState
    data class Content(
        override val period: YearMonth,
        val days: List<ContentDay>,        // ascending by date
        val isStale: Boolean = false,
    ) : ContentCalendarUiState
}

data class ContentDay(val date: LocalDate, val items: List<ScheduledContent>)

@HiltViewModel
class ContentCalendarViewModel @Inject constructor(
    private val repository: ContentCalendarRepository,
    private val zone: ZoneId,
    savedState: SavedStateHandle,
) : ViewModel() {

    private val period = MutableStateFlow(savedState["period"] ?: YearMonth.now(zone))
    val uiState: StateFlow<ContentCalendarUiState> = /* flatMapLatest period -> load() */

    fun onPeriod(next: YearMonth) { period.value = next }
    fun onToday() { period.value = YearMonth.now(zone) }
    fun retry() { /* re-emit current period */ }

    private suspend fun load(p: YearMonth): ContentCalendarUiState { /* range → repo → group */ }
}
```

`load` builds a `DateRange` from the `YearMonth` (`atDay(1)` .. next month start in
`zone`), calls the repository, groups results by `scheduledDate`, sorts days
ascending and items by time, and maps `ApiResult` outcomes to
`Content`/`Empty`/`Error`. Offline (`UnknownHostException`/no connectivity per
AND-017) yields `Error(isOffline = true)`; last-good results may be retained as
`Content(isStale = true)` per AND-045-style stale policy.

### 4.7 Compose screen

```kotlin
@Composable
fun ContentCalendarScreen(
    onItemClick: (contentId: String) -> Unit,   // → AND-275 detail/edit route
    viewModel: ContentCalendarViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    Scaffold(topBar = { ContentCalendarTopBar(state.period, viewModel::onPeriod, viewModel::onToday) }) { pad ->
        when (val s = state) {
            is ContentCalendarUiState.Loading -> LoadingState(Modifier.padding(pad))
            is ContentCalendarUiState.Empty   -> EmptyState(pad, "No scheduled content for this period")
            is ContentCalendarUiState.Error   ->
                if (s.isOffline) OfflineState(pad, onRetry = viewModel::retry)
                else ErrorState(pad, s.message, onRetry = viewModel::retry)
            is ContentCalendarUiState.Content -> ContentCalendarList(s.days, onItemClick, Modifier.padding(pad))
        }
    }
}

@Composable
private fun ContentCalendarList(
    days: List<ContentDay>, onItemClick: (String) -> Unit, modifier: Modifier,
) {
    LazyColumn(modifier) {
        days.forEach { day ->
            stickyHeader(key = "h_${day.date}") { DateHeader(day.date) }
            items(day.items, key = { it.id }) { ScheduledContentRow(it, onClick = { onItemClick(it.id) }) }
        }
    }
}
```

`LoadingState`/`EmptyState`/`ErrorState`/`OfflineState` are AND-021 composables.
`ScheduledContentRow` renders title, localized time, a `ChannelBadge`, a
`StatusChip(status)` (color-coded), and an optional Coil thumbnail.

### 4.8 Navigation + Gradle wiring

Route `content_calendar` is added to the authenticated nav graph (AND-024). No new
Gradle dependencies: `core-network` already has Retrofit/Moshi/KSP/Hilt;
`feature-calendar` already has Compose/Hilt/Coil. This ticket adds source files and
a nav entry only.

## 5. API Contract

Base path (`dev`): `http://18.222.237.167:8000/`. All reads ride the cookie
session; GET is idempotent (bounded backoff per AND-016). Shapes below are the
working contract, reconciled against `/openapi.json` + `content-calendar.ts`
before merge.

### GET `content-calendar?from=…&to=…&channel=…&status=…&page=…`
`from`/`to` RFC-3339; `channel`/`status` optional filters; `page` opaque cursor.
Response `200`:
```json
{
  "items": [
    {
      "id": "cnt_4012",
      "title": "June product newsletter",
      "summary": "Monthly roundup + release notes",
      "channel": "email",
      "status": "scheduled",
      "scheduled_at": "2026-06-10T14:00:00Z",
      "timezone": "America/New_York",
      "thumbnail_url": "https://cdn.testlogon.dev/c/4012.png",
      "author": "Dana Ruiz",
      "updated_at": "2026-06-05T12:00:00Z"
    },
    {
      "id": "cnt_4013",
      "title": "Launch teaser",
      "channel": "social",
      "status": "draft",
      "scheduled_date": "2026-06-12",
      "updated_at": "2026-06-04T09:30:00Z"
    },
    {
      "id": "cnt_4014",
      "title": "Welcome SMS blast",
      "channel": "sms",
      "status": "failed",
      "scheduled_at": "2026-06-09T16:30:00Z"
    }
  ],
  "next_page": null
}
```

Notes: `scheduled_at` (instant) and `scheduled_date` (ISO date) are alternatives;
unknown `channel`/`status` strings map to `UNKNOWN`. A bare array (no envelope) is
a possible shape variance (R-2).

**Error envelope (all endpoints):** FastAPI `detail` union
(`string | [{msg,type,loc}] | {code,...}`), decoded to typed `ApiError` by
**AND-015** and surfaced through `ApiResult.Failure` (AND-018). A `401` is
intercepted by the AND-013 `Authenticator` (one refresh + retry) before
propagating.

This ticket adds **no mutating endpoints** — create/reschedule/cancel are owned by
**AND-275 (Scheduler)**.

## 6. Data & State Management

- **Single source of truth:** `ContentCalendarViewModel.uiState`
  (`StateFlow<ContentCalendarUiState>`), collected with
  `collectAsStateWithLifecycle`. The reducer turns `ApiResult<List<ScheduledContent>>`
  + the current `YearMonth` into one immutable state.
- **Grouping:** results group by `scheduledDate` (derived in the effective tz),
  ascending; each `ContentDay` sorts items by `scheduledAt`. Grouping is done in
  the ViewModel (testable, off the main thread via the repository's IO dispatch).
- **Period persistence:** the selected `YearMonth` is held in `SavedStateHandle`
  (`"period"`), surviving process death and config changes.
- **Serialization:** Moshi codegen adapters (KSP) + shared `InstantJsonAdapter`;
  unknown JSON keys ignored; absent optionals fall back to Kotlin defaults; unknown
  enum strings → `UNKNOWN` in mappers (not at adapter level).
- **Caching (this ticket):** in-memory only — the last successful `Content` per
  period is retained to back the `isStale` state on transient failure. **No Room**
  table is introduced here; durable offline cache for content-calendar, if needed,
  is a follow-up (mirrors AND-045's auth-area stale pattern).
- **Paging:** the contract is cursor-ready (`next_page`); the dev one-month range
  is expected to fit a single page. A full Paging-3 `PagingSource` is out of scope
  (R-2).
- **Threading:** network + mapping + grouping run on the injected IO dispatcher;
  the ViewModel only reduces into state on the main-safe flow.

## 7. Error Handling & Resilience

- **Typed outcomes:** the repository returns `ApiResult<T>` (AND-018); the
  ViewModel maps `Failure` to `Error`/`Offline` UI states. No raw exceptions reach
  Compose.
- **Transport failures** (`SocketTimeoutException`, `UnknownHostException`,
  `IOException`) — given the unreliable plaintext dev host — produce a retryable
  `Error`; `UnknownHostException` / connectivity-down (AND-017) produces the
  **offline** state. The ~20s timeout and bounded backoff for the idempotent GET
  are inherited from AND-009/AND-016.
- **HTTP errors:** non-2xx is decoded to `ApiError` via AND-015 and shown with a
  user-readable message + **Retry**. A `401` is handled by the AND-013 refresh
  authenticator before surfacing; a persistent `401` routes to login (AND-025).
- **Empty vs error:** a successful `200` with `items: []` yields the **Empty**
  state ("No scheduled content for this period"), never an error.
- **Stale fallback:** on a transient failure when a previous successful load for
  the same period exists, the screen shows `Content(isStale = true)` with a subtle
  "showing last loaded" indicator plus Retry, rather than blanking the list.
- **Deserialization variance:** mappers tolerate missing optionals,
  `scheduled_at`/`scheduled_date` alternation, and unknown enums; only a
  genuinely malformed item (no schedule timestamp at all) errors, deterministically.

## 8. Security & Privacy

- **Authenticated surface:** the content-calendar read requires the cookie session
  (AND-027 family). `ContentCalendarApi` adds no manual `Cookie`/`Authorization`
  headers; identity rides the persistent jar (AND-011). The read is server-scoped
  to content the principal may see.
- **CSRF:** the only verb here is GET, so `X-CSRF-Token` is not required for this
  ticket; mutating content operations (AND-275) will rely on AND-012.
- **Cleartext on dev:** content titles/summaries/thumbnails ride plaintext HTTP on
  the dev host — a known, dev-only risk permitted by the scoped cleartext config
  (AND-006); `staging`/`prod` are HTTPS-only.
- **No payload logging:** content titles/summaries/author names are potentially
  sensitive. This ticket adds no body logging; the shared logging interceptor
  (AND-009) is debug-only and redacted. A review check confirms no content payload
  reaches logcat in any build.
- **Image loading:** Coil loads `thumbnail_url` over the session; on dev these are
  plaintext URLs. No third-party trackers; no caching of images to shared storage.
- **No new permissions / no token storage:** read-only network + display.

## 9. Accessibility & i18n

- **Dates/times localized:** all day headers and item times render via
  `java.time` + Android locale/timezone settings (12/24h aware). Items carrying an
  IANA `timezone` are grouped/displayed in their effective zone; the absence of a
  zone falls back to device tz. No hard-coded date formats.
- **Strings:** all visible text ("No scheduled content for this period", "Retry",
  "Today", status labels, channel labels) lives in `strings.xml` — no string
  literals in composables — ready for translation.
- **TalkBack:** each `ScheduledContentRow` exposes a merged content description
  combining title, localized time, channel, and status (e.g. "June product
  newsletter, email, scheduled, June 10 at 10:00 AM"). Status chips are not
  color-only — they carry text/iconography so meaning is not lost for color-blind
  users (WCAG 1.4.1). Sticky date headers use `heading()` semantics.
- **Touch targets / scaling:** rows meet the 48dp minimum target; layout reflows
  with font scaling and supports landscape. Period prev/next/today controls are
  labeled icon buttons.

## 10. Telemetry & Logging

- **HTTP logging** inherited from AND-009's redacting interceptor (debug only); no
  new payload logging.
- **Analytics (redacted, per AND-052 policy):** emit
  `content_calendar_viewed { period, item_count }` on a successful load,
  `content_calendar_item_opened { content_id_hashed, channel, status }` on row tap,
  and `content_calendar_load_failed { reason, is_offline }` on failure. **No**
  titles/summaries/author names or raw ids are logged; ids are hashed/anonymized.
- **Build-time signal:** KSP must generate Moshi adapters for both content-calendar
  DTOs; a missing adapter fails the build (no reflection fallback).

## 11. Testing Strategy

**Unit — mappers & API (core-network, JVM + MockWebServer).** Using the production
Moshi config (incl. `InstantJsonAdapter`):

- **T-1 — `listScheduledContent` query.** Issues `GET /content-calendar`, sends
  `from`/`to`/`channel`/`status` query params, decodes the `{items,next_page}`
  envelope. Asserts verb, `encodedPath == "/content-calendar"`, and each query
  value.
- **T-2 — instant-scheduled mapping.** `items[0]` (`scheduled_at` + `timezone`)
  maps to `scheduledAt` parsed correctly and `scheduledDate` derived in the item
  tz (no off-by-one across the UTC→ET boundary).
- **T-3 — date-only mapping.** `items[1]` (`scheduled_date`, no `scheduled_at`)
  maps to a derived `Instant` at start-of-day in the effective zone and a non-null
  `scheduledDate`.
- **T-4 — enum tolerance.** `status:"failed"` → `FAILED`; `channel:"social"` →
  `SOCIAL`; an unknown `channel:"carrier-pigeon"` → `UNKNOWN`; missing `status` →
  `UNKNOWN`. No throw.
- **T-5 — error propagation.** A `401` surfaces as `HttpException`/`ApiResult.Failure`
  (not swallowed), leaving room for AND-013/AND-015.

**Unit — repository (core-data).**
- **T-6 — success mapping + sort.** Mocked `ContentCalendarApi` returns 3 items;
  repository returns `ApiResult.Success` with items sorted ascending by
  `scheduledAt`.
- **T-7 — failure mapping.** API throws `IOException` → `ApiResult.Failure` with
  the offline/transport classification (AND-017/AND-018).

**Unit — ViewModel (core-testing harness, `runTest` + fake repository).**
- **T-8 — loading→content.** Initial state `Loading`, then `Content` whose `days`
  are ascending and items grouped by `scheduledDate`, item count matches.
- **T-9 — empty.** Empty list → `Empty` state.
- **T-10 — error/offline + retry.** Failure → `Error`/`Offline`; `retry()`
  re-queries and recovers to `Content`.
- **T-11 — period change.** `onPeriod(next)` issues a new range and updates state;
  `onToday()` resets to `YearMonth.now`; period survives via `SavedStateHandle`.
- **T-12 — stale fallback.** A successful load followed by a transient failure for
  the same period yields `Content(isStale = true)` (last-good retained).

**Compose UI tests (feature-calendar, instrumented).**
- **T-13 — renders content (ACCEPTANCE).** With a fake ViewModel emitting
  `Content`, the screen shows sticky date headers and one row per item with title,
  time, channel, and status — satisfying the backlog "Content calendar renders."
- **T-14 — state surfaces.** Loading shows the spinner; empty shows the empty
  message; error shows the message + Retry (clicking calls `retry`); offline shows
  the offline state.
- **T-15 — navigation.** Tapping a row invokes `onItemClick` with the item id
  (the AND-275 hand-off).

Coverage target: ≥85% on mappers, repository, and ViewModel reducer. Every state
and the grouping logic have a dedicated assertion.

## 12. Dependencies & Sequencing

**Hard upstream (must merge first):**
- **AND-270** — Calendar API + DTOs (backlog `Deps: AND-270`): establishes the
  Android calendar-domain conventions (Moshi codegen DTOs, `InstantJsonAdapter`,
  enum-tolerant mappers, shared-Retrofit Hilt provider) this ticket follows.

**Transitive upstream (already in place via AND-270/AND-027):** AND-027 (cookie
session), AND-010 (shared Retrofit/Moshi), AND-009 (client/timeouts/redacting
logger), AND-016 (idempotent-GET backoff), AND-015 (`ApiError` mapping), AND-018
(`ApiResult`), AND-011/AND-012/AND-013 (cookies/CSRF/refresh), AND-017
(connectivity), AND-021 (state composables), AND-019/AND-020 (theme/composables),
AND-024 (authenticated nav graph), AND-006 (`BuildConfig`).

**Downstream (this ticket blocks):**
- **AND-275 (Scheduler)** — builds schedule/reschedule create+edit on the content
  domain and detail route this screen navigates to (`blocks: [AND-275]`).
- Broader content-management features reuse `ScheduledContent` /
  `ContentCalendarRepository`.

**Sequencing within the ticket:** (1) confirm path/query/shape against
`/openapi.json` + `content-calendar.ts`; (2) define `core-model` types; (3) DTOs +
codegen adapters; (4) mappers; (5) `ContentCalendarApi` + Hilt provider;
(6) `ContentCalendarRepository`; (7) `ContentCalendarViewModel`; (8)
`ContentCalendarScreen` + nav entry; (9) tests T-1..T-15.

## 13. Risks & Open Questions

- **R-1 Domain overlap with AND-270.** Content-calendar items are scheduled
  *content*, not raw `CalendarEvent`s. Mitigation: a dedicated `ScheduledContent`
  model; reuse only shared infra (`InstantJsonAdapter`, mapper conventions), not
  `CalendarEvent`. Revisit if OpenAPI shows the backend reuses the event shape.
- **R-2 Paging / envelope shape.** The endpoint may return a bare array, a
  `{items,next_page}` envelope, or offset/limit. Mitigation: default to the cursor
  envelope; tolerate a bare array via a lenient response type if OpenAPI dictates.
  Full Paging-3 is a follow-up. Guarded by T-1.
- **R-3 Timestamp form.** Items may carry `scheduled_at` (instant), a naive time +
  separate `timezone`, or only `scheduled_date`. Mitigation: DTO accepts both;
  mapper derives `Instant` + `LocalDate` using item tz when present, device tz
  otherwise. Open: is `scheduled_at` always UTC? Guarded by T-2/T-3.
- **R-4 Read-only boundary.** This view is display-only; create/edit is AND-275.
  Risk of scope creep into scheduling. Mitigation: row tap only navigates; no
  mutation endpoints declared here.
- **R-5 Unreliable dev host.** Loads may time out/flap. Mitigation: robust
  offline/stale/error states + Retry + bounded backoff (AND-016).
- **Q-1** Endpoint path: `content-calendar` vs `content/calendar` vs
  `calendar/content`? *Proposed:* match `content-calendar.ts`/OpenAPI; spec assumes
  flat `content-calendar`.
- **Q-2** Filter params: are `channel`/`status` server-supported query filters, or
  must filtering be client-side? *Proposed:* send as query if OpenAPI lists them;
  otherwise filter client-side in the repository.
- **Q-3** Status/channel enum value sets — confirm the full vocabulary against
  `types.ts`/OpenAPI; unknowns map to `UNKNOWN` regardless.
- **Q-4** Default period: current month vs current week? *Proposed:* current month
  in device tz; confirm with the web reference's default range.

## 14. Acceptance Criteria

- **AC-1 (backlog).** **Content calendar renders.** With a session (or fake
  ViewModel), `ContentCalendarScreen` fetches scheduled content for the selected
  period and renders it grouped by date with sticky day headers and per-item rows
  (title, time, channel, status), proven by Compose UI test T-13.
- **AC-2.** `ContentCalendarApi.listScheduledContent` issues `GET /content-calendar`
  with `from`/`to`/`channel`/`status`/`page` query params and decodes the paged
  envelope (T-1).
- **AC-3.** `ScheduledContentDto.toDomain` maps both instant- and date-scheduled
  items losslessly into `ScheduledContent`, deriving `scheduledDate` in the
  effective tz with no off-by-one (T-2, T-3).
- **AC-4.** Unknown enum strings and missing optional fields map to `UNKNOWN`/
  defaults without throwing (T-4).
- **AC-5.** `ContentCalendarRepository.scheduledContent` returns `ApiResult` with
  items sorted ascending by schedule time; failures map to typed `ApiResult.Failure`
  (T-6, T-7).
- **AC-6.** `ContentCalendarViewModel.uiState` exposes a `StateFlow` cycling
  Loading → Content/Empty/Error/Offline, groups items by date ascending, and
  supports retry + period change with `SavedStateHandle` persistence (T-8..T-12).
- **AC-7.** The screen renders all of loading/empty/error/offline via the AND-021
  composables, and row tap navigates with the content id (T-14, T-15).
- **AC-8.** `ContentCalendarApi` is Hilt-provided as a `@Singleton` on the **shared**
  Retrofit; no new `OkHttpClient`/`Retrofit`, no per-method cookie/CSRF headers.
- **AC-9.** Route `content_calendar` is registered in the authenticated nav graph
  (AND-024) and reachable from the calendar area.
- **AC-10.** All tests pass in CI; modules build clean under AGP 8.7.3 / Gradle 8.9
  / JDK 17 with KSP-generated adapters present and no detekt/lint regressions.

## 15. Definition of Done

- Domain types (`ScheduledContent`, `ContentChannel`, `PublishStatus`, `DateRange`,
  `ContentFilter`) in `core-model`
  (`com.testlogon.android.core.model.contentcalendar`); DTOs, `ContentCalendarApi`,
  mappers, and the Hilt provider in `core-network`
  (`com.testlogon.android.core.network.contentcalendar`); repository in `core-data`;
  `ContentCalendarViewModel` + `ContentCalendarScreen` (+ rows/headers/badges) in
  `feature-calendar` (`...feature.calendar.content`).
- Open questions Q-1..Q-4 resolved against `/openapi.json` and
  `frontend/src/api/endpoints/content-calendar.ts` + `types.ts`; the path, query
  params, and enum vocabularies reflect the confirmed contract.
- Tests T-1 through T-15 implemented and green in CI; ≥85% coverage on mappers /
  repository / ViewModel reducer; the Compose render test (T-13) satisfies the
  backlog acceptance.
- No second `OkHttpClient`/`Retrofit`; no manual cookie/CSRF/auth headers; no
  content payload bodies in logs (verified in review); analytics redacted per
  AND-052.
- `./gradlew :core-model:assemble :core-network:assemble :core-data:assemble
  :feature-calendar:assemble :core-network:testDebugUnitTest
  :feature-calendar:testDebugUnitTest` passes locally and in CI with no new
  lint/detekt violations (AND-005 config); instrumented UI tests pass on the
  headless emulator (AND-051).
- The screen is reachable in a debug build against the dev backend (or
  MockWebServer fixtures) and renders content/empty/error/offline correctly.
- Code reviewed and merged to `android-port`; **AND-275 (Scheduler)** is unblocked
  with the content domain types and the read-only view to build create/edit on.
- A one-line note in the `feature-calendar` README (per AND-007) records the
  `content_calendar` route and the `ContentCalendarApi` path/verb.
