---
id: AND-274
title: Content calendar
milestone: M6
epic: E37
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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
  for the *content scheduling* shapes (`ScheduledContent`, content `type`
  post/broadcast/vod, schedule `status`), which are distinct from raw calendar
  events.
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
  content-calendar slice of `frontend/src/api/types.ts`
  (`ContentCalendarItem`/`ContentCalendarResponse`, content `type`, schedule
  `status`). OpenAPI at `/openapi.json` is the final
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

FR-2. **[CORRECTED]** The range-list endpoint accepts typed `@Query` params
`from_ts` and `to_ts` (**Unix epoch seconds, integer, both REQUIRED**) plus an
optional `types` param (a **comma-separated** string of `post,broadcast,vod`).
There is **no** `channel`, `status`, or `page` query param and **no** RFC-3339
date strings on the wire — verified against OpenAPI `GET /ui/content-calendar`
(params `from_ts,to_ts,types`) and `src/api/endpoints/content-calendar.ts:
getContentCalendar`. The relative Retrofit path is `ui/content-calendar`
(declared **without** a leading slash per the AND-010 convention; the full path
is `/ui/content-calendar`).

FR-3. **[CORRECTED]** Define Moshi `@JsonClass(generateAdapter = true)` DTOs for
the content-calendar shapes confirmed in `src/api/types.ts`:
`ContentCalendarItemDto` (the per-item shape) and `ContentCalendarRespDto` (the
response envelope `{items, from_ts, to_ts, count, conflicts}` — **not** a paged
`{items, next_page}` cursor envelope; the real API returns no paging cursor) and
`ContentCalendarConflictDto`. Wire fields are snake_case; Kotlin properties
camelCase via `@Json(name=...)` where codegen cannot infer.

FR-4. **[CORRECTED]** Provide pure DTO→domain mappers
(`ContentCalendarItemDto.toDomain(): ScheduledContent`) that map unknown enum
strings to `UNKNOWN` (never throw) and tolerate absent optional fields via Kotlin
defaults. **`scheduled_at` is a Unix epoch-seconds integer on the wire**
(verified `src/api/types.ts: ContentCalendarItem.scheduled_at: number`), so the
mapper converts via `Instant.ofEpochSecond(scheduledAt)` — it is **not** an
RFC-3339 string and does **not** flow through `InstantJsonAdapter`. (The shared
`InstantJsonAdapter` may still register globally for other DTOs, but this DTO's
timestamp is a plain numeric field.)

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
showing title, scheduled time, a **content-type** badge (post/broadcast/vod),
status chip (scheduled/overdue/cancelled), and an optional thumbnail (Coil, VOD
items). Tapping a row navigates toward the content/scheduler
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

// [CORRECTED] Fields/enums realigned to the verified web contract
// (src/api/types.ts: ContentCalendarItem). The wire item is keyed by content
// `type` (post|broadcast|vod), NOT a delivery `channel`, and its `status`
// vocabulary is scheduled|overdue|cancelled, NOT a publish lifecycle.
data class ScheduledContent(
    val id: String,
    val type: ContentItemType,          // post | broadcast | vod
    val title: String,
    val status: ScheduledStatus,        // scheduled | overdue | cancelled
    val scheduledAt: Instant,           // from `scheduled_at` (Unix epoch seconds)
    val scheduledDate: LocalDate,       // derived (in effective tz) for grouping
    val timezone: String?,              // IANA tz, if the item carries one
    val localTime: String?,             // server-formatted local time (`local_time`)
    val color: String?,                 // server hint
    val icon: String?,                  // server hint
    val thumbnailUrl: String?,          // VOD-specific (optional)
    val description: String?,           // broadcast-specific (optional)
    val durationSeconds: Long?,         // VOD-specific (optional)
)

enum class ContentItemType { POST, BROADCAST, VOD, UNKNOWN }

enum class ScheduledStatus { SCHEDULED, OVERDUE, CANCELLED, UNKNOWN }

data class DateRange(val from: Instant, val to: Instant) // [from, to)

// [CORRECTED] Only `types` is a server-supported filter (comma-separated
// post,broadcast,vod). There is no server status filter; any status filtering
// is client-side. See Q-2.
data class ContentFilter(
    val types: Set<ContentItemType> = emptySet(),
)
```

### 4.2 DTOs (core-network)

```kotlin
package com.testlogon.android.core.network.contentcalendar

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

// [CORRECTED] Field set verified against src/api/types.ts: ContentCalendarItem.
// scheduled_at is Unix epoch SECONDS (Long), not an Instant string. There is no
// `summary`, `author`, `updated_at`, `channel`, or `scheduled_date` field. The
// item is keyed by `type` (post|broadcast|vod) and carries server `color`/`icon`
// plus type-specific optionals.
@JsonClass(generateAdapter = true)
data class ContentCalendarItemDto(
    val id: String,
    val type: String? = null,                                  // post|broadcast|vod
    val title: String,
    @Json(name = "scheduled_at") val scheduledAt: Long,        // Unix epoch seconds
    val timezone: String? = null,
    @Json(name = "local_time") val localTime: String? = null,
    val status: String? = null,                                // scheduled|overdue|cancelled
    val color: String? = null,
    val icon: String? = null,
    // Post-specific (optional)
    @Json(name = "has_images") val hasImages: Boolean? = null,
    @Json(name = "has_video") val hasVideo: Boolean? = null,
    val visibility: String? = null,
    val locked: Boolean? = null,
    @Json(name = "unlock_price_cents") val unlockPriceCents: Int? = null,
    // Broadcast-specific (optional)
    val description: String? = null,
    @Json(name = "profile_id") val profileId: String? = null,
    @Json(name = "has_announcement") val hasAnnouncement: Boolean? = null,
    // VOD-specific (optional)
    @Json(name = "duration_seconds") val durationSeconds: Long? = null,
    @Json(name = "thumbnail_url") val thumbnailUrl: String? = null,
)

@JsonClass(generateAdapter = true)
data class ContentCalendarConflictDto(
    @Json(name = "item_a_id") val itemAId: String,
    @Json(name = "item_a_type") val itemAType: String? = null,
    @Json(name = "item_b_id") val itemBId: String,
    @Json(name = "item_b_type") val itemBType: String? = null,
    @Json(name = "gap_seconds") val gapSeconds: Long? = null,
    @Json(name = "gap_minutes") val gapMinutes: Long? = null,
)

// [CORRECTED] Real envelope: {items, from_ts, to_ts, count, conflicts}.
// No `next_page` cursor exists on this endpoint.
@JsonClass(generateAdapter = true)
data class ContentCalendarRespDto(
    val items: List<ContentCalendarItemDto>,
    @Json(name = "from_ts") val fromTs: Long? = null,
    @Json(name = "to_ts") val toTs: Long? = null,
    val count: Int? = null,
    val conflicts: List<ContentCalendarConflictDto> = emptyList(),
)
```

`scheduled_at` is a Unix epoch-seconds integer; the mapper converts via
`Instant.ofEpochSecond(...)` (R-3). No `InstantJsonAdapter` is involved for this
DTO — the timestamp is a plain numeric JSON field.

### 4.3 The `ContentCalendarApi` interface

```kotlin
package com.testlogon.android.core.network.contentcalendar

import retrofit2.http.GET
import retrofit2.http.Query

interface ContentCalendarApi {

    /** Scheduled content overlapping [fromTs, toTs). Idempotent GET; not paged. */
    // [CORRECTED] Path is `ui/content-calendar` (full: /ui/content-calendar).
    // Params are from_ts/to_ts (Unix epoch seconds, required) + optional
    // comma-separated `types`. No channel/status/page params exist.
    @GET("ui/content-calendar")
    suspend fun listScheduledContent(
        @Query("from_ts") fromTs: Long,          // Unix epoch seconds, inclusive
        @Query("to_ts") toTs: Long,              // Unix epoch seconds, exclusive
        @Query("types") types: String? = null,   // CSV: post,broadcast,vod
    ): ContentCalendarRespDto
}
```

The exact path and params are **confirmed** against OpenAPI
`GET /ui/content-calendar` (op `content_calendar_ui_content_calendar_get`,
params `from_ts,to_ts,types`) and `src/api/endpoints/content-calendar.ts:
getContentCalendar`. Q-1 is therefore resolved: the path is `ui/content-calendar`,
not flat `content-calendar`.

### 4.4 Mappers

```kotlin
package com.testlogon.android.core.network.contentcalendar

import com.testlogon.android.core.model.contentcalendar.*
import java.time.Instant
import java.time.ZoneId

// [CORRECTED] scheduled_at is Unix epoch seconds; convert with
// Instant.ofEpochSecond. No scheduled_date alternation, no summary/author/
// updated_at, and enums use the real vocabularies.
fun ContentCalendarItemDto.toDomain(deviceZone: ZoneId): ScheduledContent {
    val instant = Instant.ofEpochSecond(scheduledAt)
    val zone = timezone?.let(ZoneId::of) ?: deviceZone
    return ScheduledContent(
        id = id,
        type = type.toContentItemType(),
        title = title,
        status = status.toScheduledStatus(),
        scheduledAt = instant,
        scheduledDate = instant.atZone(zone).toLocalDate(),
        timezone = timezone,
        localTime = localTime,
        color = color,
        icon = icon,
        thumbnailUrl = thumbnailUrl,
        description = description,
        durationSeconds = durationSeconds,
    )
}

private fun String?.toScheduledStatus(): ScheduledStatus = when (this?.lowercase()) {
    "scheduled" -> ScheduledStatus.SCHEDULED
    "overdue" -> ScheduledStatus.OVERDUE
    "cancelled", "canceled" -> ScheduledStatus.CANCELLED
    else -> ScheduledStatus.UNKNOWN
}

private fun String?.toContentItemType(): ContentItemType = when (this?.lowercase()) {
    "post" -> ContentItemType.POST
    "broadcast" -> ContentItemType.BROADCAST
    "vod" -> ContentItemType.VOD
    else -> ContentItemType.UNKNOWN
}
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
                // [CORRECTED] from_ts/to_ts are Unix epoch SECONDS; `types` is a
                // CSV of the requested content types. No channel/status query.
                api.listScheduledContent(
                    fromTs = range.from.epochSecond,
                    toTs = range.to.epochSecond,
                    types = filter.types.takeIf { it.isNotEmpty() }
                        ?.joinToString(",") { it.wire() },
                ).items.map { it.toDomain(zone) }
                 .sortedBy { it.scheduledAt }
            }
        }
}
```

**[CORRECTED]** There is **no** paging cursor on this endpoint — the response
envelope is `{items, from_ts, to_ts, count, conflicts}`, so the prior
"`next_page` cursor / Paging-3 follow-up" note (R-2) is dropped. The full result
for the range is returned in a single response; the repository simply maps and
sorts `items`. (The `conflicts` array is available for a future overlap-warning
UI but is out of scope for this read-only render ticket.)

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
`ScheduledContentRow` renders title, localized time, a `ContentTypeBadge`
(post/broadcast/vod), a `StatusChip(status)` (scheduled/overdue/cancelled,
color-coded), and an optional Coil thumbnail (VOD).

### 4.8 Navigation + Gradle wiring

Route `content_calendar` is added to the authenticated nav graph (AND-024). No new
Gradle dependencies: `core-network` already has Retrofit/Moshi/KSP/Hilt;
`feature-calendar` already has Compose/Hilt/Coil. This ticket adds source files and
a nav entry only.

## 5. API Contract

Base path (`dev`): `http://18.222.237.167:8000/`. **[CORRECTED]** Shapes below are
the **verified** contract from OpenAPI `GET /ui/content-calendar` and
`src/api/types.ts` / `src/api/endpoints/content-calendar.ts`.

**Transport / auth (verified against `src/api/client.ts`):** the web client sends,
on every request, an `Authorization: Bearer <accessToken>` header (from the auth
store) **and** cookies (`credentials: "include"`) **and** an `X-CSRF-Token` header
read from the `ui_csrf` cookie — i.e. it is **not** a pure cookie session; a Bearer
token is also present. The CSRF header is sent on **all** verbs including GET (so
the earlier "GET needs no CSRF" claim in §8 is corrected). OpenAPI additionally
declares optional `X-SESSION-ID` and `X-IMPERSONATION-TOKEN` headers and a
`user_sub` query param on this operation. On `401`, the web client performs **one**
refresh via `POST /ui/session/refresh` (credentials included) and retries; a
second `401` logs out. The Android port supplies these headers globally via the
shared OkHttp interceptors (AND-011/AND-012/AND-013) and does not declare them
per-method. GET is idempotent (bounded backoff per AND-016).

### GET `/ui/content-calendar?from_ts=…&to_ts=…&types=…`
`from_ts`/`to_ts` are **Unix epoch seconds (integers, both required)**; `types` is
an optional **comma-separated** string of `post,broadcast,vod`. Response `200`
(envelope `{items, from_ts, to_ts, count, conflicts}`):
```json
{
  "items": [
    {
      "id": "cnt_4012",
      "type": "post",
      "title": "June product newsletter",
      "scheduled_at": 1781445600,
      "timezone": "America/New_York",
      "local_time": "10:00 AM",
      "status": "scheduled",
      "color": "#3b82f6",
      "icon": "calendar",
      "has_images": true,
      "visibility": "subscribers"
    },
    {
      "id": "cnt_4013",
      "type": "broadcast",
      "title": "Launch teaser",
      "scheduled_at": 1781618400,
      "timezone": null,
      "local_time": null,
      "status": "overdue",
      "color": "#ef4444",
      "icon": "video",
      "description": "Go-live teaser",
      "profile_id": "prf_22"
    },
    {
      "id": "cnt_4014",
      "type": "vod",
      "title": "Welcome clip",
      "scheduled_at": 1781367000,
      "status": "cancelled",
      "color": "#9ca3af",
      "icon": "film",
      "duration_seconds": 95,
      "thumbnail_url": "https://cdn.testlogon.dev/c/4014.png"
    }
  ],
  "from_ts": 1780723200,
  "to_ts": 1783315200,
  "count": 3,
  "conflicts": []
}
```

Notes: `scheduled_at` is **always** a Unix epoch-seconds integer (no
`scheduled_date` ISO variant exists). `type` is `post|broadcast|vod`; `status` is
`scheduled|overdue|cancelled`; unknown strings map to `UNKNOWN`. The
`200` response schema is declared as an open object (`schema: {}`) in OpenAPI, so
the concrete field shape is taken from `src/api/types.ts: ContentCalendarResponse`
/ `ContentCalendarItem` (the authoritative client contract).

**Error envelope:** validation failures return `422` with
`HTTPValidationError` (`{detail: [{loc, msg, type}]}` — the only error response
documented for this operation in OpenAPI). FastAPI `detail` may also be a
`string` or a `{code,...}` object for other statuses (see `normalizeErrorDetail`
in `src/api/client.ts`); it is decoded to a typed `ApiError` by **AND-015** and
surfaced through `ApiResult.Failure` (AND-018). A `401` is intercepted by the
AND-013 `Authenticator` (one refresh via `/ui/session/refresh` + retry) before
propagating; `403` carries a permission/`geo_blocked` `detail`.

The sibling mutating operations confirmed in OpenAPI but **owned by AND-275** are:
`POST /ui/content-calendar/reschedule`, `POST /ui/content-calendar/cancel`, plus
the read helpers `GET /ui/content-calendar/today` and
`GET /ui/content-calendar/conflicts`. This ticket adds **no** mutating endpoints.

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
- **Paging:** **[CORRECTED]** the endpoint is **not** paged — the response is a
  single `{items, from_ts, to_ts, count, conflicts}` envelope with no cursor. All
  items in the requested range arrive in one response; no Paging-3 source is
  needed (R-2 closed).
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
- **Deserialization variance:** **[CORRECTED]** mappers tolerate missing
  type-specific optionals and unknown `type`/`status` strings (→ `UNKNOWN`).
  `scheduled_at` is a required Unix-seconds integer in the contract (there is no
  `scheduled_date` alternation); a payload missing it is a contract violation and
  surfaces as a deterministic decode failure via `ApiResult.Failure`.

## 8. Security & Privacy

- **Authenticated surface:** the content-calendar read requires an authenticated
  session. **[CORRECTED]** Per `src/api/client.ts`, the web client authenticates
  with an `Authorization: Bearer <accessToken>` header **plus** cookies
  (`credentials: include`), not cookies alone. `ContentCalendarApi` adds no manual
  auth headers per-method; identity is injected globally (Bearer/token interceptor
  + persistent cookie jar, AND-011). The read is server-scoped to content the
  principal may see.
- **CSRF:** **[CORRECTED]** the web client sends `X-CSRF-Token` (from the `ui_csrf`
  cookie) on **every** request, including GET — not only on mutations. The Android
  port therefore attaches CSRF globally via AND-012 for all verbs; the earlier
  "GET needs no CSRF" assumption was wrong. Mutating content operations are still
  out of scope (AND-275).
- **Cleartext on dev:** content titles/summaries/thumbnails ride plaintext HTTP on
  the dev host — a known, dev-only risk permitted by the scoped cleartext config
  (AND-006); `staging`/`prod` are HTTPS-only.
- **No payload logging:** content titles and broadcast descriptions are
  potentially sensitive. This ticket adds no body logging; the shared logging interceptor
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
  "Today", status labels, content-type labels) lives in `strings.xml` — no string
  literals in composables — ready for translation.
- **TalkBack:** each `ScheduledContentRow` exposes a merged content description
  combining title, content type, localized time, and status (e.g. "June product
  newsletter, post, scheduled, June 10 at 10:00 AM"). Status chips are not
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
  `content_calendar_item_opened { content_id_hashed, type, status }` on row tap,
  and `content_calendar_load_failed { reason, is_offline }` on failure. **No**
  titles/descriptions or raw ids are logged; ids are hashed/anonymized.
- **Build-time signal:** KSP must generate Moshi adapters for both content-calendar
  DTOs; a missing adapter fails the build (no reflection fallback).

## 11. Testing Strategy

**Unit — mappers & API (core-network, JVM + MockWebServer).** Using the production
Moshi config (incl. `InstantJsonAdapter`):

- **T-1 — `listScheduledContent` query.** [CORRECTED] Issues
  `GET /ui/content-calendar`, sends `from_ts`/`to_ts` (Unix seconds) and a CSV
  `types` query param, decodes the `{items, from_ts, to_ts, count, conflicts}`
  envelope. Asserts verb, `encodedPath == "/ui/content-calendar"`, and each query
  value (e.g. `types=post,broadcast`).
- **T-2 — epoch-seconds mapping + tz derivation.** [CORRECTED] `items[0]`
  (`scheduled_at` epoch seconds + `timezone`) maps to `scheduledAt ==
  Instant.ofEpochSecond(...)` and `scheduledDate` derived in the item tz (no
  off-by-one across the UTC→ET boundary).
- **T-3 — null-timezone fallback.** [CORRECTED] `items[1]` (`timezone: null`)
  derives `scheduledDate` in the device zone; `localTime`/`description` optionals
  map through; status `overdue` → `OVERDUE`.
- **T-4 — enum tolerance.** [CORRECTED] `status:"cancelled"` → `CANCELLED`;
  `type:"vod"` → `VOD`; unknown `type:"reel"` → `UNKNOWN`; missing `status` →
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
  time, content type, and status — satisfying the backlog "Content calendar renders."
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
- **R-2 Envelope shape.** [RESOLVED] Verified: the response is the fixed envelope
  `{items, from_ts, to_ts, count, conflicts}` (`src/api/types.ts:
  ContentCalendarResponse`). There is no bare array, no `next_page`, and no
  offset/limit paging. Guarded by T-1.
- **R-3 Timestamp form.** [RESOLVED] Verified: `scheduled_at` is a Unix
  epoch-seconds **integer** (`ContentCalendarItem.scheduled_at: number`); there is
  no `scheduled_date` ISO variant. The mapper uses `Instant.ofEpochSecond` and
  derives `LocalDate` in the item `timezone` when present, device tz otherwise.
  (Epoch seconds are absolute/UTC by definition, so the "is it UTC?" question is
  moot.) Guarded by T-2/T-3.
- **R-4 Read-only boundary.** This view is display-only; create/edit is AND-275.
  Risk of scope creep into scheduling. Mitigation: row tap only navigates; no
  mutation endpoints declared here.
- **R-5 Unreliable dev host.** Loads may time out/flap. Mitigation: robust
  offline/stale/error states + Retry + bounded backoff (AND-016).
- **Q-1** [RESOLVED] Endpoint path is **`/ui/content-calendar`** (Retrofit
  relative `ui/content-calendar`) — confirmed in OpenAPI and
  `src/api/endpoints/content-calendar.ts`. Not flat `content-calendar`.
- **Q-2** [RESOLVED] The only server-supported filter is **`types`** (CSV of
  `post,broadcast,vod`). There is **no** server `status` filter, so any status
  filtering must be **client-side** in the repository/ViewModel.
- **Q-3** [RESOLVED] Vocabularies (from `src/api/types.ts`): item `type` =
  `post|broadcast|vod`; `status` = `scheduled|overdue|cancelled`. There is no
  delivery "channel" concept. Unknown strings map to `UNKNOWN`.
- **Q-4** Default period: current month vs current week? *Proposed:* current month
  in device tz, converting month bounds to `from_ts`/`to_ts` epoch seconds.
  **Open** — the web reference computes the range from caller-supplied `fromTs`/
  `toTs` and does not pin a default month vs week in `content-calendar.ts`; the
  Android default is a product choice (see §16 Open assumptions).

## 14. Acceptance Criteria

- **AC-1 (backlog).** **Content calendar renders.** With a session (or fake
  ViewModel), `ContentCalendarScreen` fetches scheduled content for the selected
  period and renders it grouped by date with sticky day headers and per-item rows
  (title, time, content type, status), proven by Compose UI test T-13.
- **AC-2.** [CORRECTED] `ContentCalendarApi.listScheduledContent` issues
  `GET /ui/content-calendar` with `from_ts`/`to_ts` (Unix epoch seconds) and an
  optional CSV `types` query param, and decodes the
  `{items, from_ts, to_ts, count, conflicts}` envelope (T-1).
- **AC-3.** [CORRECTED] `ContentCalendarItemDto.toDomain` maps `scheduled_at`
  (Unix epoch seconds) losslessly into `ScheduledContent.scheduledAt` and derives
  `scheduledDate` in the effective tz with no off-by-one (T-2, T-3).
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

- Domain types (`ScheduledContent`, `ContentItemType`, `ScheduledStatus`,
  `DateRange`, `ContentFilter`) in `core-model`
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

## 16. Citations & Assumption Audit

Each key technical claim below is paired with a VERDICT and an exact SOURCE
pointer. Sources: OpenAPI index/spec (`reference/openapi.index.txt`,
`reference/openapi.pretty.json`) and frontend reference (`reference/src/...`).

1. **Endpoint path is `/ui/content-calendar`** (Retrofit relative
   `ui/content-calendar`). VERDICT: **Corrected** (spec originally said flat
   `content-calendar`). SOURCE: OpenAPI `GET /ui/content-calendar`
   (op `content_calendar_ui_content_calendar_get`);
   `src/api/endpoints/content-calendar.ts: getContentCalendar`
   (`api.get("/ui/content-calendar", …)`).
2. **HTTP method is GET, idempotent read.** VERDICT: **Verified**. SOURCE: OpenAPI
   `GET /ui/content-calendar`; `src/api/endpoints/content-calendar.ts:
   getContentCalendar`.
3. **Query params are `from_ts` + `to_ts` (Unix epoch seconds, integer, both
   required) and optional `types` (CSV of `post,broadcast,vod`).** VERDICT:
   **Corrected** (spec said `from`/`to` RFC-3339 + `channel`/`status`/`page`).
   SOURCE: OpenAPI `GET /ui/content-calendar` params `from_ts,to_ts,types`
   (`from_ts`/`to_ts` `type: integer`, "Unix seconds"; `types` "Comma-separated
   content types: post,broadcast,vod"); `src/api/endpoints/content-calendar.ts:
   getContentCalendar` (builds `from_ts`/`to_ts`/`types` params).
4. **No paging cursor; response envelope is
   `{items, from_ts, to_ts, count, conflicts}`.** VERDICT: **Corrected** (spec said
   `{items, next_page}` cursor envelope). SOURCE:
   `src/api/types.ts: ContentCalendarResponse`.
5. **Item shape `ContentCalendarItem`: `id`, `type` (post|broadcast|vod),
   `title`, `scheduled_at` (number = Unix seconds), `timezone`, `local_time`,
   `status` (scheduled|overdue|cancelled), `color`, `icon`, plus type-specific
   optionals (`has_images`, `description`, `duration_seconds`, `thumbnail_url`,
   …).** VERDICT: **Corrected** (spec invented `summary`, `author`, `updated_at`,
   `channel`, `scheduled_date`, and a publish-lifecycle status). SOURCE:
   `src/api/types.ts: ContentCalendarItem`.
6. **`scheduled_at` is a Unix epoch-seconds integer (not an RFC-3339 string, no
   `scheduled_date` ISO variant).** VERDICT: **Corrected**. SOURCE:
   `src/api/types.ts: ContentCalendarItem.scheduled_at: number`; OpenAPI param
   wording confirms epoch seconds for the matching range params.
7. **Content `type` vocabulary = `post | broadcast | vod`.** VERDICT: **Corrected**
   (spec used delivery channels email/sms/push/etc.). SOURCE:
   `src/api/types.ts: ContentItemType`.
8. **`status` vocabulary = `scheduled | overdue | cancelled`.** VERDICT:
   **Corrected** (spec used draft/scheduled/publishing/published/failed/canceled).
   SOURCE: `src/api/types.ts: ContentCalendarItem.status`.
9. **Auth: web client sends `Authorization: Bearer <accessToken>` AND cookies
   (`credentials: include`) AND `X-CSRF-Token` (from `ui_csrf` cookie) on every
   request.** VERDICT: **Corrected** (spec described a pure cookie session with no
   Authorization header). SOURCE: `src/api/client.ts` (the `api<T>()` core sets
   `Authorization: Bearer`, `credentials: "include"`, and `X-CSRF-Token`).
10. **CSRF is sent on GET too, not only mutations.** VERDICT: **Corrected** (spec
    said GET needs no CSRF). SOURCE: `src/api/client.ts` (CSRF header set
    unconditionally before the fetch, for all verbs).
11. **401 handling: one refresh via `POST /ui/session/refresh`, then retry; second
    401 logs out.** VERDICT: **Verified** (consistent with the spec's AND-013
    one-refresh model). SOURCE: `src/api/client.ts: refreshSession` + the 401
    branch.
12. **OpenAPI also declares optional `X-SESSION-ID`, `X-IMPERSONATION-TOKEN`
    headers and a `user_sub` query param on this op.** VERDICT: **Verified**.
    SOURCE: OpenAPI `GET /ui/content-calendar` params
    `…,user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN`; `X-IMPERSONATION-TOKEN` also
    set in `src/api/client.ts`.
13. **Error model: `422` → `HTTPValidationError` (`{detail:[{loc,msg,type}]}`);
    `detail` may also be a string or `{code,...}` object.** VERDICT: **Verified**.
    SOURCE: OpenAPI `GET /ui/content-calendar` `resp 422:HTTPValidationError`;
    `src/api/client.ts: normalizeErrorDetail`.
14. **Sibling mutating ops belong to AND-275:
    `POST /ui/content-calendar/reschedule`, `POST /ui/content-calendar/cancel`;
    read helpers `GET /ui/content-calendar/today`, `…/conflicts`.** VERDICT:
    **Verified**. SOURCE: OpenAPI lines for those paths;
    `src/api/endpoints/content-calendar.ts` (`rescheduleCalendarItem`,
    `cancelCalendarItem`, `getTodayAgenda`, `getConflicts`).
15. **`conflicts` array shape `{item_a_id, item_a_type, item_b_id, item_b_type,
    gap_seconds, gap_minutes}`.** VERDICT: **Verified**. SOURCE:
    `src/api/types.ts: ContentCalendarConflict`.
16. **Stack pins (Kotlin 2.0.21, Compose/M3, Retrofit 2.11.0, OkHttp 4.12.0,
    Moshi 1.15.x KSP, Coil, core-library desugaring for `java.time`, minSdk 24,
    compile/target 35, AGP 8.7.3, Gradle 8.9, JDK 17).** VERDICT:
    **Unverified-assumption** (no build files in the provided sources). These are
    inherited project conventions; framework ref for desugaring `java.time`:
    `developer.android.com/studio/write/java8-support` (framework ref).
17. **Compose `LazyColumn` `stickyHeader` for date-grouped agenda layout.**
    VERDICT: **Unverified-assumption** (UI design choice; not in sources).
    Framework ref: `developer.android.com/jetpack/compose/lists#sticky-headers`
    (framework ref).
18. **`collectAsStateWithLifecycle` + `SavedStateHandle` for state/period
    persistence.** VERDICT: **Unverified-assumption** (Android architecture
    choice). Framework ref:
    `developer.android.com/topic/libraries/architecture/viewmodel/viewmodel-savedstate`
    (framework ref).

### Corrections made

- **Path:** `content-calendar` → `ui/content-calendar` (full `/ui/content-calendar`)
  — §3 FR-2, §4.3, §5, §13 Q-1, §14 AC-2, §11 T-1.
- **Query params:** dropped `from`/`to` (RFC-3339), `channel`, `status`, `page`;
  replaced with `from_ts`/`to_ts` (Unix epoch seconds) + CSV `types` — §3 FR-2,
  §4.3, §4.5, §5, §13 Q-2, §14 AC-2.
- **Response envelope:** `{items, next_page}` cursor → `{items, from_ts, to_ts,
  count, conflicts}` (no paging) — §3 FR-3, §4.2, §4.5, §5, §6, §13 R-2.
- **Item fields:** removed `summary`/`author`/`updated_at`/`channel`/
  `scheduled_date`; added real fields (`type`, `local_time`, `color`, `icon`,
  type-specific optionals) — §4.1, §4.2, §4.4, §5, §7, §8 (privacy wording),
  §9 (TalkBack), §10 (analytics).
- **Timestamp:** `scheduled_at` Instant/RFC-3339 (+`scheduled_date` fallback) →
  Unix epoch seconds via `Instant.ofEpochSecond` — §3 FR-4, §4.2, §4.4, §5, §7,
  §13 R-3, §14 AC-3, §11 T-2/T-3.
- **Enums:** `ContentChannel`(email/sms/…)/`PublishStatus`(draft/publishing/…) →
  `ContentItemType`(post/broadcast/vod)/`ScheduledStatus`(scheduled/overdue/
  cancelled) — §4.1, §4.4, §11 T-4, §15.
- **Auth/CSRF:** pure cookie session → Bearer token + cookies + `X-CSRF-Token` on
  all verbs (incl. GET) — §5, §8.
- **Open questions:** Q-1/Q-2/Q-3 resolved; R-2/R-3 marked resolved.

### Open assumptions

- **Default period (Q-4):** current month vs week is **not** pinned by the web
  reference (`content-calendar.ts` takes caller-supplied `fromTs`/`toTs`); the
  Android default (current month in device tz) is a product decision, not a
  verified contract fact.
- **200 response schema is open (`schema: {}`) in OpenAPI**, so the concrete field
  shape is taken from `src/api/types.ts` (the TypeScript client contract), which is
  treated as authoritative but is not formally pinned in the OpenAPI document.
- **Stale-cache (`isStale`) behavior** and the AND-045-style retain-last-good
  policy are an Android UX decision, not derived from the backend or web client.
- **Build/toolchain pins (item 16)** and the framework choices (items 17–18) are
  not present in the provided sources; treated as inherited project conventions.
- **Whether the `types` filter and `status`/type vocabularies are exhaustive** at
  runtime cannot be guaranteed; unknown values are defended via `UNKNOWN` mapping.

## 17. Test Plan

Test target keys: **JVM** (local unit/Robolectric, no device); **emulator**
(headless AVD `test35`, x86_64, API 35); **device** (physical Samsung Galaxy A15
5G, SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a). For this read-only,
non-hardware feature most cases run on JVM/emulator; one ABI/API-parity case is
called out for the physical device.

- **TC-AND-274-01 — Happy-path query + decode.**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: MockWebServer enqueues a `200` with the §5 envelope (3 items,
  `conflicts: []`).
  Steps: call `ContentCalendarApi.listScheduledContent(fromTs, toTs,
  types="post,broadcast")`; capture `RecordedRequest`.
  Expected: method `GET`; `encodedPath == "/ui/content-calendar"`; query has
  `from_ts`/`to_ts` (epoch seconds) and `types=post,broadcast`; body decodes to
  `ContentCalendarRespDto` with 3 items and `count == 3`.
  Traces: AC-2.

- **TC-AND-274-02 — Epoch-seconds + timezone mapping (no off-by-one).**
  Type: unit (JVM). Target: JVM.
  Preconditions: `items[0]` has `scheduled_at` epoch seconds late-evening UTC and
  `timezone: "America/New_York"` (so ET date < UTC date).
  Steps: map via `ContentCalendarItemDto.toDomain(deviceZone)`.
  Expected: `scheduledAt == Instant.ofEpochSecond(raw)`; `scheduledDate` equals the
  ET calendar date, not the UTC one.
  Traces: AC-3.

- **TC-AND-274-03 — Null-timezone falls back to device zone.**
  Type: unit (JVM). Target: JVM.
  Preconditions: `items[1]` has `timezone: null`.
  Steps: map with a fixed device `ZoneId`.
  Expected: `scheduledDate` derived in device zone; `localTime`/`description`
  optionals carried; `status "overdue" → OVERDUE`.
  Traces: AC-3, AC-4.

- **TC-AND-274-04 — Enum + optional tolerance (never throws).**
  Type: unit (JVM). Target: JVM.
  Preconditions: items with `type:"vod"`/`status:"cancelled"`, an unknown
  `type:"reel"`, and one with `status` absent.
  Steps: map each.
  Expected: `VOD`/`CANCELLED`; unknown `type → UNKNOWN`; missing `status →
  UNKNOWN`; no exception.
  Traces: AC-4.

- **TC-AND-274-05 — Repository success: map + ascending sort.**
  Type: unit (JVM). Target: JVM.
  Preconditions: fake `ContentCalendarApi` returns 3 items out of time order.
  Steps: call `repository.scheduledContent(range, ContentFilter())`.
  Expected: `ApiResult.Success` whose list is sorted ascending by `scheduledAt`;
  `from_ts`/`to_ts` passed as `range.from.epochSecond`/`range.to.epochSecond`.
  Traces: AC-5.

- **TC-AND-274-06 — Repository failure mapping (offline/transport).**
  Type: unit (JVM). Target: JVM.
  Preconditions: fake API throws `UnknownHostException` (and a separate case:
  `IOException`).
  Steps: call the repository.
  Expected: `ApiResult.Failure` classified as offline/transport (AND-017/018); no
  exception escapes.
  Traces: AC-5.

- **TC-AND-274-07 — 422 validation error decode.**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: MockWebServer enqueues `422` with
  `{"detail":[{"loc":["query","from_ts"],"msg":"field required","type":"missing"}]}`.
  Steps: call the repository.
  Expected: `ApiResult.Failure` carrying a typed `ApiError` whose message derives
  from `detail[].msg` (AND-015); not swallowed, not crashed.
  Traces: AC-5.

- **TC-AND-274-08 — 401 triggers single refresh + retry.**
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: enqueue `401`, then (refresh succeeds) a `200`; AND-013
  authenticator wired.
  Steps: call the repository once.
  Expected: exactly one refresh attempt, original request retried, final
  `ApiResult.Success`; a second consecutive `401` instead yields `Failure` routing
  to login.
  Traces: AC-5, AC-8.

- **TC-AND-274-09 — ViewModel Loading → Content, grouped & ordered.**
  Type: unit (JVM, `runTest` + fake repo). Target: JVM.
  Preconditions: repo returns items spanning 3 distinct dates.
  Steps: collect `uiState` from init.
  Expected: first `Loading`, then `Content` with `days` ascending by date and each
  day's items ascending by time; item count matches input.
  Traces: AC-1, AC-6.

- **TC-AND-274-10 — ViewModel Empty / Error+Offline / retry / period change.**
  Type: unit (JVM, `runTest`). Target: JVM.
  Preconditions: parametrized fake repo (empty list; failure; failure→success on
  retry; period switch).
  Steps: drive `retry()`, `onPeriod(next)`, `onToday()`; recreate ViewModel with
  the saved `SavedStateHandle`.
  Expected: empty→`Empty`; failure→`Error`/offline; `retry()` recovers to
  `Content`; `onPeriod`/`onToday` re-query the new range; restored period survives
  via `SavedStateHandle`.
  Traces: AC-6.

- **TC-AND-274-11 — Stale fallback retains last-good.**
  Type: unit (JVM, `runTest`). Target: JVM.
  Preconditions: one successful load for a period, then a transient failure for the
  same period.
  Steps: trigger the second load.
  Expected: state is `Content(isStale = true)` with prior items retained (not
  blanked).
  Traces: AC-6.

- **TC-AND-274-12 — Screen renders grouped content (ACCEPTANCE).**
  Type: Compose-UI (instrumented). Target: emulator (`test35`).
  Preconditions: fake ViewModel emits `Content` with sticky-headed days.
  Steps: launch `ContentCalendarScreen`; assert nodes.
  Expected: sticky date headers present; one row per item showing title, localized
  time, content-type badge (post/broadcast/vod), and status chip
  (scheduled/overdue/cancelled). Satisfies backlog "Content calendar renders."
  Traces: AC-1, AC-7.

- **TC-AND-274-13 — State surfaces + navigation hand-off.**
  Type: Compose-UI (instrumented). Target: emulator (`test35`).
  Preconditions: fake ViewModel toggles Loading/Empty/Error/Offline; then Content.
  Steps: assert each state's composable (spinner; empty message "No scheduled
  content for this period"; error message + Retry invoking `retry`; offline state);
  tap a row.
  Expected: each state renders its AND-021 composable; row tap invokes
  `onItemClick(id)` (AND-275 hand-off).
  Traces: AC-7, AC-1.

- **TC-AND-274-14 — Accessibility (TalkBack semantics, targets, color-safe).**
  Type: Compose-UI / instrumented a11y. Target: emulator (`test35`).
  Preconditions: `Content` with one item per status/type.
  Steps: inspect semantics tree; enable font scaling 2x and landscape.
  Expected: each row exposes a merged content description (title, type, time,
  status); status chips carry text/icon (not color-only, WCAG 1.4.1); date headers
  have `heading()` semantics; touch targets ≥48dp; layout reflows without
  truncation.
  Traces: AC-1, AC-7.

- **TC-AND-274-15 — Auth headers present; no per-method/second client.**
  Type: contract/MockWebServer (JVM) + review check. Target: JVM.
  Preconditions: app-wired OkHttp with global Bearer/cookie/CSRF interceptors;
  authenticated session fixture.
  Steps: issue the GET; inspect `RecordedRequest` headers; assert DI graph.
  Expected: request carries `Authorization: Bearer …`, session cookie(s), and
  `X-CSRF-Token`; `ContentCalendarApi` declares no per-method auth/cookie/CSRF
  headers; `@Singleton` provider uses the shared `Retrofit` (no second
  `OkHttpClient`/`Retrofit`).
  Traces: AC-8.

- **TC-AND-274-16 — ABI/API parity smoke (real device).**
  Type: instrumented/e2e. Target: **device** (must run on physical SM-A156U,
  arm64-v8a, API 34 — to catch arm64-vs-x86 desugaring/`java.time` and
  API-34-vs-35 differences not exercised by the x86_64 API-35 emulator).
  Preconditions: debug build installed via adb on serial R5CX821TA9R; MockWebServer
  or dev backend reachable.
  Steps: open the content calendar, scroll the agenda, rotate, tap an item.
  Expected: dates/times group and format identically to emulator results (no
  desugaring/tz off-by-one on arm64/API 34); navigation hand-off works; no crash.
  Traces: AC-1, AC-3, AC-10.

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
| --- | --- |
| AC-1 (Content calendar renders) | TC-09, TC-12, TC-13, TC-14, TC-16 |
| AC-2 (GET /ui/content-calendar with from_ts/to_ts/types, decode envelope) | TC-01 |
| AC-3 (epoch-seconds → scheduledAt + scheduledDate, no off-by-one) | TC-02, TC-03, TC-16 |
| AC-4 (unknown enums / missing optionals tolerated) | TC-03, TC-04 |
| AC-5 (repository ApiResult: sorted success; typed failures) | TC-05, TC-06, TC-07, TC-08 |
| AC-6 (ViewModel StateFlow cycle, grouping, retry, period, SavedStateHandle) | TC-09, TC-10, TC-11 |
| AC-7 (loading/empty/error/offline composables; row-tap nav) | TC-12, TC-13, TC-14 |
| AC-8 (Hilt @Singleton on shared Retrofit; no per-method auth/CSRF, no 2nd client) | TC-08, TC-15 |
| AC-9 (route `content_calendar` registered + reachable) | TC-13 (nav hand-off); manual nav-graph check |
| AC-10 (CI green; builds clean; instrumented pass on emulator) | TC-12..TC-14 (emulator), TC-16 (device) |
