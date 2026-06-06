---
id: AND-065
title: Dashboard data layer
milestone: M2
epic: E09
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-027]
blocks: [AND-066, AND-068]
---

# AND-065 — Dashboard data layer

## 1. Overview & Goal

This ticket builds the **headless data layer for the Dashboard feature**: the
Retrofit service `DashboardApi`, the Moshi DTOs that mirror the web reference
`frontend/src/api/endpoints/dashboard.ts`, the domain model the rest of the app
consumes, and the `DashboardRepository` that fetches the dashboard payload, maps
it to domain, and returns it wrapped in `ApiResult<T>`.

Scope, verbatim from the backlog: *`DashboardApi` + DTOs from `dashboard.ts`;
repository.* The single acceptance criterion is: *Dashboard payload loads + maps
to domain (tested).*

This is the seam between transport and presentation. It owns: the typed HTTP
interface for the dashboard endpoint(s); the wire DTOs and their KSP-generated
Moshi adapters; the domain model (`Dashboard` and its earnings/analytics/broadcast/milestone
value types — see §5 for the verified shape); the
DTO→domain mapping function; and the repository that orchestrates the call,
applies `ApiResult` wrapping (AND-018), uses the IO dispatcher, and exposes a
suspend `fun` plus a `Flow` for refreshable reads.

It deliberately does **not** own: the `DashboardViewModel`/`StateFlow<UiState>`
(AND-068), any Compose UI or widget composables (AND-066), the loading/empty/
error/offline state composables (AND-069), the cookie jar / CSRF / 401-refresh
plumbing (AND-011/012/013, inherited via the shared client), or the `ApiError`
detail mapping (AND-015). Those are consumed or inherited, not redefined here.

The deliverable: a compiling `DashboardApi`, its DTOs + domain model + mapper,
`DashboardRepository` with a Hilt binding, and a JVM test suite proving the
payload deserializes and maps to domain correctly via `MockWebServer`.

## 2. Context & References

- **Repo / location:** `spannella/testlogon`, monorepo subfolder `android/`,
  branch `android-port`. Transport (`DashboardApi`, DTOs) lands in **`core-network`**
  and **`core-model`**; the domain model + `DashboardRepository` land in
  **`core-data`** (or `feature-dashboard`'s data sub-package if the team keeps
  feature repositories co-located — default here is `core-data`).
- **Canonical package:** `com.testlogon.android` everywhere.
- **Stack pins relevant here:** Kotlin 2.0.21, Retrofit **2.11.0**, OkHttp
  **4.12.0**, Moshi **1.15.x** (codegen via KSP), Hilt (KSP), Coroutines/Flow,
  JDK 17, minSdk 24 / compileSdk 35.
- **Module layering:** `app -> feature-* -> core-*`. `DashboardApi` (core-network)
  consumes DTOs from `core-model`; `DashboardRepository` (core-data) consumes
  `DashboardApi` + the mapper and returns domain types wrapped in `ApiResult`. No
  `feature-*`/`app` symbols leak downward.
- **Upstream dependency — AND-027 (AuthApi / session endpoints):** establishes the
  Retrofit/Hilt patterns this ticket mirrors (suspend methods, relative paths with
  no leading slash, singleton provider on the shared Retrofit). The dashboard
  endpoint is **authenticated** — it relies on the session cookies and CSRF
  established by the auth flow that AND-027 fronts. `me()` (AND-027) gates access
  upstream of any dashboard fetch.
- **Transitive upstream:** AND-010 (Retrofit + Moshi), AND-009 (shared
  `OkHttpClient`, ~20s timeouts, redacting logging), AND-016 (bounded backoff for
  idempotent GETs), AND-018 (`ApiResult<T>`), AND-015 (`ApiError`/`detail`
  mapping), AND-011/012/013 (cookie jar, CSRF, 401-refresh). Dev base URL:
  `http://18.222.237.167:8000/`.
- **Web reference (authoritative for shapes):** `frontend/src/api/endpoints/
  dashboard.ts` for endpoint paths and request/response, `frontend/src/api/
  types.ts` for the TS types this DTO set mirrors. OpenAPI at `/openapi.json` is
  the tiebreaker on exact field names/nullability.
- **Backend:** FastAPI + DynamoDB; dev host is plaintext HTTP and unreliable —
  design for timeouts, bounded backoff (idempotent GET), and offline/stale UI
  states surfaced to AND-068.

## 3. Functional Requirements

FR-1. Declare a Retrofit interface `DashboardApi` exposing the dashboard read
operation `getDashboard` as a `suspend` GET returning a `DashboardSummaryDto`.

FR-2. The endpoint path/verb match the web reference and `/openapi.json` exactly.
**Verified:** the read operation is `GET ui/dashboard/summary` (relative, no
leading slash) — confirmed in `src/api/endpoints/dashboard.ts: getDashboardSummary`
(`api.get<DashboardSummary>("/ui/dashboard/summary")`) and OpenAPI
`GET /ui/dashboard/summary` (op `dashboard_summary_ui_dashboard_summary_get`,
tag `creator-dashboard`). There is **no** plain `GET /ui/dashboard` endpoint; the
earlier draft path `ui/dashboard` was incorrect and is corrected here. A separate
`POST ui/dashboard/refresh` exists (server-side refresh trigger) — see FR-11.

FR-3. Define Moshi `@JsonClass(generateAdapter = true)` DTOs mirroring
`src/api/types.ts: DashboardSummary` (verified): a top-level `DashboardSummaryDto`
plus nested `DashboardEarningsBreakdownDto`, `DashboardTopContentItemDto`, and
`DashboardActiveBroadcastDto`. (`DashboardMilestone` is returned by the *separate*
`GET ui/milestones` endpoint, not embedded in the summary except as
`recent_milestones`.) Snake_case wire fields map via `@Json(name = ...)`. Unknown
keys are ignored; absent optional fields fall back to Kotlin defaults.

FR-4. Define an immutable domain model `Dashboard` (and its nested types) free of
serialization annotations, expressing only what the UI needs (AND-066/068).

FR-5. Provide a pure mapper `fun DashboardSummaryDto.toDomain(): Dashboard` that is
total (never throws on absent optionals), defaults missing collections to empty,
and normalizes nullable wire fields into non-null domain fields where the UI
requires them.

FR-6. Declare `DashboardRepository` (interface + impl) with:
`suspend fun getDashboard(forceRefresh: Boolean = false): ApiResult<Dashboard>`
and `fun dashboard(): Flow<ApiResult<Dashboard>>` for refreshable streaming reads.

FR-7. The repository wraps the API call in `ApiResult` (AND-018): success →
`ApiResult.Success(dashboard)`; non-2xx → `ApiResult.Error(ApiError)` via AND-015
mapping; transport failure → `ApiResult.Error` carrying a network/offline marker.

FR-8. The repository invokes the API on an injected IO dispatcher
(`@IoDispatcher CoroutineDispatcher`); it imposes no `Main` work.

FR-9. The dashboard GET is idempotent and therefore eligible for AND-016 bounded
backoff (inherited from the shared client tagging mechanism); the repository adds
no custom retry loop of its own.

FR-10. Hilt: `@Provides @Singleton fun provideDashboardApi(retrofit: Retrofit)`
and an `@Binds` for `DashboardRepository -> DashboardRepositoryImpl`.

FR-11. No caching (Room/DataStore) is in scope. The `Flow` emits live fetch
results only; offline/stale persistence, if needed, is a later ticket. The
repository must expose enough error typing for AND-068 to render offline/stale UI.
**Refresh semantics (verified):** unlike the earlier draft's "pure no-op hint", a
real `POST ui/dashboard/refresh` endpoint exists and the web client calls it on
the explicit Refresh button, then re-fetches the summary (`CreatorDashboard.tsx`).
`getDashboard(forceRefresh = true)` SHOULD, when wired by AND-068, call
`api.refreshDashboard()` then `api.getDashboard()`; without that wiring it remains a
plain re-fetch. The web also polls the summary every 60s (`refetchInterval`),
informing AND-068's refresh cadence (not implemented in this headless layer).

## 4. Technical Design

Transport in `core-network`; DTOs in `core-model`; domain + mapper + repository in
`core-data`.

### 4.1 The `DashboardApi` interface

`core-network/src/main/kotlin/com/testlogon/android/core/network/dashboard/DashboardApi.kt`

```kotlin
package com.testlogon.android.core.network.dashboard

import com.testlogon.android.core.model.dashboard.DashboardSummaryDto
import retrofit2.http.GET
import retrofit2.http.POST

interface DashboardApi {

    /**
     * Authenticated creator dashboard summary. Idempotent GET.
     * Path verified against src/api/endpoints/dashboard.ts and OpenAPI
     * GET /ui/dashboard/summary.
     */
    @GET("ui/dashboard/summary")
    suspend fun getDashboard(): DashboardSummaryDto

    /**
     * Optional server-side refresh trigger (web calls this then refetches the
     * summary). Returns { ok, message, refreshed_at } per dashboard.ts.
     * Include only if AND-068's pull-to-refresh wires through to it (see FR-11).
     */
    @POST("ui/dashboard/refresh")
    suspend fun refreshDashboard(): RefreshAck
}
```

### 4.2 Wire DTOs (`core-model`)

`core-model/src/main/kotlin/com/testlogon/android/core/model/dashboard/DashboardSummaryDto.kt`

> **Corrected.** The earlier draft invented a `user`/`stats`/`widgets`/
> `quick_links` shape. The real payload (verified against
> `src/api/types.ts: DashboardSummary` and its nested interfaces) is a
> **creator earnings/analytics dashboard**. Fields below mirror that interface
> exactly. Note the OpenAPI response schema for this endpoint is untyped
> (`schema: {}`), so `types.ts` is the authoritative contract.

```kotlin
package com.testlogon.android.core.model.dashboard

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
data class DashboardSummaryDto(
    @Json(name = "today_earnings_cents") val todayEarningsCents: Long = 0,
    @Json(name = "earnings_breakdown") val earningsBreakdown: DashboardEarningsBreakdownDto = DashboardEarningsBreakdownDto(),
    @Json(name = "period_views") val periodViews: Long = 0,
    @Json(name = "period_revenue_cents") val periodRevenueCents: Long = 0,
    @Json(name = "total_subscribers") val totalSubscribers: Long = 0,
    @Json(name = "top_content") val topContent: List<DashboardTopContentItemDto> = emptyList(),
    @Json(name = "active_broadcasts") val activeBroadcasts: List<DashboardActiveBroadcastDto> = emptyList(),
    @Json(name = "recent_milestones") val recentMilestones: List<DashboardMilestoneDto> = emptyList(),
    @Json(name = "currency") val currency: String = "USD",
    // generated_at is a UNIX EPOCH NUMBER in the wire contract (types.ts: number),
    // NOT an ISO-8601 string. Decode as Long, convert in the mapper.
    @Json(name = "generated_at") val generatedAt: Long? = null,
    @Json(name = "warnings") val warnings: List<String> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class DashboardEarningsBreakdownDto(
    @Json(name = "subscriptions") val subscriptions: Long = 0,
    @Json(name = "tips") val tips: Long = 0,
    @Json(name = "unlocks") val unlocks: Long = 0,
    @Json(name = "vod_purchases") val vodPurchases: Long = 0,
    @Json(name = "other") val other: Long = 0,
)

@JsonClass(generateAdapter = true)
data class DashboardTopContentItemDto(
    @Json(name = "content_id") val contentId: String,
    @Json(name = "content_type") val contentType: String,
    @Json(name = "title") val title: String,
    @Json(name = "views") val views: Long = 0,
    @Json(name = "revenue_cents") val revenueCents: Long = 0,
)

@JsonClass(generateAdapter = true)
data class DashboardActiveBroadcastDto(
    @Json(name = "session_id") val sessionId: String,
    @Json(name = "status") val status: String,
    @Json(name = "name") val name: String? = null,
    @Json(name = "started_at") val startedAt: String? = null, // ISO string, per types.ts
)

// Returned both as DashboardSummary.recent_milestones and (full list) by
// GET ui/milestones. Shape from types.ts: DashboardMilestone.
@JsonClass(generateAdapter = true)
data class DashboardMilestoneDto(
    @Json(name = "milestone_id") val milestoneId: String,
    @Json(name = "user_id") val userId: String,
    @Json(name = "metric") val metric: String,
    @Json(name = "threshold") val threshold: Long = 0,
    @Json(name = "current_value") val currentValue: Long = 0,
    @Json(name = "formatted") val formatted: String,
    @Json(name = "achieved_at") val achievedAt: Long = 0,    // epoch number
    @Json(name = "acknowledged") val acknowledged: Boolean = false,
)

// POST ui/dashboard/refresh response, per dashboard.ts.
@JsonClass(generateAdapter = true)
data class RefreshAck(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "message") val message: String? = null,
    @Json(name = "refreshed_at") val refreshedAt: Long? = null, // epoch number
)
```

The field set is reconciled against `types.ts: DashboardSummary` and its nested
interfaces (`DashboardEarningsBreakdown`, `DashboardTopContentItem`,
`DashboardActiveBroadcast`, `DashboardMilestone`). Money fields are integer cents;
`generated_at`/`achieved_at`/`refreshed_at` are epoch numbers;
`active_broadcasts[].started_at` is an ISO string. Adding/removing a field is a
local change confined to this DTO set + mapper + fixtures.

### 4.3 Domain model (`core-data` or `core-model`)

`com/testlogon/android/core/model/dashboard/Dashboard.kt`

```kotlin
package com.testlogon.android.core.model.dashboard

import java.time.Instant

data class Dashboard(
    val todayEarningsCents: Long,
    val earningsBreakdown: EarningsBreakdown,
    val periodViews: Long,
    val periodRevenueCents: Long,
    val totalSubscribers: Long,
    val topContent: List<TopContentItem>,
    val activeBroadcasts: List<ActiveBroadcast>,
    val recentMilestones: List<Milestone>,
    val currency: String,
    val generatedAt: Instant?,   // null when absent
    val warnings: List<String>,  // partial-failure notices from backend
)

data class EarningsBreakdown(
    val subscriptions: Long, val tips: Long, val unlocks: Long,
    val vodPurchases: Long, val other: Long,
)
data class TopContentItem(
    val contentId: String, val contentType: String, val title: String,
    val views: Long, val revenueCents: Long,
)
data class ActiveBroadcast(
    val sessionId: String, val status: String, val name: String?,
    val startedAt: Instant?,
)
data class Milestone(
    val milestoneId: String, val metric: String, val threshold: Long,
    val currentValue: Long, val formatted: String, val achievedAt: Instant?,
    val acknowledged: Boolean,
)
```

### 4.4 Mapper

`com/testlogon/android/core/data/dashboard/DashboardMapper.kt`

```kotlin
fun DashboardSummaryDto.toDomain(): Dashboard = Dashboard(
    todayEarningsCents = todayEarningsCents,
    earningsBreakdown = earningsBreakdown.toDomain(),
    periodViews = periodViews,
    periodRevenueCents = periodRevenueCents,
    totalSubscribers = totalSubscribers,
    topContent = topContent.map {
        TopContentItem(it.contentId, it.contentType, it.title, it.views, it.revenueCents)
    },
    activeBroadcasts = activeBroadcasts.map {
        ActiveBroadcast(it.sessionId, it.status, it.name, it.startedAt.toInstantOrNull())
    },
    recentMilestones = recentMilestones.map { it.toDomain() },
    currency = currency,
    generatedAt = generatedAt.epochToInstantOrNull(),
    warnings = warnings,
)

private fun DashboardEarningsBreakdownDto.toDomain() =
    EarningsBreakdown(subscriptions, tips, unlocks, vodPurchases, other)

private fun DashboardMilestoneDto.toDomain() = Milestone(
    milestoneId, metric, threshold, currentValue, formatted,
    achievedAt.epochToInstantOrNull(), acknowledged,
)

// generated_at / achieved_at are epoch SECONDS numbers in the wire contract.
private fun Long?.epochToInstantOrNull(): Instant? =
    this?.let { runCatching { Instant.ofEpochSecond(it) }.getOrNull() }

// active_broadcasts[].started_at is an ISO-8601 string.
private fun String?.toInstantOrNull(): Instant? =
    this?.let { runCatching { Instant.parse(it) }.getOrNull() }
```

The mapper is **total**: out-of-range or absent epoch numbers become `null`,
unparseable ISO strings become `null`, and absent collections are already empty
(DTO defaults). It never throws. NOTE: the epoch unit (seconds vs. milliseconds)
is an unverified assumption — see §16 Open assumptions; OpenAPI gives no schema and
`types.ts` only types it as `number`. The web `formatCents`/display logic in
`CreatorDashboard.tsx` does not disambiguate. Confirm against a live payload and
swap `ofEpochSecond` for `ofEpochMilli` if needed.

### 4.5 Repository

`com/testlogon/android/core/data/dashboard/DashboardRepository.kt`

```kotlin
interface DashboardRepository {
    suspend fun getDashboard(forceRefresh: Boolean = false): ApiResult<Dashboard>
    fun dashboard(): Flow<ApiResult<Dashboard>>
}

class DashboardRepositoryImpl @Inject constructor(
    private val api: DashboardApi,
    @IoDispatcher private val io: CoroutineDispatcher,
) : DashboardRepository {

    override suspend fun getDashboard(forceRefresh: Boolean): ApiResult<Dashboard> =
        withContext(io) {
            apiCall { api.getDashboard().toDomain() }   // apiCall from AND-018
        }

    override fun dashboard(): Flow<ApiResult<Dashboard>> = flow {
        emit(getDashboard())
    }.flowOn(io)
}
```

`apiCall { ... }` is the AND-018 helper that runs the block, returns
`ApiResult.Success` on success, maps `HttpException` → `ApiResult.Error` with an
`ApiError` decoded by AND-015, and maps `IOException`/`SocketTimeoutException` →
an offline/network `ApiResult.Error`. `forceRefresh` is currently a no-op
hint (no cache layer); it is retained in the signature so AND-068's pull-to-refresh
and a future cache ticket need no API change.

### 4.6 Hilt wiring

```kotlin
@Module @InstallIn(SingletonComponent::class)
object DashboardApiModule {
    @Provides @Singleton
    fun provideDashboardApi(retrofit: Retrofit): DashboardApi =
        retrofit.create(DashboardApi::class.java)
}

@Module @InstallIn(SingletonComponent::class)
abstract class DashboardDataModule {
    @Binds @Singleton
    abstract fun bindDashboardRepository(impl: DashboardRepositoryImpl): DashboardRepository
}
```

The injected `Retrofit` is AND-010's singleton on AND-009's shared `OkHttpClient`;
no new client is constructed.

### 4.7 Gradle wiring

No new dependencies. `core-network` already has Retrofit/Moshi/Hilt/MockWebServer;
`core-model` has Moshi codegen; `core-data` has Hilt + Coroutines and an
`implementation(project(":core-network"))` + `:core-model` + `:core-testing`
(test). This ticket adds source files only.

## 5. API Contract

Base path (`dev`): `http://18.222.237.167:8000/`. JSON. **Auth model (verified
against `src/api/client.ts`):** the web client sends THREE things on every request:
(1) `Authorization: Bearer <accessToken>` from the auth store, (2)
`X-CSRF-Token: <ui_csrf cookie value>` on **every** request including GETs (the
client sets it unconditionally — the earlier claim that "GET does not require CSRF"
is incorrect for the web client's behavior, though the server may not enforce it on
GET), and (3) cookies via `credentials: include`. The Android client inherits the
equivalent header/cookie/CSRF plumbing from AND-011/012/013; this layer adds no
manual headers. The summary endpoint also accepts optional `user_sub` (query) and
`X-SESSION-ID` / `X-IMPERSONATION-TOKEN` headers (OpenAPI params) — none are sent
by the normal authenticated client and none are needed here.

### GET `ui/dashboard/summary`

(Verified path. There is no `GET /ui/dashboard`.) Request: no body; auth/cookies/
CSRF attached by the shared client.

Response `200` (shape from `types.ts: DashboardSummary`; OpenAPI response is
untyped):
```json
{
  "today_earnings_cents": 12750,
  "earnings_breakdown": {
    "subscriptions": 8000, "tips": 2500, "unlocks": 1500,
    "vod_purchases": 750, "other": 0
  },
  "period_views": 18342,
  "period_revenue_cents": 96000,
  "total_subscribers": 1280,
  "top_content": [
    { "content_id": "c_1", "content_type": "video", "title": "Best of May",
      "views": 5400, "revenue_cents": 32000 }
  ],
  "active_broadcasts": [
    { "session_id": "b_1", "status": "live", "name": "Live Q&A",
      "started_at": "2026-06-05T12:00:00Z" }
  ],
  "recent_milestones": [
    { "milestone_id": "m_1", "user_id": "u_1", "metric": "subscribers",
      "threshold": 1000, "current_value": 1280, "formatted": "1,000 subscribers",
      "achieved_at": 1748952000, "acknowledged": false }
  ],
  "currency": "USD",
  "generated_at": 1749126600,
  "warnings": []
}
```

`POST ui/dashboard/refresh` → `{ "ok": true, "message": "...",
"refreshed_at": <epoch> }` (per `dashboard.ts: refreshDashboard`). The web client
calls it then re-fetches the summary.

`401` when the session is invalid → AND-013 `Authenticator` calls
`POST ui/session/refresh` once then retries; a second `401` propagates as
`HttpException` → AND-068 routes to login (AND-025).

**Error envelope:** FastAPI `detail` union (`string | [{msg,type,loc}] |
{code,...}`). Decoding to typed `ApiError` is owned by **AND-015**; the repository
consumes that mapping via `apiCall`. This ticket defines no error envelope of its
own. (`normalizeErrorDetail` in `src/api/client.ts` confirms the union: `string`,
`[{msg,...}]`, or `{code, ...}` objects such as `role_required_scope`/`geo_blocked`.)
The summary endpoint's only typed error in OpenAPI is `422 HTTPValidationError`
(the FastAPI loc/msg/type array). Path/field names are now verified (§16); the
remaining open item is the epoch unit on timestamp fields.

## 6. Data & State Management

- **Stateless API:** `DashboardApi` is a singleton Retrofit proxy with no fields.
- **No Room / DataStore** in scope. There is no persisted dashboard cache;
  `forceRefresh` is a forward-compatible hint only. A cache/stale-read ticket, if
  groomed, will back the `Flow` with a Room mirror without changing this API.
- **No `StateFlow`/`UiState`.** The repository returns `ApiResult<Dashboard>`
  (suspend) and `Flow<ApiResult<Dashboard>>`. AND-068's `DashboardViewModel` maps
  these to `StateFlow<DashboardUiState>` (loading/content/empty/error/offline).
- **Domain vs wire separation:** UI and ViewModel depend only on `Dashboard`
  (no Moshi annotations leak upward). DTOs never cross the `core-data` boundary.
- **Threading:** all I/O on the injected `@IoDispatcher`; `withContext(io)` for the
  suspend call, `flowOn(io)` for the stream. No main-thread work.
- **Serialization:** KSP-generated Moshi adapters via the shared converter; unknown
  keys ignored, optional fields default. No reflection adapter fallback (AND-010).
- **Immutability:** all DTO and domain classes are immutable `data class`es;
  collections default to empty, never null.

## 7. Error Handling & Resilience

- **Non-2xx** → `HttpException` inside `apiCall` → `ApiResult.Error(ApiError)`
  (AND-015 decodes `detail`). The repository never throws to callers; all outcomes
  are `ApiResult`.
- **`401`** is handled transparently by the AND-013 `Authenticator`
  (refresh-then-retry once). A persistent `401` surfaces as an
  `ApiResult.Error` whose `ApiError` marks an auth/unauthorized condition so
  AND-068 can route to login.
- **Transport failures** (`SocketTimeoutException`, `UnknownHostException`,
  `IOException`) → `apiCall` returns an offline/network `ApiResult.Error`
  (distinguishable kind) so AND-068 renders the offline state (AND-021/AND-069).
  The dev host is unreliable; ~20s timeouts come from the shared client (AND-009).
- **Bounded backoff:** the dashboard GET is idempotent → eligible for AND-016
  retry/backoff on the shared client. The repository adds no manual retry loop
  (avoids double-retry).
- **Deserialization failures** (`JsonDataException`/`EOFException`) → `apiCall`
  maps to `ApiResult.Error`. Lenient DTO defaults and the total mapper minimize
  these against the evolving dev backend; unknown keys are ignored and absent
  fields fall back to Kotlin defaults.
- **Partial payloads (verified semantic):** the backend signals partial failure via
  the `warnings: string[]` field ("Some data sources are currently unavailable: …"
  per `CreatorDashboard.tsx`), NOT via missing sections. Missing top-level
  collections (e.g. no `active_broadcasts`/`top_content`/`recent_milestones`) yield
  empty lists, not errors. The repository must surface `Dashboard.warnings` so
  AND-068 can render a non-fatal warning banner alongside content.

## 8. Security & Privacy

- **Authenticated read:** `ui/dashboard/summary` returns the authenticated
  principal's own creator data (earnings, views, subscribers), scoped server-side by
  the session. The optional `user_sub` query param exists (OpenAPI) but is not sent
  by the normal client; this layer never sets it, so no cross-user access path is
  introduced here.
- **No credentials handled here.** Cookie/CSRF/refresh are delegated to
  AND-011/012/013 on the shared client; `DashboardApi` declares no manual
  `Cookie`/`Authorization`/`X-CSRF-Token` headers.
- **Transport:** on `dev` the payload rides plaintext HTTP
  (`http://18.222.237.167:8000`) — a known dev-only risk permitted by the scoped
  cleartext config (AND-006); `staging`/`prod` are HTTPS-only.
- **Logging:** HTTP logging is inherited from AND-009's redacting interceptor
  (debug only). The dashboard body contains **financial data** (earnings cents,
  revenue, subscriber counts) — sensitive, not just mild PII; this ticket adds no
  logging and must not log response bodies. A code-review check confirms
  `Dashboard`/`DashboardSummaryDto` contents never reach logcat in release.
- **No token storage:** cookie-based model; nothing persisted by this layer.

## 9. Accessibility & i18n

Largely N/A — this is a headless data layer with no UI surface and no user-facing
strings. Accessibility (content descriptions, focus order, touch targets) and
localization of dashboard chrome are owned by the **screen/widgets ticket
(AND-066)** and `core-ui`. One i18n note carried here: server-provided strings
(`TopContentItem.title`, `Milestone.formatted`, `warnings[]`, and the `currency`
code) are passed through as opaque display text; the client does not translate them.
`Milestone.formatted` is a server-formatted human string (e.g. "1,000
subscribers"); money amounts arrive as integer cents in `currency` and are
formatted client-side by AND-066. If localization of the server strings is required
it must be a backend/`Accept-Language` concern, flagged as Q-3.

## 10. Telemetry & Logging

- **HTTP logging** inherited from AND-009 (redacting, debug only). No new logging
  in this layer; no response-body logging (Section 8).
- **No analytics events** emitted here. A `dashboard_loaded` / `dashboard_refresh`
  event (with load latency and success/offline outcome) is emitted by AND-068's
  ViewModel from the `ApiResult` outcome — derived state, not raw transport.
- **Build-time signal:** KSP must generate Moshi adapters for every dashboard DTO;
  a missing adapter fails the build (no reflection fallback, AND-010 policy).
- The repository may expose the `ApiError.kind`/latency to the ViewModel so AND-068
  can attach telemetry without re-deriving it; this layer emits nothing itself.

## 11. Testing Strategy

JVM unit tests in `core-network/src/test/...` (API decode) and
`core-data/src/test/...` (mapper + repository), using `MockWebServer` and the
production Moshi/Retrofit config plus a `StandardTestDispatcher` as the IO
dispatcher. Fixtures from the AND-046 MockWebServer harness where available.

API harness:
```kotlin
private fun api(server: MockWebServer): DashboardApi {
    val moshi = Moshi.Builder().build() // mirrors provideMoshi(): codegen adapters
    val retrofit = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
    return retrofit.create(DashboardApi::class.java)
}
```

**T-1 — endpoint contract.** `getDashboard()` issues `GET /ui/dashboard/summary`
(verb + resolved path asserted via `server.takeRequest()`).

**T-2 — full payload decodes.** Enqueue the Section-5 JSON; assert
`DashboardSummaryDto` fields decode, including snake_case (`today_earnings_cents`,
`earnings_breakdown`, `top_content`, `active_broadcasts`, `recent_milestones`,
`generated_at`).

```kotlin
@Test fun getDashboard_decodesFullPayload() = runTest {
    val server = MockWebServer().apply { enqueue(MockResponse().setBody(FIXTURE)); start() }
    val dto = api(server).getDashboard()
    assertEquals(12750, dto.todayEarningsCents)
    assertEquals(8000, dto.earningsBreakdown.subscriptions)
    assertEquals(1, dto.topContent.size)
    assertEquals(1, dto.activeBroadcasts.size)
    assertEquals(1, dto.recentMilestones.size)
    assertEquals(1749126600L, dto.generatedAt)
    server.shutdown()
}
```

**T-3 — mapper happy path.** `dto.toDomain()` produces the expected `Dashboard`:
correct earnings/breakdown values, top-content/broadcast/milestone counts,
`currency`, and `generatedAt` converted from the epoch number to an `Instant`.

**T-4 — mapper totality / forward-compat.** A DTO with an out-of-range/absent
`generated_at` → `generatedAt == null`; an unparseable broadcast `started_at` →
`null`; absent `top_content`/`active_broadcasts`/`recent_milestones` → empty lists.
No exception thrown.

**T-5 — warnings / partial payload.** Payload with a populated `warnings` array →
`Dashboard.warnings` carries the strings; empty/missing `warnings` → empty list.

**T-6 — repository success.** Fake `DashboardApi` returns a DTO →
`repo.getDashboard()` returns `ApiResult.Success` carrying the mapped domain
object.

**T-7 — repository HTTP error.** API throws `HttpException(401/500)` →
`ApiResult.Error` with the AND-015-mapped `ApiError` (auth vs server kind).

**T-8 — repository offline.** API throws `IOException`/`SocketTimeoutException` →
`ApiResult.Error` flagged as offline/network (drives AND-068 offline state).

**T-9 — `dashboard()` Flow.** Collecting the flow emits a single
`ApiResult<Dashboard>` and runs on the test IO dispatcher.

**T-10 — Hilt provider (optional `@HiltAndroidTest` or core-testing harness).**
`DashboardApi` and `DashboardRepository` inject as singletons on the shared
Retrofit; repeated injection yields the same instances.

Coverage target: ≥90% on DTOs+mapper+repository. Each DTO field has at least one
decode assertion; the mapper has happy-path, epoch-conversion, null/absent-field,
and warnings cases. The backlog AC ("payload loads + maps to domain, tested") is met
by T-1/T-2/T-3 together.

## 12. Dependencies & Sequencing

**Hard upstream (must merge first):**
- **AND-027** — AuthApi / session endpoints. Establishes the authenticated session
  the dashboard read depends on and the Retrofit/Hilt patterns reused here.

**Transitive upstream (already required):** AND-026 (DTO/adapter conventions),
AND-018 (`ApiResult` + `apiCall`), AND-015 (`ApiError`/`detail` mapping), AND-016
(idempotent-GET backoff), AND-010 (Retrofit/Moshi), AND-009 (shared client),
AND-011/012/013 (cookie jar, CSRF, 401-refresh), AND-006 (`BuildConfig` base URL),
AND-003/004 (module structure, Hilt baseline), AND-046 (MockWebServer fixtures, for
tests).

**Downstream (this ticket blocks):**
- **AND-068** — Dashboard ViewModel + state: consumes `DashboardRepository` to
  build `StateFlow<DashboardUiState>`. (AND-068 deps include AND-065.)
- **AND-066** — Dashboard screen + widgets: renders the domain `Dashboard` via the
  ViewModel; pull-to-refresh calls `getDashboard(forceRefresh = true)`. (AND-066
  deps include AND-065 + AND-024.)
- AND-069 (states + UI tests) depends transitively via AND-066/AND-068.

**Sequencing within the ticket:** (1) confirm path + field shapes against
`dashboard.ts`/`types.ts`/`/openapi.json` (Q-1, Q-2); (2) add DTOs in `core-model`;
(3) add `DashboardApi` + provider in `core-network`; (4) add domain model + mapper
+ `DashboardRepository` + binding in `core-data`; (5) write tests T-1..T-10.

## 13. Risks & Open Questions

- **R-1 Path/shape drift.** *Resolved.* Path verified as `GET ui/dashboard/summary`
  and shape verified against `types.ts: DashboardSummary` (§16). Residual risk: the
  OpenAPI response schema is untyped (`{}`), so a backend change to the summary
  fields would not surface in OpenAPI — only `types.ts` and a live payload pin it.
  Tests T-1/T-2 pin the confirmed shape.
- **R-2 Aggregated vs multiple endpoints.** *Resolved for this ticket.* The summary
  is a single aggregate GET (description: "earnings + analytics + broadcasts +
  milestones"). `recent_milestones` is embedded; the **full** milestones list is a
  separate `GET ui/milestones` consumed by AND-066/068, not by this repository.
- **R-3 Timestamp/epoch unit.** Timestamp wire fields (`generated_at`,
  `achieved_at`, `refreshed_at`) are epoch **numbers** in `types.ts`, but the unit
  (seconds vs. milliseconds) is not specified anywhere in the sources. The mapper
  assumes seconds (`Instant.ofEpochSecond`); confirm against a live payload. Guarded
  by T-4 (null-safety) but the unit itself is an open assumption (§16).
- **R-4 Empty payload semantics.** Distinguishing "no data yet" (empty lists) from
  "error" matters for AND-068's empty vs error states. This layer returns empty
  collections for absent sections, surfaces `warnings` for partial-data notices, and
  returns `ApiResult.Error` only for real failures.
- **Q-1** *Resolved:* `GET ui/dashboard/summary` (`dashboard.ts` + OpenAPI).
- **Q-2** *Resolved:* top-level field set = `types.ts: DashboardSummary`; optionals
  defaulted with Kotlin defaults; timestamps are nullable epoch numbers.
- **Q-3** Are server-provided strings localized server-side, or does the client need
  `Accept-Language`? *Proposed:* treat as opaque display text; flag to backend if
  i18n required. (Unverified.)
- **Q-4** Epoch unit (seconds vs ms) for timestamp fields? *Proposed:* seconds;
  confirm on a live payload (R-3). (Unverified.)

## 14. Acceptance Criteria

- **AC-1 (backlog).** `DashboardApi` declares `getDashboard` and the dashboard
  payload **loads** against a `MockWebServer` enqueued with the Section-5 JSON
  (correct verb `GET` + resolved path `/ui/dashboard/summary`) — T-1/T-2.
- **AC-2 (backlog).** The payload **maps to domain**: `DashboardSummaryDto.toDomain()`
  produces a `Dashboard` with correct earnings/breakdown values, top-content/
  broadcast/milestone contents, `currency`, and epoch→`Instant` `generatedAt` — T-3,
  **tested**.
- **AC-3.** Snake_case wire fields (`today_earnings_cents`, `earnings_breakdown`,
  `top_content`, `active_broadcasts`, `recent_milestones`, `generated_at`) decode via
  KSP-generated adapters — T-2.
- **AC-4.** The mapper is total: out-of-range/absent epoch → null timestamp,
  unparseable ISO `started_at` → null, missing sections → empty lists, `warnings`
  preserved; never throws — T-4/T-5.
- **AC-5.** `DashboardRepository.getDashboard()` returns `ApiResult.Success` on
  2xx and `ApiResult.Error` on HTTP failure (with AND-015 `ApiError`) and on
  transport failure (offline-flagged) — T-6/T-7/T-8.
- **AC-6.** `dashboard()` returns a `Flow<ApiResult<Dashboard>>` that emits the
  result and runs on the injected IO dispatcher — T-9.
- **AC-7.** `DashboardApi` and `DashboardRepository` are Hilt-provided/bound as
  singletons on the shared Retrofit; no new `OkHttpClient`/`Retrofit`; no manual
  cookie/CSRF/auth headers — T-10.
- **AC-8.** No DTO leaks above `core-data`; the ViewModel/UI tickets depend only on
  the `Dashboard` domain type.
- **AC-9.** All tests pass in CI; modules build clean under AGP 8.7.3 / Gradle 8.9
  / JDK 17 with KSP adapters present and no detekt/lint regressions.

## 15. Definition of Done

- DTOs (`com.testlogon.android.core.model.dashboard`), `DashboardApi`
  (`...core.network.dashboard`) + provider, domain model + `toDomain()` mapper,
  and `DashboardRepository`/`Impl` + Hilt binding (`...core.data.dashboard`) are
  implemented across `core-model`/`core-network`/`core-data`, reusing AND-018
  `apiCall`, AND-015 `ApiError`, and the shared Retrofit/client.
- Open questions Q-1..Q-4 are resolved against `frontend/src/api/endpoints/
  dashboard.ts`, `types.ts`, and `/openapi.json`; the endpoint count, path, and
  field set reflect the confirmed contract.
- Tests T-1 through T-10 are implemented and green in CI; ≥90% line coverage on the
  DTOs + mapper + repository; the backlog AC ("payload loads + maps to domain,
  tested") is demonstrably covered.
- No second `OkHttpClient`/`Retrofit`; no manual cookie/CSRF/auth headers; response
  bodies are not logged (redaction verified); DTOs do not cross the `core-data`
  boundary.
- `./gradlew :core-model:assemble :core-network:assemble :core-data:assemble
  :core-network:testDebugUnitTest :core-data:testDebugUnitTest` passes locally and
  in CI with no new lint/detekt violations (AND-005 config).
- Code reviewed and merged to `android-port`; AND-068 (ViewModel) and AND-066
  (screen) are unblocked — the `DashboardRepository` seam and `Dashboard` domain
  type are in place.
- A one-line note in the relevant module README (owned by AND-007) records the
  `DashboardApi` path/verb, the `Dashboard` domain shape, and the delegation of
  session/CSRF/error mapping to AND-027/012/013/015.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. Sources:
OpenAPI index/spec (`reference/openapi.index.txt`, `reference/openapi.pretty.json`)
and the frontend reference app (`reference/src/...`). "framework ref" = Android
docs.

1. **Dashboard read endpoint is `GET ui/dashboard/summary`.** VERDICT: Corrected
   (draft said `GET ui/dashboard`). SOURCE: `src/api/endpoints/dashboard.ts:
   getDashboardSummary` → `api.get<DashboardSummary>("/ui/dashboard/summary")`;
   OpenAPI `GET /ui/dashboard/summary` (op
   `dashboard_summary_ui_dashboard_summary_get`, tag `creator-dashboard`). No
   `GET /ui/dashboard` exists in the index.
2. **Response shape = creator earnings/analytics summary**
   (`today_earnings_cents`, `earnings_breakdown`, `period_views`,
   `period_revenue_cents`, `total_subscribers`, `top_content[]`,
   `active_broadcasts[]`, `recent_milestones[]`, `currency`, `generated_at`,
   `warnings[]`). VERDICT: Corrected (draft invented `user/stats/widgets/
   quick_links`). SOURCE: `src/api/types.ts: DashboardSummary` and nested
   `DashboardEarningsBreakdown`, `DashboardTopContentItem`,
   `DashboardActiveBroadcast`, `DashboardMilestone`. OpenAPI response schema is
   `{}` (untyped) — `types.ts` is authoritative.
3. **OpenAPI 200 response for the summary is untyped (`schema: {}`).** VERDICT:
   Verified. SOURCE: `openapi.pretty.json` → `dashboard_summary_..._get`
   `responses.200.content.application/json.schema = {}`.
4. **`top_content[]` fields = `content_id, content_type, title, views,
   revenue_cents`.** VERDICT: Verified. SOURCE: `src/api/types.ts:
   DashboardTopContentItem`.
5. **`active_broadcasts[]` fields = `session_id, status, name?, started_at?`;
   `started_at` is an ISO string.** VERDICT: Verified. SOURCE: `src/api/types.ts:
   DashboardActiveBroadcast`.
6. **`recent_milestones[]` / `DashboardMilestone` fields = `milestone_id, user_id,
   metric, threshold, current_value, formatted, achieved_at, acknowledged`.**
   VERDICT: Verified. SOURCE: `src/api/types.ts: DashboardMilestone`.
7. **A separate `GET ui/milestones` returns the full milestone list (not part of
   this repository's scope).** VERDICT: Verified. SOURCE: `src/api/endpoints/
   dashboard.ts: listMilestones`; OpenAPI `GET /ui/milestones` (op
   `milestones_list_ui_milestones_get`).
8. **`POST ui/dashboard/refresh` exists and returns `{ ok, message,
   refreshed_at }`; the web calls it then refetches the summary.** VERDICT:
   Corrected (draft treated `forceRefresh` as a pure no-op with no endpoint).
   SOURCE: `src/api/endpoints/dashboard.ts: refreshDashboard`; OpenAPI `POST
   /ui/dashboard/refresh` (op `dashboard_refresh_ui_dashboard_refresh_post`);
   `src/pages/dashboard/CreatorDashboard.tsx` (refreshMut → invalidateQueries).
9. **The web client sends `Authorization: Bearer <accessToken>` on requests.**
   VERDICT: Corrected (draft asserted a pure cookie model with no Authorization
   header). SOURCE: `src/api/client.ts` (`headers.set("Authorization",
   \`Bearer ${accessToken}\`)`). NB: the Android transport (AND-011/012/013)
   provides the equivalent; this layer still declares no manual headers.
10. **CSRF (`X-CSRF-Token` from the `ui_csrf` cookie) is attached to EVERY request,
    including GETs.** VERDICT: Corrected (draft said "GET does not require CSRF").
    SOURCE: `src/api/client.ts` (`const csrf = getCookie("ui_csrf"); if (csrf)
    headers.set("X-CSRF-Token", csrf)` — unconditional). Server enforcement on GET
    is unconfirmed, but the client always sends it.
11. **401 handling: refresh once via `POST ui/session/refresh`, retry, then logout
    on a second 401.** VERDICT: Verified. SOURCE: `src/api/client.ts`
    (`refreshSession()` → `POST /ui/session/refresh`, retry, `logout`); OpenAPI
    `POST /ui/session/refresh` (op `ui_session_refresh_ui_session_refresh_post`).
12. **Error envelope is the FastAPI `detail` union (`string` |
    `[{msg,type,loc}]` | `{code,...}`).** VERDICT: Verified. SOURCE:
    `src/api/client.ts: normalizeErrorDetail`/`mapAuthorizationError` (handles
    string, array-of-msg, and `{code}` objects like `role_required_scope`,
    `geo_blocked`); OpenAPI `422 HTTPValidationError` for the summary endpoint.
13. **The web polls the summary every 60s and warnings are surfaced from
    `summary.warnings`.** VERDICT: Verified. SOURCE: `src/pages/dashboard/
    CreatorDashboard.tsx` (`refetchInterval: 60_000`; `warnings = summary?.warnings
    ?? []`; "Some data sources are currently unavailable").
14. **`generated_at` (and `achieved_at`, `refreshed_at`) are epoch NUMBERS, not ISO
    strings.** VERDICT: Corrected (draft modeled `generated_at` as a `String` parsed
    with `Instant.parse`). SOURCE: `src/api/types.ts` (`generated_at: number`,
    `achieved_at: number`; `refreshed_at: number` in `dashboard.ts`).
15. **Endpoint also accepts optional `user_sub` (query) and `X-SESSION-ID` /
    `X-IMPERSONATION-TOKEN` headers; none are sent by the normal client.** VERDICT:
    Verified. SOURCE: OpenAPI `GET /ui/dashboard/summary` parameters; `src/api/
    client.ts` only sends `X-IMPERSONATION-TOKEN` when impersonating.
16. **Retrofit relative paths with no leading slash; suspend GET; singleton
    provider on the shared Retrofit.** VERDICT: Verified (pattern, inherited from
    AND-027/AND-010). SOURCE: framework ref — Retrofit (`https://square.github.io/
    retrofit/`) + AND-027 pattern referenced in §2.
17. **Money fields are integer cents formatted client-side.** VERDICT: Verified.
    SOURCE: `src/pages/dashboard/CreatorDashboard.tsx` (`formatCents(summary?.
    today_earnings_cents ?? 0)`).

### Corrections made

- Endpoint path `ui/dashboard` → **`ui/dashboard/summary`** (FR-2, FR-3, §4.1, §5,
  §11 T-1, §14 AC-1) — claim 1.
- Response/DTO/domain shape replaced the invented `user/stats/widgets/quick_links`
  model with the verified earnings/analytics/broadcast/milestone model (FR-3, §4.2,
  §4.3, §5) — claim 2.
- `generated_at` retyped from `String` (ISO, `Instant.parse`) to epoch `Long`
  (`Instant.ofEpochSecond`); mapper rewritten accordingly (§4.4) — claim 14.
- Auth model corrected: web sends a Bearer token in addition to cookies (§5) —
  claim 9; CSRF is attached to GETs too (§5) — claim 10.
- `forceRefresh` is no longer "pure no-op"; documented the real `POST
  ui/dashboard/refresh` and 60s polling (FR-11, §4.1, §5) — claims 8, 13.
- Partial-failure semantics corrected from "missing sections" to the `warnings[]`
  field (§7) — claim 13.
- Security/i18n/test sections updated to reference real fields (financial data;
  `TopContentItem.title`, `Milestone.formatted`, `currency`, `warnings`); removed
  references to `WidgetType`, `StatCard`, `quick_links`, `display_name`,
  `avatar_url` (§8, §9, §11, §14 AC-3/AC-4); R-3 repurposed to the epoch-unit risk.

### Open assumptions

- **Epoch unit (seconds vs. milliseconds)** for `generated_at` / `achieved_at` /
  `refreshed_at`. Unverified — `types.ts` only types them as `number`, OpenAPI gives
  no schema, and `CreatorDashboard.tsx` does not parse them into dates. The mapper
  assumes **seconds**; confirm against a live `dev` payload and switch to
  `Instant.ofEpochMilli` if wrong (Q-4 / R-3).
- **Server enforcement of CSRF on GET.** The client sends `X-CSRF-Token` on GETs,
  but whether the server requires it for the summary GET is not derivable from the
  sources (no security scheme attached to the operation in OpenAPI).
- **Nullability of scalar fields** (e.g. is `currency` ever absent, can
  `today_earnings_cents` be null). `types.ts` types them as non-optional `number`/
  `string`; DTOs nonetheless default them defensively against the unreliable dev
  backend. Unverified against a live payload.
- **Server-side localization of opaque strings** (`Milestone.formatted`,
  `warnings`) — Q-3; not determinable from the sources.
- **Backend backoff/idempotency tagging (AND-016) and `ApiResult`/`apiCall`
  (AND-018), `ApiError` mapping (AND-015), cookie/CSRF plumbing (AND-011/012/013)**
  are referenced upstream tickets, not re-verified here (out of scope; inherited).

## 17. Test Plan

Test targets: **JVM** = JVM/Robolectric local (no device); **emu35** = headless
AVD `test35` (x86_64, API 35); **deviceA15** = physical Samsung Galaxy A15 5G
(SM-A156U, API 34, arm64-v8a). This ticket is a **headless data layer** with no UI,
so the bulk is JVM unit + contract (MockWebServer). Instrumented/device cases are
limited to Hilt-graph wiring, real-network behavior against the flaky dev host, and
the cleartext-HTTP security check; no camera/biometric/WebRTC/FCM surface exists
here. Where a case has no device dependency, run it on **JVM** (fastest); reserve
emu35/deviceA15 for the genuinely device-bound items noted below.

- **TC-AND-065-01** — Type: contract/MockWebServer (JVM). Target: JVM. Pre: Retrofit
  built on `server.url("/")` with production Moshi. Steps: enqueue 200 with the §5
  fixture; call `getDashboard()`; `server.takeRequest()`. Expected: request method
  `GET`, path `/ui/dashboard/summary`. Traces: AC-1.
- **TC-AND-065-02** — Type: contract/MockWebServer (JVM). Target: JVM. Pre: as 01.
  Steps: enqueue the full §5 fixture; decode to `DashboardSummaryDto`. Expected: all
  snake_case fields decode (`today_earnings_cents`=12750, `earnings_breakdown.
  subscriptions`=8000, `top_content` size 1, `active_broadcasts` size 1,
  `recent_milestones` size 1, `generated_at`=1749126600, `currency`="USD"). Traces:
  AC-1, AC-3.
- **TC-AND-065-03** — Type: unit (JVM). Target: JVM. Pre: a fully-populated
  `DashboardSummaryDto`. Steps: call `toDomain()`. Expected: `Dashboard` carries
  correct earnings/breakdown values, list counts, `currency`, and
  `generatedAt == Instant.ofEpochSecond(1749126600)`; `active_broadcasts[0].
  startedAt` parsed from ISO. Traces: AC-2.
- **TC-AND-065-04** — Type: unit (JVM). Target: JVM. Pre: DTO with `generated_at`
  null/out-of-range, an unparseable broadcast `started_at`, and absent
  `top_content`/`active_broadcasts`/`recent_milestones`. Steps: `toDomain()`.
  Expected: no throw; `generatedAt == null`, broadcast `startedAt == null`, all three
  lists empty. Traces: AC-4.
- **TC-AND-065-05** — Type: unit (JVM). Target: JVM. Pre: DTO with populated
  `warnings` ("Source X unavailable") and, separately, missing `warnings`. Steps:
  `toDomain()`. Expected: warnings preserved in the first; empty list in the second
  (never null). Traces: AC-4.
- **TC-AND-065-06** — Type: contract/MockWebServer (JVM). Target: JVM. Pre: payload
  with an extra unknown top-level key and an unknown key inside `earnings_breakdown`.
  Steps: decode. Expected: unknown keys ignored, no `JsonDataException`; known fields
  intact (forward-compat). Traces: AC-3, AC-4.
- **TC-AND-065-07** — Type: unit (JVM). Target: JVM. Pre: fake `DashboardApi`
  returning a valid DTO; `StandardTestDispatcher` as `@IoDispatcher`. Steps:
  `repo.getDashboard()`. Expected: `ApiResult.Success` carrying the mapped
  `Dashboard`. Traces: AC-2, AC-5.
- **TC-AND-065-08** — Type: unit (JVM). Target: JVM. Pre: fake API throwing
  `HttpException(401)` then, in a second run, `HttpException(500)` with a FastAPI
  `detail` body. Steps: `repo.getDashboard()`. Expected: `ApiResult.Error`; the
  AND-015-mapped `ApiError` distinguishes auth(401) vs server(500) kinds; never
  throws to caller. Traces: AC-5.
- **TC-AND-065-09** — Type: unit (JVM). Target: JVM. Pre: fake API throwing
  `SocketTimeoutException` / `UnknownHostException` / `IOException`. Steps:
  `repo.getDashboard()`. Expected: `ApiResult.Error` flagged offline/network
  (distinct kind for AND-068's offline state). Traces: AC-5.
- **TC-AND-065-10** — Type: unit (JVM). Target: JVM. Pre: repo over a fake API on
  the test dispatcher. Steps: collect `repo.dashboard()`. Expected: exactly one
  `ApiResult<Dashboard>` emitted; work runs on the injected IO dispatcher
  (assert via dispatcher / no main-thread access). Traces: AC-6.
- **TC-AND-065-11** — Type: integration/instrumented Hilt (emu35). Target: emu35
  (any KVM device; ABI-independent). Pre: `@HiltAndroidTest` with the production
  modules. Steps: inject `DashboardApi` and `DashboardRepository` twice. Expected:
  both resolve as singletons (same instance both times), bound on the shared
  Retrofit/OkHttp (no second client); `DashboardRepositoryImpl` is the bound impl.
  Traces: AC-7. (Run on emu35 — no hardware dependency.)
- **TC-AND-065-12** — Type: contract/MockWebServer (JVM). Target: JVM. Pre: enqueue
  401 then a successful 200 (simulating the AND-013 refresh-retry, configured with a
  test Authenticator). Steps: `getDashboard()`. Expected: a `POST /ui/session/
  refresh` is issued, then the original GET is retried and succeeds; a persistent
  second 401 instead surfaces as an auth `ApiResult.Error`. Traces: AC-5.
- **TC-AND-065-13** — Type: instrumented/e2e real-network (deviceA15). Target:
  **deviceA15 (physical, required)**. Pre: a valid authenticated session against the
  flaky dev host `http://18.222.237.167:8000/`; airplane-mode toggle available.
  Steps: (a) fetch dashboard online; (b) enable airplane mode and fetch again.
  Expected: (a) `ApiResult.Success` with real data; (b) offline-flagged
  `ApiResult.Error` within the ~20s client timeout. MUST run on the physical device
  to exercise real radio offline behavior and the unreliable plaintext dev host
  (emulator network is too clean to reproduce flakiness); also validates arm64/API-34
  path. Traces: AC-5.
- **TC-AND-065-14** — Type: instrumented security (deviceA15 preferred, emu35
  acceptable). Target: deviceA15. Pre: release-type network-security config. Steps:
  perform a dashboard fetch and inspect that (1) cleartext to the dev host is only
  permitted under the scoped AND-006 config, (2) the response body (earnings/revenue)
  never appears in logcat, and (3) `DashboardApi` adds no manual `Authorization`/
  `Cookie`/`X-CSRF-Token` headers (only inherited ones present). Expected: no
  financial data in logcat; no manual auth headers; cleartext scoped to dev only.
  Traces: AC-7, plus §8 security DoD. Prefer deviceA15 to validate real logcat under
  API 34.

(No accessibility cases: this ticket has no UI surface — a11y is owned by AND-066.)

### Coverage matrix

| AC (section 14) | Covered by |
|---|---|
| AC-1 (loads, correct verb+path) | TC-01, TC-02 |
| AC-2 (maps to domain) | TC-03, TC-07 |
| AC-3 (snake_case decode) | TC-02, TC-06 |
| AC-4 (mapper total: nulls/empty/warnings, no throw) | TC-04, TC-05, TC-06 |
| AC-5 (Success on 2xx; Error on HTTP + offline) | TC-07, TC-08, TC-09, TC-12, TC-13 |
| AC-6 (`dashboard()` Flow on IO dispatcher) | TC-10 |
| AC-7 (Hilt singletons; no new client; no manual headers) | TC-11, TC-14 |
| AC-8 (no DTO leak above core-data) | enforced by module structure; visibility checked in TC-03/TC-07 (domain-only) |
| AC-9 (builds + tests green in CI) | whole suite TC-01..TC-14 in CI |
