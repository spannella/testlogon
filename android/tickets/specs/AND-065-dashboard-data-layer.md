---
id: AND-065
title: Dashboard data layer
milestone: M2
epic: E09
priority: P0
size: M
status: draft
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
Moshi adapters; the domain model (`Dashboard` and its widget value types); the
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
operation `getDashboard` as a `suspend` GET returning a `DashboardDto`.

FR-2. The endpoint path/verb match the web reference and `/openapi.json` exactly.
Spec assumes `GET ui/dashboard` (relative, no leading slash). If `dashboard.ts`
resolves a different path (e.g. `ui/dashboard/summary`), the annotation is
corrected during implementation (Q-1) — the rest of the design is unaffected.

FR-3. Define Moshi `@JsonClass(generateAdapter = true)` DTOs mirroring
`dashboard.ts`: a top-level `DashboardDto` plus nested widget/card/quick-link
DTOs. Snake_case wire fields map via `@Json(name = ...)`. Unknown keys are
ignored; absent optional fields fall back to Kotlin defaults.

FR-4. Define an immutable domain model `Dashboard` (and its nested types) free of
serialization annotations, expressing only what the UI needs (AND-066/068).

FR-5. Provide a pure mapper `fun DashboardDto.toDomain(): Dashboard` that is
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

## 4. Technical Design

Transport in `core-network`; DTOs in `core-model`; domain + mapper + repository in
`core-data`.

### 4.1 The `DashboardApi` interface

`core-network/src/main/kotlin/com/testlogon/android/core/network/dashboard/DashboardApi.kt`

```kotlin
package com.testlogon.android.core.network.dashboard

import com.testlogon.android.core.model.dashboard.DashboardDto
import retrofit2.http.GET

interface DashboardApi {

    /** Authenticated dashboard payload. Idempotent GET; rides session cookies. */
    @GET("ui/dashboard")
    suspend fun getDashboard(): DashboardDto
}
```

### 4.2 Wire DTOs (`core-model`)

`core-model/src/main/kotlin/com/testlogon/android/core/model/dashboard/DashboardDto.kt`

```kotlin
package com.testlogon.android.core.model.dashboard

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
data class DashboardDto(
    @Json(name = "user") val user: DashboardUserDto? = null,
    @Json(name = "stats") val stats: List<StatCardDto> = emptyList(),
    @Json(name = "widgets") val widgets: List<WidgetDto> = emptyList(),
    @Json(name = "quick_links") val quickLinks: List<QuickLinkDto> = emptyList(),
    @Json(name = "generated_at") val generatedAt: String? = null,
)

@JsonClass(generateAdapter = true)
data class DashboardUserDto(
    @Json(name = "username") val username: String? = null,
    @Json(name = "display_name") val displayName: String? = null,
    @Json(name = "avatar_url") val avatarUrl: String? = null,
)

@JsonClass(generateAdapter = true)
data class StatCardDto(
    @Json(name = "id") val id: String,
    @Json(name = "label") val label: String,
    @Json(name = "value") val value: String,
    @Json(name = "delta") val delta: String? = null,
)

@JsonClass(generateAdapter = true)
data class WidgetDto(
    @Json(name = "id") val id: String,
    @Json(name = "type") val type: String,
    @Json(name = "title") val title: String? = null,
    @Json(name = "body") val body: String? = null,
)

@JsonClass(generateAdapter = true)
data class QuickLinkDto(
    @Json(name = "id") val id: String,
    @Json(name = "label") val label: String,
    @Json(name = "route") val route: String,
    @Json(name = "icon") val icon: String? = null,
)
```

The exact field set is reconciled against `dashboard.ts` / `types.ts` /
`/openapi.json` at implementation time (Q-1, Q-2); names above reflect the
expected shape (a personalized header, stat cards, free-form widgets, and quick
links per the backlog "key widgets/cards + quick links"). Adding/removing a field
is a local change confined to this DTO set + mapper + fixtures.

### 4.3 Domain model (`core-data` or `core-model`)

`com/testlogon/android/core/model/dashboard/Dashboard.kt`

```kotlin
package com.testlogon.android.core.model.dashboard

data class Dashboard(
    val user: DashboardUser?,
    val stats: List<StatCard>,
    val widgets: List<Widget>,
    val quickLinks: List<QuickLink>,
    val generatedAt: Instant?,   // java.time.Instant; null when absent/unparseable
)

data class DashboardUser(val username: String, val displayName: String, val avatarUrl: String?)
data class StatCard(val id: String, val label: String, val value: String, val delta: String?)
data class Widget(val id: String, val type: WidgetType, val title: String?, val body: String?)
data class QuickLink(val id: String, val label: String, val route: String, val icon: String?)

enum class WidgetType { TEXT, CHART, LIST, UNKNOWN }
```

### 4.4 Mapper

`com/testlogon/android/core/data/dashboard/DashboardMapper.kt`

```kotlin
fun DashboardDto.toDomain(): Dashboard = Dashboard(
    user = user?.let {
        DashboardUser(
            username = it.username.orEmpty(),
            displayName = it.displayName ?: it.username.orEmpty(),
            avatarUrl = it.avatarUrl,
        )
    },
    stats = stats.map { StatCard(it.id, it.label, it.value, it.delta) },
    widgets = widgets.map {
        Widget(it.id, it.type.toWidgetType(), it.title, it.body)
    },
    quickLinks = quickLinks.map { QuickLink(it.id, it.label, it.route, it.icon) },
    generatedAt = generatedAt?.let { runCatching { Instant.parse(it) }.getOrNull() },
)

private fun String.toWidgetType(): WidgetType = when (lowercase()) {
    "text" -> WidgetType.TEXT
    "chart" -> WidgetType.CHART
    "list" -> WidgetType.LIST
    else -> WidgetType.UNKNOWN
}
```

The mapper is **total**: unknown widget types degrade to `WidgetType.UNKNOWN`
(forward-compatible with new backend widget kinds), unparseable timestamps become
`null`, and absent collections are already empty (DTO defaults). It never throws.

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

Base path (`dev`): `http://18.222.237.167:8000/`. JSON. Authenticated via session
cookies + `X-CSRF-Token` (inherited; GET does not require CSRF but rides cookies).

### GET `ui/dashboard`

Request: no body; cookies attached by the jar (AND-011).

Response `200`:
```json
{
  "user": {
    "username": "alice@example.com",
    "display_name": "Alice",
    "avatar_url": "https://cdn.example.com/a/alice.png"
  },
  "stats": [
    { "id": "logins", "label": "Logins (30d)", "value": "42", "delta": "+12%" },
    { "id": "sessions", "label": "Active sessions", "value": "3", "delta": null }
  ],
  "widgets": [
    { "id": "w_welcome", "type": "text", "title": "Welcome back", "body": "..." },
    { "id": "w_activity", "type": "list", "title": "Recent activity", "body": null }
  ],
  "quick_links": [
    { "id": "ql_profile", "label": "Profile", "route": "/profile", "icon": "user" },
    { "id": "ql_settings", "label": "Settings", "route": "/settings", "icon": "gear" }
  ],
  "generated_at": "2026-06-05T12:30:00Z"
}
```

`401` when the session is invalid → AND-013 `Authenticator` calls
`POST ui/session/refresh` once then retries; a second `401` propagates as
`HttpException` → AND-068 routes to login (AND-025).

**Error envelope:** FastAPI `detail` union (`string | [{msg,type,loc}] |
{code,...}`). Decoding to typed `ApiError` is owned by **AND-015**; the repository
consumes that mapping via `apiCall`. This ticket defines no error envelope of its
own. Exact path/field names are confirmed against `dashboard.ts` and
`/openapi.json` (Q-1, Q-2) before merge.

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
  these against the evolving dev backend; an unknown `widget.type` does not fail
  the parse (maps to `UNKNOWN`).
- **Partial payloads:** missing top-level sections (e.g. no `quick_links`) yield
  empty lists, not errors; AND-068 can then render an empty-state for that section.

## 8. Security & Privacy

- **Authenticated read:** `ui/dashboard` returns the authenticated principal's own
  data, scoped server-side by the session cookie. No identifier is passed by the
  client; no cross-user access path exists in this layer.
- **No credentials handled here.** Cookie/CSRF/refresh are delegated to
  AND-011/012/013 on the shared client; `DashboardApi` declares no manual
  `Cookie`/`Authorization`/`X-CSRF-Token` headers.
- **Transport:** on `dev` the payload rides plaintext HTTP
  (`http://18.222.237.167:8000`) — a known dev-only risk permitted by the scoped
  cleartext config (AND-006); `staging`/`prod` are HTTPS-only.
- **Logging:** HTTP logging is inherited from AND-009's redacting interceptor
  (debug only). The dashboard body may contain a display name / avatar URL (mild
  PII); this ticket adds no logging and must not log response bodies. A code-review
  check confirms `Dashboard`/`DashboardDto` contents never reach logcat in release.
- **No token storage:** cookie-based model; nothing persisted by this layer.

## 9. Accessibility & i18n

Largely N/A — this is a headless data layer with no UI surface and no user-facing
strings. Accessibility (content descriptions, focus order, touch targets) and
localization of dashboard chrome are owned by the **screen/widgets ticket
(AND-066)** and `core-ui`. One i18n note carried here: server-provided labels
(`StatCard.label`, `Widget.title`, `QuickLink.label`) are passed through as opaque
display text; the client does not translate them. If localization of these strings
is required it must be a backend/`Accept-Language` concern, flagged as Q-3.

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

**T-1 — endpoint contract.** `getDashboard()` issues `GET /ui/dashboard` (verb +
resolved path asserted via `server.takeRequest()`).

**T-2 — full payload decodes.** Enqueue the Section-5 JSON; assert `DashboardDto`
fields decode, including snake_case (`display_name`, `avatar_url`, `quick_links`,
`generated_at`).

```kotlin
@Test fun getDashboard_decodesFullPayload() = runTest {
    val server = MockWebServer().apply { enqueue(MockResponse().setBody(FIXTURE)); start() }
    val dto = api(server).getDashboard()
    assertEquals("alice@example.com", dto.user?.username)
    assertEquals(2, dto.stats.size)
    assertEquals("quick_links maps", 2, dto.quickLinks.size)
    server.shutdown()
}
```

**T-3 — mapper happy path.** `dto.toDomain()` produces the expected `Dashboard`:
correct stat/widget/quick-link counts, `WidgetType.LIST`/`TEXT` resolved,
`generatedAt` parsed to `Instant`.

**T-4 — mapper totality / forward-compat.** A DTO with an unknown `type:"gauge"`
maps to `WidgetType.UNKNOWN`; an unparseable `generated_at` → `generatedAt == null`;
absent `quick_links` → empty list. No exception thrown.

**T-5 — mapper null user.** Payload with `user: null` → `Dashboard.user == null`,
other fields intact.

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
decode assertion; the mapper has happy-path, unknown-enum, null, and missing-field
cases. The backlog AC ("payload loads + maps to domain, tested") is met by
T-1/T-2/T-3 together.

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

- **R-1 Path/shape drift.** The dashboard endpoint path and field names are assumed
  (`GET ui/dashboard`, the Section-5 shape). If `dashboard.ts`/`/openapi.json`
  differ, DTOs/annotations are corrected locally. Mitigation: confirm before
  coding; tests pin the confirmed shape. Guarded by T-1/T-2.
- **R-2 Aggregated vs multiple endpoints.** The web dashboard may compose several
  calls (stats, activity, links) rather than one aggregate. If so, `DashboardApi`
  gains methods and the repository fans out + combines into one `Dashboard`.
  Mitigation: inspect `dashboard.ts`; default to a single aggregate GET.
- **R-3 Widget polymorphism.** `widgets[].type` may carry type-specific payloads
  (chart series, list items) beyond `title`/`body`. If so, model as a sealed
  hierarchy keyed on `type` with a Moshi `PolymorphicJsonAdapterFactory` or manual
  discriminator mapping. Mitigation: start with the flat DTO + `UNKNOWN` fallback;
  expand if the contract requires structured widget bodies. Guarded by T-4.
- **R-4 Empty payload semantics.** Distinguishing "no data yet" (empty lists) from
  "error" matters for AND-068's empty vs error states. This layer returns empty
  collections for absent sections and `ApiResult.Error` only for real failures.
- **Q-1** Exact endpoint path/verb? *Proposed:* `GET ui/dashboard`; confirm via
  `dashboard.ts` + `/openapi.json`.
- **Q-2** Exact top-level field set and nullability (is `user` always present? is
  `generated_at` present)? *Proposed:* mirror `types.ts`; default optionals to
  nullable with Kotlin defaults.
- **Q-3** Are server-provided labels localized server-side, or does the client need
  `Accept-Language`? *Proposed:* treat as opaque display text; flag to backend if
  i18n required.
- **Q-4** One aggregate call or several (R-2)? *Proposed:* single aggregate;
  re-scope the repository to fan-out if the reference composes calls.

## 14. Acceptance Criteria

- **AC-1 (backlog).** `DashboardApi` declares `getDashboard` and the dashboard
  payload **loads** against a `MockWebServer` enqueued with the Section-5 JSON
  (correct verb + resolved path) — T-1/T-2.
- **AC-2 (backlog).** The payload **maps to domain**: `DashboardDto.toDomain()`
  produces a `Dashboard` with correct stat/widget/quick-link contents, resolved
  `WidgetType`, and parsed `generatedAt` — T-3, **tested**.
- **AC-3.** Snake_case wire fields (`display_name`, `avatar_url`, `quick_links`,
  `generated_at`) decode via KSP-generated adapters — T-2.
- **AC-4.** The mapper is total: unknown widget type → `UNKNOWN`, unparseable
  timestamp → null, missing sections → empty lists; never throws — T-4/T-5.
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
