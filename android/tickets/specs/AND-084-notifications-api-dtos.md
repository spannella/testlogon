---
id: AND-084
title: Notifications API + DTOs
milestone: M2
epic: E12
priority: P0
size: M
status: draft
depends_on: [AND-027]
blocks: [AND-085]
---

# AND-084 — Notifications API + DTOs

## 1. Overview & Goal

This ticket delivers the typed HTTP seam and data layer for the TestLogon
notification center: the Moshi-backed DTOs that model the notification wire
format, the Retrofit `NotificationsApi` interface that lists notifications,
marks them read, and reports the unread badge count, and a
`NotificationRepository` (in `core-data`) that wraps those calls in
`ApiResult<T>` and exposes them to the notifications feature.

Scope, verbatim from the backlog: *`notifications.ts` endpoints/DTOs;
repository (list, mark read, unread count).* The single acceptance criterion is
that *list + mark-read map correctly (tested)*.

This is a **transport + repository** ticket within epic **E12 (Notifications &
alerts)**. It owns: the `core-model` DTOs (`NotificationDto`, page envelope,
mark-read request/response, unread-count response), their Moshi codegen
adapters, the `NotificationsApi` Retrofit interface, its Hilt provider, and the
`NotificationRepository` with its domain mapping. It deliberately does **not**
own the notification-center UI, the badge composable, `NotificationsViewModel`,
or push/FCM delivery — those are downstream E12 tickets (placeholder AND-085+).
It consumes the network plumbing already established by the auth chain (shared
`OkHttpClient`, Retrofit/Moshi, cookie jar, CSRF interceptor, 401-refresh
`Authenticator`, `ApiResult`).

Deliverable: compiling DTOs + adapters, a `NotificationsApi`, its Hilt
provider, a `NotificationRepository` returning `ApiResult<T>`, and a unit test
suite (MockWebServer + repository tests) proving list and mark-read map
correctly.

## 2. Context & References

- **Repo / location:** `spannella/testlogon`, monorepo subfolder `android/`,
  branch `android-port`. DTOs land in `core-model`, the API in `core-network`,
  the repository in `core-data`.
- **Canonical package:** `com.testlogon.android` everywhere.
  - DTOs: `com.testlogon.android.core.model.notifications`
  - API + adapters + provider: `com.testlogon.android.core.network.notifications`
  - Repository + domain model: `com.testlogon.android.core.data.notifications`
- **Stack pins relevant here:** Kotlin 2.0.21, Retrofit **2.11.0**, OkHttp
  **4.12.0**, Moshi **1.15.x** (codegen via KSP), Hilt (KSP), Coroutines/Flow,
  JDK 17, minSdk 24 / compileSdk 35, AGP 8.7.3 / Gradle 8.9.
- **Module layering:** `app -> feature-* -> core-*`. No `feature-*`/`app`
  symbols leak into `core-network`/`core-data`. `NotificationsApi` lives in
  `core-network`, consumes `core-model` DTOs; `NotificationRepository` lives in
  `core-data`, consumes the API and maps DTOs to domain models.
- **Upstream dependency — AND-027 (AuthApi / session endpoints):** establishes
  the cookie-based authenticated session and the shared Retrofit on which this
  API rides. All notification endpoints require an authenticated session
  (cookies + `X-CSRF-Token` on mutating verbs); that transport is inherited, not
  re-implemented here. The 401 path is handled by the AND-013 `Authenticator`.
- **Transitive upstream (already merged via the auth chain):** AND-010
  (Retrofit/Moshi), AND-009 (shared `OkHttpClient`, ~20s timeouts, redacting
  logger), AND-011 (cookie jar), AND-012 (CSRF interceptor), AND-013 (401
  refresh), AND-015 (`ApiError`/`detail` mapping), AND-016 (bounded backoff for
  idempotent GETs), AND-018 (`ApiResult<T>`), AND-006 (`BuildConfig`).
- **Backend:** FastAPI + DynamoDB; dev host `http://18.222.237.167:8000`
  (plaintext, unreliable). OpenAPI at `/openapi.json`. Web reference for exact
  field names and endpoint paths: `frontend/src/api/endpoints/notifications.ts`
  and shared types in `frontend/src/api/types.ts` — mirror those names (backend
  is snake_case); do not invent camelCase wire variants.

## 3. Functional Requirements

FR-1. Define request/response DTOs for the notification surface in `core-model`:
`NotificationDto`, `NotificationPageDto` (list envelope), `MarkReadReq`,
`MarkReadResp`, `UnreadCountResp`. All are immutable `data class`es annotated
`@JsonClass(generateAdapter = true)`.

FR-2. Each DTO field maps to the backend snake_case name via `@Json(name=…)`
when the Kotlin property is camelCase. Optional fields are nullable with a
`null`/empty default; required fields are non-null and their absence must throw
`JsonDataException` (fail fast).

FR-3. Declare a Retrofit `NotificationsApi` covering exactly: `list`
(paginated GET), `markRead` (mark one or many read), `markAllRead`, and
`unreadCount` (GET).

FR-4. List supports pagination parameters (`cursor` and/or `limit`) and an
optional `unread_only` filter, all as `@Query`. The response carries the page of
items plus a `next_cursor` for the next page.

FR-5. `markRead` is a mutating POST taking a body of notification ids; the CSRF
header is injected globally by AND-012 (not declared per-method). `markAllRead`
is a mutating POST with no body.

FR-6. A `NotificationRepository` interface + implementation in `core-data`
exposes: `list(...)`, `markRead(ids)`, `markAllRead()`, `unreadCount()`, each
returning `ApiResult<T>` (AND-018). The repository maps `NotificationDto` →
domain `Notification` (ISO-8601 `String` → `Instant`, enum normalization).

FR-7. The repository runs all calls on an injected IO dispatcher and never
throws to callers — non-2xx/transport failures are folded into
`ApiResult.Error` via AND-015 mapping.

FR-8. `unreadCount()` exposes the badge count; the repository additionally
publishes it as an observable `StateFlow<Int>` (`unreadCount: StateFlow<Int>`)
refreshed on demand, so a badge composable (downstream) can collect it without
re-fetching.

FR-9. A Hilt `@Provides @Singleton fun provideNotificationsApi(retrofit:
Retrofit): NotificationsApi` constructs the service from the shared Retrofit;
the repository binding is `@Binds`. No new Retrofit/OkHttp instance is created.

## 4. Technical Design

Production code lands in three modules. DTOs are `@JsonClass(generateAdapter =
true)` so Moshi codegen (KSP) emits adapters at build time — no reflection
adapter is added.

### 4.1 DTOs (`core-model`)

```kotlin
package com.testlogon.android.core.model.notifications

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
data class NotificationDto(
    val id: String,
    val type: String,                                   // see NotificationType normalization
    val title: String? = null,
    val body: String? = null,
    val read: Boolean = false,
    @Json(name = "created_at") val createdAt: String,   // ISO-8601, kept as String here
    @Json(name = "read_at") val readAt: String? = null,
    @Json(name = "deep_link") val deepLink: String? = null,
    val data: Map<String, String> = emptyMap(),         // free-form payload
)

@JsonClass(generateAdapter = true)
data class NotificationPageDto(
    val items: List<NotificationDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
    @Json(name = "unread_count") val unreadCount: Int? = null,   // some backends include it inline
)

@JsonClass(generateAdapter = true)
data class MarkReadReq(
    val ids: List<String>,
)

@JsonClass(generateAdapter = true)
data class MarkReadResp(
    val ok: Boolean,
    @Json(name = "updated") val updated: Int = 0,
    @Json(name = "unread_count") val unreadCount: Int? = null,
)

@JsonClass(generateAdapter = true)
data class UnreadCountResp(
    @Json(name = "unread_count") val unreadCount: Int,
)
```

### 4.2 Domain model + mapping (`core-data`)

```kotlin
package com.testlogon.android.core.data.notifications

import java.time.Instant

enum class NotificationType { ALERT, MESSAGE, SYSTEM, MFA, BILLING, UNKNOWN;
    companion object {
        fun fromToken(t: String?): NotificationType =
            entries.firstOrNull { it.name.equals(t, ignoreCase = true) } ?: UNKNOWN
    }
}

data class Notification(
    val id: String,
    val type: NotificationType,
    val title: String?,
    val body: String?,
    val read: Boolean,
    val createdAt: Instant,
    val readAt: Instant?,
    val deepLink: String?,
    val data: Map<String, String>,
)

internal fun NotificationDto.toDomain(): Notification = Notification(
    id = id,
    type = NotificationType.fromToken(type),
    title = title,
    body = body,
    read = read,
    createdAt = Instant.parse(createdAt),                 // tolerant parse; see §7
    readAt = readAt?.let { runCatching { Instant.parse(it) }.getOrNull() },
    deepLink = deepLink,
    data = data,
)

data class NotificationPage(
    val items: List<Notification>,
    val nextCursor: String?,
)
```

### 4.3 `NotificationsApi` (`core-network`)

```kotlin
package com.testlogon.android.core.network.notifications

import com.testlogon.android.core.model.notifications.MarkReadReq
import com.testlogon.android.core.model.notifications.MarkReadResp
import com.testlogon.android.core.model.notifications.NotificationPageDto
import com.testlogon.android.core.model.notifications.UnreadCountResp
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Query

interface NotificationsApi {

    /** Paginated list. Idempotent GET — eligible for AND-016 bounded backoff. */
    @GET("ui/notifications")
    suspend fun list(
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
        @Query("unread_only") unreadOnly: Boolean? = null,
    ): NotificationPageDto

    /** Mark a set of notifications read. Mutating POST (CSRF injected by AND-012). */
    @Headers("Content-Type: application/json")
    @POST("ui/notifications/mark-read")
    suspend fun markRead(@Body body: MarkReadReq): MarkReadResp

    /** Mark all read. No request body. */
    @POST("ui/notifications/mark-all-read")
    suspend fun markAllRead(): MarkReadResp

    /** Unread badge count. Idempotent GET. */
    @GET("ui/notifications/unread-count")
    suspend fun unreadCount(): UnreadCountResp
}
```

Path/verb conventions (consistent with AND-027): relative paths, no leading
slash, resolving against `http://18.222.237.167:8000/`. Mutating verbs
(`mark-read`, `mark-all-read`) receive `X-CSRF-Token` from AND-012; GETs (`list`,
`unread-count`) are AND-016 backoff candidates.

### 4.4 Hilt providers

```kotlin
@Module
@InstallIn(SingletonComponent::class)
object NotificationsApiModule {
    @Provides @Singleton
    fun provideNotificationsApi(retrofit: Retrofit): NotificationsApi =
        retrofit.create(NotificationsApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class NotificationDataModule {
    @Binds @Singleton
    abstract fun bindNotificationRepository(
        impl: DefaultNotificationRepository,
    ): NotificationRepository
}
```

The injected `Retrofit` is the singleton from AND-010 built on AND-009's shared
`OkHttpClient`. No client/Retrofit is constructed here. The `MfaFactorAdapter`-
style enum adapter is unnecessary: `NotificationType` normalization happens in
the repository mapper (`fromToken`), keeping `core-model` adapter-free for this
surface.

### 4.5 Repository (`core-data`)

```kotlin
package com.testlogon.android.core.data.notifications

interface NotificationRepository {
    val unreadCount: StateFlow<Int>
    suspend fun list(cursor: String? = null, limit: Int? = null,
                     unreadOnly: Boolean = false): ApiResult<NotificationPage>
    suspend fun markRead(ids: List<String>): ApiResult<Int>      // returns updated count
    suspend fun markAllRead(): ApiResult<Int>
    suspend fun unreadCount(): ApiResult<Int>                    // also refreshes the StateFlow
}

@Singleton
class DefaultNotificationRepository @Inject constructor(
    private val api: NotificationsApi,
    @IoDispatcher private val io: CoroutineDispatcher,
) : NotificationRepository {

    private val _unreadCount = MutableStateFlow(0)
    override val unreadCount: StateFlow<Int> = _unreadCount.asStateFlow()

    override suspend fun list(cursor: String?, limit: Int?, unreadOnly: Boolean) =
        withContext(io) {
            apiCall {                                            // AND-018 wrapper
                api.list(cursor, limit, unreadOnly.takeIf { it })
            }.map { dto ->
                dto.unreadCount?.let { _unreadCount.value = it }
                NotificationPage(dto.items.map { it.toDomain() }, dto.nextCursor)
            }
        }

    override suspend fun markRead(ids: List<String>) = withContext(io) {
        apiCall { api.markRead(MarkReadReq(ids)) }.map { resp ->
            resp.unreadCount?.let { _unreadCount.value = it }
            resp.updated
        }
    }

    override suspend fun markAllRead() = withContext(io) {
        apiCall { api.markAllRead() }.map { resp ->
            _unreadCount.value = resp.unreadCount ?: 0
            resp.updated
        }
    }

    override suspend fun unreadCount() = withContext(io) {
        apiCall { api.unreadCount() }.map { it.unreadCount.also { c -> _unreadCount.value = c } }
    }
}
```

`apiCall { … }` and `ApiResult.map` are the AND-018 helpers. `@IoDispatcher` is
the qualifier from the dispatchers module. No new Gradle dependencies are added;
`core-network` already has Retrofit/Moshi/Hilt and (test) MockWebServer,
`core-data` already depends on `:core-network`, `:core-model`, AND-018, and the
dispatchers module.

## 5. API Contract

Base path (`dev`): `http://18.222.237.167:8000/`. All bodies JSON. Exact paths
and field names are confirmed against `frontend/src/api/endpoints/notifications.ts`
and `/openapi.json` before coding (Q-1).

### GET `ui/notifications`
Query: `?cursor=<opaque>&limit=20&unread_only=true`. Response `200`:
```json
{
  "items": [
    {
      "id": "ntf_01HRZ...",
      "type": "alert",
      "title": "New login from a new device",
      "body": "A session started on Pixel 7 (Android 14).",
      "read": false,
      "created_at": "2026-06-05T12:00:00Z",
      "read_at": null,
      "deep_link": "testlogon://sessions",
      "data": { "session_id": "sess_01HRY..." }
    }
  ],
  "next_cursor": "eyJvZmZzZXQiOjIwfQ==",
  "unread_count": 7
}
```

### POST `ui/notifications/mark-read`
Request:
```json
{ "ids": ["ntf_01HRZ...", "ntf_01HS0..."] }
```
Response `200`:
```json
{ "ok": true, "updated": 2, "unread_count": 5 }
```

### POST `ui/notifications/mark-all-read`
Request: no body. Response `200`: `{ "ok": true, "updated": 5, "unread_count": 0 }`.

### GET `ui/notifications/unread-count`
Response `200`: `{ "unread_count": 7 }`.

**Error envelope (all endpoints):** FastAPI `detail` union
(`string | [{msg, type, loc}] | {code, ...}`). Non-2xx surfaces from the API as
`retrofit2.HttpException`; the repository maps it to `ApiResult.Error` via
**AND-015**. `401` is handled by the AND-013 `Authenticator` (refresh-then-retry
once) before it reaches the repository.

## 6. Data & State Management

- **DTOs are transient wire types** and must not be stored directly in Room or
  DataStore. The repository maps them to the domain `Notification` model. ISO-8601
  timestamps become `java.time.Instant` at the repository boundary.
- **`NotificationsApi` is stateless** — a singleton interface proxy with no
  fields. Session identity rides on cookies (AND-011), invisible to this layer.
- **Unread count state:** the repository holds the single source of truth for the
  badge via `MutableStateFlow<Int>`, updated from every response that carries
  `unread_count` (list, mark-read, mark-all-read, unread-count). A downstream badge
  composable collects `unreadCount: StateFlow<Int>` without re-fetching.
- **Pagination:** cursor-based. The repository surfaces `NotificationPage(items,
  nextCursor)`; assembling pages into a Paging 3 `PagingSource`/`Pager` is a
  downstream feature concern (AND-085+). This ticket exposes the primitive
  cursor-paged `list(...)` call only.
- **No Room caching in this ticket.** An offline/stale cache for notifications, if
  needed, is a separate E12 ticket; the repository here is network-only and
  returns `ApiResult.Error` (not stale data) when offline.
- **Serialization:** request/response (de)serialization uses Moshi codegen
  adapters via the shared converter; unknown JSON keys are ignored and absent
  optional fields fall back to Kotlin defaults (lenient).

## 7. Error Handling & Resilience

- **Non-2xx** surfaces from `NotificationsApi` as `retrofit2.HttpException`
  carrying the raw `detail` body; `DefaultNotificationRepository` (via the AND-018
  `apiCall` wrapper) converts it to `ApiResult.Error` with the AND-015-mapped
  `ApiError`. The repository never throws to callers.
- **`401`** on any call is intercepted by the AND-013 `Authenticator`, which calls
  `sessionRefresh()` once and retries; a second `401` becomes `ApiResult.Error`
  whose code lets the feature route to login (AND-025).
- **Transport failures** (`SocketTimeoutException`, `UnknownHostException`,
  `IOException`) from the ~20s-timeout client (AND-009) map to
  `ApiResult.Error(...)` with an offline/timeout classification. Idempotent GETs
  (`list`, `unreadCount`) are eligible for AND-016 bounded backoff on the shared
  client; the mutating `markRead`/`markAllRead` calls are **not** retried (avoid
  double-apply, even though they are server-idempotent by id).
- **Timestamp parsing:** `created_at` uses `Instant.parse` and is required; a
  malformed value throws during mapping. To keep list rendering robust, the mapper
  wraps the *optional* `read_at` parse in `runCatching` (→ `null` on failure) but
  treats a malformed `created_at` as a mapping error that becomes
  `ApiResult.Error` rather than crashing the stream (Q-2: confirm whether to
  fall back to `Instant.EPOCH` instead).
- **Unknown `type` token** maps to `NotificationType.UNKNOWN`, never throws, so an
  additive backend notification kind cannot crash the list.
- **Deserialization failures** surface as `JsonDataException` from the converter
  and are folded into `ApiResult.Error`; lenient parsing minimizes these against
  the evolving dev backend.
- **Idempotency on retry:** because the user may retry mark-read after a perceived
  failure, `markRead(ids)` is safe to re-send (server applies by id); the
  repository surfaces success/failure and the UI may retry without duplicate side
  effects.

## 8. Security & Privacy

- **Authenticated, cookie-scoped:** all four endpoints return only the current
  principal's notifications (server-enforced via the session cookie). The client
  passes identity implicitly through the cookie jar (AND-011); no user id is sent.
- **CSRF:** mutating verbs (`mark-read`, `mark-all-read`) carry `X-CSRF-Token`
  injected by AND-012. No manual `Cookie`/`Authorization`/CSRF headers are declared
  in `NotificationsApi`.
- **Plaintext dev host:** notification bodies may contain personal context (e.g.
  "new login from <device>"). On `dev` this rides plaintext HTTP — a known
  dev-only risk permitted by the scoped cleartext config (AND-006);
  `staging`/`prod` are HTTPS-only.
- **Logging hygiene:** notification `title`/`body`/`data` may carry PII and must
  **not** be logged. This ticket adds no logging; HTTP logging is inherited from
  AND-009's redacting interceptor (debug builds only). A code-review check confirms
  no notification content reaches logcat in any build.
- **Deep links:** `deep_link` values are treated as untrusted input; the
  downstream UI must validate/allow-list the `testlogon://` scheme and host before
  navigating. Noted here as a constraint for AND-085; this layer passes the string
  through verbatim.

## 9. Accessibility & i18n

Not applicable at this layer — this is a headless DTO/API/repository surface with
no UI and no app-authored user-facing strings. Notification `title`/`body` are
server-supplied content passed through verbatim; their presentation,
content-description, and any locale handling are owned by the notification-center
UI ticket (AND-085+). No `strings.xml` entries are added here. Relative-time
formatting of `createdAt` is a UI concern; this layer provides a parsed `Instant`
to enable it.

## 10. Telemetry & Logging

- **HTTP logging** is inherited from AND-009's redacting `HttpLoggingInterceptor`
  (debug builds only); no new logging is added and notification content is not
  logged (Section 8).
- **No analytics events** are emitted by this layer. Notification-open /
  mark-read / mark-all-read engagement events are emitted by the feature
  ViewModel (AND-085+), derived from `ApiResult` outcomes — not from the API or
  repository directly.
- **Build-time signal:** KSP must have generated Moshi adapters for every DTO in
  Section 4; a missing adapter fails the build (no reflection fallback, per
  AND-010 policy).

## 11. Testing Strategy

JVM unit tests only; no Android instrumentation. Two suites: a MockWebServer
suite in `core-network/src/test/...` against the production Moshi/Retrofit config,
and a repository suite in `core-data/src/test/...` using a fake/mock
`NotificationsApi` plus a `StandardTestDispatcher`.

Test harness (network):
```kotlin
private fun api(server: MockWebServer): NotificationsApi {
    val moshi = Moshi.Builder().build()                 // mirrors provideMoshi()
    return Retrofit.Builder()
        .baseUrl(server.url("/"))
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
        .create(NotificationsApi::class.java)
}
```

**T-1 — `list` contract & mapping (backlog AC).**
```kotlin
@Test fun list_getsAndDecodesPage() = runTest {
    val server = MockWebServer().apply {
        enqueue(MockResponse().setBody("""
          {"items":[{"id":"ntf_1","type":"alert","title":"Hi","read":false,
            "created_at":"2026-06-05T12:00:00Z","data":{"k":"v"}}],
           "next_cursor":"c2","unread_count":3}"""))
        start()
    }
    val resp = api(server).list(cursor = null, limit = 20, unreadOnly = true)
    val req = server.takeRequest()
    assertEquals("GET", req.method)
    assertTrue(req.path!!.startsWith("/ui/notifications"))
    assertTrue(req.path!!.contains("limit=20"))
    assertTrue(req.path!!.contains("unread_only=true"))
    assertEquals("ntf_1", resp.items.single().id)
    assertEquals("c2", resp.nextCursor)
    assertEquals(3, resp.unreadCount)
    server.shutdown()
}
```

**T-2 — `markRead` contract & mapping (backlog AC).** Posts
`{"ids":[...]}` to `/ui/notifications/mark-read` (verb POST), decodes
`MarkReadResp(ok, updated, unread_count)`; assert request body contains
`"ids"` and the serialized id, assert `updated == 2`.

**T-3 — `markAllRead`** issues `POST /ui/notifications/mark-all-read` with an
empty body and decodes `MarkReadResp` with `unread_count == 0`.

**T-4 — `unreadCount`** issues `GET /ui/notifications/unread-count` and decodes
`UnreadCountResp(unread_count)`.

**T-5 — DTO field mapping.** `NotificationDto` decodes snake_case fields
(`created_at`, `read_at`, `deep_link`, `unread_count`) via codegen adapters;
serialized `MarkReadReq` emits `"ids"`.

**T-6 — unknown-key tolerance & defaults.** A `NotificationDto` JSON with an extra
`server_time` key and missing optional fields deserializes without error
(defaults applied).

**T-7 — error propagation.** A `403`/`401` from `list()` throws
`retrofit2.HttpException` (not swallowed), leaving room for AND-013/AND-015.

**T-8 — repository list mapping.** Given a fake `NotificationsApi` returning a
`NotificationPageDto`, `DefaultNotificationRepository.list(...)` returns
`ApiResult.Success` with domain `Notification`s whose `type` is normalized
(`"alert"` → `ALERT`, `"weird"` → `UNKNOWN`), `createdAt` parsed to `Instant`,
and `unreadCount` StateFlow updated to the response's `unread_count`.

**T-9 — repository mark-read mapping (backlog AC).**
`repository.markRead(listOf("ntf_1"))` returns `ApiResult.Success(updated)` and
updates the `unreadCount` StateFlow; a thrown `HttpException` from the fake API
yields `ApiResult.Error` (never throws).

**T-10 — Hilt provider.** Minimal `core-testing` harness injects
`NotificationsApi` and `NotificationRepository`, asserting both are non-null
singletons (same instance on repeated injection).

Coverage target: ≥90% on the new surface (DTOs, API binding, repository mapping).
Every endpoint has at least one path/verb assertion; list and mark-read each have
both an API-level and a repository-level mapping test.

## 12. Dependencies & Sequencing

**Hard upstream (must merge first):**
- **AND-027** — AuthApi / session endpoints (per backlog `Deps`). Establishes the
  authenticated cookie session and the shared Retrofit these endpoints ride on;
  the notification calls are meaningless without an authenticated session.

**Transitive upstream (already required by the auth chain):** AND-010
(Retrofit/Moshi), AND-009 (shared `OkHttpClient`), AND-011 (cookie jar), AND-012
(CSRF), AND-013 (401 refresh), AND-015 (`ApiError`), AND-016 (GET backoff),
AND-018 (`ApiResult`), AND-006 (`BuildConfig`), AND-003/AND-004 (module
structure, Hilt baseline).

**Downstream (this ticket blocks):**
- The **notification-center UI**, **badge composable**, and
  **`NotificationsViewModel`** consume `NotificationRepository`.
- A **Paging 3** `PagingSource` for the list (if built) wraps `list(cursor=…)`.
- (ID **AND-085** in `blocks` is a placeholder for the notifications feature
  consumer; align to the actual backlog id during grooming.)

**Sequencing within the ticket:** (1) confirm paths/field names against
`frontend/src/api/endpoints/notifications.ts` and `/openapi.json`; (2) add
`core-model` DTOs; (3) declare `NotificationsApi` + Hilt provider + MockWebServer
tests; (4) add domain model + `NotificationRepository` + repository tests.

## 13. Risks & Open Questions

- **R-1 Endpoint shape drift.** Paths/field names are inferred from convention;
  the live backend may differ (e.g. `mark-read` vs `read`, query param spellings,
  bare list vs paged envelope). Mitigation: confirm against the web reference and
  `/openapi.json` before coding. Guarded by T-1..T-4.
- **R-2 Pagination model.** The backend may use offset/`page` rather than an
  opaque `cursor`, or omit `next_cursor`. Mitigation: match the web reference;
  `list(...)` query params are adjusted to the confirmed contract.
- **R-3 Inline vs separate unread count.** `unread_count` may not appear inline in
  list/mark-read responses, making the dedicated `unread-count` endpoint the only
  source. Mitigation: the repository updates the StateFlow from whichever
  responses carry it and always re-reads via `unreadCount()` when needed.
- **R-4 Timestamp format.** If `created_at` is epoch-millis or a non-ISO format,
  `Instant.parse` throws. Mitigation: confirm format; add a tolerant parser if
  needed. Guarded by T-8.
- **Q-1** Exact paths/verbs: are mark-read/mark-all-read `POST` to the spelled
  paths above? *Proposed:* confirm via `/openapi.json`; adjust annotations.
- **Q-2** On malformed `created_at`, fail the item (→ `ApiResult.Error`) or fall
  back to `Instant.EPOCH`? *Proposed:* fail fast in dev; revisit for prod
  resilience.
- **Q-3** Does the list endpoint accept `unread_only`, and is the default page
  `limit` server-defined? *Proposed:* send `limit` only when provided; treat the
  filter as optional.

## 14. Acceptance Criteria

- **AC-1 (backlog).** `list` + `mark-read` **map correctly**, proven by tests:
  `list()` decodes the page envelope to domain `Notification`s with normalized
  `type` and parsed `Instant` (T-1, T-8); `markRead(ids)` serializes `{ids}`,
  decodes the updated count, and updates the unread StateFlow (T-2, T-9).
- **AC-2.** `NotificationsApi` declares exactly `list`, `markRead`, `markAllRead`,
  `unreadCount`; each endpoint's **verb + resolved path + request body** match
  Section 5, asserted with MockWebServer (T-1..T-4).
- **AC-3.** DTOs decode snake_case fields and tolerate unknown keys / absent
  optionals via codegen adapters (T-5, T-6).
- **AC-4.** `NotificationRepository` returns `ApiResult<T>` for all operations and
  never throws; non-2xx/transport failures become `ApiResult.Error` (T-9).
- **AC-5.** Unknown notification `type` maps to `NotificationType.UNKNOWN` without
  throwing (T-8).
- **AC-6.** `unreadCount: StateFlow<Int>` reflects the latest `unread_count` from
  list, mark-read, mark-all-read, and unread-count responses (T-8, T-9).
- **AC-7.** Non-2xx surfaces as `HttpException` from the API and is not swallowed
  (T-7); `401` is delegated to AND-013, not handled here.
- **AC-8.** `NotificationsApi` is Hilt-provided as a `@Singleton` on the shared
  Retrofit and `NotificationRepository` is `@Binds @Singleton`; no new
  `OkHttpClient`/`Retrofit` is created; no per-method CSRF/cookie headers declared
  (T-10).
- **AC-9.** All tests pass in CI; modules build clean under AGP 8.7.3 / Gradle 8.9
  / JDK 17 with KSP-generated adapters present and no detekt/lint regressions.

## 15. Definition of Done

- DTOs (`com.testlogon.android.core.model.notifications`), `NotificationsApi` +
  `NotificationsApiModule` (`...core.network.notifications`), and
  `NotificationRepository` / `DefaultNotificationRepository` + domain model
  (`...core.data.notifications`) are implemented, package base
  `com.testlogon.android`.
- Open questions Q-1/Q-2/Q-3 and risks R-1..R-4 are resolved against
  `/openapi.json` and `frontend/src/api/endpoints/notifications.ts`; the
  interface's paths/verbs/query params and the mapper reflect the confirmed
  contract.
- MockWebServer tests T-1..T-7, T-10 and repository tests T-8/T-9 are implemented
  and green in CI; ≥90% line coverage on the new surface; list and mark-read each
  have API-level and repository-level mapping assertions.
- No second `OkHttpClient`/`Retrofit`; no manual cookie/CSRF/auth headers in the
  interface; no notification content logged (verified in review).
- `./gradlew :core-model:test :core-network:testDebugUnitTest
  :core-data:testDebugUnitTest` passes locally and in CI with no new lint/detekt
  violations (AND-005 config).
- Code reviewed and merged to `android-port`; the notifications feature
  (UI/ViewModel/badge, AND-085+) is unblocked against `NotificationRepository`.
- A one-line note in the relevant module README (owned by AND-007) records the
  notifications path/verb map and the delegation of cookie/CSRF/refresh/error
  mapping to AND-011/AND-012/AND-013/AND-015.
