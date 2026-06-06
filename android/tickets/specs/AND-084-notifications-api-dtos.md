---
id: AND-084
title: Notifications API + DTOs
milestone: M2
epic: E12
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
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
`NotificationDto` (wire schema `NotificationOut`), `NotificationListResponseDto`
(list envelope, schema `NotificationListResponse`), `MarkNotificationsReadReq`
(schema `MarkNotificationsReadIn`), `MarkReadResp` (`{ ok, marked_count }`),
`UnreadCountResp` (`{ count }`). All are immutable `data class`es annotated
`@JsonClass(generateAdapter = true)`. (CORRECTED schema/field names — see §4.1.)

FR-2. Each DTO field maps to the backend snake_case name via `@Json(name=…)`
when the Kotlin property is camelCase. CORRECTED: per the backend schema, only
`notification_id` is server-required; every other `NotificationOut`/list field
has a server default, so they are modeled non-null with a Kotlin default that
mirrors the server default (e.g. `notification_type=""`, `batch_count=1`,
`unread_count=0`). The one field whose absence should fail fast is
`notification_id`.

FR-3. Declare a Retrofit `NotificationsApi` covering exactly: `list`
(paginated GET), `markRead` (mark one or many read), `markAllRead`, and
`unreadCount` (GET).

FR-4. List supports pagination parameters `cursor` and `limit` as `@Query`.
CORRECTED: there is NO `unread_only` filter on this endpoint (OpenAPI
params=cursor,limit). The response (`NotificationListResponse`) carries the page
of items, a nullable `next_cursor`, and a non-null `unread_count`.

FR-5. `markRead` is a mutating POST taking a body `{ notification_ids: [...] }`;
the CSRF header is injected globally by AND-012 (not declared per-method).
`markAllRead` is a mutating POST; CORRECTED: the web client sends an empty JSON
object `{}` as the body (not a truly bodyless request).

FR-6. A `NotificationRepository` interface + implementation in `core-data`
exposes: `list(...)`, `markRead(ids)`, `markAllRead()`, `unreadCount()`, each
returning `ApiResult<T>` (AND-018). The repository maps `NotificationDto` →
domain `Notification` (CORRECTED: `created_at` is epoch SECONDS `Long` →
`Instant.ofEpochSecond`, enum normalization of `notification_type`).

FR-7. The repository runs all calls on an injected IO dispatcher and never
throws to callers — non-2xx/transport failures are folded into
`ApiResult.Error` via AND-015 mapping.

FR-8. `unreadCount()` exposes the badge count (wire field `count`); the repository additionally
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

// CORRECTED against schema NotificationOut (openapi.pretty.json) and
// src/api/types.ts: NotificationOut. Wire field names are notification_id /
// notification_type (NOT id/type); created_at is epoch SECONDS (integer), not
// an ISO-8601 string; there is no read_at and no deep_link on the wire; data is
// an arbitrary JSON object (Record<string, unknown>); batch_key/batch_count/
// batch_actors are real fields. Only notification_id is required server-side;
// every other field has a server default, so they are modeled non-null with a
// Kotlin default mirroring that default.
@JsonClass(generateAdapter = true)
data class NotificationDto(
    @Json(name = "notification_id") val notificationId: String,                   // required
    @Json(name = "notification_type") val notificationType: String = "",          // default ""
    val title: String = "",                                                       // default ""
    val body: String = "",                                                        // default ""
    val read: Boolean = false,
    @Json(name = "created_at") val createdAt: Long = 0L,                          // epoch SECONDS
    val data: Map<String, Any?> = emptyMap(),                                     // free-form JSON object
    @Json(name = "batch_key") val batchKey: String? = null,
    @Json(name = "batch_count") val batchCount: Int = 1,                          // default 1
    @Json(name = "batch_actors") val batchActors: List<String> = emptyList(),
)

// CORRECTED: backend schema is NotificationListResponse. unread_count is a
// non-null integer with server default 0 (it is NOT optional/inline-only).
@JsonClass(generateAdapter = true)
data class NotificationListResponseDto(
    val items: List<NotificationDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
    @Json(name = "unread_count") val unreadCount: Int = 0,
)

// CORRECTED: backend schema is MarkNotificationsReadIn; the field is
// notification_ids (NOT ids). The MarkReadReq{alert_ids} schema in the OpenAPI
// belongs to the ALERTS surface, not notifications — do not reuse it here.
@JsonClass(generateAdapter = true)
data class MarkNotificationsReadReq(
    @Json(name = "notification_ids") val notificationIds: List<String>,
)

// CORRECTED: the mark-read / mark-all-read responses are { ok, marked_count }.
// There is NO `updated` field and NO inline `unread_count` on these responses
// (confirmed in src/api/endpoints/notifications.ts). The OpenAPI index lists the
// 200 body as untyped (resp=200:), so this shape is taken from the frontend
// contract.
@JsonClass(generateAdapter = true)
data class MarkReadResp(
    val ok: Boolean = false,
    @Json(name = "marked_count") val markedCount: Int = 0,
)

// CORRECTED: the unread-count endpoint returns { count }, NOT { unread_count }
// (src/api/endpoints/notifications.ts: getNotificationUnreadCount).
@JsonClass(generateAdapter = true)
data class UnreadCountResp(
    val count: Int = 0,
)
```

### 4.2 Domain model + mapping (`core-data`)

```kotlin
package com.testlogon.android.core.data.notifications

import java.time.Instant

// CORRECTED enum tokens. The web reference (NotificationsPage.tsx TYPE_ICONS)
// uses these notification_type values: follow, like, comment, mention, tip,
// message, system. The previous ALERT/MFA/BILLING tokens were invented and do
// not appear in any source. UNKNOWN is the safe fallback for additive kinds.
enum class NotificationType { FOLLOW, LIKE, COMMENT, MENTION, TIP, MESSAGE, SYSTEM, UNKNOWN;
    companion object {
        fun fromToken(t: String?): NotificationType =
            entries.firstOrNull { it.name.equals(t, ignoreCase = true) } ?: UNKNOWN
    }
}

data class Notification(
    val id: String,
    val type: NotificationType,
    val title: String,
    val body: String,
    val read: Boolean,
    val createdAt: Instant,
    val batchKey: String?,
    val batchCount: Int,
    val batchActors: List<String>,
    val data: Map<String, Any?>,
)

// CORRECTED: createdAt is epoch SECONDS -> Instant.ofEpochSecond (NOT
// Instant.parse on an ISO string). No read_at/deep_link to map. notificationId/
// notificationType are the source fields.
internal fun NotificationDto.toDomain(): Notification = Notification(
    id = notificationId,
    type = NotificationType.fromToken(notificationType),
    title = title,
    body = body,
    read = read,
    createdAt = Instant.ofEpochSecond(createdAt),
    batchKey = batchKey,
    batchCount = batchCount,
    batchActors = batchActors,
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

import com.testlogon.android.core.model.notifications.MarkNotificationsReadReq
import com.testlogon.android.core.model.notifications.MarkReadResp
import com.testlogon.android.core.model.notifications.NotificationListResponseDto
import com.testlogon.android.core.model.notifications.UnreadCountResp
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Query

interface NotificationsApi {

    /**
     * Paginated list. Idempotent GET — eligible for AND-016 bounded backoff.
     * CORRECTED: only `cursor` and `limit` are accepted (OpenAPI params=cursor,limit;
     * the frontend getNotifications only sends limit/cursor). There is NO
     * `unread_only` query param on this endpoint — removed.
     */
    @GET("ui/notifications")
    suspend fun list(
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
    ): NotificationListResponseDto

    /** Mark a set of notifications read. Mutating POST (CSRF injected by AND-012). */
    @Headers("Content-Type: application/json")
    @POST("ui/notifications/mark-read")
    suspend fun markRead(@Body body: MarkNotificationsReadReq): MarkReadResp

    /**
     * Mark all read. CORRECTED: the web client POSTs an empty JSON object `{}`
     * (not a bodyless request). Send an explicit empty body so Content-Type
     * application/json is set and the request matches the web contract.
     */
    @Headers("Content-Type: application/json")
    @POST("ui/notifications/mark-all-read")
    suspend fun markAllRead(@Body body: Map<String, String> = emptyMap()): MarkReadResp

    /** Unread badge count. Idempotent GET. */
    @GET("ui/notifications/unread-count")
    suspend fun unreadCount(): UnreadCountResp
}
```

Path/verb conventions (consistent with AND-027): relative paths, no leading
slash in the Retrofit annotation, resolving against
`http://18.222.237.167:8000/` (the web client uses the equivalent absolute
`/ui/notifications` paths — same resolved URL). Mutating verbs (`mark-read`,
`mark-all-read`) receive `X-CSRF-Token` from AND-012; GETs (`list`,
`unread-count`) are AND-016 backoff candidates. Note: per the web client
(`src/api/client.ts`), the `X-CSRF-Token` (from the `ui_csrf` cookie) and an
`Authorization: Bearer` header are actually attached to ALL requests, not only
mutating verbs — that transport detail is owned upstream (AND-012/AND-027) and
inherited here, so `NotificationsApi` declares no headers itself.

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
    suspend fun list(cursor: String? = null,
                     limit: Int? = null): ApiResult<NotificationPage>   // CORRECTED: no unreadOnly
    suspend fun markRead(ids: List<String>): ApiResult<Int>      // returns marked_count
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

    // CORRECTED: list() no longer takes/sends unreadOnly (endpoint has no such
    // param). dto.unreadCount is non-null and always carried, so it always
    // refreshes the StateFlow.
    override suspend fun list(cursor: String?, limit: Int?) =
        withContext(io) {
            apiCall {                                            // AND-018 wrapper
                api.list(cursor, limit)
            }.map { dto ->
                _unreadCount.value = dto.unreadCount
                NotificationPage(dto.items.map { it.toDomain() }, dto.nextCursor)
            }
        }

    // CORRECTED: request is MarkNotificationsReadReq(notification_ids);
    // response is { ok, marked_count } with NO unread_count, so this call
    // cannot refresh the StateFlow from its own response — it returns
    // markedCount and the badge is re-read via unreadCount() / next list().
    override suspend fun markRead(ids: List<String>) = withContext(io) {
        apiCall { api.markRead(MarkNotificationsReadReq(ids)) }.map { resp ->
            resp.markedCount
        }
    }

    // CORRECTED: response is { ok, marked_count }, no unread_count field. We
    // optimistically zero the badge locally (all read) and return markedCount.
    override suspend fun markAllRead() = withContext(io) {
        apiCall { api.markAllRead() }.map { resp ->
            _unreadCount.value = 0
            resp.markedCount
        }
    }

    // CORRECTED: response field is `count`, not `unread_count`.
    override suspend fun unreadCount() = withContext(io) {
        apiCall { api.unreadCount() }.map { it.count.also { c -> _unreadCount.value = c } }
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
Query: `?cursor=<opaque>&limit=20` (CORRECTED: only `cursor` + `limit`; no
`unread_only`). Response `200` (schema `NotificationListResponse`):
```json
{
  "items": [
    {
      "notification_id": "ntf_01HRZ...",
      "notification_type": "follow",
      "title": "New follower",
      "body": "alice started following you.",
      "read": false,
      "created_at": 1749124800,
      "data": { "actor_id": "usr_01HRY..." },
      "batch_key": "follow:usr_01HRY",
      "batch_count": 1,
      "batch_actors": ["usr_01HRY..."]
    }
  ],
  "next_cursor": "eyJvZmZzZXQiOjIwfQ==",
  "unread_count": 7
}
```
CORRECTED field names: `notification_id`/`notification_type` (not `id`/`type`);
`created_at` is an epoch-seconds integer (not an ISO-8601 string); there is no
`read_at` and no `deep_link`; `batch_key`/`batch_count`/`batch_actors` are real
fields. `notification_type` observed values: follow, like, comment, mention,
tip, message, system.

### POST `ui/notifications/mark-read`
Request (schema `MarkNotificationsReadIn`):
```json
{ "notification_ids": ["ntf_01HRZ...", "ntf_01HS0..."] }
```
Response `200` (untyped in OpenAPI; shape from the web client):
```json
{ "ok": true, "marked_count": 2 }
```

### POST `ui/notifications/mark-all-read`
Request: empty JSON object `{}`. Response `200`: `{ "ok": true, "marked_count": 5 }`.
(CORRECTED: response is `{ ok, marked_count }` — there is no `updated` and no
`unread_count` on the mark-read / mark-all-read responses.)

### GET `ui/notifications/unread-count`
Response `200`: `{ "count": 7 }` (CORRECTED: field is `count`, not `unread_count`).

**Error envelope (all endpoints):** FastAPI `detail` union
(`string | [{msg, type, loc}] | {code, ...}`). Non-2xx surfaces from the API as
`retrofit2.HttpException`; the repository maps it to `ApiResult.Error` via
**AND-015**. `401` is handled by the AND-013 `Authenticator` (refresh-then-retry
once) before it reaches the repository.

## 6. Data & State Management

- **DTOs are transient wire types** and must not be stored directly in Room or
  DataStore. The repository maps them to the domain `Notification` model.
  CORRECTED: `created_at` (epoch-seconds integer) becomes `java.time.Instant`
  via `Instant.ofEpochSecond` at the repository boundary.
- **`NotificationsApi` is stateless** — a singleton interface proxy with no
  fields. Session identity rides on cookies (AND-011) plus the inherited
  `Authorization: Bearer` header (AND-027 transport), invisible to this layer.
- **Unread count state:** the repository holds the single source of truth for the
  badge via `MutableStateFlow<Int>`. CORRECTED: only the `list` response
  (`unread_count`) and the `unread-count` response (`count`) carry a count;
  mark-read returns only `marked_count`, and mark-all-read carries no count, so
  the repo zeroes the badge optimistically on mark-all-read. A downstream badge
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
- **Timestamp parsing:** CORRECTED — `created_at` is an epoch-seconds integer,
  mapped with `Instant.ofEpochSecond(createdAt)`. Because Moshi decodes it to a
  `Long` (defaulting to `0L` when absent), the mapping itself cannot throw a
  parse error, so the previous `read_at`/`Instant.parse` resilience handling no
  longer applies (there is no `read_at` field). A `0L` `created_at` maps to the
  Unix epoch; the UI's relative-time formatter handles display. Q-2 (EPOCH
  fallback for malformed ISO strings) is therefore moot and resolved.
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

- **Authenticated, session-scoped:** all four endpoints return only the current
  principal's notifications (server-enforced). CORRECTED: per `src/api/client.ts`
  the web client authenticates with BOTH the session cookie (`credentials:
  include`, AND-011 cookie jar) AND an `Authorization: Bearer <accessToken>`
  header; no explicit `user_sub` is sent by the UI client (the OpenAPI lists an
  optional `user_sub` query param, used only by admin/impersonation flows, not by
  the first-party UI). The Bearer/cookie transport is inherited from AND-027.
- **CSRF:** CORRECTED — per the web client the `X-CSRF-Token` (read from the
  `ui_csrf` cookie) is attached to ALL requests, not only mutating verbs; it is
  injected by the shared transport (AND-012). No manual
  `Cookie`/`Authorization`/CSRF headers are declared in `NotificationsApi`.
- **Plaintext dev host:** notification bodies may contain personal context (e.g.
  "new login from <device>"). On `dev` this rides plaintext HTTP — a known
  dev-only risk permitted by the scoped cleartext config (AND-006);
  `staging`/`prod` are HTTPS-only.
- **Logging hygiene:** notification `title`/`body`/`data` may carry PII and must
  **not** be logged. This ticket adds no logging; HTTP logging is inherited from
  AND-009's redacting interceptor (debug builds only). A code-review check confirms
  no notification content reaches logcat in any build.
- **Deep links / payload:** CORRECTED — there is no `deep_link` field on the wire
  (it was invented in the original draft). Any navigation target lives inside the
  free-form `data` object (e.g. `actor_id`, `session_id`); the `data` map is
  untrusted input and the downstream UI (AND-085) must validate any value it uses
  to navigate. This layer passes `data` through verbatim as `Map<String, Any?>`.

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
          {"items":[{"notification_id":"ntf_1","notification_type":"follow",
            "title":"Hi","body":"b","read":false,
            "created_at":1749124800,"data":{"k":"v"},
            "batch_count":1,"batch_actors":[]}],
           "next_cursor":"c2","unread_count":3}"""))
        start()
    }
    val resp = api(server).list(cursor = null, limit = 20)   // CORRECTED: no unreadOnly arg
    val req = server.takeRequest()
    assertEquals("GET", req.method)
    assertTrue(req.path!!.startsWith("/ui/notifications"))
    assertTrue(req.path!!.contains("limit=20"))
    assertFalse(req.path!!.contains("unread_only"))          // CORRECTED: param does not exist
    assertEquals("ntf_1", resp.items.single().notificationId)
    assertEquals("c2", resp.nextCursor)
    assertEquals(3, resp.unreadCount)
    server.shutdown()
}
```

**T-2 — `markRead` contract & mapping (backlog AC).** CORRECTED. Posts
`{"notification_ids":[...]}` to `/ui/notifications/mark-read` (verb POST),
decodes `MarkReadResp(ok, marked_count)`; assert request body contains
`"notification_ids"` and the serialized id, assert `markedCount == 2`.

**T-3 — `markAllRead`** issues `POST /ui/notifications/mark-all-read` with an
empty JSON object `{}` body and decodes `MarkReadResp` with `marked_count == 5`.

**T-4 — `unreadCount`** issues `GET /ui/notifications/unread-count` and decodes
`UnreadCountResp(count)` (CORRECTED field name).

**T-5 — DTO field mapping.** CORRECTED. `NotificationDto` decodes snake_case
fields (`notification_id`, `notification_type`, `created_at` as a Long,
`batch_key`, `batch_count`, `batch_actors`) via codegen adapters; serialized
`MarkNotificationsReadReq` emits `"notification_ids"`.

**T-6 — unknown-key tolerance & defaults.** A `NotificationDto` JSON with an extra
`server_time` key and missing optional fields deserializes without error
(defaults applied).

**T-7 — error propagation.** A `403`/`401` from `list()` throws
`retrofit2.HttpException` (not swallowed), leaving room for AND-013/AND-015.

**T-8 — repository list mapping.** CORRECTED. Given a fake `NotificationsApi`
returning a `NotificationListResponseDto`, `DefaultNotificationRepository.list(...)`
returns `ApiResult.Success` with domain `Notification`s whose `type` is normalized
(`"follow"` → `FOLLOW`, `"weird"` → `UNKNOWN`), `createdAt` mapped from epoch
seconds via `Instant.ofEpochSecond`, and the `unreadCount` StateFlow updated to
the response's `unread_count`.

**T-9 — repository mark-read mapping (backlog AC).** CORRECTED.
`repository.markRead(listOf("ntf_1"))` returns `ApiResult.Success(markedCount)`
(the mark-read response carries no count, so the StateFlow is NOT updated by this
call); a thrown `HttpException` from the fake API yields `ApiResult.Error` (never
throws).

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

- **R-1 Endpoint shape drift. RESOLVED in this review.** Paths/verbs confirmed
  against the OpenAPI index and the web reference: `GET /ui/notifications`,
  `POST /ui/notifications/mark-read`, `POST /ui/notifications/mark-all-read`,
  `GET /ui/notifications/unread-count`. Field names were materially WRONG in the
  original draft and have been corrected throughout (see §16). Guarded by T-1..T-4.
- **R-2 Pagination model. RESOLVED.** The backend uses an opaque `cursor` + `limit`
  with a nullable `next_cursor` (confirmed: `NotificationListResponse`, OpenAPI
  params=cursor,limit). No offset/`page` variant.
- **R-3 Inline vs separate unread count. RESOLVED.** Confirmed: the `list`
  response carries `unread_count` (non-null) and the dedicated endpoint returns
  `{ count }`; mark-read returns only `marked_count` and mark-all-read carries no
  count. The repository refreshes the StateFlow from `list`/`unread-count` and
  zeroes it optimistically on mark-all-read.
- **R-4 Timestamp format. RESOLVED.** `created_at` is epoch SECONDS (integer),
  mapped via `Instant.ofEpochSecond`. No ISO string and therefore no parse risk;
  the prior `Instant.parse` concern is removed.
- **Q-1** Exact paths/verbs. **RESOLVED:** all four confirmed as above
  (OpenAPI index lines 1686–1690; `src/api/endpoints/notifications.ts`).
- **Q-2** Malformed `created_at` handling. **RESOLVED / moot:** the field is a
  numeric epoch decoded to `Long` (default `0L`); there is no string parse that
  can fail, so no `Instant.EPOCH` fallback decision is needed.
- **Q-3** `unread_only` + default `limit`. **RESOLVED:** there is NO `unread_only`
  param; only `cursor` and `limit` are accepted, both optional with the page size
  server-defined when `limit` is omitted (the web client sends `limit=30`).

## 14. Acceptance Criteria

- **AC-1 (backlog).** `list` + `mark-read` **map correctly**, proven by tests:
  `list()` decodes the `NotificationListResponse` envelope to domain
  `Notification`s with normalized `notification_type` and `created_at` mapped from
  epoch seconds (T-1, T-8); `markRead(ids)` serializes `{notification_ids}` and
  decodes `marked_count` (T-2, T-9). (CORRECTED: req field is `notification_ids`,
  resp field is `marked_count`; mark-read does NOT update the StateFlow.)
- **AC-2.** `NotificationsApi` declares exactly `list`, `markRead`, `markAllRead`,
  `unreadCount`; each endpoint's **verb + resolved path + request body** match
  Section 5, asserted with MockWebServer (T-1..T-4).
- **AC-3.** DTOs decode snake_case fields and tolerate unknown keys / absent
  optionals via codegen adapters (T-5, T-6).
- **AC-4.** `NotificationRepository` returns `ApiResult<T>` for all operations and
  never throws; non-2xx/transport failures become `ApiResult.Error` (T-9).
- **AC-5.** Unknown `notification_type` maps to `NotificationType.UNKNOWN` without
  throwing (T-8).
- **AC-6.** CORRECTED. `unreadCount: StateFlow<Int>` reflects the latest count
  from the `list` response (`unread_count`) and the `unread-count` response
  (`count`), and is zeroed on `mark-all-read`; `mark-read` carries no count and
  does not update it (T-8, T-9).
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources:
**OpenAPI index** = `reference/openapi.index.txt`; **OpenAPI spec** =
`reference/openapi.pretty.json` (components.schemas.<Name>); **FE** =
`reference/src/...`.

1. **`GET /ui/notifications` exists, params `cursor`,`limit` only; 200 =
   `NotificationListResponse`.** VERDICT: Verified (and Corrected — draft also
   claimed an `unread_only` param, which does not exist). SOURCE: OpenAPI index
   `GET /ui/notifications | resp=200:NotificationListResponse | params=cursor,limit,user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN`; FE `src/api/endpoints/notifications.ts: getNotifications`.
2. **`POST /ui/notifications/mark-read`, req `MarkNotificationsReadIn`.** VERDICT:
   Verified. SOURCE: OpenAPI index `POST /ui/notifications/mark-read | req=MarkNotificationsReadIn`; FE `src/api/endpoints/notifications.ts: markNotificationsRead`.
3. **`POST /ui/notifications/mark-all-read`, empty `{}` body.** VERDICT: Verified.
   SOURCE: OpenAPI index `POST /ui/notifications/mark-all-read | req=`; FE
   `src/api/endpoints/notifications.ts: markAllNotificationsRead` (posts `{}`).
4. **`GET /ui/notifications/unread-count`.** VERDICT: Verified. SOURCE: OpenAPI
   index `GET /ui/notifications/unread-count`; FE `getNotificationUnreadCount`.
5. **Notification item wire shape = schema `NotificationOut`: required
   `notification_id`; `notification_type`, `title`, `body`, `read`, `created_at`,
   `data`, `batch_key`, `batch_count`, `batch_actors` (all defaulted).** VERDICT:
   Corrected (draft used `id`/`type`/`read_at`/`deep_link`). SOURCE: OpenAPI spec
   `components.schemas.NotificationOut` (required: [notification_id]); FE
   `src/api/types.ts: NotificationOut`.
6. **`created_at` is epoch SECONDS (integer), not ISO-8601 string.** VERDICT:
   Corrected. SOURCE: OpenAPI spec `NotificationOut.created_at` `type:integer
   default:0`; FE `src/pages/notifications/NotificationsPage.tsx: formatTimeAgo`
   (`Math.floor(Date.now()/1000) - ts`).
7. **List envelope `NotificationListResponse` = `items`, nullable `next_cursor`,
   non-null `unread_count` (default 0).** VERDICT: Verified/Corrected (draft made
   `unread_count` an optional "some backends" field). SOURCE: OpenAPI spec
   `components.schemas.NotificationListResponse`; FE `src/api/types.ts: NotificationListResponse`.
8. **mark-read request field is `notification_ids` (NOT `ids`).** VERDICT:
   Corrected. SOURCE: OpenAPI spec `components.schemas.MarkNotificationsReadIn.notification_ids`;
   FE `src/api/types.ts: MarkNotificationsReadReq`; FE `NotificationsPage.tsx`
   (`markNotificationsRead({ notification_ids: ids })`). NOTE: the OpenAPI also
   contains a separate `MarkReadReq{alert_ids}` schema — that belongs to the
   ALERTS surface, not notifications.
9. **mark-read / mark-all-read response = `{ ok, marked_count }` (no `updated`,
   no `unread_count`).** VERDICT: Corrected. SOURCE: FE
   `src/api/endpoints/notifications.ts` (`{ ok: boolean; marked_count: number }`).
   The OpenAPI index lists these 200 bodies as untyped (`resp=200:`), so the
   field shape is taken from the frontend contract (see Open assumptions).
10. **unread-count response = `{ count }` (NOT `{ unread_count }`).** VERDICT:
    Corrected. SOURCE: FE `src/api/endpoints/notifications.ts: getNotificationUnreadCount`
    (`api.get<{ count: number }>`); also `NotificationsPage.tsx`
    (`unreadData?.count ?? data?.unread_count`).
11. **`notification_type` values: follow, like, comment, mention, tip, message,
    system.** VERDICT: Corrected (draft enumerated ALERT/MFA/BILLING, which appear
    nowhere). SOURCE: FE `src/pages/notifications/NotificationsPage.tsx: TYPE_ICONS`.
12. **CSRF via `X-CSRF-Token` from `ui_csrf` cookie, on ALL requests; plus
    `Authorization: Bearer` and cookies.** VERDICT: Corrected (draft said
    cookie-only and CSRF on mutating verbs only). SOURCE: FE `src/api/client.ts`
    (sets `Authorization: Bearer`, `X-CSRF-Token` from `getCookie("ui_csrf")` on
    every request, `credentials: include`).
13. **401 → single refresh-then-retry; refresh endpoint `POST /ui/session/refresh`.**
    VERDICT: Verified. SOURCE: FE `src/api/client.ts: refreshSession` /
    `api` 401 branch.
14. **Network/offline error surfaces distinctly (FE → `ApiError(0, ...)`).**
    VERDICT: Verified. SOURCE: FE `src/api/client.ts` catch block.
15. **FastAPI error `detail` union (string | [{msg,type,loc}] | {code,...}) and
    422 validation responses.** VERDICT: Verified. SOURCE: FE
    `src/api/client.ts: normalizeErrorDetail`; OpenAPI index `resp=...;422:HTTPValidationError`
    on all four endpoints; OpenAPI spec `components.schemas.HTTPValidationError`.
16. **Framework choices (Retrofit `@GET/@POST/@Query/@Body`, Moshi
    `@JsonClass(generateAdapter=true)` codegen via KSP, Hilt `@Provides`/`@Binds`).**
    VERDICT: Unverified-assumption (framework ref — not derivable from backend/FE
    sources). framework ref: Retrofit https://square.github.io/retrofit/ ; Moshi
    codegen https://github.com/square/moshi#codegen ; Hilt
    https://developer.android.com/training/dependency-injection/hilt-android .

### Corrections made

- Field/schema renames in DTOs (§4.1) and throughout: `id`→`notification_id`,
  `type`→`notification_type`; envelope `NotificationPageDto`→`NotificationListResponseDto`
  (`NotificationListResponse`); `MarkReadReq{ids}`→`MarkNotificationsReadReq{notification_ids}`
  (`MarkNotificationsReadIn`).
- `created_at` retyped from ISO-8601 `String` (`Instant.parse`) to epoch-seconds
  `Long` (`Instant.ofEpochSecond`); §4.2, §6, §7, §4.5, T-1, T-8.
- Removed invented wire fields `read_at` and `deep_link`; added the real
  `batch_key`/`batch_count`/`batch_actors` and `data: Map<String, Any?>` (§4.1,
  §4.2, §8 deep-link bullet).
- mark-read/mark-all-read response corrected to `{ ok, marked_count }` (no
  `updated`, no inline `unread_count`); unread-count response corrected to
  `{ count }` (§4.1, §4.5, §5, T-2/T-3/T-4/T-9, AC-1/AC-6).
- Removed the non-existent `unread_only` query param from `list` (interface §4.3,
  repo §4.5, FR-4, §5, T-1, Q-3).
- `NotificationType` enum tokens replaced with the real set (follow/like/comment/
  mention/tip/message/system + UNKNOWN) (§4.2, T-8).
- StateFlow update logic corrected: refreshed from `list`/`unread-count`, zeroed
  on `mark-all-read`, NOT updated by `mark-read` (§4.5, §6, AC-6).
- CSRF/auth description corrected: Bearer + cookie + CSRF-on-all-requests (§4.3
  note, §8).

### Open assumptions

- **mark-read / mark-all-read 200 body shape (`{ ok, marked_count }`):** the
  OpenAPI marks these responses as untyped (no schema), so the field names come
  solely from the frontend (`src/api/endpoints/notifications.ts`). Treated as
  authoritative because it is the live web contract, but it is not schema-pinned;
  if the live dev backend differs, adjust `MarkReadResp`. (Lenient Moshi parsing
  defaults `ok=false`/`marked_count=0` if either field is absent.)
- **`send` endpoint (`POST /ui/notifications/send`, `SendNotificationIn`):**
  exists in the backend/FE but is an admin/authoring path and out of scope for
  this read/mark ticket — intentionally not modeled. (Source: OpenAPI index line
  1689; FE `sendNotification`.)
- **`user_sub` / `X-SESSION-ID` / `X-IMPERSONATION-TOKEN` params** on these
  endpoints are admin/impersonation transport, not used by the first-party UI
  client; assumed handled (or omitted) by the inherited AND-027 transport, not by
  `NotificationsApi`.
- **Android framework annotations/versions** (item 16) are convention, not
  verifiable from the provided sources.

## 17. Test Plan

Test targets: **JVM** = local JVM/Robolectric unit (no device); **emu35** =
headless AVD `test35` (x86_64, API 35); **A15** = physical Samsung Galaxy A15 5G
(SM-A156U, serial R5CX821TA9R, API 34, arm64-v8a). This ticket is a headless
DTO/API/repository surface, so the core suite is JVM contract/unit; a few
instrumented cases verify the inherited transport (CSRF/cookie/refresh) and ABI
parity on real targets.

- **TC-AND-084-01** — Type: contract/MockWebServer (JVM). Target: `NotificationsApi.list`.
  Preconditions: MockWebServer with production Moshi/Retrofit config.
  Steps: enqueue a 200 `NotificationListResponse` body with one `NotificationOut`
  (`notification_id`,`notification_type`,`created_at` integer,`data`,`batch_*`),
  call `list(cursor=null, limit=20)`. Expected: request is `GET`, path starts
  `/ui/notifications`, contains `limit=20`, contains NO `unread_only`; decoded
  `items[0].notificationId == "ntf_1"`, `nextCursor == "c2"`, `unreadCount == 3`.
  Traces: AC-1, AC-2, AC-3.
- **TC-AND-084-02** — Type: contract/MockWebServer (JVM). Target:
  `NotificationsApi.markRead`. Preconditions: MockWebServer. Steps: enqueue
  `{"ok":true,"marked_count":2}`; call `markRead(MarkNotificationsReadReq(listOf("ntf_1","ntf_2")))`.
  Expected: request `POST` to `/ui/notifications/mark-read`, body JSON contains
  key `notification_ids` and both ids (NOT `ids`); decoded `ok==true`,
  `markedCount==2`. Traces: AC-1, AC-2.
- **TC-AND-084-03** — Type: contract/MockWebServer (JVM). Target:
  `NotificationsApi.markAllRead`. Steps: enqueue `{"ok":true,"marked_count":5}`;
  call `markAllRead()`. Expected: `POST /ui/notifications/mark-all-read`, request
  body is `{}` (Content-Type application/json), decoded `markedCount==5`.
  Traces: AC-2.
- **TC-AND-084-04** — Type: contract/MockWebServer (JVM). Target:
  `NotificationsApi.unreadCount`. Steps: enqueue `{"count":7}`; call
  `unreadCount()`. Expected: `GET /ui/notifications/unread-count`, decoded
  `count==7` (field is `count`, not `unread_count`). Traces: AC-2.
- **TC-AND-084-05** — Type: unit (JVM). Target: `NotificationDto` Moshi codegen
  adapter. Preconditions: production Moshi. Steps: decode a `NotificationOut`
  JSON that (a) includes an unknown extra key `server_time`, (b) omits all
  optional fields except `notification_id`. Expected: decode succeeds; defaults
  applied (`notificationType==""`, `body==""`, `read==false`, `createdAt==0L`,
  `batchCount==1`, `data=={}`); a JSON missing `notification_id` throws
  `JsonDataException`. Traces: AC-3.
- **TC-AND-084-06** — Type: unit (JVM). Target: `NotificationDto.toDomain()`.
  Steps: map DTOs with `notification_type` = `"follow"`, `"SYSTEM"` (mixed case),
  and `"weird"`, and `created_at = 1749124800`. Expected: types normalize to
  `FOLLOW`, `SYSTEM`, `UNKNOWN` (no throw); `createdAt == Instant.ofEpochSecond(1749124800)`.
  Traces: AC-1, AC-5.
- **TC-AND-084-07** — Type: unit (JVM). Target: `DefaultNotificationRepository.list`.
  Preconditions: fake `NotificationsApi` returning a `NotificationListResponseDto`
  (`unread_count=4`) on a `StandardTestDispatcher`. Steps: call `list()`, collect
  `unreadCount` StateFlow. Expected: `ApiResult.Success<NotificationPage>` with
  mapped domain `Notification`s; `unreadCount.value == 4`. Traces: AC-1, AC-4, AC-6.
- **TC-AND-084-08** — Type: unit (JVM). Target: `DefaultNotificationRepository`
  mark-read / state. Steps: seed StateFlow via a prior `list` (value 4); call
  `markRead(listOf("ntf_1"))` against a fake returning `marked_count=1`. Expected:
  `ApiResult.Success(1)`; `unreadCount.value` stays 4 (mark-read carries no count).
  Then `markAllRead()` → `ApiResult.Success(5)` and `unreadCount.value == 0`.
  Traces: AC-1, AC-4, AC-6.
- **TC-AND-084-09** — Type: unit (JVM). Target: repository error folding.
  Preconditions: fake API throwing `retrofit2.HttpException` (403) and, in a
  second case, `java.net.SocketTimeoutException`. Steps: call `list()` /
  `markRead()`. Expected: each returns `ApiResult.Error` (never throws); the
  transport-failure case is classified offline/timeout (AND-015 mapping); the
  HTTP case carries the mapped status. Traces: AC-4, AC-7.
- **TC-AND-084-10** — Type: contract/MockWebServer (JVM). Target: error
  propagation through the API layer. Steps: enqueue a `403` then a `422` with a
  FastAPI `detail`/`HTTPValidationError` body; call `list()`. Expected: the
  suspend call throws `retrofit2.HttpException` (not swallowed), leaving room for
  AND-013/AND-015; the `detail` body is retained on the exception. Traces: AC-7.
- **TC-AND-084-11** — Type: integration (Hilt) (JVM/Robolectric or emu35).
  Target: `NotificationsApiModule` / `NotificationDataModule`. Steps: build a
  Hilt test component; inject `NotificationsApi` and `NotificationRepository`
  twice. Expected: both non-null; repeated injection yields the SAME instance
  (`@Singleton`); the API is built on the shared `Retrofit` (no second
  `OkHttpClient`/`Retrofit`). Traces: AC-8.
- **TC-AND-084-12** — Type: instrumented/e2e (A15 — physical device REQUIRED).
  Target: inherited transport (CSRF + cookie + Bearer + 401 refresh) on a real
  authenticated session against the dev host. Preconditions: app logged in
  (valid `ui_csrf` cookie + access token), device on network. Steps: call
  `repository.markRead(ids)`; capture the outbound request. Expected: request
  carries `X-CSRF-Token` (from `ui_csrf`) and `Authorization: Bearer` and session
  cookie (none declared in `NotificationsApi`); on a forced 401 the AND-013
  `Authenticator` performs one `POST /ui/session/refresh` then retries.
  Rationale for physical device: exercises the real cookie jar/Credential-backed
  session and real network rather than emulator loopback. Traces: AC-7, AC-8.
- **TC-AND-084-13** — Type: integration (offline / flaky-dev-host) (emu35; or
  A15 with airplane mode). Target: repository offline path. Preconditions: dev
  host unreachable (emulator: no network / wrong host; device: airplane mode).
  Steps: call `list()` and `unreadCount()`. Expected: each returns
  `ApiResult.Error` with offline/timeout classification within the ~20s client
  timeout (AND-009); never throws; no stale data returned (network-only). GETs
  may show AND-016 bounded-retry attempts; mark-read is NOT auto-retried.
  Traces: AC-4.
- **TC-AND-084-14** — Type: instrumented (ABI/API parity) (run on BOTH A15
  arm64-v8a/API-34 and emu35 x86_64/API-35). Target: Moshi codegen
  decode + `Instant.ofEpochSecond` mapping. Steps: run TC-05/06 decode+map
  assertions as an instrumented test on each target. Expected: identical decoded
  values and identical `Instant` results on arm64-v8a/API-34 and x86_64/API-35
  (no ABI/desugaring `java.time` divergence). Rationale for physical device:
  confirms arm64 + API-34 (core-library desugaring) parity with the API-35
  emulator. Traces: AC-3, AC-1.

Accessibility note: this layer has no UI, so no Compose-UI/a11y cases apply here;
content-description and relative-time presentation for `title`/`body`/`createdAt`
are owned by AND-085 and tested there.

### Coverage matrix

| AC (§14) | Covered by |
| --- | --- |
| AC-1 (list + mark-read map correctly) | TC-01, TC-02, TC-06, TC-07, TC-08, TC-14 |
| AC-2 (exactly 4 ops; verb/path/body) | TC-01, TC-02, TC-03, TC-04 |
| AC-3 (snake_case decode, unknown-key/defaults) | TC-01, TC-05, TC-14 |
| AC-4 (ApiResult, never throws) | TC-07, TC-08, TC-09, TC-13 |
| AC-5 (unknown type → UNKNOWN) | TC-06 |
| AC-6 (unreadCount StateFlow semantics) | TC-07, TC-08 |
| AC-7 (non-2xx → HttpException; 401 → AND-013) | TC-09, TC-10, TC-12 |
| AC-8 (Hilt singletons, shared Retrofit, no per-method headers) | TC-11, TC-12 |
| AC-9 (CI build/tests green, KSP adapters) | all TC-01..TC-14 (suite green in CI) |
