---
id: AND-120
title: Messaging API + DTOs
milestone: M3
epic: E18
priority: P0
size: M
status: draft
depends_on: [AND-027, AND-026, AND-010]
blocks: [AND-121, AND-122, AND-123, AND-124, AND-125]
---

# AND-120 — Messaging API + DTOs

## 1. Overview & Goal

This ticket defines the typed HTTP seam for the TestLogon messaging domain: a
Retrofit service interface `MessagingApi` plus the Moshi DTOs it (de)serializes,
covering the conversation list, a single conversation, the messages within a
conversation, and the messaging feature configuration. It is the transport layer
that the messaging feature (`feature-messaging`) and its repositories
(`core-data`) build on for the conversation list (AND-121/AND-122), the thread
screen (AND-123), text send (AND-124), and read state (AND-125).

Scope, verbatim from the backlog: *`MessagingApi` + DTOs for
`/messaging/conversations`, `/conversations/{id}`, `/conversations/{id}/messages`,
`/config`.* The single acceptance criterion is that *conversation + message
payloads map (tested vs fixtures)* — i.e. every documented JSON shape decodes
into its DTO (and request DTOs serialize) exactly, proven with `MockWebServer`
and captured fixtures.

This is a **transport + DTO-definition** ticket. It owns: the `MessagingApi`
interface (verbs, paths, `@Body`/`@Path`/`@Query` bindings), the
`@JsonClass(generateAdapter = true)` DTOs and any custom adapters they need, the
Hilt provider that builds the service from the shared Retrofit, and a fixture-
driven `MockWebServer` test suite. It deliberately does **not** own: cursor/page
plumbing for Paging 3 (AND-122 `PagingSource`, this ticket only exposes the
cursor-shaped endpoint), the SWR cache (AND-116/`core-data`), optimistic send
reconciliation (AND-124), read-state UX (AND-125), `ApiResult` wrapping
(AND-018), FastAPI `detail` error mapping (AND-015), or any ViewModel/UI. Cookie
jar (AND-011), CSRF header injection (AND-012), and 401-refresh (AND-013) attach
to the shared `OkHttpClient` and apply to `MessagingApi` calls without changes
here.

The deliverable: a compiling `MessagingApi`, its DTOs + adapters in `core-model`,
its Hilt provider, captured JSON fixtures, and a `MockWebServer` test suite
asserting each endpoint's verb, resolved path, request body / query params, and
successful response decoding against those fixtures.

## 2. Context & References

- **Repo / location:** `spannella/testlogon`, monorepo subfolder `android/`,
  branch `android-port`. The interface + provider land in module
  **`core-network`** under package
  `com.testlogon.android.core.network.messaging`; the DTOs land in
  **`core-model`** under `com.testlogon.android.core.model.messaging`.
- **Canonical package:** `com.testlogon.android` everywhere.
- **Stack pins relevant here:** Kotlin 2.0.21, Retrofit **2.11.0**, OkHttp
  **4.12.0**, Moshi **1.15.x** (codegen via KSP), Hilt (KSP), Coroutines, JDK 17,
  minSdk 24 / compileSdk 35, AGP 8.7.3, Gradle 8.9.
- **Module layering:** `app -> feature-* -> core-*`. `MessagingApi` lives in
  `core-network`, consumes DTOs from `core-model`, and is consumed by `core-data`
  repositories and `feature-messaging`. No `feature-*`/`app` symbols leak into
  `core-network`/`core-model`.
- **Pattern precedent — AND-027 (`AuthApi`) and AND-026 (Auth DTOs):** this
  ticket follows the same shape — relative paths with no leading slash, `suspend`
  methods returning DTO bodies, `@Headers("Content-Type: application/json")` on
  JSON POSTs, a `@Provides @Singleton` that calls `retrofit.create(...)`, Moshi
  codegen DTOs with snake_case `@Json(name=...)` mappings, and MockWebServer
  contract tests. Reuse those conventions verbatim.
- **Upstream dependency — AND-027:** the backlog names AND-027 as the dependency.
  AND-120 mirrors AND-027's transport conventions and depends on the same shared
  Retrofit/Moshi/OkHttp wiring (AND-010/AND-009/AND-006) and on the DTO+adapter
  conventions established by AND-026.
- **Downstream consumers (this ticket blocks):** AND-121 (conversation list
  screen), AND-122 (list ViewModel + Paging 3 — consumes the cursor-paged
  messages/conversations endpoints), AND-123 (thread screen — paged reverse
  history), AND-124 (`POST /conversations/{id}/messages` send), AND-125 (`POST
  /conversations/{id}/read`).
- **Auth:** all messaging calls are authenticated; the session rides on cookies +
  `ui_csrf` → `X-CSRF-Token` (AND-011/AND-012), and a `401` triggers AND-013
  refresh-then-retry once. `MessagingApi` is header-agnostic.
- **Backend:** FastAPI + DynamoDB; dev host `http://18.222.237.167:8000` is
  plaintext and unreliable (~20s timeouts, bounded backoff for idempotent GETs —
  AND-009/AND-016). OpenAPI at `/openapi.json`. Web reference for the exact
  shapes: `frontend/src/api/endpoints/messaging.ts` (or equivalent) and shared
  types in `frontend/src/api/types.ts` — these are the source of truth for field
  names and the conversations/messages cursor envelope.

## 3. Functional Requirements

FR-1. Declare a single Retrofit interface `MessagingApi` covering exactly:
`config`, `listConversations`, `getConversation`, `listMessages`,
`sendMessage`, `markRead`.

FR-2. Each method's verb + relative path matches the backend (Section 5). Paths
have **no leading slash** (AND-010 convention) so they append to the normalized
base URL. The backlog scope lists `/messaging/conversations`,
`/conversations/{id}`, `/conversations/{id}/messages`, `/config`; the exact
prefix (`messaging/` vs bare) is reconciled against `/openapi.json` and the web
reference before coding (Q-1) and declared consistently.

FR-3. All methods are `suspend` and return the typed DTO body. `markRead` returns
`OkResp` (reused from AND-026 Appendix A) or `Unit` per the confirmed shape (Q-4).

FR-4. Idempotent GETs (`config`, `listConversations`, `getConversation`,
`listMessages`) accept paging/filter inputs via `@Query`; mutating POSTs
(`sendMessage`, `markRead`) use `@Body` request DTOs. No raw `Map`/`JsonObject`
bodies.

FR-5. `listConversations` and `listMessages` are **cursor-paged**: each accepts an
optional `cursor: String?` and `limit: Int?` query param and returns a paged
envelope DTO (`items` + `next_cursor`) so AND-122/AND-123's Paging 3 sources can
drive forward/reverse pagination. `listMessages` supports reverse-chronological
history (AND-123) via the same cursor (Q-3 confirms `before`/`after` semantics).

FR-6. `sendMessage` posts `{ "body": "..." , "client_id": "..." }` and returns the
persisted `MessageDto` (server-assigned `id`, `created_at`, echoed `client_id`)
so AND-124 can reconcile its optimistic placeholder.

FR-7. POST methods carry `@Headers("Content-Type: application/json")`. The CSRF
header is **not** declared per-method (injected globally by AND-012).

FR-8. A Hilt `@Provides @Singleton fun provideMessagingApi(retrofit: Retrofit):
MessagingApi` constructs the service from the shared Retrofit (AND-010). No new
Retrofit/OkHttp instance is created.

FR-9. DTOs are Moshi `@JsonClass(generateAdapter = true)` with explicit
`@Json(name="...")` for every snake_case backend field. Optional fields are
nullable with Kotlin defaults; unknown keys are ignored (lenient).

FR-10. Provide captured JSON fixtures (via the AND-046 `core-testing` harness) for
each response shape used in tests; fixtures must match live backend shapes.

## 4. Technical Design

Production code: interface + provider in
`core-network/src/main/kotlin/com/testlogon/android/core/network/messaging/`;
DTOs in `core-model/src/main/kotlin/com/testlogon/android/core/model/messaging/`.

### 4.1 The `MessagingApi` interface

```kotlin
package com.testlogon.android.core.network.messaging

import com.testlogon.android.core.model.auth.OkResp
import com.testlogon.android.core.model.messaging.ConversationDto
import com.testlogon.android.core.model.messaging.ConversationPageDto
import com.testlogon.android.core.model.messaging.MessageDto
import com.testlogon.android.core.model.messaging.MessagePageDto
import com.testlogon.android.core.model.messaging.MessagingConfigDto
import com.testlogon.android.core.model.messaging.SendMessageReq
import com.testlogon.android.core.model.messaging.MarkReadReq
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

interface MessagingApi {

    /** Messaging feature config (limits, flags). Idempotent GET. */
    @GET("messaging/config")
    suspend fun config(): MessagingConfigDto

    /** Cursor-paged conversation list, most-recent first. Idempotent GET. */
    @GET("messaging/conversations")
    suspend fun listConversations(
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
    ): ConversationPageDto

    /** Single conversation by id. Idempotent GET. */
    @GET("messaging/conversations/{id}")
    suspend fun getConversation(@Path("id") id: String): ConversationDto

    /** Cursor-paged messages in a conversation (reverse history via cursor). */
    @GET("messaging/conversations/{id}/messages")
    suspend fun listMessages(
        @Path("id") id: String,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
    ): MessagePageDto

    /** Send a text message; returns the persisted message (echoes client_id). */
    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/{id}/messages")
    suspend fun sendMessage(
        @Path("id") id: String,
        @Body body: SendMessageReq,
    ): MessageDto

    /** Mark a conversation read up to a message/timestamp. */
    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/{id}/read")
    suspend fun markRead(
        @Path("id") id: String,
        @Body body: MarkReadReq,
    ): OkResp
}
```

Path prefix note: the interface above assumes a `messaging/` prefix on the
conversation routes. If `/openapi.json` shows the conversation routes are mounted
at the root (`conversations/...`) with only `config` under `messaging/`, the
annotations are adjusted to match (Q-1). The method names/signatures do not
change.

### 4.2 DTOs (`core-model`, package `...core.model.messaging`)

```kotlin
@JsonClass(generateAdapter = true)
data class MessagingConfigDto(
    @Json(name = "max_message_length") val maxMessageLength: Int,
    @Json(name = "attachments_enabled") val attachmentsEnabled: Boolean = false,
    @Json(name = "page_size") val pageSize: Int = 30,
)

@JsonClass(generateAdapter = true)
data class ConversationPageDto(
    @Json(name = "items") val items: List<ConversationDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class ConversationDto(
    @Json(name = "id") val id: String,
    @Json(name = "title") val title: String? = null,
    @Json(name = "participants") val participants: List<ParticipantDto> = emptyList(),
    @Json(name = "last_message") val lastMessage: MessageDto? = null,
    @Json(name = "unread_count") val unreadCount: Int = 0,
    @Json(name = "updated_at") val updatedAt: String, // ISO-8601 UTC
)

@JsonClass(generateAdapter = true)
data class ParticipantDto(
    @Json(name = "user_id") val userId: String,
    @Json(name = "username") val username: String,
    @Json(name = "avatar_url") val avatarUrl: String? = null,
)

@JsonClass(generateAdapter = true)
data class MessagePageDto(
    @Json(name = "items") val items: List<MessageDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class MessageDto(
    @Json(name = "id") val id: String,
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "sender_id") val senderId: String,
    @Json(name = "body") val body: String,
    @Json(name = "created_at") val createdAt: String,   // ISO-8601 UTC
    @Json(name = "client_id") val clientId: String? = null,
    @Json(name = "read") val read: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class SendMessageReq(
    @Json(name = "body") val body: String,
    @Json(name = "client_id") val clientId: String,
)

@JsonClass(generateAdapter = true)
data class MarkReadReq(
    @Json(name = "up_to_message_id") val upToMessageId: String? = null,
)
```

Timestamps stay as ISO-8601 `String` in the DTO; conversion to a domain time
type (Instant) is a `core-data` mapping concern, not a transport one (keeps the
DTO a faithful wire mirror). `OkResp` is reused from AND-026 Appendix A. No custom
Moshi adapter is required beyond codegen unless a polymorphic message type appears
(Q-2) — in that case a single sealed `@JsonClass(generator = "sealed:type")`
adapter is added here.

### 4.3 Hilt provider

```kotlin
package com.testlogon.android.core.network.messaging.di

import com.testlogon.android.core.network.messaging.MessagingApi
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object MessagingApiModule {

    @Provides
    @Singleton
    fun provideMessagingApi(retrofit: Retrofit): MessagingApi =
        retrofit.create(MessagingApi::class.java)
}
```

### 4.4 Conventions

- Relative paths, no leading slash; resolve against base
  `http://18.222.237.167:8000/`.
- Mutating verbs (`sendMessage`, `markRead`) are POST → CSRF header attached by
  AND-012.
- Idempotent GETs (`config`, `listConversations`, `getConversation`,
  `listMessages`) → eligible for AND-016 bounded backoff.

### 4.5 Gradle wiring

No new dependencies. `core-network` already has Retrofit/Moshi/Hilt and (test)
MockWebServer from AND-010; `core-model` already has Moshi + KSP. This ticket adds
source files and test fixtures only. `core-network` already declares
`:core-model` as `implementation`.

## 5. API Contract

Base path (`dev`): `http://18.222.237.167:8000/`. All bodies JSON. Paths below use
the assumed `messaging/` prefix (confirm per Q-1).

### GET `messaging/config`
Response `200`:
```json
{ "max_message_length": 4000, "attachments_enabled": false, "page_size": 30 }
```

### GET `messaging/conversations?cursor=&limit=30`
Response `200`:
```json
{
  "items": [
    {
      "id": "conv_01HZ...",
      "title": null,
      "participants": [
        { "user_id": "usr_1", "username": "alice", "avatar_url": null },
        { "user_id": "usr_2", "username": "bob", "avatar_url": "https://.../b.png" }
      ],
      "last_message": {
        "id": "msg_99", "conversation_id": "conv_01HZ...", "sender_id": "usr_2",
        "body": "see you then", "created_at": "2026-06-05T12:30:00Z",
        "client_id": null, "read": false
      },
      "unread_count": 2,
      "updated_at": "2026-06-05T12:30:00Z"
    }
  ],
  "next_cursor": "eyJvIjoyMH0="
}
```
`next_cursor` is `null` on the last page.

### GET `messaging/conversations/{id}`
`messaging/conversations/conv_01HZ...` → `200` returns a single `ConversationDto`
(same object shape as a list item).

### GET `messaging/conversations/{id}/messages?cursor=&limit=30`
Response `200`:
```json
{
  "items": [
    {
      "id": "msg_98", "conversation_id": "conv_01HZ...", "sender_id": "usr_1",
      "body": "lunch?", "created_at": "2026-06-05T12:00:00Z",
      "client_id": "cli_abc", "read": true
    }
  ],
  "next_cursor": "eyJvIjozMH0="
}
```
Reverse-history pagination semantics (whether `cursor` walks older or newer) per
Q-3; AND-123 drives reverse paging from this envelope.

### POST `messaging/conversations/{id}/messages`
Request:
```json
{ "body": "on my way", "client_id": "cli_7f3a" }
```
Response `201` (or `200`):
```json
{
  "id": "msg_100", "conversation_id": "conv_01HZ...", "sender_id": "usr_1",
  "body": "on my way", "created_at": "2026-06-05T12:31:00Z",
  "client_id": "cli_7f3a", "read": false
}
```
The echoed `client_id` lets AND-124 reconcile the optimistic placeholder.

### POST `messaging/conversations/{id}/read`
Request (optional cursor to a message; empty body marks all read):
```json
{ "up_to_message_id": "msg_100" }
```
Response `200`: `{ "ok": true }`.

**Error envelope (all endpoints):** FastAPI `detail` union
(`string | [{msg,type,loc}] | {code,...}`). Mapping to a typed `ApiError` is owned
by **AND-015**; this ticket lets non-2xx surface as `HttpException`. A `401` is
handled by AND-013 (refresh-then-retry once).

## 6. Data & State Management

`MessagingApi` is **stateless** — a singleton interface proxy with no fields.

- **No Room / DataStore here.** Caching conversations/messages (SWR) is AND-116 /
  `core-data`. This ticket only returns wire DTOs.
- **No `StateFlow`/`UiState`.** ViewModels (AND-122/AND-123) expose UI state by
  consuming repositories that wrap these calls in `ApiResult<T>` (AND-018). This
  interface returns plain DTOs on success and throws on failure.
- **Cursor paging contract:** the `{ items, next_cursor }` envelope is the unit of
  paging. AND-122/AND-123 implement `PagingSource` over `listConversations` /
  `listMessages`, using `next_cursor` as `LoadResult.nextKey` (or `prevKey` for
  reverse history). This ticket guarantees only the envelope shape and that
  `next_cursor == null` denotes end-of-list.
- **Session state** lives in cookies (AND-011); CSRF in the `ui_csrf` cookie →
  `X-CSRF-Token` (AND-012). `MessagingApi` is unaware of both.
- **Serialization:** Moshi codegen adapters via the shared converter; unknown keys
  ignored, absent optional fields fall back to Kotlin defaults (lenient).
- **Threading:** suspend methods are invoked from an IO-dispatcher coroutine at the
  repository layer; this ticket imposes no dispatcher.

## 7. Error Handling & Resilience

Responsibilities are narrow: declare endpoints/DTOs so failures propagate cleanly.

- **Non-2xx** surfaces as `retrofit2.HttpException` carrying the raw error body for
  AND-015 to decode the FastAPI `detail`. `401` on any call is intercepted by the
  AND-013 `Authenticator` (refresh once, retry; second 401 is terminal → route to
  login, AND-025). `403` (CSRF/permission) and `404` (unknown conversation)
  propagate as `HttpException`.
- **Transport failures** (`SocketTimeoutException`, `UnknownHostException`,
  `IOException`) propagate unchanged; ~20s timeouts + bounded backoff for the
  idempotent GETs (`config`, `listConversations`, `getConversation`,
  `listMessages`) are owned by AND-009/AND-016. **`sendMessage`/`markRead` are
  POSTs and are NOT auto-retried** (non-idempotent without `client_id` dedupe) —
  AND-124 owns send-retry using the `client_id` for server-side idempotency.
- **Deserialization failures** surface as `JsonDataException`; lenient parsing
  (nullable optionals, defaults, ignored unknown keys) minimizes these against the
  evolving dev backend.
- **Empty-body decoding:** if `markRead` returns a bare `200` with no body,
  declaring `OkResp` throws Moshi `EOFException`; resolve the return type
  (`OkResp` vs `Unit`) against `/openapi.json` (Q-4), guarded by a test.
- This ticket maps **no** errors itself — AND-015 (`ApiError`) and AND-018
  (`ApiResult`) own that.

## 8. Security & Privacy

- **Authenticated surface:** every messaging call requires an active session
  (cookies). The cookie-scoped identity is server-enforced; clients cannot read or
  send to conversations they are not a participant of (server returns 403/404).
- **Cleartext on dev:** message bodies (which may contain personal content) ride
  plaintext HTTP on the `dev` host — a known dev-only risk permitted by the scoped
  cleartext config (AND-006); `staging`/`prod` are HTTPS-only.
- **No body logging of message content:** AND-009's logging interceptor (debug
  only) must not log `sendMessage` request bodies or message-bearing responses in
  a way that leaks content to logcat; treat message `body` as sensitive. This
  ticket adds no logging. A code-review check confirms message content never
  reaches logcat in release builds.
- **CSRF/cookies** delegated to AND-011/AND-012; no manual `Cookie`/`Authorization`
  headers in the interface.
- **`client_id`** is a client-generated opaque dedupe token (e.g. UUID); it carries
  no PII and is safe to echo.

## 9. Accessibility & i18n

Not applicable — this is a headless transport interface + DTO layer with no UI and
no user-facing strings. Accessibility for the conversation/thread screens is owned
by `core-ui` and AND-121/AND-123. Localization of error text derived from these
endpoints is owned by AND-015 and the consuming features. Message timestamps are
transported as ISO-8601 UTC strings; locale-aware formatting is a UI concern
(AND-121/AND-123).

## 10. Telemetry & Logging

- **HTTP logging** inherited from AND-009's redacting interceptor (debug only);
  message bodies treated as sensitive (Section 8). No new logging here.
- **No analytics events** from this layer. Message-sent / conversation-opened /
  read events are emitted by the messaging ViewModels (AND-122/AND-123/AND-124/
  AND-125) from `ApiResult` outcomes, not from `MessagingApi`.
- **Build-time signal:** KSP must generate Moshi adapters for every messaging DTO;
  a missing adapter fails the build (no reflection fallback, AND-010 policy).

## 11. Testing Strategy

JVM unit tests in `core-network/src/test/...` and `core-model/src/test/...` using
`MockWebServer` and the production Moshi/Retrofit config, plus captured JSON
fixtures from the AND-046 `core-testing` harness
(`core-testing/src/main/resources/fixtures/messaging/*.json`). Tests assert
**verb, resolved path, query params, request body, and decoded response vs
fixture** — directly satisfying the acceptance criterion (payloads map vs
fixtures).

Test harness (mirrors `provideMoshi()` / `provideRetrofit()`):
```kotlin
private fun api(server: MockWebServer): MessagingApi {
    val moshi = Moshi.Builder().build() // codegen adapters
    val retrofit = Retrofit.Builder()
        .baseUrl(server.url("/"))
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()
    return retrofit.create(MessagingApi::class.java)
}
```

**T-1 — `config`.** `GET messaging/config`; decode `MessagingConfigDto`
(`max_message_length`, `page_size`) from `config.json` fixture.

**T-2 — `listConversations` contract + decode.**
```kotlin
@Test fun listConversations_getsPagedEnvelope() = runTest {
    val server = MockWebServer().apply {
        enqueue(MockResponse().setBody(fixture("messaging/conversations_page.json")))
        start()
    }
    val page = api(server).listConversations(cursor = null, limit = 30)

    val req = server.takeRequest()
    assertEquals("GET", req.method)
    assertEquals("/messaging/conversations?limit=30", req.path)
    assertEquals(1, page.items.size)
    assertEquals("conv_01HZ...", page.items[0].id)
    assertEquals(2, page.items[0].unreadCount)
    assertEquals("usr_2", page.items[0].lastMessage?.senderId)
    assertEquals("eyJvIjoyMH0=", page.nextCursor)
    server.shutdown()
}
```
Also assert a `cursor` value is appended when non-null, and `next_cursor: null`
decodes to a Kotlin `null` (end-of-list).

**T-3 — `getConversation`.** `GET messaging/conversations/conv_1` (path param
interpolated); decode `ConversationDto` including `participants[].avatar_url`
nullability.

**T-4 — `listMessages`.** `GET messaging/conversations/conv_1/messages?limit=30`;
decode `MessagePageDto`; assert `items[].created_at`, `client_id` nullability, and
`next_cursor`.

**T-5 — `sendMessage`.** `POST messaging/conversations/conv_1/messages` with body
`{"body":"on my way","client_id":"cli_7f3a"}`; assert verb/path, that the request
body serializes exactly, and that the response `MessageDto` echoes
`client_id == "cli_7f3a"` and carries a server `id`/`created_at`.

**T-6 — `markRead`.** `POST messaging/conversations/conv_1/read` with
`{"up_to_message_id":"msg_100"}`; decode `OkResp` (or tolerate empty body per Q-4).

**T-7 — DTO round-trip (`core-model`).** For `MessageDto`/`ConversationDto`,
deserialize the fixture then re-serialize and assert no required field is dropped
and snake_case names are preserved (mirrors AND-026's captured-sample tests).

**T-8 — lenient decoding.** A fixture with an extra unknown key and a missing
optional (`title` absent, `avatar_url` absent) decodes without error to defaults.

**T-9 — error propagation.** `404` from `getConversation` throws
`retrofit2.HttpException` with `code() == 404` (non-2xx not swallowed; room for
AND-015).

**T-10 — Hilt provider.** Minimal `core-testing`/`@HiltAndroidTest` injects
`MessagingApi` and asserts a non-null singleton on the shared Retrofit (same
instance on repeated injection).

Coverage target: ≥90% on the new surface (interface binding, DTOs, provider).
Every endpoint has at least one path/verb assertion; every DTO has at least one
decode-vs-fixture assertion.

## 12. Dependencies & Sequencing

**Hard upstream (must merge first):**
- **AND-027** (backlog-named dependency) — establishes the `*Api` transport
  pattern, the shared Retrofit/provider conventions, and `OkResp` usage that this
  ticket follows.
- **AND-026** — supplies the reused `OkResp` DTO + the DTO/adapter conventions.
- **AND-010** — shared Retrofit + Moshi (KSP) the provider/converter rely on.

**Transitive upstream (already required by the above):** AND-009 (shared
`OkHttpClient`), AND-006 (`BuildConfig.API_BASE_URL`), AND-003/AND-004 (module
structure, Hilt baseline), AND-046 (MockWebServer harness + fixture loader used by
the tests).

**Downstream (this ticket blocks):**
- AND-121 (conversation list screen) and AND-122 (list ViewModel + Paging 3) —
  consume `listConversations` + the page envelope.
- AND-123 (thread screen) — consumes `listMessages` reverse paging.
- AND-124 (send text) — consumes `sendMessage` + `client_id` reconciliation.
- AND-125 (read/unread) — consumes `markRead` + `unread_count`.

**Sequencing within the ticket:** (1) confirm prefix/shapes/cursor semantics
against `/openapi.json` + web reference and capture fixtures (AND-046); (2) declare
the `core-model` DTOs; (3) declare `MessagingApi`; (4) add `MessagingApiModule`;
(5) write MockWebServer + round-trip tests T-1..T-10.

## 13. Risks & Open Questions

- **R-1 Route prefix drift.** The backlog lists mixed paths
  (`/messaging/conversations` vs bare `/conversations/{id}`). If the real mount
  points differ from the assumed `messaging/` prefix the interface paths are wrong.
  Mitigation: reconcile against `/openapi.json` + web reference before coding
  (Q-1); fixtures + path assertions catch mismatches.
- **R-2 Paging envelope shape.** The list endpoints may return a bare array, a
  `{items,next_cursor}` envelope, or offset/limit pagination instead of cursor.
  Mitigation: inspect the web reference; pick the matching DTO; guarded by T-2/T-4.
- **R-3 Polymorphic messages.** If messages carry a `type` discriminator
  (text/image/system), `MessageDto` needs a sealed hierarchy + custom adapter.
  Mitigation: confirm via OpenAPI (Q-2); spec assumes a single text shape with a
  `body`.
- **R-4 Send idempotency.** If the backend does not honor `client_id` for dedupe,
  AND-124's retry can create duplicates. Mitigation: this ticket transports
  `client_id`; the server-side dedupe contract is confirmed during grooming.
- **R-5 DTO drift on field names.** Snake_case names assumed here
  (`unread_count`, `last_message`, `next_cursor`) must match live JSON exactly.
  Mitigation: fixtures captured from the real backend; round-trip tests (T-7).
- **Q-1** Is the conversation route prefix `messaging/` or root `conversations/`,
  and is `config` at `messaging/config` or `config`? *Proposed:* match
  `/openapi.json`; spec assumes `messaging/` throughout.
- **Q-2** Are messages polymorphic (a `type` field)? *Proposed:* default to single
  text shape; add a sealed adapter only if OpenAPI shows a discriminator.
- **Q-3** Does `listMessages` cursor page older or newer messages (reverse history
  direction)? *Proposed:* confirm with web reference; expose the cursor verbatim so
  AND-123 chooses prev/next key.
- **Q-4** Does `markRead` return `{"ok":true}` or an empty body? *Proposed:* verify
  via `/openapi.json`; default `OkResp`, fall back to `Unit`.

## 14. Acceptance Criteria

- **AC-1 (backlog).** `MessagingApi` declares operations for
  `/messaging/conversations`, `/conversations/{id}`, `/conversations/{id}/messages`,
  and `/config` (`config`, `listConversations`, `getConversation`, `listMessages`,
  `sendMessage`, `markRead`); both modules compile.
- **AC-2 (backlog).** Conversation + message payloads map — every documented
  response decodes into its DTO and every request DTO serializes exactly, asserted
  **vs captured fixtures** with MockWebServer (T-1..T-8).
- **AC-3.** Each endpoint's verb + resolved path (+ query params for paged GETs +
  request body for POSTs) match Section 5 (path/verb assertions in T-1..T-6).
- **AC-4.** Paged endpoints decode the `{items,next_cursor}` envelope, with
  `next_cursor: null` → Kotlin `null` (T-2/T-4).
- **AC-5.** `sendMessage` serializes `{body,client_id}` and decodes a `MessageDto`
  that echoes `client_id` (T-5).
- **AC-6.** Snake_case fields (`unread_count`, `last_message`, `created_at`,
  `next_cursor`) decode via codegen adapters; unknown keys ignored; absent
  optionals default (T-7/T-8).
- **AC-7.** Non-2xx (e.g. `404` from `getConversation`) surfaces as `HttpException`
  and is not swallowed (T-9).
- **AC-8.** `MessagingApi` is Hilt-provided as a `@Singleton` on the shared
  Retrofit; repeated injection yields the same instance (T-10).
- **AC-9.** No new `OkHttpClient`/`Retrofit` constructed; no per-method CSRF/cookie
  headers declared.
- **AC-10.** Module builds clean under AGP 8.7.3 / Gradle 8.9 / JDK 17 with
  KSP-generated adapters present; all tests pass in CI; no detekt/lint regressions
  (AND-005).

## 15. Definition of Done

- DTOs (`com.testlogon.android.core.model.messaging`) and `MessagingApi` +
  `MessagingApiModule` (`com.testlogon.android.core.network.messaging[.di]`) are
  implemented, reusing `OkResp` (AND-026) and the shared Retrofit (AND-010); no
  DTOs redefined.
- Open questions Q-1..Q-4 resolved against `/openapi.json` and the web reference;
  the interface paths, cursor semantics, message shape, and `markRead` return type
  reflect the confirmed contract.
- JSON fixtures captured (via AND-046) for config / conversations page /
  conversation / messages page / sent message, matching live backend shapes.
- MockWebServer + round-trip tests T-1 through T-10 implemented and green in CI;
  ≥90% line coverage on the new surface; every endpoint has a path/verb assertion
  and every DTO a decode-vs-fixture assertion.
- No second `OkHttpClient`/`Retrofit`; no manual cookie/CSRF/auth headers; message
  bodies treated as sensitive and never logged in release (verified in review).
- `./gradlew :core-model:testDebugUnitTest :core-network:assemble
  :core-network:testDebugUnitTest` passes locally and in CI with no new
  lint/detekt violations (AND-005 config).
- Code reviewed and merged to `android-port`; AND-121/AND-122/AND-123/AND-124/
  AND-125 are unblocked (the conversation/message/config seams are in place).
- A one-line note in the `core-network` README (AND-007) records the
  `MessagingApi` path/verb map and the delegation of cookie/CSRF/refresh to
  AND-011/AND-012/AND-013.
