---
id: AND-120
title: Messaging API + DTOs
milestone: M3
epic: E18
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
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

FR-3. All methods are `suspend` and return the typed DTO body. **[CORRECTED — see
§16]** `markRead` returns **`Unit`**: OpenAPI declares its `200` response with an
empty/unspecified schema (`{}`), **not** `{"ok": true}`, so `OkResp` would throw on
decode (Q-4 resolved → `Unit`, Retrofit handles the empty body).

FR-4. Idempotent GETs (`config`, `listConversations`, `getConversation`,
`listMessages`) accept paging/filter inputs via `@Query`; mutating POSTs
(`sendMessage`, `markRead`) use `@Body` request DTOs. No raw `Map`/`JsonObject`
bodies.

FR-5. **[CORRECTED — see §16]** The list endpoints are **NOT** an `{items,
next_cursor}` envelope and `listConversations` is **not paged at all**. Verified
against OpenAPI:
- `GET messaging/conversations` returns a **bare JSON array** of `ConversationOut`
  with **no** `cursor`/`limit`/`before` query params (the only declared params are
  auth headers). `listConversations()` therefore takes no paging args and returns
  `List<ConversationDto>`.
- `GET messaging/conversations/{id}/messages` returns a **bare JSON array** of
  `MessageOut`, paginated by `limit: Int?` (default 50, max 200, min 1) and
  `before: String?` (reverse-history key) query params — **not** `cursor`, **not** a
  `next_cursor` envelope. `listMessages()` returns `List<MessageDto>`. AND-123
  drives reverse history by passing the oldest loaded `message_id`/timestamp as
  `before`; end-of-history is signalled by a short/empty array, not a null cursor.
  (Q-3 resolved: reverse-only via `before`.)

FR-6. **[CORRECTED — see §16]** `sendMessage` posts a `SendTextMessageIn` whose
text field is **`text`** (1–4000 chars), **not** `body`, and the wire contract has
**no `client_id`** field anywhere (request or response). The endpoint returns the
persisted `MessageDto` (server-assigned `message_id`, `created_at`). AND-124's
optimistic-send reconciliation cannot rely on an echoed `client_id` (it must
reconcile on `message_id`/`text`+`created_at` or a future server field); this is
flagged as an open assumption in §16. Response status is **`200`** (`MessageOut`),
not `201`.

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

import com.testlogon.android.core.model.messaging.ConversationDto
import com.testlogon.android.core.model.messaging.MessageDto
import com.testlogon.android.core.model.messaging.MessagingConfigDto
import com.testlogon.android.core.model.messaging.SendMessageReq
import com.testlogon.android.core.model.messaging.MarkReadReq
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

// [CORRECTED vs original draft — verified against OpenAPI (see §16)]:
//  - listConversations returns a BARE ARRAY, no query params.
//  - listMessages returns a BARE ARRAY, paged via limit + before (NOT cursor).
//  - sendMessage body is SendTextMessageIn { text } (NOT { body, client_id });
//    response 200 MessageOut.
//  - markRead returns Unit (empty 200 body), body field last_read_message_id.
//  - No OkResp / ConversationPageDto / MessagePageDto exist on this surface.
interface MessagingApi {

    /** Messaging feature config (boolean feature flags). Idempotent GET. */
    @GET("messaging/config")
    suspend fun config(): MessagingConfigDto

    /** Full conversation list (bare array, NOT paged). Idempotent GET. */
    @GET("messaging/conversations")
    suspend fun listConversations(): List<ConversationDto>

    /** Single conversation by id. Idempotent GET. */
    @GET("messaging/conversations/{id}")
    suspend fun getConversation(@Path("id") id: String): ConversationDto

    /** Messages in a conversation (bare array); reverse history via `before`. */
    @GET("messaging/conversations/{id}/messages")
    suspend fun listMessages(
        @Path("id") id: String,
        @Query("limit") limit: Int? = null,   // default 50, max 200 server-side
        @Query("before") before: String? = null,
    ): List<MessageDto>

    /** Send a text message; returns the persisted MessageOut (HTTP 200). */
    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/{id}/messages")
    suspend fun sendMessage(
        @Path("id") id: String,
        @Body body: SendMessageReq,
    ): MessageDto

    /** Mark a conversation read up to a message id / timestamp. Empty 200 body. */
    @Headers("Content-Type: application/json")
    @POST("messaging/conversations/{id}/read")
    suspend fun markRead(
        @Path("id") id: String,
        @Body body: MarkReadReq,
    )
}
```

Path prefix note: **[VERIFIED — see §16]** Q-1 is resolved. All routes are mounted
under a single `messaging/` prefix: `messaging/config`, `messaging/conversations`,
`messaging/conversations/{conversation_id}`,
`messaging/conversations/{conversation_id}/messages`, and
`messaging/conversations/{conversation_id}/read`. The backlog's bare
`/conversations/{id}` was shorthand; there is no root-level mount. (Path param is
named `conversation_id` on the backend; the Retrofit `@Path("id")` name is local
and only needs to match the `{id}` placeholder used in the annotation.)

### 4.2 DTOs (`core-model`, package `...core.model.messaging`)

**[CORRECTED — every DTO below was reshaped to match the live OpenAPI schemas;
see §16 for the field-by-field audit.]** Key changes vs the original draft:
`MessagingConfigOut` is a set of feature-flag booleans (no length/page-size);
`ConversationOut`/`MessageOut` key the id as `conversation_id`/`message_id`;
timestamps are **epoch-second `Long` integers**, not ISO-8601 strings; the message
text field is `text` (nullable); messages carry a `kind` discriminator; there is no
`client_id`, no `read` boolean, and no page envelope DTOs.

```kotlin
// GET messaging/config -> MessagingConfigOut (feature flags only)
@JsonClass(generateAdapter = true)
data class MessagingConfigDto(
    @Json(name = "messaging_encrypted_messages_enabled") val encryptedMessagesEnabled: Boolean = false,
    @Json(name = "messaging_gallery_enabled") val galleryEnabled: Boolean = false,
    @Json(name = "messaging_dm_lottery_enabled") val dmLotteryEnabled: Boolean = false,
    @Json(name = "messaging_hide_controls_enabled") val hideControlsEnabled: Boolean = false,
    @Json(name = "messaging_pins_enabled") val pinsEnabled: Boolean = false,
    @Json(name = "messaging_reporting_enabled") val reportingEnabled: Boolean = false,
    @Json(name = "messaging_mass_send_enabled") val massSendEnabled: Boolean = false,
)

// ConversationOut (returned bare-array by list, and singly by get).
// Required by server: conversation_id, type, created_at, created_by,
// participant_count, status. Many optional helpdesk/pin fields omitted as
// unknown-key-tolerant; add only what consumers need.
@JsonClass(generateAdapter = true)
data class ConversationDto(
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "type") val type: String,                 // "dm" | "group"
    @Json(name = "title") val title: String? = null,
    @Json(name = "created_at") val createdAt: Long,        // epoch seconds
    @Json(name = "created_by") val createdBy: String,
    @Json(name = "participant_count") val participantCount: Int,
    @Json(name = "status") val status: String,
    @Json(name = "participants") val participants: List<ParticipantDto> = emptyList(),
    @Json(name = "last_message") val lastMessage: MessageDto? = null,
    @Json(name = "last_message_at") val lastMessageAt: Long? = null,
    @Json(name = "last_message_preview") val lastMessagePreview: String? = null,
    @Json(name = "unread_count") val unreadCount: Int = 0,
    @Json(name = "last_read_at") val lastReadAt: Long = 0,
)

// app__routers__messaging__ParticipantOut. Required: user_id, status, role.
@JsonClass(generateAdapter = true)
data class ParticipantDto(
    @Json(name = "user_id") val userId: String,
    @Json(name = "status") val status: String,
    @Json(name = "role") val role: String,                 // "admin" | "member"
    @Json(name = "display_name") val displayName: String? = null,
    @Json(name = "profile_photo_url") val profilePhotoUrl: String? = null,
    @Json(name = "last_read_at") val lastReadAt: Long = 0,
)

// MessageOut. Required: conversation_id, message_id, sender_id, created_at, kind.
// `kind` is the message-type discriminator (text/image/file/gif/sticker/...);
// `text` is null for non-text kinds. This ticket transports `kind` + `text`;
// richer per-kind payloads (image/voice/etc.) are out of scope here.
@JsonClass(generateAdapter = true)
data class MessageDto(
    @Json(name = "message_id") val messageId: String,
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "sender_id") val senderId: String,
    @Json(name = "created_at") val createdAt: Long,        // epoch seconds
    @Json(name = "kind") val kind: String,                 // discriminator
    @Json(name = "text") val text: String? = null,
    @Json(name = "edited_at") val editedAt: Long? = null,
    @Json(name = "read_by_count") val readByCount: Int? = null,
)

// POST messages body = SendTextMessageIn. Field is `text` (1..4000), NOT `body`.
// No client_id on the wire. All fields optional server-side; `text` carried here.
@JsonClass(generateAdapter = true)
data class SendMessageReq(
    @Json(name = "text") val text: String,
)

// POST read body = app__routers__messaging__MarkReadIn.
@JsonClass(generateAdapter = true)
data class MarkReadReq(
    @Json(name = "last_read_message_id") val lastReadMessageId: String? = null,
    @Json(name = "last_read_at") val lastReadAt: Long? = null,
)
```

Timestamps are transported as **epoch-second `Long`** (matching the integer wire
type and the web `adaptMessage`/`adaptConversation` `toNum(...)` coercion);
conversion to a domain `Instant` is a `core-data` mapping concern. **[CORRECTED]**
`markRead` returns `Unit` (empty body) — `OkResp` is **not** used on this surface.
**[Q-2 resolved]** Messages **are** polymorphic via the required `kind`
discriminator; this transport ticket keeps a single flat `MessageDto` carrying
`kind` + nullable `text` (and tolerates the many per-kind optional keys via lenient
parsing). A sealed hierarchy is deferred to the consuming features if/when richer
per-kind rendering is needed; it is **not** required to satisfy this ticket's
"payloads map vs fixtures" AC.

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

Base path (`dev`): `http://18.222.237.167:8000/`. All bodies JSON. Prefix
`messaging/` is **verified** (Q-1). **All examples below were corrected against the
live OpenAPI shapes** (see §16); timestamps are epoch-second integers.

### GET `messaging/config` → `MessagingConfigOut`
Response `200` (feature flags only — **no** `max_message_length`/`page_size`):
```json
{
  "messaging_encrypted_messages_enabled": false,
  "messaging_gallery_enabled": true,
  "messaging_dm_lottery_enabled": false,
  "messaging_hide_controls_enabled": false,
  "messaging_pins_enabled": true,
  "messaging_reporting_enabled": true,
  "messaging_mass_send_enabled": false
}
```

### GET `messaging/conversations` → **bare array** of `ConversationOut`
**No query params.** Response `200` is a JSON array (not an envelope):
```json
[
  {
    "conversation_id": "conv_01HZ...",
    "type": "dm",
    "title": null,
    "created_at": 1749126600,
    "created_by": "usr_1",
    "participant_count": 2,
    "status": "active",
    "participants": [
      { "user_id": "usr_1", "status": "active", "role": "member", "display_name": "alice", "profile_photo_url": null },
      { "user_id": "usr_2", "status": "active", "role": "member", "display_name": "bob", "profile_photo_url": "https://.../b.png" }
    ],
    "last_message": {
      "message_id": "msg_99", "conversation_id": "conv_01HZ...", "sender_id": "usr_2",
      "created_at": 1749126600, "kind": "text", "text": "see you then"
    },
    "last_message_at": 1749126600,
    "unread_count": 2,
    "last_read_at": 1749120000
  }
]
```

### GET `messaging/conversations/{conversation_id}` → `ConversationOut`
`messaging/conversations/conv_01HZ...` → `200` returns a single `ConversationOut`
(same object shape as a list element).

### GET `messaging/conversations/{conversation_id}/messages?limit=50&before=<id|ts>`
Query params: `limit` (int, default **50**, max 200, min 1) and `before`
(string, reverse-history key). Response `200` is a **bare array** of `MessageOut`:
```json
[
  {
    "message_id": "msg_98", "conversation_id": "conv_01HZ...", "sender_id": "usr_1",
    "created_at": 1749124800, "kind": "text", "text": "lunch?", "read_by_count": 2
  }
]
```
Reverse history: pass the oldest loaded message's id/timestamp as `before`;
end-of-history = a short/empty array (there is no `next_cursor`). AND-123 drives
reverse paging from this.

### POST `messaging/conversations/{conversation_id}/messages` → `MessageOut`
Request body = `SendTextMessageIn` (text field is **`text`**, 1–4000 chars; **no**
`client_id`):
```json
{ "text": "on my way" }
```
Response **`200`** (`MessageOut`):
```json
{
  "message_id": "msg_100", "conversation_id": "conv_01HZ...", "sender_id": "usr_1",
  "created_at": 1749126660, "kind": "text", "text": "on my way"
}
```
There is **no echoed `client_id`**; AND-124 must reconcile its optimistic
placeholder on `message_id`/content rather than a client token (see §16 open
assumption).

### POST `messaging/conversations/{conversation_id}/read`
Request body = `MarkReadIn` (required body; both fields optional):
```json
{ "last_read_message_id": "msg_100" }
```
Response **`200` with an empty/unspecified body** (`{}` schema) — **not**
`{"ok": true}`. Decode as `Unit`.

**Error envelope (all endpoints):** non-2xx bodies are FastAPI `detail`, but the
messaging routes return a **structured detail object** `{"detail": {"code": "...",
"reason": "...", ...}}` (verified examples include `api_key_invalid`,
`api_entitlement_denied`, `api_key_scope_denied`, `api_key_dual_credential_conflict`)
on `400/401/403/429`, and the standard validation list `{"detail":
[{"loc","msg","type"}]}` on `422`. Mapping to a typed `ApiError` is owned by
**AND-015**; this ticket lets non-2xx surface as `HttpException`. A `401` is handled
by AND-013 (refresh-then-retry once).

## 6. Data & State Management

`MessagingApi` is **stateless** — a singleton interface proxy with no fields.

- **No Room / DataStore here.** Caching conversations/messages (SWR) is AND-116 /
  `core-data`. This ticket only returns wire DTOs.
- **No `StateFlow`/`UiState`.** ViewModels (AND-122/AND-123) expose UI state by
  consuming repositories that wrap these calls in `ApiResult<T>` (AND-018). This
  interface returns plain DTOs on success and throws on failure.
- **Paging contract [CORRECTED — see §16]:** there is **no `{items,next_cursor}`
  envelope**. `listConversations` returns the **full conversation list** as a bare
  array (no paging) — AND-122 paginates client-side or treats it as a single page.
  `listMessages` returns a bare array paged by `limit` + `before`: AND-123's
  `PagingSource` uses the oldest loaded message id/timestamp as the next `before`
  key, and treats a returned page shorter than `limit` (or empty) as end-of-history.
  This ticket guarantees the array element shapes only.
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
- **Empty-body decoding [RESOLVED — see §16]:** `markRead`'s `200` response has an
  empty/unspecified body, so its method returns **`Unit`** (Retrofit consumes the
  empty body without invoking Moshi). Declaring `OkResp` here would throw
  `EOFException`/`JsonDataException`; a test guards the `Unit` decode.
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

**T-1 — `config`.** `GET messaging/config`; decode `MessagingConfigDto` (the
boolean flags `messaging_gallery_enabled`, `messaging_pins_enabled`, etc.) from
`config.json` fixture. **[CORRECTED: flags, not `max_message_length`/`page_size`.]**

**T-2 — `listConversations` contract + decode (bare array).**
```kotlin
@Test fun listConversations_getsBareArray() = runTest {
    val server = MockWebServer().apply {
        enqueue(MockResponse().setBody(fixture("messaging/conversations.json")))
        start()
    }
    val list = api(server).listConversations()

    val req = server.takeRequest()
    assertEquals("GET", req.method)
    assertEquals("/messaging/conversations", req.path)   // no query params
    assertEquals(1, list.size)
    assertEquals("conv_01HZ...", list[0].conversationId)
    assertEquals(2, list[0].unreadCount)
    assertEquals("usr_2", list[0].lastMessage?.senderId)
    assertEquals(1749126600L, list[0].createdAt)
    server.shutdown()
}
```
**[CORRECTED: bare `List<ConversationDto>`, no envelope/cursor, no query params.]**

**T-3 — `getConversation`.** `GET messaging/conversations/conv_1` (path param
interpolated); decode `ConversationDto` including `participants[].profile_photo_url`
and `title` nullability. **[CORRECTED field names.]**

**T-4 — `listMessages` (bare array + `before`/`limit`).** `GET
messaging/conversations/conv_1/messages?limit=50&before=msg_98`; decode
`List<MessageDto>`; assert the resolved query carries `limit` and `before` (not
`cursor`), and assert `items[].createdAt` (Long), `kind`, and `text` nullability.
**[CORRECTED: bare array, `before` not `cursor`, no `next_cursor`.]**

**T-5 — `sendMessage`.** `POST messaging/conversations/conv_1/messages` with body
`{"text":"on my way"}`; assert verb/path, that the request body serializes exactly
(field `text`, no `client_id`), and that the response `MessageDto` carries a server
`message_id`, `kind`, and `created_at` (Long). **[CORRECTED: `text` body, 200
response, no `client_id`.]**

**T-6 — `markRead`.** `POST messaging/conversations/conv_1/read` with
`{"last_read_message_id":"msg_100"}`; method returns `Unit`; assert the call
completes against an empty `200` body (and does NOT throw a decode error).
**[CORRECTED: `Unit` + empty body, `last_read_message_id`.]**

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
- **Q-1 [RESOLVED].** Everything is under `messaging/` (`messaging/config`,
  `messaging/conversations`, ...). No root mount. Source: OpenAPI paths.
- **Q-2 [RESOLVED].** Messages **are** polymorphic via a required `kind`
  discriminator (`text`, `image`, `file`, `gif`, `sticker`, calendar/poll/voice/...).
  This ticket keeps a flat `MessageDto` with `kind` + nullable `text`; a sealed
  hierarchy is deferred to consumers. Source: `MessageOut.required` includes `kind`;
  `kind`-specific POST routes in the index.
- **Q-3 [RESOLVED].** `listMessages` paginates **older** messages via a `before`
  query param (string), not a cursor; it returns a bare array. AND-123 walks
  backwards by passing the oldest loaded id/timestamp. Source: OpenAPI
  `GET .../messages` params `limit,before`; frontend `getMessages` maps `cursor`→
  `before`.
- **Q-4 [RESOLVED].** `markRead` returns an **empty `200` body** (schema `{}`), not
  `{"ok":true}`; return type is `Unit`. Source: OpenAPI `POST .../read` 200 content.

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
- **AC-4 [CORRECTED].** List endpoints decode **bare JSON arrays**:
  `listConversations` → `List<ConversationDto>` (no query params); `listMessages` →
  `List<MessageDto>` with `limit`+`before` query params resolved correctly (no
  `cursor`/`next_cursor`) (T-2/T-4).
- **AC-5 [CORRECTED].** `sendMessage` serializes `{"text": "..."}` (no `client_id`)
  and decodes a `MessageDto` carrying `message_id`, `kind`, and `created_at` from a
  `200` response (T-5).
- **AC-6 [CORRECTED].** Snake_case fields (`conversation_id`, `message_id`,
  `unread_count`, `last_message`, `created_at`, `last_message_at`) decode via codegen
  adapters; epoch-second `created_at` decodes to `Long`; unknown keys ignored; absent
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
  implemented on the shared Retrofit (AND-010); no DTOs redefined. **[CORRECTED:
  `OkResp` is NOT used — `markRead` returns `Unit`.]**
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

## 16. Citations & Assumption Audit

Each claim below is the spec's assertion, a VERDICT, and an exact source pointer.
OpenAPI paths cite `reference/openapi.index.txt` / `reference/openapi.pretty.json`
(by `components.schemas.<Name>` or path object); frontend pointers cite
`reference/src/...`.

1. **Prefix is `messaging/` for all routes (config, conversations, messages,
   read).** VERDICT: **Verified.** Source: OpenAPI `GET /messaging/config`,
   `GET /messaging/conversations`, `GET /messaging/conversations/{conversation_id}`,
   `GET|POST /messaging/conversations/{conversation_id}/messages`,
   `POST /messaging/conversations/{conversation_id}/read`. The backlog's bare
   `/conversations/{id}` was shorthand (no root mount exists).

2. **`GET messaging/config` returns `{max_message_length, attachments_enabled,
   page_size}`.** VERDICT: **Corrected.** It returns `MessagingConfigOut`, a set of
   **boolean feature flags** (`messaging_encrypted_messages_enabled`,
   `messaging_gallery_enabled`, `messaging_dm_lottery_enabled`,
   `messaging_hide_controls_enabled`, `messaging_pins_enabled`,
   `messaging_reporting_enabled`, `messaging_mass_send_enabled`). Source:
   `components.schemas.MessagingConfigOut`; frontend `src/api/types.ts:
   MessagingConfig`; `src/api/endpoints/messaging.ts: getMessagingConfig`.

3. **`listConversations` is cursor-paged returning `{items, next_cursor}` with
   `cursor`/`limit` query params.** VERDICT: **Corrected.** `GET
   /messaging/conversations` returns a **bare array** of `ConversationOut` and
   declares **no** `cursor`/`limit` query params (only auth headers). Source:
   OpenAPI path `/messaging/conversations` get → `200` schema `type: array, items:
   $ref ConversationOut`; index params for that op = `authorization,X-SESSION-ID,
   X-API-Key` only. (Frontend `getConversations` defensively also accepts an
   envelope, but the live contract is a bare array.)

4. **`listMessages` is cursor-paged returning `{items, next_cursor}` via a
   `cursor` query param.** VERDICT: **Corrected.** `GET
   /messaging/conversations/{conversation_id}/messages` returns a **bare array** of
   `MessageOut`, paged via `limit` (default 50, max 200, min 1) and `before`
   (string) — no `cursor`, no `next_cursor`. Source: OpenAPI path object
   parameters `limit,before` + `200` schema `type: array, items: $ref MessageOut`;
   frontend `src/api/endpoints/messaging.ts: getMessages` (maps its arg to
   `{ before }`).

5. **`getConversation` GET returns a single `ConversationOut`.** VERDICT:
   **Verified.** Source: OpenAPI
   `GET /messaging/conversations/{conversation_id}` → `200:ConversationOut`;
   frontend `getConversation`.

6. **Conversation id field is `id`; has `updated_at` (ISO-8601 string).** VERDICT:
   **Corrected.** The id is **`conversation_id`**; there is **no `updated_at`** —
   recency is `last_message_at` (epoch int). `created_at` is an **integer (epoch
   seconds)**, not an ISO string. Required: `conversation_id, type, created_at,
   created_by, participant_count, status`. Source:
   `components.schemas.ConversationOut`; frontend `src/api/types.ts: Conversation`.

7. **Participant fields `username` + `avatar_url`.** VERDICT: **Corrected.**
   `app__routers__messaging__ParticipantOut` uses `user_id`, `status`, `role`
   (required) plus optional `display_name`, `profile_photo_url`, `last_read_at`,
   `joined_at`, etc. No `username`/`avatar_url`. Source:
   `components.schemas.app__routers__messaging__ParticipantOut`; frontend
   `src/api/types.ts: Participant`.

8. **Message id field `id`; text in `body`; `created_at` ISO string; has
   `client_id` and a `read` boolean.** VERDICT: **Corrected.** `MessageOut` uses
   **`message_id`**, text is **`text`** (nullable), `created_at` is **integer
   (epoch seconds)**, there is **no `client_id`** and **no `read` boolean**
   (read state is `read_by_count` / `read_by_user_ids`). Required:
   `conversation_id, message_id, sender_id, created_at, kind`. Source:
   `components.schemas.MessageOut`; frontend `src/api/endpoints/messagingAdapter.ts:
   adaptMessage` and `src/api/types.ts: Message`.

9. **Messages are a single flat text shape (Q-2 / R-3).** VERDICT: **Corrected.**
   Messages are **polymorphic** via a **required `kind`** discriminator
   (text/image/file/gif/sticker/calendar/poll/voice/…); `text` is null for non-text
   kinds. This ticket transports a flat `MessageDto` with `kind` + nullable `text`.
   Source: `MessageOut.required` includes `kind`; the many `.../messages/{kind}`
   POST routes in `openapi.index.txt`.

10. **`sendMessage` body is `{body, client_id}` and the response echoes
    `client_id`; status `201`.** VERDICT: **Corrected.** Request is
    `SendTextMessageIn` whose text field is **`text`** (1–4000); there is **no
    `client_id`** in the request or `MessageOut` response; response status is
    **`200`** (`MessageOut`). Source: `components.schemas.SendTextMessageIn`
    (`text` maxLength 4000), OpenAPI `POST .../messages` → `200:MessageOut`;
    frontend `src/api/types.ts: SendTextMessageReq`, `src/api/endpoints/
    messaging.ts: sendTextMessage`.

11. **The `4000` max-message length lives in config.** VERDICT: **Corrected.** It
    is a **request-body constraint** on `SendTextMessageIn.text` (maxLength 4000,
    minLength 1), not a config field. Source: `components.schemas.SendTextMessageIn`.

12. **`markRead` body is `{up_to_message_id}` and response is `{"ok": true}`
    (`OkResp`).** VERDICT: **Corrected.** Body is
    `app__routers__messaging__MarkReadIn` with **`last_read_message_id`** and/or
    **`last_read_at`** (both optional, body required); the `200` response has an
    **empty/unspecified body** (`schema: {}`) → return `Unit`, not `OkResp`. Source:
    `components.schemas.app__routers__messaging__MarkReadIn`; OpenAPI `POST .../read`
    request/response.

13. **Mutating verbs are POST; CSRF/cookies injected globally (AND-011/012); 401 →
    AND-013 refresh.** VERDICT: **Verified (transport)** for POST verbs (send/read
    are POST per OpenAPI). The CSRF/cookie/401 wiring is an Android-side concern
    owned by AND-011/012/013 and not observable in these sources — treated as a
    cross-ticket dependency, not a backend claim.

14. **Idempotent GETs eligible for AND-016 bounded backoff; ~20s dev-host
    timeouts.** VERDICT: **Unverified-assumption** (Android transport policy, not in
    OpenAPI/frontend). Carried as a dependency on AND-009/AND-016.

15. **Error bodies are FastAPI `detail`.** VERDICT: **Verified + refined.** Non-2xx
    on messaging routes return a **structured** `{"detail": {"code","reason",...}}`
    (e.g. `api_key_invalid`, `api_entitlement_denied`, `api_key_scope_denied`,
    `api_key_dual_credential_conflict`) on 400/401/403/429, and the validation list
    `{"detail":[{"loc","msg","type"}]}` on 422. Source: OpenAPI `/messaging/
    conversations` and `.../messages` response examples; `HTTPValidationError`.

16. **Hilt `@Provides @Singleton fun provideMessagingApi(retrofit) =
    retrofit.create(...)`.** VERDICT: **Unverified-assumption (framework pattern).**
    Standard Retrofit+Hilt usage; not derivable from backend sources. Framework ref:
    Retrofit `create` — https://square.github.io/retrofit/ ; Hilt modules —
    https://developer.android.com/training/dependency-injection/hilt-android .

17. **Moshi codegen (`@JsonClass(generateAdapter=true)`) with `@Json(name=...)`;
    lenient unknown-key handling.** VERDICT: **Unverified-assumption (framework
    pattern).** Framework ref: Moshi codegen —
    https://github.com/square/moshi#codegen . (Moshi ignores unknown JSON keys by
    default, which the lenient-parse requirement relies on.)

### Corrections made

- **Config DTO** rewritten from `{max_message_length, attachments_enabled,
  page_size}` to the seven boolean feature flags of `MessagingConfigOut` (claims 2,
  11).
- **List endpoints** changed from `{items,next_cursor}` cursor envelopes to **bare
  arrays**; `listConversations()` lost its `cursor`/`limit` params (none exist);
  `listMessages()` paginates via **`limit` + `before`**, not `cursor`; removed
  `ConversationPageDto`/`MessagePageDto` (claims 3, 4). Updated FR-5, §4.1
  interface, §4.2 DTOs, §5, §6 paging contract, T-2/T-4, AC-4.
- **ConversationDto** rekeyed `id`→`conversation_id`, dropped `updated_at`, added
  `type/created_by/participant_count/status/last_message_at`, timestamps →
  epoch-second `Long` (claim 6).
- **ParticipantDto** rekeyed `username`/`avatar_url` → `display_name`/
  `profile_photo_url` + `user_id`/`status`/`role` (claim 7).
- **MessageDto** rekeyed `id`→`message_id`, `body`→`text` (nullable), `created_at`→
  `Long`, removed `client_id` and `read`, added required `kind` discriminator
  (claims 8, 9).
- **SendMessageReq** changed body field `body`→`text`, removed `client_id`; send
  response status corrected `201`→`200`; updated FR-6, §5, T-5, AC-5 (claim 10).
- **MarkReadReq** field `up_to_message_id` → `last_read_message_id` (+ optional
  `last_read_at`); **`markRead` return `OkResp`→`Unit`** (empty body); removed
  `OkResp` import/usage; updated FR-3, §4.1, §7, §15, T-6 (claim 12).
- **Error envelope** in §5 refined to the structured `detail` object shape (claim
  15).
- Q-1..Q-4 marked resolved in §13.

### Open assumptions

- **AND-124 optimistic-send reconciliation has no `client_id` to echo.** The wire
  contract carries no client-supplied dedupe token (claim 10). AND-124 must
  reconcile its optimistic placeholder on `message_id` (+ content/`created_at`) or
  negotiate a new backend field. *Why unverifiable:* no such field exists in
  `SendTextMessageIn`/`MessageOut`, and the backend's send-idempotency behaviour is
  not described in OpenAPI (R-4 remains open).
- **AND-016 backoff / ~20s dev-host timeout policy** (claim 14) — Android transport
  policy, not in the backend/frontend sources.
- **Hilt provider + Moshi codegen + lenient parsing** (claims 16, 17) — framework
  conventions, validated against Retrofit/Hilt/Moshi docs, not backend sources.
- **`config` cache/backoff eligibility and "limits"** — `MessagingConfigOut`
  carries only feature-flag booleans; any client-side length/page limits must come
  from elsewhere (e.g. the `SendTextMessageIn.text` 1–4000 constraint), not config.

## 17. Test Plan

All cases target the JVM/Robolectric runner unless noted; this is a headless
transport+DTO ticket, so the bulk is contract/MockWebServer and unit decode tests
on the **JVM unit/Robolectric** target (no device). Test target legend matches the
CI/dev targets. The physical Galaxy A15 / emulator `test35` are only invoked for
the Hilt graph instrumented case and a real-dev-host smoke; nothing here needs
camera/biometric/WebRTC hardware.

- **TC-AND-120-01 — config decode.** Type: contract/MockWebServer. Target: JVM
  unit. Preconditions: `config.json` fixture = the seven `messaging_*` boolean
  flags. Steps: enqueue `200` with fixture; call `config()`. Expected: `GET`,
  path `/messaging/config`, decoded `MessagingConfigDto` with each flag mapped (e.g.
  `galleryEnabled == true`, `pinsEnabled == true`); no `max_message_length` field
  exists. Traces: AC-1, AC-2, AC-3.

- **TC-AND-120-02 — listConversations bare array + no query params.** Type:
  contract/MockWebServer. Target: JVM unit. Preconditions:
  `conversations.json` fixture is a JSON **array**. Steps: enqueue `200`; call
  `listConversations()`. Expected: `GET` `/messaging/conversations` with **no**
  query string; result is `List<ConversationDto>`; `[0].conversationId`,
  `unreadCount`, `lastMessage?.senderId`, and `createdAt` (Long) decode. Traces:
  AC-1, AC-2, AC-3, AC-4.

- **TC-AND-120-03 — getConversation path interpolation + nullable fields.** Type:
  contract/MockWebServer. Target: JVM unit. Preconditions: `conversation.json`
  fixture with `title: null` and a participant with `profile_photo_url: null`.
  Steps: enqueue `200`; call `getConversation("conv_1")`. Expected: `GET`
  `/messaging/conversations/conv_1`; `ConversationDto` decodes with `title == null`
  and `participants[].profilePhotoUrl == null`; `type`/`status` present. Traces:
  AC-1, AC-2, AC-3, AC-6.

- **TC-AND-120-04 — listMessages `limit`+`before` + bare array.** Type:
  contract/MockWebServer. Target: JVM unit. Preconditions: `messages.json` fixture
  is a JSON array of `MessageOut`. Steps: enqueue `200`; call
  `listMessages("conv_1", limit = 50, before = "msg_98")`. Expected: `GET`; resolved
  path contains `limit=50` and `before=msg_98` and **no** `cursor`; result is
  `List<MessageDto>`; `[0].messageId`, `kind`, nullable `text`, `createdAt` (Long)
  decode. Traces: AC-1, AC-2, AC-3, AC-4.

- **TC-AND-120-05 — listMessages with null paging args.** Type:
  contract/MockWebServer. Target: JVM unit. Preconditions: same fixture. Steps:
  call `listMessages("conv_1")` (both args null). Expected: resolved path is
  `/messaging/conversations/conv_1/messages` with **no** query params (Retrofit
  omits null `@Query`). Traces: AC-3, AC-4.

- **TC-AND-120-06 — sendMessage serializes `{text}` and decodes `MessageOut`.**
  Type: contract/MockWebServer. Target: JVM unit. Preconditions: `sent_message.json`
  fixture. Steps: enqueue `200`; call `sendMessage("conv_1", SendMessageReq(text =
  "on my way"))`. Expected: `POST`
  `/messaging/conversations/conv_1/messages`; recorded request body is exactly
  `{"text":"on my way"}` (no `client_id`/`body` keys); `Content-Type: application/
  json`; response `MessageDto` has `messageId`, `kind == "text"`, `createdAt`
  (Long). Traces: AC-1, AC-2, AC-3, AC-5.

- **TC-AND-120-07 — markRead serializes `{last_read_message_id}` and returns
  Unit on empty body.** Type: contract/MockWebServer. Target: JVM unit.
  Preconditions: none. Steps: enqueue `200` with **empty body**; call
  `markRead("conv_1", MarkReadReq(lastReadMessageId = "msg_100"))`. Expected:
  `POST` `/messaging/conversations/conv_1/read`; request body
  `{"last_read_message_id":"msg_100"}`; call returns `Unit` and does **not** throw a
  decode error on the empty body. Traces: AC-1, AC-2, AC-3.

- **TC-AND-120-08 — DTO round-trip (core-model).** Type: unit. Target: JVM unit.
  Preconditions: captured `MessageOut`/`ConversationOut` fixtures. Steps: decode
  fixture → re-encode with the production Moshi. Expected: required fields
  (`conversation_id`, `message_id`, `sender_id`, `created_at`, `kind` /
  `conversation_id`, `type`, `created_at`, `created_by`, `participant_count`,
  `status`) survive; snake_case names and integer timestamps preserved. Traces:
  AC-2, AC-6.

- **TC-AND-120-09 — lenient decoding (unknown keys + absent optionals).** Type:
  unit. Target: JVM unit. Preconditions: a `MessageOut` fixture with extra unknown
  keys (e.g. `tip_amount_cents`, `voice_message`) and a non-text fixture with
  `text` absent / `kind: "image"`. Steps: decode. Expected: decodes without error;
  unknown keys ignored; `text == null`; absent optionals fall to defaults. Traces:
  AC-6.

- **TC-AND-120-10 — non-2xx propagation (structured detail).** Type:
  contract/MockWebServer. Target: JVM unit. Preconditions: none. Steps: enqueue
  `404` with body `{"detail":{"code":"not_found","reason":"conversation_not_found"}}`;
  call `getConversation("missing")`. Expected: throws `retrofit2.HttpException` with
  `code() == 404`; the raw error body is retrievable (not swallowed) for AND-015.
  Also enqueue `403` `{"detail":{"code":"api_key_scope_denied",...}}` and assert
  `HttpException(403)`. Traces: AC-7.

- **TC-AND-120-11 — Hilt provider singleton.** Type: instrumented (Hilt graph).
  Target: emulator `test35` (API 35) — sufficient, no hardware needed. Preconditions:
  `@HiltAndroidTest` with the shared Retrofit bound. Steps: inject `MessagingApi`
  twice. Expected: non-null; both injections yield the **same** singleton instance;
  no second `Retrofit`/`OkHttpClient` constructed. Traces: AC-8, AC-9.

- **TC-AND-120-12 — security: message `text` never logged in release.** Type:
  manual + code-review (static). Target: JVM unit (assert the AND-009 interceptor
  redaction config) + reviewer check. Preconditions: release build config. Steps:
  inspect that no per-method body logging is added here and that the shared logging
  interceptor redacts/omits `sendMessage` bodies and message-bearing responses.
  Expected: message `text` does not reach logcat in release. Traces: AC-9 (and §8).

- **TC-AND-120-13 — flaky/offline dev-host behaviour.** Type: integration /
  manual. Target: **physical device (Galaxy A15, SM-A156U)** pointed at the
  cleartext dev host `http://18.222.237.167:8000` over real mobile/Wi-Fi network
  (preferred over emulator because the ~20s timeout + cleartext + real-network
  flakiness is the behaviour under test). Steps: with the host slow/unreachable,
  call `listConversations()` / `listMessages()`; then drop connectivity and call
  `sendMessage()`. Expected: transport failures surface as
  `SocketTimeoutException`/`IOException` (unchanged); idempotent GETs are retried per
  AND-009/AND-016 policy while `sendMessage`/`markRead` are **not** auto-retried.
  Traces: AC-3 (transport), §7. *Must run on the physical device.*

- **TC-AND-120-14 — build/codegen gate.** Type: integration (CI). Target: JVM/CI.
  Preconditions: clean checkout. Steps: run `./gradlew :core-model:
  testDebugUnitTest :core-network:assemble :core-network:testDebugUnitTest`.
  Expected: KSP generates a Moshi adapter for every messaging DTO (build fails if
  one is missing); all tests pass; no new lint/detekt violations. Traces: AC-10.

### Coverage matrix

| Acceptance criterion | Covered by |
|---|---|
| AC-1 (operations declared, compiles) | TC-01, 02, 03, 04, 06, 07, 14 |
| AC-2 (payloads map vs fixtures) | TC-01, 02, 03, 04, 06, 08 |
| AC-3 (verb/path/query/body) | TC-01, 02, 03, 04, 05, 06, 07, 13 |
| AC-4 (bare arrays; `limit`/`before`) | TC-02, 04, 05 |
| AC-5 (`{text}` send → `MessageDto`) | TC-06 |
| AC-6 (snake_case + epoch Long; lenient) | TC-03, 08, 09 |
| AC-7 (non-2xx → HttpException) | TC-10 |
| AC-8 (Hilt singleton) | TC-11 |
| AC-9 (no new client; no manual headers; no body logging) | TC-11, 12 |
| AC-10 (clean build + codegen + tests) | TC-14 |
