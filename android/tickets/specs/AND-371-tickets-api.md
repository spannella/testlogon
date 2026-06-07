---
id: AND-371
title: Tickets API
milestone: M8
epic: E48
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-027]
blocks: [AND-372, AND-373, AND-375]
---

# AND-371 — Tickets API

## 1. Overview & Goal

This ticket delivers the **network and serialization layer for the Ticket Spaces
feature** in the native Android port of TestLogon. It ports the web reference
module `frontend/src/api/endpoints/tickets.ts` (plus the shared types it consumes
from `frontend/src/api/types.ts`) into a typed Kotlin Retrofit interface and a
complete set of Moshi DTOs covering **ticket spaces, their members, the tickets
within a space, and ticket messages**.

The deliverable is **purely a data-access layer**: a `TicketsApi` Retrofit
interface in `core-network`, the supporting request/response DTOs in
`core-model`, the Moshi adapter registrations, and a Hilt binding. No UI,
ViewModel, repository, caching, or navigation is in scope here — those are owned
by downstream tickets (AND-372 spaces/threads UI, AND-373 messages/reply,
AND-375 ViewModels). The single testable goal is: **ticket-spaces payloads
(spaces, members, tickets, messages) round-trip through Moshi exactly as the
backend emits them, verified with captured JSON samples and MockWebServer.**

## 2. Context & References

- **Stack:** Kotlin 2.0.21, Retrofit 2.11, OkHttp 4.12, Moshi 1.15 (codegen via
  KSP), Coroutines/Flow. Module layering `app → feature-* → core-*`; this ticket
  touches only `core-network` and `core-model`.
- **Web reference:** `frontend/src/api/endpoints/tickets.ts` (endpoint surface),
  `frontend/src/api/types.ts` (DTO field names/optionality). These are the
  authoritative source for paths, verbs, query params, and field shapes.
- **Backend:** FastAPI + DynamoDB. Dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable). OpenAPI at `/openapi.json` — cross-check the
  `tickets`/`ticket-spaces` operation schemas against the web reference before
  freezing field names.
- **Auth/transport (AND-027):** Every call rides the cookie-based session
  established by `AuthApi`. The shared authenticated `Retrofit`/`OkHttpClient`
  (persistent cookie jar, `X-CSRF-Token` echo from the `ui_csrf` cookie, single
  `POST /ui/session/refresh` retry on 401) is provided by AND-027 / the
  `core-network` DI graph. **AND-371 reuses that client unchanged** and adds only
  the new endpoint interface and DTOs.
- **Error model:** FastAPI `detail` mapping (`string | [{msg}] | {code,...}`) and
  the typed `ApiResult<T>` wrapper are owned by `core-network` and applied
  uniformly; this ticket does not redefine them.
- **Namespace:** all classes live under `com.testlogon.android.*`.

## 3. Functional Requirements

FR-1. Expose a `TicketsApi` Retrofit interface declaring suspend functions for
the read surface of the ticket-spaces feature present in the web reference
(`src/api/endpoints/tickets.ts`):
- List ticket spaces the current user can access (`GET /ticket-spaces`).
- Get a single ticket space, including its embedded members
  (`GET /ticket-spaces/{space_id}`).
- List tickets within a space, paginated (`GET /ticket-spaces/{space_id}/tickets`).
- Get a single ticket within a space, including its embedded messages and
  activity (`GET /ticket-spaces/{space_id}/tickets/{ticket_id}`).

> CORRECTED (review AND-371): the web reference exposes **no** standalone
> `GET .../members` or `GET .../messages` endpoint. Members are returned embedded
> in the `TicketSpace` object (`members[]`) and messages are returned embedded in
> the `Ticket` object (`messages[]`); both are populated by the get-space and
> get-ticket calls respectively. The "list members (paginated)" and "list
> messages (paginated)" functions in the original draft do not exist on the
> backend and have been removed. (Verified: `src/api/endpoints/tickets.ts`;
> OpenAPI `GET /ticket-spaces/{space_id}` → `TicketSpaceEnvelope`/`TicketSpaceOut`,
> `GET /ticket-spaces/{space_id}/tickets/{ticket_id}` → `SpaceTicketEnvelope`/
> `SpaceTicketOut`.) Member mutation (`POST`/`DELETE .../members`) and message
> posting (`POST .../messages`) are write endpoints owned by AND-373.

FR-2. Provide Moshi DTOs that **exactly** model the JSON for: `TicketSpace`
(`TicketSpaceOut`), `TicketSpaceMember` (`SpaceMemberOut`), `Ticket`
(`SpaceTicketOut`), `TicketMessage` (`SpaceTicketMessage`), the embedded
`TicketActivity` (`SpaceTicketActivity`), and the **response envelopes** the
backend actually returns: object envelopes `TicketSpaceEnvelope` (`{space}`) and
`SpaceTicketEnvelope` (`{ticket}`), and list envelopes `TicketSpaceListEnvelope`
and `SpaceTicketListEnvelope` (each `{items[], next_cursor?}`).

> CORRECTED (review AND-371): the backend wraps single objects in a **named
> envelope** (`{"space": {...}}`, `{"ticket": {...}}`) rather than returning the
> bare object, and list responses use `{items, next_cursor}` with **no `total`
> field**. The original draft's bare-object and `*Page` shapes were wrong on both
> counts. (Verified: OpenAPI `TicketSpaceEnvelope`, `SpaceTicketEnvelope`,
> `TicketSpaceListEnvelope`, `SpaceTicketListEnvelope`; `src/api/endpoints/tickets.ts`
> interfaces `TicketSpaceEnvelope`/`TicketSpaceListEnvelope`/`TicketEnvelope`/
> `TicketListEnvelope`.)

FR-3. All wire field names must match the backend (snake_case) via
`@Json(name=...)`; Kotlin properties use idiomatic camelCase.

FR-4. Nullability must match the contract: fields the backend may omit are
nullable Kotlin types with sensible defaults so deserialization never throws on
absent-but-optional fields; required fields are non-null.

FR-5. Enum-like string fields are modeled as `String` constants in a companion
object (not Kotlin `enum class`) so an unknown server value never fails
deserialization — forward-compatible by design. The real enum-like fields are:
ticket `status` (`open` | `in_progress` | `waiting_on_user` | `done`; the
writable form additionally allows `reopened`), space-member `role` (`owner` |
`editor` | `viewer`), space `visibility` (`private` | `shared`), and the
message's `sender_role` (free-form string).

> CORRECTED (review AND-371): there is **no** `author_type` field on messages.
> Messages carry `sender_role` and `sender_sub`. Ticket statuses are NOT
> `open/pending/closed` and member roles are NOT `owner/agent/member`; the real
> values are listed above. (Verified: OpenAPI `SpaceTicketStatusReq`/`TicketStatusReq`
> enums, `SpaceMemberOut.role` enum, `TicketSpaceOut.visibility` enum,
> `SpaceTicketMessage`; `src/api/endpoints/tickets.ts` `TicketStatus`,
> `TicketStatusWritable`, `SpaceRole`, `TicketMessage`.)

FR-6. The interface returns `ApiResult<T>`-compatible types per the established
`core-network` call convention (suspend returning the DTO; the `ApiResult`
wrapping is applied by the shared call adapter/extension from AND-027's stack).

FR-7. Out of scope (named owners): UI rendering (AND-372), posting messages /
reply mutations and member management (AND-373), ViewModels/state (AND-375),
Room caching (no ticket caching ticket exists — repository-level only if added
later), Projects (`projects.ts`, AND-374).

## 4. Technical Design

**Module placement.** DTOs in `core-model`
(`com.testlogon.android.core.model.tickets`); the Retrofit interface and DI in
`core-network` (`com.testlogon.android.core.network.tickets`).

**Interface.**

```kotlin
package com.testlogon.android.core.network.tickets

import com.testlogon.android.core.model.tickets.*
import retrofit2.http.GET
import retrofit2.http.Path
import retrofit2.http.Query

interface TicketsApi {

    // GET /ticket-spaces  (query: cursor, limit)
    @GET("ticket-spaces")
    suspend fun listSpaces(
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
    ): TicketSpaceListEnvelope

    // GET /ticket-spaces/{spaceId}  -> {space} (members embedded)
    @GET("ticket-spaces/{spaceId}")
    suspend fun getSpace(@Path("spaceId") spaceId: String): TicketSpaceEnvelope

    // GET /ticket-spaces/{spaceId}/tickets  (query: status, assignee_sub, cursor, limit)
    @GET("ticket-spaces/{spaceId}/tickets")
    suspend fun listSpaceTickets(
        @Path("spaceId") spaceId: String,
        @Query("status") status: String? = null,
        @Query("assignee_sub") assigneeSub: String? = null,
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
    ): SpaceTicketListEnvelope

    // GET /ticket-spaces/{spaceId}/tickets/{ticketId}  -> {ticket} (messages+activity embedded)
    @GET("ticket-spaces/{spaceId}/tickets/{ticketId}")
    suspend fun getSpaceTicket(
        @Path("spaceId") spaceId: String,
        @Path("ticketId") ticketId: String,
    ): SpaceTicketEnvelope
}
```

> CORRECTED (review AND-371) vs. the original draft:
> - Base path is `ticket-spaces`, **not** `ui/ticket-spaces` — there is no `/ui`
>   prefix on this resource (the only `/ui/...` call in the flow is the shared
>   `POST /ui/session/refresh` retry). (Verified: OpenAPI `GET /ticket-spaces`;
>   `src/api/endpoints/tickets.ts: listTicketSpaces` calls `/ticket-spaces`.)
> - The standalone `listMembers` and `listMessages` functions were removed — no
>   such endpoints exist (members/messages are embedded; see FR-1).
> - Return types are the named **envelopes**, not bare objects/`*Page` types.
> - `listSpaceTickets` gains the real `assignee_sub` query param documented by the
>   backend and used by the web client.
> - `getSpace` takes no `limit`/`cursor` (members are embedded, not paginated).
>
> Note (framework ref): Retrofit treats a leading `/` on the `@GET` value as
> host-absolute, so the relative form `"ticket-spaces"` (no leading slash) is
> used so the configured base URL's path is preserved
> (https://square.github.io/retrofit/2.x/retrofit/retrofit2/http/GET.html).
> Write endpoints (`POST/DELETE .../members`, `POST .../assign|messages|status`)
> are intentionally **out of scope** here (AND-373).

**DI binding (Hilt + KSP).**

```kotlin
@Module
@InstallIn(SingletonComponent::class)
object TicketsApiModule {
    @Provides
    @Singleton
    fun provideTicketsApi(retrofit: Retrofit): TicketsApi =
        retrofit.create(TicketsApi::class.java)
}
```

The injected `Retrofit` is the **authenticated, Moshi-configured** instance from
the AND-027 network graph (cookie jar, CSRF header, refresh-on-401, `MoshiConverterFactory`,
suspend `ApiResult` call adapter). AND-371 adds no new OkHttp interceptors.

## 5. API Contract

All in-scope endpoints are HTTP GET, idempotent, and eligible for the bounded
backoff retry on transient failures already implemented in the shared client.
Base URL is the configured dev host. Cookies + `X-CSRF-Token` are attached
transparently. **All examples below are corrected against the live contract**
(`src/api/endpoints/tickets.ts` and OpenAPI); timestamps are **Unix epoch
seconds (integers)**, not ISO-8601 strings.

**`GET /ticket-spaces` → `200 TicketSpaceListEnvelope`**

```json
{
  "items": [
    {
      "space_id": "spc_01H...",
      "owner_sub": "usr_01HZ...",
      "name": "Support — Tier 1",
      "visibility": "shared",
      "created_at": 1743606069,
      "updated_at": 1748597561,
      "members": [
        {
          "space_id": "spc_01H...",
          "member_sub": "usr_01HZ...",
          "role": "owner",
          "created_at": 1743606069,
          "updated_at": 1743606069
        }
      ]
    }
  ],
  "next_cursor": "eyJrIjoi..."
}
```

**`GET /ticket-spaces/{spaceId}` → `200 TicketSpaceEnvelope`** — the space object
is wrapped under a `space` key and **always** includes its `members` array
(no separate members endpoint):

```json
{ "space": { "space_id": "spc_01H...", "owner_sub": "usr_01HZ...", "name": "Support — Tier 1", "visibility": "shared", "created_at": 1743606069, "updated_at": 1748597561, "members": [ /* SpaceMemberOut[] */ ] } }
```

**`GET /ticket-spaces/{spaceId}/tickets` → `200 SpaceTicketListEnvelope`**
(query: `status`, `assignee_sub`, `cursor`, `limit`)

```json
{
  "items": [
    {
      "ticket_id": "tkt_01J2...",
      "subject": "Login loop on Android",
      "owner_sub": "usr_01HZ...",
      "status": "open",
      "assigned_admin_sub": null,
      "assigned_by": null,
      "assigned_at": null,
      "assigned_to_sub": null,
      "space_id": "spc_01HZ...",
      "created_at": 1748772000,
      "updated_at": 1749060660,
      "version": 3,
      "messages": [],
      "activity": []
    }
  ],
  "next_cursor": "eyJrIjoi..."
}
```

> Note: `SpaceTicketOut` always carries `messages` and `activity` arrays (both
> `required`); list responses typically return them populated or empty depending
> on backend projection. Treat them as present-but-possibly-empty.

**`GET /ticket-spaces/{spaceId}/tickets/{ticketId}` → `200 SpaceTicketEnvelope`**
— ticket wrapped under a `ticket` key, with embedded `messages` and `activity`:

```json
{
  "ticket": {
    "ticket_id": "tkt_01J2...",
    "subject": "Login loop on Android",
    "owner_sub": "usr_01HZ...",
    "status": "in_progress",
    "assigned_admin_sub": "usr_admin_01...",
    "assigned_by": "usr_admin_01...",
    "assigned_at": 1749000000,
    "assigned_to_sub": null,
    "space_id": "spc_01HZ...",
    "created_at": 1748772000,
    "updated_at": 1749060660,
    "version": 4,
    "messages": [
      {
        "message_id": "msg_01J3...",
        "sender_sub": "usr_01HZ...",
        "sender_role": "owner",
        "body": "Tried clearing cookies, still loops.",
        "created_at": 1749060660,
        "email_alert_queued_for": []
      }
    ],
    "activity": [
      { "type": "status_change", "actor_sub": "usr_admin_01...", "assignee_sub": null, "status": "in_progress", "created_at": 1749000000 }
    ]
  }
}
```

**Error responses.** The OpenAPI documents two distinct error shapes for these
routes, mapped by the shared `core-network` error layer:
- `400` / `403` / `404` / `409` → **`ErrorEnvelope`**: `{ "error": { "code":
  string, "message": string, "details"?: object | null } }`. (Verified: OpenAPI
  `ErrorEnvelope` / `ErrorDetail`.) This is the typed-error shape; surface as
  `ApiResult.Failure` with `error.message` (and `error.code` for branching).
- `422` → **`HTTPValidationError`**: `{ "detail": [{ "loc": [...], "msg":
  string, "type": string }] }`.
- `401` triggers the shared one-shot `POST /ui/session/refresh` + single retry;
  persistent `401` surfaces as `ApiResult.Failure(Unauthorized)`.

> CORRECTED (review AND-371): the original draft described a single FastAPI
> `detail` envelope (`string | [{msg}] | {code,...}`) for all errors. Per the
> OpenAPI the non-validation errors actually use the `{error:{code,message,...}}`
> envelope; only `422` uses the `detail` array. The web client's
> `normalizeErrorDetail` is lenient (it reads `body.detail` in several shapes),
> but the Android mapper should handle **both** the `error` envelope and the
> `detail` form. Confirm the exact runtime body against the live dev host when
> capturing fixtures.

## 6. Data & State Management

DTOs (Moshi `@JsonClass(generateAdapter = true)`), in
`com.testlogon.android.core.model.tickets`:

> CORRECTED (review AND-371): the DTOs below are rewritten to match the live
> contract. The original draft's field names, types, defaults, the
> `TicketAttachment` type, and the `*Page` envelopes were all incorrect (see §16).

```kotlin
// TicketSpaceOut
@JsonClass(generateAdapter = true)
data class TicketSpace(
    @Json(name = "space_id") val spaceId: String,
    @Json(name = "owner_sub") val ownerSub: String,
    val name: String,
    val visibility: String = VISIBILITY_PRIVATE,
    @Json(name = "created_at") val createdAt: Long,
    @Json(name = "updated_at") val updatedAt: Long,
    val members: List<TicketSpaceMember> = emptyList(),
) { companion object { const val VISIBILITY_PRIVATE = "private"; const val VISIBILITY_SHARED = "shared" } }

// SpaceMemberOut
@JsonClass(generateAdapter = true)
data class TicketSpaceMember(
    @Json(name = "space_id") val spaceId: String,
    @Json(name = "member_sub") val memberSub: String,
    val role: String = ROLE_VIEWER,
    @Json(name = "created_at") val createdAt: Long,
    @Json(name = "updated_at") val updatedAt: Long,
) { companion object { const val ROLE_OWNER = "owner"; const val ROLE_EDITOR = "editor"; const val ROLE_VIEWER = "viewer" } }

// SpaceTicketOut
@JsonClass(generateAdapter = true)
data class Ticket(
    @Json(name = "ticket_id") val ticketId: String,
    val subject: String,
    @Json(name = "owner_sub") val ownerSub: String,
    val status: String = STATUS_OPEN,
    @Json(name = "assigned_admin_sub") val assignedAdminSub: String? = null,
    @Json(name = "assigned_by") val assignedBy: String? = null,
    @Json(name = "assigned_at") val assignedAt: Long? = null,
    @Json(name = "assigned_to_sub") val assignedToSub: String? = null,
    @Json(name = "space_id") val spaceId: String? = null,
    @Json(name = "created_at") val createdAt: Long,
    @Json(name = "updated_at") val updatedAt: Long,
    val version: Int,
    val messages: List<TicketMessage> = emptyList(),
    val activity: List<TicketActivity> = emptyList(),
) { companion object {
    const val STATUS_OPEN = "open"; const val STATUS_IN_PROGRESS = "in_progress"
    const val STATUS_WAITING_ON_USER = "waiting_on_user"; const val STATUS_DONE = "done"
    const val STATUS_REOPENED = "reopened" // writable-only
} }

// SpaceTicketMessage
@JsonClass(generateAdapter = true)
data class TicketMessage(
    @Json(name = "message_id") val messageId: String,
    @Json(name = "sender_sub") val senderSub: String,
    @Json(name = "sender_role") val senderRole: String = "",
    val body: String = "",
    @Json(name = "created_at") val createdAt: Long,
    @Json(name = "email_alert_queued_for") val emailAlertQueuedFor: List<String> = emptyList(),
)

// SpaceTicketActivity
@JsonClass(generateAdapter = true)
data class TicketActivity(
    val type: String,
    @Json(name = "actor_sub") val actorSub: String,
    @Json(name = "assignee_sub") val assigneeSub: String? = null,
    val status: String? = null,
    @Json(name = "created_at") val createdAt: Long,
)
```

Response envelopes (the backend wraps single objects under a named key; lists
use `{items, next_cursor}` with **no `total`**):

```kotlin
@JsonClass(generateAdapter = true) data class TicketSpaceEnvelope(val space: TicketSpace)
@JsonClass(generateAdapter = true) data class SpaceTicketEnvelope(val ticket: Ticket)

@JsonClass(generateAdapter = true) data class TicketSpaceListEnvelope(
    val items: List<TicketSpace> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)
@JsonClass(generateAdapter = true) data class SpaceTicketListEnvelope(
    val items: List<Ticket> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)
```

Moshi codegen (KSP) generates the adapters; no hand-written adapters are
required unless a polymorphic field appears (none in this surface). **No
persistent state** (Room/DataStore) is created by this ticket; `next_cursor` is
returned to callers verbatim for downstream Paging 3 integration in
AND-372/AND-375. **Timestamps are epoch-second `Long` integers** at the wire
level and stay `Long` at this layer; conversion to `Instant`/`OffsetDateTime` is
a ViewModel/repository concern.

> CORRECTED (review AND-371): the original draft modeled timestamps as ISO-8601
> `String`. The backend emits **integer epoch seconds** (`"type": "integer"` on
> every `created_at`/`updated_at`/`assigned_at`). Modeling them as `String` would
> throw `JsonDataException` on a numeric token. (Verified: OpenAPI
> `TicketSpaceOut`, `SpaceTicketOut`, `SpaceMemberOut`, `SpaceTicketMessage`.)

## 7. Error Handling & Resilience

This layer does not implement its own error policy — it inherits the
`core-network` behavior established by AND-027:
- **Timeouts:** ~20s call/read timeout for the unreliable dev host.
- **Retry:** bounded exponential backoff for these idempotent GETs only.
- **401:** single `POST /ui/session/refresh` then one retry; persistent failure
  surfaces as `ApiResult.Failure(Unauthorized)`.
- **Error mapping:** the shared mapper collapses both the `{error:{code,message,
  details}}` envelope (400/403/404/409) and the `{detail:[{msg,loc,type}]}`
  validation form (422) into a typed error message (see corrected §5).
- **Deserialization robustness (this ticket's responsibility):** optional fields
  are nullable with defaults and string-typed enums (`status`, `role`,
  `visibility`, `sender_role`) prevent `JsonDataException` on unknown/absent
  values, so a partially-populated or forward-evolved payload still parses. A
  genuinely malformed body becomes `ApiResult.Failure(Parse)` via the shared
  converter — verified by a malformed-fixture test. Note required integer
  timestamps and `version` must be present; a missing required field is a parse
  failure by design.

## 8. Security & Privacy

- Reuses the authenticated client: session cookies + `X-CSRF-Token` are attached
  by existing interceptors; AND-371 adds no auth code and stores no credentials.
- Although CSRF tokens are not required for GETs, the header is sent uniformly by
  the shared client — no change here.
- DTOs carry PII / sensitive identifiers (`owner_sub`, `member_sub`,
  `sender_sub`, `assigned_*_sub` user IDs, ticket `subject`, and message `body`
  free text — and `email_alert_queued_for`, which may contain email-related
  values). They must **not** be logged in plaintext; the network logging
  interceptor stays at headers-only / redacted-body level in release builds.

> CORRECTED (review AND-371): the original draft listed usernames, display names,
> and avatar URLs as PII fields — none of those exist in this contract (members
> are bare `member_sub` IDs; there is no profile data on these DTOs). PII surface
> is the opaque `*_sub` identifiers plus free-text `subject`/`body`.
- Transport is plaintext HTTP on the dev host only; production base URL and
  cleartext policy are owned by the network/build config tickets, not this one.
- No new fields are persisted, so there is no at-rest data surface introduced.

## 9. Accessibility & i18n

N/A for the runtime UI — this is a non-UI data layer. Constraints it must honor
for downstream A11y/i18n: DTOs preserve server-provided human-readable strings
(`subject`, `body`) verbatim without truncation or locale transformation, and
timestamps remain raw epoch-second `Long` values so the presentation layer
(AND-372) can format them per device locale and expose content descriptions. No
user-facing strings are introduced here.

## 10. Telemetry & Logging

- Reuses the shared OkHttp logging interceptor (debug = `BODY`, release =
  `NONE`/redacted). No bespoke logging is added.
- Per-endpoint latency/error counts are emitted by the shared metrics
  interceptor (if present in the AND-027 graph) keyed by route template (e.g.
  `ticket-spaces/{spaceId}/tickets`) — no new instrumentation in this ticket.
- No analytics events are defined here; user-facing ticket events belong to the
  UI tickets (AND-372/AND-373).

## 11. Testing Strategy

The acceptance bar is "**ticket payloads map (tested)**." Tests live in
`core-model` (pure Moshi) and `core-network` (MockWebServer), using `core-testing`
helpers.

**A. DTO serialization (JVM unit, `core-model`):** For each of `TicketSpace`,
`TicketSpaceMember`, `Ticket`, `TicketMessage`, `TicketActivity`, and all four
envelopes (`TicketSpaceEnvelope`, `SpaceTicketEnvelope`,
`TicketSpaceListEnvelope`, `SpaceTicketListEnvelope`):
1. Load a captured JSON fixture (committed under
   `core-model/src/test/resources/tickets/*.json`, derived from the web
   reference / OpenAPI / live dev host).
2. Deserialize with the production Moshi instance; assert every field maps,
   including snake_case → camelCase, integer-epoch `created_at`/`updated_at`
   into `Long`, and nested `members`/`messages`/`activity`.
3. Round-trip re-serialize and assert structural equality (JSON-tree compare,
   not raw string).

**B. Optional/edge fixtures:** minimal payloads (only required fields present),
`null` for every optional field (`assigned_*`, `space_id`, `next_cursor`), empty
`items`/`members`/`messages`/`activity`/`email_alert_queued_for` arrays, and an
**unknown enum value** for `status`/`role`/`visibility`/`sender_role` — assert no
exception and the raw value is retained.

**C. Endpoint contract (`core-network`, MockWebServer):** Stand up
`TicketsApi` against MockWebServer. For each of the four GET functions assert the
**request** method, path (no `/ui` prefix; with substituted
`{spaceId}`/`{ticketId}`), and query params (`limit`/`cursor`, plus
`status`/`assignee_sub` for `listSpaceTickets`), and that a `200` fixture
deserializes into the expected envelope DTO. Include a `422` validation-array
fixture and a `{error:{code,message}}` (e.g. 404) fixture and a malformed-body
fixture to confirm failure mapping. The 401-refresh path is covered by AND-027's
suite and not re-tested here.

**D. Malformed/parse:** a truncated JSON body produces a parse failure rather
than a crash.

Coverage target: 100% of DTO fields exercised by at least one fixture.

## 12. Dependencies & Sequencing

- **Depends on AND-027** (AuthApi / authenticated session network stack): supplies
  the shared `Retrofit`/OkHttp client, cookie jar, CSRF + refresh interceptors,
  Moshi configuration, and the `ApiResult` call convention this interface plugs
  into. AND-027 transitively depends on AND-026 (auth DTOs/adapters) and
  AND-010 (core-network base).
- **Blocks AND-372** (Ticket spaces + threads UI — consumes `TicketsApi` for
  spaces/ticket/thread rendering), **AND-373** (messages/reply + members — extends
  this surface with mutations), and **AND-375** (Tickets/projects ViewModels —
  wraps these calls in `StateFlow<UiState>`). AND-376 tests the repo/UI built on
  top.
- **Sequencing:** land DTOs (`core-model`) first with fixture tests, then the
  Retrofit interface + DI (`core-network`) with MockWebServer tests, then hand
  off to AND-372. The reply/post-message endpoints needed by AND-373 are **not**
  added here unless they appear adjacent in `tickets.ts`; if so, they may be
  stubbed as additional interface methods but their tests belong to AND-373.

## 13. Risks & Open Questions

- **R1 — Field-shape drift (RESOLVED in review):** paths, pagination, and field
  names were reconciled against `src/api/endpoints/tickets.ts` and the OpenAPI
  spec during this review; §5/§6 now reflect the verified contract. Residual
  risk: the live dev host may diverge from the documented spec, so **fixtures
  captured from the live host remain authoritative** and any divergence must be
  noted in the PR.
- **R2 — Embedded vs. separate members (RESOLVED):** `GET /ticket-spaces/{id}`
  **embeds** `members` (a `required` array on `TicketSpaceOut`); there is **no**
  `GET .../members` endpoint. Modeled as a non-null embedded list. (Verified:
  OpenAPI `TicketSpaceOut.members`.)
- **R3 — Pagination contract (RESOLVED):** the backend uses **`next_cursor`
  only**; there is no `total` field on any list envelope. Cursor is opaque and
  passed back verbatim. (Verified: OpenAPI `TicketSpaceListEnvelope`,
  `SpaceTicketListEnvelope`.)
- **R4 — Attachments shape (RESOLVED — removed):** there is **no** attachments
  field on messages and no `TicketAttachment` type. `SpaceTicketMessage` carries
  `message_id`, `sender_sub`, `sender_role`, `body`, `created_at`, and
  `email_alert_queued_for: string[]`. The DTO was deleted.
- **Open question (RESOLVED):** messages have no `author_type`; they carry
  `sender_role` (free-form string) and `sender_sub` (a user id string, not a
  denormalized object). Ticket assignment is via `assigned_admin_sub` /
  `assigned_to_sub` (id strings). (Verified: OpenAPI `SpaceTicketMessage`,
  `SpaceTicketOut`; `src/api/endpoints/tickets.ts: TicketMessage`, `Ticket`.)
- **R5 — Error envelope ambiguity (NEW, open):** OpenAPI documents
  `{error:{code,message}}` for 400/403/404/409 but the web client reads
  `body.detail`. The exact runtime body on the dev host must be confirmed when
  capturing fixtures so the Android error mapper matches reality.

## 14. Acceptance Criteria

1. `TicketsApi` exists in `core-network` with suspend GET functions for: list
   spaces (`GET /ticket-spaces`), get space (`GET /ticket-spaces/{spaceId}`), list
   space tickets (`GET /ticket-spaces/{spaceId}/tickets`), and get space ticket
   (`GET /ticket-spaces/{spaceId}/tickets/{ticketId}`) — paths (no `/ui` prefix),
   verbs, and query params (`limit`/`cursor`, plus `status`/`assignee_sub` on list
   tickets) matching `src/api/endpoints/tickets.ts` and the OpenAPI spec
   (MockWebServer-verified per §11.C). No standalone members/messages list
   functions (those resources are embedded; see FR-1).
2. Moshi DTOs `TicketSpace`, `TicketSpaceMember`, `Ticket`, `TicketMessage`,
   `TicketActivity`, and the four response envelopes (`TicketSpaceEnvelope`,
   `SpaceTicketEnvelope`, `TicketSpaceListEnvelope`, `SpaceTicketListEnvelope`)
   exist in `core-model` with `@JsonClass(generateAdapter = true)`, integer-epoch
   `Long` timestamps, and correct `@Json` wire names.
3. Captured-sample fixtures for every DTO deserialize **exactly** (all fields
   mapped) and round-trip without loss (§11.A) — this satisfies the backlog
   acceptance "Ticket payloads map (tested)."
4. Minimal, all-null-optional, empty-array, and **unknown-enum** payloads parse
   without exception (§11.B).
5. A malformed body yields a typed parse failure, not a crash (§11.D).
6. `TicketsApi` is provided via Hilt and injectable; it reuses the AND-027
   authenticated `Retrofit` (no new interceptors/cookie handling added).
7. No UI, ViewModel, repository, or persistence is introduced.

## 15. Definition of Done

- All §14 criteria met; new unit + MockWebServer tests pass in CI.
- `./gradlew :core-model:test :core-network:test` green; KSP Moshi adapters
  generate with no warnings.
- Code in `com.testlogon.android.core.model.tickets` and
  `...core.network.tickets`, conforming to module layering (`core-*` only).
- ktlint/detekt clean; no public DTO field undocumented relative to the captured
  fixtures.
- Fixtures committed under `core-model/src/test/resources/tickets/` and
  referenced by tests; any deviation from §5/§6 reconciled against the live
  payload and noted in the PR.
- Reviewed and merged to `android-port`; AND-372/AND-373/AND-375 unblocked
  (interface + DTOs importable downstream with no further network changes
  required).

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source pointer.
"OpenAPI" = `reference/openapi.index.txt` + schemas in `reference/openapi.pretty.json`
(`components.schemas.<Name>`). Frontend paths are under `reference/src/`.

1. **Spaces list endpoint is `GET /ticket-spaces`** (no `/ui` prefix). VERDICT:
   Corrected (draft said `GET /ui/ticket-spaces`). SOURCE: OpenAPI
   `GET /ticket-spaces` (op `list_ticket_spaces_ticket_spaces_get`);
   `src/api/endpoints/tickets.ts: listTicketSpaces` → `api.get("/ticket-spaces")`.
2. **Get space is `GET /ticket-spaces/{space_id}` returning `TicketSpaceEnvelope`
   (`{space}`)**, with `members` embedded. VERDICT: Corrected (draft returned a
   bare `TicketSpace` and posited an optional/possibly-separate members call).
   SOURCE: OpenAPI `GET /ticket-spaces/{space_id}` → `TicketSpaceEnvelope` →
   `TicketSpaceOut` (`members` required); `src/api/endpoints/tickets.ts: getTicketSpace`.
3. **No standalone `GET .../members` endpoint exists.** VERDICT: Corrected
   (draft declared `listMembers`). SOURCE: OpenAPI exposes only
   `POST /ticket-spaces/{space_id}/members` and
   `DELETE /ticket-spaces/{space_id}/members/{member_sub}` (writes, AND-373);
   no GET. `src/api/endpoints/tickets.ts` has only `addTicketSpaceMember` /
   `removeTicketSpaceMember`.
4. **List space tickets is `GET /ticket-spaces/{space_id}/tickets` returning
   `SpaceTicketListEnvelope` (`{items, next_cursor}`), query params
   `status, assignee_sub, cursor, limit`.** VERDICT: Corrected (draft path had
   `/ui` prefix, missing `assignee_sub`, and returned a `*Page` with `total`).
   SOURCE: OpenAPI `GET /ticket-spaces/{space_id}/tickets`
   (`params=space_id,status,assignee_sub,cursor,limit,...`) →
   `SpaceTicketListEnvelope`; `src/api/endpoints/tickets.ts: listSpaceTickets`.
5. **Get space ticket is `GET /ticket-spaces/{space_id}/tickets/{ticket_id}`
   returning `SpaceTicketEnvelope` (`{ticket}`)**, with `messages` + `activity`
   embedded. VERDICT: Corrected (draft returned bare `Ticket`). SOURCE: OpenAPI
   same path → `SpaceTicketEnvelope` → `SpaceTicketOut` (`messages`, `activity`
   required); `src/api/endpoints/tickets.ts: getSpaceTicket`.
6. **No standalone `GET .../messages` endpoint exists; messages are embedded in
   the ticket.** VERDICT: Corrected (draft declared `listMessages` with a
   `TicketMessagePage`). SOURCE: OpenAPI exposes only
   `POST /ticket-spaces/{space_id}/tickets/{ticket_id}/messages` (write, AND-373);
   `SpaceTicketOut.messages` is the read path.
7. **List envelopes contain only `items` + optional `next_cursor` — no `total`.**
   VERDICT: Corrected (draft `*Page` types had nullable `total`). SOURCE: OpenAPI
   `TicketSpaceListEnvelope`, `SpaceTicketListEnvelope` (only `items` required,
   `next_cursor` nullable).
8. **Single objects are wrapped in named envelopes (`{space}`, `{ticket}`).**
   VERDICT: Corrected (draft returned bare objects). SOURCE: OpenAPI
   `TicketSpaceEnvelope.space`, `SpaceTicketEnvelope.ticket`;
   `src/api/endpoints/tickets.ts: TicketSpaceEnvelope`, `TicketEnvelope`.
9. **Timestamps (`created_at`, `updated_at`, `assigned_at`, message/activity
   `created_at`) are integer Unix epoch seconds.** VERDICT: Corrected (draft used
   ISO-8601 `String`). SOURCE: OpenAPI `TicketSpaceOut`, `SpaceTicketOut`,
   `SpaceMemberOut`, `SpaceTicketMessage`, `SpaceTicketActivity`
   (`"type": "integer"`); `src/api/endpoints/tickets.ts` (`created_at: number`).
10. **`TicketSpace` fields are `space_id, owner_sub, name, visibility
    (private|shared), created_at, updated_at, members[]`.** VERDICT: Corrected
    (draft had `id, slug, description, status, member_count, open_ticket_count`).
    SOURCE: OpenAPI `TicketSpaceOut`; `src/api/endpoints/tickets.ts: TicketSpace`.
11. **`TicketSpaceMember` (`SpaceMemberOut`) fields are `space_id, member_sub,
    role (owner|editor|viewer), created_at, updated_at`.** VERDICT: Corrected
    (draft had `user_id, username, display_name, avatar_url, joined_at`, and role
    enum `owner|agent|member`). SOURCE: OpenAPI `SpaceMemberOut`;
    `src/api/endpoints/tickets.ts: TicketSpaceMember`, `SpaceRole`.
12. **`Ticket` (`SpaceTicketOut`) fields are `ticket_id, subject, owner_sub,
    status, assigned_admin_sub?, assigned_by?, assigned_at?, assigned_to_sub?,
    space_id?, created_at, updated_at, version, messages[], activity[]`.**
    VERDICT: Corrected (draft had `id, number, priority, created_by, assignee_id,
    message_count, last_message_at` — none exist). SOURCE: OpenAPI `SpaceTicketOut`;
    `src/api/endpoints/tickets.ts: Ticket`.
13. **Ticket `status` enum is `open|in_progress|waiting_on_user|done`; writable
    form adds `reopened`.** VERDICT: Corrected (draft `open|pending|closed`).
    SOURCE: OpenAPI `SpaceTicketStatusReq`/`TicketStatusReq` enum;
    `src/api/endpoints/tickets.ts: TicketStatus`, `TicketStatusWritable`.
14. **`TicketMessage` (`SpaceTicketMessage`) fields are `message_id, sender_sub,
    sender_role, body, created_at, email_alert_queued_for[]`; there is no
    `author_type`, `author_id`, `edited_at`, or `attachments`.** VERDICT:
    Corrected. SOURCE: OpenAPI `SpaceTicketMessage`;
    `src/api/endpoints/tickets.ts: TicketMessage`.
15. **No `TicketAttachment` type exists on this surface.** VERDICT: Corrected
    (draft defined and embedded it). SOURCE: absence of any attachment field in
    `SpaceTicketMessage` / `src/api/endpoints/tickets.ts: TicketMessage`.
16. **A `TicketActivity` (`SpaceTicketActivity`) embedded array exists on the
    ticket (`type, actor_sub, assignee_sub?, status?, created_at`).** VERDICT:
    Corrected (draft omitted it entirely). SOURCE: OpenAPI `SpaceTicketOut.activity`
    → `SpaceTicketActivity`; `src/api/endpoints/tickets.ts: TicketActivity`.
17. **CSRF: `X-CSRF-Token` header is read from the `ui_csrf` cookie and sent on
    every request (including GETs).** VERDICT: Verified. SOURCE:
    `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", ...)`).
18. **401 handling: a single `POST /ui/session/refresh` then one retry of the
    original request; persistent 401 logs out.** VERDICT: Verified (refresh only
    when already authenticated — an unauthenticated 401 propagates). SOURCE:
    `src/api/client.ts` (`refreshSession`, `refreshPromise`, retry block).
19. **Auth transport also sends `Authorization: Bearer <accessToken>` and an
    optional `X-IMPERSONATION-TOKEN`, in addition to session cookies.** VERDICT:
    Verified — clarifies the draft's cookie-only description (the Android equivalent
    is owned by AND-027). SOURCE: `src/api/client.ts` (auth-token / impersonation
    header blocks); OpenAPI `params=...,X-IMPERSONATION-TOKEN,...`.
20. **Error shapes: `400/403/404/409` → `ErrorEnvelope` `{error:{code,message,
    details?}}`; `422` → `HTTPValidationError` `{detail:[{loc,msg,type}]}`.**
    VERDICT: Corrected (draft described a single FastAPI `detail` envelope for
    all). SOURCE: OpenAPI `resp=...400:ErrorEnvelope;...422:HTTPValidationError`,
    schemas `ErrorEnvelope`/`ErrorDetail`; web client `normalizeErrorDetail`
    (`src/api/client.ts`) is lenient toward `detail`.
21. **All in-scope endpoints are GET and carry a `user_sub` query/auth param plus
    session headers; they are read-only/idempotent.** VERDICT: Verified. SOURCE:
    OpenAPI `params=...,user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN`.
22. **Stack/module/Hilt-DI choices (Kotlin 2.0.21, Retrofit 2.11, OkHttp 4.12,
    Moshi 1.15 + KSP, Coroutines).** VERDICT: Unverified-assumption (not derivable
    from backend/frontend sources; inherited from AND-027/project conventions).
    SOURCE: project convention; Retrofit relative-`@GET`-path behavior is a
    framework ref (https://square.github.io/retrofit/2.x/retrofit/retrofit2/http/GET.html).
23. **Dev host `http://18.222.237.167:8000`, ~20s timeouts, bounded backoff
    retry, `ApiResult` call adapter.** VERDICT: Unverified-assumption (AND-027 /
    network-config owned; not in these sources). SOURCE: stated as inherited from
    AND-027.

### Corrections made

- Endpoint base path corrected from `/ui/ticket-spaces` to `/ticket-spaces`
  (no `/ui` prefix) across §3/§4/§5/§10/§14 (#1).
- Removed the non-existent `listMembers` and `listMessages` interface functions
  and the `TicketSpaceMemberPage`/`TicketMessagePage` types; members and messages
  are embedded in the space/ticket objects (#3, #6).
- Replaced bare-object returns with named envelopes
  (`TicketSpaceEnvelope`/`SpaceTicketEnvelope`) and replaced `*Page` types
  (with `total`) with `{items, next_cursor}` list envelopes (#2, #5, #7, #8).
- Rewrote every DTO's fields and `@Json` wire names to the real contract:
  `TicketSpace`, `TicketSpaceMember`, `Ticket`, `TicketMessage`; added
  `TicketActivity`; deleted `TicketAttachment` (#10–#16).
- Corrected timestamps from ISO-8601 `String` to epoch-second `Long` (#9).
- Corrected enums: ticket status `open|in_progress|waiting_on_user|done(+reopened)`,
  member role `owner|editor|viewer`, space `visibility private|shared`; removed
  the fictitious `author_type` (#13, #11, #14).
- Added the `assignee_sub` query param to list-tickets (#4).
- Corrected the error-shape description to the dual `ErrorEnvelope`/`detail`
  model (#20) and updated §5/§7/§11.
- Corrected the PII inventory in §8 (no usernames/display names/avatars; the
  PII surface is `*_sub` IDs + free-text subject/body) (#11, #14).

### Open assumptions

- **OA-1 (R5):** OpenAPI documents `{error:{code,message}}` for non-validation
  errors, but the web client (`src/api/client.ts`) reads `body.detail`. The exact
  runtime body of the dev host is not directly inspectable from these static
  sources; capture a live error fixture to pin the Android mapper. Why
  unverifiable: requires hitting the live host.
- **OA-2 (#22/#23):** Library versions, base-URL/timeouts/retry policy, the
  `ApiResult` adapter, cookie jar, and refresh interceptor are AND-027/project
  infrastructure, not present in the backend/frontend reference; taken as given.
  Why unverifiable: out of scope of the provided sources.
- **OA-3:** Whether list-ticket responses populate the embedded `messages`/
  `activity` arrays or return them empty (both are schema-`required` arrays) is
  not specified by the schema. Treat as present-but-possibly-empty; confirm
  against a live list fixture. Why unverifiable: schema marks them required but
  does not constrain population in list vs. detail projections.

## 17. Test Plan

Acceptance bar: "Ticket payloads map (tested)." Cases below trace to the §14
Acceptance Criteria (AC-1..AC-7). IDs are stable. "Test target" picks the
cheapest sufficient environment; none of this ticket's logic is hardware
dependent (pure JSON/HTTP), so JVM/Robolectric or the headless emulator suffice
and no physical-device case is required.

**TC-AND-371-01** — Type: unit (JVM, `core-model`). Target: JVM unit/Robolectric
(local, no device). Preconditions: production Moshi instance; fixture
`space_envelope_full.json` (a `{space}` envelope with a fully populated
`TicketSpace` incl. multiple `members`). Steps: deserialize into
`TicketSpaceEnvelope`; assert `space_id/owner_sub/name/visibility`, epoch `Long`
`created_at/updated_at`, and each embedded `TicketSpaceMember`
(`member_sub/role/...`); re-serialize and JSON-tree compare. Expected: every
field maps (snake→camel), members nested correctly, round-trip equal. Traces: AC-2, AC-3.

**TC-AND-371-02** — Type: unit (JVM, `core-model`). Target: JVM unit. Preconditions:
fixture `ticket_envelope_full.json` (a `{ticket}` envelope with embedded
`messages[]` and `activity[]`). Steps: deserialize into `SpaceTicketEnvelope`;
assert all `Ticket` fields incl. nullable `assigned_*`/`space_id`, `version`,
epoch timestamps, and nested `TicketMessage`(`message_id/sender_sub/sender_role/
body/email_alert_queued_for`) + `TicketActivity`; round-trip compare. Expected:
exact mapping and lossless round-trip. Traces: AC-2, AC-3.

**TC-AND-371-03** — Type: unit (JVM, `core-model`). Target: JVM unit. Preconditions:
fixtures `space_list.json` and `ticket_list.json` (each `{items, next_cursor}`,
one with `next_cursor` present, one `null`). Steps: deserialize into
`TicketSpaceListEnvelope` / `SpaceTicketListEnvelope`. Expected: `items` parse,
`nextCursor` maps to the value or `null`; no `total` field is required or read.
Traces: AC-2, AC-3.

**TC-AND-371-04** — Type: unit (JVM, `core-model`). Target: JVM unit. Preconditions:
fixtures with minimal required-only objects, all-null optionals
(`assigned_admin_sub/assigned_by/assigned_at/assigned_to_sub/space_id`,
`next_cursor`), and empty arrays (`items/members/messages/activity/
email_alert_queued_for`). Steps: deserialize each. Expected: no exception;
optionals are null, arrays are empty (defaulted). Traces: AC-4.

**TC-AND-371-05** — Type: unit (JVM, `core-model`). Target: JVM unit. Preconditions:
fixtures carrying **unknown enum values** — `status:"escalated"`,
`role:"auditor"`, `visibility:"team"`, `sender_role:"bot"`. Steps: deserialize.
Expected: no `JsonDataException`; the raw string is retained verbatim
(forward-compatible String modeling). Traces: AC-4.

**TC-AND-371-06** — Type: unit (JVM, `core-model`). Target: JVM unit. Preconditions:
fixture with a numeric `created_at` (e.g. `1749060660`). Steps: deserialize a
`Ticket`/`TicketSpace`. Expected: `createdAt` is a `Long` epoch value (proves the
ISO-8601→`Long` correction; a String-typed field would have thrown). Traces: AC-2, AC-3.

**TC-AND-371-07** — Type: unit (JVM, `core-model`). Target: JVM unit. Preconditions:
malformed body (truncated JSON) and a body missing a required field
(`version` absent on a ticket). Steps: attempt deserialize via the production
Moshi/converter. Expected: a typed parse failure (`JsonDataException`/
`ApiResult.Failure(Parse)`), not a crash. Traces: AC-5.

**TC-AND-371-08** — Type: contract/MockWebServer (`core-network`). Target: JVM
unit (MockWebServer, no device). Preconditions: `TicketsApi` built on the test
Retrofit pointed at MockWebServer; 200 fixtures enqueued. Steps: call
`listSpaces(limit=20, cursor="c1")`, `getSpace("spc_1")`,
`listSpaceTickets("spc_1", status="open", assigneeSub="usr_2", limit=10,
cursor="c2")`, `getSpaceTicket("spc_1","tkt_9")`. For each, read the recorded
request. Expected request paths/queries (no `/ui` prefix):
`GET /ticket-spaces?limit=20&cursor=c1`, `GET /ticket-spaces/spc_1`,
`GET /ticket-spaces/spc_1/tickets?status=open&assignee_sub=usr_2&limit=10&cursor=c2`,
`GET /ticket-spaces/spc_1/tickets/tkt_9`; each response deserializes to the
correct envelope. Traces: AC-1, AC-2.

**TC-AND-371-09** — Type: contract/MockWebServer (`core-network`). Target: JVM
unit. Preconditions: MockWebServer enqueues a `422` `HTTPValidationError`
(`{detail:[{loc,msg,type}]}`). Steps: call `listSpaceTickets` with a bad
`status`. Expected: surfaces as `ApiResult.Failure` with the validation message;
no crash. Traces: AC-1, AC-5.

**TC-AND-371-10** — Type: contract/MockWebServer (`core-network`). Target: JVM
unit. Preconditions: MockWebServer enqueues a `404` `ErrorEnvelope`
(`{error:{code:"not_found",message:"..."}}`) for an unknown space. Steps: call
`getSpace("missing")`. Expected: `ApiResult.Failure` mapped from
`error.message`/`error.code`, not from `detail`; confirms the dual error-shape
mapping. Traces: AC-1, AC-5.

**TC-AND-371-11** — Type: contract/MockWebServer (`core-network`). Target: JVM
unit. Preconditions: MockWebServer simulates the flaky/offline dev host —
enqueue a connection drop / socket timeout, then a 200. Steps: call `getSpace`;
allow the shared bounded-retry to fire. Expected: a transient failure either
retries to success (if within the shared retry budget) or surfaces as a typed
network failure — never a raw uncaught `IOException`. (Retry/timeout policy is
AND-027-owned; this asserts the GET integrates with it.) Traces: AC-1, AC-6.

**TC-AND-371-12** — Type: contract/MockWebServer (`core-network`). Target: JVM
unit. Preconditions: `TicketsApi` resolved from the Hilt graph (or a Hilt test
component) using the AND-027 authenticated Retrofit; MockWebServer behind it.
Steps: issue any GET; inspect recorded headers. Expected: `TicketsApi` is
injectable; the request carries `X-CSRF-Token` (from `ui_csrf`) and session/auth
headers added by the shared client; AND-371 added no new interceptor. Traces:
AC-6, AC-7.

**TC-AND-371-13** — Type: integration (instrumented, optional/CI-gated). Target:
headless emulator AVD `test35` (API 35). Preconditions: app module wired with the
real Hilt network graph against MockWebServer (or a recorded dev-host capture).
Steps: resolve `TicketsApi` via DI on-device and perform `listSpaces` +
`getSpaceTicket`. Expected: DTOs deserialize identically to the JVM tests on a
real ART runtime (catches Moshi/KSP codegen or R8 issues). No UI assertions.
Emulator is sufficient — behavior is ABI/API-independent, so the physical device
is **not** required. Traces: AC-2, AC-3, AC-6.

**TC-AND-371-14** — Type: unit (JVM, static/architecture). Target: JVM unit.
Preconditions: compiled `core-model`/`core-network` modules. Steps: assert (e.g.
via a Konsist/reflection test) that the `tickets` packages contain no UI,
ViewModel, repository, Room, or DataStore types, and that `core-network` does not
depend on `feature-*`. Expected: scope guard passes. Traces: AC-7.

### Coverage matrix

| AC (§14) | Covered by |
| --- | --- |
| AC-1 (interface paths/verbs/params) | TC-08, TC-09, TC-10, TC-11 |
| AC-2 (DTOs + wire names + Long timestamps) | TC-01, TC-02, TC-03, TC-06, TC-08, TC-13 |
| AC-3 (fixtures deserialize exactly + round-trip) | TC-01, TC-02, TC-03, TC-06, TC-13 |
| AC-4 (minimal/null/empty/unknown-enum parse) | TC-04, TC-05 |
| AC-5 (malformed/error → typed failure) | TC-07, TC-09, TC-10 |
| AC-6 (Hilt-injectable, reuses AND-027 client) | TC-11, TC-12, TC-13 |
| AC-7 (no UI/VM/repo/persistence) | TC-12, TC-14 |

> Note on test targets: every case runs on JVM/Robolectric or the headless
> emulator (`test35`). No case in this ticket needs the physical Samsung Galaxy
> A15 — there is no camera/biometric/FCM/WebRTC/Telecom/streaming or
> ABI-sensitive behavior; the data layer is pure JSON-over-HTTP. TC-13 is the
> only on-device case and the emulator is the appropriate target.
