---
id: AND-371
title: Tickets API
milestone: M8
epic: E48
priority: P1
size: M
status: draft
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
the ticket-spaces surface present in the web reference:
- List ticket spaces the current user can access.
- Get a single ticket space (including its members).
- List members of a space.
- List tickets within a space (paginated).
- Get a single ticket.
- List messages on a ticket (paginated).

FR-2. Provide Moshi DTOs that **exactly** model the JSON for: `TicketSpace`,
`TicketSpaceMember`, `Ticket`, `TicketMessage`, and the list/paged envelopes
returned for each collection.

FR-3. All wire field names must match the backend (snake_case) via
`@Json(name=...)`; Kotlin properties use idiomatic camelCase.

FR-4. Nullability must match the contract: fields the backend may omit are
nullable Kotlin types with sensible defaults so deserialization never throws on
absent-but-optional fields; required fields are non-null.

FR-5. Enum-like string fields (`status`, member `role`, message `author_type`)
are modeled as `String` constants in a companion object (not Kotlin `enum class`)
so an unknown server value never fails deserialization — forward-compatible by
design.

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

    @GET("ui/ticket-spaces")
    suspend fun listSpaces(
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
    ): TicketSpacePage

    @GET("ui/ticket-spaces/{spaceId}")
    suspend fun getSpace(@Path("spaceId") spaceId: String): TicketSpace

    @GET("ui/ticket-spaces/{spaceId}/members")
    suspend fun listMembers(
        @Path("spaceId") spaceId: String,
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
    ): TicketSpaceMemberPage

    @GET("ui/ticket-spaces/{spaceId}/tickets")
    suspend fun listTickets(
        @Path("spaceId") spaceId: String,
        @Query("status") status: String? = null,
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
    ): TicketPage

    @GET("ui/ticket-spaces/{spaceId}/tickets/{ticketId}")
    suspend fun getTicket(
        @Path("spaceId") spaceId: String,
        @Path("ticketId") ticketId: String,
    ): Ticket

    @GET("ui/ticket-spaces/{spaceId}/tickets/{ticketId}/messages")
    suspend fun listMessages(
        @Path("spaceId") spaceId: String,
        @Path("ticketId") ticketId: String,
        @Query("limit") limit: Int? = null,
        @Query("cursor") cursor: String? = null,
    ): TicketMessagePage
}
```

> Exact paths/verbs/query params must be reconciled against
> `frontend/src/api/endpoints/tickets.ts` and `/openapi.json` during
> implementation; the shapes above reflect the documented surface. Any deviation
> found in the reference overrides this draft and must be captured in the
> committed sample JSON fixtures.

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

All endpoints are HTTP GET, idempotent, and eligible for the bounded backoff
retry on transient failures already implemented in the shared client. Base URL is
the configured dev host. Cookies + `X-CSRF-Token` are attached transparently.

**`GET /ui/ticket-spaces` → `200 TicketSpacePage`**

```json
{
  "items": [
    {
      "id": "spc_01H...",
      "name": "Support — Tier 1",
      "slug": "support-tier-1",
      "description": "Customer support intake",
      "status": "active",
      "member_count": 12,
      "open_ticket_count": 4,
      "created_at": "2026-04-02T15:01:09Z",
      "updated_at": "2026-05-30T09:22:41Z"
    }
  ],
  "next_cursor": "eyJrIjoi...",
  "total": 3
}
```

**`GET /ui/ticket-spaces/{spaceId}` → `200 TicketSpace`** — same object shape as a
list item, optionally including an embedded `members` array.

**`GET /ui/ticket-spaces/{spaceId}/members` → `200 TicketSpaceMemberPage`**

```json
{
  "items": [
    {
      "user_id": "usr_01HZ...",
      "username": "ada",
      "display_name": "Ada L.",
      "avatar_url": "https://.../a.png",
      "role": "owner",
      "joined_at": "2026-04-02T15:01:09Z"
    }
  ],
  "next_cursor": null
}
```

**`GET /ui/ticket-spaces/{spaceId}/tickets` → `200 TicketPage`**

```json
{
  "items": [
    {
      "id": "tkt_01J2...",
      "space_id": "spc_01HZ...",
      "number": 142,
      "subject": "Login loop on Android",
      "status": "open",
      "priority": "high",
      "created_by": "usr_01HZ...",
      "assignee_id": null,
      "message_count": 6,
      "last_message_at": "2026-06-04T18:11:00Z",
      "created_at": "2026-06-01T10:00:00Z",
      "updated_at": "2026-06-04T18:11:00Z"
    }
  ],
  "next_cursor": "eyJrIjoi...",
  "total": 142
}
```

**`GET /ui/ticket-spaces/{spaceId}/tickets/{ticketId}` → `200 Ticket`** — single
ticket object as above.

**`GET /ui/ticket-spaces/{spaceId}/tickets/{ticketId}/messages` → `200 TicketMessagePage`**

```json
{
  "items": [
    {
      "id": "msg_01J3...",
      "ticket_id": "tkt_01J2...",
      "author_id": "usr_01HZ...",
      "author_type": "member",
      "body": "Tried clearing cookies, still loops.",
      "attachments": [],
      "created_at": "2026-06-04T18:11:00Z",
      "edited_at": null
    }
  ],
  "next_cursor": null
}
```

**Error responses** follow the standard FastAPI `detail` envelope mapped by the
shared client: `401` triggers the one-shot session refresh + retry; `403`/`404`
surface as typed `ApiResult.Failure` with the mapped message; `422` yields the
validation-array form `[{ "msg": "...", "loc": [...] }]`.

## 6. Data & State Management

DTOs (Moshi `@JsonClass(generateAdapter = true)`), in
`com.testlogon.android.core.model.tickets`:

```kotlin
@JsonClass(generateAdapter = true)
data class TicketSpace(
    val id: String,
    val name: String,
    val slug: String? = null,
    val description: String? = null,
    val status: String = STATUS_ACTIVE,
    @Json(name = "member_count") val memberCount: Int = 0,
    @Json(name = "open_ticket_count") val openTicketCount: Int = 0,
    val members: List<TicketSpaceMember>? = null,
    @Json(name = "created_at") val createdAt: String,
    @Json(name = "updated_at") val updatedAt: String? = null,
) { companion object { const val STATUS_ACTIVE = "active"; const val STATUS_ARCHIVED = "archived" } }

@JsonClass(generateAdapter = true)
data class TicketSpaceMember(
    @Json(name = "user_id") val userId: String,
    val username: String? = null,
    @Json(name = "display_name") val displayName: String? = null,
    @Json(name = "avatar_url") val avatarUrl: String? = null,
    val role: String = ROLE_MEMBER,
    @Json(name = "joined_at") val joinedAt: String? = null,
) { companion object { const val ROLE_OWNER = "owner"; const val ROLE_AGENT = "agent"; const val ROLE_MEMBER = "member" } }

@JsonClass(generateAdapter = true)
data class Ticket(
    val id: String,
    @Json(name = "space_id") val spaceId: String,
    val number: Int? = null,
    val subject: String,
    val status: String = STATUS_OPEN,
    val priority: String? = null,
    @Json(name = "created_by") val createdBy: String? = null,
    @Json(name = "assignee_id") val assigneeId: String? = null,
    @Json(name = "message_count") val messageCount: Int = 0,
    @Json(name = "last_message_at") val lastMessageAt: String? = null,
    @Json(name = "created_at") val createdAt: String,
    @Json(name = "updated_at") val updatedAt: String? = null,
) { companion object { const val STATUS_OPEN = "open"; const val STATUS_PENDING = "pending"; const val STATUS_CLOSED = "closed" } }

@JsonClass(generateAdapter = true)
data class TicketMessage(
    val id: String,
    @Json(name = "ticket_id") val ticketId: String,
    @Json(name = "author_id") val authorId: String? = null,
    @Json(name = "author_type") val authorType: String = AUTHOR_MEMBER,
    val body: String = "",
    val attachments: List<TicketAttachment> = emptyList(),
    @Json(name = "created_at") val createdAt: String,
    @Json(name = "edited_at") val editedAt: String? = null,
) { companion object { const val AUTHOR_MEMBER = "member"; const val AUTHOR_AGENT = "agent"; const val AUTHOR_SYSTEM = "system" } }

@JsonClass(generateAdapter = true)
data class TicketAttachment(
    val id: String,
    val url: String,
    @Json(name = "content_type") val contentType: String? = null,
    val name: String? = null,
    @Json(name = "size_bytes") val sizeBytes: Long? = null,
)
```

Paged envelopes (cursor-based, matching the existing list pattern; `total`
nullable since not all collections return it):

```kotlin
@JsonClass(generateAdapter = true) data class TicketSpacePage(
    val items: List<TicketSpace> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
    val total: Int? = null,
)
@JsonClass(generateAdapter = true) data class TicketSpaceMemberPage(
    val items: List<TicketSpaceMember> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)
@JsonClass(generateAdapter = true) data class TicketPage(
    val items: List<Ticket> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
    val total: Int? = null,
)
@JsonClass(generateAdapter = true) data class TicketMessagePage(
    val items: List<TicketMessage> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)
```

Moshi codegen (KSP) generates the adapters; no hand-written adapters are
required unless `/openapi.json` reveals a polymorphic field, in which case a
sealed-type adapter is added. **No persistent state** (Room/DataStore) is
created by this ticket; cursors are returned to callers verbatim for downstream
Paging 3 integration in AND-372/AND-375. Timestamps stay `String` (ISO-8601) at
this layer; domain parsing to `Instant` is a ViewModel/repository concern.

## 7. Error Handling & Resilience

This layer does not implement its own error policy — it inherits the
`core-network` behavior established by AND-027:
- **Timeouts:** ~20s call/read timeout for the unreliable dev host.
- **Retry:** bounded exponential backoff for these idempotent GETs only.
- **401:** single `POST /ui/session/refresh` then one retry; persistent failure
  surfaces as `ApiResult.Failure(Unauthorized)`.
- **`detail` mapping:** string / `[{msg}]` / `{code,...}` collapsed to a typed
  error message by the shared mapper.
- **Deserialization robustness (this ticket's responsibility):** optional fields
  are nullable with defaults and string-typed enums prevent `JsonDataException`
  on unknown/absent values, so a partially-populated or forward-evolved payload
  still parses. A genuinely malformed body becomes `ApiResult.Failure(Parse)`
  via the shared converter — verified by a malformed-fixture test.

## 8. Security & Privacy

- Reuses the authenticated client: session cookies + `X-CSRF-Token` are attached
  by existing interceptors; AND-371 adds no auth code and stores no credentials.
- Although CSRF tokens are not required for GETs, the header is sent uniformly by
  the shared client — no change here.
- DTOs carry PII (usernames, display names, avatar URLs, member identities,
  message bodies). They must **not** be logged in plaintext; the network logging
  interceptor stays at headers-only / redacted-body level in release builds.
- Transport is plaintext HTTP on the dev host only; production base URL and
  cleartext policy are owned by the network/build config tickets, not this one.
- No new fields are persisted, so there is no at-rest data surface introduced.

## 9. Accessibility & i18n

N/A for the runtime UI — this is a non-UI data layer. Constraints it must honor
for downstream A11y/i18n: DTOs preserve server-provided human-readable strings
(`subject`, `body`, `display_name`) verbatim without truncation or locale
transformation, and timestamps remain raw ISO-8601 strings so the
presentation layer (AND-372) can format them per device locale and expose
content descriptions. No user-facing strings are introduced here.

## 10. Telemetry & Logging

- Reuses the shared OkHttp logging interceptor (debug = `BODY`, release =
  `NONE`/redacted). No bespoke logging is added.
- Per-endpoint latency/error counts are emitted by the shared metrics
  interceptor (if present in the AND-027 graph) keyed by route template (e.g.
  `ui/ticket-spaces/{spaceId}/tickets`) — no new instrumentation in this ticket.
- No analytics events are defined here; user-facing ticket events belong to the
  UI tickets (AND-372/AND-373).

## 11. Testing Strategy

The acceptance bar is "**ticket payloads map (tested)**." Tests live in
`core-model` (pure Moshi) and `core-network` (MockWebServer), using `core-testing`
helpers.

**A. DTO serialization (JVM unit, `core-model`):** For each of `TicketSpace`,
`TicketSpaceMember`, `Ticket`, `TicketMessage`, and all four `*Page` envelopes:
1. Load a captured JSON fixture (committed under
   `core-model/src/test/resources/tickets/*.json`, derived from the web
   reference / `/openapi.json`).
2. Deserialize with the production Moshi instance; assert every field maps,
   including snake_case → camelCase and nested `members`/`attachments`.
3. Round-trip re-serialize and assert structural equality (JSON-tree compare,
   not raw string).

**B. Optional/edge fixtures:** minimal payloads (only required fields present),
`null` for every optional field, empty `items`/`attachments` arrays, and an
**unknown enum value** for `status`/`role`/`author_type` — assert no exception
and the raw value is retained.

**C. Endpoint contract (`core-network`, MockWebServer):** Stand up
`TicketsApi` against MockWebServer. For each function assert the **request**
method, path (with substituted `{spaceId}`/`{ticketId}`), and query params, and
that a `200` fixture deserializes into the expected DTO. Include a `422`
validation-array fixture and a malformed-body fixture to confirm failure
mapping. The 401-refresh path is covered by AND-027's suite and not re-tested
here.

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

- **R1 — Field-shape drift:** the exact paths, pagination style (cursor vs
  offset/`total`), and field names must be confirmed against
  `frontend/src/api/endpoints/tickets.ts` and `/openapi.json`. The JSON in §5/§6
  is the documented best estimate; **fixtures captured from the live dev host are
  authoritative** and override this draft.
- **R2 — Embedded vs. separate members:** unclear whether `GET space` embeds
  `members` or requires the `/members` call. Modeled as optional `members` plus a
  dedicated endpoint to cover both; confirm and prune.
- **R3 — Pagination contract:** does the backend use `next_cursor` or
  `limit/offset` + `total`? Envelopes include both `next_cursor` and nullable
  `total` defensively; align with the platform-wide list pattern before freezing.
- **R4 — Attachments shape:** `TicketAttachment` is inferred; verify against the
  message schema; may be `[]`-only in the dev data.
- **Open question:** Does `author_type` distinguish `agent` vs `member` vs
  `system`, and is `created_by`/`author_id` a user id or a denormalized object?
  Resolve from `/openapi.json`.

## 14. Acceptance Criteria

1. `TicketsApi` exists in `core-network` with suspend GET functions for: list
   spaces, get space, list members, list tickets, get ticket, list messages —
   paths/verbs/query params matching `tickets.ts` / `/openapi.json`
   (MockWebServer-verified per §11.C).
2. Moshi DTOs `TicketSpace`, `TicketSpaceMember`, `Ticket`, `TicketMessage`,
   `TicketAttachment`, and the four `*Page` envelopes exist in `core-model` with
   `@JsonClass(generateAdapter = true)` and correct `@Json` wire names.
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
