---
id: AND-161
title: Helpdesk queue
milestone: M3
epic: E22
priority: P2
size: M
depends_on: [AND-120]
blocks: [AND-162, AND-165]
status: reviewed
reviewed_on: 2026-06-06
---

# AND-161 — Helpdesk queue

## 1. Overview & Goal

This ticket delivers the **agent-facing helpdesk queue** for the native Android port: a read-only, paginated list of inbound helpdesk conversations that authenticated **agent-role** users can browse to triage support requests. The screen consumes `GET /messaging/helpdesk/queue` and renders each queue entry in a scrollable list with loading, empty, error, and offline/stale states, plus pull-to-refresh and manual refresh.

> **REVIEW CORRECTION (verified against OpenAPI + frontend).** Three foundational assumptions in the original draft were wrong and are corrected throughout this spec:
> 1. **No pagination.** `GET /messaging/helpdesk/queue` returns a **bare JSON array of `ConversationOut`** (200 schema `type: array, items: ConversationOut`), not a paged envelope. There is **no** `items`/`next_cursor`/`has_more` wrapper and **no cursor**. The only size control is an optional `limit` query param (default 50, max 200). Paging 3 cursor paging (FR-3, original §4/§5) is therefore **not applicable**; the queue is a single bounded fetch. Sections below are amended to use a plain list (still rendered in a `LazyColumn`) with `limit` rather than a `PagingSource`.
> 2. **`group_id` is REQUIRED.** The endpoint requires a `group_id` query param (`required: true`, `maxLength 128`); the web client passes a configured helpdesk group id (`VITE_HELPDESK_GROUP_ID`, default `"e2e-helpdesk"`). The original spec omitted this entirely.
> 3. **Role is inferred from 403, not from `/ui/me`.** `/ui/me` (`MeResp`) returns only `{ user_sub, session_id, ip }` — **no roles/agent flag**. The web app does **not** gate client-side; it issues the queue request and treats a 403 as "not an agent" (`silent403`, `isAgent = !queueError`). The original "no API call for non-agents, gated by `/ui/me` role store" model is unsupported by the contract — see §2 (role model), §3 FR-2, §8, and §16.
>
> The fields rendered per row map to `ConversationOut`: `title` (with participant-name fallback), `last_message_preview`, `unread_count`, `routing_state` badge (`awaiting_agent`/`assigned`/`paused_no_agents_online`), `active_agent_user_id` (claim/assignee), and `last_message_at` (epoch-seconds integer → relative time). There is no `helpdesk_id`, `subject`, `requester`, or `assignee` object on the wire.

The scope is deliberately bounded to **reading and rendering the queue**. Claiming a conversation, opening a thread, and replying are owned by the downstream ticket **AND-162 (Helpdesk claim + reply)**; this ticket only exposes the per-row navigation hook and assignee/claim metadata that AND-162 consumes. The queue must also be **role-gated**: non-agent users must never see the queue (no API call, no entry point), surfaced as a "not authorized" state rather than a crash or an empty list.

Success is behavioral and matches the source acceptance criterion: **the queue renders for an agent role** — given an authenticated user who is a helpdesk agent for the configured group, the queue request returns the group's conversations and the screen displays them; given a non-agent user, the request returns **403** and the screen shows an unauthorized state (the 403 is the role signal — see REVIEW CORRECTION above).

## 2. Context & References

- **Module:** `feature-helpdesk` (new feature module) depending on `core-network`, `core-model`, `core-ui`, `core-data`, `core-testing`. Package root `com.testlogon.android.feature.helpdesk`. Wired into the authenticated nav graph (AND-024) and root `NavHost` (AND-022).
- **Branch / repo:** `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- **Depends on AND-120 (Messaging API + DTOs):** provides `MessagingApi`, the Retrofit/Moshi wiring, shared messaging DTOs (`ConversationDto`, `MessageDto`, pagination envelope) and the `core-network` `ApiResult<T>` plumbing. The helpdesk queue endpoint is a sibling of the messaging conversation endpoints and reuses the same conversation payload shapes where possible. **AND-161 must not duplicate** the messaging DTOs; it extends/reuses them and adds only helpdesk-specific fields (claim/assignee/SLA).
- **Blocks AND-162 (Helpdesk claim + reply):** AND-162 calls `POST /messaging/helpdesk/conversations/{conversation_id}/claim` (corrected path — the original `/helpdesk/conversations/{id}/claim` was missing the `/messaging` prefix; verified against OpenAPI + `claimHelpdeskConversation`). The claim takes **no request body** (web posts `{}`) and returns `HelpdeskClaimOut { ok, conversation_id, state, assigned_agent_user_id, assignment_version, idempotent }`. AND-162 depends on this ticket's row model (`conversationId`, `claimState`, `activeAgentUserId`) and navigation hook — note the row key is `conversation_id`, **not** a `helpdeskId` (no such field exists).
- **Blocks AND-165 (Groups/helpdesk tests):** the consolidated repo + UI test ticket exercises this queue.
- **Cross-cutting reuse:** `core-network` cookie jar (AND-011), CSRF interceptor (AND-012), 401 refresh authenticator (AND-013), error/detail mapping (AND-015), retry/backoff for idempotent GETs (AND-016), `ApiResult` (AND-018); `core-ui` state composables (AND-021); auth state / `/ui/me` role store (AND-029); offline/stale reads (AND-045); paging conventions (AND-122).
- **Auth model (corrected):** the web client sends **all three** of: `Authorization: Bearer <accessToken>` (from the auth store), session cookies (`credentials: include`), and `X-CSRF-Token` echoed from the `ui_csrf` cookie — and it sets `X-CSRF-Token` on **every** request, including GETs (`src/api/client.ts`). A single refresh-on-401 (`POST /ui/session/refresh`) then one retry; a persistent 401 logs out with `session_expired`. The Android stack must mirror this (Bearer + cookie jar + CSRF on all requests), not cookie-only.
- **Role model (corrected):** there is **no agent-role field** to read. `/ui/me` returns only `{ user_sub, session_id, ip }` (`MeResp`). Agent-ness is determined **by calling the queue and observing the response**: 200 ⇒ agent for that group; **403 ⇒ not an agent** (`getHelpdeskQueue` uses `silent403: true`; `HelpdeskPage.tsx` computes `isAgent = !queueError`). AND-029's role store cannot supply this; do **not** pre-gate the network call on a `/ui/me` role.
- **Helpdesk group id (corrected):** `group_id` is a **required** query param. The web app reads it from `VITE_HELPDESK_GROUP_ID` (default `"e2e-helpdesk"`). Android must source an equivalent configured group id (build config / remote config / DataStore) — see OQ-5.
- **Web reference:** `src/api/endpoints/messaging.ts` (`getHelpdeskQueue`, `claimHelpdeskConversation`, `startHelpdeskConversation`), `src/api/types.ts` (`Conversation`/`ConversationOut`, `HelpdeskClaimOut`, `MeResp`), `src/pages/helpdesk/HelpdeskPage.tsx` (screen behavior), and `src/api/client.ts` (auth/CSRF/transport) are the canonical contract; shapes confirmed against `reference/openapi.pretty.json` in this review. Dev backend (`http://18.222.237.167:8000`) is PLAINTEXT and unreliable — design for ~20s timeouts and stale UI.
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11/OkHttp 4.12/Moshi 1.15, Room 2.6, DataStore, Paging 3. minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.

## 3. Functional Requirements

FR-1 — **Queue list renders.** The screen loads helpdesk conversations from `GET /messaging/helpdesk/queue?group_id=<configured>` (optionally `&state=<filter>&limit=<n>`) and renders the returned `ConversationOut[]` in a vertically scrolling `LazyColumn`. Each row shows: `title` (or, when absent, a participant-name fallback built from non-self `participants[].display_name`, matching `HelpdeskPage.tsx`), `last_message_preview`, a routing-state badge (`awaiting_agent` → "Waiting", `assigned` → "Assigned", `paused_no_agents_online` → "Paused"), a claim/assignee indicator derived from `active_agent_user_id`, an unread indicator from `unread_count`, and a relative timestamp from `last_message_at` ("3m", "2h", "Yesterday"). *(Corrected: there is no `subject`/`requester`/`status=open|closed` on the wire; status semantics are carried by `routing_state`.)*

FR-2 — **Role gating (by 403, corrected).** There is no readable agent-role field, so the screen **does** issue the queue request for any authenticated user (with `silent403`-equivalent handling). A **200** response means the user is an agent for the group and rows render. A **403** response means the user is not an agent; the screen shows a non-blocking **Not authorized** state and suppresses any error toast. *(Corrected from the original "no network call for non-agents via `/ui/me` role store" — unsupported by the contract.)* The nav entry point may still be shown to all authenticated users, or optionally hidden behind a cached "was-agent" hint; it must not depend on a non-existent `/ui/me` role.

FR-3 — **Bounded fetch (no paging, corrected).** The endpoint returns a **single bounded array** (no cursor/envelope). The client issues one request with `limit` (default 50, max 200) and renders the full result; there is no incremental append. *(Corrected: Paging 3 cursor paging from the original draft is removed — `next_cursor`/`has_more` do not exist.)* If the queue ever exceeds `limit`, raise `limit` (≤200) or track as a backend follow-up (OQ-1); no client-side cursor loop is possible.

FR-4 — **Pull-to-refresh.** Pull-to-refresh re-issues the single queue fetch and replaces the list. *(Corrected: no `PagingSource.invalidate()`; the ViewModel re-runs the suspend fetch and re-emits the list state.)*

FR-5 — **Loading / empty / error / offline states.** First-load shows a loading state (AND-021). An authorized agent with zero queue entries shows an **empty** state ("Queue is clear"). A failed first load shows a full-screen **error** state with Retry. When offline/unreachable with a cached list present, a **stale** banner is shown over last-known content (AND-045).

FR-6 — **Row navigation hook (for AND-162).** Tapping a row invokes `onOpenConversation(conversationId: String)` *(corrected: keyed on `conversation_id`; there is no `helpdesk_id`)*. In AND-161 this navigates to a placeholder/detail route stub; AND-162 replaces the stub with the claim+reply detail (`POST /messaging/helpdesk/conversations/{conversation_id}/claim`). The row model must carry `conversationId`, `claimState`, and `activeAgentUserId` so AND-162 needs no additional fetch to render claim controls.

FR-7 — **Sort/order.** Entries are presented in backend order (server-sorted by priority/age); if the backend does not sort, the client sorts unassigned-first then oldest-first. Sorting is deterministic and unit-tested.

FR-8 — **Manual refresh entry.** A toolbar refresh action triggers the same first-page refresh as pull-to-refresh (for accessibility and emulator use without gestures).

FR-9 — **No write actions.** This ticket performs no claim/reply/close mutations. Any such control belongs to AND-162; rows are read-only beyond the open hook.

## 4. Technical Design

**Module / package layout** (`feature-helpdesk`):

```
com.testlogon.android.feature.helpdesk.data.HelpdeskApi
com.testlogon.android.feature.helpdesk.data.HelpdeskRepository
com.testlogon.android.feature.helpdesk.data.dto.ConversationDto          // reuse AND-120 ConversationOut DTO (do NOT duplicate)
com.testlogon.android.feature.helpdesk.domain.HelpdeskQueueItem
com.testlogon.android.feature.helpdesk.domain.ClaimState
com.testlogon.android.feature.helpdesk.ui.HelpdeskQueueScreen
com.testlogon.android.feature.helpdesk.ui.HelpdeskQueueViewModel
com.testlogon.android.feature.helpdesk.ui.HelpdeskQueueUiState
com.testlogon.android.feature.helpdesk.navigation.HelpdeskGraph
com.testlogon.android.feature.helpdesk.di.HelpdeskModule
```

> *(Corrected: no `HelpdeskQueuePagingSource`, `HelpdeskQueueItemDto`, or `HelpdeskQueuePageDto`. The endpoint returns `ConversationOut[]`, so the wire DTO is the shared AND-120 conversation DTO; the helpdesk-specific work is the DTO→`HelpdeskQueueItem` mapping plus `ClaimState` derivation. No Paging 3.)*

**API surface.** Helpdesk-specific Retrofit interface (kept separate from `MessagingApi` for module boundaries; both share the `core-network` Retrofit instance):

```kotlin
interface HelpdeskApi {
    @GET("messaging/helpdesk/queue")
    suspend fun getQueue(
        @Query("group_id") groupId: String,          // REQUIRED, maxLength 128
        @Query("state") state: String? = null,        // optional routing-state filter
        @Query("limit") limit: Int = 50,              // optional, default 50, max 200
    ): Response<List<ConversationDto>>                 // bare array (ConversationOut[])
}
```

*(Corrected: `group_id` is required; the filter param is `state` (not `status`); there is no `cursor`; the response is `List<ConversationDto>`, not a page envelope. Reuse AND-120's `ConversationDto`/`ConversationOut` mapping — do not introduce a helpdesk-only DTO.)*

**Domain model.**

```kotlin
enum class ClaimState { UNASSIGNED, CLAIMED_BY_ME, CLAIMED_BY_OTHER }

data class HelpdeskQueueItem(
    val conversationId: String,              // ConversationOut.conversation_id (row key)
    val title: String?,                      // ConversationOut.title (fallback: participant names)
    val preview: String?,                    // ConversationOut.last_message_preview
    val routingState: String?,               // ConversationOut.routing_state (awaiting_agent|assigned|paused_no_agents_online)
    val claimState: ClaimState,
    val activeAgentUserId: String?,          // ConversationOut.active_agent_user_id
    val unreadCount: Int,                    // ConversationOut.unread_count (default 0)
    val lastMessageAt: Instant?,             // from ConversationOut.last_message_at (EPOCH SECONDS int)
)
```

*(Corrected field mapping: no `helpdesk_id`/`subject`/`requester`/`assignee` exist. `ConversationOut` carries `title`, `last_message_preview`, `routing_state`, `active_agent_user_id`, `unread_count`, and `last_message_at` as an **epoch-seconds integer** — parse with `Instant.ofEpochSecond(...)`, not ISO-8601.)*

`ClaimState` is derived in the mapper by comparing `active_agent_user_id` to the current user's id (`authState.currentUserId()`, AND-029): null/blank `active_agent_user_id` → `UNASSIGNED`; equals me → `CLAIMED_BY_ME`; else `CLAIMED_BY_OTHER`. *(Corrected: compares `active_agent_user_id`, not a non-existent `assignee_id`.)*

**Repository + Paging.**

```kotlin
class HelpdeskRepository @Inject constructor(
    private val api: HelpdeskApi,
    private val errorMapper: ApiErrorMapper,          // AND-015
    private val authState: AuthStateStore,            // AND-029 (current user id only)
    private val helpdeskGroupId: String,              // configured group id (OQ-5)
) {
    /**
     * Single bounded fetch. Returns:
     *  - Success(list)          when 200 (caller is an agent for the group)
     *  - Error(NotAuthorized)   when 403 (caller is NOT an agent — this is the role signal)
     *  - Error(...)             for 422/5xx/timeout/IO/parse, mapped via AND-015
     * Maps ConversationOut[] -> HelpdeskQueueItem[] with ClaimState derived from
     * active_agent_user_id vs authState.currentUserId().
     */
    suspend fun loadQueue(state: String? = null, limit: Int = 50): ApiResult<List<HelpdeskQueueItem>> { /* ... */ }
}
```

*(Corrected: no `isAgent()` precheck against `/ui/me` — there is no role field; agent-ness is the 200-vs-403 outcome of `loadQueue`. No `Pager`/`PagingSource`/`queuePager`. The repository performs one suspend call and maps the array.)* On HTTP/IO failure `loadQueue` returns a mapped `ApiResult.Error`; a **403** maps specifically to a `NotAuthorized` error so the ViewModel can render the not-authorized chrome. On **401** the shared authenticator (AND-013) has already attempted one refresh+retry, so a persistent 401 maps to a session-expired error surfaced to AND-044's expiry UX. Idempotent GET retry/backoff (AND-016) wraps the call for transient 5xx/timeouts only (never for 401/403/422).

**ViewModel.**

```kotlin
@HiltViewModel
class HelpdeskQueueViewModel @Inject constructor(
    private val repository: HelpdeskRepository,
) : ViewModel() {
    val uiState: StateFlow<HelpdeskQueueUiState>      // single source of screen state
    fun refresh()                                      // re-runs loadQueue (pull + toolbar)
    fun retry()                                        // re-runs loadQueue after error
}

sealed interface HelpdeskQueueUiState {
    data object Loading : HelpdeskQueueUiState
    data object NotAuthorized : HelpdeskQueueUiState                                   // 403 outcome
    data class Ready(                                                                  // 200 outcome
        val items: List<HelpdeskQueueItem>,                                           // empty list => empty state
        val isRefreshing: Boolean,
        val isStale: Boolean,
    ) : HelpdeskQueueUiState
    data class Error(val message: String, val retryable: Boolean) : HelpdeskQueueUiState
}
```

*(Corrected: no `PagingData`/`LazyPagingItems`/`cachedIn`. The ViewModel holds the rendered list inside `Ready`.)* On init (and on `refresh`/`retry`) the ViewModel calls `repository.loadQueue(...)`, emitting `Loading` then mapping the result: `Success([])` → `Ready(items = [])` (empty state), `Success(list)` → `Ready(items = list)`, the `NotAuthorized` error → `NotAuthorized` chrome (no API gate beforehand — the call IS the role check), other errors → `Error(...)`, and offline-with-cache → `Ready(cachedItems, isStale = true)`.

**Composable.**

```kotlin
@Composable
fun HelpdeskQueueScreen(
    onOpenConversation: (conversationId: String) -> Unit,
    viewModel: HelpdeskQueueViewModel = hiltViewModel(),
)
```

Collects `viewModel.uiState` with `collectAsStateWithLifecycle()`, a Material 3 `Scaffold` with a `TopAppBar` (title "Helpdesk", refresh action) and a `PullToRefreshBox`. Maps `uiState` to AND-021 state composables: `Loading` → loading; `NotAuthorized` → informational not-authorized composable; `Error` → full-screen error + Retry; `Ready(items=[])` → empty state; `Ready(items)` → `LazyColumn` keyed on `conversationId` (with the stale banner when `isStale`). *(Corrected: no `collectAsLazyPagingItems()`, no `append` footer rows — there is no paging.)*

**Navigation.** `HelpdeskGraph` registers route `helpdesk/queue` inside the authenticated graph (AND-024). Because there is no readable role, the destination may be exposed to all authenticated users; the screen self-reports `NotAuthorized` on 403 (the queue call IS the gate). Row tap calls `onOpenConversation(conversationId)` → in this ticket routes to a stub `helpdesk/conversation/{conversationId}` placeholder owned/replaced by AND-162. *(Corrected: route arg is `conversationId`, not `helpdeskId`.)*

**DI.** `HelpdeskModule` provides `HelpdeskApi` via `retrofit.create(...)` from the shared `core-network` Retrofit; `HelpdeskRepository` is `@Singleton`-scoped or constructor-injected per Hilt conventions.

## 5. API Contract

**Endpoint:** `GET /messaging/helpdesk/queue` (op `get_helpdesk_queue_messaging_helpdesk_queue_get`; agent membership enforced server-side, surfaced as 403). Idempotent → eligible for retry/backoff (AND-016).

Query params (verified against OpenAPI):
- `group_id` — **string, REQUIRED, maxLength 128.**
- `state` — string, optional (routing-state filter; `anyOf [string, null]`).
- `limit` — integer, optional, **default 50, min 1, max 200.**

*(Corrected: the original `cursor`/`status`/`limit=30` were wrong; `group_id` was missing.)*

Headers: `Authorization: Bearer <accessToken>` + session cookies (auto via jar) + `X-CSRF-Token` from `ui_csrf` — the web client sends `X-CSRF-Token` on every request including this GET (`src/api/client.ts`); AND-012 should do the same. OpenAPI also lists optional `authorization` and `X-SESSION-ID` headers.

**Success 200 — a bare JSON array of `ConversationOut`** (NOT an envelope; 200 schema is `{ type: array, items: $ref ConversationOut }`):

```json
[
  {
    "conversation_id": "conv_01H...",
    "type": "dm",
    "title": "Cannot access my account",
    "last_message_preview": "I tried resetting but...",
    "last_message_at": 1749132069,
    "status": "active",
    "unread_count": 2,
    "routing_mode": "helpdesk_bridge",
    "routing_group_id": "e2e-helpdesk",
    "routing_state": "awaiting_agent",
    "active_agent_user_id": null,
    "active_agent_claimed_at": null,
    "assignment_version": 0,
    "participant_count": 2,
    "created_at": 1749100000,
    "created_by": "usr_123",
    "participants": [ { "user_id": "usr_123", "display_name": "Jamie R." } ]
  }
]
```

When claimed: `"active_agent_user_id": "usr_999"`, `"routing_state": "assigned"`, `"active_agent_claimed_at": <epoch>`.

**DTO (Moshi) — reuse AND-120's `ConversationDto`/`ConversationOut`; do not introduce a helpdesk-only DTO.** Required `ConversationOut` fields: `conversation_id`, `type`, `created_at`, `created_by`, `participant_count`, `status`. Helpdesk-relevant optionals (all `anyOf [.., null]` unless noted): `title`, `last_message_preview`, `last_message_at` (**epoch seconds int**), `unread_count` (int, default 0), `routing_mode`, `routing_group_id`, `routing_state`, `active_agent_user_id`, `active_agent_claimed_at` (epoch int), `assignment_version` (int), `participants` (array of `app__routers__messaging__ParticipantOut`). The Android service signature returns `Response<List<ConversationDto>>`.

*(Corrected: no `HelpdeskQueuePageDto`/`HelpdeskQueueItemDto`/`PartyDto`; no `helpdesk_id`/`subject`/`preview`/`requester`/`assignee`/`updated_at`. Timestamps are epoch integers, not ISO-8601.)*

**Error responses** map via AND-015 FastAPI `detail` mapping (string | `[{msg}]` | `{code,...}`):
- **401** — session invalid; AND-013 authenticator refreshes once (`POST /ui/session/refresh`) then retries; persistent 401 → `SessionExpired` (AND-044 UX).
- **403** — caller is **not a helpdesk agent** for the group. This is the **primary role signal** (the web client uses `silent403` and infers `isAgent = !queueError`). Mapped to `NotAuthorized` chrome with no error toast. Note: 403 may also carry a `{code: "geo_blocked", message}` detail (`client.ts`) — that variant should surface a region message, not the agent-not-authorized state.
- **422 — `HTTPValidationError`** (verified resp): e.g. missing/invalid `group_id` or bad `state`; non-retryable; treat as a configuration/programming error (we always send a valid `group_id`).
- **5xx / timeout (~20s) / IO** — retryable; surfaced as Error with Retry; offline + cache → stale banner.

## 6. Data & State Management

- **Single source of truth:** `HelpdeskQueueUiState` in the ViewModel holds the rendered `List<HelpdeskQueueItem>` (inside `Ready`). *(Corrected: no Paging 3 `PagingData`/`cachedIn`; the list survives config changes via `ViewModel` retention + `SavedStateHandle` if needed.)*
- **Chrome state:** `HelpdeskQueueUiState` (`StateFlow`) drives loading/not-authorized/empty/error/stale, computed from the `loadQueue` result + connectivity (AND-017) + cache presence.
- **Caching / offline (AND-045):** Room table `helpdesk_queue_cache(conversation_id PK, group_id, title, preview, routing_state, active_agent_user_id, unread_count, last_message_at, order_index, cached_at)` stores the **last successful queue result** (per group) for stale rendering. *(Corrected: keyed on `conversation_id`; columns reflect `ConversationOut` — no `helpdesk_id`/`subject`/`requester_*`/`assignee_*`.)* The fetch is network-first; on failure with non-empty cache, cache is emitted with `isStale = true`. Cache is user-scoped and cleared on logout (AND-032).
- **DataStore:** no new prefs for filters; the helpdesk `group_id` is read from app/build config (OQ-5). AND-161 uses the server default `state` (none) unless a filter is added.
- **User identity:** read `currentUserId()` from AND-029 `AuthStateStore` for `ClaimState` derivation. *(Corrected: do NOT read a "roles"/agent flag — `MeResp` has none; agent-ness comes from the queue's 200-vs-403 outcome.)*

## 7. Error Handling & Resilience

- **Timeouts:** `core-network` ~20s OkHttp timeouts; load timeout → Error(retryable). *(Corrected: no append timeout / footer row — single fetch, no paging.)*
- **Retry/backoff:** idempotent GET wrapped by AND-016 bounded backoff for transient 5xx/timeouts only. No retry on 4xx (except the single 401 refresh in AND-013; 403/422 are never retried).
- **401:** delegated to the shared authenticator (one `POST /ui/session/refresh` + retry; verified path in `client.ts`). Persistent 401 → `SessionExpired`, handed to AND-044's expiry flow (never silently empty the list).
- **403 = not authorized (primary path).** A 403 from the queue is the agent-role signal: render `NotAuthorized`, suppress the error toast (`silent403`-equivalent). There is no `/ui/me` role to re-fetch — re-`refresh()` re-issues the queue call and a later 200 will flip back to `Ready`.
- **Empty vs error:** a 200 with an **empty array `[]`** is **empty** (success), never an error.
- **Offline:** connectivity probe (AND-017) + cache → stale banner over last-known list; refresh re-attempts. No infinite spinners.
- **Result edges:** the array is fully materialized in one response; rows keyed on `conversationId` (stable `LazyColumn` key) guard duplicates. *(Corrected: no `has_more`/`next_cursor` to terminate.)*
- **Malformed payloads:** Moshi parse failure → Error(retryable=false), generic message; raw error logged (section 10), never shown verbatim.

## 8. Security & Privacy

- **Authorization is server-authoritative and is the ONLY gate.** The backend enforces agent access on `GET /messaging/helpdesk/queue` and returns **403** for non-agents; the client cannot pre-filter because no role field is exposed. The 403 IS the authorization result — handle it as `NotAuthorized`, never as an error/crash.
- **Auth transport (corrected):** session rides `Authorization: Bearer <accessToken>` + the persistent cookie jar (AND-011) + `X-CSRF-Token` from the `ui_csrf` cookie injected by AND-012 — and CSRF is sent on **all** requests including this GET, mirroring `client.ts`. No tokens are logged or persisted outside the secured store/jar.
- **PII handling:** queue rows contain requester PII (names, support content previews). Cached rows live in app-private Room storage, scoped to the current user, and are **cleared on logout** and on role loss. No PII in analytics events (section 10) — only opaque ids/counts.
- **Transport:** dev backend is plaintext HTTP (cleartext permitted only for the dev flavor's host per AND-006/AND-014); production builds must use HTTPS. No helpdesk content is written to logs at non-debug levels.
- **No write surface:** this ticket issues no mutations, minimizing CSRF/abuse surface.

## 9. Accessibility & i18n

- All interactive elements (rows, refresh action, retry) have content descriptions; rows expose a combined semantic label ("Open helpdesk conversation from {requester}, {status}, {unread} unread").
- Status/claim badges convey state via text/icon + color, never color alone (color-blind safe).
- Touch targets ≥ 48dp; supports TalkBack focus order top-to-bottom; refresh available via toolbar action (not gesture-only) for switch/keyboard users.
- Dynamic type / large font scaling supported; rows reflow without truncating critical info.
- All strings in `strings.xml` (no hardcoded literals): titles, empty ("Queue is clear"), not-authorized, error, retry, relative-time units.
- Relative timestamps and status labels are locale-aware; uses `android.text.format`/`java.time` with the device locale. RTL layout mirrored.

## 10. Telemetry & Logging

- **Events** (via the project analytics facade; no PII): `helpdesk_queue_viewed { is_agent }`, `helpdesk_queue_loaded { item_count, from_cache }`, `helpdesk_queue_refresh { trigger: pull|toolbar }`, `helpdesk_queue_load_error { stage: refresh|append, http_status?, error_type }`, `helpdesk_queue_row_open` (no requester identity).
- **Logging:** OkHttp logging interceptor (AND-009) at BODY only in debug; helpdesk content never logged at INFO+. Parse/HTTP failures logged with endpoint + status + error class (no payload bodies in release).
- **Metrics of interest:** first-load latency, cache-hit rate on offline, append failure rate — derived from the events above.

## 11. Testing Strategy

Owned partly here and consolidated in **AND-165**; AND-161 must ship the following:

- **Mapper unit tests:** `ConversationOut`→`HelpdeskQueueItem` incl. `ClaimState` derivation (null/blank `active_agent_user_id`→UNASSIGNED; ==me→CLAIMED_BY_ME; else CLAIMED_BY_OTHER), null `title`→participant-name fallback, `routing_state`→badge label mapping, epoch-seconds `last_message_at`→`Instant` parsing.
- **API/repository contract tests** (`core-testing` + MockWebServer, AND-046): `getQueue` sends `group_id` (required) and optional `state`/`limit`; 200 bare array maps to `List<HelpdeskQueueItem>`; **403 → `NotAuthorized`** error; 422 → non-retryable error; 5xx/timeout → retryable error; empty array → empty success. *(Corrected: no PagingSource/cursor/`next_cursor` tests.)*
- **Repository tests:** `loadQueue()` → `ApiResult.Success` for 200, `NotAuthorized` for 403, mapped `Error` for 422/5xx; offline→cache fallback sets `isStale`.
- **ViewModel tests:** 403 → `NotAuthorized`; 200 → `Ready(items)`; 200 `[]` → `Ready(items=[])` (empty); `refresh()`/`retry()` re-issue the fetch; error→chrome mapping. *(Corrected: there is no "zero requests for non-agent" expectation — the call is always made; the 403 is the gate.)*
- **Compose UI tests** (AND-048/049 patterns): agent sees rows (acceptance); 403 shows Not-authorized; empty for `[]`; error + Retry re-fetches; row tap invokes `onOpenConversation(conversationId)`; toolbar refresh reloads. All run headlessly on CI (AND-050) via MockWebServer fixtures.

## 12. Dependencies & Sequencing

- **Hard dependency — AND-120 (Messaging API + DTOs):** must be merged first; provides `core-network` messaging wiring, the shared `ConversationDto`/`ConversationOut` (and participant) DTOs, and `ApiResult`. AND-161 adds only `HelpdeskApi` + the helpdesk mapper/`ClaimState` alongside it (no new wire DTOs). *(Corrected: no helpdesk-specific page/item DTOs.)*
- **Implicit dependencies (already in M1/early M3):** AND-011/012/013/015/016/018 (network resilience), AND-021 (state composables), AND-022/024 (navigation), AND-029 (role/auth store), AND-045 (offline/stale), AND-046/048/050 (test infra).
- **Blocks AND-162 (Helpdesk claim + reply):** consumes this ticket's row model (`conversationId`, `claimState`, `activeAgentUserId`) and the `onOpenConversation(conversationId)` hook; replaces the detail stub. AND-162's claim call is `POST /messaging/helpdesk/conversations/{conversation_id}/claim` (no body) → `HelpdeskClaimOut`.
- **Blocks AND-165 (Groups/helpdesk tests):** consolidated test ticket exercises the queue.
- **Recommended order:** DTOs + mapper → `HelpdeskApi` + PagingSource → repository (gating + cache) → ViewModel → Compose screen → nav wiring → tests.

## 13. Risks & Open Questions

- **OQ-1 — RESOLVED (this review).** Endpoint returns a **bare `ConversationOut[]`** with **no pagination** (no cursor/envelope). Field names verified against `reference/openapi.pretty.json` (`ConversationOut`) and `src/api/types.ts` (`Conversation`). Residual: if a group's queue can exceed `limit` (max 200), an unbounded queue would truncate — track a backend paging follow-up if that becomes real.
- **OQ-2 — RESOLVED (this review).** There is **no** agent-role field. `/ui/me` (`MeResp`) = `{ user_sub, session_id, ip }`. Agent-ness is the **200-vs-403** outcome of the queue call (web: `silent403` + `isAgent = !queueError`). `hasHelpdeskAgentRole()` is removed.
- **OQ-3 — SLA/priority fields.** `ConversationOut` exposes no SLA/priority field; ordering metadata is limited to `last_message_at`/`routing_state`/`active_agent_user_id`. If client ordering is wanted, fall back to unassigned-first then most-recent (FR-7). Low risk.
- **OQ-4 — Unreliable dev host.** The dev backend is plaintext and flaky; flaky CI/manual testing mitigated by MockWebServer fixtures and ~20s timeouts. Risk: intermittent manual-verification failures, not code defects.
- **OQ-5 — Helpdesk `group_id` source (NEW).** The required `group_id` is configured on web via `VITE_HELPDESK_GROUP_ID` (default `"e2e-helpdesk"`). Android needs an equivalent source (build config / remote config / DataStore) and a strategy if a user belongs to multiple helpdesk groups (single configured group vs group picker). **Action:** confirm the production group-id scheme with backend before merge. Medium risk — without it the call 422s.
- **R-1 — Authorization drift mid-session** (agent access revoked) handled by 403→NotAuthorized on the next fetch (section 7); there is no `/ui/me` role to re-check, so `refresh()` simply re-issues the queue. Residual risk a stale cached list briefly shows after revoke — mitigated by clearing cache on logout and on a 403.

## 14. Acceptance Criteria

- **AC-1 (source):** For an authenticated **agent** user (queue returns **200**), the screen loads conversations from `GET /messaging/helpdesk/queue?group_id=<configured>` and renders them in the list (`title`/participant fallback, `last_message_preview`, `routing_state` badge, claim/assignee from `active_agent_user_id`, relative `last_message_at`). *(Verified by Compose UI test against MockWebServer fixture and manual run.)*
- **AC-2:** For a **non-agent** user, the queue request returns **403** and the screen shows a **Not authorized** state with no error toast. *(Corrected: the request IS made — the 403 is the role signal; do not assert zero requests.)*
- **AC-3:** A 200 with an **empty array `[]`** for an agent shows the **empty** state, not an error.
- **AC-4:** A failed load shows a full-screen **error** state with a working Retry; transient 5xx/timeouts are retried per AND-016.
- **AC-5:** The full result set returned by a single fetch is rendered (request honors `limit`, default 50, max 200). *(Corrected: no cursor paging / append rows.)*
- **AC-6:** **Pull-to-refresh** and the **toolbar refresh** both re-issue the queue fetch and replace the list.
- **AC-7:** Offline with a cached list shows last-known rows under a **stale** banner (no infinite spinner).
- **AC-8:** Tapping a row invokes `onOpenConversation(conversationId)` with the correct id (navigates to the AND-162 stub). *(Corrected: id is `conversation_id`.)*
- **AC-9:** `ClaimState` mapping from `active_agent_user_id` is correct for unassigned / claimed-by-me / claimed-by-other (unit-tested).
- **AC-10:** No helpdesk PII appears in analytics events or release-level logs; cache cleared on logout.

## 15. Definition of Done

- `feature-helpdesk` module created and wired (Hilt, nav, `core-*` deps); package root `com.testlogon.android.feature.helpdesk`.
- `HelpdeskApi`, the `ConversationOut`→`HelpdeskQueueItem` mapper, `HelpdeskRepository`, `HelpdeskQueueViewModel`, `HelpdeskQueueScreen`, and `HelpdeskGraph` implemented per sections 4–6. *(No PagingSource — single bounded fetch.)*
- Authorization handled by the **200-vs-403 outcome** of the queue call (no client-side `/ui/me` role precheck); 403 → not-authorized chrome.
- All states implemented: loading, ready, empty, error (with retry), offline/stale, not-authorized. *(No paging append loading/retry.)*
- Unit (mapper), repository, ViewModel, and Compose UI tests written and **passing headlessly in CI** (AND-050); acceptance criteria AC-1…AC-10 covered.
- No hardcoded strings (all in `strings.xml`); accessibility (TalkBack labels, ≥48dp targets, non-color-only state) verified; RTL/locale-aware timestamps.
- ktlint/detekt (AND-005) clean; no new lint baseline regressions.
- `onOpenConversation(conversationId)` hook and row model (`conversationId`, `claimState`, `activeAgentUserId`, `routingState`) exposed and documented for AND-162.
- OQ-1 and OQ-2 reconciled (done in §16 against OpenAPI + frontend: bare `ConversationOut[]`, no paging, role-by-403); OQ-5 (`group_id` source) finalized or tracked as a follow-up TODO before merge.
- Code reviewed and merged to `android-port`.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. OpenAPI pointers reference `reference/openapi.index.txt` / `reference/openapi.pretty.json`; frontend pointers reference `reference/src/...`.

1. **Endpoint exists at `GET /messaging/helpdesk/queue`.** — **Verified.** Source: OpenAPI `GET /messaging/helpdesk/queue` (op `get_helpdesk_queue_messaging_helpdesk_queue_get`); `src/api/endpoints/messaging.ts: getHelpdeskQueue`.
2. **Endpoint is idempotent GET (eligible for retry/backoff).** — **Verified.** Source: OpenAPI `GET /messaging/helpdesk/queue` (method = GET).
3. **`group_id` is a required query param (string, maxLength 128).** — **Corrected** (original omitted it). Source: OpenAPI `GET /messaging/helpdesk/queue` params, `name=group_id, required=true, maxLength=128`; `src/api/endpoints/messaging.ts: getHelpdeskQueue` (passes `group_id`).
4. **Filter param is `state` (optional), not `status`.** — **Corrected.** Source: OpenAPI params `name=state, required=false (anyOf string|null)`; `src/api/endpoints/messaging.ts: getHelpdeskQueue` (`params.state`).
5. **`limit` is optional, default 50, min 1, max 200 (original said default 30).** — **Corrected.** Source: OpenAPI params `name=limit, default=50, minimum=1, maximum=200`.
6. **There is NO `cursor` param.** — **Corrected.** Source: OpenAPI `GET /messaging/helpdesk/queue` params list (only `group_id, state, limit` + headers).
7. **200 response is a bare array of `ConversationOut`, NOT a paged envelope (`items`/`next_cursor`/`has_more`).** — **Corrected** (central correction). Source: OpenAPI 200 schema `{ type: array, items: $ref ConversationOut }`; `src/api/endpoints/messaging.ts: getHelpdeskQueue` returns `Conversation[]`.
8. **Row/item shape = `ConversationOut`; fields used: `conversation_id`, `title`, `last_message_preview`, `last_message_at`, `unread_count`, `status`, `routing_mode`, `routing_state`, `routing_group_id`, `active_agent_user_id`, `active_agent_claimed_at`, `assignment_version`, `participants`.** — **Verified.** Source: `components.schemas.ConversationOut`; `src/api/types.ts: Conversation`.
9. **No `helpdesk_id`, `subject`, `preview`, `requester`, or `assignee` field exists on the wire (original DTOs invented these).** — **Corrected.** Source: `components.schemas.ConversationOut` properties; `src/api/types.ts: Conversation`.
10. **Timestamps (`last_message_at`, `active_agent_claimed_at`, `created_at`) are epoch integers, not ISO-8601 strings.** — **Corrected.** Source: `ConversationOut` (`last_message_at: integer|null`, `created_at: integer`); `src/api/types.ts: Conversation` (`number`).
11. **`routing_state` values are `awaiting_agent` / `assigned` / `paused_no_agents_online` (original used `open|pending|claimed|closed`).** — **Corrected.** Source: `src/pages/helpdesk/HelpdeskPage.tsx: routingStateBadge`.
12. **`ClaimState` must derive from `active_agent_user_id` vs current user (original compared a non-existent `assignee_id`).** — **Corrected.** Source: `ConversationOut.active_agent_user_id`; `src/api/types.ts: Conversation.active_agent_user_id`; `src/pages/helpdesk/HelpdeskPage.tsx` (uses `active_agent_user_id`).
13. **Role is NOT readable from `/ui/me`; `MeResp` = `{ user_sub, session_id, ip }`.** — **Corrected** (central correction). Source: `src/api/types.ts: MeResp`; `src/api/endpoints/auth.ts` (`api.get<MeResp>("/ui/me")`).
14. **Agent-ness is determined by the queue response: 200 ⇒ agent, 403 ⇒ not agent (web uses `silent403` + `isAgent = !queueError`).** — **Verified / Corrected** (replaces the `/ui/me` gating model). Source: `src/api/endpoints/messaging.ts: getHelpdeskQueue` (`silent403: true`); `src/pages/helpdesk/HelpdeskPage.tsx` (`const isAgent = !queueError`).
15. **403 is the not-authorized signal and must be handled without an error toast.** — **Verified.** Source: `src/api/client.ts` (403 branch honors `silent403`); `src/api/endpoints/messaging.ts: getHelpdeskQueue`.
16. **Auth transport = `Authorization: Bearer <accessToken>` + cookies (`credentials: include`) + `X-CSRF-Token` from `ui_csrf` on ALL requests incl. GET (original said cookie-only / CSRF-not-on-GET).** — **Corrected.** Source: `src/api/client.ts` (sets `Authorization`, `credentials: "include"`, and `X-CSRF-Token` unconditionally).
17. **401 handling = one `POST /ui/session/refresh` then a single retry; persistent 401 → logout/`session_expired`.** — **Verified.** Source: `src/api/client.ts` (`refreshSession()` → `/ui/session/refresh`; retry; `logout("session_expired")`).
18. **422 error is `HTTPValidationError`.** — **Verified.** Source: OpenAPI `GET /messaging/helpdesk/queue` resp `422:HTTPValidationError`.
19. **AND-162 claim endpoint = `POST /messaging/helpdesk/conversations/{conversation_id}/claim`, no body, returns `HelpdeskClaimOut` (original path dropped the `/messaging` prefix).** — **Corrected.** Source: OpenAPI `POST /messaging/helpdesk/conversations/{conversation_id}/claim` (`req=` empty; `resp=200:HelpdeskClaimOut`); `src/api/endpoints/messaging.ts: claimHelpdeskConversation` (posts `{}`).
20. **`HelpdeskClaimOut` = `{ ok, conversation_id, state, assigned_agent_user_id, assignment_version, idempotent }`.** — **Verified.** Source: `components.schemas.HelpdeskClaimOut`; `src/api/types.ts: HelpdeskClaimOut`.
21. **Web reads helpdesk `group_id` from `VITE_HELPDESK_GROUP_ID` (default `"e2e-helpdesk"`).** — **Verified.** Source: `src/pages/helpdesk/HelpdeskPage.tsx` (`HELPDESK_GROUP_ID = import.meta.env.VITE_HELPDESK_GROUP_ID ?? "e2e-helpdesk"`).
22. **Title fallback uses non-self `participants[].display_name`.** — **Verified.** Source: `src/pages/helpdesk/HelpdeskPage.tsx: ConvoRow` (participantNames fallback).
23. **Empty queue renders an empty state (web: "No conversations in queue"), not an error.** — **Verified.** Source: `src/pages/helpdesk/HelpdeskPage.tsx` (`queueConvos.length === 0`).
24. **Stack/framework choices (Compose, Paging 3 removed, Material 3 `PullToRefreshBox`, Hilt, Retrofit/Moshi).** — **Unverified-assumption (framework ref).** Not derivable from backend/frontend sources; standard Android stack per the ticket's §2. Refs: Compose `PullToRefreshBox` (framework ref: developer.android.com/reference/kotlin/androidx/compose/material3/pulltorefresh/package-summary); lifecycle `collectAsStateWithLifecycle` (framework ref: developer.android.com/topic/architecture/ui-layer/state-production).

### Corrections made
- §1/§5: 200 response is a **bare `ConversationOut[]`** array — removed the invented `items`/`next_cursor`/`has_more` envelope and all cursor pagination (claims 6, 7).
- §1/§2/§3 FR-2/§6/§7/§8/§11/§13: role model changed from "`/ui/me` agent role + no call for non-agents" to "**call always made; 200⇒agent, 403⇒not-authorized**" — `MeResp` has no role field (claims 13, 14, 15).
- §3 FR-1/§4/§5: query params corrected to `group_id` (required), `state`, `limit` (default 50/max 200); removed `cursor`/`status`; `limit` default fixed from 30 (claims 3, 4, 5).
- §4/§5/§6: DTO/domain field names rebound to `ConversationOut` (no `helpdesk_id`/`subject`/`requester`/`assignee`); timestamps as epoch integers; `ClaimState` derived from `active_agent_user_id`; row key/nav arg = `conversation_id` (claims 8, 9, 10, 12).
- §3 FR-1: `routing_state` badge values corrected to `awaiting_agent`/`assigned`/`paused_no_agents_online` (claim 11).
- §2/§4/§5/§8: auth transport corrected to Bearer + cookie jar + CSRF-on-all-requests (claim 16).
- §2/§12: AND-162 claim path corrected to include `/messaging` prefix; documented no-body + `HelpdeskClaimOut` (claims 19, 20).
- §4 package layout: removed `HelpdeskQueuePagingSource`/`HelpdeskQueueItemDto`/`HelpdeskQueuePageDto`; reuse AND-120 `ConversationDto`.

### Open assumptions
- **OA-1 — Helpdesk `group_id` source on Android (OQ-5).** Web uses an env var; the Android equivalent (build/remote config, multi-group handling) is not derivable from the sources. Must be confirmed with backend before merge — a missing/invalid `group_id` yields 422.
- **OA-2 — Queue size vs `limit`.** With no pagination and `limit ≤ 200`, a very large group queue could be truncated. Whether real queues stay under 200 is unverified; track a backend paging follow-up if needed.
- **OA-3 — Android framework/library choices** (Compose, Material 3, Hilt, Retrofit/Moshi, Paging removed). Architectural decisions, not contract facts; labeled framework refs (claim 24). Not verifiable against backend/frontend.
- **OA-4 — Offline/stale Room cache & telemetry (§6, §10).** App-internal design; no backend/frontend contract governs it. Reasonable but unverified against sources.
- **OA-5 — Sort order (FR-7).** The endpoint's server-side ordering is not documented in OpenAPI; the unassigned-first/most-recent client fallback is an assumption.

## 17. Test Plan

IDs `TC-AND-161-NN`. "Traces" links to §14 Acceptance Criteria. Targets: JVM/Robolectric (local), emulator AVD `test35` (API 35 x86_64), or the physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64) on the build host. UI/instrumented cases here are device-agnostic (no camera/biometrics/WebRTC/push), so they run on the **emulator `test35`** in CI; one ABI-parity case (TC-12) is called out for the **physical device**.

- **TC-AND-161-01 — Mapper: `ConversationOut`→`HelpdeskQueueItem` happy path.**
  Type: unit (JVM). Target: JVM/Robolectric local.
  Preconditions: a `ConversationOut` JSON fixture with `title`, `last_message_preview`, `last_message_at` (epoch seconds), `unread_count`, `routing_state="awaiting_agent"`, `active_agent_user_id=null`.
  Steps: parse via the shared Moshi adapter; run the mapper.
  Expected: `HelpdeskQueueItem` has matching `conversationId`/`title`/`preview`/`unreadCount`; `lastMessageAt == Instant.ofEpochSecond(...)`; `routingState=="awaiting_agent"`; `claimState==UNASSIGNED`.
  Traces: AC-1, AC-9.

- **TC-AND-161-02 — Mapper: `ClaimState` derivation (all three).**
  Type: unit (JVM). Target: JVM local.
  Preconditions: current user id `usr_me`; three fixtures with `active_agent_user_id` = null, `usr_me`, `usr_other`.
  Steps: map each.
  Expected: `UNASSIGNED`, `CLAIMED_BY_ME`, `CLAIMED_BY_OTHER` respectively.
  Traces: AC-9.

- **TC-AND-161-03 — Mapper: title fallback to participant names.**
  Type: unit (JVM). Target: JVM local.
  Preconditions: fixture with `title=null` and `participants=[{user_id:usr_123, display_name:"Jamie R."},{user_id:usr_me,...}]`, current user `usr_me`.
  Steps: map.
  Expected: displayed title resolves to "Jamie R." (self excluded), matching `HelpdeskPage.tsx`.
  Traces: AC-1.

- **TC-AND-161-04 — Contract: request sends required `group_id` (+ default limit).**
  Type: contract/MockWebServer. Target: JVM/Robolectric + MockWebServer.
  Preconditions: MockWebServer enqueues 200 `[]`; repository configured with `group_id="e2e-helpdesk"`.
  Steps: call `loadQueue()`; inspect the recorded request.
  Expected: path `/messaging/helpdesk/queue`, query contains `group_id=e2e-helpdesk`; no `cursor` param; `X-CSRF-Token` and `Authorization` headers present.
  Traces: AC-1.

- **TC-AND-161-05 — Contract: 200 bare array maps to list (happy path).**
  Type: contract/MockWebServer. Target: JVM + MockWebServer.
  Preconditions: enqueue 200 with a 2-element `ConversationOut[]` fixture.
  Steps: `loadQueue()`.
  Expected: `ApiResult.Success` with 2 `HelpdeskQueueItem`s in order; no envelope parsing.
  Traces: AC-1, AC-5.

- **TC-AND-161-06 — Contract: 403 → NotAuthorized (role signal).**
  Type: contract/MockWebServer. Target: JVM + MockWebServer.
  Preconditions: enqueue 403 with `{"detail":"forbidden"}`.
  Steps: `loadQueue()`.
  Expected: result maps to the `NotAuthorized` error variant; no retry attempted; no exception thrown. (The request IS made — assert exactly one request was recorded.)
  Traces: AC-2.

- **TC-AND-161-07 — Contract: 422 `HTTPValidationError` → non-retryable error; 5xx/timeout → retryable.**
  Type: contract/MockWebServer. Target: JVM + MockWebServer.
  Preconditions: case A enqueues 422 `HTTPValidationError`; case B enqueues 503 then 200.
  Steps: `loadQueue()` for each.
  Expected: A → mapped non-retryable `Error` (no retry); B → AND-016 retries the 503 and ultimately succeeds (or surfaces retryable Error if attempts exhausted).
  Traces: AC-4.

- **TC-AND-161-08 — Contract: empty array `[]` → empty success.**
  Type: contract/MockWebServer. Target: JVM + MockWebServer.
  Preconditions: enqueue 200 `[]`.
  Steps: `loadQueue()`.
  Expected: `ApiResult.Success(emptyList())` (not an error).
  Traces: AC-3.

- **TC-AND-161-09 — Compose UI: agent sees rows (acceptance).**
  Type: Compose-UI (instrumented). Target: emulator `test35`.
  Preconditions: MockWebServer 200 with fixture rows; ViewModel wired to it.
  Steps: launch `HelpdeskQueueScreen`; wait for idle.
  Expected: rows render with title/preview, `routing_state` badge text, and a relative timestamp; tapping is enabled.
  Traces: AC-1.

- **TC-AND-161-10 — Compose UI: 403 shows Not-authorized, no toast; 200 `[]` shows empty.**
  Type: Compose-UI (instrumented). Target: emulator `test35`.
  Preconditions: case A MockWebServer 403; case B 200 `[]`.
  Steps: launch screen per case.
  Expected: A → "Not authorized" composable shown, no error toast/snackbar; B → empty state ("Queue is clear"). Neither is rendered as an error.
  Traces: AC-2, AC-3.

- **TC-AND-161-11 — Compose UI: error + Retry re-fetches; pull/toolbar refresh reloads; row tap passes `conversationId`.**
  Type: Compose-UI (instrumented). Target: emulator `test35`.
  Preconditions: MockWebServer enqueues 500, then 200 with rows; a fake `onOpenConversation` capturing the arg.
  Steps: launch → error state shown → tap Retry → rows render; trigger toolbar refresh (enqueue another 200) → list replaced; tap first row.
  Expected: Retry and toolbar refresh both issue a new request and render rows; `onOpenConversation` invoked with the row's `conversation_id` (not a `helpdesk_id`).
  Traces: AC-4, AC-6, AC-8.

- **TC-AND-161-12 — Offline/flaky-host: cached list under stale banner; ABI/API parity.**
  Type: instrumented/e2e. Target: **physical device (SM-A156U, API 34, arm64-v8a)** — to exercise real airplane-mode/network-loss and arm64 vs the x86_64 emulator (epoch-time/`Instant` and Moshi codegen parity).
  Preconditions: one successful fetch populates the Room cache; then enable airplane mode.
  Steps: relaunch/refresh the screen offline.
  Expected: last-known rows render under a **stale** banner (no infinite spinner); on reconnect, refresh replaces with fresh data. Behavior matches the emulator run (no ABI/API-34-vs-35 divergence).
  Traces: AC-7.

- **TC-AND-161-13 — Security: CSRF/Bearer present; no PII in logs/analytics; cache cleared on logout.**
  Type: integration (Robolectric/instrumented). Target: emulator `test35`.
  Preconditions: capture outbound headers + analytics events + release-level logs; perform a load then a logout.
  Steps: load queue; inspect headers/events/logs; log out; inspect Room cache.
  Expected: every request carries `Authorization` + `X-CSRF-Token`; analytics events contain only ids/counts (no requester names/preview text); release logs contain no payload bodies; `helpdesk_queue_cache` is empty after logout.
  Traces: AC-10.

- **TC-AND-161-14 — Accessibility: TalkBack labels, ≥48dp targets, non-color-only state.**
  Type: Compose-UI (instrumented, semantics + accessibility checks). Target: emulator `test35`.
  Preconditions: 200 with rows incl. one claimed + one unread.
  Steps: assert merged semantics per row; run the accessibility checks (touch-target + contrast); verify badges expose text not color alone.
  Expected: each row has a combined content description ("Open helpdesk conversation from {title}, {state}, {unread} unread"); refresh action has a content description; targets ≥48dp; `routing_state`/claim conveyed via text/icon.
  Traces: AC-1 (a11y aspect).

### Coverage matrix

| AC (§14) | Covered by |
| --- | --- |
| AC-1 (agent renders queue from endpoint) | TC-01, TC-03, TC-04, TC-05, TC-09, TC-14 |
| AC-2 (non-agent → 403 → Not authorized, request still made) | TC-06, TC-10 |
| AC-3 (200 `[]` → empty state) | TC-08, TC-10 |
| AC-4 (error + working Retry; 5xx retried) | TC-07, TC-11 |
| AC-5 (full single-fetch result rendered, honors `limit`) | TC-05 |
| AC-6 (pull + toolbar refresh reload) | TC-11 |
| AC-7 (offline → cached list under stale banner) | TC-12 |
| AC-8 (row tap → `onOpenConversation(conversationId)`) | TC-11 |
| AC-9 (`ClaimState` mapping) | TC-01, TC-02 |
| AC-10 (no PII in logs/analytics; cache cleared on logout) | TC-13 |
