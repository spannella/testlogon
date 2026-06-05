---
id: AND-161
title: Helpdesk queue
milestone: M3
epic: E22
priority: P2
size: M
status: draft
depends_on: [AND-120]
blocks: [AND-162, AND-165]
---

# AND-161 — Helpdesk queue

## 1. Overview & Goal

This ticket delivers the **agent-facing helpdesk queue** for the native Android port: a read-only, paginated list of inbound helpdesk conversations that authenticated **agent-role** users can browse to triage support requests. The screen consumes `GET /messaging/helpdesk/queue` and renders each queue entry (subject/preview, requester, status, age/SLA hint, claim/assignee state) in a scrollable list with loading, empty, error, and offline/stale states, plus pull-to-refresh and incremental paging.

The scope is deliberately bounded to **reading and rendering the queue**. Claiming a conversation, opening a thread, and replying are owned by the downstream ticket **AND-162 (Helpdesk claim + reply)**; this ticket only exposes the per-row navigation hook and assignee/claim metadata that AND-162 consumes. The queue must also be **role-gated**: non-agent users must never see the queue (no API call, no entry point), surfaced as a "not authorized" state rather than a crash or an empty list.

Success is behavioral and matches the source acceptance criterion: **the queue renders for an agent role** — given an authenticated user whose `/ui/me` profile includes the agent role/permission, the screen loads queue items from the backend and displays them; given a non-agent user, the screen shows an unauthorized state and issues no queue request.

## 2. Context & References

- **Module:** `feature-helpdesk` (new feature module) depending on `core-network`, `core-model`, `core-ui`, `core-data`, `core-testing`. Package root `com.testlogon.android.feature.helpdesk`. Wired into the authenticated nav graph (AND-024) and root `NavHost` (AND-022).
- **Branch / repo:** `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- **Depends on AND-120 (Messaging API + DTOs):** provides `MessagingApi`, the Retrofit/Moshi wiring, shared messaging DTOs (`ConversationDto`, `MessageDto`, pagination envelope) and the `core-network` `ApiResult<T>` plumbing. The helpdesk queue endpoint is a sibling of the messaging conversation endpoints and reuses the same conversation payload shapes where possible. **AND-161 must not duplicate** the messaging DTOs; it extends/reuses them and adds only helpdesk-specific fields (claim/assignee/SLA).
- **Blocks AND-162 (Helpdesk claim + reply):** AND-162 calls `/helpdesk/conversations/{id}/claim` + reply and depends on this ticket's row model, `helpdeskId`, and navigation hook.
- **Blocks AND-165 (Groups/helpdesk tests):** the consolidated repo + UI test ticket exercises this queue.
- **Cross-cutting reuse:** `core-network` cookie jar (AND-011), CSRF interceptor (AND-012), 401 refresh authenticator (AND-013), error/detail mapping (AND-015), retry/backoff for idempotent GETs (AND-016), `ApiResult` (AND-018); `core-ui` state composables (AND-021); auth state / `/ui/me` role store (AND-029); offline/stale reads (AND-045); paging conventions (AND-122).
- **Auth model:** cookie-based session, `ui_csrf` echoed as `X-CSRF-Token`, persistent jar, single refresh-on-401 retry — handled transparently by the shared OkHttp stack.
- **Web reference:** `frontend/src/api/endpoints/*.ts` (helpdesk endpoint) and `frontend/src/api/types.ts` (queue item shape) are the canonical contract; confirm shapes against `/openapi.json` on the dev backend (`http://18.222.237.167:8000`, PLAINTEXT, unreliable — design for ~20s timeouts and stale UI).
- **Stack:** Kotlin 2.0.21, Compose + Material 3, Navigation-Compose, Hilt (KSP), Coroutines/Flow, Retrofit 2.11/OkHttp 4.12/Moshi 1.15, Room 2.6, DataStore, Paging 3. minSdk 24, compileSdk/targetSdk 35, JDK 17, AGP 8.7.3, Gradle 8.9.

## 3. Functional Requirements

FR-1 — **Queue list renders.** The screen loads helpdesk queue entries from `GET /messaging/helpdesk/queue` and renders them in a vertically scrolling `LazyColumn`. Each row shows: subject/title (or last-message preview fallback), requester display name/handle, status badge (e.g. `open`/`pending`/`claimed`/`closed`), claim/assignee indicator (unassigned vs assigned-to name), unread/new indicator, and a relative timestamp ("3m", "2h", "Yesterday").

FR-2 — **Role gating.** The queue is only requested and rendered for users whose `/ui/me` profile grants the agent/helpdesk role (see AND-029 role store). For non-agent users the screen shows a non-blocking **Not authorized** state and performs **no** network call. The queue entry point (nav destination/menu item) is hidden/disabled for non-agents.

FR-3 — **Paging.** The list pages incrementally via Paging 3 using the backend cursor/offset pagination from AND-120's envelope. Reaching the end appends the next page; a footer shows an inline loading row and an inline retry row on append failure.

FR-4 — **Pull-to-refresh.** Pull-to-refresh re-fetches from the first page and replaces the list (`PagingSource.invalidate()`), preserving scroll affordances per Paging 3 conventions.

FR-5 — **Loading / empty / error / offline states.** First-load shows a loading state (AND-021). An authorized agent with zero queue entries shows an **empty** state ("Queue is clear"). A failed first load shows a full-screen **error** state with Retry. When offline/unreachable with cached data present, a **stale** banner is shown over last-known content (AND-045).

FR-6 — **Row navigation hook (for AND-162).** Tapping a row invokes `onOpenConversation(helpdeskId: String)`. In AND-161 this navigates to a placeholder/detail route stub; AND-162 replaces the stub with the claim+reply detail. The row model must carry `helpdeskId`, `conversationId`, `claimState`, and `assignee` so AND-162 needs no additional fetch to render claim controls.

FR-7 — **Sort/order.** Entries are presented in backend order (server-sorted by priority/age); if the backend does not sort, the client sorts unassigned-first then oldest-first. Sorting is deterministic and unit-tested.

FR-8 — **Manual refresh entry.** A toolbar refresh action triggers the same first-page refresh as pull-to-refresh (for accessibility and emulator use without gestures).

FR-9 — **No write actions.** This ticket performs no claim/reply/close mutations. Any such control belongs to AND-162; rows are read-only beyond the open hook.

## 4. Technical Design

**Module / package layout** (`feature-helpdesk`):

```
com.testlogon.android.feature.helpdesk.data.HelpdeskApi
com.testlogon.android.feature.helpdesk.data.HelpdeskRepository
com.testlogon.android.feature.helpdesk.data.HelpdeskQueuePagingSource
com.testlogon.android.feature.helpdesk.data.dto.HelpdeskQueueItemDto
com.testlogon.android.feature.helpdesk.data.dto.HelpdeskQueuePageDto
com.testlogon.android.feature.helpdesk.domain.HelpdeskQueueItem
com.testlogon.android.feature.helpdesk.domain.ClaimState
com.testlogon.android.feature.helpdesk.ui.HelpdeskQueueScreen
com.testlogon.android.feature.helpdesk.ui.HelpdeskQueueViewModel
com.testlogon.android.feature.helpdesk.ui.HelpdeskQueueUiState
com.testlogon.android.feature.helpdesk.navigation.HelpdeskGraph
com.testlogon.android.feature.helpdesk.di.HelpdeskModule
```

**API surface.** Helpdesk-specific Retrofit interface (kept separate from `MessagingApi` for module boundaries; both share the `core-network` Retrofit instance):

```kotlin
interface HelpdeskApi {
    @GET("messaging/helpdesk/queue")
    suspend fun getQueue(
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = 30,
        @Query("status") status: String? = null, // e.g. "open" (default server-side)
    ): Response<HelpdeskQueuePageDto>
}
```

**Domain model.**

```kotlin
enum class ClaimState { UNASSIGNED, CLAIMED_BY_ME, CLAIMED_BY_OTHER }

data class HelpdeskQueueItem(
    val helpdeskId: String,
    val conversationId: String,
    val subject: String?,
    val preview: String?,
    val requesterName: String,
    val requesterId: String?,
    val status: String,          // raw backend status, lowercased
    val claimState: ClaimState,
    val assigneeName: String?,
    val unread: Boolean,
    val updatedAt: Instant,
)
```

`ClaimState` is derived in the mapper by comparing `assignee_id` to the current user's id (from AND-029 auth state): null assignee -> `UNASSIGNED`; assignee == me -> `CLAIMED_BY_ME`; else `CLAIMED_BY_OTHER`.

**Repository + Paging.**

```kotlin
class HelpdeskRepository @Inject constructor(
    private val api: HelpdeskApi,
    private val errorMapper: ApiErrorMapper,          // AND-015
    private val authState: AuthStateStore,            // AND-029 (current user id + roles)
) {
    fun isAgent(): Boolean = authState.currentUser()?.hasHelpdeskAgentRole() == true

    fun queuePager(status: String? = null): Flow<PagingData<HelpdeskQueueItem>> =
        Pager(PagingConfig(pageSize = 30, prefetchDistance = 10, enablePlaceholders = false)) {
            HelpdeskQueuePagingSource(api, errorMapper, currentUserId = authState.currentUserId(), status = status)
        }.flow

    suspend fun refreshOnce(status: String? = null): ApiResult<List<HelpdeskQueueItem>> { /* first-page fetch for tests */ }
}
```

`HelpdeskQueuePagingSource : PagingSource<String, HelpdeskQueueItem>` uses the cursor envelope: `load()` calls `api.getQueue(cursor, limit, status)`, maps DTO→domain, returns `LoadResult.Page(data, prevKey = null, nextKey = page.nextCursor)`. On HTTP/IO failure it returns `LoadResult.Error(mappedThrowable)`; on **401** the shared authenticator (AND-013) has already attempted one refresh+retry, so a persistent 401 maps to a session-expired error surfaced to AND-044's expiry UX. Idempotent GET retry/backoff (AND-016) wraps the call for transient 5xx/timeouts.

**ViewModel.**

```kotlin
@HiltViewModel
class HelpdeskQueueViewModel @Inject constructor(
    private val repository: HelpdeskRepository,
) : ViewModel() {
    val uiState: StateFlow<HelpdeskQueueUiState>      // gating + chrome state
    val items: Flow<PagingData<HelpdeskQueueItem>>    // cachedIn(viewModelScope)
    fun refresh()                                      // triggers PagingSource invalidate
    fun retry()
}

sealed interface HelpdeskQueueUiState {
    data object Loading : HelpdeskQueueUiState
    data object NotAuthorized : HelpdeskQueueUiState   // non-agent
    data class Ready(val isRefreshing: Boolean, val isStale: Boolean) : HelpdeskQueueUiState
    data class Error(val message: String, val retryable: Boolean) : HelpdeskQueueUiState
}
```

On init the ViewModel checks `repository.isAgent()`. If false, it emits `NotAuthorized` and never collects `items` (no API call). If true, it exposes `items` and maps `LoadState` from the `LazyPagingItems` (in the composable) into the `Ready`/`Error` chrome.

**Composable.**

```kotlin
@Composable
fun HelpdeskQueueScreen(
    onOpenConversation: (helpdeskId: String) -> Unit,
    viewModel: HelpdeskQueueViewModel = hiltViewModel(),
)
```

Uses `viewModel.items.collectAsLazyPagingItems()`, a Material 3 `Scaffold` with a `TopAppBar` (title "Helpdesk", refresh action) and a `PullToRefreshBox`. Maps `lazyItems.loadState.refresh` to AND-021 state composables; `append` to inline footer rows. `NotAuthorized` renders a `core-ui` informational empty-state composable.

**Navigation.** `HelpdeskGraph` registers route `helpdesk/queue` inside the authenticated graph (AND-024). The destination is only added to the nav menu/shell for agents; gating is also enforced inside the screen (defense in depth). Row tap calls `onOpenConversation(helpdeskId)` → in this ticket routes to a stub `helpdesk/conversation/{helpdeskId}` placeholder owned/replaced by AND-162.

**DI.** `HelpdeskModule` provides `HelpdeskApi` via `retrofit.create(...)` from the shared `core-network` Retrofit; `HelpdeskRepository` is `@Singleton`-scoped or constructor-injected per Hilt conventions.

## 5. API Contract

**Endpoint:** `GET /messaging/helpdesk/queue` (cookie-authenticated; agent role enforced server-side). Idempotent → eligible for retry/backoff (AND-016).

Query params: `cursor` (opaque, optional), `limit` (int, default 30), `status` (optional filter).

Headers: session cookies (auto via jar); `X-CSRF-Token` not required for GET but injected harmlessly by AND-012 interceptor.

**Success 200 — page envelope** (mirror AND-120 envelope; confirm against `/openapi.json`):

```json
{
  "items": [
    {
      "helpdesk_id": "hd_01H...",
      "conversation_id": "conv_01H...",
      "subject": "Cannot access my account",
      "preview": "I tried resetting but...",
      "requester": { "id": "usr_123", "display_name": "Jamie R." },
      "status": "open",
      "assignee": null,
      "unread_count": 2,
      "updated_at": "2026-06-05T14:21:09Z"
    }
  ],
  "next_cursor": "eyJvZmZzZXQiOjMwfQ==",
  "has_more": true
}
```

`assignee` when claimed: `{ "id": "usr_999", "display_name": "Agent Pat" }`.

**DTOs (Moshi):**

```kotlin
@JsonClass(generateAdapter = true)
data class HelpdeskQueuePageDto(
    @Json(name = "items") val items: List<HelpdeskQueueItemDto>,
    @Json(name = "next_cursor") val nextCursor: String?,
    @Json(name = "has_more") val hasMore: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class HelpdeskQueueItemDto(
    @Json(name = "helpdesk_id") val helpdeskId: String,
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "subject") val subject: String?,
    @Json(name = "preview") val preview: String?,
    @Json(name = "requester") val requester: PartyDto?,
    @Json(name = "status") val status: String,
    @Json(name = "assignee") val assignee: PartyDto?,
    @Json(name = "unread_count") val unreadCount: Int = 0,
    @Json(name = "updated_at") val updatedAt: Instant,
)

@JsonClass(generateAdapter = true)
data class PartyDto(
    @Json(name = "id") val id: String?,
    @Json(name = "display_name") val displayName: String?,
)
```

**Error responses** map via AND-015 FastAPI `detail` mapping (string | `[{msg}]` | `{code,...}`):
- **401** — session invalid; AND-013 authenticator refreshes once then retries; persistent 401 → `SessionExpired` (AND-044 UX).
- **403** — caller lacks agent role (server-side). Mapped to `NotAuthorized` chrome (should be unreachable due to client gating, but handled defensively).
- **422** — invalid query (e.g. bad `status`); surfaced as a non-retryable error; default the filter and retry.
- **5xx / timeout (~20s) / IO** — retryable; surfaced as Error with Retry; offline + cache → stale banner.

Field assumptions (`subject` nullability, `next_cursor` vs offset paging, `assignee` shape) are **provisional** and MUST be reconciled against `/openapi.json` and `frontend/src/api/types.ts` before merge (Open Question OQ-1).

## 6. Data & State Management

- **Single source of truth:** Paging 3 `PagingData<HelpdeskQueueItem>` from `queuePager()`, `cachedIn(viewModelScope)` so config changes don't refetch.
- **Chrome state:** `HelpdeskQueueUiState` (`StateFlow`) drives gating, refresh spinner, and stale banner, computed from `LazyPagingItems.loadState` + connectivity (AND-017) + cache presence.
- **Caching / offline (AND-045):** Room table `helpdesk_queue_cache(helpdesk_id PK, conversation_id, subject, preview, requester_name, requester_id, status, assignee_id, assignee_name, unread_count, updated_at, page_index, cached_at)` stores the **first page** for stale rendering. PagingSource is network-first; on first-page failure with non-empty cache, cache is emitted with `isStale = true`. Appended pages are network-only. Cache is user-scoped and cleared on logout (AND-032).
- **DataStore:** no new prefs; AND-161 uses the server default `status` and stores nothing.
- **Role data:** read from AND-029 `AuthStateStore` (`currentUser`, `currentUserId`, roles). No new role persistence here.

## 7. Error Handling & Resilience

- **Timeouts:** `core-network` ~20s OkHttp timeouts; first-load timeout → Error(retryable); append timeout → inline retry footer row.
- **Retry/backoff:** idempotent GET wrapped by AND-016 bounded backoff for transient 5xx/timeouts only. No retry on 4xx (except the single 401 refresh in AND-013).
- **401:** delegated to the shared authenticator (one `POST /ui/session/refresh` + retry). Persistent 401 → `SessionExpired`, handed to AND-044's expiry flow (never silently empty the list).
- **403 / authorization drift:** server 403 despite client gating (role revoked mid-session) → flip to `NotAuthorized` and refresh `/ui/me` via AND-029.
- **Empty vs error:** 200 with `items: []` is **empty** (success), never an error.
- **Offline:** connectivity probe (AND-017) + cache → stale banner over last-known first page; refresh re-attempts. No infinite spinners.
- **Pagination edges:** `has_more=false`/null `next_cursor` ends cleanly; rows keyed on `helpdeskId` (stable `LazyColumn` key) guard duplicates.
- **Malformed payloads:** Moshi parse failure → Error(retryable=false), generic message; raw error logged (section 10), never shown verbatim.

## 8. Security & Privacy

- **Authorization is server-authoritative.** Client role gating is a UX optimization; the backend enforces agent access on `GET /messaging/helpdesk/queue`. The client must not assume gating substitutes for server checks.
- **Cookie/CSRF:** session rides the persistent cookie jar (AND-011); `X-CSRF-Token` injected by AND-012. No tokens are logged or persisted outside the secured jar.
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

- **Mapper unit tests:** DTO→domain incl. `ClaimState` derivation (null→UNASSIGNED; ==me→CLAIMED_BY_ME; else CLAIMED_BY_OTHER), null subject→preview fallback, status lowercasing, timestamp parsing.
- **PagingSource tests** (`core-testing` + MockWebServer, AND-046): first page maps; `nextKey` follows `next_cursor`; `has_more=false`/null cursor terminates; 5xx/timeout → `LoadResult.Error`; empty page → empty `Page`.
- **Repository tests:** `isAgent()` true/false from injected `AuthStateStore`; `refreshOnce()` → `ApiResult.Success` for 200, mapped `Error` for 422/5xx; offline→cache fallback sets stale.
- **ViewModel tests:** non-agent → `NotAuthorized` and **zero** MockWebServer requests; agent → exposes items; `refresh()` invalidates source; error→chrome mapping.
- **Compose UI tests** (AND-048/049 patterns): agent sees rows (acceptance); non-agent sees Not-authorized; empty for `items:[]`; error + Retry re-fetches; row tap invokes `onOpenConversation(helpdeskId)`; toolbar refresh reloads. All run headlessly on CI (AND-050) via MockWebServer fixtures.

## 12. Dependencies & Sequencing

- **Hard dependency — AND-120 (Messaging API + DTOs):** must be merged first; provides `core-network` messaging wiring, shared envelope/party DTOs, and `ApiResult`. AND-161 adds `HelpdeskApi` + helpdesk DTOs alongside it.
- **Implicit dependencies (already in M1/early M3):** AND-011/012/013/015/016/018 (network resilience), AND-021 (state composables), AND-022/024 (navigation), AND-029 (role/auth store), AND-045 (offline/stale), AND-046/048/050 (test infra).
- **Blocks AND-162 (Helpdesk claim + reply):** consumes this ticket's row model (`helpdeskId`, `claimState`, `assignee`) and the `onOpenConversation` hook; replaces the detail stub.
- **Blocks AND-165 (Groups/helpdesk tests):** consolidated test ticket exercises the queue.
- **Recommended order:** DTOs + mapper → `HelpdeskApi` + PagingSource → repository (gating + cache) → ViewModel → Compose screen → nav wiring → tests.

## 13. Risks & Open Questions

- **OQ-1 — Endpoint shape/pagination.** `/messaging/helpdesk/queue` field names, nullability, and pagination style (cursor vs offset, `next_cursor`/`has_more` naming) are provisional. **Action:** verify against `/openapi.json` and `frontend/src/api/types.ts`; adjust DTOs before merge. Risk: rework if the envelope differs from AND-120's.
- **OQ-2 — Role signal.** How agent role is exposed in `/ui/me` (boolean flag vs roles array vs permission string) is TBD; `hasHelpdeskAgentRole()` must map to the real field. **Action:** confirm with AND-029 and backend `/ui/me` schema.
- **OQ-3 — SLA/priority fields.** Whether the queue includes SLA/priority/age-sorting metadata is unknown; if absent, client falls back to unassigned-first/oldest-first (FR-7). Low risk.
- **OQ-4 — Unreliable dev host.** The dev backend is plaintext and flaky; flaky CI/manual testing mitigated by MockWebServer fixtures and ~20s timeouts. Risk: intermittent manual-verification failures, not code defects.
- **R-1 — Authorization drift mid-session** (role revoked) handled by 403→NotAuthorized + `/ui/me` refresh (section 7); residual risk a stale cached page briefly shows after revoke — mitigated by clearing cache on role loss.

## 14. Acceptance Criteria

- **AC-1 (source):** For an authenticated **agent-role** user, the helpdesk queue screen loads entries from `GET /messaging/helpdesk/queue` and renders them in the list (subject/preview, requester, status, claim/assignee, timestamp). *(Verified by Compose UI test against MockWebServer fixture and manual run.)*
- **AC-2:** For a **non-agent** user, the screen shows a **Not authorized** state and issues **no** request to `/messaging/helpdesk/queue`. *(Verified: zero MockWebServer requests.)*
- **AC-3:** A 200 with `items: []` for an agent shows the **empty** state, not an error.
- **AC-4:** A failed first load shows a full-screen **error** state with a working Retry; transient 5xx/timeouts are retried per AND-016.
- **AC-5:** The list **pages** to subsequent pages following `next_cursor`/`has_more`, with an inline append-loading row and inline append-retry on failure.
- **AC-6:** **Pull-to-refresh** and the **toolbar refresh** both reload the first page (PagingSource invalidated).
- **AC-7:** Offline with cached first page shows last-known rows under a **stale** banner (no infinite spinner).
- **AC-8:** Tapping a row invokes `onOpenConversation(helpdeskId)` with the correct id (navigates to the AND-162 stub).
- **AC-9:** `ClaimState` mapping is correct for unassigned / claimed-by-me / claimed-by-other (unit-tested).
- **AC-10:** No helpdesk PII appears in analytics events or release-level logs; cache cleared on logout.

## 15. Definition of Done

- `feature-helpdesk` module created and wired (Hilt, nav, `core-*` deps); package root `com.testlogon.android.feature.helpdesk`.
- `HelpdeskApi`, DTOs, mappers, `HelpdeskQueuePagingSource`, `HelpdeskRepository`, `HelpdeskQueueViewModel`, `HelpdeskQueueScreen`, and `HelpdeskGraph` implemented per sections 4–6.
- Role gating enforced client-side (no call for non-agents) with server-side 403 fallback handling.
- All states implemented: loading, ready, empty, error (with retry), offline/stale, not-authorized; paging with append loading/retry.
- Unit, PagingSource, repository, ViewModel, and Compose UI tests written and **passing headlessly in CI** (AND-050); acceptance criteria AC-1…AC-10 covered.
- No hardcoded strings (all in `strings.xml`); accessibility (TalkBack labels, ≥48dp targets, non-color-only state) verified; RTL/locale-aware timestamps.
- ktlint/detekt (AND-005) clean; no new lint baseline regressions.
- `onOpenConversation` hook and row model (`helpdeskId`, `conversationId`, `claimState`, `assignee`) exposed and documented for AND-162.
- OQ-1 and OQ-2 reconciled against `/openapi.json` and `/ui/me`; DTO/role field names finalized (or tracked as follow-ups with TODOs referencing the open questions).
- Code reviewed and merged to `android-port`.
