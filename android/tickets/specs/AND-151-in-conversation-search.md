---
id: AND-151
title: In-conversation search
milestone: M3
epic: E21
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-123]
blocks: []
---

# AND-151 — In-conversation search

## 1. Overview & Goal

Add the ability to search the messages of a single open conversation thread, highlight every match in the rendered message list, and jump-to / scroll-to the next or previous match. This is the **in-conversation** (scoped) search experience that lives inside the Thread screen built in AND-123; it is distinct from AND-152 (cross-conversation *global* search) which has its own results screen.

The feature is invoked from the Thread screen top app bar (a search icon), opens an in-place search input ("find in conversation") bar, queries the backend endpoint `GET /messaging/conversations/{conversation_id}/messages/search` (CORRECTED: the path is prefixed with `/messaging` and the path param is `conversation_id`, not the spec's earlier `/conversations/{id}/...` — verified against OpenAPI), renders a match count and prev/next navigation, highlights matching substrings inside message bubbles, and programmatically scrolls the `LazyColumn` so the active match is centered and visually emphasized.

Success is defined by the source acceptance bullet: **the feature finds matches and scrolls to them.** Concretely: typing a query returns the set of matching messages in the currently open thread, the UI reports `N` matches, tapping next/prev moves the active match cursor, and the message list scrolls the active match into view with a transient emphasis.

## 2. Context & References

- **Depends on:** AND-123 (`feature-thread`, Thread / message-list screen). This ticket extends the existing `ThreadScreen`, `ThreadViewModel`, and the reverse-paged `LazyColumn` produced there. The message item composable and message domain model from AND-123 are reused, not duplicated.
- **Sibling:** AND-152 (Global message search) owns the cross-conversation experience and `GET /messaging/messages/search` (verified present in OpenAPI). Where this ticket and AND-152 share helpers (query debounce, highlight span builder), the shared code is placed in `core-ui` so AND-152 can consume it.
- **Web reference:** CORRECTED — there is **no** in-conversation message-search call in the frontend (`src/api/endpoints/conversations.ts` does not exist; the messaging calls live in `src/api/endpoints/messaging.ts`, which has *no* `messages/search` call, and `src/api/endpoints/search.ts` only covers the global `/ui/search`). There is also **no** `MessageSearchResult` type in `src/api/types.ts`. The web app does not exercise this endpoint, so the native client is the first consumer; field names are mirrored from the OpenAPI `MessageOut` schema (see §5), not from a web DTO.
- **OpenAPI:** the dev backend's OpenAPI is the source of truth for the request/response schema. The endpoint is `GET /messaging/conversations/{conversation_id}/messages/search`; the 200 response is a bare JSON array of `MessageOut` (no envelope). Confirmed during this review (see §5).
- **Module layering:** `app -> feature-thread -> core-network, core-model, core-ui, core-data, core-testing`. Networking lives in `core-network`; the highlight span builder in `core-ui`; domain models in `core-model`.

## 3. Functional Requirements

1. **Entry point.** The Thread top app bar exposes a search action (magnifier icon, `contentDescription = "Search in conversation"`). Activating it switches the app bar into a search-input state with a back/close affordance.
2. **Query input.** A single-line text field accepts the query. Input is debounced (300 ms) before a network call is issued. Empty/blank queries clear results and highlights and issue no network call.
3. **Search execution.** On a non-blank debounced query the app calls `GET /messaging/conversations/{conversation_id}/messages/search?q=<query>` for the currently open conversation id (CORRECTED path). The query is trimmed; minimum effective length is 2 characters (a client-side rule — note the backend `q` constraint is `minLength: 1, maxLength: 200`, so the 2-char floor is stricter than the server requires and is purely a UX choice). Shorter queries show an inline "Type at least 2 characters" hint and issue no call. The client must also cap `q` at 200 chars before sending, since the backend rejects longer `q` with 422.
4. **Result reporting.** The search bar shows a status: `0 results`, `1 result`, `M of N` (active cursor / total), or a loading spinner while in flight.
5. **Match navigation.** Up (previous) and down (next) chevron buttons move the active-match cursor. Navigation wraps (next from last -> first; prev from first -> last). Buttons are disabled when there are zero matches. The keyboard "search"/IME action advances to the next match.
6. **Highlighting.** Every message that contains a match renders the matched substring(s) with a highlight background. The *active* match renders with a stronger/distinct emphasis color so it is distinguishable from the other (inactive) matches. NOTE: the backend returns only the matched messages (`MessageOut[]`), with **no** per-occurrence character offsets, so all highlight spans are computed **locally** on the client from `text` + `query` (see §4/§5).
7. **Scroll-to / jump-to.** Changing the active match scrolls the `LazyColumn` so the active message is brought into view (centered when possible). If the target message is not in the currently loaded page window, the loaded window is extended (paging) until the target index is materialized, then scrolled to.
8. **Match positioning within a message.** A single message may contain multiple occurrences; each occurrence is an addressable match. The active-match cursor addresses (messageId, occurrenceIndex).
9. **Dismissal.** Closing search restores the normal Thread app bar, clears the query, removes all highlights, and leaves the list at its current scroll position.
10. **Persistence across config change.** Query text, results, and active-match cursor survive rotation / process-death-light (SavedStateHandle).
11. **Live messages during search.** New messages arriving (via the AND-123 append path) do not crash search; the result set is recomputed on the next query change. Re-running an identical query after new messages append refreshes counts. (Auto-re-search on append is out of scope — see §13.)

## 4. Technical Design

### Module & files

```
feature-thread/
  search/
    ThreadSearchUiState.kt
    ThreadSearchController.kt      // search sub-state owned by ThreadViewModel
    ThreadSearchBar.kt            // composable app-bar search input
core-network/
    ConversationSearchApi.kt
    dto/MessageSearchResponseDto.kt
core-model/
    MessageSearchMatch.kt
core-ui/
    text/SearchHighlight.kt        // shared with AND-152
```

### State

```kotlin
data class ThreadSearchUiState(
    val active: Boolean = false,            // search mode on/off
    val query: String = "",
    val phase: SearchPhase = SearchPhase.Idle,
    val matches: List<MessageSearchMatch> = emptyList(), // ordered oldest->newest
    val activeIndex: Int = -1,              // index into matches; -1 == none
) {
    val total: Int get() = matches.size
    val cursorLabel: String get() =
        if (matches.isEmpty()) "" else "${activeIndex + 1} of $total"
    val activeMatch: MessageSearchMatch? get() = matches.getOrNull(activeIndex)
}

sealed interface SearchPhase {
    data object Idle : SearchPhase
    data object Loading : SearchPhase
    data object Loaded : SearchPhase
    data class Error(val message: String) : SearchPhase
}
```

```kotlin
// core-model
data class MessageSearchMatch(
    val messageId: String,      // from MessageOut.message_id
    val occurrenceIndex: Int,   // nth hit inside this message's text (computed locally)
    val start: Int,             // char offset of hit start in message text (computed locally)
    val end: Int,               // char offset (exclusive, computed locally)
    val createdAt: Instant,     // derived from MessageOut.created_at (epoch SECONDS as integer)
)
// NOTE: MessageOut.created_at is a Unix-epoch INTEGER, not an ISO-8601 string.
// The DTO must type it as Long and the mapper converts to Instant
// (Instant.ofEpochSecond / ofEpochMilli — confirm unit at integration; see §13).
// start/end/occurrenceIndex are ALL computed client-side; the backend
// supplies no highlight offsets.
```

### ViewModel integration

`ThreadSearchController` is a plain class held by `ThreadViewModel` (AND-123), keeping search concerns isolated while sharing the thread's `conversationId` and `SavedStateHandle`. It exposes a `StateFlow<ThreadSearchUiState>`.

```kotlin
class ThreadSearchController(
    private val conversationId: String,
    private val api: ConversationSearchApi,
    private val saved: SavedStateHandle,
    private val scope: CoroutineScope,
) {
    val state: StateFlow<ThreadSearchUiState>

    fun open()
    fun close()
    fun onQueryChange(raw: String)   // updates query + restarts debounce
    fun next()                       // activeIndex = (activeIndex + 1).wrap(total)
    fun prev()                       // activeIndex = (activeIndex - 1).wrap(total)

    @OptIn(FlowPreview::class)
    private val searches = MutableStateFlow("")
    // searches.debounce(300).map(String::trim).distinctUntilChanged()
    //   .filter { it.length >= 2 }.flatMapLatest { runSearch(it) }
}
```

`flatMapLatest` guarantees only the latest query's result is applied (stale responses cancelled). Each successful `runSearch` resets `activeIndex` to `0` (or `-1` when empty).

### Scroll-to mechanics

The Thread `LazyColumn` from AND-123 already uses a `LazyListState`. Search subscribes to `state.activeMatch` and drives scrolling:

```kotlin
LaunchedEffect(searchUi.activeMatch) {
    val match = searchUi.activeMatch ?: return@LaunchedEffect
    val index = threadVm.indexOfMessage(match.messageId)   // suspend; may page in
        ?: return@LaunchedEffect
    lazyListState.animateScrollToItem(index, scrollOffset = -centeringOffsetPx)
    pulse(match.messageId)   // transient emphasis ~600ms
}
```

`ThreadViewModel.indexOfMessage(id): Int?` resolves the loaded-list index, extending the reverse-paged window (Paging 3) when the target is older than the loaded set, with a bounded number of page loads (cap = 10) before giving up and surfacing "Match is too far back to jump to."

### Highlighting

Shared builder in `core-ui` produces a Compose `AnnotatedString`:

```kotlin
// core-ui/text/SearchHighlight.kt
fun highlightMatches(
    body: String,
    query: String,
    activeOccurrence: Int?,        // non-null when this message holds active match
    base: SpanStyle,
    matchBg: Color,
    activeBg: Color,
): AnnotatedString
```

Matching is case-insensitive, literal (not regex), Unicode-normalized (NFC) substring matching to align with backend behavior. The message item composable from AND-123 gains an optional `searchQuery`/`activeOccurrence` parameter; when null it renders exactly as before (no behavior change when search is closed).

## 5. API Contract

> **CORRECTED throughout this section.** The earlier draft described a wrapped
> `{conversation_id, query, total, results[...]}` envelope with `body` and
> `highlights` fields at `/conversations/{id}/...`. None of that matches the
> backend. The real contract follows.

**Request** (verified against OpenAPI `search_messages_in_conversation_...`):

```
GET /messaging/conversations/{conversation_id}/messages/search?q={query}&limit=50
Authorization: Bearer <accessToken>          (web sends this from the auth store)
X-CSRF-Token: <ui_csrf cookie value>         (web echoes the ui_csrf cookie on every request, incl. GET)
Cookie: <session cookies>                     (web uses credentials:"include")
```

`{conversation_id}` is the open conversation id. `q` is the URL-encoded trimmed
query, **required**, constrained `minLength: 1, maxLength: 200`. `limit` is
optional, **default 50**, `minimum: 1, maximum: 200` (CORRECTED: the earlier
draft assumed a default of 200; the server default is 50, and 200 is the *max*,
so the client should pass `limit=200` explicitly if it wants the larger cap).

Additional **optional** query params exist on this endpoint (not used by this
ticket, but available): `sender_id` (string, ≤64 chars), `after_ts`
(integer ≥0, epoch), `kind` (array of strings). They may be wired later for
filtered search; out of scope for AND-151.

Auth header note: the OpenAPI declares optional `authorization` and
`X-SESSION-ID` headers. The web client (`src/api/client.ts`) actually sends
`Authorization: Bearer <token>`, `X-CSRF-Token` (from the `ui_csrf` cookie),
and session cookies via `credentials: "include"`. The Android client reuses
core-network's existing auth/cookie/CSRF transport (see §8) — it does not
hand-roll headers here.

**Response 200** — a **bare JSON array** of `MessageOut` objects (NO envelope,
NO `total`, NO `query` echo, NO `highlights`). Example:

```json
[
  {
    "conversation_id": "conv_abc123",
    "message_id": "msg_0001",
    "sender_id": "user_42",
    "created_at": 1746210060,
    "kind": "text",
    "text": "we deploy to prod after the deploy freeze"
  }
]
```

Verified `MessageOut` facts: `required` = `[conversation_id, message_id,
sender_id, created_at, kind]`; the message body is the **nullable** `text`
field (NOT `body`); `created_at` is an **integer epoch** (NOT an ISO string);
there are **no** per-occurrence highlight offsets. `total` is therefore derived
client-side as the count of returned items (after local-match flattening), and
all highlight spans are computed locally from `text` + `query` using the §4
matcher. Messages whose `text` is null (e.g. media/sticker `kind`s) cannot
contain a textual match and are dropped during flattening.

**Retrofit**

```kotlin
interface ConversationSearchApi {
    @GET("messaging/conversations/{conversationId}/messages/search")
    suspend fun search(
        @Path("conversationId") conversationId: String,
        @Query("q") query: String,
        @Query("limit") limit: Int = 200,   // pass 200 explicitly; server default is 50
    ): List<MessageOutDto>                   // bare array, no wrapper
}
```

```kotlin
@JsonClass(generateAdapter = true)
data class MessageOutDto(
    @Json(name = "conversation_id") val conversationId: String,
    @Json(name = "message_id") val messageId: String,
    @Json(name = "sender_id") val senderId: String,
    @Json(name = "created_at") val createdAt: Long,   // epoch integer, NOT Instant/ISO
    val kind: String,
    val text: String? = null,                          // nullable; the message body
    // ...other MessageOut fields reused from AND-123's message DTO as needed
)
// NOTE: MessageSearchResponseDto / MessageSearchHitDto / HighlightDto from the
// earlier draft DO NOT EXIST in the contract and have been removed. If AND-123
// already defines a MessageOut DTO, reuse it instead of MessageOutDto above.
```

The call is wrapped to return `ApiResult<List<MessageOutDto>>` via the project's
`safeApiCall` so the `detail` error shape is mapped uniformly. The repository
flattens hits into an ordered `List<MessageSearchMatch>` by computing local
occurrences in each `text`, sorted by `created_at` asc, then `occurrenceIndex`.

**Error `detail` shape (verified).** Validation errors (422) return
`HTTPValidationError { detail: ValidationError[] }`, where each `ValidationError`
has `loc[]`, `msg`, `type`. Other handlers may return `detail` as a plain string
or an object with a `code`. The web client's `normalizeErrorDetail`
(`src/api/client.ts`) handles all three shapes (`string | [{msg}] | {code,...}`),
which is the contract `safeApiCall` must mirror.

**Errors:** 401 -> the shared core-network transport does one
`POST /ui/session/refresh` (verified endpoint: 200, empty body) then retries
the original request once (this mirrors web `client.ts`; not re-implemented
here). 404 (conversation gone) -> surfaced as `SearchPhase.Error`. 422 (bad
query, e.g. `q` empty or >200 chars) -> mapped to inline hint. NOTE: the
OpenAPI documents only `200` and `422` for this operation; `404`/`5xx` are
inferred platform behaviors, not declared in the schema (see §16 open
assumptions).

## 6. Data & State Management

- **No persistence.** Search results are transient and **not** written to Room. The Thread message cache (Room, owned by AND-123) is the only durable store; search reads message bodies from the cached/loaded thread for highlighting and never mutates it.
- **In-memory only:** `matches`, `activeIndex`, `phase`.
- **SavedStateHandle:** `search_active` (Boolean), `search_query` (String), `search_active_index` (Int) survive config change. `matches` is *not* saved (re-fetched on restore if `search_active && query.length >= 2`); on restore the controller re-issues the search and restores `activeIndex` by clamping to the new result size.
- **DataStore:** not used by this ticket.
- **Single source of truth:** the active match drives both highlight emphasis and scroll via the same `StateFlow`; there is no separate scroll state to keep in sync.
- **Idempotent GET:** the search endpoint is a read; eligible for the bounded backoff retry policy for idempotent GETs (see §7).

## 7. Error Handling & Resilience

- **Timeouts:** the unreliable dev host uses the project-wide ~20s call timeout. A spinner shows in the search bar while `phase == Loading`.
- **Retry:** search is an idempotent GET, so it uses the bounded backoff retry (max 2 retries, jittered) for transient failures (timeout, 5xx, IOException). Non-idempotent retries are not applicable.
- **flatMapLatest cancellation:** rapid typing cancels in-flight calls; only the latest query result is applied, preventing flicker/stale counts.
- **Empty / no results:** `phase = Loaded`, `matches = []`, status "0 results", nav disabled — not an error.
- **Network error:** `SearchPhase.Error("Couldn't search — tap to retry")` with a retry affordance; previous highlights are cleared. Offline is treated as a retryable error (no cached search).
- **Jump-out-of-range:** if `indexOfMessage` exhausts the page-load cap, show a one-time snackbar "Match is too far back to jump to" and keep the cursor advanced to the next reachable match.
- **Stale offsets:** CORRECTED — the backend returns no offsets, so there is nothing to be stale. Highlight spans are always computed locally from the message `text`. If a returned message's `text` is null, or local matching finds no occurrence (e.g. the server's tokenized match diverges from a literal substring search), that hit is dropped from `matches`.

## 8. Security & Privacy

- **Auth:** reuses the cookie-based session (persistent cookie jar) and `X-CSRF-Token` echo established in core-network. No new auth surface.
- **Transport:** dev backend is plaintext HTTP; the existing `network_security_config` cleartext allowance for the dev host applies. No additional secrets handled by this feature. Production builds must use HTTPS (inherited platform requirement).
- **No PII at rest:** search queries and results are not persisted to disk, DataStore, or logs (see §10). Query text stays in memory + SavedStateHandle (in-process bundle only).
- **Injection:** `q` is sent as a URL query parameter (Retrofit `@Query` handles encoding); local highlight matching is literal substring (no regex compilation of user input), avoiding ReDoS.
- **Authorization:** scoping by `{id}` means a user can only search conversations the backend already authorizes; no client-side trust decisions.

## 9. Accessibility & i18n

- All controls have `contentDescription`: search icon ("Search in conversation"), close ("Close search"), next ("Next match"), previous ("Previous match").
- The status text ("M of N", "0 results") is announced via `liveRegion = LiveRegionMode.Polite` so screen-reader users hear the count and active-match changes.
- On active-match change, the scrolled-to message requests accessibility focus so TalkBack reads the active match.
- Highlight emphasis does not rely on color alone for the active match: the active match also gets a subtle bold weight / underline so it is distinguishable in high-contrast and color-blind modes. Contrast of `matchBg`/`activeBg` against text meets WCAG AA in both light and dark Material 3 themes.
- Touch targets for nav chevrons >= 48dp.
- All user-facing strings (hints, statuses, error messages, content descriptions) are `stringResource` entries in `feature-thread` `strings.xml`; counts use plurals (`R.plurals.search_results`). No hardcoded strings.

## 10. Telemetry & Logging

- **Events** (via the project analytics interface, no PII): `conversation_search_opened`, `conversation_search_executed { query_length, result_count, latency_ms }`, `conversation_search_match_navigated { direction }`, `conversation_search_jump_failed { reason }`, `conversation_search_closed`. **The raw query string is never logged** — only its length.
- **Logging:** debug-only `Timber.d` for phase transitions and resolved scroll index; redact query at all levels. No query/body content in release logs.
- **Metrics of interest:** search latency on the unreliable host, retry rate, jump-failure rate (informs §13 paging decisions).

## 11. Testing Strategy

Owned partly by AND-150-style discipline but specified here for this feature.

**Unit (core-testing + JUnit + Turbine):**
- `ThreadSearchController`: debounce coalesces rapid input to one call; `< 2` chars issues no call; blank clears results; `flatMapLatest` drops stale results (assert only last query applied); `next`/`prev` wrap correctly; `activeIndex` resets to 0 on new results and to -1 on empty.
- `highlightMatches`: case-insensitive, multiple occurrences, active vs inactive styling, no-match returns base string, Unicode NFC normalization, out-of-bounds offset fallback.
- Repository flattening: multi-occurrence message -> ordered matches; sort by `created_at` then `occurrenceIndex`.
- DTO Moshi round-trip incl. missing `highlights` (defaults to empty -> local compute).
- Error mapping: 422 -> inline hint; 404 -> Error; 5xx -> retry then Error.

**Instrumented / Compose UI tests:**
- Typing a known term shows "M of N" and highlights the expected nodes (assert highlighted semantics).
- Tapping next scrolls the active match into view: assert the target message node `isDisplayed()` after navigation (**directly validates the acceptance bullet "Finds + scrolls to matches"**).
- Wrap-around: next from last selects first.
- Close restores normal app bar and removes highlight semantics.
- Rotation preserves query and active match.

**Fakes:** `FakeConversationSearchApi` returns deterministic fixtures (incl. multi-occurrence, far-back message requiring paging, empty, error). MockWebServer used for retry/timeout/401-refresh integration.

## 12. Dependencies & Sequencing

- **Hard dependency: AND-123** — requires the Thread screen, its `LazyListState`, paged message list, message domain model, and message item composable. This ticket cannot start until AND-123's list + paging are merged.
- **Shared output for AND-152:** `core-ui/text/SearchHighlight.kt` and the debounced-query pattern are authored here and reused by Global search (AND-152). Coordinate so AND-152 consumes rather than forks them.
- **No backend dependency to build:** `/conversations/{id}/messages/search` is assumed to exist on the dev backend; confirm via `/openapi.json` at implementation start (§13).
- **Sequencing:** (1) core-network API + DTOs + repository flatten; (2) `ThreadSearchController` + tests; (3) `ThreadSearchBar` UI + highlight integration; (4) scroll/jump + paging-extension; (5) instrumented tests.

## 13. Risks & Open Questions

1. **Endpoint shape — NOW VERIFIED (was an open question).** Confirmed against OpenAPI: path is `GET /messaging/conversations/{conversation_id}/messages/search`; the 200 response is a bare `MessageOut[]` array; the body field is `text` (nullable), `created_at` is an epoch integer; there are **no** highlight offsets, **no** envelope, and **no** pagination cursor (only `limit`, default 50 / max 200). There is no frontend reference call for this endpoint (`conversations.ts` does not exist). Residual uncertainty: the unit of `created_at` (seconds vs milliseconds) — assumed seconds; confirm at integration (see §16).
- 2. **Jump to far-back matches vs reverse paging.** A match older than the loaded window requires extending Paging 3 loads (capped at 10). For very deep threads this may fail to reach the target. Open question: should the backend return a stable index/cursor so we can deep-link the page directly? Mitigated by the "too far back" snackbar for now.
3. **Auto-re-search on live append.** Out of scope: when new messages arrive mid-search the counts only refresh on the next query change. Risk of mildly stale counts; acceptable for P1.
4. **Highlight offset drift** if a cached message body differs from the backend's indexed body (edited message). Mitigated by local-match fallback (§7).
5. **Very common terms** could return large result sets; bounded by `limit` (max 200; the client passes 200 explicitly since the server default is only 50). The backend returns a bare array with no `total` and no truncation flag, so the client cannot distinguish "exactly 200 matches" from "200+ truncated". If the array length equals the requested `limit`, the status should optimistically show "200+" as a best-effort signal. There is no server-side truncation indicator to rely on.
6. **Match granularity** — backend may return per-message hits without per-occurrence offsets; client computes occurrences locally, which could diverge from server tokenization (e.g., diacritics). Accepted; NFC normalization reduces divergence.

## 14. Acceptance Criteria

1. **Finds matches** — Entering a >=2-char query for the open conversation calls `GET /messaging/conversations/{conversation_id}/messages/search?q=...&limit=200` (CORRECTED path) and the search bar reports the correct match count ("M of N" / "0 results"). *(maps to source: "Finds … matches")*
2. **Scrolls to matches** — Tapping next/previous makes the active match scroll into view (target message node displayed) with distinct active-match emphasis. *(maps to source: "scrolls to matches")*
3. Highlighting renders for every matching message; active vs inactive matches are visually distinct (and not by color alone).
4. Next/previous wrap around; nav controls disabled at zero results; IME search action advances to next match.
5. Debounce: rapid typing issues a single network call for the settled query; stale responses never overwrite newer ones.
6. Queries < 2 chars / blank issue no network call and clear highlights.
7. Closing search restores the normal Thread app bar and removes all highlights without crashing.
8. Query + active match survive rotation.
9. Network/timeout failure shows a retryable error state; the search GET retries with bounded backoff; 401 triggers exactly one session refresh + retry.
10. No raw query text appears in logs or telemetry (length only).

## 15. Definition of Done

- All §14 acceptance criteria pass.
- Code merged to `android-port` under `android/feature-thread`, `android/core-network`, `android/core-ui`, `android/core-model`, package base `com.testlogon.android`.
- Unit + Compose UI tests from §11 implemented and green in CI; the "next scrolls active match into view" instrumented test explicitly covers the acceptance bullet.
- `SearchHighlight` placed in `core-ui` and documented as the shared helper for AND-152.
- Endpoint schema verified against `/openapi.json`; DTOs match; `ApiResult`/`detail` error mapping wired through `safeApiCall`.
- No new lint/detekt warnings; all strings localized (incl. plurals); accessibility checks (content descriptions, live region, 48dp targets, AA contrast) pass.
- Telemetry events fire with no PII; verified in debug build.
- AND-123's message item composable renders unchanged when search is closed (no regression).

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer.

1. **Endpoint path & method.** Claim: search is `GET /conversations/{id}/messages/search`. VERDICT: **Corrected** → real path is `GET /messaging/conversations/{conversation_id}/messages/search`. SOURCE: OpenAPI `GET /messaging/conversations/{conversation_id}/messages/search` (op `search_messages_in_conversation_messaging_conversations__conversation_id__messages_search_get`).
2. **Query params.** Claim: `q` + `limit` (default 200). VERDICT: **Corrected** → `q` required (`minLength 1`, `maxLength 200`); `limit` optional, **default 50**, max 200; plus optional `sender_id`, `after_ts`, `kind`. SOURCE: OpenAPI same operation, `parameters`.
3. **Response envelope `{conversation_id, query, total, results[]}`.** VERDICT: **Corrected** → response is a bare `MessageOut[]` array; no envelope, no `total`, no `query` echo. SOURCE: OpenAPI same op, `responses.200.content.application/json.schema` = `array of #/components/schemas/MessageOut`.
4. **Message body field name `body` (string).** VERDICT: **Corrected** → field is `text` and is **nullable**. SOURCE: `components.schemas.MessageOut.properties.text` (anyOf string|null).
5. **`created_at` is an ISO-8601 string.** VERDICT: **Corrected** → `created_at` is an **integer** (Unix epoch). SOURCE: `components.schemas.MessageOut.properties.created_at` (type integer); `required` includes `created_at`.
6. **`highlights` offset array returned by backend.** VERDICT: **Corrected** → no `highlights` field exists on `MessageOut`; the client must compute all occurrence offsets locally. SOURCE: `components.schemas.MessageOut` (no highlight property); whole-spec grep for message-search `highlight` returns only unrelated Stories endpoints.
7. **`MessageOut` required fields.** Claim (implicit). VERDICT: **Verified** → `[conversation_id, message_id, sender_id, created_at, kind]`. SOURCE: `components.schemas.MessageOut.required`.
8. **Web reference `frontend/src/api/endpoints/conversations.ts` + `types.ts: MessageSearchResult`.** VERDICT: **Corrected** → neither exists. Messaging calls are in `src/api/endpoints/messaging.ts` (no `messages/search` call); global search is in `src/api/endpoints/search.ts` (covers only `/ui/search`); `src/api/types.ts` has no `MessageSearchResult`. The web app does not call this endpoint. SOURCE: `src/api/endpoints/messaging.ts` (grep `messages/search` → no match), `src/api/endpoints/search.ts`, `src/api/types.ts`.
9. **AND-152 global search endpoint `/messaging/messages/search`.** VERDICT: **Verified** (exists; out of scope here). SOURCE: OpenAPI `GET /messaging/messages/search` (op `search_messages_all_conversations_...`).
10. **CSRF echo on GET via `X-CSRF-Token` from `ui_csrf` cookie.** VERDICT: **Verified** → web sets `X-CSRF-Token` from the `ui_csrf` cookie on every request regardless of method. SOURCE: `src/api/client.ts` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`).
11. **Auth = cookie session only.** VERDICT: **Corrected / clarified** → web sends `Authorization: Bearer <accessToken>` **and** `X-CSRF-Token` **and** session cookies (`credentials: "include"`); OpenAPI declares optional `authorization` + `X-SESSION-ID` headers. Android reuses core-network transport. SOURCE: `src/api/client.ts` (lines building `Authorization` header + `credentials:"include"`); OpenAPI op `parameters` (header `authorization`, `X-SESSION-ID`).
12. **401 → one `POST /ui/session/refresh` then retry.** VERDICT: **Verified**. SOURCE: `src/api/client.ts` (`refreshSession()` → `POST /ui/session/refresh`, single retry); OpenAPI `POST /ui/session/refresh` (op `ui_session_refresh_...`, resp 200, empty body).
13. **Error `detail` shape `string | [{msg}] | {code,...}`.** VERDICT: **Verified**. SOURCE: `src/api/client.ts: normalizeErrorDetail`; OpenAPI `components.schemas.HTTPValidationError` (`detail: ValidationError[]`) and `components.schemas.ValidationError` (`loc, msg, type`).
14. **422 returned for bad query.** VERDICT: **Verified** (only `200` and `422` are declared for this op). SOURCE: OpenAPI same op, `responses` keys `200`, `422`.
15. **404 / 5xx handling.** VERDICT: **Unverified-assumption** → not declared in the OpenAPI op (only 200/422). Treated as generic platform/transport errors. SOURCE: OpenAPI op `responses` (no 404/5xx entry).
16. **Android framework choices** (Compose `LazyListState.animateScrollToItem`, `SavedStateHandle`, Paging 3, `liveRegion`/TalkBack focus, Moshi `@JsonClass`). VERDICT: **Verified — framework ref** (standard AndroidX APIs). SOURCE (framework refs): developer.android.com/jetpack/compose/lists#control-scroll-position; developer.android.com/topic/libraries/architecture/saving-states; developer.android.com/topic/libraries/architecture/paging/v3-overview; developer.android.com/jetpack/compose/accessibility (liveRegion/focus).

### Corrections made

- §1, §3, §5, §14: endpoint path corrected to `GET /messaging/conversations/{conversation_id}/messages/search` (was `/conversations/{id}/messages/search`).
- §5: response shape corrected from a wrapped `{conversation_id, query, total, results[]}` object to a bare `MessageOut[]` array; removed the fabricated `MessageSearchResponseDto`/`MessageSearchHitDto`/`HighlightDto` and replaced with `MessageOutDto`.
- §1/§3/§4/§5/§6/§7/§13: message body field corrected `body` → `text` (nullable); `created_at` corrected ISO-string → epoch integer (`Long`); `highlights` offsets removed (computed locally; nothing to be "stale").
- §3/§5/§13: `limit` corrected — server default is 50 (not 200); 200 is the max; client passes 200 explicitly. Added the `q` `maxLength 200` constraint and client-side cap.
- §2: removed the fabricated web references (`conversations.ts`, `types.ts: MessageSearchResult`); clarified the web app does not call this endpoint, so the native client is the first consumer.
- §8 left as-is for cookie/CSRF (verified) but §5 clarifies the additional `Authorization: Bearer` header the web client sends.

### Open assumptions

- **`created_at` time unit (seconds vs milliseconds).** OpenAPI only says `integer`. Assumed epoch **seconds**. Why unverifiable: the schema carries no format/example; must be confirmed against a live response or AND-123's existing `MessageOut` mapping at integration.
- **404 / 5xx behavior.** Not declared in the op (only 200/422). Assumed standard platform errors; the retry/error path treats them generically. Why unverifiable: not in the OpenAPI for this operation.
- **Server match semantics vs local literal substring.** The backend decides which messages match (tokenization/diacritics) but returns no offsets; the client re-derives spans by case-insensitive NFC literal substring. Divergence (e.g. stemming) could yield a returned message with zero local occurrences (dropped). Why unverifiable: the backend's matching algorithm is not described in the schema.
- **Truncation signal for large result sets.** No `total`/truncation flag is returned; "200+" is a heuristic when array length == requested limit. Why unverifiable: not modeled in the response schema.
- **`X-SESSION-ID` header usage on Android.** OpenAPI lists it as optional and the web client does not send it (it relies on Bearer + cookies). Assumed the Android core-network transport mirrors the web (Bearer + cookies + CSRF). Why unverifiable: no Android core-network source in the reference set.

## 17. Test Plan

Test target legend — **JVM** (local JUnit/Robolectric, no device), **MWS** (MockWebServer contract test, JVM), **Emu35** (headless AVD `test35`, API 35 x86_64, CI), **Device** (physical Samsung Galaxy A15 5G `SM-A156U`, serial `R5CX821TA9R`, API 34 arm64-v8a). For this ticket no case strictly requires real hardware (no camera/biometrics/FCM/WebRTC), so UI/instrumented cases run on **Emu35** in CI; one case is designated **Device** to validate API-34/arm64 behavior and real animated scrolling.

- **TC-AND-151-01** — Happy path: finds + reports count.
  - Type: unit. Target: JVM (`ThreadSearchController` + `FakeConversationSearchApi`).
  - Preconditions: fake returns 3 `MessageOut` items with `text` containing the query.
  - Steps: open(); onQueryChange("deploy"); advance debounce 300ms.
  - Expected: exactly one API call to `…/messages/search?q=deploy&limit=200`; state `phase=Loaded`, `total=3` (derived from array length after local flatten), `activeIndex=0`, `cursorLabel="1 of 3"`.
  - Traces: AC-1, AC-5.

- **TC-AND-151-02** — DTO/contract: bare `MessageOut[]` decodes; `text` null and `created_at` integer.
  - Type: contract/MockWebServer. Target: MWS (JVM).
  - Preconditions: MWS enqueues a 200 body that is a bare JSON array including one item with `"text": null` and `"created_at": 1746210060` and integer-typed timestamps.
  - Steps: call `ConversationSearchApi.search(...)`; flatten via repository.
  - Expected: Moshi decodes to `List<MessageOutDto>` (no wrapper); `createdAt` maps to `Long`; the null-`text` item is dropped during flatten; remaining matches sorted by `created_at` asc then `occurrenceIndex`.
  - Traces: AC-1.

- **TC-AND-151-03** — Local highlight computation (no server offsets).
  - Type: unit. Target: JVM (`highlightMatches` in core-ui).
  - Preconditions: body "we deploy to prod after the deploy freeze", query "deploy".
  - Steps: build `AnnotatedString` with activeOccurrence=1.
  - Expected: two spans at the two "deploy" occurrences (case-insensitive, NFC); the active occurrence uses `activeBg` + bold/underline (not color alone); non-matching text uses `base`; a no-match query returns the base string unchanged.
  - Traces: AC-3, AC-6.

- **TC-AND-151-04** — Debounce + flatMapLatest stale-drop.
  - Type: unit. Target: JVM (Turbine).
  - Preconditions: fake delays first response; second query issued before first resolves.
  - Steps: onQueryChange("dep"); onQueryChange("deploy") within 300ms; advance.
  - Expected: exactly one network call (for "deploy"); the in-flight "dep" call is cancelled; only "deploy" results are applied; counts never flicker to a stale value.
  - Traces: AC-5.

- **TC-AND-151-05** — Query length / blank gating + 200-char cap.
  - Type: unit. Target: JVM.
  - Preconditions: none.
  - Steps: onQueryChange("d"); onQueryChange("   "); onQueryChange("a".repeat(250)).
  - Expected: "d" and blank issue **no** call and clear matches/highlights ("Type at least 2 characters" hint for "d"); the 250-char input is trimmed/capped to ≤200 before sending (no 422 from over-length).
  - Traces: AC-6.

- **TC-AND-151-06** — Navigation wrap + nav disabled at zero.
  - Type: unit. Target: JVM.
  - Preconditions: 3 matches loaded.
  - Steps: next×3 then next; prev from index 0; then load a 0-result query.
  - Expected: next from last → index 0; prev from first → last; with 0 matches, next/prev are no-ops and nav controls are disabled; `activeIndex=-1`.
  - Traces: AC-4.

- **TC-AND-151-07** — 422 validation error → inline hint (real error shape).
  - Type: contract/MockWebServer. Target: MWS (JVM).
  - Preconditions: MWS enqueues 422 with `{"detail":[{"loc":["query","q"],"msg":"ensure this value has at most 200 characters","type":"value_error"}]}`.
  - Steps: run a search that the fake server rejects.
  - Expected: `safeApiCall` maps `detail[].msg` per the `string|[{msg}]|{code}` rule; surfaced as the inline hint (not a crash, not a generic error toast); no highlights rendered.
  - Traces: AC-6, AC-9.

- **TC-AND-151-08** — 401 → single `POST /ui/session/refresh` + retry.
  - Type: integration/MockWebServer. Target: MWS (JVM).
  - Preconditions: MWS enqueues 401, then 200 (`/ui/session/refresh`), then 200 array for the retried search.
  - Steps: issue a search while "authenticated".
  - Expected: exactly one refresh POST is made, the original GET is retried once and succeeds; results applied; a second consecutive 401 would log out (assert refresh is not looped).
  - Traces: AC-9.

- **TC-AND-151-09** — Offline / timeout → retryable error, bounded backoff.
  - Type: integration/MockWebServer. Target: MWS (JVM).
  - Preconditions: MWS set to no-response (socket timeout) / `SocketPolicy.DISCONNECT`.
  - Steps: issue a search on the flaky host; let the ~20s call timeout elapse (use a shortened timeout in test config).
  - Expected: the idempotent GET retries with jittered backoff up to 2 times; on continued failure `SearchPhase.Error("Couldn't search — tap to retry")` with retry affordance; previous highlights cleared; no cached search served.
  - Traces: AC-9.

- **TC-AND-151-10** — Compose UI: finds + scrolls active match into view (the acceptance bullet).
  - Type: Compose-UI / instrumented. Target: Emu35.
  - Preconditions: thread seeded (fake API) with a match far enough down to be off-screen; search open.
  - Steps: type a known term; assert "M of N"; tap "Next match".
  - Expected: the active match's message node `isDisplayed()` after `animateScrollToItem`; active match has distinct emphasis semantics; status text present.
  - Traces: AC-1, AC-2, AC-3.

- **TC-AND-151-11** — Compose UI: close restores app bar + clears highlights; rotation persists state.
  - Type: Compose-UI / instrumented. Target: Emu35.
  - Preconditions: an active search with a query + active match.
  - Steps: rotate device (recreate activity); assert query + activeIndex restored and search re-issued; then tap close.
  - Expected: after rotation, query text and active-match cursor survive (SavedStateHandle: `search_active`, `search_query`, `search_active_index`); after close, the normal Thread app bar returns, highlight semantics removed, list stays at current scroll position, no crash.
  - Traces: AC-7, AC-8.

- **TC-AND-151-12** — Accessibility checks.
  - Type: Compose-UI / instrumented (+ accessibility assertions). Target: Emu35.
  - Preconditions: search open with results.
  - Steps: inspect semantics of search icon, close, next, prev, and status text; verify nav chevron touch targets; verify live region.
  - Expected: contentDescriptions present ("Search in conversation"/"Close search"/"Next match"/"Previous match"); status uses `liveRegion = Polite`; chevron targets ≥48dp; active-match emphasis not color-only; scrolled-to active message requests a11y focus.
  - Traces: AC-3, AC-2.

- **TC-AND-151-13** — Security/privacy: no raw query in logs/telemetry; literal (non-regex) matching.
  - Type: unit. Target: JVM.
  - Preconditions: telemetry + Timber captured via test trees; query contains regex metacharacters e.g. `.*(a|b)`.
  - Steps: run a search; inspect emitted analytics events and captured logs; run the local matcher with the metacharacter query.
  - Expected: events (`conversation_search_executed`, etc.) carry only `query_length`/`result_count`/`latency_ms` — never the raw query; no query/`text` content in logs; the matcher treats the query as a literal substring (no regex compilation → no ReDoS), so `.*` matches the literal characters only.
  - Traces: AC-10, AC-6.

- **TC-AND-151-14** — Physical-device validation: real scroll-to on API 34 / arm64.
  - Type: instrumented/e2e. Target: **Device** (SM-A156U `R5CX821TA9R`, API 34, arm64-v8a) — MUST run on the physical device to confirm `animateScrollToItem` centering + transient pulse and arm64/API-34 behavior differ from the x86_64/API-35 emulator path.
  - Preconditions: app installed via adb on the device; a real conversation (or seeded fake) with a match requiring reverse-paging beyond the loaded window.
  - Steps: open search, query a far-back term, tap next until the paging-extension path triggers; observe scroll and the "too far back" cap behavior.
  - Expected: list extends pages (cap 10) and scrolls the active match centered; if cap exceeded, the one-time "Match is too far back to jump to" snackbar shows and the cursor advances to the next reachable match; no ANR/jank on real hardware.
  - Traces: AC-2.

### Coverage matrix

| AC (§14) | Covered by |
| --- | --- |
| AC-1 Finds matches + count | TC-01, TC-02, TC-10 |
| AC-2 Scrolls to matches | TC-10, TC-12, TC-14 |
| AC-3 Highlight every match, active distinct, not color-only | TC-03, TC-10, TC-12 |
| AC-4 Nav wrap; disabled at zero; IME next | TC-06 |
| AC-5 Debounce single call; no stale overwrite | TC-01, TC-04 |
| AC-6 <2 chars / blank → no call, clear | TC-03, TC-05, TC-07, TC-13 |
| AC-7 Close restores app bar, removes highlights | TC-11 |
| AC-8 Query + active match survive rotation | TC-11 |
| AC-9 Network/timeout retryable; bounded backoff; 401 one refresh | TC-07, TC-08, TC-09 |
| AC-10 No raw query in logs/telemetry | TC-13 |
