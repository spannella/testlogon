---
id: AND-151
title: In-conversation search
milestone: M3
epic: E21
priority: P1
size: M
status: draft
depends_on: [AND-123]
blocks: []
---

# AND-151 — In-conversation search

## 1. Overview & Goal

Add the ability to search the messages of a single open conversation thread, highlight every match in the rendered message list, and jump-to / scroll-to the next or previous match. This is the **in-conversation** (scoped) search experience that lives inside the Thread screen built in AND-123; it is distinct from AND-152 (cross-conversation *global* search) which has its own results screen.

The feature is invoked from the Thread screen top app bar (a search icon), opens an in-place search input ("find in conversation") bar, queries the backend endpoint `GET /conversations/{id}/messages/search`, renders a match count and prev/next navigation, highlights matching substrings inside message bubbles, and programmatically scrolls the `LazyColumn` so the active match is centered and visually emphasized.

Success is defined by the source acceptance bullet: **the feature finds matches and scrolls to them.** Concretely: typing a query returns the set of matching messages in the currently open thread, the UI reports `N` matches, tapping next/prev moves the active match cursor, and the message list scrolls the active match into view with a transient emphasis.

## 2. Context & References

- **Depends on:** AND-123 (`feature-thread`, Thread / message-list screen). This ticket extends the existing `ThreadScreen`, `ThreadViewModel`, and the reverse-paged `LazyColumn` produced there. The message item composable and message domain model from AND-123 are reused, not duplicated.
- **Sibling:** AND-152 (Global message search) owns the cross-conversation experience and `/messaging/messages/search`. Where this ticket and AND-152 share helpers (query debounce, highlight span builder), the shared code is placed in `core-ui` so AND-152 can consume it.
- **Web reference:** `frontend/src/api/endpoints/conversations.ts` (search call) and `frontend/src/api/types.ts` (`MessageSearchResult`). The native Moshi models mirror these field names exactly.
- **OpenAPI:** `GET /openapi.json` on the dev backend (`http://18.222.237.167:8000`) is the source of truth for the request/response schema; confirm field names against it during implementation (see §13 open questions).
- **Module layering:** `app -> feature-thread -> core-network, core-model, core-ui, core-data, core-testing`. Networking lives in `core-network`; the highlight span builder in `core-ui`; domain models in `core-model`.

## 3. Functional Requirements

1. **Entry point.** The Thread top app bar exposes a search action (magnifier icon, `contentDescription = "Search in conversation"`). Activating it switches the app bar into a search-input state with a back/close affordance.
2. **Query input.** A single-line text field accepts the query. Input is debounced (300 ms) before a network call is issued. Empty/blank queries clear results and highlights and issue no network call.
3. **Search execution.** On a non-blank debounced query the app calls `GET /conversations/{id}/messages/search?q=<query>` for the currently open conversation id. The query is trimmed; minimum effective length is 2 characters (shorter queries show an inline "Type at least 2 characters" hint and issue no call).
4. **Result reporting.** The search bar shows a status: `0 results`, `1 result`, `M of N` (active cursor / total), or a loading spinner while in flight.
5. **Match navigation.** Up (previous) and down (next) chevron buttons move the active-match cursor. Navigation wraps (next from last -> first; prev from first -> last). Buttons are disabled when there are zero matches. The keyboard "search"/IME action advances to the next match.
6. **Highlighting.** Every message that contains a match renders the matched substring(s) with a highlight background. The *active* match renders with a stronger/distinct emphasis color so it is distinguishable from the other (inactive) matches.
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
    val messageId: String,
    val occurrenceIndex: Int,   // nth hit inside this message's body
    val start: Int,             // char offset of hit start in message body
    val end: Int,               // char offset (exclusive)
    val createdAt: Instant,     // used for ordering + paging-target resolution
)
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

**Request**

```
GET /conversations/{id}/messages/search?q={query}&limit=200
Cookies: session + ui_csrf
Header:  X-CSRF-Token: <ui_csrf value>      (echoed; GET but client sends consistently)
```

`{id}` is the open conversation id. `q` is the URL-encoded trimmed query. `limit` bounds result volume for very common terms (default 200; see §13 re: pagination).

**Response 200** (field names mirror `frontend/src/api/types.ts`; verify against `/openapi.json`):

```json
{
  "conversation_id": "conv_abc123",
  "query": "deploy",
  "total": 3,
  "results": [
    {
      "message_id": "msg_0001",
      "created_at": "2026-05-02T18:21:00Z",
      "body": "we deploy to prod after the deploy freeze",
      "highlights": [{ "start": 3, "end": 9 }, { "start": 28, "end": 34 }]
    }
  ]
}
```

If the backend does not return `highlights` offsets, the client computes occurrences locally from `body` + `query` using the §4 matcher; `MessageSearchMatch` is built either way.

**Retrofit**

```kotlin
interface ConversationSearchApi {
    @GET("conversations/{id}/messages/search")
    suspend fun search(
        @Path("id") conversationId: String,
        @Query("q") query: String,
        @Query("limit") limit: Int = 200,
    ): MessageSearchResponseDto
}
```

```kotlin
@JsonClass(generateAdapter = true)
data class MessageSearchResponseDto(
    @Json(name = "conversation_id") val conversationId: String,
    val query: String,
    val total: Int,
    val results: List<MessageSearchHitDto>,
)
@JsonClass(generateAdapter = true)
data class MessageSearchHitDto(
    @Json(name = "message_id") val messageId: String,
    @Json(name = "created_at") val createdAt: Instant,
    val body: String,
    val highlights: List<HighlightDto> = emptyList(),
)
@JsonClass(generateAdapter = true)
data class HighlightDto(val start: Int, val end: Int)
```

The call is wrapped to return `ApiResult<MessageSearchResponseDto>` via the project's `safeApiCall` so the `detail` error shape (`string | [{msg}] | {code,...}`) is mapped uniformly. The repository flattens hits into ordered `List<MessageSearchMatch>` (sorted by `created_at` asc, then `occurrenceIndex`).

**Errors:** 401 -> the shared OkHttp authenticator does one `POST /ui/session/refresh` then retries (existing core-network behavior; not re-implemented here). 404 (conversation gone) -> surfaced as `SearchPhase.Error`. 422 (bad query) -> mapped to inline hint.

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
- **Stale offsets:** if backend `highlights` offsets are out of bounds for the (possibly edited) cached body, the client falls back to local matching; if local matching also finds nothing, that hit is dropped from `matches`.

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

1. **Endpoint shape unverified.** The exact response (field names, whether `highlights` offsets are returned, pagination cursor vs `limit`) must be confirmed against `/openapi.json` and `frontend/src/api/endpoints/conversations.ts`. If the schema differs, only the DTO + flatten layer changes. **Action:** verify before coding §5.
- 2. **Jump to far-back matches vs reverse paging.** A match older than the loaded window requires extending Paging 3 loads (capped at 10). For very deep threads this may fail to reach the target. Open question: should the backend return a stable index/cursor so we can deep-link the page directly? Mitigated by the "too far back" snackbar for now.
3. **Auto-re-search on live append.** Out of scope: when new messages arrive mid-search the counts only refresh on the next query change. Risk of mildly stale counts; acceptable for P1.
4. **Highlight offset drift** if a cached message body differs from the backend's indexed body (edited message). Mitigated by local-match fallback (§7).
5. **Very common terms** could return large result sets; bounded by `limit=200`. If trimmed, the status should indicate "200+"; confirm whether the backend signals truncation.
6. **Match granularity** — backend may return per-message hits without per-occurrence offsets; client computes occurrences locally, which could diverge from server tokenization (e.g., diacritics). Accepted; NFC normalization reduces divergence.

## 14. Acceptance Criteria

1. **Finds matches** — Entering a >=2-char query for the open conversation calls `GET /conversations/{id}/messages/search?q=...` and the search bar reports the correct match count ("M of N" / "0 results"). *(maps to source: "Finds … matches")*
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
