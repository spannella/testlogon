---
id: AND-123
title: Thread (message list) screen
milestone: M3
epic: E18
priority: P0
size: L
status: draft
depends_on: [AND-120]
blocks: [AND-124]
---

# AND-123 — Thread (message list) screen

## 1. Overview & Goal

The Thread screen is the conversation-detail surface of the TestLogon messaging
feature (epic E18, milestone M3). When a user taps a conversation in the
conversation-list screen (AND-121), the app navigates to this screen and renders
the full message history for that conversation, newest at the bottom, in the
familiar chat layout: a reverse-chronological, paged, infinitely scrolling list
with date separators, consecutive-sender grouping, and a "scroll to bottom"
affordance.

This ticket delivers the **read-only** thread experience: load the most recent
page of messages, paginate backward into history as the user scrolls up, append
newly arriving messages at the bottom, and present resilient loading / empty /
error / offline states. The message **composer and send path are explicitly out
of scope** and are owned by AND-124 (Send text message), which depends on this
ticket. The list surface built here (the `LazyColumn`, item models, and append
hook) is the substrate AND-124 plugs optimistic sends into.

Goal: a correct, performant, accessible thread reader that loads and paginates
history from the FastAPI backend, groups messages sensibly, and never strands
the user on a blank or frozen screen when the unreliable dev backend stalls.

## 2. Context & References

- **Module:** `feature-messaging` (Gradle module `:feature-messaging`), package
  `com.testlogon.android.feature.messaging.thread`. Consumes `:core-network`,
  `:core-model`, `:core-data`, `:core-ui`, `:core-testing`.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. Web reference:
  `frontend/src/api/endpoints/messaging.ts`, types `frontend/src/api/types.ts`.
- **Upstream (AND-120, hard dep):** provides `MessagingApi`, the message/
  conversation DTOs, and their Moshi adapters. This ticket consumes that
  contract and must not redefine DTOs.
- **Upstream patterns:** AND-122 establishes the Paging 3 + ViewModel pattern for
  the conversation list; this ticket mirrors that pattern for messages.
- **Downstream (AND-124, blocked):** the composer + optimistic send. This ticket
  exposes the append hook and item model AND-124 builds on.
- **Auth:** cookie-based session (`/ui/session/*`), CSRF echoed via
  `X-CSRF-Token`, persistent cookie jar, single `/ui/session/refresh` retry on
  401 — all handled centrally by the OkHttp interceptor stack from
  `:core-network` (AND-027 lineage). This screen issues only authenticated GETs.
- **Navigation:** single-Activity Navigation-Compose. Route
  `messaging/thread/{conversationId}` registered in the app nav graph.

## 3. Functional Requirements

1. **History load.** On entry the screen loads the most recent page of messages
   for `conversationId` and renders them with the newest message at the bottom,
   pinned to the bottom on first display.
2. **Reverse pagination.** Scrolling toward the top (older messages) triggers a
   prepend of the next older page until history is exhausted; an exhausted-history
   state shows no further spinner.
3. **Append of new messages.** Newer messages not yet shown (e.g. on
   refresh/poll, and later from AND-124's optimistic send) append at the bottom.
4. **Date separators.** A sticky/inline separator is inserted whenever the
   calendar day (device local time zone) changes between adjacent messages
   ("Today", "Yesterday", or a localized date).
5. **Sender grouping.** Consecutive messages from the same sender within a short
   window (≤ 5 min, same day) are visually grouped: avatar + sender name render
   only on the first message of the run; subsequent bubbles are tightly spaced.
6. **Self vs. other alignment.** Messages authored by the current user (from
   `GET /ui/me`) align trailing/end; others align leading/start.
7. **Scroll-to-bottom FAB.** A floating button appears when the list is scrolled
   away from the bottom; tapping it smooth-scrolls to the newest message. It
   shows an unread-since-scroll count badge when new messages arrive while the
   user is scrolled up.
8. **States.** Initial loading (skeleton/spinner), populated, empty
   ("No messages yet"), prepend-loading (top spinner), append/refresh error
   (inline banner), and full-screen error with retry — all distinct and testable.
9. **Top app bar.** Shows the conversation title/peer name and a back action.
10. **No composer.** The bottom composer area is intentionally absent in this
    ticket (AND-124).

## 4. Technical Design

### Layering & entry points

```kotlin
// feature/messaging/src/main/kotlin/com/testlogon/android/feature/messaging/thread/
ThreadRoute.kt        // composable bound to nav route, hoists VM
ThreadScreen.kt       // stateless content: Scaffold + LazyColumn + FAB
ThreadViewModel.kt    // StateFlow<ThreadUiState>, paging flow, intents
ThreadUiState.kt      // UI state + ThreadListItem sealed model
ThreadItemMapper.kt   // DTO -> ThreadListItem, separators + grouping
ThreadMessagesPagingSource.kt // PagingSource (or RemoteMediator) over MessagingApi
```

Navigation registration:

```kotlin
const val ARG_CONVERSATION_ID = "conversationId"
const val ROUTE_THREAD = "messaging/thread/{$ARG_CONVERSATION_ID}"
fun NavController.navigateToThread(id: String) =
    navigate("messaging/thread/$id")
```

### ViewModel

```kotlin
@HiltViewModel
class ThreadViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val repository: MessagingRepository,   // from :core-data
    private val sessionRepository: SessionRepository, // exposes current user id
) : ViewModel() {

    private val conversationId: String =
        checkNotNull(savedStateHandle[ARG_CONVERSATION_ID])

    val header: StateFlow<ThreadHeaderState>          // title/peer, load state

    /** Reverse-chronological paged history, mapped to grouped UI items. */
    val items: Flow<PagingData<ThreadListItem>> =
        repository.messageHistory(conversationId)     // Pager<String, MessageDto>
            .map { paging -> paging.map(itemMapper::toMessageItem) }
            .insertSeparators(::separatorOrNull)      // date separators
            .cachedIn(viewModelScope)

    fun onRetry()                 // retry full load
    fun onAppendNewMessages()     // pull newest after the visible head
    fun onScrolledToBottom(atBottom: Boolean)
}
```

### Paging

Use **Paging 3** with the backend's opaque cursor. Because the dev backend is a
poor source of truth for live freshness, the screen uses a network-only
`PagingSource` for backward history (cursor `before=<message_id>`), while the
**append-at-bottom** path is a separate, explicit `onAppendNewMessages()` call
(not a Paging append) so that AND-124 can inject optimistic items without
fighting the pager. Page size: `PagingConfig(pageSize = 30, prefetchDistance = 8,
initialLoadSize = 30, enablePlaceholders = false)`.

```kotlin
class ThreadMessagesPagingSource(
    private val api: MessagingApi,
    private val conversationId: String,
) : PagingSource<String, MessageDto>() {
    override suspend fun load(params: LoadParams<String>):
        LoadResult<String, MessageDto> { /* GET ?before=key&limit=size */ }
    override fun getRefreshKey(state: PagingState<String, MessageDto>): String? = null
}
```

`MessagingRepository.messageHistory(id)` returns
`Flow<PagingData<MessageDto>>`; the ViewModel maps DTO → `ThreadListItem` and
inserts separators so paging math stays in DTO space.

### UI items, separators, grouping

```kotlin
sealed interface ThreadListItem {
    val key: String
    data class DateSeparator(override val key: String, val label: String) : ThreadListItem
    data class Message(
        override val key: String,          // message id
        val id: String,
        val authorId: String,
        val authorName: String,
        val avatarUrl: String?,
        val body: String,
        val sentAt: Instant,
        val isOwn: Boolean,
        val isFirstInGroup: Boolean,       // show avatar/name
        val isLastInGroup: Boolean,        // bubble tail/spacing
        val deliveryState: DeliveryState,  // SENT (this ticket); SENDING/FAILED reserved for AND-124
    ) : ThreadListItem
}
```

Grouping is computed in `insertSeparators` neighbor context: `isFirstInGroup =
prev == null || prev.authorId != cur.authorId || gap > 5.minutes || dayChanged`.
A `DateSeparator` is inserted when `dayChanged` between neighbors.

### Compose surface

```kotlin
@Composable
fun ThreadScreen(
    header: ThreadHeaderState,
    items: LazyPagingItems<ThreadListItem>,
    onBack: () -> Unit,
    onRetry: () -> Unit,
)
```

`LazyColumn(reverseLayout = true, state = listState)`. With `reverseLayout`,
index 0 is the newest message at the visual bottom, so "scroll to bottom" is
`listState.animateScrollToItem(0)` and "at bottom" is
`listState.firstVisibleItemIndex == 0 && firstVisibleItemScrollOffset == 0`. The
prepend spinner renders as the last item (oldest end). Items keyed via
`items(count, key = { items[it]?.key })`; `contentType` distinguishes message vs.
separator for recycling. The scroll-to-bottom FAB visibility derives from a
`derivedStateOf { listState.firstVisibleItemIndex > 2 }`.

## 5. API Contract

All endpoints are defined and deserialized by **AND-120** (`MessagingApi`); this
ticket only consumes them. Authentication is the cookie/CSRF session; this screen
issues authenticated GETs only.

**History (reverse paged):**

```
GET /messaging/conversations/{conversation_id}/messages?limit=30&before=<message_id>
```

Response (shape per AND-120 / `frontend/src/api/types.ts`):

```json
{
  "items": [
    {
      "id": "msg_01HX...",
      "conversation_id": "conv_8f...",
      "author_id": "usr_42",
      "author_name": "Ada Lovelace",
      "avatar_url": "https://.../a.png",
      "body": "see you at 3",
      "created_at": "2026-06-05T14:32:10.000Z",
      "kind": "text"
    }
  ],
  "next_before": "msg_01HW...",
  "has_more": true
}
```

- `next_before == null` / `has_more == false` ⇒ history exhausted ⇒ paging
  `LoadResult.Page(prevKey = null)`.
- Newest page fetched with no `before`. Backward paging passes the previous
  page's `next_before`.

**Current user** (for `isOwn`): `GET /ui/me` (cached via `SessionRepository`).

**Conversation header** (title/peer): `GET /messaging/conversations/{id}` (from
AND-120) — read lazily for the app-bar title; falls back to the title passed via
nav args if available.

These GETs are idempotent ⇒ eligible for bounded backoff retry (Section 7).
`detail`-shaped FastAPI errors (`string | [{msg}] | {code,...}`) are normalized
to `ApiResult.Error` by the `:core-network` mapper.

## 6. Data & State Management

`ThreadUiState` is split so paging and chrome update independently:

```kotlin
data class ThreadHeaderState(
    val title: String = "",
    val isLoading: Boolean = true,
    val errorMessage: String? = null,
)
// list content carried by LazyPagingItems<ThreadListItem>.loadState
```

- **Source of truth:** the Paging `Flow<PagingData>` (`cachedIn(viewModelScope)`)
  survives config changes; `listState` is `rememberLazyListState()` (survives via
  Compose saver). `conversationId` comes from `SavedStateHandle`.
- **Caching (Room, optional but specified):** `:core-data` may back history with
  Room (`MessageEntity` keyed by `conversation_id`, `created_at`, `id`) so a
  reopened thread renders instantly from cache while a network refresh runs. If
  Room is wired, swap `PagingSource` for a `RemoteMediator`; the UI contract is
  unchanged. Prefs/DataStore are not used by this screen.
- **Append model:** `onAppendNewMessages()` fetches messages newer than the
  current head id and inserts them at index 0 of the backing store (or invalidates
  the pager when Room-backed). This is the explicit seam AND-124 reuses for
  optimistic items, so its `DeliveryState` field is present now though only `SENT`
  is produced by this ticket.
- **Read receipts / mark-as-read are out of scope** (separate ticket); unread
  badge here is the local "messages arrived while scrolled up" counter only.

## 7. Error Handling & Resilience

The dev backend is plaintext and unreliable; design for stalls.

- **Timeouts:** rely on the `:core-network` OkHttp client (~20s call timeout). No
  per-call override here.
- **Retry:** history GETs are idempotent ⇒ bounded exponential backoff (max 3
  attempts, jittered, ~250ms→2s) handled by the shared retry interceptor.
- **401:** the interceptor performs a single `POST /ui/session/refresh` then
  retries once; on continued 401 the screen surfaces a "session expired" state
  routing back to auth (no local handling needed beyond mapping the terminal
  error).
- **Initial load failure** (`loadState.refresh is LoadState.Error`): full-screen
  error with message + **Retry** (`items.retry()` / `onRetry()`).
- **Prepend failure** (`loadState.prepend is Error`): inline footer with a small
  retry chip; existing messages stay visible.
- **Append/refresh failure:** transient snackbar/banner ("Couldn't load new
  messages"), auto-dismiss; never clears the list.
- **Offline / no connectivity:** distinct empty-ish state "You're offline —
  showing cached messages" when Room cache exists, else an offline error with
  retry. Detected via the connectivity signal in `:core-data`.
- **Empty conversation:** `items.itemCount == 0 && refresh is NotLoading` ⇒
  "No messages yet" empty state (not an error).

## 8. Security & Privacy

- All requests carry the session cookie jar + `X-CSRF-Token` automatically; this
  screen never reads, logs, or persists credentials, cookies, or the CSRF token.
- Message bodies and avatar URLs are treated as untrusted: rendered as plain text
  (no HTML/markdown execution); avatars loaded via Coil with a non-credentialed
  image pipeline.
- If Room caching is enabled, the messages DB lives in app-private storage; no
  exported providers. No message content is written to logs (Section 10).
- `usesCleartextTraffic` is permitted only for the dev host via a debug network
  security config (inherited from `:core-network`); release builds remain
  HTTPS-only. This ticket adds no new cleartext exemption.

## 9. Accessibility & i18n

- All strings (state labels, "Today"/"Yesterday", FAB content description,
  retry) live in `strings.xml`; no hard-coded UI text. Date/time formatting via
  `java.time` + Android locale (`DateUtils.getRelativeTimeSpanString` or
  ICU `DateTimeFormatter` with the device locale and zone).
- RTL: list alignment uses start/end (not left/right); self-vs-other alignment
  flips correctly under RTL.
- TalkBack: each message exposes a merged semantics node reading
  "{sender}, {time}: {body}"; grouped messages still announce sender via the
  semantics even when the avatar/name is visually suppressed. The FAB has
  `contentDescription = "Scroll to latest messages"`; its unread badge is
  appended to the description.
- Touch targets ≥ 48dp (FAB, back). Dynamic type / font scaling respected via
  Material 3 typography (no fixed sp where avoidable). Honors reduced-motion by
  using `scrollToItem` instead of animated scroll when the system flag is set.

## 10. Telemetry & Logging

Via the app analytics abstraction in `:core-ui`/`:core-data` (no PII, no message
bodies):

- `thread_opened` { conversation_id_hash }
- `thread_history_page_loaded` { page_index, item_count, latency_ms }
- `thread_history_exhausted` { total_loaded }
- `thread_load_error` { phase: refresh|prepend|append, error_code }
- `thread_scroll_to_bottom_tapped` { unread_since_scroll }

Logging: structured `Timber` at debug for load-state transitions and paging keys
only; conversation ids are hashed/truncated, message bodies and author names are
never logged. No logging in release beyond crash breadcrumbs.

## 11. Testing Strategy

**Unit (`:feature-messaging` test, `:core-testing` fakes):**
- `ThreadItemMapper`: date-separator insertion across day boundaries
  (incl. Today/Yesterday and TZ at local midnight); sender grouping
  (`isFirstInGroup`/`isLastInGroup`) for same-sender runs, the 5-min gap break,
  and the day-change break; `isOwn` computed from current-user id.
- `ThreadMessagesPagingSource`: first page (no `before`), backward page (with
  `before`), `has_more=false` ⇒ `prevKey=null`, and error → `LoadResult.Error`.
  Use a `FakeMessagingApi` driven by JSON fixtures shared with AND-120.
- `ThreadViewModel`: `header` state transitions; `onAppendNewMessages` inserts at
  head; retry re-emits.

**Compose UI tests (`createAndroidComposeRule`, MockWebServer):**
- History renders newest-at-bottom; scroll up triggers prepend (assert second
  fixture page appears).
- New message appended at bottom appears after `onAppendNewMessages`.
- Scroll-to-bottom FAB shows when scrolled up, hidden at bottom, scrolls on tap,
  shows unread badge.
- Empty, initial-error+retry, prepend-error, and offline states each render with
  the expected testTag/semantics.

**Acceptance harness:** MockWebServer scripted with two history pages + an
appended message validates the two acceptance bullets end-to-end. A smoke test
against the live dev host is manual/optional (flaky host).

Coverage target: mapper and paging logic ≥ 90% line; ViewModel ≥ 80%.

## 12. Dependencies & Sequencing

- **Hard dependency — AND-120 (Messaging API + DTOs):** must land first;
  provides `MessagingApi`, `MessageDto`, and the `/messages` contract. This spec
  must not redefine those DTOs.
- **Upstream platform:** `:core-network` session/CSRF/retry stack (AND-027
  lineage); Paging 3 wiring conventions from AND-122.
- **Soft references:** AND-121 (conversation list) provides the navigation entry
  point and the title to pass into the route.
- **Blocks — AND-124 (Send text message):** consumes the list surface, the
  `ThreadListItem.Message.deliveryState` field, and `onAppendNewMessages()` seam
  introduced here.
- **Sequencing:** AND-120 → **AND-123** → AND-124. Can proceed in parallel with
  AND-121/AND-122 once AND-120 merges.

## 13. Risks & Open Questions

- **Reverse-layout vs. date separators:** sticky headers interact awkwardly with
  `reverseLayout = true`. Mitigation: inline (non-sticky) separators by default;
  revisit sticky only if UX requires it. *(Open: sticky required?)*
- **Cursor semantics:** confirm with AND-120/OpenAPI whether the cursor is
  `before=<message_id>` vs. a timestamp and whether `items` are returned ascending
  or descending — affects prepend mapping. *(Open, must verify against
  `/openapi.json` before coding.)*
- **Live freshness:** there is no push/websocket in M3, so "new messages append"
  relies on refresh/poll-on-resume + AND-124's optimistic path. *(Open: is a poll
  interval in scope, or only on-resume + send?)* Assumption: on-resume refresh +
  AND-124 append; no timer poll in this ticket.
- **Room caching optional:** spec supports both PagingSource and RemoteMediator;
  decision deferred to `:core-data` capacity. UI contract unaffected either way.
- **Unreliable host:** backoff + offline state mitigate, but UI test flakiness is
  a risk → all networked tests use MockWebServer, never the live host.

## 14. Acceptance Criteria

1. Opening a conversation loads and displays the most recent page of messages,
   newest pinned to the bottom (maps the AND-120 fixture payload). *(Acceptance:
   "History loads".)*
2. Scrolling to the top loads the next older page; repeating reaches an exhausted
   state with no further spinner once `has_more=false`. *(Acceptance:
   "paginates".)*
3. A new message (via `onAppendNewMessages` from a MockWebServer fixture) appears
   appended at the bottom without reloading the list. *(Acceptance: "new messages
   append".)*
4. Adjacent messages on different calendar days are separated by a date
   separator with localized Today/Yesterday/date labels.
5. Consecutive messages from one sender within 5 minutes are grouped (avatar/name
   shown once); a >5-min gap or day change breaks the group.
6. Own messages align end; others align start, derived from `GET /ui/me`.
7. The scroll-to-bottom FAB appears when scrolled up, scrolls to newest on tap,
   and shows an unread-since-scroll badge; it is hidden at the bottom.
8. Initial-load error shows a full-screen retry that recovers on success;
   prepend/append errors keep existing messages visible; empty and offline states
   render distinctly.
9. No composer/send UI is present (deferred to AND-124).
10. Unit + Compose tests in Section 11 pass in CI; mapper/paging coverage meets
    targets.

## 15. Definition of Done

- Code merged to `android-port` under `:feature-messaging`, package
  `com.testlogon.android.feature.messaging.thread`, building on Kotlin 2.0.21 /
  AGP 8.7.3 / Gradle 8.9, compileSdk/targetSdk 35, minSdk 24, JDK 17.
- Nav route `messaging/thread/{conversationId}` registered and reachable from the
  conversation list (AND-121).
- ViewModel exposes `StateFlow`/`Flow<PagingData>` per the layering rules; Hilt
  graph compiles with KSP; no DTOs redefined (consumes AND-120).
- All Section 14 acceptance criteria verified by the Section 11 test suite; CI
  green (unit + Compose + lint/detekt).
- No hard-coded strings; TalkBack reading verified; RTL verified; reduced-motion
  honored.
- No PII/message bodies in logs or telemetry; no new cleartext exemption beyond
  the dev-host debug config.
- `onAppendNewMessages()` seam and `DeliveryState` field documented for AND-124
  hand-off; open questions in Section 13 resolved or filed as follow-ups.
- Spec reviewed by a feature owner and a platform/`:core-network` owner.
