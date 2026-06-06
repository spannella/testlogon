---
id: AND-123
title: Thread (message list) screen
milestone: M3
epic: E18
priority: P0
size: L
status: reviewed
reviewed_on: 2026-06-06
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
- **Auth:** the web client uses a *hybrid* scheme (verified against
  `src/api/client.ts`): an `Authorization: Bearer <accessToken>` header **plus**
  the session cookie jar (`credentials: "include"`) **plus** a CSRF token read
  from the `ui_csrf` cookie and echoed as `X-CSRF-Token`. On a 401 for an
  already-authenticated user it performs a single `POST /ui/session/refresh`
  then retries the request once; a continued 401 logs out (`session_expired`).
  The OpenAPI contract for `/messaging/...` lists `authorization` + `X-SESSION-ID`
  (+ `X-API-Key`) as the accepted credentials. The Android port handles all of
  this centrally in the OkHttp interceptor stack from `:core-network`
  (AND-027 lineage). This screen issues only authenticated GETs.
  *(Correction: the prior draft described this as "cookie-based session" only and
  omitted the `Authorization: Bearer` header.)*
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

Response (shape **corrected** against `src/api/endpoints/messaging.ts:getMessages`
and the `Message` DTO in `src/api/types.ts:1098`). The web client tolerates **two
shapes** the backend may return — a bare array, or an object wrapper — and the
cursor field is **`next_cursor`** (NOT `next_before`, and there is NO `has_more`):

```jsonc
// Shape A (object wrapper):
{
  "messages": [
    {
      "message_id": "msg_01HX...",     // NOT "id"
      "conversation_id": "conv_8f...",
      "sender_id": "usr_42",           // NOT "author_id"; there is NO author_name/avatar_url on a message
      "kind": "text",
      "created_at": 1749134730,        // epoch SECONDS (number), NOT an ISO string
      "text": "see you at 3"           // NOT "body"
    }
  ],
  "next_cursor": "msg_01HW..."         // absent/null ⇒ history exhausted
}
// Shape B: a bare JSON array of the same message objects, with no cursor wrapper.
```

- **Sort order (verified):** the backend returns each page **newest→oldest**;
  the web client reverses each page (`.slice().reverse()`) and concatenates pages
  oldest→newest. The Android `PagingSource` must account for this when mapping to
  a `reverseLayout` list.
- `next_cursor == null` (or a bare array with no wrapper) ⇒ history exhausted ⇒
  paging `LoadResult.Page(prevKey = null)`.
- Newest page fetched with no `before`. Backward paging passes the previous
  page's `next_cursor` as the `before` query param.
- **Display name / avatar gap (verified):** the message DTO carries only
  `sender_id` — no `author_name`/`avatar_url`. Sender display name and avatar must
  be resolved from the conversation's `participants` (see `ConversationOut`), or
  from a profile lookup; AND-120/AND-123 must wire this. The `ThreadListItem.Message`
  `authorName`/`avatarUrl` fields are therefore *derived*, not taken verbatim from
  the message payload.

**Current user** (for `isOwn`): the web client computes `isOwn` as
`msg.sender_id === userId`, where `userId` comes from the client auth store
(`ConversationView.tsx:1166`), not from a per-screen `GET /ui/me` call. `GET /ui/me`
*does* exist in the OpenAPI and is the appropriate Android source for the current
user id (cached via `SessionRepository`); confirm AND-027/AND-120 expose it.

**Conversation header** (title/peer): `GET /messaging/conversations/{id}` (from
AND-120) — read lazily for the app-bar title; falls back to the title passed via
nav args if available.

These GETs are idempotent ⇒ eligible for bounded backoff retry (Section 7).
FastAPI errors are `detail`-shaped (verified): the canonical 422 is
`HTTPValidationError = { detail: ValidationError[] }` where
`ValidationError = { loc: (string|int)[], msg: string, type: string }`; other
handlers return `detail` as a plain string. The `/messaging/*` endpoints also
declare 400/401/403/429 responses (and a `MessageControlsErrorOut` shape on the
controls sub-routes, not used by the read path). All of these are normalized to
`ApiResult.Error` by the `:core-network` mapper.

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
  Room (`MessageEntity` keyed by `conversation_id`, `created_at`, `message_id`;
  note the DTO field is `message_id`, not `id`, and `created_at` is epoch seconds)
  so a
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

- All requests carry the credentials assembled centrally by `:core-network` — the
  `Authorization: Bearer` token, the session cookie jar, and the `X-CSRF-Token`
  header (see corrected Section 2); this screen never reads, logs, or persists
  credentials, cookies, the access token, or the CSRF token.
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
- **Cursor semantics:** *RESOLVED during this review.* The OpenAPI declares the
  query param as `before` (alongside `limit`), and the web client passes the prior
  page's `next_cursor` (a `message_id`) as `before` — so the cursor is an opaque
  `before=<message_id>`, not a timestamp. Pages are returned **newest→oldest**;
  the web client reverses each page. One residual unknown: whether the wrapper is
  always present or sometimes a bare array (the client handles both) — treat both
  in the `PagingSource`. *(See corrected Section 5.)*
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer. Sources:
OpenAPI index = `reference/openapi.index.txt`; OpenAPI spec =
`reference/openapi.pretty.json` (`components.schemas.<Name>`); frontend paths are
relative to `reference/src/`.

1. **History endpoint is `GET /messaging/conversations/{conversation_id}/messages`.**
   VERIFIED. OpenAPI `GET /messaging/conversations/{conversation_id}/messages`
   (op `list_messages_...`); frontend `src/api/endpoints/messaging.ts: getMessages`.
2. **Query params are `limit` and `before` (opaque message-id cursor).**
   VERIFIED. OpenAPI params `conversation_id,limit,before,authorization,X-SESSION-ID,X-API-Key`;
   `src/api/endpoints/messaging.ts: getMessages` passes `{ before: cursor }`.
3. **Response shape is `{ items, next_before, has_more }` with message
   `{ id, author_id, author_name, avatar_url, body, created_at(ISO), kind }`.**
   CORRECTED. The OpenAPI declares the 200 body with no named schema, but the
   frontend (`src/api/endpoints/messaging.ts: getMessages`) shows the real shape:
   either a bare `Message[]` or `{ messages: Message[]; next_cursor?: string }`.
   The cursor field is **`next_cursor`**; there is no `has_more`/`next_before`/`items`
   on this endpoint. (`items/next_before/has_more` belongs to the *separate*
   `GET /messaging/threads/{thread_id}/messages` → `ThreadMessagesPageOut`, not used here.)
4. **Message DTO field names.** CORRECTED. `src/api/types.ts: Message` (line 1098)
   and `src/api/endpoints/messagingAdapter.ts: adaptMessage`: fields are
   `message_id` (not `id`), `conversation_id`, `sender_id` (not `author_id`),
   `kind`, `created_at` as **epoch seconds (number)** (not ISO string), `text`
   (not `body`). There is **no** `author_name` or `avatar_url` on the message.
5. **Sender display name / avatar source.** CORRECTED/clarified. Not on the
   message DTO; must be derived from conversation `participants`
   (OpenAPI `ConversationOut.participants`, schema in `openapi.pretty.json`).
6. **Page sort order (affects prepend mapping).** VERIFIED. `ConversationView.tsx`
   (~line 211–216) reverses each page (`.slice().reverse()`) and concatenates
   pages oldest→newest ⇒ backend returns each page **newest→oldest**.
7. **Pagination exhaustion = `next_cursor` absent ⇒ `prevKey = null`.** VERIFIED
   (mapped). `ConversationView.tsx` `getNextPageParam: (lastPage) => lastPage.next_cursor ?? undefined`.
8. **`isOwn` derives from `GET /ui/me`.** CORRECTED/clarified. The web client
   computes `isOwn = msg.sender_id === userId` from the auth store
   (`ConversationView.tsx:1166`), not a `/ui/me` call. `GET /ui/me` *does* exist
   (OpenAPI `GET /ui/me`) and is the right Android source for the current user id.
9. **Conversation header via `GET /messaging/conversations/{id}` provides a title.**
   VERIFIED. OpenAPI `GET /messaging/conversations/{conversation_id}` →
   `ConversationOut`, which has a `title` field (+ `participants`, `participant_count`).
10. **Auth is cookie-based session + `X-CSRF-Token`, single `/ui/session/refresh`
    retry on 401.** CORRECTED (incomplete). `src/api/client.ts`: sends
    `Authorization: Bearer <accessToken>` **and** `credentials: "include"` cookies
    **and** `X-CSRF-Token` from the `ui_csrf` cookie. On 401 for an authenticated
    user it calls `POST /ui/session/refresh` once and retries once; continued 401
    logs out. `/messaging/*` OpenAPI params list `authorization,X-SESSION-ID,X-API-Key`.
11. **`POST /ui/session/refresh` is the refresh endpoint and is a POST.** VERIFIED.
    OpenAPI `POST /ui/session/refresh`; `src/api/client.ts: refreshSession`.
12. **FastAPI errors are `detail`-shaped (`string | [{msg}] | {code,...}`).**
    CORRECTED (made precise). Canonical 422 is `HTTPValidationError = { detail:
    ValidationError[] }`, `ValidationError = { loc, msg, type }`
    (`openapi.pretty.json` schemas `HTTPValidationError`, `ValidationError`);
    other handlers return `detail` as a plain string. `/messaging/*` also declares
    400/401/403/429.
13. **Composer/send is out of scope (AND-124).** VERIFIED as a scope assertion;
    the send endpoint exists (`POST /messaging/conversations/{conversation_id}/messages`
    → `SendTextMessageIn`/`MessageOut`) and is intentionally not consumed here.
14. **Paging 3 / LazyColumn `reverseLayout` / `derivedStateOf` / `cachedIn`.**
    Framework choices — not verifiable from backend/frontend sources. (framework ref:
    developer.android.com/topic/libraries/architecture/paging/v3-overview;
    developer.android.com/jetpack/compose/lists.)
15. **No push/websocket in M3 ⇒ "new messages append" via refresh/poll + AND-124.**
    UNVERIFIED-ASSUMPTION (project/milestone scope, not in the provided sources).

### Corrections made

- **C1 (Section 5):** Replaced the fabricated `{ items, next_before, has_more }`
  response with the real dual shape (`Message[]` or `{ messages, next_cursor }`)
  and the `next_cursor` cursor field.
- **C2 (Section 5/6):** Corrected message field names — `id`→`message_id`,
  `author_id`→`sender_id`, `body`→`text`, `created_at` ISO string → epoch seconds
  (number) — and flagged that `author_name`/`avatar_url` do not exist on the
  message and must be derived from `participants`.
- **C3 (Section 5):** Documented the verified page sort order (newest→oldest per
  page) so the `reverseLayout` mapping is correct.
- **C4 (Section 2 & 8):** Corrected the auth model to the hybrid
  Bearer-token + cookies + CSRF scheme used by `client.ts` (prior draft said
  "cookie-based" only).
- **C5 (Section 5):** Made the FastAPI error description precise
  (`HTTPValidationError`/`ValidationError`).
- **C6 (Section 5):** Clarified `isOwn` derivation (auth-store id in web; `/ui/me`
  for Android) — prior draft over-claimed a per-screen `/ui/me` dependency.
- **C7 (Section 13):** Marked the "cursor semantics" open question RESOLVED.

### Open assumptions

- **OA1 — Response wrapper variability.** The backend may return a bare array or
  an object wrapper (the web client handles both); the OpenAPI 200 body is
  unschematized. The `PagingSource` must defensively handle both. *Why unverifiable:*
  the index/spec leave the 200 body schema empty for this op.
- **OA2 — `isOwn` source on Android.** Web uses the auth store; whether AND-027/
  AND-120 expose the current user id via `SessionRepository` or require a live
  `GET /ui/me` is an upstream-contract assumption. *Why:* depends on unbuilt
  Android modules, not in these sources.
- **OA3 — Live freshness / poll interval.** No push/websocket in M3 is a
  milestone-scope assumption not present in the API/frontend sources. *Why:* scope
  decision, not a code fact.
- **OA4 — Sender name/avatar resolution path.** Whether to read from
  `ConversationOut.participants` vs. a profile endpoint is an AND-120 design call.
  *Why:* the message DTO omits these fields; the resolution strategy isn't fixed
  in the reference sources.
- **OA5 — Room/RemoteMediator decision.** Deferred to `:core-data` capacity
  (Section 6); not a backend fact.

## 17. Test Plan

Test-target legend: **JVM** = local JVM/Robolectric unit; **MWS** =
contract/integration with MockWebServer (JVM or `test35`); **emu test35** =
headless x86_64 API-35 AVD; **A15** = physical Samsung Galaxy A15 5G (SM-A156U,
arm64-v8a, API 34). Networked UI/instrumented suites use MockWebServer, never the
flaky live dev host (Section 13).

- **TC-AND-123-01 — Happy-path history load (newest pinned to bottom).**
  Type: contract/MockWebServer + Compose-UI. Target: emu test35 (MWS).
  Preconditions: MWS scripted to return one page for
  `GET /messaging/conversations/{id}/messages` (no `before`) as
  `{ messages:[...8 msgs newest→oldest], next_cursor:"msg_p2" }`.
  Steps: launch `ThreadRoute` with `conversationId`; await refresh `NotLoading`.
  Expected: 8 messages render mapped via `message_id/sender_id/text/created_at`;
  newest is at the visual bottom (`reverseLayout`, index 0); list pinned to bottom.
  Traces: AC-1.

- **TC-AND-123-02 — Reverse pagination + exhaustion.**
  Type: contract/MockWebServer + Compose-UI. Target: emu test35 (MWS).
  Preconditions: page 1 `next_cursor:"msg_p2"`; page 2 requested with
  `?before=msg_p2` returns a bare array (Shape B) with no cursor (exhausted).
  Steps: scroll toward top to trigger prepend; assert page-2 items appear; scroll
  again. Expected: page-2 request carries `before=msg_p2`; older items prepend at
  the oldest end; once the array/`next_cursor==null` is seen, `prevKey=null` and
  no further prepend spinner shows. Traces: AC-2.

- **TC-AND-123-03 — Append of newer messages without reload.**
  Type: unit + Compose-UI. Target: JVM (mapper/VM) + emu test35 (MWS).
  Preconditions: populated list; MWS fixture for a newer message.
  Steps: invoke `onAppendNewMessages()`. Expected: the new message is inserted at
  index 0 (bottom) and appears without a full refresh; existing items unchanged.
  Traces: AC-3.

- **TC-AND-123-04 — Date separators across day boundaries (incl. Today/Yesterday,
  TZ at local midnight).** Type: unit. Target: JVM (Robolectric for locale/zone).
  Preconditions: `ThreadItemMapper` with fixtures spanning two calendar days in a
  fixed device zone, including a message right at local midnight.
  Steps: map + `insertSeparators`. Expected: a `DateSeparator` is emitted between
  adjacent messages on different local days; labels localize to Today/Yesterday/date.
  Traces: AC-4.

- **TC-AND-123-05 — Sender grouping (5-min gap + day-change breaks).**
  Type: unit. Target: JVM.
  Preconditions: same-sender run within 5 min; a >5-min gap; a day change.
  Steps: map and inspect `isFirstInGroup`/`isLastInGroup`.
  Expected: grouped within ≤5 min same day (avatar/name once); group breaks on
  >5-min gap or day change. Traces: AC-5.

- **TC-AND-123-06 — Self vs. other alignment from current user id.**
  Type: unit + Compose-UI. Target: JVM + emu test35.
  Preconditions: current user id = `usr_42`; fixture mixes `sender_id usr_42` and
  others. Steps: map (`isOwn = sender_id == currentUserId`) and render.
  Expected: own messages align end/trailing; others align start/leading.
  Traces: AC-6.

- **TC-AND-123-07 — Scroll-to-bottom FAB visibility, scroll, and unread badge.**
  Type: Compose-UI. Target: emu test35.
  Preconditions: populated list scrolled up; then a new message appended while
  scrolled up. Steps: scroll up (FAB appears), append (badge increments), tap FAB.
  Expected: FAB hidden at bottom, visible when scrolled up; tap smooth-scrolls to
  newest and clears badge; unread-since-scroll count is correct. Traces: AC-7.

- **TC-AND-123-08 — Initial-load error → full-screen retry recovers.**
  Type: contract/MockWebServer + Compose-UI. Target: emu test35 (MWS).
  Preconditions: first `GET .../messages` returns 500 (or `detail`-string error);
  a queued second response returns a valid page. Steps: open screen (full-screen
  error shows), tap Retry. Expected: `loadState.refresh` Error renders full-screen
  error + Retry; `onRetry()`/`items.retry()` re-requests and the list populates.
  Traces: AC-8.

- **TC-AND-123-09 — Prepend/append errors keep existing messages visible.**
  Type: Compose-UI. Target: emu test35 (MWS).
  Preconditions: page 1 OK; page-2 (`before=...`) returns error; separately an
  append fails. Steps: scroll to trigger prepend (fails); trigger append (fails).
  Expected: prepend shows an inline retry chip at the oldest end; append shows a
  transient banner/snackbar ("Couldn't load new messages"); the existing list is
  never cleared. Traces: AC-8.

- **TC-AND-123-10 — Empty conversation state.**
  Type: contract/MockWebServer + Compose-UI. Target: emu test35 (MWS).
  Preconditions: `GET .../messages` returns `[]` (or `{messages:[]}` no cursor).
  Steps: open screen. Expected: `itemCount==0 && refresh NotLoading` ⇒
  "No messages yet" empty state (not an error). Traces: AC-8.

- **TC-AND-123-11 — Offline / flaky-host path.**
  Type: instrumented/e2e. Target: **A15 (physical device — MUST)**.
  Rationale: real radio toggling + OkHttp DNS/connect failures behave differently
  from an emulator's virtual NIC; exercise on the arm64 API-34 device.
  Preconditions: a thread previously cached (if Room wired); enable airplane mode.
  Steps: open the thread offline; then restore connectivity and retry.
  Expected: offline shows "You're offline — showing cached messages" when cache
  exists, else an offline error with retry; no crash; retry recovers when online.
  Traces: AC-8.

- **TC-AND-123-12 — 401 → single `/ui/session/refresh` retry, then terminal.**
  Type: contract/MockWebServer. Target: JVM/emu test35 (MWS).
  Preconditions: MWS returns 401 for the messages GET; `POST /ui/session/refresh`
  scripted (a) 200 then a 200 retry of the GET, and (b) a second 401 path.
  Steps: drive both. Expected: on (a) exactly one refresh POST then one GET retry
  that succeeds; on (b) a single refresh, continued 401 surfaces a terminal
  "session expired" state routing to auth. No infinite retry loop. Traces: AC-8.

- **TC-AND-123-13 — No composer/send UI present; no credentials logged.**
  Type: Compose-UI + unit. Target: emu test35 + JVM.
  Preconditions: populated screen; Timber test tree capturing logs.
  Steps: assert no composer/input/send affordance exists; perform a load and
  inspect logs. Expected: no bottom composer node; logs contain no message bodies,
  author names, raw cookies, access token, or CSRF token (conversation id hashed).
  Traces: AC-9 (and Section 8/10 security).

- **TC-AND-123-14 — Accessibility: TalkBack semantics, touch targets,
  reduced-motion, RTL.** Type: instrumented/e2e (a11y). Target: **A15 (physical
  device — PREFER; real TalkBack engine)**.
  Preconditions: populated thread; enable TalkBack; set system reduced-motion;
  switch to an RTL locale. Steps: traverse messages and the FAB.
  Expected: each message announces "{sender}, {time}: {body}" (grouped messages
  still announce sender); FAB `contentDescription` "Scroll to latest messages"
  with unread count appended; FAB/back ≥48dp; reduced-motion uses non-animated
  `scrollToItem`; alignment flips correctly under RTL. Traces: AC-7, AC-6
  (and Section 9).

### Coverage matrix (Section-14 AC → test cases)

| AC | Description | Covered by |
|----|-------------|-----------|
| AC-1 | History loads, newest pinned to bottom | TC-AND-123-01 |
| AC-2 | Reverse pagination to exhaustion | TC-AND-123-02 |
| AC-3 | New message appends without reload | TC-AND-123-03 |
| AC-4 | Date separators (Today/Yesterday/date) | TC-AND-123-04 |
| AC-5 | Sender grouping (5-min/day-change break) | TC-AND-123-05 |
| AC-6 | Self/other alignment from current user | TC-AND-123-06, TC-AND-123-14 |
| AC-7 | Scroll-to-bottom FAB + unread badge | TC-AND-123-07, TC-AND-123-14 |
| AC-8 | Error/empty/offline states distinct + retry | TC-AND-123-08, TC-AND-123-09, TC-AND-123-10, TC-AND-123-11, TC-AND-123-12 |
| AC-9 | No composer/send UI | TC-AND-123-13 |
| AC-10 | Unit + Compose tests pass; coverage targets | TC-AND-123-01…14 (suite) |
