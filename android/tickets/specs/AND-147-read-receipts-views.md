---
id: AND-147
title: Read receipts / views
milestone: M3
epic: E20
priority: P1
size: M
depends_on: [AND-144]
blocks: []
status: reviewed
reviewed_on: 2026-06-06
---

# AND-147 — Read receipts / views

## 1. Overview & Goal

This ticket adds per-message **delivery and read (seen) receipts** to the
TestLogon Android messaging experience. When the local user opens a thread and a
message scrolls into view, the client reports the view to the backend
(`POST /messaging/conversations/{conversation_id}/messages/{message_id}/view`);
when the counterpart(s) view a message authored by the local user, the client
reflects **delivered / seen markers** on those outbound messages. The viewer
roster for a single message is read on demand via `GET
/messaging/conversations/{conversation_id}/messages/{message_id}/views`.

> **[Corrected in review]** Both endpoints are **conversation-scoped** — they
> include a `{conversation_id}` path segment (verified against OpenAPI
> `POST /messaging/conversations/{conversation_id}/messages/{message_id}/view`
> and the matching `/views` GET, and against the web client
> `src/api/endpoints/messaging.ts: markViewed/getViewers`). The earlier
> draft's flat `/messaging/messages/{message_id}/...` paths do not exist.

The defining acceptance criterion is **"Receipts update live."** Receipt state
must change in real time over the messaging SSE stream established in AND-144 —
without the user leaving and re-entering the thread — and must survive the
unreliable dev backend (host blips, 20s timeouts, reconnects) by reconciling
idempotently against the authoritative server state.

Goal: an outbound message visibly transitions `sending → sent → delivered →
seen`, an inbound message in an open thread is reported as viewed once, and a
"Seen by" detail sheet (groups) or inline "Seen" marker (DMs) renders the live
viewer roster.

Out of scope: unread-count badges and `POST /conversations/{id}/read`
(owned by **AND-125**); typing indicators (**AND-146**); presence/online dots
(**AND-145**); the SSE transport itself (**AND-143**) and the messaging event
dispatch fabric (**AND-144**); cross-cache reconciliation primitives reused here
(**AND-148**).

## 2. Context & References

- **Stack:** Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow,
  Retrofit 2.11 / OkHttp 4.12 / Moshi 1.15, Room 2.6, Paging 3. minSdk 24,
  compileSdk/targetSdk 35, JDK 17, AGP 8.7.3.
- **Module layering:** `app → feature-messaging → core-network, core-model,
  core-data, core-ui, core-testing`. ViewModels expose `StateFlow<UiState>`; all
  network calls return typed `ApiResult<T>`.
- **Namespace:** `com.testlogon.android` everywhere a package appears.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. Cookie-based auth +
  `ui_csrf` cookie echoed as `X-CSRF-Token`; on 401, client refreshes once via
  `POST /ui/session/refresh` then retries. **[Verified, with addenda]** The web
  client (`src/api/client.ts`) sends `Authorization: Bearer <token>` (from the
  auth store) **and** `X-CSRF-Token` (from `ui_csrf`) with `credentials:
  include`; the two view endpoints additionally accept optional `authorization`
  and `X-SESSION-ID` headers (OpenAPI params). The Android client should mirror
  Bearer + cookie + CSRF; `X-SESSION-ID` is optional. Refresh endpoint confirmed
  as `POST /ui/session/refresh` (`src/api/client.ts`).
- **Web reference:** `frontend/src/api/endpoints/*.ts`,
  `frontend/src/api/types.ts` (verify exact `view`/`views` field names against
  `/openapi.json` before finalizing DTOs).
- **Upstream deps:**
  - **AND-144 (depends_on)** — supplies `MessagingEventBus`: a hot
    `SharedFlow<MessagingEvent>` of typed SSE events. AND-147 adds a new sealed
    subtype (`MessagingEvent.MessageViewed`) and a dispatch path for it.
  - **AND-123** (transitively) — Thread screen + paged `LazyColumn` whose
    visibility signals drive view reporting.
  - **AND-148** — provides the merge/ordering helpers; AND-147 writes receipt
    columns through the same cache without introducing duplicate rows.

## 3. Functional Requirements

FR-1 **View reporting (outbound report).** When a message authored by *another*
user becomes ≥ 50% visible in the open thread for ≥ 400 ms while the app is
foregrounded, the client reports a single view via `POST
/messaging/conversations/{conversation_id}/messages/{message_id}/view`. Each
message is reported **at most once
per process lifetime** (in-memory dedupe set + Room `viewReportedAt` guard).
The web reference uses an `IntersectionObserver` at `threshold: 0.5` (the 50%
basis) and marks once per element mount, skipping own and optimistic messages
(`src/pages/messages/ReadReceipts.tsx: ViewTracker`); the **400 ms dwell** and
the stronger **once-per-process** guard are Android-side hardening choices not
present in the web client (unverified-assumption — see §16).

FR-2 **Delivered marker.** An outbound message shows a **delivered** marker once
the backend confirms delivery. **[Corrected in review]** Delivery is carried by
the **message payload fields** `delivered_to_count` / `delivered_to_user_ids`
(verified `src/api/types.ts: Message`); there is **no** dedicated SSE
`message.delivered` event in the reference transport (the web stream only handles
`message:viewed` — see `src/hooks/useMessagingStream.ts`). The client derives
DELIVERED from `delivered_to_count > 0` on the refreshed message row. DMs show a
single delivered tick; groups show delivered when ≥ 1 recipient has it
(`delivered_to_count ≥ 1`). This resolves Open Question Q2.

FR-3 **Seen marker (live).** An outbound message shows a **seen** marker when a
counterpart reports a view. This MUST update live via SSE while the thread is
open, with no manual refresh. **[Corrected in review]** The SSE event type is
**`message:viewed`** (colon-delimited), not `message.viewed`; its `data` carries
`message_id`, `viewer_id`, and `viewed_at` (verified
`src/hooks/useMessagingStream.ts`). The authoritative "seen" count on an outbound
message also surfaces in the message payload fields `read_by_count` /
`read_by_user_ids` (verified `src/api/types.ts: Message`). The web reference
reacts to `message:viewed` by **invalidating** the `message-views` and `messages`
caches (a refetch), rather than mutating local state from the event body; the
Android client may instead apply the event optimistically, but MUST treat the
server fields as authoritative on the next fetch.

FR-4 **DM vs group semantics.**
- DM: outbound bubble renders a state glyph `sending → sent → delivered → seen`
  plus, when seen, a relative "Seen 2m ago".
- Group: outbound bubble renders aggregate state; tapping a small
  "Seen by N" affordance opens a **viewer roster sheet** populated from `GET
  /messaging/conversations/{conversation_id}/messages/{message_id}/views`.

FR-5 **Viewer roster.** The roster sheet lists each viewer, sorted most-recent
first, and updates live while open as new `message:viewed` events arrive for that
message. **[Corrected in review]** The `/views` response is a **bare JSON array
of `MessageViewOut`** with fields `{ user_id, last_viewed_at, view_count }` only
(verified OpenAPI schema `MessageViewOut` and `src/api/types.ts: MessageViewer`).
It does **not** include `display_name` or `avatar_url` — the client must resolve
display name/avatar for each `user_id` from a separate participant/profile cache
(the web reference renders only `user_id` initials). The endpoint takes a `limit`
query param (default 200, max 500) and has **no cursor / pagination** — so the
roster is a single bounded fetch, not a paged stream (see corrections to §5/§6).

FR-6 **No self-receipts.** The local user's own views never render as "seen by
me", and the local user never appears in their own outbound message's roster.

FR-7 **Lifecycle.** View reporting pauses on background (`ON_STOP`) and resumes
on `ON_START`; messages already on screen at resume are re-evaluated for
reporting (subject to the once-per-lifetime guard).

FR-8 **Offline / stale.** When offline or the report POST fails, the inbound
message is queued for a single retry on reconnect (idempotent); receipt markers
read from cache render with the last known state and no error toast.

## 4. Technical Design

New code lives in `feature-messaging` and `core-data`/`core-model`; the API
surface extends the existing `MessagingApi` from AND-120.

### 4.1 Domain model (`core-model`)

```kotlin
enum class ReceiptStatus { SENDING, SENT, DELIVERED, SEEN, FAILED }

data class MessageReceipt(
    val messageId: String,
    val status: ReceiptStatus,
    val deliveredAt: Instant?,
    val seenAt: Instant?,        // earliest view for groups
    val seenCount: Int,          // distinct viewers excluding self
)

data class MessageViewer(
    val userId: String,
    val displayName: String,
    val avatarUrl: String?,
    val viewedAt: Instant,
)
```

### 4.2 Repository (`core-data`)

```kotlin
interface ReceiptsRepository {
    /** Idempotent; no-op if already reported this lifetime. */
    suspend fun reportView(messageId: String): ApiResult<Unit>

    /** Live receipt state for a message, backed by Room + SSE. */
    fun receiptFlow(messageId: String): Flow<MessageReceipt>

    /** Viewer roster, paged; refreshes on MessageViewed events. */
    fun viewersFlow(messageId: String): Flow<PagingData<MessageViewer>>

    /** Apply an SSE MessageViewed/Delivered event to the cache. */
    suspend fun applyReceiptEvent(event: MessagingEvent)
}
```

`ReceiptsRepositoryImpl` is `@Singleton`, Hilt-bound in
`MessagingDataModule`. It:
- holds a `Collections.synchronizedSet<String>` of reported message ids;
- collects `MessagingEventBus.events.filterIsInstance<MessageViewed/Delivered>()`
  in an app-scoped coroutine and calls `applyReceiptEvent`;
- writes receipts to `MessageEntity` columns (no new table) and viewers to a new
  `MessageViewerEntity`.

### 4.3 Event subscription

AND-144's `MessagingEventDispatcher` is extended to decode two new SSE event
types into `MessagingEvent.MessageViewed` and `MessagingEvent.MessageDelivered`,
which `ReceiptsRepositoryImpl` consumes. No second SSE connection is opened —
this rides the single stream from AND-143/144.

### 4.4 ViewModel

```kotlin
@HiltViewModel
class ThreadReceiptsViewModel @Inject constructor(
    private val repo: ReceiptsRepository,
) : ViewModel() {
    /** Called by the thread when a message's visibility crosses threshold. */
    fun onMessageVisible(messageId: String, authoredByMe: Boolean) {
        if (authoredByMe) return
        viewModelScope.launch { repo.reportView(messageId) }
    }
    fun receipt(messageId: String): StateFlow<MessageReceipt?> = ...
    fun openViewers(messageId: String) { ... }   // emits roster sheet UiState
}
```

### 4.5 Compose

A `LazyListState`-derived `derivedStateOf` computes visible item keys; a
`LaunchedEffect` keyed on the visible set debounces 400 ms and calls
`onMessageVisible`. Outbound bubbles render `ReceiptGlyph(status)`. Group bubbles
render `SeenByChip(seenCount)` opening `ViewerRosterSheet` (Material 3
`ModalBottomSheet`).

## 5. API Contract

> **[Heavily corrected in review]** The draft contract below was wrong on every
> shape. The corrected contract is verified against OpenAPI ops
> `mark_message_viewed_...` / `get_message_views_...`, schemas `ViewMessageIn`,
> `ViewAckOut`, `MessageViewOut`, and the web client
> `src/api/endpoints/messaging.ts` + `src/api/types.ts`.

Two REST endpoints, both **conversation-scoped** (base path `/messaging`):

**Report a view (idempotent on server):**
```
POST /messaging/conversations/{conversation_id}/messages/{message_id}/view
Headers: Authorization: Bearer <token>; X-CSRF-Token: <ui_csrf>
         (cookies carry session; optional X-SESSION-ID)
Body (ViewMessageIn): { "viewed_at": 1749124800 }   // optional epoch int, may be null/omitted
200 OK (ViewAckOut):
{ "ok": true, "conversation_id": "c_1", "message_id": "msg_123",
  "viewer_id": "u_self", "viewed_at": 1749124800 }
```
Note: `viewed_at` is an **integer epoch timestamp**, NOT an ISO-8601 string. The
ack echoes `conversation_id`, `message_id`, `viewer_id`, `ok`.

**Read viewer roster (idempotent GET — retryable with bounded backoff):**
```
GET /messaging/conversations/{conversation_id}/messages/{message_id}/views?limit=200
200 OK — a BARE JSON ARRAY of MessageViewOut (no envelope object):
[
  { "user_id": "u_9", "last_viewed_at": 1749124801, "view_count": 3 }
]
```
There is **no** `views`/`delivered_to`/`next_cursor` envelope, **no** cursor
pagination (only `limit`, default 200, max 500), and **no** `display_name` /
`avatar_url` in the payload — resolve identity from a participant/profile cache.
`last_viewed_at` and `view_count` are integers.

**Delivered/seen on outbound messages** are NOT a separate endpoint: they are
fields on the `Message` DTO returned by the message-list endpoint —
`delivered_to_count`, `delivered_to_user_ids`, `read_by_count`,
`read_by_user_ids` (`src/api/types.ts: Message`).

**SSE event (over the AND-144 stream):**
```json
{ "type": "message:viewed",
  "data": { "message_id": "msg_123", "viewer_id": "u_9",
            "viewed_at": 1749124801 } }
```
The event type is **`message:viewed`** (colon), and the actor field is
**`viewer_id`** (not `user_id`). There is **no `message.delivered` SSE event**
in the reference stream; delivery state comes from the `Message` fields above.

Moshi DTOs (`core-network`): `ViewAckOut` (report response), `MessageViewOut`
(roster element; deserialize a `List<MessageViewOut>`), `ViewMessageIn` (optional
report body), and the `MessageViewedEvent` SSE DTO. Retrofit:

```kotlin
@POST("messaging/conversations/{cid}/messages/{id}/view")
suspend fun reportView(
    @Path("cid") conversationId: String,
    @Path("id") messageId: String,
    @Body body: ViewMessageIn = ViewMessageIn(viewedAt = null),
): Response<ViewAckOut>

@GET("messaging/conversations/{cid}/messages/{id}/views")
suspend fun getViews(
    @Path("cid") conversationId: String,
    @Path("id") messageId: String,
    @Query("limit") limit: Int = 200,
): Response<List<MessageViewOut>>
```

FastAPI validation errors return **422** with an `HTTPValidationError`
(`{ "detail": [{ "loc", "msg", "type" }] }`) — verified as the only declared
error response for both endpoints besides 200. The shared error mapper handles
the string | `[{msg}]` | `{code,...}` shapes into `ApiResult.Error`. **Open
Question Q1 is now resolved**: all field/endpoint names above are verified against
the live OpenAPI; `@Json(name=...)` remains the single point of change if the
backend later renames anything.

## 6. Data & State Management

Room (`core-data`), schema-migrated additively:
- `MessageEntity` gains: `receiptStatus TEXT`, `deliveredAt INTEGER?`,
  `seenAt INTEGER?`, `seenCount INTEGER NOT NULL DEFAULT 0`,
  `viewReportedAt INTEGER?` (local once-guard).
- New `MessageViewerEntity(messageId, userId, displayName, avatarUrl,
  viewedAt, viewCount)`, PK `(messageId, userId)` — composite key gives natural
  idempotent upsert (no duplicate viewers on event replay).
  **[Note from review]** `displayName`/`avatarUrl` are **not** returned by
  `/views` (which yields only `user_id`, `last_viewed_at`, `view_count` — see §5);
  they are populated by joining `user_id` against the participant/profile cache at
  write time, and may be null until resolved. `viewedAt` maps to the API's
  `last_viewed_at` (epoch int).

```kotlin
@Dao interface ReceiptDao {
    @Query("SELECT receiptStatus, deliveredAt, seenAt, seenCount " +
           "FROM messages WHERE id = :id")
    fun observeReceipt(id: String): Flow<ReceiptProjection?>

    @Upsert suspend fun upsertViewers(rows: List<MessageViewerEntity>)

    @Query("SELECT * FROM message_viewers WHERE messageId = :id " +
           "ORDER BY viewedAt DESC")
    fun pagingViewers(id: String): PagingSource<Int, MessageViewerEntity>
}
```

State flow: SSE `message:viewed` → `applyReceiptEvent` upserts a viewer row and
recomputes `seenCount`/`seenAt`/`receiptStatus = SEEN` for the message → Room
emits → `receiptFlow` updates → Compose recomposes the bubble. The roster sheet
collects `pagingViewers` via Paging 3 over **local Room** so live upserts appear
without a refetch; note the **network** roster fetch is single-shot (server has
no cursor — §5), so Paging here pages the local cache only. Cache is the single
source of truth; the network layer only writes into it (consistent with AND-148).

## 7. Error Handling & Resilience

- **`reportView` failures** are silent to the user (no toast); the message is
  added to a bounded in-memory `pendingViews` queue and retried once on the next
  SSE reconnect (`onConnected`). The POST is **not** auto-retried on the same
  connection beyond one attempt, since the server treats repeats idempotently and
  a stale dev host should not be hammered.
- **`getViews` (idempotent GET)** uses bounded exponential backoff (e.g. 3
  attempts, base 500 ms, cap 4 s, jitter) under the standard ~20 s OkHttp call
  timeout. On exhaustion the roster sheet shows a "Couldn't load viewers — Retry"
  state, while cached viewers (if any) remain visible.
- **401** is handled by the shared OkHttp authenticator: one
  `POST /ui/session/refresh` then a single retry of the original request.
- **SSE drop:** receipt markers freeze at last-cached state (no spinner on
  bubbles); on reconnect, `applyReceiptEvent` replays buffered events
  idempotently (composite-key upsert → no double counting). Any seen state that
  was missed while disconnected is recovered lazily the next time `getViews` runs
  for that message.
- **Clock skew:** `viewed_at` from the server is authoritative for ordering;
  device time is never used for receipt timestamps.

## 8. Security & Privacy

- Receipts ride the existing cookie session; every mutating call
  (`POST .../view`) sends `X-CSRF-Token` from the `ui_csrf` cookie.
- **Plaintext dev host:** receipt payloads (who viewed what, and when) traverse
  HTTP in dev — flagged as a privacy risk acceptable only for the dev backend
  and gated behind `usesCleartextTraffic` limited to the dev host in the network
  security config (owned by core-network); production must be HTTPS.
- **Read-receipt visibility is a privacy-sensitive signal.** The client honors
  the server as the authority on whether a user's views are exposed; if the
  backend omits a viewer (e.g. recipient disabled receipts), the client renders
  no marker — it never infers "seen" from local heuristics. No client toggle is
  shipped in this ticket (Open Question Q3).
- Viewer rosters and `viewReportedAt` are stored only in the app-private Room DB;
  cleared on logout with the rest of the messaging cache.
- No receipt data is logged in release builds (see §10).

## 9. Accessibility & i18n

- Receipt glyphs have `contentDescription`: "Sending", "Sent", "Delivered",
  "Seen", "Failed to send" — never color-only (TalkBack must announce state).
- The "Seen by N" chip exposes role=Button with description "Seen by N people,
  double-tap to view".
- Roster sheet rows announce "<name>, viewed <relative time>".
- All strings (markers, relative-time, error states) live in
  `strings.xml`; counts use plurals (`<plurals name="seen_by_count">`);
  timestamps use `DateUtils.getRelativeTimeSpanString` for locale-correct
  formatting and respect RTL layout.
- Minimum touch target 48dp for the "Seen by" affordance.

## 10. Telemetry & Logging

- Structured events (debug + analytics sink, no PII in release):
  `receipt_view_reported{conversationId, succeeded}`,
  `receipt_seen_rendered{isGroup}`, `receipt_roster_opened{viewerCount}`,
  `receipt_report_retry{attempt}`.
- Logs **never** include the *identity* of viewers or message bodies; only
  hashed/opaque ids in debug builds, fully stripped in release via the shared
  Timber release tree.
- A counter for `getViews` backoff exhaustion helps quantify dev-host
  flakiness for AND-149 tuning.

## 11. Testing Strategy

Unit (JUnit + Turbine + MockWebServer, `core-testing`):
- `reportView` is sent exactly once per message despite repeated
  `onMessageVisible` calls (once-guard).
- A `message:viewed` SSE event upserts a viewer, increments `seenCount`, sets
  `receiptStatus = SEEN`; a **duplicate** event is idempotent (count unchanged) —
  proves the composite-key upsert.
- `getViews` retries on 503 with backoff then succeeds; surfaces error state on
  exhaustion while keeping cached viewers.
- Self-view events are filtered (FR-6).
- 401 triggers one refresh + retry.

Instrumented / Compose (`createComposeRule`):
- Outbound bubble transitions `sent → delivered → seen` when fake events are
  injected into the `MessagingEventBus` test fake — asserts **live** update
  (acceptance criterion) with no recomposition gap.
- Visibility-driven reporting: scrolling an inbound message into view triggers
  one `reportView`; scrolling away/back does not re-report.
- Roster sheet renders viewers and updates live on a new event.

Determinism: SSE is driven by an in-memory `FakeMessagingEventBus`; no real
network. All tests run headlessly in CI.

## 12. Dependencies & Sequencing

- **Hard dep: AND-144** — must land first; AND-147 extends its event sealed
  hierarchy and dispatcher. Implement after AND-144 is merged.
- **Transitive: AND-123** (thread/list UI hooks), **AND-120** (`MessagingApi`
  base + DTO conventions), **AND-143** (SSE transport).
- **Soft / parallel: AND-148** (reconciliation) — share the same cache-write
  path; coordinate the additive Room migration to avoid conflicting schema
  versions. AND-147 should adopt AND-148's merge helper if merged first;
  otherwise provide a minimal idempotent upsert that AND-148 later subsumes.
- **Sibling, non-blocking:** AND-145 (presence), AND-146 (typing) share the
  bubble/footer UI region — coordinate layout slots in `feature-messaging` to
  avoid churn.
- **Does not block** any ticket (`blocks: []`).

## 13. Risks & Open Questions

- **Q1 — Exact field/endpoint names — RESOLVED (this review).** Paths are
  conversation-scoped; report body is `ViewMessageIn { viewed_at?: int }`; ack is
  `ViewAckOut { ok, conversation_id, message_id, viewer_id, viewed_at:int }`;
  roster is `List<MessageViewOut { user_id, last_viewed_at:int, view_count:int }>`
  (no `seen_at`, no `delivered_to` envelope, no cursor); SSE type is
  `message:viewed` with `viewer_id`. All verified against the OpenAPI and web
  client (see §16). Residual rename risk stays mitigated by Moshi `@Json`.
- **Q2 — Delivered semantics — RESOLVED (this review).** The backend does **not**
  emit a distinct `message.delivered`/`message:delivered` SSE event (the
  reference stream handles only `message:viewed`). DELIVERED is derived from the
  `Message` payload fields `delivered_to_count` / `delivered_to_user_ids`; SEEN
  from `read_by_count` / `read_by_user_ids`. DM = single tick when
  `delivered_to_count ≥ 1`; group = delivered when ≥ 1 recipient.
- **Q3 — Receipt opt-out.** Does the backend support per-user "disable read
  receipts"? If so, a future ticket (M8 settings) should add the toggle; this
  ticket only honors whatever the server exposes.
- **Q4 — Dev-host flakiness** may make "live" updates look intermittent in
  manual testing; reconnect replay (AND-149) mitigates but cannot fully hide a
  down host. Acceptance is validated against the fake bus, not the live host.
- **Risk — high-volume groups:** large rosters / rapid view storms could thrash
  Room; mitigated by paging the roster and batching viewer upserts per event
  tick.

## 14. Acceptance Criteria

AC-1 (**primary — "Receipts update live"**): With a thread open, injecting a
`message:viewed` SSE event for an outbound message transitions its bubble to a
**seen** state without any manual refresh or navigation, in an automated test.

AC-2: An inbound message that becomes ≥ 50% visible for ≥ 400 ms while
foregrounded triggers exactly one `POST
/messaging/conversations/{conversation_id}/messages/{message_id}/view`; repeated
visibility does not re-report.

AC-3: A duplicate/replayed `message:viewed` event does not double-count viewers
or `seenCount` (idempotent upsert proven by test).

AC-4: In a group, tapping "Seen by N" opens a roster sheet from `GET
/messaging/conversations/{conversation_id}/messages/{message_id}/views` that lists
viewers and updates live as new view events arrive.

AC-5: The local user is never shown as a viewer of their own message and never
reports a view on their own message (FR-6).

AC-6: Failed `reportView` produces no user-visible error and is retried once on
SSE reconnect; cached receipt markers continue to render.

AC-7: All receipt glyphs/affordances expose non-color-only TalkBack
descriptions and use localized plurals/relative times.

## 15. Definition of Done

- Code merged to `android-port`; module boundaries respected (`feature-messaging`
  → `core-*`), namespace `com.testlogon.android`.
- Additive Room migration written and tested (migration test included);
  coordinated with AND-148 schema version.
- `ReceiptsRepository`, `ThreadReceiptsViewModel`, DTOs, DAO, and Compose
  (`ReceiptGlyph`, `SeenByChip`, `ViewerRosterSheet`) implemented and wired
  through Hilt.
- All §11 unit + Compose tests pass headlessly in CI; AC-1…AC-7 verified.
- No receipt PII logged in release; CSRF header sent on the view POST; 401
  refresh-retry confirmed.
- Strings externalized + plurals; accessibility descriptions present.
- Open Questions Q1/Q2 resolved against the live OpenAPI in this review (see §16);
  DTOs frozen to the verified shapes. Q3 (opt-out) remains deferred.
- ktlint/detekt clean; PR description links AND-144 and notes AND-148
  coordination.

## 16. Citations & Assumption Audit

Each key technical claim with VERDICT and exact SOURCE pointer.

1. **View-report endpoint is `POST /messaging/conversations/{conversation_id}/messages/{message_id}/view`.**
   VERDICT: **Corrected** (draft had flat `/messaging/messages/{message_id}/view`).
   SOURCE: OpenAPI `POST /messaging/conversations/{conversation_id}/messages/{message_id}/view`
   (op `mark_message_viewed_...`); `src/api/endpoints/messaging.ts: markViewed`.
2. **Viewer-roster endpoint is `GET /messaging/conversations/{conversation_id}/messages/{message_id}/views`.**
   VERDICT: **Corrected** (draft had flat path).
   SOURCE: OpenAPI `GET /messaging/conversations/{conversation_id}/messages/{message_id}/views`
   (op `get_message_views_...`); `src/api/endpoints/messaging.ts: getViewers`.
3. **Report request body is `ViewMessageIn { viewed_at?: integer|null }`, not `{}`.**
   VERDICT: **Corrected** (draft said `Body: {}`).
   SOURCE: OpenAPI schema `ViewMessageIn`. (The web client posts `{}`, which is
   valid since the field is optional — `src/api/endpoints/messaging.ts: markViewed`.)
4. **Report response is `ViewAckOut { ok, conversation_id, message_id, viewer_id, viewed_at:integer }`.**
   VERDICT: **Corrected** (draft had `{ message_id, viewed_at: ISO-string }`).
   SOURCE: OpenAPI schema `ViewAckOut`; mirrored in
   `src/api/endpoints/messaging.ts: markViewed` generic type.
5. **`viewed_at` / `last_viewed_at` are integer epoch timestamps, not ISO-8601 strings.**
   VERDICT: **Corrected**.
   SOURCE: OpenAPI `ViewAckOut.viewed_at: integer`, `MessageViewOut.last_viewed_at: integer`;
   `src/api/types.ts: MessageViewer.last_viewed_at: number`.
6. **Roster GET returns a BARE JSON ARRAY of `MessageViewOut`, fields `{ user_id, last_viewed_at, view_count }` only.**
   VERDICT: **Corrected** (draft had an envelope with `views`/`delivered_to`/`next_cursor`
   and per-viewer `display_name`/`avatar_url`/`viewed_at`).
   SOURCE: OpenAPI response schema (array of `MessageViewOut`) + schema `MessageViewOut`;
   `src/api/types.ts: MessageViewer`; `src/api/endpoints/messaging.ts: getViewers` (`MessageViewer[]`).
7. **No `display_name` / `avatar_url` in the roster payload; identity resolved elsewhere.**
   VERDICT: **Corrected**.
   SOURCE: schema `MessageViewOut` (3 fields only); `src/pages/messages/ReadReceipts.tsx`
   renders `user_id` initials only (no name/avatar available).
8. **Roster GET has only a `limit` query (default 200, max 500); no cursor / pagination.**
   VERDICT: **Corrected** (draft had `?limit=50&cursor=`).
   SOURCE: OpenAPI `get_message_views_...` params (`limit` only; default 200,
   min 1, max 500); index line shows `params=conversation_id,message_id,limit,...`.
9. **SSE event type is `message:viewed` (colon), carrying `{ message_id, viewer_id, viewed_at }`.**
   VERDICT: **Corrected** (draft had `message.viewed` with `user_id`).
   SOURCE: `src/hooks/useMessagingStream.ts` (`if (eventType === "message:viewed")`,
   reads `data.message_id` and `data.viewer_id`).
10. **There is NO `message.delivered` / `message:delivered` SSE event.**
    VERDICT: **Corrected** (draft asserted a delivered SSE variant).
    SOURCE: `src/hooks/useMessagingStream.ts` (no delivered branch; only
    `message:viewed`, presence, and call/webrtc events).
11. **Delivered/seen for outbound messages come from `Message` payload fields:
    `delivered_to_count`, `delivered_to_user_ids`, `read_by_count`, `read_by_user_ids`.**
    VERDICT: **Verified**.
    SOURCE: `src/api/types.ts: Message` (lines ~1199–1202);
    `src/pages/messages/DeliveryStatus.tsx` (uses `read_by_count`/`delivered_to_count`).
12. **422 `HTTPValidationError` is the only declared non-200 error response.**
    VERDICT: **Verified**.
    SOURCE: OpenAPI both ops `resp=200:...;422:HTTPValidationError`; schema `HTTPValidationError`.
13. **Auth: `Authorization: Bearer` + `X-CSRF-Token` (from `ui_csrf` cookie) + cookies;
    optional `X-SESSION-ID`.**
    VERDICT: **Verified (draft was partial — it omitted Bearer and X-SESSION-ID).**
    SOURCE: `src/api/client.ts` (sets `Authorization: Bearer`, `X-CSRF-Token` from
    `getCookie("ui_csrf")`, `credentials: "include"`); OpenAPI params
    `authorization, X-SESSION-ID` on both view ops.
14. **401 handling: one `POST /ui/session/refresh` then a single retry.**
    VERDICT: **Verified**.
    SOURCE: `src/api/client.ts` (`fetch(withApiBase("/ui/session/refresh"), ...)`).
15. **Web view-tracking uses `IntersectionObserver` at `threshold: 0.5`, marks once
    per mount, skips own + optimistic messages, swallows POST errors.**
    VERDICT: **Verified**.
    SOURCE: `src/pages/messages/ReadReceipts.tsx: ViewTracker`
    (`threshold: 0.5`, `markedRef`, `markViewed(...).catch(() => {})`).
16. **Self-receipts are not shown; reporting skips own messages.**
    VERDICT: **Verified** (web parity).
    SOURCE: `src/pages/messages/ReadReceipts.tsx` (`if (!isOwn) return null`,
    `ViewTracker` early-returns on `isOwn`); `DeliveryStatus.tsx` (`if (!isOwn) return null`).
17. **Stack/framework choices (Compose Material 3 `ModalBottomSheet`, `LazyListState`
    + `derivedStateOf`/`snapshotFlow` for visibility, Paging 3 over Room,
    `DateUtils.getRelativeTimeSpanString`, TalkBack `contentDescription`).**
    VERDICT: **Unverified-assumption (framework ref)** — Android client design, not in sources.
    SOURCE (framework ref): developer.android.com/jetpack/compose/components/bottom-sheets,
    developer.android.com/jetpack/compose/lists, developer.android.com/topic/libraries/architecture/paging/v3-overview,
    developer.android.com/reference/android/text/format/DateUtils,
    developer.android.com/guide/topics/ui/accessibility.

### Corrections made

- Endpoints rewritten to the conversation-scoped paths (claims 1, 2) in §1, §3
  (FR-1/4/5), §5, §14 (AC-2/AC-4).
- Report body changed from `{}` to optional `ViewMessageIn` (claim 3, §5).
- Report response corrected to `ViewAckOut` with all five fields and an **integer**
  `viewed_at` (claims 4, 5, §5).
- Roster response corrected from an envelope to a **bare array** of `MessageViewOut`,
  dropping the non-existent `views`/`delivered_to`/`next_cursor` and per-viewer
  `display_name`/`avatar_url` (claims 6, 7, §5, §6).
- Removed the non-existent cursor; `limit` default 200/max 500 (claim 8, §5).
- SSE event corrected to `message:viewed` with `viewer_id` (claim 9) throughout
  (§3 FR-3, §5, §6, §11, §14 AC-1/AC-3).
- Removed the fictitious `message.delivered` SSE event; delivery/seen now sourced
  from `Message` payload fields (claims 10, 11, §3 FR-2/FR-3, §5, §13 Q2).
- Auth note expanded with Bearer + X-SESSION-ID (claim 13, §2).
- Open Questions Q1 and Q2 marked **RESOLVED** (§5, §13, §15).

### Open assumptions

- **400 ms visibility dwell** (FR-1, §4.5): Android-side hardening; the web client
  marks immediately on 50% intersection with no dwell. Unverifiable from sources —
  it is a UX-tuning choice. WHY: no dwell parameter exists in the reference.
- **Once-per-process dedupe** (FR-1): stronger than the web's once-per-mount guard.
  WHY: Android process/lifecycle model differs; not derivable from the web client.
- **Distinct DM "sending → sent → delivered → seen" four-state glyph** (FR-4): the
  web client renders only Clock/Check/CheckCheck (sending/delivered/read) — a
  separate "sent" state is an Android addition. WHY: no `sent`-only signal is shown
  in `DeliveryStatus.tsx`.
- **Optimistic local application of `message:viewed`** (§3 FR-3): the web client
  only invalidates+refetches; applying the event body locally is an Android choice.
  WHY: reference does not mutate from the event payload.
- **Receipt opt-out (Q3)**: no opt-out field observed on the view endpoints or
  `MessageViewOut`; cannot confirm server support. WHY: not present in OpenAPI.
- **All framework/library choices** in claim 17 (Compose, Paging 3, Room, Hilt,
  Moshi, OkHttp authenticator behavior). WHY: Android stack, outside the
  backend/web sources; cited as framework refs.

## 17. Test Plan

Test-target legend: **JVM** = JVM unit/Robolectric (local, no device);
**EMU** = headless emulator AVD `test35` (x86_64, API 35); **DEVICE** = physical
Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a) via adb on the build host.
Most cases here are non-hardware (cache/SSE/UI logic) and run JVM or EMU; the
accessibility and physical-rendering cases note where DEVICE is preferred.

- **TC-AND-147-01 — Report-once on visibility (happy path).**
  Type: unit (contract/MockWebServer). Target: JVM.
  Preconditions: `ReceiptsRepositoryImpl` with MockWebServer; an inbound message
  not authored by self; empty dedupe set.
  Steps: call `onMessageVisible(id, authoredByMe=false)` repeatedly (5×) for the
  same message past the 400 ms debounce.
  Expected: exactly **one** `POST
  /messaging/conversations/{cid}/messages/{id}/view` with body `ViewMessageIn`;
  request includes `Authorization` + `X-CSRF-Token` headers; 200 `ViewAckOut`
  parsed; `viewReportedAt` set. No further POSTs on repeat.
  Traces: AC-2.

- **TC-AND-147-02 — Self message is never reported.**
  Type: unit. Target: JVM.
  Preconditions: a message authored by the local user.
  Steps: call `onMessageVisible(id, authoredByMe=true)`.
  Expected: **no** network call; no dedupe entry; no `viewReportedAt` write.
  Traces: AC-5.

- **TC-AND-147-03 — Live SEEN via `message:viewed` SSE (primary).**
  Type: integration. Target: JVM (FakeMessagingEventBus).
  Preconditions: outbound message cached as DELIVERED; `receiptFlow(id)` collected
  via Turbine; thread open.
  Steps: emit `MessagingEvent.MessageViewed(messageId, viewerId="u_9", viewedAt)`
  decoded from a `message:viewed` frame onto the bus.
  Expected: `receiptFlow` emits `status=SEEN`, `seenCount=1`, `seenAt` from event;
  no refetch required to reach SEEN; transition observed without re-collection.
  Traces: AC-1, AC-3.

- **TC-AND-147-04 — Idempotent duplicate `message:viewed`.**
  Type: unit. Target: JVM.
  Preconditions: one viewer already upserted for the message (composite PK
  `(messageId, userId)`).
  Steps: apply the same `message:viewed` event (same `viewer_id`) twice, then a
  second distinct viewer once.
  Expected: after duplicates, `seenCount` stays 1 (no double-count); after the
  distinct viewer, `seenCount` = 2; no duplicate Room rows.
  Traces: AC-3.

- **TC-AND-147-05 — Roster fetch parses bare array of `MessageViewOut`.**
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: MockWebServer returns `200` with body
  `[{"user_id":"u_9","last_viewed_at":1749124801,"view_count":3}]`.
  Steps: call `getViews(cid, id, limit=200)`.
  Expected: deserializes to `List<MessageViewOut>` of size 1; URL is the
  conversation-scoped `/views` path with `?limit=200` and **no** `cursor` param;
  values map to Room viewer row (name/avatar null until resolved).
  Traces: AC-4.

- **TC-AND-147-06 — Roster GET backoff then success; cached viewers retained.**
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: MockWebServer enqueues `503, 503, 200(array)`; one viewer already
  in cache.
  Steps: open roster → trigger `getViews`.
  Expected: bounded backoff retries (≤3 attempts), then success merges; on the two
  failures the previously cached viewer remains visible; on simulated exhaustion
  (`503,503,503`) a "Couldn't load viewers — Retry" state shows while cache
  remains. Backoff-exhaustion counter incremented.
  Traces: AC-4, AC-6.

- **TC-AND-147-07 — Delivered derived from `Message` payload fields.**
  Type: unit. Target: JVM.
  Preconditions: outbound message updated with `delivered_to_count=2`,
  `read_by_count=0`.
  Steps: write the message row; collect `receiptFlow`.
  Expected: `status=DELIVERED` (not SEEN); when `read_by_count` later becomes ≥1,
  status flips to SEEN. Confirms no reliance on a non-existent delivered SSE event.
  Traces: AC-1.

- **TC-AND-147-08 — 401 → single refresh + retry.**
  Type: contract/MockWebServer. Target: JVM.
  Preconditions: MockWebServer returns `401` for the first view POST, then `200`;
  refresh endpoint stub returns `200`.
  Steps: call `reportView`.
  Expected: client calls `POST /ui/session/refresh` exactly once, retries the
  original POST exactly once, succeeds; no infinite loop on repeated 401.
  Traces: AC-6.

- **TC-AND-147-09 — Offline / flaky-host: failed report queued and retried on reconnect.**
  Type: integration. Target: JVM (FakeMessagingEventBus + MockWebServer).
  Preconditions: report POST fails (connection error / host blip); `pendingViews`
  empty.
  Steps: trigger a view report while "offline"; assert no user-visible error/toast;
  then emit bus `onConnected` (reconnect).
  Expected: failure is silent; message enqueued once in `pendingViews`; on
  reconnect, exactly one retry POST is sent (idempotent); cached markers keep
  rendering throughout.
  Traces: AC-6.

- **TC-AND-147-10 — Live bubble transition in Compose (no manual refresh).**
  Type: Compose-UI. Target: EMU (`test35`).
  Preconditions: `createComposeRule`; FakeMessagingEventBus; outbound bubble shown
  as DELIVERED.
  Steps: inject `message:viewed` for that message into the fake bus.
  Expected: `ReceiptGlyph` recomposes to the SEEN glyph and "Seen …" text without
  navigation or pull-to-refresh; assertion via test tag.
  Traces: AC-1.

- **TC-AND-147-11 — Visibility-driven reporting via scroll; no re-report.**
  Type: instrumented/e2e. Target: EMU (`test35`).
  Preconditions: thread with several inbound messages in a `LazyColumn`; mocked
  view endpoint counting requests.
  Steps: scroll an inbound message ≥50% into view for ≥400 ms; scroll away; scroll
  back.
  Expected: exactly one `view` POST for that message across the whole sequence.
  Traces: AC-2.

- **TC-AND-147-12 — Group roster sheet renders and updates live.**
  Type: Compose-UI. Target: EMU (`test35`).
  Preconditions: group outbound message with two cached viewers; sheet closed.
  Steps: tap "Seen by N" → assert `ViewerRosterSheet` lists viewers (newest first);
  inject a new `message:viewed` for a third viewer while the sheet is open.
  Expected: sheet opens from the conversation-scoped `/views` data; the third
  viewer appears live (Paging over Room) without closing/reopening.
  Traces: AC-4.

- **TC-AND-147-13 — Accessibility: non-color-only descriptions + plurals.**
  Type: Compose-UI / accessibility. Target: DEVICE (preferred — real TalkBack on
  API 34) with EMU as fallback.
  Preconditions: bubbles in each state; "Seen by N" chip present.
  Steps: traverse with accessibility checks / TalkBack; verify `contentDescription`
  for SENDING/SENT/DELIVERED/SEEN/FAILED; chip announces "Seen by N people,
  double-tap to view" (role=Button); roster rows announce "<name>, viewed <relative
  time>"; touch target ≥48dp; verify localized `seen_by_count` plural.
  Expected: every state is announced non-color-only; plurals/relative-time
  localized; min target met. MUST validate the TalkBack announcement on DEVICE.
  Traces: AC-7.

- **TC-AND-147-14 — Security: CSRF header on POST; no receipt PII in release logs.**
  Type: contract/MockWebServer + unit. Target: JVM.
  Preconditions: release-tree Timber config; MockWebServer capturing headers.
  Steps: invoke `reportView`; inspect captured request; exercise telemetry on a
  view + roster open.
  Expected: POST carries `X-CSRF-Token` (and `Authorization`); release logs contain
  no viewer identity or message body (only opaque/absent ids); analytics events
  carry no PII.
  Traces: AC-6, AC-7 (privacy), supports §8/§10.

### Coverage matrix

| AC | Covered by |
|----|------------|
| AC-1 (live seen via SSE) | TC-AND-147-03, TC-AND-147-07, TC-AND-147-10 |
| AC-2 (report exactly once on visibility) | TC-AND-147-01, TC-AND-147-11 |
| AC-3 (idempotent duplicate event) | TC-AND-147-03, TC-AND-147-04 |
| AC-4 (group roster sheet, live) | TC-AND-147-05, TC-AND-147-06, TC-AND-147-12 |
| AC-5 (no self-receipts) | TC-AND-147-02 |
| AC-6 (silent failure + retry on reconnect) | TC-AND-147-06, TC-AND-147-08, TC-AND-147-09, TC-AND-147-14 |
| AC-7 (accessibility, plurals, relative time) | TC-AND-147-13, TC-AND-147-14 |
