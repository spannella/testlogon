---
id: AND-147
title: Read receipts / views
milestone: M3
epic: E20
priority: P1
size: M
status: draft
depends_on: [AND-144]
blocks: []
---

# AND-147 — Read receipts / views

## 1. Overview & Goal

This ticket adds per-message **delivery and read (seen) receipts** to the
TestLogon Android messaging experience. When the local user opens a thread and a
message scrolls into view, the client reports the view to the backend
(`POST /messaging/messages/{message_id}/view`); when the counterpart(s) view a
message authored by the local user, the client reflects **delivered / seen
markers** on those outbound messages. The viewer roster for a single message is
read on demand via `GET /messaging/messages/{message_id}/views`.

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
  `POST /ui/session/refresh` then retries.
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
/messaging/messages/{message_id}/view`. Each message is reported **at most once
per process lifetime** (in-memory dedupe set + Room `viewReportedAt` guard).

FR-2 **Delivered marker.** An outbound message shows a **delivered** marker once
the backend confirms delivery (delivery event over SSE, or `views`/message
payload field indicating the recipient's transport received it). DMs show a
single delivered tick; groups show delivered when ≥ 1 recipient has it.

FR-3 **Seen marker (live).** An outbound message shows a **seen** marker when a
counterpart reports a view. This MUST update live via SSE
(`MessageViewed`) while the thread is open, with no manual refresh.

FR-4 **DM vs group semantics.**
- DM: outbound bubble renders a state glyph `sending → sent → delivered → seen`
  plus, when seen, a relative "Seen 2m ago".
- Group: outbound bubble renders aggregate state; tapping a small
  "Seen by N" affordance opens a **viewer roster sheet** populated from `GET
  /messaging/messages/{message_id}/views`.

FR-5 **Viewer roster.** The roster sheet lists each viewer (avatar, display
name, viewed-at timestamp), sorted most-recent first, paginates if large, and
updates live while open as new `MessageViewed` events arrive for that message.

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

Three endpoints (verify exact names against `/openapi.json`; base path
`/messaging`):

**Report a view (idempotent on server):**
```
POST /messaging/messages/{message_id}/view
Headers: X-CSRF-Token: <ui_csrf>   (cookies carry session)
Body: {}                            (server infers viewer from session)
200 OK
{ "message_id": "msg_123", "viewed_at": "2026-06-05T12:00:00Z" }
```

**Read viewer roster (idempotent GET — retryable with bounded backoff):**
```
GET /messaging/messages/{message_id}/views?limit=50&cursor=<opaque>
200 OK
{
  "message_id": "msg_123",
  "views": [
    { "user_id": "u_9", "display_name": "Ada",
      "avatar_url": "https://.../a.jpg", "viewed_at": "2026-06-05T12:00:01Z" }
  ],
  "delivered_to": ["u_9", "u_7"],
  "next_cursor": null
}
```

**SSE event (over the AND-144 stream):**
```json
{ "type": "message.viewed",
  "data": { "message_id": "msg_123", "user_id": "u_9",
            "viewed_at": "2026-06-05T12:00:01Z" } }
```
A `message.delivered` variant carries `{ "message_id", "user_id",
"delivered_at" }`.

Moshi DTOs (`core-network`): `ViewReportResponse`, `MessageViewsResponse`,
`MessageViewDto`, plus the two SSE event DTOs. Retrofit:

```kotlin
@POST("messaging/messages/{id}/view")
suspend fun reportView(@Path("id") id: String): Response<ViewReportResponse>

@GET("messaging/messages/{id}/views")
suspend fun getViews(
    @Path("id") id: String,
    @Query("limit") limit: Int = 50,
    @Query("cursor") cursor: String? = null,
): Response<MessageViewsResponse>
```

FastAPI `detail` errors (string | `[{msg}]` | `{code,...}`) are mapped by the
shared error mapper into `ApiResult.Error`. If any field name differs in the live
OpenAPI, the DTO `@Json(name=...)` is the single point of change (Open Question
Q1).

## 6. Data & State Management

Room (`core-data`), schema-migrated additively:
- `MessageEntity` gains: `receiptStatus TEXT`, `deliveredAt INTEGER?`,
  `seenAt INTEGER?`, `seenCount INTEGER NOT NULL DEFAULT 0`,
  `viewReportedAt INTEGER?` (local once-guard).
- New `MessageViewerEntity(messageId, userId, displayName, avatarUrl,
  viewedAt)`, PK `(messageId, userId)` — composite key gives natural idempotent
  upsert (no duplicate viewers on event replay).

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

State flow: SSE `MessageViewed` → `applyReceiptEvent` upserts a viewer row and
recomputes `seenCount`/`seenAt`/`receiptStatus = SEEN` for the message → Room
emits → `receiptFlow` updates → Compose recomposes the bubble. The roster sheet
collects `pagingViewers` via Paging 3 so live upserts appear without a refetch.
Cache is the single source of truth; the network layer only writes into it
(consistent with AND-148).

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
- A `message.viewed` SSE event upserts a viewer, increments `seenCount`, sets
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

- **Q1 — Exact field/endpoint names.** Backlog says message `/view`, `/views`;
  exact paths/field names (`viewed_at` vs `seen_at`, `delivered_to` presence,
  SSE `type` strings) must be confirmed against live `/openapi.json` and the SSE
  payloads before DTOs freeze. Risk: rename churn — mitigated by isolating in
  Moshi `@Json` annotations.
- **Q2 — Delivered semantics.** Whether the backend emits a distinct
  `message.delivered` event or only `message.viewed`. If no delivery signal
  exists, the DELIVERED state is derived from message-ack only (DM) or hidden
  (groups) until confirmed. Needs backend verification.
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
`message.viewed` SSE event for an outbound message transitions its bubble to a
**seen** state without any manual refresh or navigation, in an automated test.

AC-2: An inbound message that becomes ≥ 50% visible for ≥ 400 ms while
foregrounded triggers exactly one `POST /messaging/messages/{id}/view`; repeated
visibility does not re-report.

AC-3: A duplicate/replayed `message.viewed` event does not double-count viewers
or `seenCount` (idempotent upsert proven by test).

AC-4: In a group, tapping "Seen by N" opens a roster sheet from `GET
/messaging/messages/{id}/views` that lists viewers and updates live as new view
events arrive.

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
- Open Questions Q1/Q2 resolved against live `/openapi.json` (or explicitly
  deferred with a tracked follow-up) before merge.
- ktlint/detekt clean; PR description links AND-144 and notes AND-148
  coordination.
