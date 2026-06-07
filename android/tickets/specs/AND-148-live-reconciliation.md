---
id: AND-148
title: Live reconciliation
milestone: M3
epic: E20
priority: P0
size: L
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-144, AND-116]
blocks: []
---

# AND-148 — Live reconciliation

## 1. Overview & Goal

The TestLogon feeds (event timeline, notifications, and any live-updating
list backed by Paging 3) receive two independent sources of truth: a cold,
paginated REST snapshot served by FastAPI and a hot stream of Server-Sent
Events (SSE). This ticket defines the **reconciliation engine** that merges
the SSE stream into the Room-backed Paging cache so that the visible list is
correct, ordered, and stable across the full lifecycle — initial load, live
push, scroll-driven pagination, network drop, and SSE reconnect.

The hard guarantee this ticket delivers: **no duplicate rows and no missing
rows (gaps) are ever presented to the UI, including across an SSE
disconnect/reconnect cycle.** SSE delivers at-least-once and may replay or
skip events around a reconnect; the REST snapshot is the durable backstop.
Reconciliation makes the two converge to a single, deterministically ordered
list.

This is a pure data/domain-layer feature in `core-data`. It owns the merge
algorithm, the cursor/sequence bookkeeping, and the conflict-resolution
rules. It does **not** own the SSE transport (AND-144) or the Paging
RemoteMediator wiring for the REST snapshot (AND-116); it consumes both.

## 2. Context & References

- **Stack:** Kotlin 2.0.21, Coroutines/Flow, Room 2.6, Paging 3, Moshi
  1.15, Retrofit 2.11 / OkHttp 4.12. Module: `core-data` (namespace
  `com.testlogon.android.core.data`), with model types in `core-model`
  (`com.testlogon.android.core.model`).
- **Upstream dependency AND-144 — SSE transport:** provides a
  `Flow<SseEnvelope>` of decoded live events plus the connection state and
  the `Last-Event-ID` resume token. AND-148 subscribes to that flow; it does
  not open the connection.
- **Upstream dependency AND-116 — Paging/RemoteMediator:** provides the Room
  `PagingSource` and the `RemoteMediator` that fills the cache from the REST
  snapshot endpoint. AND-148 writes reconciled rows into the same Room table
  that AND-116's `PagingSource` reads.
- **Backend:** FastAPI + DynamoDB, dev host `http://18.222.237.167:8000`
  (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. The two inputs
  are a paginated list-snapshot endpoint and an SSE stream endpoint.
  **Correction (verified against OpenAPI):** there is **no** `/ui/events`
  or `/ui/events/stream` endpoint. The real snapshot endpoints are
  `GET /ui/notifications` (→ `NotificationListResponse`) and
  `GET /ui/activity/feed` (→ `ActivityFeedResponse`), both paginated by an
  **opaque `cursor` + `limit`** (not a numeric `before_seq`). The real SSE
  streams are `GET /messaging/events/stream` and `GET /ui/alerts/stream`
  (server-typed events via `EventSource`). The per-stream monotonic `seq`
  and `op` fields this design relies on are **not present** in the backend
  contract today (item ids are e.g. `notification_id`; ordering field is
  `created_at`, an epoch integer); `seq`-based reconciliation is an
  Android-side design assumption — see §16 and risks R1/R2.
- **Web reference:** `frontend/src/api/endpoints/*.ts` (snapshot fetch +
  `EventSource` handling) and `frontend/src/api/types.ts` (event shapes).
- **Auth:** cookie-based session with `X-CSRF-Token`; the SSE and snapshot
  calls reuse the shared OkHttp cookie jar. On 401 the client refreshes once
  (`POST /ui/session/refresh`) then retries. Reconciliation treats an auth
  failure as a transient stream interruption (see §7).

## 3. Functional Requirements

FR-1. **Single ordered list.** The reconciler exposes a single
`Flow<PagingData<EventEntity>>` whose ordering is **descending by
`(seq, id)`** (newest first). `seq` is the primary key for ordering; `id`
is the deterministic tiebreaker for equal `seq`.

FR-2. **De-duplication.** An event identified by its stable `id` appears at
most once in the cache regardless of how many times it arrives (REST page,
SSE live push, SSE replay-on-reconnect). Last-writer-wins on the same `id`
updates the row contents but never adds a second row.

FR-3. **No gaps.** Reconciliation must guarantee that for any contiguous
range of `seq` values the UI has either every item in that range or a
visible, recoverable "gap marker" that triggers a backfill. Silent loss is
not permitted.

FR-4. **Live insert.** When an SSE event arrives with `seq` newer than the
current cache head, it is upserted and surfaced at the top without a full
list reload.

FR-5. **Out-of-order / late events.** An SSE event with `seq` older than the
cache head is upserted at its correct sorted position (it does not jump to
the top).

FR-6. **Reconnect reconciliation.** On SSE reconnect, the reconciler must
detect whether the resume was lossless (server honored `Last-Event-ID`) or
lossy (token expired / `seq` jump). On a detected jump it schedules a
**bounded REST backfill** for the missing `seq` window before clearing the
gap marker.

FR-7. **Tombstones / deletes.** An SSE event with `op = "delete"` removes
the row by `id` (idempotent — deleting a missing row is a no-op).

FR-8. **Idempotent replay.** Replaying the same SSE event N times yields the
same cache state as applying it once.

FR-9. **Cold-start ordering.** Before the SSE stream produces anything, the
list is fully usable from the REST snapshot via AND-116's mediator.

FR-10. **Bounded memory.** Live events are batched/conflated under load; the
reconciler must not unbounded-buffer SSE events when the DB write is the
bottleneck.

## 4. Technical Design

All logic lives in `core-data` under
`com.testlogon.android.core.data.reconcile`.

### 4.1 Entities

```kotlin
@Entity(
    tableName = "events",
    indices = [Index(value = ["seq", "id"], unique = true)]
)
data class EventEntity(
    @PrimaryKey val id: String,   // stable server id, dedupe key
    val seq: Long,                // monotonic ordering key per stream
    val streamId: String,         // partition (e.g. "notifications")
    val type: String,
    val payloadJson: String,      // raw JSON, decoded lazily in core-model
    val createdAtEpochMs: Long,
    val origin: Origin,           // SNAPSHOT or LIVE — provenance
    val updatedAtEpochMs: Long    // local write time, for LWW
)

enum class Origin { SNAPSHOT, LIVE }
```

A second table records the contiguity watermark so gaps survive process
death:

```kotlin
@Entity(tableName = "stream_cursor")
data class StreamCursorEntity(
    @PrimaryKey val streamId: String,
    val contiguousFromSeq: Long,  // lowest seq with no gap below head
    val headSeq: Long,            // highest seq held
    val lastEventId: String?,     // SSE resume token last persisted
    val hasGap: Boolean
)
```

### 4.2 The reconciler

```kotlin
class LiveReconciler @Inject constructor(
    private val dao: EventDao,
    private val cursorDao: StreamCursorDao,
    private val sse: SseEventSource,            // from AND-144
    private val backfill: SnapshotBackfiller,   // wraps AND-116 REST
    private val clock: Clock,
    @IoDispatcher private val io: CoroutineDispatcher
) {
    fun pagingFlow(streamId: String): Flow<PagingData<EventEntity>>

    suspend fun start(streamId: String): Nothing   // long-lived collector
}
```

`start()` runs in the feature's `viewModelScope` (or a stream-scoped
coroutine owned by a repository singleton). It collects the SSE flow and
applies each envelope through `apply()`:

```kotlin
internal suspend fun apply(env: SseEnvelope) = dao.withTransaction {
    when (env.op) {
        Op.UPSERT -> upsert(env.toEntity(Origin.LIVE, clock.nowMs()))
        Op.DELETE -> dao.deleteById(env.id)
    }
    advanceCursor(env.streamId, env.seq, env.eventId)
}
```

### 4.3 Merge / ordering algorithm

- The DAO upsert is `@Insert(onConflict = REPLACE)` keyed on `id`. REPLACE
  on the same `id` rewrites contents and `updatedAtEpochMs` (LWW), never
  adds a row → satisfies FR-2/FR-8.
- The unique index on `(seq, id)` plus the descending `PagingSource` query
  (`ORDER BY seq DESC, id DESC`) fixes deterministic ordering for FR-1/FR-5.
- **Gap detection on reconnect (FR-6):** AND-144 surfaces a
  `ConnectionState.Reconnected(resumedFrom: String?, firstSeq: Long)`. The
  reconciler compares `firstSeq` against persisted `headSeq + 1`:
  - `firstSeq <= headSeq + 1` → lossless, no gap.
  - `firstSeq > headSeq + 1` → gap of `[headSeq + 1, firstSeq - 1]`. Set
    `hasGap = true`, emit a gap marker, and enqueue
    `backfill.fill(streamId, fromSeq, toSeq)`.

```kotlin
internal suspend fun advanceCursor(streamId: String, seq: Long, eventId: String?) {
    val c = cursorDao.get(streamId) ?: StreamCursorEntity(streamId, seq, seq, eventId, false)
    val newHead = maxOf(c.headSeq, seq)
    val contiguous = if (seq == c.headSeq + 1 || seq <= c.contiguousFromSeq) c.contiguousFromSeq else seq
    cursorDao.upsert(c.copy(headSeq = newHead, lastEventId = eventId ?: c.lastEventId))
}
```

### 4.4 Backfill

```kotlin
class SnapshotBackfiller @Inject constructor(private val api: EventsApi, private val dao: EventDao) {
    suspend fun fill(streamId: String, fromSeq: Long, toSeq: Long): ApiResult<Int>
}
```

It pages the REST snapshot endpoint constrained to the gap window, upserts
each item with `Origin.SNAPSHOT`, then clears `hasGap` only after the full
window is persisted (transactional). Because snapshot rows share the same
`id` dedupe key, any overlap with already-seen LIVE rows is harmless.

### 4.5 Backpressure (FR-10)

SSE events are collected with `.buffer(capacity = 256, onBufferOverflow =
DROP_OLDEST_AND_MARK_GAP)` — practically, the collector batches up to N
envelopes and applies them in one Room transaction via `chunked`/
`conflate`-style windowing. A dropped batch flips `hasGap = true` so the
backstop snapshot reconciles it rather than losing data.

## 5. API Contract

AND-148 consumes two endpoints already defined by its dependencies; it
introduces none of its own.

### 5.1 Snapshot (REST, owned by AND-116; used here for backfill)

**Corrected.** The originally-claimed `GET /ui/events?...&before_seq=...`
does not exist. The actual snapshot endpoints (verified in OpenAPI) are:

- `GET /ui/notifications?cursor={c}&limit={n}` → `200: NotificationListResponse`
- `GET /ui/activity/feed?cursor={c}&limit={n}` → `200: ActivityFeedResponse`

Both use **opaque cursor pagination** (`cursor`, `limit` query params;
no numeric `before_seq`/`after_seq`). Real response shape
(`NotificationListResponse`):
```json
{
  "items": [
    {"notification_id":"ntf_01H...","notification_type":"login.success",
     "title":"...","body":"...","read":false,
     "created_at":1749124801,"data":{"...":"..."}}
  ],
  "next_cursor": "eyJrIjoi...",
  "unread_count": 3
}
```
(`ActivityFeedResponse` is the same shape with `ActivityOut` items keyed by
`activity_id` and a `total_unread` counter.) Note: the item key is
`notification_id`/`activity_id` (string), `created_at` is an **epoch
integer**, and there is **no `seq` field and no `next_before_seq`/`has_more`
pair** — the spec's `seq`-windowed backfill is an Android-side assumption
(§16, R1/R3). Backfill must therefore page by `cursor` until the desired
window is covered (or fall back to a head-pages refresh per R3), not by a
`seq` range. Auth: cookie session + `X-CSRF-Token` (see §8).

### 5.2 SSE stream (owned by AND-144; consumed here)

**Corrected.** There is no `/ui/events/stream`. The real SSE endpoints
(verified in OpenAPI and the web client) are `GET /messaging/events/stream`
(query params `after`, `limit`, `poll_ms`) and `GET /ui/alerts/stream`,
consumed in the web app via `EventSource` with cookie auth
(`withCredentials: true`). The actual frame format does **not** match the
`op`/`seq`/`Last-Event-ID` shape claimed above:

- The backend emits **server-typed events** whose `event:` name is the
  semantic type, e.g. `message:new`, `message:revoked`, `message:edited`,
  `presence:update`, `call.invite`, … (messaging) or `alert`, `new_alert`,
  `alert_read`, `hello`, `sync`, `heartbeat` (alerts). There is **no
  generic `op: upsert|delete` field**; "delete"-like semantics are distinct
  typed events (e.g. `message:revoked`/`message:expired`).
- `data:` is a JSON object carrying domain ids (e.g. `conversation_id`,
  `message_id`, `alert_id`, `unread_delta`, `unread_count`) — **no `seq`
  field is present** in the observed payloads.
- The web client does **not** send `Last-Event-ID` on resume; it reconnects
  with exponential backoff (cap 30 s) and **re-fetches/invalidates** caches
  rather than replaying by token. A `heartbeat` event resets the backoff.

Implication for AND-148: the `op`/`seq`/`Last-Event-ID`/`firstSeq`-jump
model is a **design-level assumption** that AND-144 (and the backend) must
satisfy, not an established contract. Until confirmed (R1/R2), the
reconciler should treat reconnect as **always potentially lossy** and rely
on the cursor-paged snapshot as the backstop (the same strategy the web app
uses implicitly). Tracked in §16 Open assumptions.

### 5.3 Error envelope

FastAPI `detail` is mapped per the project rule (string | `[{msg}]` |
`{code,...}`) by `core-network`; the backfill surfaces it as
`ApiResult.Error`. **Verified:** the snapshot endpoints declare `422:
HTTPValidationError`, whose shape is `{"detail":[{"loc":[...],"msg":"...",
"type":"..."}]}` (FastAPI `ValidationError`), matching the `[{msg}]` branch
of the project rule. SSE transport errors arrive as `ConnectionState` from
AND-144, not as HTTP responses here.

## 6. Data & State Management

- **Source of truth:** the Room `events` table. The UI never reads SSE
  directly; it observes `pagingFlow()`. This guarantees a single
  consistent list and survives process death.
- **Cursor durability:** `stream_cursor` persists `headSeq`,
  `contiguousFromSeq`, `lastEventId`, and `hasGap` so reconnect logic and
  gap recovery are correct after cold start.
- **UI state:** the feature ViewModel maps `PagingData` plus the
  `StreamCursorEntity.hasGap`/connection flags into a
  `StateFlow<FeedUiState>` (Live / Stale / Reconnecting / GapBackfilling).
  Gap markers are represented as a `PagingData` separator/placeholder item.
- **Transactionality:** every `apply()` and every backfill window commit
  runs inside `dao.withTransaction { }` so the row writes and the cursor
  advance are atomic — a crash mid-merge can never leave an advertised head
  ahead of persisted rows (which would manifest as a phantom gap or, worse,
  a hidden gap).

## 7. Error Handling & Resilience

- **SSE disconnect:** handled by AND-144's bounded backoff. AND-148 reacts
  to `ConnectionState.Disconnected` by setting the UI to `Reconnecting`
  (stale-but-usable cache stays visible). No data is dropped.
- **Lossy reconnect:** detected via the `firstSeq` jump (§4.3) → bounded
  REST backfill of exactly the missing window. Backfill itself uses the
  project's idempotent-GET policy: ~20s timeout, bounded backoff retry
  (GET only). On exhausted retries, `hasGap` stays `true` and the gap
  marker remains so the user can pull-to-refresh to retry.
- **401 during backfill:** delegated to `core-network` (single
  `/ui/session/refresh` then retry); a persistent failure surfaces as
  `ApiResult.Error` and a non-fatal banner, gap preserved.
- **Duplicate/replayed events:** absorbed by the `id` REPLACE upsert — no
  special handling needed (FR-8).
- **Clock skew / non-monotonic seq:** ordering relies on server `seq`, not
  device time; `createdAtEpochMs` is display-only. If the server emits a
  non-monotonic `seq` (defensive), the `(seq,id)` ordering still yields a
  deterministic, stable list.
- **DB write failure:** the transaction rolls back; the envelope is treated
  as un-applied and the next reconnect/backfill recovers it via the gap
  path.

## 8. Security & Privacy

No new network surface or credentials. Both inputs ride the existing
cookie + `X-CSRF-Token` session through the shared OkHttp jar. Event
`payloadJson` is stored verbatim in Room — if a stream can carry sensitive
PII the table inherits the app's at-rest posture; no plaintext logging of
payloads (see §10). The dev backend is plaintext HTTP; this is an accepted
dev-only condition documented in the network module and out of scope here.
Backfill requests must not widen authorization — they query the same
`stream` the user is already subscribed to.

## 9. Accessibility & i18n

This is a data-layer ticket with no direct UI surface. The one user-visible
artifact it defines is the **gap marker / reconciliation state**, consumed
by feature UIs (`core-ui`). Requirements passed downstream: the gap marker
must have a localized, screen-reader-readable label (e.g.
`R.string.feed_gap_loading` / `feed_gap_retry`), expose a content
description, and the "Reconnecting/Stale" indicator must not rely on color
alone. All strings live in `core-ui`/feature resources; none are hardcoded
here.

## 10. Telemetry & Logging

Structured, payload-free events (Timber + the app analytics sink):

- `reconcile_apply` — `streamId`, `op`, `seq`, `latencyMs` (debug only).
- `reconcile_gap_detected` — `streamId`, `fromSeq`, `toSeq`,
  `gapSizeEvents`.
- `reconcile_backfill_result` — `streamId`, `requested`, `persisted`,
  `outcome` (ok/error), `attempts`.
- `reconcile_reconnect` — `streamId`, `resumedLossless` (bool),
  `firstSeq`, `headSeq`.

Never log `payloadJson` or any event body. Counters for gaps and backfill
failures are the primary health signal for the unreliable dev host. Log
levels: gap/backfill-failure at WARN, normal apply at VERBOSE.

## 11. Testing Strategy

Lives in `core-data`'s test source set with `core-testing` fakes; the merge
logic is deterministic and fully unit-testable without a device.

Unit (JVM, `runTest`, in-memory Room):
- **T-dedupe:** apply the same `id` 5× (mix of LIVE and SNAPSHOT) → exactly
  one row; contents reflect last write (FR-2/FR-8).
- **T-order:** interleave events with shuffled `seq` → query returns strict
  `seq DESC, id DESC` (FR-1/FR-5).
- **T-live-insert:** newest `seq` appears at head without reload (FR-4).
- **T-delete:** delete by `id`, and delete of unknown `id` is a no-op
  (FR-7).
- **T-gap-detect:** persisted `headSeq = 100`, reconnect `firstSeq = 110`
  → gap `[101,109]`, `hasGap = true`, backfill enqueued with that exact
  window (FR-6).
- **T-lossless-reconnect:** `firstSeq = 101` → no gap, no backfill.
- **T-backfill-clears-gap:** fake backfill returns the window → `hasGap`
  flips false only after full persist; partial persist keeps gap.
- **T-process-death:** rebuild reconciler from persisted `stream_cursor` →
  gap state and head survive.
- **T-backpressure:** flood 10k events faster than writes → no crash,
  bounded buffer, dropped-batch sets `hasGap`.

**The acceptance test (T-reconnect-no-dupe-no-gap):** scripted scenario —
snapshot of seq 1..100, live to 150, simulated disconnect, server advances
to 200, lossy reconnect resuming at 200, backfill of 151..200 → assert the
final cache is exactly seq 1..200, each `id` once, strictly ordered. This is
the testable embodiment of the ticket's acceptance bullet.

Instrumented (optional, Paging integration): a Paging snapshot test
asserting no duplicate `id` across `PagingData` pages after a reconnect.

## 12. Dependencies & Sequencing

- **AND-144 (SSE transport)** — hard dependency. Provides
  `SseEventSource`, `SseEnvelope`, `ConnectionState` incl.
  `Reconnected(firstSeq)` and `Last-Event-ID` resume. AND-148 cannot detect
  lossy reconnects without `firstSeq`; this is a contract requirement on
  AND-144.
- **AND-116 (Paging/RemoteMediator + snapshot endpoint)** — hard
  dependency. Provides the Room table schema, `PagingSource`, and the
  `GET /ui/events` snapshot client AND-148 reuses for backfill.
- **Blocks:** the feature feed UI tickets that render `pagingFlow()` and the
  gap/connection state (E20 feed screens). Those consume but do not modify
  the reconciler.
- **Sequencing:** implement after both deps merge to `android-port`. Order:
  entities + DAO + cursor → `apply()`/ordering (unit-test) → reconnect/gap
  detection → backfill wiring → backpressure → acceptance test.

## 13. Risks & Open Questions

- **R1 — server `seq` monotonicity per stream:** the whole design assumes a
  monotonic, gap-meaningful `seq`. **Status after review: NOT present in the
  current contract.** OpenAPI `NotificationOut`/`ActivityOut` and the SSE
  payloads observed in the web client expose `notification_id`/`activity_id`
  + an epoch `created_at`, but **no `seq`**. Either (a) the backend must add
  a per-stream monotonic `seq` (and AND-144 must surface it + a resume
  token), or (b) AND-148 must order by `(created_at, id)` and treat every
  reconnect as lossy (cursor-paged snapshot backstop). Decide before build.
- **R2 — does the SSE stream replay on reconnect?** **Status after review:
  the web client does NOT use `Last-Event-ID`;** it reconnects with
  exponential backoff and re-fetches/invalidates. So today there is no
  token-replay guarantee and backfill is the primary recovery path. Affects
  test weighting (weight lossy-reconnect/backfill cases heavily).
- **R3 — gap window size:** an unbounded backfill window (long offline)
  could be huge. *Mitigation:* cap backfill at a max window; beyond it,
  fall back to a full snapshot refresh of the head pages and trim.
- **R4 — delete vs ordering:** deletes carry `seq`; ensure a late delete for
  an `id` not yet inserted is still effective (insert-then-delete races).
  Handled by `id`-keyed delete being position-independent.
- **R5 — multi-stream:** initial scope is per-`streamId`; confirm whether a
  single SSE connection multiplexes streams (then `apply()` must route by
  `env.streamId`, already supported).

## 14. Acceptance Criteria

AC-1. After snapshot load + live updates + a simulated lossy SSE reconnect,
the cache contains every `seq` in the covered range with **zero duplicate
`id`s and zero missing `seq`** — verified by the automated
T-reconnect-no-dupe-no-gap test (maps directly to the ticket's acceptance
bullet).

AC-2. The list returned to the UI is strictly ordered `seq DESC, id DESC`
under arbitrary event interleaving (T-order passes).

AC-3. Re-applying any event (same `id`) any number of times leaves the cache
byte-identical to applying it once (T-dedupe/T-replay pass).

AC-4. A detected `seq` jump on reconnect produces a gap marker and a bounded
REST backfill of exactly the missing window; the gap clears only after the
window is fully persisted (T-gap-detect, T-backfill-clears-gap pass).

AC-5. Gap and head state survive process death (T-process-death passes).

AC-6. Under a flood of events exceeding write throughput, the app does not
OOM or crash; dropped batches are recovered via the gap/backfill path
(T-backpressure passes).

AC-7. No event `payloadJson` appears in any log output at any level.

## 15. Definition of Done

- `LiveReconciler`, `SnapshotBackfiller`, `EventEntity`,
  `StreamCursorEntity`, and their DAOs implemented in
  `com.testlogon.android.core.data.reconcile` and Hilt-bound.
- All §11 unit tests plus the acceptance test green in CI; the merge logic
  has no Android-runtime dependency in its unit path.
- `pagingFlow(streamId)` consumed by at least one feature screen behind the
  E20 feed UI (smoke-verified) without modification to the reconciler.
- Telemetry events from §10 emitted and verified payload-free.
- KtLint/Detekt clean; no new lint baseline entries.
- Reviewed and merged to `android-port`; the AND-144/AND-116 contract
  assumptions (R1/R2) confirmed or filed as follow-ups.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Auth = cookie session + `X-CSRF-Token` header.** VERDICT: Verified.
   SOURCE: `src/api/client.ts` (reads `ui_csrf` cookie → sets
   `X-CSRF-Token`; all requests use `credentials: "include"`).

2. **On 401 the client refreshes once via `POST /ui/session/refresh` then
   retries.** VERDICT: Verified. SOURCE: OpenAPI `POST /ui/session/refresh`
   (`resp=200`, no request body); `src/api/client.ts` `refreshSession()` +
   the 401 handler (single-flight `refreshPromise`, one retry).

3. **422 error shape is FastAPI `HTTPValidationError`
   `{detail:[{loc,msg,type}]}`.** VERDICT: Verified. SOURCE: OpenAPI
   `components.schemas.HTTPValidationError` → `ValidationError`; every
   listed endpoint declares `422:HTTPValidationError`.

4. **Snapshot/list endpoint `GET /ui/events?stream&before_seq&limit` with
   response `{items:[{id,seq,type,stream,created_at,payload}],
   next_before_seq, has_more}`.** VERDICT: Corrected. SOURCE: OpenAPI index
   has **no** `/ui/events`. Real: `GET /ui/notifications` →
   `NotificationListResponse {items, next_cursor, unread_count}` and
   `GET /ui/activity/feed` → `ActivityFeedResponse {items, next_cursor,
   total_unread}`; params are `cursor,limit`. Item key is `notification_id`
   / `activity_id`; `created_at` is an epoch integer; **no `seq`**, **no
   `next_before_seq`/`has_more`**. (OpenAPI `GET /ui/notifications`,
   `GET /ui/activity/feed`; schemas `NotificationListResponse`,
   `NotificationOut`, `ActivityFeedResponse`, `ActivityOut`.)

5. **SSE endpoint `GET /ui/events/stream?stream` with `Last-Event-ID`
   resume.** VERDICT: Corrected. SOURCE: OpenAPI has **no**
   `/ui/events/stream`. Real SSE: `GET /messaging/events/stream`
   (`params=after,limit,poll_ms`) and `GET /ui/alerts/stream`; consumed via
   `EventSource` in `src/hooks/useMessagingStream.ts`
   (`MESSAGING_STREAM_URL = "/messaging/events/stream"`) and
   `src/hooks/useAlertStream.ts` (`alertStreamUrl` from
   `src/api/endpoints/alerts.ts` = `"/ui/alerts/stream"`).

6. **SSE frame uses `op: upsert|delete` and a numeric `seq`.** VERDICT:
   Corrected / Unverified-assumption. SOURCE: `src/hooks/useMessagingStream.ts`
   (events are server-typed names: `message:new`, `message:revoked`,
   `message:edited`, `presence:update`, `call.*`, `webrtc.*`; `data` carries
   `conversation_id`/`message_id` — no `op`, no `seq`) and
   `src/hooks/useAlertStream.ts` (`new_alert`/`alert_read`/`hello`/`sync`/
   `heartbeat`; fields `alert_id`, `unread_delta`, `unread_count` — no `seq`,
   no `op`). The `op`/`seq` model is an Android-side assumption.

7. **`Last-Event-ID` token resume / lossless replay on reconnect.** VERDICT:
   Corrected (web does not do this). SOURCE: `src/hooks/useMessagingStream.ts`
   and `src/hooks/useAlertStream.ts` — `onerror` closes and reconnects with
   exponential backoff (`MAX_RETRY_DELAY = 30_000`); no `Last-Event-ID` is
   sent; recovery is by re-fetch/invalidate. `heartbeat` resets backoff.

8. **SSE reconnect backoff is bounded.** VERDICT: Verified. SOURCE:
   `src/hooks/useMessagingStream.ts` / `useAlertStream.ts`
   (`Math.min(1000 * 2**retry, 30_000)`).

9. **Both inputs ride the shared cookie jar (SSE uses cookie auth).**
   VERDICT: Verified. SOURCE: `EventSource(url, { withCredentials: true })`
   in `src/hooks/useMessagingStream.ts` and `useAlertStream.ts`; REST via
   `credentials: "include"` in `src/api/client.ts`.

10. **Per-stream monotonic `seq` exists in the backend; `Last-Event-ID`
    maps to `seq`; SSE multiplexes streams by a `stream` selector.** VERDICT:
    Unverified-assumption. SOURCE: not found in OpenAPI schemas or web
    client. The real streams are fixed-path (`/messaging/events/stream`,
    `/ui/alerts/stream`) with no `stream` query selector for partitioning.

11. **Reconciler is a pure `core-data` concern (Room/Paging3/Moshi/Retrofit
    stack) consuming AND-144 (SSE) and AND-116 (snapshot mediator).**
    VERDICT: Unverified-assumption (internal Android architecture; no
    external contract source). The Kotlin/Room/Paging 3 choices are
    framework refs: Paging 3 RemoteMediator —
    https://developer.android.com/topic/libraries/architecture/paging/v3-network-db
    ; Room transactions — https://developer.android.com/training/data-storage/room ;
    `Flow.buffer`/`conflate` backpressure —
    https://kotlinlang.org/api/kotlinx.coroutines/kotlinx-coroutines-core/kotlinx.coroutines.flow/buffer.html
    (framework ref).

12. **Dev backend is plaintext HTTP at `http://18.222.237.167:8000`.**
    VERDICT: Unverified-assumption (carried from §2; not independently
    confirmable from the OpenAPI/frontend sources provided).

### Corrections made

- §2 Backend bullet: removed the false `/ui/events` + `/ui/events/stream`
  claim; named the real snapshot (`/ui/notifications`, `/ui/activity/feed`,
  cursor-paginated) and SSE (`/messaging/events/stream`, `/ui/alerts/stream`)
  endpoints; flagged that `seq`/`op` are not in the contract.
- §5.1: replaced the non-existent `GET /ui/events?...before_seq` and its
  fabricated response with the verified cursor-paged
  `NotificationListResponse`/`ActivityFeedResponse` shapes; corrected item
  key to `notification_id`/`activity_id`, `created_at` to epoch int, and
  removed `next_before_seq`/`has_more`.
- §5.2: replaced `/ui/events/stream` + `op`/`seq`/`Last-Event-ID` frame
  format with the real typed-event SSE model and backoff-based reconnect;
  noted reconnect must be treated as potentially lossy.
- §5.3: pinned the 422 shape to the verified `HTTPValidationError`.
- §13 R1/R2: updated from "open question" to reviewed status — `seq` and
  `Last-Event-ID` replay are confirmed **absent** from the current contract.

### Open assumptions

- **Per-stream monotonic `seq`** (FR-1/FR-3/FR-6 ordering + gap math): not in
  the contract; depends on a backend change or an `(created_at,id)` fallback.
  Why unverifiable: no `seq` field in any list schema or SSE payload.
- **`op: upsert|delete` envelope field**: not in the contract; deletes are
  distinct typed events (`message:revoked`/`message:expired`). Why: web
  client branches on event-type names, never an `op` field.
- **`Last-Event-ID` / `firstSeq`-jump lossy-reconnect detection** (FR-6,
  §4.3): web client does not send a resume token. Why: AND-144 contract for
  `ConnectionState.Reconnected(firstSeq)` is internal and unbuilt; needs
  backend resume support to be lossless.
- **`stream` query selector multiplexing multiple streams over one SSE
  connection** (R5): real endpoints are fixed-path with no `stream` param.
- **Dev host plaintext HTTP** (§8): carried assumption, not confirmable here.

## 17. Test Plan

IDs `TC-AND-148-NN`. The merge logic is pure JVM-testable; only a few cases
need a device. Targets: JVM/Robolectric (local), emulator AVD `test35`
(API 35 x86_64), or the physical Samsung Galaxy A15 5G (SM-A156U, API 34,
arm64-v8a). MockWebServer is used for contract/backfill cases.

- **TC-AND-148-01 — De-dup across origins (happy path).** Type: unit (JVM,
  in-memory Room). Target: JVM. Preconditions: empty `events` table.
  Steps: `apply()` the same `id` 5× alternating `Origin.LIVE`/`SNAPSHOT`
  with changing payloads. Expected: exactly one row for that `id`; contents
  = last write; `updatedAtEpochMs` = last write time. Traces: AC-3.

- **TC-AND-148-02 — Deterministic ordering.** Type: unit (JVM, in-memory
  Room). Target: JVM. Preconditions: empty table. Steps: insert events with
  shuffled `seq` (incl. equal `seq`, different `id`); query the
  `PagingSource`. Expected: rows strictly ordered `seq DESC, id DESC`.
  Traces: AC-2.
  Note: if R1 resolves to no `seq`, re-target ordering to `(created_at,id)`.

- **TC-AND-148-03 — Live insert at head / late event in place.** Type: unit
  (JVM). Target: JVM. Preconditions: cache head `seq=150`. Steps: apply a
  live event `seq=151` (newer) then one `seq=120` (late). Expected: 151 at
  top without reload; 120 inserted at its sorted position, not at top.
  Traces: AC-2 (ordering of live/late events).

- **TC-AND-148-04 — Delete/tombstone idempotency.** Type: unit (JVM).
  Target: JVM. Preconditions: row `id=A` present. Steps: apply delete for
  `A`; apply delete for unknown `id=Z`. Expected: `A` removed; deleting `Z`
  is a no-op (no row, no error). Traces: AC-3 (idempotent re-apply incl.
  deletes).

- **TC-AND-148-05 — Gap detection + bounded backfill window.** Type: unit
  (JVM) with fake `SnapshotBackfiller`. Target: JVM. Preconditions:
  persisted `headSeq=100`. Steps: signal reconnect `firstSeq=110`. Expected:
  gap `[101,109]` computed, `hasGap=true`, gap marker emitted, backfill
  enqueued for exactly that window; `reconcile_gap_detected` telemetry
  emitted. Traces: AC-4.

- **TC-AND-148-06 — Lossless reconnect (no gap).** Type: unit (JVM). Target:
  JVM. Preconditions: `headSeq=100`. Steps: reconnect `firstSeq=101`.
  Expected: no gap, `hasGap` stays false, no backfill enqueued. Traces:
  AC-4 (negative case).

- **TC-AND-148-07 — Backfill clears gap only after full persist.** Type:
  contract/MockWebServer. Target: JVM + MockWebServer. Preconditions: gap
  `[101,109]`, `hasGap=true`. Steps: stub the **real** cursor-paged
  endpoint (`GET /ui/notifications?cursor&limit`, response
  `NotificationListResponse {items, next_cursor, unread_count}`) to return
  the window across 2 pages; run backfill. Expected: rows persisted with
  `Origin.SNAPSHOT`; `hasGap` flips false only after the final page commits;
  a simulated partial persist (interrupt before last page) leaves
  `hasGap=true`. Traces: AC-4.

- **TC-AND-148-08 — 422 / validation error from backfill.** Type:
  contract/MockWebServer. Target: JVM + MockWebServer. Preconditions: gap
  open. Steps: stub the snapshot endpoint to return `422` with body
  `{"detail":[{"loc":["query","cursor"],"msg":"invalid","type":"value_error"}]}`.
  Expected: `core-network` maps it to `ApiResult.Error` (the `[{msg}]`
  branch); `hasGap` preserved; gap marker remains; non-fatal error surfaced;
  `reconcile_backfill_result outcome=error` logged at WARN. Traces: AC-4,
  AC-7 (no payload leak in the error log).

- **TC-AND-148-09 — 401 during backfill triggers single refresh + retry.**
  Type: contract/MockWebServer. Target: JVM + MockWebServer. Preconditions:
  gap open; authenticated session. Steps: stub snapshot → `401`, stub
  `POST /ui/session/refresh` → `200`, stub snapshot retry → `200` window.
  Expected: exactly one refresh, then retry succeeds, gap clears. Variant:
  refresh also `401` → `ApiResult.Error`, gap preserved, non-fatal banner.
  Traces: AC-4.

- **TC-AND-148-10 — Flaky/offline dev host: retries exhaust, gap stays.**
  Type: contract/MockWebServer (offline path). Target: JVM + MockWebServer.
  Preconditions: gap open. Steps: stub snapshot to time out / drop the
  connection repeatedly (simulate the unreliable plaintext dev host) past
  the bounded GET-retry budget (~20 s, bounded backoff). Expected: no crash;
  `hasGap` stays true; gap marker remains so pull-to-refresh can retry;
  `reconcile_backfill_result outcome=error attempts=N` at WARN. Traces:
  AC-4, AC-6 (recovery via gap path).

- **TC-AND-148-11 — Process-death durability.** Type: integration
  (Robolectric or instrumented, on-disk Room). Target: emulator `test35`
  (preferred for real SQLite-on-Android persistence; Robolectric acceptable
  for CI). Preconditions: persisted `stream_cursor` with `headSeq`,
  `contiguousFromSeq`, `lastEventId`, `hasGap=true`. Steps: close and rebuild
  the reconciler/DB from disk. Expected: head + gap state recovered exactly;
  reconnect logic uses the persisted watermark. Traces: AC-5.

- **TC-AND-148-12 — Backpressure under event flood (no OOM).** Type:
  integration (JVM `runTest` + in-memory Room). Target: JVM (deterministic);
  optionally re-run on the **physical device** to confirm arm64/API-34
  behavior under real GC/IO pressure. Preconditions: writer slower than
  producer. Steps: emit 10k envelopes faster than DB writes. Expected:
  bounded buffer, no unbounded growth, no crash/OOM; a dropped batch sets
  `hasGap=true` so the backstop reconciles it. Traces: AC-6.
  Note: the arm64-vs-x86 re-run is the case that MUST use the physical
  device if ABI-specific behavior is suspected.

- **TC-AND-148-13 — Acceptance: reconnect, no dup / no gap.** Type:
  integration (scripted end-to-end of the merge engine). Target: emulator
  `test35`. Preconditions: empty cache. Steps: snapshot seq 1..100 → live to
  150 → simulated disconnect → server advances to 200 → lossy reconnect
  resuming at 200 → cursor-paged backfill of 151..200. Expected: final cache
  is exactly seq 1..200, each `id` exactly once, strictly `seq DESC, id DESC`;
  no duplicate `id` across `PagingData` pages. Traces: AC-1, AC-2, AC-3.

- **TC-AND-148-14 — No payload in logs (security/privacy).** Type: unit
  (JVM, log capture). Target: JVM. Preconditions: capture Timber + analytics
  sink. Steps: drive apply/gap/backfill/reconnect paths with a payload
  containing a unique sentinel string. Expected: the sentinel
  (`payloadJson`/event body) never appears at any log level; only structured
  fields (`streamId`, `op`, `seq`, counts, outcomes) are present. Traces:
  AC-7.

- **TC-AND-148-15 — Gap-marker accessibility (downstream UI).** Type:
  Compose-UI (instrumented). Target: emulator `test35` (a11y assertions run
  well headless). Preconditions: feed screen rendering a gap marker +
  Reconnecting/Stale indicator from `FeedUiState`. Steps: render with
  TalkBack/semantics enabled; inspect semantics tree. Expected: gap marker
  exposes a localized content description (`feed_gap_loading`/
  `feed_gap_retry`); the Reconnecting/Stale state is distinguishable without
  relying on color alone. Traces: AC-1 (user-visible reconciliation state);
  satisfies §9. Note: this verifies the contract AND-148 passes downstream;
  the consuming UI ticket owns final placement.

### Coverage matrix

| AC   | Covered by |
|------|------------|
| AC-1 | TC-AND-148-13, TC-AND-148-15 |
| AC-2 | TC-AND-148-02, TC-AND-148-03, TC-AND-148-13 |
| AC-3 | TC-AND-148-01, TC-AND-148-04, TC-AND-148-13 |
| AC-4 | TC-AND-148-05, TC-AND-148-06, TC-AND-148-07, TC-AND-148-08, TC-AND-148-09, TC-AND-148-10 |
| AC-5 | TC-AND-148-11 |
| AC-6 | TC-AND-148-10, TC-AND-148-12 |
| AC-7 | TC-AND-148-08, TC-AND-148-14 |
