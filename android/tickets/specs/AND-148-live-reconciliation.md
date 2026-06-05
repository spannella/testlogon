---
id: AND-148
title: Live reconciliation
milestone: M3
epic: E20
priority: P0
size: L
status: draft
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
  (plaintext HTTP, unreliable). OpenAPI at `/openapi.json`. The list
  snapshot endpoint and the `/ui/events/stream` SSE endpoint are the two
  inputs (paths confirmed in §5). DynamoDB ordering is by a monotonic
  `seq` per stream plus an item `id`.
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

`GET /ui/events?stream={streamId}&before_seq={n}&limit={n}` (cursor
pagination). Backfill uses `before_seq`/`after_seq` to bound the window.

Response:
```json
{
  "items": [
    {"id":"evt_01H...","seq":4821,"type":"login.success",
     "stream":"notifications","created_at":"2026-06-05T12:00:01Z",
     "payload":{"...":"..."}}
  ],
  "next_before_seq": 4801,
  "has_more": true
}
```

### 5.2 SSE stream (owned by AND-144; consumed here)

`GET /ui/events/stream?stream={streamId}` with header
`Last-Event-ID: {token}` on resume. Each frame:
```
id: evt_01HX...
event: upsert
data: {"id":"evt_01HX...","seq":4822,"op":"upsert","type":"login.success",
       "stream":"notifications","created_at":"2026-06-05T12:00:02Z",
       "payload":{"...":"..."}}
```
Delete frames use `event: delete` with `data:{"id":...,"seq":...,"op":"delete"}`.

### 5.3 Error envelope

FastAPI `detail` is mapped per the project rule (string | `[{msg}]` |
`{code,...}`) by `core-network`; the backfill surfaces it as
`ApiResult.Error`. SSE transport errors arrive as `ConnectionState` from
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
  monotonic, gap-meaningful `seq`. *Open:* confirm via `/openapi.json` and
  backend that `seq` is per-stream monotonic and that `Last-Event-ID` maps
  to `seq`. If `seq` is global, gap windows must be stream-filtered.
- **R2 — does the SSE stream replay on reconnect?** If the server replays
  from `Last-Event-ID` reliably, lossy paths are rare; if it only sends new
  events, backfill is the primary recovery path. Affects test weighting.
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
