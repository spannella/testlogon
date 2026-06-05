---
id: AND-150
title: Real-time tests
milestone: M3
epic: E20
priority: P1
size: M
status: draft
depends_on: [AND-148]
blocks: []
---

# AND-150 — Real-time tests

## 1. Overview & Goal

This ticket delivers the deterministic automated test suite that locks down the
real-time messaging behavior built in the SSE stack (AND-143 SSE client core,
AND-144 messaging events stream, AND-148 live reconciliation). It is a **Test**
ticket: it adds no production behavior of its own. Its goal is to prove, under
JVM-deterministic conditions, that Server-Sent Events are merged into the
cache/paging data set **without duplicates and without gaps**, that ordering is
preserved, and that the client **reconnects and reconciles correctly after a
connection drop**.

The success condition is narrow and measurable: the test suite runs
headlessly (`./gradlew :feature-messaging:test :core-network:test`), is fully
deterministic (no `Thread.sleep`, no real network, virtual time only), and every
reconciliation/reconnect scenario enumerated in §3 passes on every run.

These tests are the regression guard for the hardest correctness property of the
messaging feature — that the union of a paged REST snapshot and a live SSE tail
is exactly the true message set, exactly once, in order — across reconnects where
the server may replay, drop, or reorder events.

## 2. Context & References

- **Source ticket:** AND-150 — Real-time tests · Type: Test · Priority: P1 ·
  Deps: AND-148. Scope: "SSE reconciliation + reconnect tests." Acceptance:
  "Deterministic tests pass."
- **System under test (SUT):**
  - `AND-143` — `SseClient`: OkHttp `EventSource` wrapper, lifecycle-aware, sends
    auth/CSRF cookies, reconnect/backoff, exposes `Flow<SseEvent>`.
  - `AND-144` — messaging events stream: subscribes `/messaging/events/stream`
    (and `/events`), dispatches `new-message` / `message-edited` /
    `message-deleted` events.
  - `AND-148` — live reconciliation: merges SSE events with the Room cache and
    Paging 3 stream without dupes/gaps; ordering. **This ticket's deps.**
  - Underpinned by `AND-116` (SWR base repository) and `AND-009`
    (Retrofit/OkHttp/cookie-jar networking).
- **Repo:** `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. Package base `com.testlogon.android`.
- **Web reference:** `frontend/src/api/endpoints/*.ts` SSE consumers and
  `frontend/src/api/types.ts` event payload shapes are the canonical schema
  reference; the Kotlin event models in `core-model` must match them.
- **Test infra:** `core-testing` module (shared rules, fakes, dispatchers),
  JUnit4 + `kotlinx-coroutines-test` (`runTest`, `StandardTestDispatcher`,
  virtual time), Turbine for `Flow` assertions, OkHttp `MockWebServer` for
  transport-level SSE framing, Room in-memory database, Truth for assertions.
- **Pattern precedent:** AND-069 (Dashboard states + tests) establishes the
  headless UI/unit test convention; this ticket mirrors that for the data layer.

## 3. Functional Requirements

The deliverable is a test module. "Functional requirements" here are the
behaviors the tests must assert against the SUT.

**FR-1 — Reconciliation: no duplicates.** When an SSE `new-message` event
arrives for a message already present in the cache (because the REST page that
backs the Paging stream already contained it, or because the server replayed it
after reconnect), the reconciled output MUST contain exactly one entry for that
message id.

**FR-2 — Reconciliation: no gaps.** When the REST snapshot covers ids up to
`Last-Event-ID = N` and SSE delivers `N+1, N+2, …`, the reconciled set MUST be
contiguous with no missing ids; if a gap is detected (a live event whose
predecessor is unknown), the repository MUST trigger a backfill fetch and the
test MUST assert the gap is closed.

**FR-3 — Ordering.** Reconciled messages are ordered by the canonical sort key
(`created_at` then `id` tiebreak, ascending in-thread). Out-of-order SSE arrival
MUST result in correctly ordered output.

**FR-4 — Edit / delete reconciliation.** A `message-edited` event updates the
cached row in place (no duplicate, body/edited flag updated); a
`message-deleted` event removes the row (or tombstones it). Tests assert the
final projection.

**FR-5 — Reconnect with `Last-Event-ID`.** After a stream drop, the client
reconnects sending the last successfully processed event id as the
`Last-Event-ID` header. The test asserts the header value on the second
MockWebServer request.

**FR-6 — Reconnect backoff is deterministic.** Reconnect delay is driven by the
injected test dispatcher's virtual clock; tests advance virtual time and assert
the reconnect schedule (e.g. bounded exponential backoff capped per AND-143)
without any wall-clock waiting.

**FR-7 — Replay-after-reconnect is idempotent.** If the server replays events
≤ `Last-Event-ID` on reconnect (overlap), reconciliation drops the overlap;
FR-1 still holds.

**FR-8 — Determinism.** No test uses `Thread.sleep`, real time, real sockets to
the dev backend, or random ordering. All concurrency runs on
`StandardTestDispatcher`; all time advanced via `advanceTimeBy` /
`advanceUntilIdle`. Repeated runs produce identical results.

## 4. Technical Design

### 4.1 Test module layout

Tests live alongside the SUT they exercise:

```
feature-messaging/src/test/java/com/testlogon/android/feature/messaging/
    ReconciliationTest.kt           // FR-1..FR-4, FR-7
    ReconnectReconciliationTest.kt  // FR-5..FR-7 end-to-end
    fakes/FakeMessagesRemote.kt
    builders/MessageFixtures.kt
core-network/src/test/java/com/testlogon/android/core/network/sse/
    SseClientReconnectTest.kt       // transport-level reconnect/backoff
```

Shared helpers (dispatcher rule, MockWebServer SSE dispatcher, Turbine
extensions) are promoted to `core-testing` for reuse.

### 4.2 Coroutine / time control

```kotlin
class MainDispatcherRule(
    val dispatcher: TestDispatcher = StandardTestDispatcher(),
) : TestWatcher() {
    override fun starting(d: Description) = Dispatchers.setMain(dispatcher)
    override fun finished(d: Description) = Dispatchers.resetMain()
}
```

The SUT under AND-143/148 must already accept an injected `CoroutineDispatcher`
and a backoff delay primitive routed through `delay()` so virtual time controls
reconnect timing. The tests pass `mainDispatcherRule.dispatcher` into the
repository/client constructors via the test-only Hilt overrides or direct
construction.

### 4.3 Transport-level SSE: MockWebServer dispatcher

`SseClientReconnectTest` drives the real `SseClient` over `MockWebServer` to
validate framing, `Last-Event-ID`, and reconnect at the wire level:

```kotlin
private fun sseResponse(body: String) = MockResponse()
    .setHeader("Content-Type", "text/event-stream")
    .setBody(body)            // "id: 41\nevent: new-message\ndata: {...}\n\n"
    .setSocketPolicy(SocketPolicy.DISCONNECT_AT_END) // force a drop → reconnect
```

A `Dispatcher` subclass inspects `request.getHeader("Last-Event-ID")` and the
`Cookie` / `X-CSRF-Token` headers, returning the first stream, then on the
reconnect request returns the replay/tail stream. The test records the captured
requests for FR-5/FR-7 assertions.

### 4.4 Repository-level reconciliation: fakes

`ReconciliationTest` exercises the AND-148 reconciliation logic against an
in-memory Room DB and a fake remote, feeding SSE events through a `MutableSharedFlow`
to control arrival order precisely:

```kotlin
val events = MutableSharedFlow<SseEvent>(extraBufferCapacity = 64)
val repo = MessageRepository(
    dao = inMemoryDb.messageDao(),
    remote = FakeMessagesRemote(pages),
    sseEvents = events,            // injected instead of live SseClient
    dispatcher = rule.dispatcher,
)

repo.observeThread(threadId).test {     // Turbine
    val initial = awaitItem()           // cache → REST (SWR)
    events.emit(newMessage(id = 42))
    val merged = awaitItem()
    assertThat(merged.map { it.id }).containsNoDuplicates()
    assertThat(merged.map { it.id }).isInOrder()
    cancelAndIgnoreRemainingEvents()
}
```

### 4.5 Property-style duplicate/gap oracle

A shared assertion helper encodes FR-1/FR-2/FR-3 as one invariant so each
scenario reuses it:

```kotlin
fun List<MessageUi>.assertReconciled(expectedIds: Set<Long>) {
    val ids = map { it.id }
    assertThat(ids).containsExactlyElementsIn(expectedIds)  // no dupes, no gaps
    assertThat(ids).isInStrictOrder(compareBy(MessageUi::sortKey))
}
```

## 5. API Contract

This ticket defines no new API surface. The tests **mock** the real endpoints;
the shapes below are the contract the fakes/MockWebServer must reproduce so the
tests remain faithful to production.

**SSE stream** (`GET /messaging/events/stream`, also `/events`), wire framing:

```
id: 42
event: new-message
data: {"message_id":42,"thread_id":"t_8","author_id":"u_3","body":"hi",
       "created_at":"2026-06-05T12:00:01Z","seq":42}

```

Reconnect request issued by the client carries the resume cursor:

```
GET /messaging/events/stream HTTP/1.1
Last-Event-ID: 42
Cookie: session=...; ui_csrf=...
X-CSRF-Token: <echo of ui_csrf>
```

**Event payload types** (must match `core-model`, mirroring
`frontend/src/api/types.ts`): `new-message` / `message-edited` /
`message-deleted`, each carrying `message_id`, `thread_id`, `seq`, and (for
edit) the new `body`/`edited_at`. The REST snapshot the Paging source returns
(`GET /messaging/threads/{id}/messages?cursor=`) is faked to a fixed page set so
the reconciliation boundary (`seq` of last REST item vs first SSE `seq`) is
controlled by the test.

## 6. Data & State Management

The tests assert against the production state model without introducing new
state. Relevant elements:

- **Room cache:** `MessageEntity(id, threadId, seq, body, createdAt, editedAt,
  deleted)`. Tests use `Room.inMemoryDatabaseBuilder(...).allowMainThreadQueries()`
  and assert DAO contents after reconciliation (FR-4 edit/delete persistence).
- **Reconciliation key:** `seq` is the gap/duplicate detector; `sortKey =
  (createdAt, id)` is the order key. Tests fix both in fixtures.
- **UiState:** the repository emits `Flow<List<MessageUi>>` (or
  `PagingData<MessageUi>` snapshotted via `AsyncPagingDataDiffer` in a JVM test);
  tests use Turbine to capture the SWR sequence: cache emission → fresh emission
  → live-merged emission.
- **Resume cursor state:** `lastEventId` held by the client; tests assert it
  advances monotonically and is the value sent on reconnect (FR-5).

`MessageFixtures` provides deterministic builders:

```kotlin
fun message(id: Long, seq: Long = id, createdAt: String = iso(id)): MessageEntity
fun page(range: LongRange): List<MessageEntity>
fun newMessage(id: Long): SseEvent.NewMessage
```

## 7. Error Handling & Resilience

The tests must cover the resilience paths of the SUT (this is the core of the
ticket), not merely the happy path:

- **Drop → reconnect (FR-5/FR-6):** `SocketPolicy.DISCONNECT_AT_END` simulates
  the unreliable dev host. Test advances virtual time across the backoff window
  and asserts a single reconnect with correct `Last-Event-ID`.
- **Bounded backoff:** assert delay sequence is capped (per AND-143 policy) and
  jitter, if present, is seeded/disabled in tests for determinism.
- **Replay overlap (FR-7):** server resends `seq ≤ lastEventId`; assert dedupe.
- **Gap after reconnect (FR-2):** server resumes at `seq = lastEventId + 3`
  (two missing); assert the repository performs a REST backfill for the missing
  range and the final set is contiguous.
- **401 mid-stream:** assert the AND-009 single-shot `POST /ui/session/refresh`
  then retry path is exercised (one refresh, one reconnect) — using a
  MockWebServer queue that returns 401 once. (If refresh wiring is owned by
  AND-143, this test asserts the client surfaces a re-auth signal rather than
  silently terminating.)
- **Malformed event frame:** a frame with unparseable `data` is dropped without
  crashing the stream; subsequent valid events still reconcile.

All failures must be deterministic: no real timeouts, no real `~20s` waits —
timeouts are simulated via `MockResponse` socket policies and virtual time.

## 8. Security & Privacy

No new security surface. Tests assert that production security wiring stays
intact:

- The reconnect/transport test asserts outbound SSE requests include the
  persistent session cookie and the `X-CSRF-Token` header echoing `ui_csrf`
  (cookie-based auth contract). A test fails if the SUT omits them.
- Fixtures use synthetic ids/bodies only — no real credentials, tokens, or PII
  in test resources or VCS.
- No plaintext dev-backend (`http://18.222.237.167:8000`) connections from tests;
  all traffic is local MockWebServer/loopback.

## 9. Accessibility & i18n

N/A for this ticket — it is a JVM unit/integration test suite with no UI surface
and no user-facing strings. Accessibility and localization of the messaging UI
are owned by the messaging UI tickets (E20 feature/UI tests, e.g. AND-144 and
the messaging screen tickets), not here.

## 10. Telemetry & Logging

No production telemetry is added. Test-side observability only:

- Tests assert no `Exception` is logged/thrown on the reconcile happy path by
  failing on uncaught exceptions via `runTest` (which propagates uncaught
  coroutine exceptions).
- On reconnect tests, captured `RecordedRequest` objects are attached to
  assertion failure messages (`assertWithMessage`) so CI output pinpoints which
  reconnect attempt had the wrong `Last-Event-ID`.
- If the SUT exposes a reconnect/event counter (AND-143), tests may assert on it;
  otherwise telemetry verification is deferred to that ticket.

## 11. Testing Strategy

This ticket **is** the testing strategy. Concrete coverage matrix:

| ID | Test | Asserts |
|----|------|---------|
| T1 | `live_new_message_no_duplicate_with_cached_page` | FR-1 |
| T2 | `live_event_replayed_after_reconnect_deduped` | FR-1, FR-7 |
| T3 | `gap_after_reconnect_triggers_backfill_no_gaps` | FR-2 |
| T4 | `out_of_order_sse_arrival_sorted_correctly` | FR-3 |
| T5 | `edit_event_updates_in_place` | FR-4 |
| T6 | `delete_event_removes_row` | FR-4 |
| T7 | `reconnect_sends_last_event_id_header` | FR-5 |
| T8 | `backoff_schedule_is_bounded_and_deterministic` | FR-6 |
| T9 | `401_midstream_refreshes_once_then_reconnects` | §7 |
| T10 | `malformed_frame_dropped_stream_survives` | §7 |
| T11 | `swr_emits_cache_then_fresh_then_live` | AND-116 integration |

**Frameworks:** JUnit4, `kotlinx-coroutines-test`, Turbine, OkHttp
`MockWebServer`, Room in-memory, Truth.

**Determinism guards:** a custom Lint/test-time check (or code review rule)
forbids `Thread.sleep` and `System.currentTimeMillis` in the new test sources;
all delays go through the injected dispatcher's virtual clock. Each test calls
`advanceUntilIdle()` before final assertions. Tests run with
`testOptions.unitTests.isReturnDefaultValues = true` disabled where Room is used
(real in-memory DB instead).

**Flakiness budget:** zero. Suite must pass 50/50 local re-runs
(`./gradlew test --rerun-tasks`) and on CI.

**Out of scope:** instrumented (`androidTest`) device tests, screenshot tests,
and end-to-end against the live backend.

## 12. Dependencies & Sequencing

- **Hard dependency:** AND-148 (live reconciliation) — the SUT for FR-1..FR-4,
  FR-7. Tests cannot be written against final behavior until AND-148's
  reconciliation API (`MessageRepository.observeThread`, dedupe/gap logic) is
  merged.
- **Transitive:** AND-143 (SSE client core, reconnect/`Last-Event-ID`/backoff)
  for FR-5/FR-6 and the transport test; AND-144 (event dispatch + payload types)
  for event modeling; AND-116 (SWR) for T11; AND-009 (cookie jar / refresh) for
  T9.
- **Enabler requirement on upstream:** AND-143/148 must expose injectable
  `CoroutineDispatcher` and a seam to feed SSE events (e.g. accept a
  `Flow<SseEvent>` or `EventSource.Factory`) so tests can avoid real sockets. If
  these seams are missing, this ticket is blocked pending a small refactor PR
  against AND-143/148.
- **Blocks:** nothing directly; it is a quality gate that should be required for
  the E20 messaging milestone (M3) sign-off.

## 13. Risks & Open Questions

- **R1 — Non-injectable timing in AND-143.** If reconnect backoff uses
  `Thread.sleep`/real `System.nanoTime`, FR-6 cannot be made deterministic.
  *Mitigation:* require `delay()`-based backoff with injected dispatcher before
  this ticket starts.
- **R2 — `Last-Event-ID` semantics.** Open question: does the backend use the
  SSE `id:` field, a `seq` body field, or both as the resume cursor? Tests must
  match production. *Resolution:* confirm against `/openapi.json` and
  `frontend/src/api/endpoints/*.ts` before fixing fixtures; default assumption is
  the SSE `id:` line equals `seq`.
- **R3 — Gap backfill ownership.** Whether gap-fill is in AND-148 or deferred.
  If AND-148 does not backfill, T3 asserts gap *detection* (surfaced state)
  rather than gap *closure*, and a follow-up ticket owns closure.
- **R4 — Paging snapshotting in JVM tests.** `PagingData` is awkward to assert
  off-device. *Mitigation:* assert on the repository's pre-paging
  `Flow<List<MessageUi>>`, or use `AsyncPagingDataDiffer` with the test
  dispatcher; pick one and document it.
- **R5 — MockWebServer SSE chunking.** Ensuring the client sees discrete events
  may require chunked transfer / throttled body. *Mitigation:* use
  `setChunkedBody` and `setBodyDelay` driven only by virtual time abstractions
  where possible.

## 14. Acceptance Criteria

1. All tests T1–T11 (§11) exist and pass via
   `./gradlew :feature-messaging:test :core-network:test` headlessly with no
   connected device. (Maps to ticket acceptance "Deterministic tests pass.")
2. **No duplicates / no gaps across reconnect** is proven: T2 and T3 fail if the
   SUT regresses to producing duplicate ids or missing `seq` after a simulated
   drop+reconnect (maps to AND-148 acceptance).
3. Reconnect sends the correct `Last-Event-ID` (T7) and carries session +
   `X-CSRF-Token` headers (§8).
4. Suite is deterministic: passes 50 consecutive runs
   (`./gradlew test --rerun-tasks`) with zero flakes; no `Thread.sleep` / real
   wall-clock waits in new test sources.
5. Ordering (T4) and edit/delete reconciliation (T5/T6) verified against
   in-memory Room state.
6. Backoff schedule (T8) and single-shot 401 refresh-then-reconnect (T9)
   verified via virtual time and MockWebServer.
7. New shared test utilities (`MainDispatcherRule`, SSE MockWebServer dispatcher,
   `assertReconciled`) live in `core-testing` and are reused, not duplicated.

## 15. Definition of Done

- All §14 acceptance criteria met; coverage matrix §11 fully implemented.
- Tests reside under `feature-messaging/src/test` and `core-network/src/test`
  with shared helpers in `core-testing`, all under package base
  `com.testlogon.android`.
- `./gradlew :feature-messaging:test :core-network:test detekt lintDebug`
  passes; no new lint/detekt suppressions added except a documented rule
  forbidding `Thread.sleep` in tests.
- CI on branch `android-port` runs the new suite as part of the unit-test job and
  it is green; the job is added to required checks for the M3 messaging
  milestone.
- Any AND-143/148 seams required for determinism (R1, injectable dispatcher /
  event flow) are merged; if a behavior could not be tested (e.g. gap closure per
  R3), the gap is documented with a linked follow-up ticket.
- PR reviewed and merged; spec status moved from `draft` to done; ticket
  acceptance "Deterministic tests pass" demonstrably satisfied.
