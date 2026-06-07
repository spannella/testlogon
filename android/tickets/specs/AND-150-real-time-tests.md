---
id: AND-150
title: Real-time tests
milestone: M3
epic: E20
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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
  - `AND-144` — messaging events stream: subscribes `GET /messaging/events/stream`
    (and `GET /messaging/events`), dispatches typed SSE events. **[CORRECTED]**
    The web reference event-type names are colon-namespaced, not hyphenated:
    `message:new` / `message:edited` / `message:revoked` (deletion is surfaced as
    `message:revoked`, there is no `message-deleted`). The full set the backend
    emits is enumerated in `src/hooks/useMessagingStream.ts` (`EVENT_TYPES`).
  - `AND-148` — live reconciliation: merges SSE events with the Room cache and
    Paging 3 stream without dupes/gaps; ordering. **This ticket's deps.**
  - Underpinned by `AND-116` (SWR base repository) and `AND-009`
    (Retrofit/OkHttp/cookie-jar networking).
- **Repo:** `spannella/testlogon`, Android app under `android/`, branch
  `android-port`. Package base `com.testlogon.android`.
- **Web reference:** the SSE consumer is `frontend/src/hooks/useMessagingStream.ts`
  (browser `EventSource`, named listeners per event type) and
  `frontend/src/api/types.ts` (`Message` interface) is the canonical payload-shape
  reference; the Kotlin event models in `core-model` must match them. Transport
  auth/CSRF wiring is in `frontend/src/api/client.ts`.
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

**FR-5 — Reconnect with resume cursor.** After a stream drop, the client
reconnects sending the last successfully processed message id as the resume
cursor. **[CORRECTED]** Per the OpenAPI index the verified resume mechanism for
`GET /messaging/events/stream` is the **`after` query parameter**, not an
SSE `Last-Event-ID` HTTP header (the web client uses neither and relies on native
`EventSource` reconnect). The test asserts the `after` value on the second
MockWebServer request. If AND-143 instead chose to emit a `Last-Event-ID` header,
the test must assert whichever the implementation actually sends — but the
backend-supported contract is `after` (see §16 Open assumptions).

**FR-6 — Reconnect backoff is deterministic.** Reconnect delay is driven by the
injected test dispatcher's virtual clock; tests advance virtual time and assert
the reconnect schedule (bounded exponential backoff) without any wall-clock
waiting. **[VERIFIED reference value]** The web client's policy
(`useMessagingStream.ts`) is `delay = min(1000 * 2^retryCount, 30_000)` —
i.e. 1s, 2s, 4s, 8s, 16s, then capped at 30s, reset to 0 on a successful `onopen`.
AND-143's Kotlin policy should match this unless it intentionally diverges; the
test asserts AND-143's actual schedule.

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

**SSE stream** (`GET /messaging/events/stream`, also `GET /messaging/events`),
wire framing. **[CORRECTED]** Event name is colon-namespaced and the payload uses
the production `Message` field names — string `message_id`/`conversation_id`,
`sender_id` (not `author_id`), `text` (not `body`), and `created_at` as an **epoch
integer** (not an ISO-8601 string). There is **no `seq` field** in the payload:

```
event: message:new
data: {"message_id":"m_42","conversation_id":"c_8","sender_id":"u_3",
       "kind":"text","text":"hi","created_at":1749124801}

```

**[CORRECTED — resume cursor.]** The backend stream's resume cursor is the
`after` query parameter on `GET /messaging/events/stream`
(`params=after,limit,poll_ms,x_request_id,authorization,X-SESSION-ID` in the
OpenAPI index), **not** an SSE `Last-Event-ID` HTTP header. The web client
(`useMessagingStream.ts`) does not send `Last-Event-ID` or `after` at all — it
relies on the browser `EventSource`'s native auto-reconnect with `withCredentials:
true` (cookie auth only; `EventSource` cannot attach custom headers). The Android
`SseClient` (AND-143) is therefore free to implement resume via the `after` query
param; tests should assert on the `after` value of the reconnect request rather
than on a `Last-Event-ID` header (see §16 Open assumptions). A reconnect request
looks like:

```
GET /messaging/events/stream?after=m_42 HTTP/1.1
Cookie: session=...; ui_csrf=...
```

**Event payload types** (must match `core-model`, mirroring the `Message`
interface in `frontend/src/api/types.ts`): `message:new` / `message:edited` /
`message:revoked` (plus the wider `EVENT_TYPES` set in `useMessagingStream.ts`).
Each carries `message_id`, `conversation_id`, `sender_id`, `kind`, `created_at`,
and (for edit) `text`/`edited_at`; deletion is `message:revoked` with
`revoked_at`/`revoked_by`. **[CORRECTED — REST snapshot endpoint.]** The canonical
message-list snapshot the Paging source returns is
`GET /messaging/conversations/{conversation_id}/messages` paginated with the
**`before`** query param (resp `MessageOut` / `{messages,next_cursor}`), not
`/messaging/threads/{id}/messages?cursor=`. A separate
`GET /messaging/threads/{thread_id}/messages?cursor=` endpoint exists for threaded
replies (`getThreadMessages`) and uses `cursor`; pick the one that matches the
screen under test. Because production has no `seq`, the reconciliation boundary is
keyed on `message_id` + `created_at`, not `seq` (see §6 correction).

## 6. Data & State Management

The tests assert against the production state model without introducing new
state. Relevant elements:

- **Room cache:** `MessageEntity(id, threadId, seq, body, createdAt, editedAt,
  deleted)`. Tests use `Room.inMemoryDatabaseBuilder(...).allowMainThreadQueries()`
  and assert DAO contents after reconciliation (FR-4 edit/delete persistence).
- **Reconciliation key:** **[CORRECTED]** production payloads carry **no `seq`
  field** (verified against the `Message` interface in `src/api/types.ts`).
  Duplicate detection is therefore keyed on the string `message_id`, and ordering
  on `sortKey = (createdAt, messageId)` where `createdAt` is an epoch integer.
  References to `seq` below are retained only as the test-fixture's synthetic
  monotonic ordinal; do not assume the wire carries it. Tests fix both in
  fixtures.
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
  MockWebServer queue that returns 401 once. **[VERIFIED]** The web client
  (`src/api/client.ts` `refreshSession`/`api`) confirms this exact contract:
  `POST /ui/session/refresh` (credentials-only, no body), de-duplicated via a
  shared `refreshPromise` so concurrent 401s trigger exactly one refresh, then the
  original request is retried once; a second 401 logs the user out
  (`logout("session_expired")`). (If refresh wiring is owned by AND-143, this test
  asserts the client surfaces a re-auth signal rather than silently terminating.)
- **Malformed event frame:** a frame with unparseable `data` is dropped without
  crashing the stream; subsequent valid events still reconcile.

All failures must be deterministic: no real timeouts, no real `~20s` waits —
timeouts are simulated via `MockResponse` socket policies and virtual time.

## 8. Security & Privacy

No new security surface. Tests assert that production security wiring stays
intact:

- **[CORRECTED / CLARIFIED]** The full web transport contract
  (`src/api/client.ts`) on normal REST calls is: `Authorization: Bearer
  <accessToken>` header **plus** `X-CSRF-Token` header echoing the `ui_csrf`
  cookie **plus** `credentials: include` (session cookie). The OpenAPI also lists
  `X-SESSION-ID` (and `authorization`) as parameters on the messaging endpoints.
  Note the SSE stream specifically: the web client opens it via browser
  `EventSource` with `withCredentials: true`, which sends cookies **only** and
  **cannot** attach `Authorization`/`X-CSRF-Token` headers — so on the *stream*
  connection auth is cookie-based. The Android `SseClient` (AND-143), built on
  OkHttp, is not subject to that browser limitation and may attach the Bearer +
  CSRF + X-SESSION-ID headers; the transport test should assert whichever headers
  AND-143 actually emits, and at minimum the session cookie. A test fails if the
  SUT omits the credentials needed to authenticate the stream.
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
| T7 | `reconnect_sends_resume_cursor` (the `after` query param; see §5/§16) | FR-5 |
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
- **R2 — resume-cursor semantics.** **[RESOLVED during review]** The backend does
  **not** use an SSE `Last-Event-ID` header or a body `seq` field as the resume
  cursor. The OpenAPI index shows `GET /messaging/events/stream` accepts an
  `after` query parameter (alongside `limit`, `poll_ms`, `x_request_id`), and the
  web client (`useMessagingStream.ts`) carries no resume cursor at all (native
  `EventSource` reconnect). Fixtures must therefore key resume on `after` =
  last-seen `message_id`, not `Last-Event-ID`/`seq`. See §16.
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

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source pointer.
Sources: OpenAPI = `reference/openapi.index.txt` / `reference/openapi.pretty.json`;
frontend paths are under `reference/src/`.

1. **SSE stream endpoint is `GET /messaging/events/stream` (with `GET
   /messaging/events`).** VERDICT: **Verified.** SOURCE: OpenAPI `GET
   /messaging/events/stream` (op=`events_stream_messaging_events_stream_get`) and
   `GET /messaging/events` (op=`fetch_events_messaging_events_get`);
   `src/hooks/useMessagingStream.ts: MESSAGING_STREAM_URL = "/messaging/events/stream"`.

2. **Stream resume cursor is the `after` query param, NOT an SSE `Last-Event-ID`
   header.** VERDICT: **Corrected** (spec claimed `Last-Event-ID` header). SOURCE:
   OpenAPI `GET /messaging/events/stream` `params=after,limit,poll_ms,x_request_id,
   authorization,X-SESSION-ID`; `src/hooks/useMessagingStream.ts` sends no cursor
   (native `EventSource` reconnect, `new EventSource(url, {withCredentials:true})`).

3. **Event-type names are colon-namespaced: `message:new` / `message:edited` /
   `message:revoked` (no `message-deleted`).** VERDICT: **Corrected** (spec used
   `new-message`/`message-edited`/`message-deleted`). SOURCE:
   `src/hooks/useMessagingStream.ts: EVENT_TYPES` (lines ~166-206) and the
   `eventType === "message:new" | "message:revoked" | "message:edited"` branches.

4. **Message payload field names: string `message_id`, string `conversation_id`,
   `sender_id`, `kind`, integer `created_at` (epoch), `text`, `edited_at`,
   `revoked_at`/`revoked_by`.** VERDICT: **Corrected** (spec used `author_id`,
   `body`, ISO-string `created_at`, and `thread_id` as routing key). SOURCE:
   `src/api/types.ts: interface Message` (lines 1098-1224).

5. **There is no `seq` field in the SSE/message payload.** VERDICT: **Corrected**
   (spec treated `seq` as the wire-level gap/dup detector and resume cursor).
   SOURCE: `src/api/types.ts: interface Message` (no `seq` member); repo-wide grep
   for `seq` in `reference/src/` finds only unrelated password-policy / test code.
   Reconciliation must key on `message_id` + `created_at`.

6. **Conversation message-list snapshot is `GET
   /messaging/conversations/{conversation_id}/messages`, paginated by the `before`
   query param.** VERDICT: **Corrected** (spec said
   `/messaging/threads/{id}/messages?cursor=` as the primary list). SOURCE: OpenAPI
   `GET /messaging/conversations/{conversation_id}/messages`
   `params=conversation_id,limit,before,authorization,X-SESSION-ID`;
   `src/api/endpoints/messaging.ts: getMessages` (uses `{ before: cursor }`).

7. **A separate threaded-replies endpoint `GET
   /messaging/threads/{thread_id}/messages` exists and uses `cursor`.** VERDICT:
   **Verified** (both endpoints are real; the spec conflated them). SOURCE:
   `src/api/endpoints/messaging.ts: getThreadMessages` (uses `{ cursor, limit }`).

8. **401 handling = single-shot `POST /ui/session/refresh` (deduped), then one
   retry, else logout.** VERDICT: **Verified.** SOURCE: OpenAPI `POST
   /ui/session/refresh` (op=`ui_session_refresh_ui_session_refresh_post`,
   resp 200); `src/api/client.ts: refreshSession` + the `res.status === 401`
   block (shared `refreshPromise`, one retry, `logout("session_expired")`).

9. **Transport auth = `Authorization: Bearer <accessToken>` + `X-CSRF-Token`
   (from `ui_csrf` cookie) + `credentials: include`; messaging endpoints also list
   `X-SESSION-ID`.** VERDICT: **Corrected/clarified** (spec listed only session
   cookie + `X-CSRF-Token`). SOURCE: `src/api/client.ts` (lines ~155-184:
   `Authorization`, `getCookie("ui_csrf")` → `X-CSRF-Token`, `credentials:
   "include"`); OpenAPI messaging params include `authorization`, `X-SESSION-ID`.

10. **On the SSE stream specifically the web client uses cookies only (EventSource
    cannot set custom headers).** VERDICT: **Verified.** SOURCE:
    `src/hooks/useMessagingStream.ts: new EventSource(MESSAGING_STREAM_URL,
    {withCredentials:true})`.

11. **Reconnect backoff = `min(1000 * 2^retryCount, 30_000)`, reset on `onopen`.**
    VERDICT: **Verified** (reference value for FR-6). SOURCE:
    `src/hooks/useMessagingStream.ts` (`MAX_RETRY_DELAY = 30_000`; the `onerror`
    handler delay computation; `onopen` resets `retryCount`).

12. **Validation/error envelope: messaging endpoints return `HTTPValidationError`
    (422) and the message-controls family returns `MessageControlsErrorOut` for
    401/403/404/422/429.** VERDICT: **Verified.** SOURCE: OpenAPI `GET
    /messaging/conversations/{conversation_id}/messages`
    (`resp=200:;422:HTTPValidationError;400;401;403;429`) and the
    `/messaging/compliance/*` rows (`MessageControlsErrorOut`);
    `src/api/types.ts: interface MessageControlsErrorResp`.

13. **Test infra choices (JUnit4, kotlinx-coroutines-test, Turbine, OkHttp
    MockWebServer, Room in-memory, Truth, virtual-time dispatcher).** VERDICT:
    **Unverified-assumption** (framework refs — not derivable from backend/web
    sources). framework ref: kotlinx-coroutines-test `runTest`/`StandardTestDispatcher`
    (developer.android.com / kotlinlang.org coroutines-test guide); OkHttp
    MockWebServer SSE via `SocketPolicy.DISCONNECT_AT_END`
    (square.github.io/okhttp/mockwebserver); Turbine (github.com/cashapp/turbine).
    These are reasonable Android conventions; no contradicting evidence found.

14. **`SocketPolicy.DISCONNECT_AT_END` reliably forces one client reconnect for a
    chunked SSE body.** VERDICT: **Unverified-assumption** (MockWebServer behavior
    with the AND-143 OkHttp `EventSource` wrapper depends on AND-143's framing/retry
    code, which is not yet present in these sources). framework ref: OkHttp
    MockWebServer docs.

### Corrections made

- §2 / §5 / §11(T7): event-type names corrected to `message:new` /
  `message:edited` / `message:revoked` (was `new-message` / `message-edited` /
  `message-deleted`); `message-deleted` does not exist (deletion = `message:revoked`).
- §5 / §3 FR-5 / §13 R2: resume cursor corrected to the `after` query param (was
  SSE `Last-Event-ID` header). Web client uses neither.
- §5 / §6: payload corrected to production `Message` fields — `message_id`,
  `conversation_id`, `sender_id`, `text`, integer `created_at`; removed `author_id`,
  `body`, ISO `created_at`. Removed reliance on a wire `seq` field (does not exist);
  reconciliation re-keyed on `message_id` + `created_at`.
- §5: REST snapshot endpoint corrected to
  `GET /messaging/conversations/{conversation_id}/messages?before=…` (was
  `/messaging/threads/{id}/messages?cursor=`); the threads endpoint clarified as a
  distinct threaded-replies API.
- §8: auth model expanded to the verified contract (Bearer + `X-CSRF-Token` +
  cookies + `X-SESSION-ID`), with the note that the SSE stream itself is cookie-only
  in the web client.
- §3 FR-6: added the verified web backoff formula as the reference value.
- §2: web-reference pointer corrected to `src/hooks/useMessagingStream.ts` (the SSE
  consumer) rather than `src/api/endpoints/*.ts`.

### Open assumptions

- **AND-143 resume implementation.** Whether the Android `SseClient` resumes via
  the `after` query param (backend-supported) or an `Last-Event-ID` header (not
  backend-supported per OpenAPI) is owned by AND-143, which is not in these
  sources. Tests assert whatever AND-143 emits; the spec recommends `after`.
  Cannot be fully verified until AND-143 lands.
- **Gap backfill ownership (R3).** Whether AND-148 closes gaps (re-fetch) or only
  detects them is not determinable from backend/web sources; T3 must adapt to the
  merged AND-148 behavior.
- **Whether the stream replays `≤ after` events on reconnect (overlap).** Not
  specified in OpenAPI (`poll_ms`/`after` semantics are server-side); FR-7 assumes
  possible overlap and must dedupe regardless. Unverifiable from current sources.
- **Test framework/version specifics** (items 13-14 above) are framework-choice
  assumptions, not contract facts.

## 17. Test Plan

All cases are JVM/headless unless noted. IDs trace to the §14 Acceptance Criteria.
"Reconcile oracle" = the `assertReconciled(expectedIds)` helper (§4.5), here keyed
on `message_id`/`created_at` per the §6 correction (no `seq`).

- **TC-AND-150-01 — Live `message:new` dedupes against cached page (happy path).**
  Type: unit (Robolectric not required; pure JVM + Room in-memory).
  Target: JVM unit. Preconditions: `FakeMessagesRemote` returns a page containing
  `m_1..m_40`; in-memory Room seeded from it. Steps: collect
  `repo.observeThread/observeConversation` via Turbine; emit `message:new` for an
  id already in the page (`m_40`), then a genuinely new `m_41`. Expected: merged
  list contains each `message_id` exactly once, ordered; `m_40` not duplicated.
  Traces: AC-1, AC-2.

- **TC-AND-150-02 — Replayed event after reconnect is deduped (idempotent
  overlap).** Type: contract/MockWebServer. Target: headless emulator `test35`
  acceptable, but pure JVM preferred. Preconditions: MockWebServer SSE dispatcher
  serves stream #1 ending at `m_42` then `DISCONNECT_AT_END`; reconnect stream
  replays `m_41,m_42` then `m_43`. Steps: run `SseClient` → repo; advance virtual
  time across backoff; let reconnect occur. Expected: final set has no duplicate
  `message_id`; `m_43` appended once. Traces: AC-2.

- **TC-AND-150-03 — Gap after reconnect triggers backfill, no gaps.** Type:
  integration (repo + fake remote + Room). Target: JVM unit. Preconditions: cache
  ends at `m_42`; reconnect stream resumes at `m_45` (m_43/m_44 missing).
  Steps: drive reconnect; observe repo. Expected: repo issues a REST backfill for
  the missing range against `GET /messaging/conversations/{id}/messages?before=…`
  and the final set is contiguous (`m_1..m_45`, none missing). If AND-148 only
  detects gaps (R3), assert the surfaced gap state instead. Traces: AC-1, AC-2.

- **TC-AND-150-04 — Out-of-order SSE arrival is sorted.** Type: unit.
  Target: JVM unit. Preconditions: empty cache. Steps: emit `message:new` events
  with `created_at` out of order (m_3@t3, m_1@t1, m_2@t2). Expected: merged list
  ordered by `(created_at, message_id)` ascending. Traces: AC-5.

- **TC-AND-150-05 — `message:edited` updates row in place.** Type: integration
  (Room). Target: JVM unit. Preconditions: cache holds `m_10` with `text="a"`.
  Steps: emit `message:edited` for `m_10` with `text="b"`, `edited_at` set.
  Expected: single row for `m_10`, `text="b"`, edited flag/`edited_at` set; no
  duplicate; DAO state matches projection. Traces: AC-5.

- **TC-AND-150-06 — `message:revoked` removes/tombstones row.** Type: integration
  (Room). Target: JVM unit. Preconditions: cache holds `m_11`. Steps: emit
  `message:revoked` for `m_11` (`revoked_at`/`revoked_by` present). Expected: row
  removed or tombstoned per AND-148 policy; final projection excludes (or marks)
  `m_11`; DAO asserted. Traces: AC-5.

- **TC-AND-150-07 — Reconnect sends the correct resume cursor (`after`).** Type:
  contract/MockWebServer. Target: JVM/MockWebServer. Preconditions: SSE dispatcher
  records `RecordedRequest`s; stream #1 ends after `m_42` then disconnects.
  Steps: let `SseClient` reconnect (advance virtual time). Expected: the second
  recorded request carries `after=m_42` (query param) — or, if AND-143 emits a
  `Last-Event-ID` header instead, assert that header equals `m_42` and flag the
  divergence from the OpenAPI `after` contract. Traces: AC-3.

- **TC-AND-150-08 — Backoff schedule is bounded and deterministic.** Type: unit
  (virtual time). Target: JVM unit. Preconditions: dispatcher with virtual clock;
  jitter disabled/seeded. Steps: force repeated `onerror`/disconnect; capture
  scheduled delays via `advanceTimeBy`. Expected: delays follow AND-143's policy
  (web reference `min(1000*2^n, 30_000)`: 1s,2s,4s,8s,16s,30s,30s…) and reset to
  the base after a successful open; no wall-clock wait occurs. Traces: AC-4, AC-6.

- **TC-AND-150-09 — Single-shot 401 refresh then reconnect.** Type:
  contract/MockWebServer. Target: JVM/MockWebServer. Preconditions: queue returns
  401 once on the stream/refresh path, `POST /ui/session/refresh` returns 200, then
  the stream succeeds. Steps: run client; advance time. Expected: exactly one
  `POST /ui/session/refresh` then exactly one reconnect/retry; concurrent 401s do
  not trigger multiple refreshes (deduped); a second 401 surfaces a re-auth/logout
  signal. Traces: AC-6.

- **TC-AND-150-10 — Malformed event frame is dropped, stream survives.** Type:
  contract/MockWebServer. Target: JVM/MockWebServer. Preconditions: SSE body
  contains a frame with unparseable `data:` between two valid frames. Steps: feed
  the stream. Expected: the bad frame is ignored (no crash, mirrors the web
  client's `try/catch` around `JSON.parse`), and the surrounding valid events still
  reconcile. Traces: AC-1.

- **TC-AND-150-11 — SWR ordering: cache → fresh → live-merged.** Type: integration
  (repo + Room + fake remote). Target: JVM unit. Preconditions: Room pre-seeded;
  remote returns a fresher page. Steps: Turbine-collect `observe…`. Expected: first
  emission = cache, second = REST-fresh, third = after a live `message:new` merge;
  each emission passes the reconcile oracle. Traces: AC-1.

- **TC-AND-150-12 — Determinism / no wall-clock waits (50× re-run).** Type: unit
  (meta/CI). Target: JVM unit + CI on `test35` emulator for the instrumented
  subset. Preconditions: full new suite. Steps: `./gradlew
  :feature-messaging:test :core-network:test --rerun-tasks` 50×; static check for
  `Thread.sleep`/`System.currentTimeMillis` in new test sources. Expected: 50/50
  green, zero flakes, no banned time APIs present. Traces: AC-1, AC-4.

- **TC-AND-150-13 — Stream auth/credentials present on outbound request
  (security).** Type: contract/MockWebServer. Target: JVM/MockWebServer.
  Preconditions: cookie jar seeded with `session` + `ui_csrf`; access token set.
  Steps: open the stream via `SseClient`; inspect the `RecordedRequest`. Expected:
  the request carries at minimum the session cookie, and whichever of
  `Authorization: Bearer …` / `X-CSRF-Token` (echoing `ui_csrf`) / `X-SESSION-ID`
  AND-143 chooses to send; the test fails if no credential able to authenticate the
  stream is present. No real credentials/PII appear in fixtures. Traces: AC-3.

- **TC-AND-150-14 — Real flaky-host reconnect on physical hardware (smoke,
  optional).** Type: instrumented/e2e. Target: **PHYSICAL DEVICE — Samsung Galaxy
  A15 5G (SM-A156U, serial R5CX821TA9R), Android 14 / API 34, arm64-v8a.** MUST run
  on the physical device (not the x86_64 API-35 emulator) to exercise real OkHttp
  socket teardown/reconnect timing and arm64 ABI behavior under genuine network
  loss. Preconditions: app pointed at a local MockWebServer or a controlled host;
  toggle connectivity. Steps: drop the connection mid-stream (airplane-mode flip),
  restore it. Expected: client reconnects, resumes from the last `message_id`
  (`after`), and the merged list shows no duplicates/gaps. NOTE: this is a
  belt-and-suspenders real-network check outside the deterministic JVM suite (which
  remains the AC-1 gate); keep it out of the required-checks unit job. Traces: AC-2,
  AC-3.

### Coverage matrix (§14 Acceptance Criteria → test cases)

| AC (§14) | Summary | Covered by |
|----------|---------|------------|
| AC-1 | Suite exists & passes headlessly, deterministic | TC-01, TC-03, TC-10, TC-11, TC-12 |
| AC-2 | No dupes/no gaps across reconnect | TC-01, TC-02, TC-03, TC-14 |
| AC-3 | Reconnect sends resume cursor + carries credentials | TC-07, TC-13, TC-14 |
| AC-4 | Determinism, 50× no flakes, no `Thread.sleep` | TC-08, TC-12 |
| AC-5 | Ordering + edit/delete reconciliation vs Room | TC-04, TC-05, TC-06 |
| AC-6 | Backoff schedule + single-shot 401 refresh | TC-08, TC-09 |
| AC-7 | Shared utilities in `core-testing`, reused | TC-01..TC-13 (all consume `MainDispatcherRule` / SSE dispatcher / `assertReconciled`) |

Accessibility note: this ticket has no UI surface (§9), so no Compose-UI /
accessibility cases are warranted here; accessibility is owned by the messaging
UI tickets (E20).
