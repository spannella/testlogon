---
id: AND-287
title: Broadcast viewer tests
milestone: M6
epic: E38
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-286]
blocks: []
---

# AND-287 — Broadcast viewer tests

## 1. Overview & Goal

This ticket delivers the automated test suite for the broadcast **viewer** experience: the
`BroadcastViewerViewModel` session state machine and chat merge logic (AND-286), HLS playback
wiring (AND-280), and viewer presence/heartbeat (AND-285). It is a **Test** ticket
(Priority **P1**, depends on **AND-286**); it adds no production behavior. The single backlog
acceptance criterion is "Pass" — i.e. a green, deterministic, non-flaky test suite that runs
in CI.

The goal is to lock the viewer feature against regression with three layers of coverage:

1. **JVM unit tests** for `BroadcastViewerViewModel`, the session state machine, the chat
   merge/dedupe/ordering algorithm, and the heartbeat scheduler — running on
   `kotlinx-coroutines-test` virtual time with no Android framework dependency.
2. **Repository / network tests** for `BroadcastViewerRepository`, exercising the
   `playback-url` / `playback/verify` / join / leave / heartbeat endpoints against a
   `MockWebServer`, including the FastAPI `detail` error shapes, 401→refresh→retry, and the
   ~20 s timeout / bounded-backoff resilience contract.
3. **Compose UI tests** for `BroadcastViewerScreen`, asserting that each `UiState`
   (`Loading`, `Live`, `Offline`, `Stale`, `Error`, `Ended`) renders the correct nodes and
   that user actions (retry, send chat, leave) dispatch the right ViewModel intents.

Out of scope: producing/broadcasting tests (WebRTC, AND-288+, epic E39), end-to-end tests
against the live dev backend, and instrumented ExoPlayer playback verification (the player is
faked/abstracted behind an interface — see §4).

## 2. Context & References

- Repo `spannella/testlogon`, Android app in `android/`, branch `android-port`.
- Namespace / applicationId base: `com.testlogon.android`.
- Module under test: `feature-broadcast` (viewer half), depending on `core-network`,
  `core-model`, `core-data`, `core-ui`. Test utilities live in `core-testing`.
- Stack: Kotlin 2.0.21, Compose + Material 3, Hilt (KSP), Coroutines/Flow, Retrofit 2.11 +
  OkHttp 4.12 + Moshi 1.15, Room 2.6, DataStore, Media3/ExoPlayer 1.4 (HLS). minSdk 24,
  compile/target 35, JDK 17, Gradle 8.9, AGP 8.7.3.
- Web reference: `frontend/src/api/endpoints/*.ts` (viewer/broadcast endpoints),
  `frontend/src/api/types.ts` (shared DTO shapes), OpenAPI at `/openapi.json`.
- Upstream code under test:
  - **AND-286** — `BroadcastViewerViewModel`, session state machine, chat merge.
  - **AND-280** — `playback-url` + `playback/verify`, HLS viewer.
  - **AND-285** — viewer join/leave/heartbeat + count.
- Auth is cookie-based (`POST /ui/session/start` → MFA → `/ui/session/finalize` → `/ui/me`),
  with `ui_csrf` echoed as `X-CSRF-Token` and a single `POST /ui/session/refresh` on 401.
  Tests assert these mechanics at the repository layer via a fake `CookieJar`.

## 3. Functional Requirements

The suite must verify the following observable behaviors of the viewer feature.

- **FR-1 Session lifecycle.** On `start(broadcastId)` the ViewModel transitions
  `Loading → (Live | Offline | Ended | Error)`. `Live` requires a successful `playback/verify`
  and a non-null playback URL.
- **FR-2 Authorization gating.** When `playback/verify` returns `valid=false` (or the
  `playback-url` mint returns `403`), state becomes `Error(Unauthorized)` and no playback URL
  is exposed. (CORRECTED: the verify response field is `valid`, not `authorized`; there is no
  `reason` field — see §5/§16.)
- **FR-3 Chat merge.** Incoming chat batches are merged into the existing list: deduped by
  `messageId`, ordered by `(serverTs, messageId)` ascending, capped at `MAX_CHAT = 500`
  (oldest evicted). Optimistic local sends are reconciled when the server echo arrives.
- **FR-4 Heartbeat.** While `Live`, a heartbeat fires every `HEARTBEAT_INTERVAL = 15s`;
  `leave()` / `onCleared()` cancels it and POSTs a single leave. Viewer count from join /
  heartbeat responses is surfaced in `UiState`.
- **FR-5 Presence/count.** `viewerCount` updates from `join` and `heartbeat` responses and is
  monotonic within a session except on explicit server-provided decreases.
- **FR-6 Resilience.** Transient GET failures (timeout, 5xx) on idempotent calls retry with
  bounded backoff; after exhaustion the state degrades to `Stale` (if a prior `Live` snapshot
  exists) or `Error`. Heartbeat failures do not crash the session.
- **FR-7 Recovery.** A 401 triggers exactly one `session/refresh` then one retry; a second
  401 surfaces `Error(SessionExpired)`.
- **FR-8 UI rendering.** Each `UiState` maps to the documented Compose nodes (§6), and
  `retry` / `sendChat` / `leave` UI affordances dispatch the correct intents.

## 4. Technical Design

### 4.1 Test source sets and module wiring

```
feature-broadcast/
  src/test/...                       # JVM unit + MockWebServer (Robolectric not required here)
  src/androidTest/...                # Compose UI tests (ConnectedAndroidTest / managed device)
core-testing/
  src/main/...                       # shared fakes & rules (MainDispatcherRule, builders, fakes)
```

`feature-broadcast/build.gradle.kts` test dependencies:

```kotlin
testImplementation(project(":core-testing"))
testImplementation(libs.junit4)
testImplementation(libs.kotlinx.coroutines.test)   // 1.9.x
testImplementation(libs.turbine)                    // app.cash.turbine 1.1.0
testImplementation(libs.mockwebserver)              // com.squareup.okhttp3:mockwebserver 4.12.0
testImplementation(libs.truth)                      // com.google.truth 1.4.x

androidTestImplementation(project(":core-testing"))
androidTestImplementation(libs.androidx.compose.ui.test.junit4)
androidTestImplementation(libs.androidx.test.ext.junit)
androidTestImplementation(libs.hilt.android.testing)
kspAndroidTest(libs.hilt.compiler)
debugImplementation(libs.androidx.compose.ui.test.manifest)
```

### 4.2 Shared test infrastructure (core-testing)

```kotlin
// core-testing: virtual-time dispatcher rule
class MainDispatcherRule(
    val dispatcher: TestDispatcher = StandardTestDispatcher(),
) : TestWatcher() {
    override fun starting(d: Description) = Dispatchers.setMain(dispatcher)
    override fun finished(d: Description) = Dispatchers.resetMain()
}

// Player abstraction so unit tests need no real ExoPlayer (Media3 is Android-only).
interface ViewerPlayer {
    val state: StateFlow<PlayerState>          // Idle | Buffering | Playing | EndedT | Failed
    fun load(hlsUrl: String)
    fun release()
}

class FakeViewerPlayer : ViewerPlayer {
    private val _state = MutableStateFlow<PlayerState>(PlayerState.Idle)
    override val state = _state.asStateFlow()
    var loadedUrl: String? = null; private set
    override fun load(hlsUrl: String) { loadedUrl = hlsUrl; _state.value = PlayerState.Buffering }
    fun emit(s: PlayerState) { _state.value = s }
    override fun release() { _state.value = PlayerState.Idle }
}

// Deterministic clock for heartbeat / chat-ordering assertions.
class FakeClock(var nowMs: Long = 0L) { fun advance(ms: Long) { nowMs += ms } }

// Builders
fun chatMessage(id: String, ts: Long, text: String = "hi", local: Boolean = false): ChatMessage
// CORRECTED: verify response field is `valid` (BroadcastPlaybackTokenVerifyOut), not `authorized`.
fun playbackVerify(valid: Boolean = true): PlaybackVerifyResponse   // { "valid": Boolean }
```

### 4.3 Unit test design (JVM, virtual time)

`BroadcastViewerViewModelTest` constructs the SUT with a fake `BroadcastViewerRepository`
(in-memory, channel-driven for chat) and `FakeViewerPlayer`, observed via Turbine:

```kotlin
@get:Rule val mainRule = MainDispatcherRule()

@Test fun start_authorized_emitsLoadingThenLive() = runTest {
    repo.queuePlaybackUrl("https://cdn/live/abc.m3u8")
    repo.queueVerify(valid = true)   // CORRECTED: BroadcastPlaybackTokenVerifyOut.valid
    vm.uiState.test {
        assertThat(awaitItem()).isInstanceOf(UiState.Loading::class.java)
        vm.start("abc")
        val live = awaitItem() as UiState.Live
        assertThat(live.hlsUrl).isEqualTo("https://cdn/live/abc.m3u8")
        assertThat(player.loadedUrl).isEqualTo("https://cdn/live/abc.m3u8")
    }
}
```

Chat merge tests target the pure function directly to avoid coroutine noise:

```kotlin
@Test fun merge_dedupesAndOrders() {
    val cur = listOf(chatMessage("b", ts = 2))
    val incoming = listOf(chatMessage("a", ts = 1), chatMessage("b", ts = 2))
    val out = ChatMerger.merge(cur, incoming, cap = 500)
    assertThat(out.map { it.id }).containsExactly("a", "b").inOrder()
}

@Test fun merge_capsAtMaxEvictingOldest() { /* 501 msgs -> size 500, oldest dropped */ }

@Test fun merge_reconcilesOptimisticEcho() { /* local msg replaced by server echo, no dup */ }
```

Heartbeat tests use `advanceTimeBy` on the test scheduler:

```kotlin
@Test fun heartbeat_firesEvery15s_whileLive() = runTest {
    vm.start("abc"); runCurrent()
    advanceTimeBy(15_001); assertThat(repo.heartbeatCount).isEqualTo(1)
    advanceTimeBy(15_000); assertThat(repo.heartbeatCount).isEqualTo(2)
    vm.leave(); advanceTimeBy(45_000)
    assertThat(repo.heartbeatCount).isEqualTo(2)          // stopped
    assertThat(repo.leaveCount).isEqualTo(1)
}
```

### 4.4 Repository / MockWebServer tests

`BroadcastViewerRepositoryTest` builds a real Retrofit/OkHttp stack against `MockWebServer`
with the project's `CsrfInterceptor`, `AuthRefreshAuthenticator`, and persistent `CookieJar`
(file-backed jar swapped for an in-memory test jar). Each test enqueues canned responses and
asserts both the parsed `ApiResult<T>` and the recorded request (path, method, `X-CSRF-Token`,
cookie).

### 4.5 Compose UI tests

`BroadcastViewerScreenTest` renders the stateless screen against fabricated `UiState` values
(no ViewModel) plus an intent-capturing lambda, using `createComposeRule()` and
`testTag`/`onNodeWithText` semantics.

## 5. API Contract

This ticket does **not** define the API — it asserts against the contracts owned by **AND-280**
(`playback-url`, `playback/verify`) and **AND-285** (join/leave/heartbeat). The canned responses
the suite enqueues are the authoritative fixtures and must track those tickets.

> **CORRECTED 2026-06-06 (review):** the paths, methods, and response shapes below were
> wrong in the draft. They are now reconciled with the backend OpenAPI and the web client
> (`reference/src/api/endpoints/broadcast.ts`). All viewer/playback routes live under
> `/broadcast/sessions/{session_id}/…` (NOT `/ui/broadcasts/{id}/…`). The test fixtures MUST
> use the corrected shapes. See §16 for the per-claim audit.

Mint playback URL — **POST**, no body (idempotent enough to retry on transient GET-like
failure; but note it is a POST, so retry policy must treat it as a safe-to-replay mint, see §7):
```
POST /broadcast/sessions/{session_id}/playback-url   -> 200  (schema BroadcastPlaybackUrlOut)
{ "session_id": "abc", "playback_url": "https://cdn.example/live/abc.m3u8", "expires_at": 1780000000 }
```
Note: `playback_url` (NOT `url`); `expires_at` is an **integer epoch seconds** (NOT an ISO-8601 string).

Playback token verify — **GET** with query params; not retried:
```
GET /broadcast/playback/verify?path=<m3u8-path>&cf_token=<t>&cf_expires=<n>
-> 200 (schema BroadcastPlaybackTokenVerifyOut) { "valid": true }
-> 200 { "valid": false }
```
Note: the only field is `valid: boolean`. There is **no** `authorized` or `reason` field.
The viewer's "unauthorized" concept (FR-2) maps to `valid: false` here, and/or a `403` on the
playback-url mint. Tests must use `valid`.

Join / heartbeat / leave / count (AND-285):
```
POST /broadcast/sessions/{session_id}/viewers/join       -> 200 (ViewerJoinOut)
     { "viewer_id": "v-001", "session_id": "abc", "viewer_count": 41 }
POST /broadcast/sessions/{session_id}/viewers/heartbeat?viewer_id=v-001  -> 200 (ViewerHeartbeatOut)
     { "ok": true, "viewer_count": 42 }
POST /broadcast/sessions/{session_id}/viewers/leave?viewer_id=v-001      -> 200
     { "ok": true, "viewer_count": 41 }
GET  /broadcast/sessions/{session_id}/viewers/count      -> 200 (ViewerCountOut)
     { "session_id": "abc", "viewer_count": 42 }
```
Notes: join returns `viewer_id` (NOT `session_token`) and the client must thread that
`viewer_id` as a **query param** on every subsequent heartbeat/leave. Leave returns **200**
with a body (NOT `204`). Heartbeat response includes `ok` alongside `viewer_count`.

Chat is fetched/sent over the session chat routes (AND-286 merges them client-side):
```
GET  /broadcast/sessions/{session_id}/chat?limit=&before=  -> 200 (BroadcastChatHistoryOut)
     { "messages": [ ChatMessage… ], "has_more": false, "oldest_sort_key": null }
POST /broadcast/sessions/{session_id}/chat  { "text": "hi" }  -> 201 (BroadcastChatMessageOut)
GET  /broadcast/sessions/{session_id}/chat/stream?after=&poll_ms=  -> 200 (long-poll batch)
```
Wire `ChatMessage` fields: `message_id`, `session_id`, `sender_id`, `sender_display_name`,
`text` (nullable), `created_at` (**integer epoch**, used for ordering), `kind`, `deleted`.
The §3/§6 domain model's `messageId`/`serverTs` are the client-side mappings of `message_id`/
`created_at`; the merge/dedupe contract is unchanged but fixtures must use the wire names.

FastAPI error `detail` polymorphism the tests must cover (all three shapes):
```
422 { "detail": [ { "loc": ["query","viewer_id"], "msg": "field required", "type": "missing" } ] }
403 { "detail": "not_entitled" }
409 { "detail": { "code": "broadcast_ended", "message": "Broadcast has ended" } }
```
Note: the `422` list shape is schema-backed (`HTTPValidationError` → `ValidationError{loc,msg,type}`;
`loc` is an array whose first element is the param source, e.g. `["query","viewer_id"]` for the
heartbeat viewer_id or `["path","session_id"]`). The `403` string `detail` and `409` object
`detail` shapes are FastAPI `HTTPException` conventions (not enumerated as response schemas in the
OpenAPI doc); the web client's `normalizeErrorDetail` (`reference/src/api/client.ts`) already
handles all three, so the repo error mapper and its tests must too. Treat the exact `403`/`409`
bodies as representative fixtures, not contract-guaranteed strings (see §16 Open assumptions).

Resilience fixtures: a `SocketPolicy.NO_RESPONSE` enqueue to exercise the ~20 s read timeout;
two `503` then one `200` to exercise bounded-backoff retry of a replay-safe call (the
playback-url mint POST and the `viewers/count` GET are the retried calls — see §7); a `401`
followed by a `200` on `/ui/session/refresh` then a `200` retry to exercise the refresh path.
(CORRECTED: the draft labelled playback-url an "idempotent GET" — it is in fact a **POST**, and
`playback/verify` is a **GET**. The retry policy is keyed on a per-call "replay-safe" flag, not
on HTTP verb alone.)

## 6. Data & State Management

State under test, `BroadcastViewerViewModel.uiState: StateFlow<BroadcastViewerUiState>`:

```kotlin
sealed interface BroadcastViewerUiState {
    data object Loading : BroadcastViewerUiState
    data class Live(
        val hlsUrl: String,
        val viewerCount: Int,
        val chat: List<ChatMessage>,
        val playerState: PlayerState,
    ) : BroadcastViewerUiState
    data class Stale(val last: Live) : BroadcastViewerUiState     // degraded from Live
    data object Offline : BroadcastViewerUiState
    data object Ended : BroadcastViewerUiState
    data class Error(val kind: ViewerError) : BroadcastViewerUiState
}

enum class ViewerError { Unauthorized, SessionExpired, Network, Unknown }
```

State-mapping assertions for `BroadcastViewerScreenTest` (testTags in parentheses):

| UiState   | Asserted node(s)                                                     |
|-----------|---------------------------------------------------------------------|
| Loading   | `viewer_progress` shown; no player surface                          |
| Live      | `viewer_player` shown; `viewer_count` text == count; chat list rows |
| Stale     | `stale_banner` shown over last player frame                         |
| Offline   | `offline_message` shown; retry button enabled                       |
| Ended     | `ended_message` shown; chat hidden                                  |
| Error     | `error_message` text matches `ViewerError`; retry per kind          |

Chat invariants verified: dedupe by `id`, sort `(serverTs, id)`, cap 500, optimistic
reconcile. Caching: tests confirm the ViewModel does not write playback URLs to Room/DataStore
(ephemeral, expiring), but a `Stale` snapshot is held in-memory only.

## 7. Error Handling & Resilience

Coverage matrix (each row is at least one test):

- **Timeout** (`NO_RESPONSE`): the `playback-url` mint (POST) exceeds read timeout → mapped to
  `ApiResult.Failure(Network)`; with no prior `Live`, state → `Offline`/`Error(Network)`.
  (CORRECTED: mint is a POST, not a GET.)
- **Bounded backoff**: two `503` + one `200` on a replay-safe call (`playback-url` mint or
  `viewers/count`) → success after retries; assert exactly 3 recorded requests, and that a
  non-replay-safe state-changing call (`viewers/join`) is **never** auto-retried (single
  recorded request on `503`). (CORRECTED: the draft used `verify` as the "non-retried POST"
  example, but `verify` is a GET; the no-retry exemplar is now `viewers/join`.)
- **401 refresh**: `401` then refresh `200` then retry `200` → success; recorded requests show
  one `session/refresh`. A second consecutive `401` → `Error(SessionExpired)`, no infinite loop.
- **detail mapping**: each of string / list / object `detail` shapes parses to the right
  `ApiError` and user-facing message bucket.
- **Heartbeat failure isolation**: a `500` on heartbeat does not change `Live` chat/player
  state and does not cancel the schedule (next tick still fires).
- **Player failure**: `FakeViewerPlayer.emit(Failed)` while `Live` surfaces a player-error
  affordance without tearing down the session (retry reloads same URL).

## 8. Security & Privacy

- Tests assert the `X-CSRF-Token` header is present on every state-changing POST
  (`verify`, `join`, `heartbeat`, `leave`) and equals the `ui_csrf` cookie value supplied to
  the in-memory `CookieJar`; absence is a test failure.
- Tests assert session cookies are sent on authenticated calls and that `session/refresh` is
  invoked at most once per 401.
- No real credentials, tokens, or PII in fixtures — usernames/messages are synthetic
  (`user_test`, `msg-001`). MockWebServer binds to loopback only; no network egress in CI.
- Assert that on `Error`/`Ended` the playback URL is cleared from `UiState` so it is not
  retained or logged.

## 9. Accessibility & i18n

- Compose tests assert non-decorative nodes expose `contentDescription` / merged semantics:
  player surface, viewer-count, retry button, send-chat button. The leave control must be
  reachable by `onNodeWithContentDescription`.
- Assert all user-facing strings render from `stringResource` (no hard-coded literals): tests
  look up by resource id via `composeRule.activity.getString(R.string.viewer_offline)` etc.,
  proving externalization for future localization.
- Assert chat row text scales (no `sp`→`dp` hard-coding) by rendering under a large
  `fontScale` density and confirming the row still composes without crash.

## 10. Telemetry & Logging

- A `FakeAnalytics : Analytics` (in `core-testing`) records events; tests assert the viewer
  emits: `viewer_session_start`, `viewer_live`, `viewer_heartbeat` (per tick),
  `viewer_leave`, and `viewer_error{kind}` with expected param maps.
- Assert no PII (no raw chat text, no cookie/CSRF values) appears in any logged event or in
  `Timber`/log statements captured by a test tree; a fixture scans recorded log lines for the
  CSRF token and synthetic password to prove they are absent.

## 11. Testing Strategy

This ticket *is* the testing strategy; the deliverable is the suite itself.

- **Frameworks**: JUnit4, `kotlinx-coroutines-test` (virtual time), Turbine (Flow assertions),
  Truth (assertions), MockWebServer (network), Compose UI Test + Hilt testing (UI).
- **Determinism**: all time via `StandardTestDispatcher`/`advanceTimeBy` and `FakeClock`; no
  `Thread.sleep`, no real delays, no real network. Backoff jitter is injected as a fixed
  sequence so retries are reproducible.
- **Structure**: one test class per unit (`BroadcastViewerViewModelTest`, `ChatMergerTest`,
  `HeartbeatSchedulerTest`, `BroadcastViewerRepositoryTest`, `BroadcastViewerScreenTest`).
- **Coverage targets**: ≥90 % line coverage of `BroadcastViewerViewModel`, `ChatMerger`,
  `HeartbeatScheduler`, and `BroadcastViewerRepository` (measured via Jacoco/Kover); every
  `BroadcastViewerUiState` constructed at least once; every `ViewerError` asserted.
- **Anti-flake gates**: unit + repo tests run on every PR via
  `./gradlew :feature-broadcast:testDebugUnitTest`; UI tests via a Gradle Managed Device
  (`pixel6api34`) `./gradlew :feature-broadcast:pixel6api34DebugAndroidTest`. The suite must
  pass 20/20 consecutive CI runs before merge.
- **Negative tests** are mandatory: unauthorized verify, double-401, retry exhaustion,
  chat cap overflow, heartbeat-after-leave.

## 12. Dependencies & Sequencing

- **Depends on AND-286** (ViewModel + state machine + chat merge) — the primary SUT must exist
  and expose the interfaces in §6. Transitively exercises **AND-280** (playback) and
  **AND-285** (presence), so those should be merged first; if not, their paths are covered by
  fakes and re-enabled when landed.
- Requires `core-testing` to provide `MainDispatcherRule`, `FakeViewerPlayer`, `FakeAnalytics`,
  `FakeClock`, and builders (add them here if absent).
- **Blocks**: nothing in the backlog directly, but this suite is the regression gate for any
  follow-on viewer work and should be green before the M6 viewer epic (E38) is closed.
- Sequencing: land `core-testing` additions → unit tests → repo/MockWebServer tests →
  Compose UI tests → wire all into CI.

## 13. Risks & Open Questions

- **Media3 in unit tests**: ExoPlayer cannot run on the JVM. Mitigation: the `ViewerPlayer`
  abstraction (§4.2). *Open*: does AND-280 already expose such an interface, or must AND-287
  introduce/refactor it? If introduced here it is a thin, non-behavioral wrapper.
- **Heartbeat interval / chat cap constants**: assumed `15s` and `500`. *Open*: confirm the
  exact values defined in AND-285/286 and source them from a shared constant rather than
  hard-coding in tests.
- **Chat transport**: VERIFIED as HTTP **long-poll**, not WebSocket/SSE. The web client uses
  `GET /broadcast/sessions/{id}/chat` (history, paginated by `before`/`oldest_sort_key`) plus
  `GET /broadcast/sessions/{id}/chat/stream?after=&poll_ms=` (long-poll batch). MockWebServer
  covers both — no fake socket needed. Batches are merged via `ChatMerger`. *Residual open*:
  AND-286's exact polling cadence / `after` cursor handling — source it from AND-286, do not
  hard-code.
- **Viewer-count monotonicity**: server may legitimately decrease the count; tests treat
  server-provided decreases as valid (FR-5) — confirm with backend.
- **UI test runtime**: managed-device tests are slower; if CI budget is tight, gate them to a
  nightly lane while unit/repo tests stay on every PR.

## 14. Acceptance Criteria

The backlog acceptance is "Pass". Concretely, this ticket is accepted when:

- **AC-1** `./gradlew :feature-broadcast:testDebugUnitTest` passes with the unit + repo suites
  described in §3–§7, with zero ignored/flaky tests.
- **AC-2** `./gradlew :feature-broadcast:pixel6api34DebugAndroidTest` passes the
  `BroadcastViewerScreenTest` state-mapping and intent-dispatch assertions in §6.
- **AC-3** Coverage thresholds in §11 are met for the named classes (CI fails below threshold).
- **AC-4** Every `BroadcastViewerUiState` and every `ViewerError` is asserted at least once.
- **AC-5** Resilience matrix (§7) is fully covered: timeout, bounded-backoff retry of GET,
  no-retry of POST, single-refresh-on-401, double-401 expiry, all three `detail` shapes.
- **AC-6** Security assertions (§8): CSRF header presence on every POST, refresh-once, no PII
  in fixtures/logs.
- **AC-7** Suite passes 20/20 consecutive CI runs (no flakiness) and adds no new lint/Detekt
  violations.
- **AC-8** No production code changes beyond the `ViewerPlayer` abstraction / `core-testing`
  additions strictly required to make the feature testable.

## 15. Definition of Done

- All test classes in §4 implemented, reviewed, and merged to `android-port`.
- CI green on both the unit/repo lane and the UI lane; coverage gate enforced and passing.
- `core-testing` fakes/rules added and reused (no duplicated test scaffolding in
  `feature-broadcast`).
- 20/20 consecutive green CI runs demonstrated on the PR.
- No `Thread.sleep`, real network, or wall-clock timing in any test; all time virtualized.
- Open questions in §13 resolved or filed as follow-ups; constants sourced from shared
  definitions rather than duplicated literals.
- PR description links AND-286/AND-280/AND-285 and lists the coverage numbers; squash-merged
  with the standard trailer.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the authoritative source pointer. "OpenAPI" =
`reference/openapi.index.txt` / `reference/openapi.pretty.json`; "FE" = `reference/src`.

1. **Playback URL endpoint is `GET /ui/broadcasts/{id}/playback-url` returning `{url, expires_at(ISO)}`.**
   VERDICT: **Corrected.** Actual: `POST /broadcast/sessions/{session_id}/playback-url` →
   `BroadcastPlaybackUrlOut { session_id, playback_url, expires_at:integer }`.
   SOURCE: OpenAPI `POST /broadcast/sessions/{session_id}/playback-url` (op
   `mint_playback_url_route…`), schema `BroadcastPlaybackUrlOut`; FE `src/api/endpoints/broadcast.ts:191`
   `mintPlaybackUrl` + `interface BroadcastPlaybackUrl` (`playback_url`, `expires_at:number`).

2. **Playback verify is `POST /ui/broadcasts/{id}/playback/verify` with body `{url}` returning `{authorized, reason}`.**
   VERDICT: **Corrected.** Actual: `GET /broadcast/playback/verify?path&cf_token&cf_expires` →
   `BroadcastPlaybackTokenVerifyOut { valid:boolean }` (no `authorized`, no `reason`).
   SOURCE: OpenAPI `GET /broadcast/playback/verify` (op `verify_playback_token_route…`,
   params `path,cf_token,cf_expires`), schema `BroadcastPlaybackTokenVerifyOut`.

3. **Viewer join `POST …/viewers/join` → `{viewer_count, session_token}`.**
   VERDICT: **Corrected.** Actual: `POST /broadcast/sessions/{session_id}/viewers/join` →
   `ViewerJoinOut { viewer_id, session_id, viewer_count }` (`viewer_id`, not `session_token`).
   The returned `viewer_id` is threaded as a query param into heartbeat/leave.
   SOURCE: OpenAPI `POST /broadcast/sessions/{session_id}/viewers/join`, schema `ViewerJoinOut`;
   FE `src/api/endpoints/broadcast.ts:199,215` (`ViewerJoinResponse`, `viewerJoin`).

4. **Viewer heartbeat `POST …/viewers/heartbeat` → `{viewer_count}`.**
   VERDICT: **Corrected.** Actual: `POST /broadcast/sessions/{session_id}/viewers/heartbeat?viewer_id=…`
   → `ViewerHeartbeatOut { ok:boolean, viewer_count:int }`. `viewer_id` is a query param.
   SOURCE: OpenAPI `POST …/viewers/heartbeat` (param `viewer_id`), schema `ViewerHeartbeatOut`;
   FE `src/api/endpoints/broadcast.ts:205,218`.

5. **Viewer leave `POST …/viewers/leave` → `204` (no body).**
   VERDICT: **Corrected.** Actual: `POST /broadcast/sessions/{session_id}/viewers/leave?viewer_id=…`
   → `200` with `{ ok, viewer_count }` (not 204). SOURCE: OpenAPI `POST …/viewers/leave`
   (resp `200`, param `viewer_id`); FE `src/api/endpoints/broadcast.ts:225` (`{ ok; viewer_count }`).

6. **Viewer count endpoint exists.** VERDICT: **Verified** (and added to §5). `GET
   /broadcast/sessions/{session_id}/viewers/count` → `ViewerCountOut { session_id, viewer_count }`.
   SOURCE: OpenAPI `GET …/viewers/count`, schema `ViewerCountOut`; FE `getViewerCount` line 232.

7. **Chat merge keys: dedupe by `messageId`, order by `(serverTs, messageId)`.**
   VERDICT: **Verified with mapping note.** Wire fields are `message_id` and `created_at`
   (integer epoch); the domain `messageId`/`serverTs` are client mappings of those. Chat is
   fetched via `GET /broadcast/sessions/{id}/chat` (history; `before`/`oldest_sort_key`
   pagination) + `GET …/chat/stream` long-poll; sent via `POST …/chat`.
   SOURCE: schema `BroadcastChatMessageOut` (required `message_id, session_id, sender_id,
   sender_display_name, created_at`); FE `src/api/endpoints/broadcast-chat.ts:5` (`interface
   ChatMessage`), `:49 sendChatMessage`, `:64 getChatHistory`, OpenAPI `GET …/chat/stream`.

8. **Auth is cookie-based; `ui_csrf` cookie echoed as `X-CSRF-Token`; single `session/refresh` on 401.**
   VERDICT: **Verified.** SOURCE: FE `src/api/client.ts:16 getCookie`, `:124/:183/:220
   credentials:"include"`, `:168 getCookie("ui_csrf")` → `:170 headers.set("X-CSRF-Token", csrf)`,
   `:119 refreshPromise` single-flight, `:194` 401 handling → one `refreshSession()` (`:122`
   `POST /ui/session/refresh`) then one retry. OpenAPI `POST /ui/session/refresh` (resp 200).

9. **Session lifecycle `/ui/session/start → MFA → /ui/session/finalize → /ui/me`.**
   VERDICT: **Verified.** SOURCE: OpenAPI `POST /ui/session/start` (`UiSessionStartReq` →
   `UiSessionStartResp`), `POST /ui/session/finalize` (`UiSessionFinalizeReq`), `GET /ui/me`.

10. **422 validation error shape `{detail:[{loc,msg,type}]}`.** VERDICT: **Verified.**
    SOURCE: schemas `HTTPValidationError` (detail: array of `ValidationError`) and
    `ValidationError { loc:[str|int], msg, type }`. (Corrected the example `loc` to a real
    viewer param, `["query","viewer_id"]`.)

11. **403 string `detail` and 409 object `{code,message}` `detail` shapes.** VERDICT:
    **Unverified-assumption** (plausible). These are FastAPI `HTTPException` detail conventions,
    not enumerated response schemas in the OpenAPI doc. The web client already normalizes all
    three (`normalizeErrorDetail`, FE `src/api/client.ts`), so handling them is correct, but the
    exact strings/codes (`not_entitled`, `broadcast_ended`) are illustrative.

12. **`HEARTBEAT_INTERVAL = 15s`, `MAX_CHAT = 500`.** VERDICT: **Unverified-assumption.** Not
    present in OpenAPI or FE; these are AND-285/AND-286 client constants. Spec already flags
    this (§13); tests must import the shared constants rather than literals.

13. **Retry policy: "idempotent GET retried; verify POST not retried".** VERDICT: **Corrected.**
    `playback-url` mint is a POST (not GET) and `playback/verify` is a GET (not POST). Retry is
    keyed on a per-call replay-safe flag; retried exemplars = `playback-url` mint + `viewers/count`;
    non-retried state-changing exemplar = `viewers/join`. SOURCE: OpenAPI methods above.

14. **`ViewerPlayer` interface / `FakeViewerPlayer` to avoid ExoPlayer on JVM.** VERDICT:
    **Unverified-assumption** (design choice; depends on AND-280). Media3/ExoPlayer is
    Android-only and cannot run on a JVM unit test. SOURCE: framework ref —
    https://developer.android.com/media/media3/exoplayer and
    https://developer.android.com/training/testing/local-tests (Robolectric/local tests).

15. **CI device target `pixel6api34` (Gradle Managed Device).** VERDICT: **Unverified-assumption**
    (project convention). Note: this review's available CI targets are the headless emulator AVD
    `test35` (API 35, x86_64) and a physical Samsung Galaxy A15 5G (API 34, arm64-v8a); see §17
    for device assignment per case. SOURCE: framework ref —
    https://developer.android.com/studio/test/gradle-managed-devices.

### Corrections made

- §5: rewrote all viewer/playback endpoints — correct paths (`/broadcast/sessions/{id}/…`),
  methods (mint = POST, verify = GET), and response schemas (`playback_url` not `url`;
  `expires_at` integer; `valid` not `authorized`/`reason`; join → `viewer_id` not
  `session_token`; heartbeat adds `ok`; leave = 200 not 204). Added `viewers/count` and the
  chat history/stream/send routes with their real wire field names.
- §3 FR-2: `authorized=false` → `valid=false` (+ 403-on-mint path).
- §4.2 / §4.3: `playbackVerify(authorized=…)` / `queueVerify(authorized=…)` → `valid=…`.
- §5/§7: corrected the "idempotent GET" mislabel of `playback-url` and the "non-retried POST"
  use of `verify`; reframed retry policy on a replay-safe flag with correct exemplars.
- §5 (422 example) and detail-polymorphism note: realistic `loc`, and clarified which shapes
  are schema-backed vs HTTPException conventions.
- §13: chat transport confirmed as HTTP long-poll (`/chat/stream`), not WebSocket/SSE.

### Open assumptions

- **403/409 `detail` exact bodies** (`not_entitled`, `{code:"broadcast_ended",…}`): FastAPI
  HTTPException conventions, not in the OpenAPI response schemas — treat as representative.
- **`HEARTBEAT_INTERVAL=15s` / `MAX_CHAT=500`**: owned by AND-285/AND-286, not in the API —
  source from shared constants.
- **`ViewerPlayer` abstraction ownership**: whether AND-280 already exposes it or AND-287
  introduces it (§13) — cannot be confirmed from API/FE sources.
- **Viewer-count monotonicity / server-driven decreases (FR-5)**: server may legitimately
  decrease the count; no contract in OpenAPI guarantees monotonicity — confirm with backend.
- **CSRF on cross-site cookie transport for native client**: the web flow relies on
  `ui_csrf` cookie + `X-CSRF-Token`; the Android `CookieJar`/interceptor must replicate this.
  Verified for the web client only; the native interceptor behaviour is this ticket's SUT.

## 17. Test Plan

Test-target legend: **JVM** = local JVM unit/Robolectric (no device); **MWS** =
contract test on the real Retrofit/OkHttp stack against `MockWebServer` (JVM); **Compose-UI** =
`createComposeRule()` UI test (emulator/device); **instrumented** = on-device. Default device
for instrumented/Compose-UI cases is the headless emulator AVD `test35` (API 35, x86_64) for
speed in CI; cases that exercise real ExoPlayer HLS playback or ABI/API-level differences are
called out to run on the **physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a)**.

This is a Test ticket: most cases assert the suite's own behaviour against fixtures. All times
are virtualized (`StandardTestDispatcher`/`advanceTimeBy`); no `Thread.sleep` or real network.

- **TC-AND-287-01 — Happy path: start → Live.**
  Type: unit (JVM). Target: `BroadcastViewerViewModelTest` + `FakeViewerPlayer`.
  Preconditions: fake repo queues `playback_url="https://cdn/live/abc.m3u8"` and verify
  `valid=true`. Steps: observe `uiState` via Turbine; call `vm.start("abc")`; `runCurrent()`.
  Expected: emits `Loading` then `Live` with `hlsUrl` == the minted `playback_url`;
  `player.loadedUrl` == that URL; `viewerCount` from join surfaced. Traces: AC-1, AC-4.

- **TC-AND-287-02 — Authorization gating: verify valid=false → Error(Unauthorized).**
  Type: unit (JVM). Target: `BroadcastViewerViewModelTest`. Preconditions: verify returns
  `{ "valid": false }` (and/or mint returns 403). Steps: `vm.start("abc")`; `runCurrent()`.
  Expected: state == `Error(Unauthorized)`; no `hlsUrl` exposed in any emitted state; player
  never loaded. Traces: AC-4 (ViewerError.Unauthorized), AC-6 (URL not retained).

- **TC-AND-287-03 — Chat merge: dedupe + order + cap + optimistic reconcile.**
  Type: unit (JVM). Target: `ChatMergerTest`. Preconditions: none (pure function).
  Steps: (a) merge `[b@2]` with `[a@1,b@2]` → `[a,b]`; (b) merge 501 messages → size 500,
  oldest (by `created_at`) evicted; (c) merge a local optimistic msg then its server echo
  (same `message_id`) → single entry, local replaced. Expected: ordering `(created_at,
  message_id)` asc, dedupe by `message_id`, cap 500, no duplicate on echo. Traces: AC-1, FR-3.

- **TC-AND-287-04 — Heartbeat cadence + leave cancels schedule.**
  Type: unit (JVM, virtual time). Target: `HeartbeatSchedulerTest`/`BroadcastViewerViewModelTest`.
  Preconditions: session `Live`, `HEARTBEAT_INTERVAL` from shared constant. Steps:
  `advanceTimeBy(15_001)` → 1 heartbeat; `advanceTimeBy(15_000)` → 2; `vm.leave()`;
  `advanceTimeBy(45_000)`. Expected: `heartbeatCount==2` after leave (stopped), `leaveCount==1`;
  heartbeat requests carry the join's `viewer_id` query param. Traces: AC-1, FR-4.

- **TC-AND-287-05 — Contract: playback-url mint + verify shapes.**
  Type: contract/MWS. Target: `BroadcastViewerRepositoryTest`. Preconditions: MWS enqueues
  `POST …/playback-url` → 200 `{session_id, playback_url, expires_at:1780000000}` and
  `GET /broadcast/playback/verify` → 200 `{valid:true}`. Steps: call repo mint + verify.
  Expected: parsed model has `playback_url` (string) and `expires_at` (Long epoch), not `url`/ISO;
  verify maps `valid` correctly; recorded mint request is **POST** and verify is **GET** with the
  `path/cf_token/cf_expires` query params. Traces: AC-1, AC-5, FR-1, FR-2.

- **TC-AND-287-06 — Contract: join/heartbeat/leave wire shapes + viewer_id threading.**
  Type: contract/MWS. Target: `BroadcastViewerRepositoryTest`. Preconditions: MWS enqueues
  join → `{viewer_id:"v-001",session_id:"abc",viewer_count:41}`, heartbeat → `{ok:true,
  viewer_count:42}`, leave → 200 `{ok:true,viewer_count:41}`. Steps: join, then heartbeat,
  then leave. Expected: heartbeat & leave recorded requests include `?viewer_id=v-001`; leave
  parses a 200 body (not treated as 204/no-content); counts surfaced. Traces: AC-1, FR-4, FR-5.

- **TC-AND-287-07 — Resilience: read timeout → Network failure / Offline.**
  Type: contract/MWS. Target: `BroadcastViewerRepositoryTest`. Preconditions: MWS
  `SocketPolicy.NO_RESPONSE` on the `playback-url` mint; OkHttp ~20 s read timeout (injected
  short in test). Steps: call mint. Expected: `ApiResult.Failure(Network)`; with no prior
  `Live`, ViewModel maps to `Offline`/`Error(Network)`. Traces: AC-5, FR-6. (Offline/flaky-host path.)

- **TC-AND-287-08 — Resilience: bounded backoff retry vs no-retry of state-changing call.**
  Type: contract/MWS. Target: `BroadcastViewerRepositoryTest`. Preconditions: replay-safe call
  (`playback-url` mint or `viewers/count`) enqueued `503,503,200`; `viewers/join` enqueued `503`.
  Backoff jitter injected as a fixed sequence. Steps: invoke both. Expected: replay-safe call
  succeeds after exactly 3 recorded requests; `viewers/join` makes exactly 1 request (no
  auto-retry). Traces: AC-5, FR-6.

- **TC-AND-287-09 — Recovery: single refresh on 401, then double-401 → SessionExpired.**
  Type: contract/MWS. Target: `BroadcastViewerRepositoryTest`. Preconditions: (a) `401` then
  `POST /ui/session/refresh`→200 then retry→200; (b) `401` then refresh→200 then retry→`401`.
  Steps: run both flows. Expected: (a) succeeds, exactly one `session/refresh` recorded;
  (b) surfaces `Error(SessionExpired)` with no infinite loop (refresh invoked at most once).
  Traces: AC-5, AC-6, FR-7.

- **TC-AND-287-10 — Error-detail polymorphism mapping (422 list / 403 string / 409 object).**
  Type: contract/MWS. Target: `BroadcastViewerRepositoryTest` (mirrors
  `client.errorMapping.test.ts`). Preconditions: enqueue `422 {detail:[{loc:["query","viewer_id"],
  msg,type}]}`, `403 {detail:"not_entitled"}`, `409 {detail:{code:"broadcast_ended",message}}`.
  Steps: trigger each. Expected: each parses to the right `ApiError`/user-message bucket; 409
  `broadcast_ended` → `Ended`; 403 → `Error(Unauthorized)`. Traces: AC-5, AC-4.

- **TC-AND-287-11 — Heartbeat-failure isolation + player-failure affordance.**
  Type: unit (JVM) + MWS. Target: `BroadcastViewerViewModelTest`. Preconditions: session
  `Live`. Steps: (a) heartbeat returns `500` → assert chat/player state unchanged and next
  tick still fires; (b) `FakeViewerPlayer.emit(Failed)` → assert player-error affordance shown
  and session not torn down; retry reloads the same URL. Traces: AC-5, FR-6, FR-8.

- **TC-AND-287-12 — Security: CSRF header on every POST + no-PII fixtures/logs.**
  Type: contract/MWS. Target: `BroadcastViewerRepositoryTest` + `FakeAnalytics`/log tree.
  Preconditions: in-memory `CookieJar` seeded with `ui_csrf=<token>` and session cookie.
  Steps: invoke verify(GET) and join/heartbeat/leave(POST). Expected: every state-changing POST
  carries `X-CSRF-Token == ui_csrf`; session cookie present; recorded analytics/log lines
  contain neither the CSRF token nor synthetic password/chat text. Traces: AC-6, FR-7.

- **TC-AND-287-13 — Compose-UI: state→node mapping for all six UiStates.**
  Type: Compose-UI (instrumented; emulator `test35`). Target: `BroadcastViewerScreenTest`.
  Preconditions: stateless screen + intent-capturing lambda; fabricate each `UiState`.
  Steps: render `Loading/Live/Stale/Offline/Ended/Error`. Expected: nodes per §6 table
  (`viewer_progress`, `viewer_player`+`viewer_count`+chat rows, `stale_banner`,
  `offline_message`+retry enabled, `ended_message`+chat hidden, `error_message` per kind);
  every `UiState` and `ViewerError` constructed at least once. Traces: AC-2, AC-4, FR-8.

- **TC-AND-287-14 — Compose-UI: intent dispatch + accessibility/i18n.**
  Type: Compose-UI (instrumented; emulator `test35`). Target: `BroadcastViewerScreenTest`.
  Preconditions: stateless screen + intent capture. Steps: tap retry / send-chat / leave;
  assert dispatched intents; assert player surface, viewer-count, retry, send-chat, leave expose
  `contentDescription`/merged semantics and leave is reachable by
  `onNodeWithContentDescription`; assert user-facing strings come from `stringResource`
  (look up via `R.string.viewer_offline` etc.); re-render under a large `fontScale` and confirm
  chat row still composes. Expected: all assertions pass. Traces: AC-2, FR-8 (§9 a11y/i18n).

- **TC-AND-287-15 — Instrumented HLS playback smoke on physical device (ABI/API parity).**
  Type: instrumented/e2e. Target: real `Media3ViewerPlayer` (the production `ViewerPlayer`
  impl) rendering a canned HLS `.m3u8` from a loopback `MockWebServer`. **MUST run on the
  physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a)** — ExoPlayer HLS decode is
  hardware/codec-dependent and arm64-vs-x86 + API-34-vs-35 behaviour cannot be trusted on the
  emulator. Preconditions: device connected via adb; short HLS test asset served locally.
  Steps: load the URL into the real player; await `Playing`. Expected: player reaches `Playing`
  without crash on arm64/API-34; this guards the §1 "player faked in unit tests" boundary at
  least once on real hardware. Traces: AC-2, FR-1. (Out-of-band of the JVM/MWS lanes; nightly.)

### Coverage matrix (section-14 Acceptance Criteria → TCs)

| AC    | Covered by |
|-------|------------|
| AC-1 (unit+repo suites pass) | 01, 03, 04, 05, 06 |
| AC-2 (UI suite passes)       | 13, 14, 15 |
| AC-3 (coverage thresholds)   | 01–12 collectively (≥90% of VM/Merger/Scheduler/Repository) |
| AC-4 (every UiState + ViewerError asserted) | 02, 10, 13 |
| AC-5 (resilience matrix)     | 05, 07, 08, 09, 10 |
| AC-6 (security: CSRF/refresh/no-PII) | 02, 09, 12 |
| AC-7 (20/20 no-flake, no lint) | whole suite — guaranteed by virtual-time determinism (01–14) |
| AC-8 (no prod changes beyond ViewerPlayer/core-testing) | 11, 15 (exercise the `ViewerPlayer` boundary) |
