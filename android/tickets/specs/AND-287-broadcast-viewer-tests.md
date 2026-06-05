---
id: AND-287
title: Broadcast viewer tests
milestone: M6
epic: E38
priority: P1
size: M
status: draft
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
- **FR-2 Authorization gating.** When `playback/verify` returns `authorized=false`, state
  becomes `Error(Unauthorized)` and no playback URL is exposed.
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
fun playbackVerify(authorized: Boolean = true): PlaybackVerifyResponse
```

### 4.3 Unit test design (JVM, virtual time)

`BroadcastViewerViewModelTest` constructs the SUT with a fake `BroadcastViewerRepository`
(in-memory, channel-driven for chat) and `FakeViewerPlayer`, observed via Turbine:

```kotlin
@get:Rule val mainRule = MainDispatcherRule()

@Test fun start_authorized_emitsLoadingThenLive() = runTest {
    repo.queuePlaybackUrl("https://cdn/live/abc.m3u8")
    repo.queueVerify(authorized = true)
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

Playback URL (idempotent GET; retried):
```
GET /ui/broadcasts/{id}/playback-url      -> 200
{ "url": "https://cdn.example/live/abc.m3u8", "expires_at": "2026-06-05T12:00:00Z" }
```

Playback verify (POST; not retried):
```
POST /ui/broadcasts/{id}/playback/verify
{ "url": "https://cdn.example/live/abc.m3u8" }
-> 200 { "authorized": true,  "reason": null }
-> 200 { "authorized": false, "reason": "not_entitled" }
```

Join / heartbeat / leave (AND-285):
```
POST /ui/broadcasts/{id}/viewers/join       -> 200 { "viewer_count": 41, "session_token": "..." }
POST /ui/broadcasts/{id}/viewers/heartbeat  -> 200 { "viewer_count": 42 }
POST /ui/broadcasts/{id}/viewers/leave      -> 204
```

FastAPI error `detail` polymorphism the tests must cover (all three shapes):
```
422 { "detail": [ { "loc": ["body","url"], "msg": "field required", "type": "value_error" } ] }
403 { "detail": "not_entitled" }
409 { "detail": { "code": "broadcast_ended", "message": "Broadcast has ended" } }
```

Resilience fixtures: a `SocketPolicy.NO_RESPONSE` enqueue to exercise the ~20 s read timeout;
two `503` then one `200` to exercise bounded-backoff retry of the idempotent GET; a `401`
followed by a `200` on `/ui/session/refresh` then a `200` retry to exercise the refresh path.

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

- **Timeout** (`NO_RESPONSE`): GET `playback-url` exceeds read timeout → mapped to
  `ApiResult.Failure(Network)`; with no prior `Live`, state → `Offline`/`Error(Network)`.
- **Bounded backoff**: two `503` + one `200` on the idempotent GET → success after retries;
  assert exactly 3 recorded requests and that a non-idempotent POST (`verify`) is **never**
  retried (single recorded request on `503`).
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
- **Chat transport**: spec assumes polling/SSE batches merged via `ChatMerger`. *Open*: if
  chat arrives over WebSocket, the repo test harness needs a fake socket instead of
  MockWebServer for that path.
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
