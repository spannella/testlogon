---
id: AND-110
title: Push tests
milestone: M2
epic: E15
priority: P1
size: M
status: draft
depends_on: [AND-106, AND-108]
blocks: []
---

# AND-110 — Push tests

## 1. Overview & Goal

This ticket delivers the automated test suite that locks down the push-notification subsystem built across epic E15. Its scope is narrow and explicit: **registration + routing unit/integration tests**. Concretely, it covers the two behaviors that are most likely to silently regress and that have the highest user-visible cost when they break:

1. **Push token registration** (AND-106) — after a successful cookie-based login, the Firebase Cloud Messaging (FCM) token is sent to the backend via `POST /ui/push/register`, the local token→registration mapping is persisted, and failures degrade gracefully.
2. **Deep-link routing from taps** (AND-108) — an FCM data payload is parsed into a typed in-app destination (`message` / `broadcast` / `alert`) and dispatched to Navigation-Compose so the correct screen opens.

The goal is a deterministic, hermetic, fast (<10s for the unit tier) test suite running in `core-data` / `feature-push` under JUnit + MockWebServer + Turbine + a fake Navigation surface, plus a small instrumented tier for the `FirebaseMessagingService` wiring that cannot be exercised on the JVM. This ticket adds **no production behavior**; it only adds tests and any minimal test seams (interfaces, `@VisibleForTesting` hooks) required to make AND-106/AND-108 testable. The acceptance bar from the backlog is simply "Tests pass," operationalized below as a green suite with enforced coverage on the two target classes.

## 2. Context & References

- **Repo:** `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- **Namespace / applicationId base:** `com.testlogon.android` (all test and production packages derive from this).
- **Module layering:** tests live with the code under test — registration tests in `core-data`/`feature-push`, routing tests in `feature-push` and `app`. Shared fakes live in `core-testing`.
- **Source ticket:** AND-110 — Type: Test · Priority: P1 · Deps: AND-106, AND-108 · Scope: "Registration + routing unit/integration tests." · Acceptance: "Tests pass."
- **Subjects under test:**
  - AND-106 `PushRegistrationRepository` + `POST /ui/push/register` (depends on AND-105 FCM bootstrap, AND-029 session/auth).
  - AND-108 `PushDestinationMapper` + `TestLogonMessagingService` payload→destination routing (depends on AND-107 channels, AND-022 navigation graph).
- **Adjacent (not owned here):** AND-107 channel/permission tests, AND-109 `onNewToken`/logout-deregister tests. AND-110 stays focused on registration + routing; it will reuse fakes those tickets also consume but does not assert their behaviors.
- **Backend reference:** FastAPI + DynamoDB, OpenAPI at `/openapi.json` on the dev host `http://18.222.237.167:8000`. Web reference for push endpoints under `frontend/src/api/endpoints/*.ts`. Tests never hit the live dev host; all HTTP is served by `MockWebServer`.
- **Test stack:** JUnit4 (`4.13.2`), MockWebServer (OkHttp `4.12`), Moshi `1.15`, Turbine `1.1.0` for `Flow` assertions, `kotlinx-coroutines-test` `1.8.x`, Truth `1.4.x` for assertions, Robolectric `4.13` for JVM-side Android types, AndroidX Test + Espresso-Intents for the instrumented tier, Hilt testing (`HiltAndroidRule`) where DI graphs are exercised.

## 3. Functional Requirements

The deliverable is the test code itself; "functional requirements" here are the behaviors the suite must assert.

**FR-1 Registration happy path.** Given an authenticated session, `PushRegistrationRepository.register(token)` issues exactly one `POST /ui/push/register` with the FCM token, platform, and app version, includes the `X-CSRF-Token` header echoed from the `ui_csrf` cookie, returns `ApiResult.Success`, and persists the token→server-registration mapping in DataStore.

**FR-2 Idempotent re-registration.** Calling `register(token)` with an already-registered, unchanged token short-circuits without a network call (asserted via `mockWebServer.requestCount`).

**FR-3 Registration failure mapping.** 4xx/5xx and malformed-`detail` responses map to `ApiResult.Error` with the correct `ErrorType`, the mapping is **not** persisted, and no exception escapes.

**FR-4 Auth refresh on 401.** A `401` on register triggers exactly one `POST /ui/session/refresh`, then a single retry of register; a second `401` surfaces `ApiResult.Error(Unauthorized)` without a third attempt.

**FR-5 Network resilience.** Timeouts / `SocketTimeoutException` produce `ApiResult.Error(Network)`; register (a non-idempotent POST) is **not** retried by the backoff layer.

**FR-6 Payload→destination mapping.** `PushDestinationMapper.map(data: Map<String,String>)` returns the correct typed `PushDestination` for `type=message|broadcast|alert` with their id fields, and returns `null`/`Unknown` for missing/unknown types.

**FR-7 Tap routing.** Dispatching a `PushDestination` to the navigation surface produces the expected Navigation-Compose route string with encoded arguments.

**FR-8 Cold vs warm start.** A tap that launches the app from cold delivers the pending destination after the nav graph is ready (deferred-deep-link buffer is drained), and a warm-start tap navigates immediately.

**FR-9 Malformed payloads.** Null values, wrong-type ids, and empty maps never crash the mapper and never produce a navigation event.

## 4. Technical Design

### 4.1 Test seams in production code

To keep tests hermetic, AND-110 may introduce these minimal seams (all backward-compatible):

```kotlin
// core-data
interface PushRegistrationRepository {
    suspend fun register(token: String): ApiResult<PushRegistration>
}

// feature-push — pure function, trivially unit-testable
class PushDestinationMapper @Inject constructor() {
    fun map(data: Map<String, String>): PushDestination?
}

sealed interface PushDestination {
    data class Message(val messageId: String) : PushDestination
    data class Broadcast(val broadcastId: String) : PushDestination
    data class Alert(val alertId: String) : PushDestination
}

// app/navigation — indirection so routing is testable without a live NavController
fun interface DeepLinkDispatcher {
    fun dispatch(destination: PushDestination)
}
```

`TestLogonMessagingService` (the `FirebaseMessagingService`) delegates parsing to `PushDestinationMapper` and persistence to a `PendingDeepLinkBuffer` (a `DataStore`-backed or in-memory holder), so the JVM tests target those collaborators directly and the instrumented tier only verifies the thin service glue.

### 4.2 Module / source-set layout

```
core-testing/src/main/kotlin/com/testlogon/android/testing/
  FakePushRegistrationStore.kt
  MockWebServerExtensions.kt        // enqueueJson(...), takeJsonRequest()
  PushFixtures.kt                   // canonical payloads + JSON bodies
  MainDispatcherRule.kt
feature-push/src/test/kotlin/com/testlogon/android/push/
  PushRegistrationRepositoryTest.kt // FR-1..FR-5
  PushDestinationMapperTest.kt      // FR-6, FR-9
  PushTapRoutingTest.kt             // FR-7, FR-8
app/src/androidTest/kotlin/com/testlogon/android/push/
  TestLogonMessagingServiceTest.kt  // instrumented glue + Espresso-Intents
```

### 4.3 Key fixtures and helpers

```kotlin
object PushFixtures {
    const val FCM_TOKEN = "fGcm-Test-Token-0001"
    val messageData = mapOf("type" to "message", "message_id" to "msg_42")
    val broadcastData = mapOf("type" to "broadcast", "broadcast_id" to "bc_7")
    val alertData = mapOf("type" to "alert", "alert_id" to "al_9")
    const val REGISTER_OK = """{"registration_id":"reg_123","token":"fGcm-Test-Token-0001","status":"active"}"""
}

@get:Rule val mainDispatcherRule = MainDispatcherRule()   // StandardTestDispatcher
```

`MockWebServer` is started per-test, the `Retrofit`/`OkHttpClient` under test is pointed at `server.url("/")`, and the persistent cookie jar is replaced with an in-memory test jar pre-seeded with a `ui_csrf` cookie so CSRF-header assertions are meaningful.

## 5. API Contract

The endpoint under test (owned by AND-106; reproduced here as the asserted contract).

**Request** — `POST /ui/push/register`

```http
POST /ui/push/register HTTP/1.1
Content-Type: application/json
Cookie: tl_session=...; ui_csrf=<csrf>
X-CSRF-Token: <csrf>

{"token":"fGcm-Test-Token-0001","platform":"android","app_version":"1.0.0"}
```

**Success** — `200 OK`

```json
{"registration_id":"reg_123","token":"fGcm-Test-Token-0001","status":"active"}
```

**Error** — FastAPI `detail`, all three shapes asserted:

```json
{"detail":"token already registered to another user"}
{"detail":[{"loc":["body","token"],"msg":"field required","type":"value_error.missing"}]}
{"detail":{"code":"PUSH_DISABLED","message":"push disabled for tenant"}}
```

Asserted via `MockWebServer`:
- `RecordedRequest.path == "/ui/push/register"`, method `POST`.
- Body decodes to `{token, platform:"android", app_version}`.
- `X-CSRF-Token` header equals the seeded `ui_csrf` cookie value.
- 401 path: register → `POST /ui/session/refresh` → register, in order, total 3 requests.

No new endpoints are introduced by this ticket; the routing half (AND-108) is internal and has no HTTP contract.

## 6. Data & State Management

- **Registration mapping** is read/written through `FakePushRegistrationStore` (an in-memory `PushRegistrationStore` impl) so DataStore I/O is not exercised on the JVM. Tests assert the stored `PushRegistration(registrationId, token, status)` after FR-1 and assert *no* write after FR-3.
- **Idempotency state** (FR-2): the store returns the last-registered token; the repository compares before calling the network.
- **`StateFlow`/`Flow` assertions** use Turbine: where a `PushUiState`/registration-status flow exists, tests `flow.test { assertThat(awaitItem())... ; cancelAndConsumeRemainingEvents() }`.
- **Pending deep-link state** (FR-8): `PendingDeepLinkBuffer` holds at most one `PushDestination`; cold-start test asserts the buffer is populated by the service path and drained exactly once when the nav surface signals ready.
- Coroutines run on `StandardTestDispatcher` via `MainDispatcherRule`; `runTest { ... }` with `advanceUntilIdle()` enforces deterministic ordering. No real time, no real threads.

## 7. Error Handling & Resilience

The suite is the primary enforcer of the resilience contract:

| Case | Stub | Expected result |
|------|------|-----------------|
| 400 string detail | `enqueueJson(400, detailString)` | `ApiResult.Error(Validation)`, no store write |
| 422 list detail | `enqueueJson(422, detailList)` | first `msg` surfaced; `Error(Validation)` |
| 500 object detail | `enqueueJson(500, detailObj)` | `Error(Server)` |
| malformed body | `enqueue(setBody("<<not json>>"))` | `Error(Unknown)`, no crash |
| 401 then 200 | two responses + refresh stub | success after one refresh+retry |
| 401 twice | 401, refresh 200, 401 | `Error(Unauthorized)`, no 3rd register |
| socket timeout | `setSocketPolicy(NO_RESPONSE)` + 1s client timeout | `Error(Network)`, single attempt |

Resilience invariants asserted: register (POST) is **never** retried by the idempotent-GET backoff path; refresh fires **at most once** per call; no unhandled exception propagates from any path (each test wraps the call and asserts a typed `ApiResult`).

## 8. Security & Privacy

- Tests assert the `X-CSRF-Token` header is present and equals the `ui_csrf` cookie on every mutating request (FR-1), guarding against CSRF-header regressions.
- The persistent cookie jar is replaced by an in-memory jar in tests; **no real session cookies are written to disk** during the suite, and no live backend is contacted.
- Fixtures use synthetic tokens/ids only (`fGcm-Test-Token-0001`, `reg_123`); no real FCM credentials, no `google-services.json` secrets, and no PII appear in test code or logs.
- A test asserts the FCM token is **not** emitted to logcat at any level by the repository (verified with a captured test logger), protecting against accidental token leakage.

## 9. Accessibility & i18n

Not directly applicable — this is a logic/integration test ticket with no UI surface of its own. Accessibility and localization of the destination screens are owned by their feature tickets (message/broadcast/alert screens) and AND-107 (channel names). The routing tests assert only route strings and arguments, which are locale-independent. One guard is included: `PushDestinationMapperTest` asserts ids pass through verbatim (no locale-dependent formatting), so non-ASCII ids route correctly.

## 10. Telemetry & Logging

No analytics events are emitted by tests. The suite verifies the *logging contract* of the code under test rather than producing telemetry:
- A `RecordingLogger` test double captures log calls; tests assert registration failures log at `warn`/`error` with an error category but **without** the raw token (see §8).
- A successful registration logs at most one `info`-level event with the `registration_id` (non-secret) and no token.
These assertions are advisory (P2 within this ticket) and skipped if AND-106 does not yet expose an injectable logger; in that case a TODO references the owning ticket.

## 11. Testing Strategy

**Tier A — JVM unit/integration (primary, gating).** Runs under `feature-push:testDebugUnitTest`. No Android device.

- `PushRegistrationRepositoryTest` (FR-1..FR-5) — `MockWebServer` + real Retrofit/Moshi/OkHttp + `FakePushRegistrationStore` + in-memory cookie jar. Representative case:

```kotlin
@Test fun register_success_persists_mapping_and_sends_csrf() = runTest {
    server.enqueueJson(200, PushFixtures.REGISTER_OK)
    val result = repo.register(PushFixtures.FCM_TOKEN)
    val req = server.takeRequest()
    assertThat(req.path).isEqualTo("/ui/push/register")
    assertThat(req.getHeader("X-CSRF-Token")).isEqualTo(SEEDED_CSRF)
    assertThat(result).isInstanceOf(ApiResult.Success::class.java)
    assertThat(store.last()?.registrationId).isEqualTo("reg_123")
}

@Test fun register_401_refreshes_once_then_retries() = runTest {
    server.enqueue(MockResponse().setResponseCode(401))
    server.enqueueJson(200, """{"ok":true}""")          // refresh
    server.enqueueJson(200, PushFixtures.REGISTER_OK)    // retry
    assertThat(repo.register(TOKEN)).isInstanceOf(ApiResult.Success::class.java)
    assertThat(server.requestCount).isEqualTo(3)
    assertThat(server.takeRequest().path).isEqualTo("/ui/push/register")
    assertThat(server.takeRequest().path).isEqualTo("/ui/session/refresh")
}
```

- `PushDestinationMapperTest` (FR-6, FR-9) — pure JUnit, parameterized over the three valid types plus malformed inputs:

```kotlin
@Test fun maps_message_payload() {
    assertThat(mapper.map(PushFixtures.messageData))
        .isEqualTo(PushDestination.Message("msg_42"))
}
@Test fun unknown_type_returns_null() {
    assertThat(mapper.map(mapOf("type" to "zzz"))).isNull()
}
@Test fun empty_or_null_values_do_not_crash() {
    assertThat(mapper.map(emptyMap())).isNull()
    assertThat(mapper.map(mapOf("type" to "message"))).isNull() // missing id
}
```

- `PushTapRoutingTest` (FR-7, FR-8) — uses a fake `DeepLinkDispatcher`/recording nav surface; asserts the route string and argument encoding, plus the cold-start buffer drain:

```kotlin
@Test fun message_destination_navigates_to_message_route() {
    routing.dispatch(PushDestination.Message("msg_42"))
    assertThat(recorder.lastRoute).isEqualTo("message/msg_42")
}
@Test fun cold_start_buffers_then_drains_once_when_ready() = runTest {
    buffer.set(PushDestination.Alert("al_9"))
    routing.onNavReady()
    advanceUntilIdle()
    assertThat(recorder.routes).containsExactly("alert/al_9")
}
```

**Tier B — instrumented (smoke, non-gating on PR, gating on merge).** `app:connectedDebugAndroidTest`, Robolectric-or-emulator. `TestLogonMessagingServiceTest` constructs the service, calls `onMessageReceived(RemoteMessage)` with a fixture data payload, and asserts via Espresso-Intents (`intended(hasComponent(MainActivity))` + extras) or buffer population that the destination is routed. Robolectric is used for `RemoteMessage`/`NotificationManager` types where an emulator is unnecessary.

**Determinism & coverage.** All async via `runTest`; no `Thread.sleep`. JaCoCo line coverage gate ≥ 85% on `PushRegistrationRepository` and `PushDestinationMapper`; the gate is scoped to these two classes only.

## 12. Dependencies & Sequencing

- **Hard deps (must merge first):** AND-106 (registration repository + `/ui/push/register`) and AND-108 (mapper + routing) — they provide the classes under test. AND-110 cannot be completed before both are on `android-port`.
- **Transitive context:** AND-105 (FCM bootstrap), AND-029 (auth/session), AND-107 (channels), AND-022 (nav graph) — relied on indirectly; not asserted here.
- **Shared with siblings:** `core-testing` fakes (`FakePushRegistrationStore`, `MockWebServerExtensions`, `PushFixtures`) are introduced here and reused by AND-107/AND-109 tests; coordinate to avoid duplicate fixtures.
- **Sequencing within ticket:** (1) add `core-testing` fakes/fixtures; (2) Tier A mapper tests (no other deps); (3) Tier A repository tests; (4) Tier A routing tests; (5) Tier B instrumented smoke; (6) wire JaCoCo gate into the `feature-push` Gradle config.
- **Does not block** any production ticket; it is a quality gate. `blocks: []`.

## 13. Risks & Open Questions

- **Seam availability.** If AND-106/AND-108 land without the interfaces in §4.1 (e.g., repository concretely couples to DataStore, or routing calls `NavController` directly), this ticket must add the seams, slightly widening scope. *Mitigation:* coordinate the seams into AND-106/AND-108 PRs.
- **Exact JSON field names.** `app_version`/`platform` and the `detail` object `code` field are inferred from project conventions; confirm against `/openapi.json` and `frontend/src/api/endpoints/*.ts` before finalizing fixtures. *Open question:* does register echo `status` or only `registration_id`?
- **Cold-start mechanism.** The buffer-vs-pending-intent strategy in AND-108 determines whether FR-8 is testable on the JVM (buffer) or only instrumented (intent extras). *Mitigation:* prefer the `PendingDeepLinkBuffer` design.
- **Robolectric vs emulator for `RemoteMessage`.** `RemoteMessage` construction under Robolectric can be brittle across FCM versions; fall back to an emulator-only Tier B if needed. CI cost is the trade-off.
- **Flake from MockWebServer timeouts.** Use a short, explicit client timeout (1s) in the timeout test rather than the production 20s to keep the suite fast and deterministic.

## 14. Acceptance Criteria

1. `./gradlew feature-push:testDebugUnitTest` is green and includes the FR-1..FR-9 cases above.
2. Registration tests prove: success persists the mapping and sends a correct body + `X-CSRF-Token` (FR-1); unchanged-token re-register makes zero network calls (FR-2); all three `detail` error shapes map to typed `ApiResult.Error` with no store write (FR-3); a single 401 triggers exactly one refresh + retry and a double 401 surfaces `Unauthorized` with no third register (FR-4); timeout yields `Error(Network)` with no retry of the POST (FR-5).
3. Routing tests prove: `message`/`broadcast`/`alert` payloads map to the correct `PushDestination` and produce the correct route string with encoded ids (FR-6, FR-7); unknown/missing/malformed payloads never crash and never navigate (FR-9); cold-start buffers then drains exactly once (FR-8).
4. Instrumented `TestLogonMessagingServiceTest` passes, proving `onMessageReceived` routes a fixture payload to the right destination.
5. JaCoCo line coverage ≥ 85% on `PushRegistrationRepository` and `PushDestinationMapper`; the build fails if it drops below.
6. No test contacts the live dev host; all HTTP is served by `MockWebServer`; no real cookies or FCM secrets are persisted.
7. Suite is deterministic: 20 consecutive local runs of Tier A pass with no flakes; no `Thread.sleep` in test code.

## 15. Definition of Done

- All §14 criteria met; Tier A green in CI on `android-port` and Tier B green on the merge pipeline.
- New test files placed per §4.2 under `com.testlogon.android.*`; shared fakes/fixtures live in `core-testing` and are reused, not duplicated.
- Any test seams added to AND-106/AND-108 are minimal, `@VisibleForTesting`-annotated where they widen visibility, and documented in the PR description.
- JaCoCo gate wired into `feature-push` Gradle and enforced in CI; coverage report attached to the PR.
- Open questions in §13 (JSON field names, cold-start mechanism) resolved against `/openapi.json` and the AND-108 implementation, or filed as follow-up tickets with references.
- Code reviewed and merged to `android-port`; no Detekt/ktlint violations introduced by the new test sources.
