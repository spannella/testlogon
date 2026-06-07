---
id: AND-110
title: Push tests
milestone: M2
epic: E15
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
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

**FR-1 Registration happy path.** Given an authenticated session, `PushRegistrationRepository.register(token)` issues exactly one `POST /ui/push/register` with the FCM token and platform (the only two fields in `PushRegisterReq`; see §5 — there is **no `app_version`** field in the backend contract), includes the `X-CSRF-Token` header echoed from the `ui_csrf` cookie **and the `Authorization: Bearer <accessToken>` header** (the web client sets both; cookies are sent via `credentials: "include"`), returns `ApiResult.Success`, and persists the token→server-registration mapping in DataStore. The 200 body is a `PushDevice` (`{device_id, platform, created_at, last_seen_at}`), so the persisted mapping keys off `device_id`, not a `registration_id`.

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
    // Backend 200 body is a PushDevice (see §5); the prior {registration_id,token,status}
    // fixture was fabricated and has been corrected to the real PushDevice shape.
    const val REGISTER_OK = """{"device_id":"dev_123","platform":"android","created_at":1733443200,"last_seen_at":1733443200}"""
}

@get:Rule val mainDispatcherRule = MainDispatcherRule()   // StandardTestDispatcher
```

`MockWebServer` is started per-test, the `Retrofit`/`OkHttpClient` under test is pointed at `server.url("/")`, and the persistent cookie jar is replaced with an in-memory test jar pre-seeded with a `ui_csrf` cookie so CSRF-header assertions are meaningful.

## 5. API Contract

The endpoint under test (owned by AND-106; reproduced here as the asserted contract).

**Request** — `POST /ui/push/register` · op `ui_register_push_ui_push_register_post` · req schema `PushRegisterReq`.

`PushRegisterReq` has **exactly two required properties**: `token` (string) and `platform` (string). There is **no `app_version`** field in the backend schema — the earlier draft inferred one; it has been removed. The web client (`src/api/client.ts`) sends, on every request: the `Authorization: Bearer <accessToken>` header (when an access token is present), the `X-CSRF-Token` header copied verbatim from the `ui_csrf` cookie, the `X-IMPERSONATION-TOKEN` header (only when impersonating), and all cookies via `credentials: "include"`.

```http
POST /ui/push/register HTTP/1.1
Content-Type: application/json
Authorization: Bearer <accessToken>
Cookie: <session cookies>; ui_csrf=<csrf>
X-CSRF-Token: <csrf>

{"token":"fGcm-Test-Token-0001","platform":"android"}
```

**Success** — `200 OK`, body is a `PushDevice` (the OpenAPI marks the 200 body untyped, `resp=200:`; the frontend types `registerPush` as returning `PushDevice`):

```json
{"device_id":"dev_123","platform":"android","created_at":1733443200,"last_seen_at":1733443200}
```

**Error** shapes (FastAPI `detail`). The OpenAPI documents only `422:HTTPValidationError` for this endpoint (the **list** shape). The string and object shapes below are the generic FastAPI/error-mapping shapes the web client's `normalizeErrorDetail` (`src/api/client.ts`) actually handles across the API; the object-with-`code` shape is real but is associated with 403 (e.g. `geo_blocked`, `role_required`) in the reference client, not arbitrary 500s — adjust the stub status accordingly when asserting it:

```json
{"detail":"token already registered to another user"}
{"detail":[{"loc":["body","token"],"msg":"field required","type":"value_error.missing"}]}
{"detail":{"code":"PUSH_DISABLED","message":"push disabled for tenant"}}
```

Asserted via `MockWebServer`:
- `RecordedRequest.path == "/ui/push/register"`, method `POST`.
- Body decodes to exactly `{token, platform:"android"}` (no `app_version`).
- `X-CSRF-Token` header equals the seeded `ui_csrf` cookie value; `Authorization: Bearer …` header present.
- 401 path: register → `POST /ui/session/refresh` → register, in order, total 3 requests. The reference client refreshes **once** (deduped via a shared `refreshPromise`) then retries once; a second 401 triggers logout/`Unauthorized`.

No new endpoints are introduced by this ticket; the routing half (AND-108) is internal and has no HTTP contract.

## 6. Data & State Management

- **Registration mapping** is read/written through `FakePushRegistrationStore` (an in-memory `PushRegistrationStore` impl) so DataStore I/O is not exercised on the JVM. Tests assert the stored mapping after FR-1 — keyed off the server's `PushDevice.device_id` plus the local FCM `token` (the prior `PushRegistration(registrationId, token, status)` shape is corrected to `PushRegistration(deviceId, token, platform)` to match the real `PushDevice` 200 body; there is no `status` field) — and assert *no* write after FR-3.
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
- A successful registration logs at most one `info`-level event with the server `device_id` (non-secret) and no FCM token.
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
    assertThat(store.last()?.deviceId).isEqualTo("dev_123")
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
- **Exact JSON field names.** *Resolved during review (§16):* `PushRegisterReq` is `{token, platform}` only — there is **no `app_version`** — and the 200 body is a `PushDevice` `{device_id, platform, created_at, last_seen_at}` (no `registration_id`/`status`). The `detail` object `code` shape is real (e.g. `geo_blocked`, `role_required`) but tied to 403 in the reference client. Fixtures in §4.3/§5 are updated accordingly.
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

## 16. Citations & Assumption Audit

Each key technical claim, with VERDICT and an exact SOURCE pointer.

1. **`POST /ui/push/register` is the registration endpoint (method POST, path `/ui/push/register`).** — **Verified.** OpenAPI `POST /ui/push/register` (op `ui_register_push_ui_push_register_post`); frontend `src/api/endpoints/push.ts: registerPush` → `api.post<PushDevice>("/ui/push/register", body)`.
2. **Request body contains `token` and `platform`.** — **Verified.** OpenAPI schema `PushRegisterReq` (`components.schemas.PushRegisterReq`): properties `token`, `platform`, both `required`; frontend `src/api/types.ts: PushRegisterReq { token: string; platform: string }`.
3. **Request body also contains `app_version`.** — **Corrected (claim was WRONG).** `PushRegisterReq` has no `app_version` property in the OpenAPI schema or in `src/api/types.ts: PushRegisterReq`. Removed from FR-1, §4.3, §5, and the asserted body.
4. **Success (200) body is `{registration_id, token, status}`.** — **Corrected (claim was WRONG).** The frontend types the response as `PushDevice`: `src/api/types.ts: PushDevice { device_id, platform, created_at, last_seen_at }` (`src/api/endpoints/push.ts: registerPush` returns `PushDevice`). OpenAPI marks the 200 body untyped (`resp=200:`). Fixtures and the persisted-mapping shape updated to `PushDevice`.
5. **`X-CSRF-Token` header is sent on every request, copied from the `ui_csrf` cookie.** — **Verified.** `src/api/client.ts` lines ~167-171: `const csrf = getCookie("ui_csrf"); if (csrf) headers.set("X-CSRF-Token", csrf);`.
6. **Auth is purely "cookie-based login."** — **Corrected/clarified (claim was INCOMPLETE).** The reference client uses a hybrid: `Authorization: Bearer <accessToken>` header (`src/api/client.ts` ~157-160) PLUS cookies via `credentials: "include"` (~183) PLUS the CSRF header. Noted in FR-1 and §5; tests should assert both the Bearer and CSRF headers.
7. **A 401 triggers exactly one `POST /ui/session/refresh`, then a single retry; a second 401 surfaces Unauthorized with no third attempt.** — **Verified.** `src/api/client.ts` ~119-237: shared `refreshPromise` dedupes refresh; on retry 401 → `useAuthStore.getState().logout("session_expired")` + `ApiError(401)`. OpenAPI `POST /ui/session/refresh` (op `ui_session_refresh_ui_session_refresh_post`, `resp=200:`).
8. **`/ui/session/refresh` exists, method POST.** — **Verified.** OpenAPI `POST /ui/session/refresh`; frontend `src/api/endpoints/auth.ts: refreshSession` → `api.post<StatusResp>("/ui/session/refresh")`.
9. **FastAPI `detail` appears as three shapes: string, list-of-`{loc,msg,type}`, object-with-`{code,message}`; all are handled.** — **Verified (with scope caveat).** `src/api/client.ts: normalizeErrorDetail` handles the string, array (extracts `msg`), and object (`mapAuthorizationError` reads `code`) shapes. Caveat: OpenAPI documents only `422:HTTPValidationError` (the list shape) for `/ui/push/register`; the object-with-`code` shape is associated with 403 (`geo_blocked`, `role_required`, etc.) in the client, not 500. Noted in §5/§7.
10. **Network/offline errors map to a typed network error.** — **Verified.** `src/api/client.ts` ~185-189: `catch (err) { … throw new ApiError(0, "Network error", err) }`. Maps cleanly to the Android `ApiResult.Error(Network)` claim.
11. **The routing half (AND-108) has no HTTP contract; payload→destination mapping and nav routing are internal.** — **Verified (by absence).** No push-routing endpoint exists in the OpenAPI index; FCM data-payload parsing and Navigation-Compose routing are client-side only. The `type=message|broadcast|alert` keys and `message_id`/`broadcast_id`/`alert_id` field names are an **unverified assumption** (see Open assumptions).
12. **Idempotent re-registration short-circuits with zero network calls (FR-2).** — **Unverified-assumption.** This is a proposed Android client behavior; the reference web client (`push.ts: registerPush`) does not implement client-side dedupe. Reasonable test target but not derived from a source.
13. **Test stack versions (JUnit 4.13.2, OkHttp/MockWebServer 4.12, Moshi 1.15, Turbine 1.1.0, Robolectric 4.13, etc.).** — **Unverified-assumption (framework refs).** Library choices, not backend contract; pin against the module's version catalog at implementation time. Framework refs: MockWebServer (square.github.io/okhttp/), Turbine (github.com/cashapp/turbine), Robolectric (robolectric.org).

### Corrections made

- Removed the fabricated `app_version` request field (FR-1, §4.3 fixture, §5 request example, §5 assertion list). `PushRegisterReq` = `{token, platform}` only.
- Corrected the 200 success body from `{registration_id, token, status}` to the real `PushDevice` `{device_id, platform, created_at, last_seen_at}` (§4.3 `REGISTER_OK` fixture, §5 success example, §6 stored-mapping shape, §11 sample assertion `store.last()?.deviceId`).
- Corrected the persisted mapping shape from `PushRegistration(registrationId, token, status)` to `PushRegistration(deviceId, token, platform)` (§6); updated §10 logging to reference `device_id` instead of `registration_id`.
- Clarified auth is a hybrid (Bearer + cookies + CSRF), not "cookie-based" alone (FR-1, §5).
- Annotated the error-shape contract: only the 422/list shape is documented in OpenAPI for this endpoint; the object-with-`code` shape is a 403-associated shape in the reference client (§5, §7).
- Resolved the §13 open question on field names (no `app_version`; `PushDevice` body, no `status`).

### Open assumptions

- **FCM data-payload keys** (`type`, `message_id`, `broadcast_id`, `alert_id`) — not present in any backend schema or frontend source available; they are defined by AND-108's client/server push-payload convention, which is not in the reference app (the web reference has no FCM data-message routing). Must be confirmed against the AND-108 implementation / backend push-sender before finalizing `PushFixtures`.
- **Android-side types** (`ApiResult`, `ErrorType` taxonomy of Validation/Server/Unauthorized/Network/Unknown, `PushRegistrationRepository`, `PushDestinationMapper`, `PendingDeepLinkBuffer`, `DeepLinkDispatcher`) — these are AND-106/AND-108 deliverables, not verifiable from backend/frontend sources; treated as the contract this ticket asserts.
- **Idempotent re-registration (FR-2)** — proposed client behavior, no source counterpart (see citation 12).
- **JaCoCo 85% gate and the exact module/source-set paths** — project-internal conventions, not externally verifiable.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **emu35** = headless AVD `test35` (x86_64, Android 15 / API 35); **deviceA15** = physical Samsung Galaxy A15 5G (SM-A156U, serial `R5CX821TA9R`, Android 14 / API 34, arm64-v8a). For this ticket the device-dependent surface is small (real FCM delivery + notification tap), so most cases run on JVM; the genuine push-delivery case is called out for the physical device.

- **TC-AND-110-01** — Registration happy path
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: MockWebServer up; in-memory cookie jar seeded with `ui_csrf=<csrf>`; access token present; `FakePushRegistrationStore` empty.
  Steps: enqueue `200` with `REGISTER_OK` (`PushDevice` body); call `repo.register(FCM_TOKEN)`; take the recorded request.
  Expected: exactly one request; `path == "/ui/push/register"`, method `POST`; JSON body decodes to `{token, platform:"android"}` with **no `app_version`**; `X-CSRF-Token` equals seeded cookie; `Authorization: Bearer …` header present; result `ApiResult.Success`; store now holds `PushRegistration(deviceId="dev_123", token, platform="android")`.
  Traces: AC-1, AC-2, AC-6.

- **TC-AND-110-02** — Idempotent re-registration (no network)
  Type: unit/contract (JVM). Target: JVM.
  Preconditions: store pre-seeded with the same `token` already registered.
  Steps: call `repo.register(FCM_TOKEN)` with the unchanged token.
  Expected: `server.requestCount == 0`; result is success/no-op; store unchanged.
  Traces: AC-2. (Note: behavior is an unverified assumption per §16 #12.)

- **TC-AND-110-03** — Error mapping: 400 string `detail`
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: as TC-01.
  Steps: enqueue `400` with `{"detail":"token already registered to another user"}`; call register.
  Expected: `ApiResult.Error(Validation)` (or client's 4xx category) carrying the surfaced message; **no store write**; no exception.
  Traces: AC-2, AC-6.

- **TC-AND-110-04** — Error mapping: 422 list `detail` (real HTTPValidationError shape)
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: as TC-01.
  Steps: enqueue `422` with `{"detail":[{"loc":["body","token"],"msg":"field required","type":"value_error.missing"}]}`; call register.
  Expected: `ApiResult.Error(Validation)`; first `msg` ("field required") surfaced; no store write.
  Traces: AC-2, AC-6.

- **TC-AND-110-05** — Error mapping: object `detail` + malformed body
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: as TC-01.
  Steps: (a) enqueue `403` with `{"detail":{"code":"PUSH_DISABLED","message":"push disabled for tenant"}}`; call register. (b) enqueue `500` with body `<<not json>>`; call register again.
  Expected: (a) typed `ApiResult.Error` with the object `message` surfaced, no store write; (b) `ApiResult.Error(Unknown)`, no crash, no store write.
  Traces: AC-2, AC-6.

- **TC-AND-110-06** — 401 → single refresh + retry → success
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: as TC-01.
  Steps: enqueue `401`; enqueue `200` (refresh, `StatusResp`); enqueue `200` `REGISTER_OK`; call register; drain recorded requests.
  Expected: `ApiResult.Success`; `server.requestCount == 3`; ordered paths `/ui/push/register`, `/ui/session/refresh`, `/ui/push/register`.
  Traces: AC-2.

- **TC-AND-110-07** — Double 401 → Unauthorized, no third register
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: as TC-01.
  Steps: enqueue `401`; enqueue `200` (refresh); enqueue `401`; call register.
  Expected: `ApiResult.Error(Unauthorized)`; exactly 3 requests (register, refresh, register) — **no** fourth/third-register attempt; refresh fired at most once.
  Traces: AC-2.

- **TC-AND-110-08** — Network/timeout: no retry of POST
  Type: contract/MockWebServer (JVM). Target: JVM.
  Preconditions: client timeout set to 1s; `server.setSocketPolicy(NO_RESPONSE)` (or `SocketPolicy.NO_RESPONSE`).
  Steps: call register.
  Expected: `ApiResult.Error(Network)`; single attempt (POST not retried by the idempotent-GET backoff path); no store write; completes well under the production 20s timeout.
  Traces: AC-2, AC-7.

- **TC-AND-110-09** — Payload→destination mapping (valid + invalid)
  Type: unit (JVM, parameterized). Target: JVM.
  Preconditions: none.
  Steps: map `messageData`, `broadcastData`, `alertData`; map `{"type":"zzz"}`, `emptyMap()`, `{"type":"message"}` (missing id), and a map with a null/empty id.
  Expected: valid inputs → `Message("msg_42")` / `Broadcast("bc_7")` / `Alert("al_9")`; all invalid/missing/unknown inputs → `null` (or `Unknown`) with no crash and no navigation.
  Traces: AC-3.

- **TC-AND-110-10** — Tap routing: route strings + non-ASCII id pass-through
  Type: unit (JVM, fake `DeepLinkDispatcher`/recording nav surface). Target: JVM.
  Preconditions: recording nav surface.
  Steps: dispatch `Message("msg_42")`, `Broadcast("bc_7")`, `Alert("al_9")`; dispatch a destination with a non-ASCII id.
  Expected: routes `message/msg_42`, `broadcast/bc_7`, `alert/al_9`; ids pass through verbatim with correct argument encoding (locale-independent, non-ASCII id routes intact).
  Traces: AC-3.

- **TC-AND-110-11** — Cold-start buffer drains exactly once; warm-start navigates immediately
  Type: integration (JVM, `runTest`). Target: JVM.
  Preconditions: `PendingDeepLinkBuffer`; recording nav surface.
  Steps: (cold) `buffer.set(Alert("al_9"))`; `routing.onNavReady()`; `advanceUntilIdle()`. (warm) with nav ready, dispatch `Message("msg_42")`.
  Expected: cold → `recorder.routes` contains exactly `["alert/al_9"]` (drained once, buffer empty after); warm → immediate navigation to `message/msg_42`; no duplicate events.
  Traces: AC-3.

- **TC-AND-110-12** — Security: CSRF + Bearer required, no token/cookie leakage
  Type: contract/MockWebServer + unit (JVM). Target: JVM.
  Preconditions: seeded `ui_csrf` cookie; access token; `RecordingLogger` installed.
  Steps: run a successful register; inspect recorded request headers; capture all log output across success and failure paths.
  Expected: mutating request carries `X-CSRF-Token` == cookie value and `Authorization: Bearer …`; the raw FCM token never appears in any log line at any level; no real session cookie written to disk (in-memory jar only); no live host contacted.
  Traces: AC-6.

- **TC-AND-110-13** — Instrumented service glue: `onMessageReceived` routes a fixture payload
  Type: instrumented/e2e (Espresso-Intents) or Robolectric. Target: emu35 (fast CI) or JVM/Robolectric for `RemoteMessage`.
  Preconditions: `TestLogonMessagingService` constructible; nav graph/`PendingDeepLinkBuffer` available.
  Steps: build a `RemoteMessage` with `messageData`; call `service.onMessageReceived(msg)`; assert via Espresso-Intents `intended(hasComponent(MainActivity))` + extras, or via buffer population.
  Expected: the destination (`Message("msg_42")`) is routed/buffered; correct component + extras. Runs on emu35; fall back to Robolectric if `RemoteMessage` is stable, per §13.
  Traces: AC-4.

- **TC-AND-110-14** — Real FCM push delivery + notification tap (hardware)
  Type: manual / instrumented-on-device. Target: **deviceA15 (MUST run on physical device)**.
  Preconditions: real `google-services.json` (dev project), app installed on SM-A156U, POST-notifications permission granted, device registered. Out of the hermetic suite — smoke validation only.
  Steps: send a real FCM data+notification message of each `type`; tap the posted notification from a cold app state and again from a warm state.
  Expected: notification is delivered and tapping opens the correct screen (message/broadcast/alert) with the right id; cold tap drains the pending buffer after nav-ready; warm tap navigates immediately. Confirms behavior the emulator cannot fully exercise (real FCM transport + system notification tap on API 34 / arm64).
  Traces: AC-4 (real-world confirmation of the wiring asserted hermetically in TC-13).

- **TC-AND-110-15** — Determinism / no-flake gate
  Type: integration (JVM, CI harness). Target: JVM.
  Preconditions: full Tier A suite.
  Steps: run `feature-push:testDebugUnitTest` 20 times consecutively; scan sources for `Thread.sleep`.
  Expected: 20/20 green; zero `Thread.sleep` occurrences; all async via `runTest`/`advanceUntilIdle`.
  Traces: AC-7.

- **TC-AND-110-16** — JaCoCo coverage gate
  Type: integration (Gradle/CI). Target: JVM.
  Preconditions: JaCoCo wired into `feature-push`, scoped to the two target classes.
  Steps: run the coverage verification task.
  Expected: line coverage ≥ 85% on `PushRegistrationRepository` and `PushDestinationMapper`; build fails if below.
  Traces: AC-5.

### Coverage matrix

| §14 Acceptance Criterion | Covered by |
|---|---|
| AC-1 (suite green, FR-1..FR-9 present) | TC-01 (and the FR cases across TC-02..TC-11), TC-15 |
| AC-2 (registration: success/body/CSRF, idempotency, error shapes, 401 refresh/retry, timeout no-retry) | TC-01, TC-02, TC-03, TC-04, TC-05, TC-06, TC-07, TC-08 |
| AC-3 (routing: mapping, route strings, malformed-no-nav, cold-start drain) | TC-09, TC-10, TC-11 |
| AC-4 (instrumented `onMessageReceived` routes payload) | TC-13, TC-14 (device confirmation) |
| AC-5 (JaCoCo ≥ 85% on the two classes) | TC-16 |
| AC-6 (no live host / no real cookies or FCM secrets) | TC-01, TC-03, TC-04, TC-05, TC-12 |
| AC-7 (determinism; no `Thread.sleep`) | TC-08, TC-15 |
