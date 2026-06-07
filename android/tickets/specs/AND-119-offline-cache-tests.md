---
id: AND-119
title: Offline cache tests
milestone: M2
epic: E17
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-116, AND-118]
blocks: []
---

# AND-119 — Offline cache tests

## 1. Overview & Goal

This ticket delivers the automated test suite that validates the offline/cache subsystem
built in M2/E17: the stale-while-revalidate (SWR) base repository (AND-116) and the TTL +
size-based eviction layer (AND-118). The goal is a fast, hermetic, deterministic set of unit
and integration tests in `core-data` (and supporting fakes in `core-testing`) that prove the
cache behaves correctly under three conditions: (a) normal cached-then-fresh emission, (b) TTL
expiry and size-based eviction, and (c) a flaky/unreliable backend host (the dev host
`http://18.222.237.167:8000` characteristics: ~20s timeouts, intermittent 5xx/timeouts,
idempotent-GET retries).

This is a **Test** ticket. It adds no production behavior. Where production code is missing
test seams (injectable clock, controllable dispatcher, fault-injecting interceptor), this ticket
may add those seams to `core-data`/`core-network`, but it must not change runtime semantics.
Success is binary and measurable: the entire suite passes deterministically (no flakiness,
no wall-clock sleeps, no real network) across repeated and randomized-order runs.

## 2. Context & References

- **Repo / module:** `spannella/testlogon`, `android/` monorepo subfolder, branch
  `android-port`. Tests live in `core-data` with shared fakes promoted to `core-testing`.
- **Namespace:** `com.testlogon.android` (test packages:
  `com.testlogon.android.core.data.cache`, `com.testlogon.android.core.testing`).
- **Module layering:** `app -> feature-* -> core-*`. The cache repository sits in `core-data`
  and depends on `core-network` (Retrofit/OkHttp/Moshi), `core-model` (domain types), and Room
  2.6 + DataStore. Tests must respect this layering and not reach into `feature-*` or `app`.
- **Subjects under test (SUT):**
  - AND-116 — `CacheRepository` / `networkBoundResource` SWR primitive (emit cache → fetch →
    update; `ApiResult<T>` mapping).
  - AND-118 — TTL expiry, LRU/size-based eviction, per-user cache clear on logout.
- **Sibling (not under test here):** AND-117 stale/reconnect UX hooks are validated by their own
  UI tests; AND-119 covers only the data layer they consume.
- **Backend contract:** FastAPI + DynamoDB, OpenAPI at `/openapi.json`. The web client uses
  cookie-based auth (`credentials: "include"`) with the `ui_csrf` cookie echoed as the
  `X-CSRF-Token` header; an `Authorization: Bearer <accessToken>` header is also attached when an
  access token is present (verified: `src/api/client.ts` lines 135, 157-171). On a 401 *for an
  already-authenticated caller*, the client performs a single deduplicated
  `POST /ui/session/refresh` (shared `refreshPromise`) and retries the original request once; an
  unauthenticated 401 propagates directly, and a failed refresh forces logout (verified:
  `src/api/client.ts` lines 119-237). NOTE on server-side headers: the OpenAPI index lists
  `X-SESSION-ID` and `X-IMPERSONATION-TOKEN` as request headers on `GET /ui/me`; impersonation
  uses `X-IMPERSONATION-TOKEN` (client.ts 162-165). Error `detail` is `string | [{msg,...}] |
  {code,...}` per `normalizeErrorDetail` (verified: client.ts 66-102). The dev host is plaintext
  HTTP and unreliable — tests simulate this rather than calling it.
- **Web reference:** `frontend/src/api/endpoints/*.ts`, `frontend/src/api/types.ts` for the
  shapes the cache stores (e.g. `GET /ui/me` → `MeResp`, list endpoints feeding Paging).

## 3. Functional Requirements

The test suite MUST verify the following SUT behaviors. Each requirement maps to one or more
test cases in §11.

- **FR-1 (SWR cached-then-fresh):** When a valid (non-expired) cache entry exists, the repository
  emits `Resource.Loading(cached)` / cached value first, then performs a network fetch, then
  emits the fresh value and persists it. Order and content are both asserted.
- **FR-2 (cold cache):** With no cache entry, the repository emits a loading state with no data,
  fetches, persists, and emits fresh data. No spurious cached emission occurs.
- **FR-3 (fetch failure with cache):** When cache is valid but the network fails, the repository
  emits the cached value followed by an error that carries the cached data (stale-served), and
  does NOT overwrite the cache with garbage.
- **FR-4 (fetch failure cold):** With no cache and a failed fetch, the repository emits an error
  with no data and persists nothing.
- **FR-5 (TTL expiry):** An entry older than its TTL is treated as stale-must-refetch: it is not
  emitted as authoritative without a refetch attempt, and on successful refetch the timestamp is
  refreshed (AND-118).
- **FR-6 (size/LRU eviction):** When the entry count or byte budget exceeds the configured cap,
  the least-recently-used entries are evicted; freshly written/accessed entries survive (AND-118).
- **FR-7 (per-user clear on logout):** Clearing the cache for a user removes only that user's
  entries, leaving other namespaces intact (AND-118, reuses AND-032 clear hook).
- **FR-8 (flaky-host simulation):** Against a fault-injecting transport (configurable error rate,
  latency, timeout, 5xx, malformed body), idempotent GET retries succeed within the bounded
  backoff budget; non-idempotent calls are not retried; sustained failure surfaces stale cache.
- **FR-9 (determinism):** All time- and concurrency-dependent behavior is driven by an injected
  `Clock`/`TimeSource` and `TestDispatcher`/virtual time. No `Thread.sleep`, no real `System`
  clock, no real OkHttp socket. Seeded randomness for fault injection.

## 4. Technical Design

### 4.1 Test layout

```
core-data/
  src/test/kotlin/com/testlogon/android/core/data/cache/
    SwrCacheRepositoryTest.kt        // FR-1..FR-4
    CacheTtlTest.kt                  // FR-5
    CacheEvictionTest.kt             // FR-6
    CacheUserScopeTest.kt            // FR-7
    FlakyHostCacheTest.kt            // FR-8 (integration: real OkHttp + MockWebServer)
core-testing/
  src/main/kotlin/com/testlogon/android/core/testing/
    MainDispatcherRule.kt
    FakeClock.kt
    FlakyDispatcher.kt               // MockWebServer Dispatcher with seeded faults
    InMemoryCacheDao.kt              // fake Room DAO
    TestEntities.kt                  // sample domain/entity fixtures
```

Unit tests (`SwrCacheRepositoryTest`, `CacheTtlTest`, `CacheEvictionTest`,
`CacheUserScopeTest`) use fakes and run on the JVM with no Android framework (Robolectric not
required). The flaky-host suite uses OkHttp's `MockWebServer` to exercise the real
Retrofit/OkHttp/interceptor stack, which is where retry/backoff/timeout behavior actually lives.

### 4.2 Test seams (added to production if absent)

The SUT must accept injected time and dispatchers. If not already present, add to `core-data`:

```kotlin
class CacheRepository<Key : Any, Domain : Any> @Inject constructor(
    private val dao: CacheDao,
    private val clock: TimeSource = TimeSource.Monotonic, // overridable in test
    private val ioDispatcher: CoroutineDispatcher,
    private val ttlPolicy: CacheTtlPolicy,
    private val evictionPolicy: EvictionPolicy,
)
```

Test helpers in `core-testing`:

```kotlin
class FakeClock(private var nowMs: Long = 0L) {
    fun now(): Long = nowMs
    fun advanceBy(deltaMs: Long) { nowMs += deltaMs }
}

class MainDispatcherRule(
    val dispatcher: TestDispatcher = StandardTestDispatcher(),
) : TestWatcher() {
    override fun starting(d: Description) = Dispatchers.setMain(dispatcher)
    override fun finished(d: Description) = Dispatchers.resetMain()
}
```

### 4.3 SWR assertion harness

`networkBoundResource`/`CacheRepository.stream(key)` returns a `Flow<Resource<Domain>>`.
Tests collect it with Turbine and assert the emission sequence:

```kotlin
@Test fun `emits cached then fresh`() = runTest {
    dao.seed(key, entity = stale, ageMs = 0)               // valid cache
    api.enqueue(success(fresh))
    repo.stream(key).test {
        assertThat(awaitItem()).isEqualTo(Resource.Loading(stale.toDomain()))
        assertThat(awaitItem()).isEqualTo(Resource.Success(fresh.toDomain()))
        awaitComplete()
    }
    assertThat(dao.get(key)).isEqualTo(fresh.toEntity())
}
```

### 4.4 Flaky-host integration harness

`FlakyDispatcher` is a `MockWebServer.Dispatcher` driven by a seeded `Random`. It maps a
configured `FaultProfile` (probabilities for `Timeout`, `Http5xx`, `MalformedBody`, plus a
latency model) onto each request. OkHttp client timeouts are shrunk to milliseconds for the
test (e.g. `callTimeout(200, MILLISECONDS)`) so the real timeout path is exercised in virtual
time without 20s waits. The retry/backoff interceptor under test is configured with a small,
deterministic backoff (e.g. base 10ms, max 3 attempts, GET-only) and the test asserts the
exact number of recorded requests via `MockWebServer.requestCount`.

## 5. API Contract

This ticket defines no new endpoints. It asserts the cache layer's handling of existing
endpoints, replayed through `MockWebServer`. Representative shapes used as fixtures:

`GET /ui/me` success body (cached domain object). CORRECTED — the real `MeResp` shape is
`{ user_sub, session_id, ip }` (verified: `src/api/types.ts` lines 31-35; endpoint
`src/api/endpoints/auth.ts:45` `api.get<MeResp>("/ui/me")`; OpenAPI `GET /ui/me`). The earlier
`{ user_id, username, display_name, factors }` fixture did not exist in the contract and has been
replaced:

```json
{ "user_sub": "u_123", "session_id": "sess_abc", "ip": "203.0.113.7" }
```

FastAPI error bodies the cache/error mapping must tolerate (each is a fixture). NOTE: the array
form is FastAPI's `HTTPValidationError` whose `ValidationError` items REQUIRE `loc`, `msg`, AND
`type` (verified: OpenAPI `components.schemas.ValidationError`, required = `[loc, msg, type]`).
The fixture below has been corrected to include `type`:

```json
{ "detail": "Service unavailable" }
{ "detail": [ { "type": "missing", "loc": ["body","x"], "msg": "field required" } ] }
{ "detail": { "code": "RATE_LIMITED", "retry_after": 5 } }
```

All three shapes are accepted by the web client's `normalizeErrorDetail` (verified: client.ts
66-102): string → as-is, array → join of item `.msg` values, object with a known authorization
`code` → mapped copy (an unknown `code` such as `RATE_LIMITED` falls through to the caller's
fallback message). The Android `AppError` mapper under test must mirror this tolerance.

The flaky-host suite enqueues HTTP 200, 500, 503, malformed JSON, and socket-timeout responses
via `MockResponse` (`setResponseCode`, `setBody`, `setBodyDelay`,
`setSocketPolicy(NO_RESPONSE)`). Authoritative endpoint contracts remain owned by their feature
tickets; AND-119 only consumes them as fixtures. Live calls to `http://18.222.237.167:8000` are
prohibited in this suite (would be non-deterministic).

## 6. Data & State Management

- **Cache store:** Room 2.6 entity `CacheEntryEntity(key: String, userScope: String, payload:
  String /*JSON*/, byteSize: Int, updatedAtMs: Long, ttlMs: Long)`. Tests use an in-memory Room
  DB (`Room.inMemoryDatabaseBuilder(...).allowMainThreadQueries()`) for AND-118 integration
  assertions, and `InMemoryCacheDao` (pure Kotlin map) for fast unit assertions of the SWR flow.
- **Emission model:** `Resource<T>` = `Loading(data: T?)` | `Success(data: T)` | `Error(error:
  AppError, data: T?)`. Tests assert the full sequence, not just the terminal value.
- **State under test, not produced:** AND-119 introduces no app/UI state. ViewModel
  `StateFlow<UiState>` reductions of these resources belong to feature tickets and AND-117.
- **Fixtures:** `TestEntities.kt` provides `stale`, `fresh`, and a `bulkEntries(n, bytesEach)`
  generator used to drive eviction caps. TTL/eviction caps are passed explicitly per test so
  the suite is independent of production default tuning.
- **Time:** all `updatedAtMs`/`ttlMs` comparisons read from `FakeClock`; tests call
  `clock.advanceBy(ttlMs + 1)` to cross the TTL boundary deterministically.

## 7. Error Handling & Resilience

This suite is primarily a verification of error handling and resilience in the cache layer.
Tests assert:

- **Bounded backoff, GET-only retry:** A GET that fails twice then succeeds yields exactly 3
  `MockWebServer` requests; a non-idempotent POST that fails yields exactly 1 request (no
  retry). Backoff delays advance via virtual time, not real sleeps.
- **Timeout handling:** `setSocketPolicy(NO_RESPONSE)` with a short `callTimeout` produces an
  `AppError.Timeout`; with valid cache present, the cached value is still emitted (FR-3).
- **Stale-served on sustained failure:** With fault rate 1.0 and valid cache, the repository
  emits cached data plus a non-fatal error; cache is never overwritten with the failed result.
- **Malformed body:** A 200 with invalid JSON maps to `AppError.Parse`, not a crash; cache is
  preserved.
- **Detail mapping:** Each of the three `detail` shapes (§5) maps to the correct `AppError`
  subtype without throwing.

The suite itself is resilient by construction: deterministic seeds, virtual time, retry-count
assertions instead of timing assertions, and no shared mutable global state between tests
(fresh fakes per test via `@Before`).

## 8. Security & Privacy

Test-only ticket; no production attack surface added. Constraints:

- **No real credentials / no live network.** Cookie jar, CSRF, and refresh flows are simulated
  through `MockWebServer`; tests never transmit real secrets or hit the dev host.
- **Fixtures use synthetic data** only (`alice`, `u_123`); no PII from real accounts.
- **Per-user isolation is a tested property:** `CacheUserScopeTest` asserts that clearing
  user A's cache leaves user B's entries intact (FR-7), guarding against cross-tenant leakage
  through the cache.
- **No secrets in cache fixtures:** tests assert that the SWR layer stores only the response
  payloads it is given; auth tokens/cookies are owned by the cookie jar, not the cache, and the
  suite includes a negative test that the cache DAO is never asked to persist a `Set-Cookie`
  header value.

## 9. Accessibility & i18n

N/A for this ticket — it contains no UI. Accessibility and localization of the stale/reconnect
affordances are owned by **AND-117** (Stale/reconnect UX hooks) and its UI tests. No
user-facing strings are introduced here.

## 10. Telemetry & Logging

No production telemetry is added. The suite asserts that existing cache telemetry/logging hooks
(if present from AND-116/AND-118) fire with correct labels using a fake/spy logger:

```kotlin
class RecordingCacheLogger : CacheLogger {
    val events = mutableListOf<CacheEvent>() // CacheHit, CacheMiss, Revalidate, Evict, Stale
}
```

Tests assert, e.g., `CacheHit` on FR-1, `CacheMiss` on FR-2, `Evict` count on FR-6, and `Stale`
on FR-3/FR-8. Test execution itself emits standard JUnit/Gradle reports
(`core-data/build/reports/tests/`) and, in CI, a JUnit XML artifact. No analytics SDK is
invoked in tests.

## 11. Testing Strategy

This ticket *is* the testing strategy for E17's data layer. Frameworks: JUnit4, Kotlin
`kotlinx-coroutines-test` (`runTest`, `TestDispatcher`, virtual time), Turbine (Flow
assertions), Truth (assertions), MockWebServer (HTTP), in-memory Room. No Mockito of final
Kotlin classes — prefer hand-written fakes in `core-testing`.

| Test class | FRs | Style | Key assertions |
|---|---|---|---|
| `SwrCacheRepositoryTest` | FR-1..4 | unit + Turbine | emission order; cache write/no-write |
| `CacheTtlTest` | FR-5, FR-9 | unit + FakeClock | refetch after `advanceBy(ttl+1)`; timestamp refreshed |
| `CacheEvictionTest` | FR-6 | Room in-memory | LRU survivors; byte/count cap enforced |
| `CacheUserScopeTest` | FR-7 | Room in-memory | only target user's rows deleted |
| `FlakyHostCacheTest` | FR-8, FR-3 | MockWebServer + real OkHttp | exact `requestCount`; GET-only retry; stale-served |

Determinism rules (acceptance-critical):
- Seeded `Random(0xFLAKY)` for `FaultProfile`; same seed → same outcome.
- All delays via `advanceUntilIdle()` / `advanceTimeBy()`; **zero** `Thread.sleep`.
- OkHttp timeouts in milliseconds; no 20s real waits.
- Tests pass under randomized order: run twice in CI —
  `./gradlew :core-data:testDebugUnitTest` and a repeat with
  `-Dtest.random.order=true` (or JUnit `@FixMethodOrder` removed) — and 50x repeat for the
  flaky suite (`--tests FlakyHostCacheTest --rerun-tasks` looped) must be green.
- Coverage target: cache package line coverage ≥ 85% (informational gate, not blocking).

## 12. Dependencies & Sequencing

- **Hard deps:** AND-116 (SWR base repository — the primary SUT) and AND-118 (TTL/eviction — the
  secondary SUT). Both must be merged to `android-port` before this suite can be completed,
  though stubs/fakes may be authored against their interfaces in parallel.
- **Transitive:** AND-115 (cache storage foundation, via AND-116/118), AND-032 (per-user clear
  hook reused by AND-118/FR-7).
- **Tooling deps:** `core-testing` must expose `MainDispatcherRule`, `FakeClock`,
  `FlakyDispatcher`; if absent, this ticket adds them (they are also reused by feature tests).
- **Does not block** feature tickets functionally, but is a quality gate for closing E17. It
  should land in the same milestone (M2) as AND-116/AND-118.

## 13. Risks & Open Questions

- **R-1 (hidden non-determinism in SUT):** If AND-116/118 read `System.currentTimeMillis()` or
  `Dispatchers.IO` directly, tests will flake. Mitigation: add injectable `clock`/dispatcher
  seams (§4.2) — minimal, semantics-preserving production change. *Open:* confirm AND-116's
  final constructor exposes these.
- **R-2 (MockWebServer timeout fidelity):** OkHttp socket timeouts can interact oddly with very
  small values on slow CI. Mitigation: use `callTimeout` at ~200ms and assert `requestCount`
  rather than elapsed time.
- **R-3 (eviction policy ambiguity):** AND-118 may implement LRU vs. LFU vs. FIFO and count- vs.
  byte-cap. *Open:* tests must match the policy AND-118 actually ships; written against the
  policy interface, parameterized so a policy swap changes only fixtures, not assertions.
- **R-4 (Room in-memory vs. fake DAO drift):** Two store implementations risk divergence.
  Mitigation: SWR-flow tests use the fake DAO; eviction/scope tests use real Room so persistence
  semantics are covered at least once.
- **Open Q:** Should the flaky suite be tagged as a separate Gradle test task (e.g.
  `flakyHostTest`) to allow a higher repeat count without slowing the main unit run? Proposed:
  yes, behind a `@Tag("flaky-sim")` JUnit tag.

## 14. Acceptance Criteria

- **AC-1:** All AND-119 test classes pass via `./gradlew :core-data:testDebugUnitTest`
  (plus the `core-testing` compile) with zero failures and zero skips.
- **AC-2 (determinism):** The full suite passes on two consecutive runs and under randomized
  method order; the flaky-host suite passes 50 consecutive repetitions with seed `0xFLAKY`.
- **AC-3 (SWR):** FR-1..FR-4 verified — cached-then-fresh order, cold fetch, stale-served on
  failure, cold error — with cache-write/no-write assertions.
- **AC-4 (TTL/eviction):** FR-5..FR-7 verified — expiry triggers refetch and timestamp refresh;
  size/LRU cap evicts the correct entries; per-user clear deletes only the target user's rows.
- **AC-5 (flaky host):** FR-8 verified — GET-only bounded-backoff retry with exact
  `requestCount`, timeout → `AppError.Timeout` with stale cache served, malformed body →
  `AppError.Parse` without crash, all three `detail` shapes mapped.
- **AC-6 (no real I/O):** Static check / review confirms no `Thread.sleep`, no real clock, and
  no network call to `18.222.237.167` anywhere in the suite.

## 15. Definition of Done

- Test files in §4.1 implemented; shared fakes (`MainDispatcherRule`, `FakeClock`,
  `FlakyDispatcher`, `InMemoryCacheDao`, `TestEntities`) live in `core-testing` and are reusable.
- Any added production test seams (injectable clock/dispatcher) are minimal, reviewed, and do not
  alter runtime behavior of AND-116/AND-118.
- `./gradlew :core-data:testDebugUnitTest` green locally and in CI; flaky-sim tag runs at the
  configured repeat count and is green.
- AC-1 through AC-6 all satisfied and demonstrated in the PR (CI logs / JUnit XML attached).
- Cache-package coverage report generated; no `Thread.sleep`/real-network usages (verified by
  review and a lint/grep check in CI).
- PR targets `android-port`, references AND-119/AND-116/AND-118, and is reviewed by a code owner
  of `core-data`. No new lint or `detekt` warnings introduced.

## 16. Citations & Assumption Audit

Each key technical claim in this spec, with verdict and an exact source pointer. Sources:
OpenAPI index `reference/openapi.index.txt`, OpenAPI full spec
`reference/openapi.pretty.json` (`components.schemas.<Name>`), and frontend reference under
`reference/src/`.

1. **`GET /ui/me` exists.** VERDICT: Verified. SOURCE: OpenAPI `GET /ui/me`
   (`op=ui_me_ui_me_get`, `resp=200;422:HTTPValidationError`,
   `params=user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN`); `src/api/endpoints/auth.ts:45`
   `api.get<MeResp>("/ui/me")`.
2. **`GET /ui/me` success body shape.** VERDICT: Corrected. The spec previously claimed
   `{ user_id, username, display_name, factors }`; the real DTO is
   `MeResp = { user_sub: string, session_id: string, ip: string }`. SOURCE:
   `src/api/types.ts:31-35 (MeResp)`. (The OpenAPI 200 response for `/ui/me` carries no named
   schema in the index; the frontend `MeResp` is the authoritative consumed shape.)
3. **`POST /ui/session/refresh` exists; empty request body; 200 response.** VERDICT: Verified.
   SOURCE: OpenAPI `POST /ui/session/refresh` (`op=ui_session_refresh_ui_session_refresh_post`,
   `req=` empty, `resp=200:`); `src/api/client.ts:121-130 (refreshSession)`.
4. **Auth uses `ui_csrf` cookie echoed as `X-CSRF-Token` header.** VERDICT: Verified. SOURCE:
   `src/api/client.ts:135` (doc comment), `:168-170` (`getCookie("ui_csrf")` →
   `headers.set("X-CSRF-Token", csrf)`), `:16-19 (getCookie)`.
5. **Cookie-based auth via `credentials: "include"`.** VERDICT: Verified. SOURCE:
   `src/api/client.ts:183, 220` (request + retry both `credentials: "include"`); refresh at
   `:124`.
6. **A Bearer token is also attached when present.** VERDICT: Verified (refinement — the spec did
   not mention this). SOURCE: `src/api/client.ts:157-160`
   (`Authorization: Bearer ${accessToken}`).
7. **401 → single `POST /ui/session/refresh` then one retry of the original request.** VERDICT:
   Verified, with nuance. The refresh runs only when the caller is already authenticated
   (unauthenticated 401 propagates), is deduplicated through a shared `refreshPromise`, and a
   failed refresh forces logout. SOURCE: `src/api/client.ts:119, 194-237`.
8. **Impersonation header is `X-IMPERSONATION-TOKEN`.** VERDICT: Verified (context). SOURCE:
   `src/api/client.ts:162-165`; OpenAPI `GET /ui/me` `params=...,X-IMPERSONATION-TOKEN`.
9. **Error `detail` is `string | [ {msg,...} ] | { code, ... }` and the client tolerates all
   three.** VERDICT: Verified. SOURCE: `src/api/client.ts:66-102 (normalizeErrorDetail)` —
   string passthrough (`:67`), array→join of `.msg` (`:70-88`), object/`code` mapping
   (`:89-94`). Authorization-`code` mapping examples confirmed in
   `src/api/client.errorMapping.test.ts`.
10. **FastAPI validation-error item shape.** VERDICT: Corrected. The spec's array fixture
    `{ msg, loc }` was missing the required `type` field. The real `ValidationError` requires
    `loc`, `msg`, AND `type`. SOURCE: OpenAPI `components.schemas.ValidationError`
    (`required: [loc, msg, type]`) and `components.schemas.HTTPValidationError` (array of
    `ValidationError`).
11. **An unknown object `code` (e.g. `RATE_LIMITED`) is not specially mapped and falls back.**
    VERDICT: Verified. SOURCE: `src/api/client.ts:89-101`; negative case in
    `src/api/client.errorMapping.test.ts:34-37` ("does not leak raw object payload for unknown
    structures").
12. **Network/offline error path exists in the transport.** VERDICT: Verified. SOURCE:
    `src/api/client.ts:185-189` (`fetch` throw → `ApiError(0, "Network error")`). This is the web
    analogue of the Android `AppError.Network`/`Timeout` the suite asserts.
13. **Cache subsystem (SWR repository, TTL/eviction, per-user clear), Room 2.6 + DataStore,
    `Resource<T>`/`ApiResult<T>`, `CacheRepository`, `networkBoundResource`, eviction policy,
    `CacheLogger`/`CacheEvent`.** VERDICT: Unverified-assumption. These are Android-side
    production artifacts from AND-116/AND-118 and are not present in the backend OpenAPI or the
    web frontend; they cannot be confirmed from the provided authoritative sources.
14. **Dev host `http://18.222.237.167:8000` with ~20s timeouts / intermittent 5xx.** VERDICT:
    Unverified-assumption. The web client takes its base URL from env `VITE_API_BASE_URL`
    (`src/api/client.ts:7`); the specific IP/port and its reliability characteristics are an
    infra/ticket-provided detail, not part of the API contract. The suite simulates this rather
    than depending on it, so the assumption does not affect determinism.
15. **Test-framework / Android choices** (JUnit4, `kotlinx-coroutines-test` virtual time,
    Turbine, Truth, OkHttp `MockWebServer`, in-memory Room). VERDICT: Unverified-assumption
    (framework refs, not contract). These are standard Android testing tools; correctness is
    asserted by the suite itself, not by the backend contract. framework ref:
    OkHttp MockWebServer (`https://square.github.io/okhttp/4.x/okhttp-mockwebserver/`),
    kotlinx-coroutines-test (`https://kotlinlang.org/api/kotlinx.coroutines/kotlinx-coroutines-test/`).

### Corrections made

- **§5 `GET /ui/me` fixture** replaced `{ user_id, username, display_name, factors }` with the
  real `MeResp` shape `{ user_sub, session_id, ip }` (claim 2).
- **§5 validation-error fixture** added the required `type` field to the array item; documented
  that `ValidationError` requires `loc`, `msg`, `type` (claim 10).
- **§2 backend-contract bullet** refined the auth description: cookie + CSRF confirmed, plus the
  Bearer-token attachment, the only-if-authenticated/deduplicated/logout-on-failure nuances of the
  401→refresh flow, and the server-side `X-SESSION-ID`/`X-IMPERSONATION-TOKEN` headers (claims
  4-9). Also corrected the `/ui/me` reference to point at `MeResp`.

### Open assumptions

- **Android cache internals (AND-116/AND-118 surface):** the class/method names, `Resource`/
  `ApiResult` shapes, eviction policy (LRU vs LFU vs FIFO; count- vs byte-cap), and
  `CacheLogger`/`CacheEvent` API are not in any provided source. They must be reconciled against
  the merged AND-116/AND-118 code before implementation (see R-1, R-3). Tests are written against
  the policy *interface* so a policy swap changes fixtures, not assertions.
- **Dev-host endpoint and reliability profile** (`18.222.237.167:8000`, ~20s timeout, 5xx rate)
  are infra assumptions, not contract; the suite deliberately simulates them via
  `FlakyDispatcher` so they need not be verified to make the suite deterministic.
- **Presence of injectable clock/dispatcher seams** in the shipped AND-116 constructor is
  unconfirmed (R-1); if absent, this ticket adds them as minimal, semantics-preserving changes.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **emu35** = headless emulator
AVD `test35` (x86_64, Android 15/API 35); **A15** = physical Samsung Galaxy A15 5G (SM-A156U,
serial R5CX821TA9R, Android 14/API 34, arm64-v8a). This is a data-layer test ticket: the bulk of
cases are pure JVM unit / MockWebServer contract tests with no device dependency. A few cases are
added to exercise real Room persistence and a real arm64/API-34 run; those are flagged.

- **TC-AND-119-01** — Type: unit. Target: JVM. Precondition: `InMemoryCacheDao` seeded with a
  valid (non-expired) entry for `key`; `FakeClock` at t0; `MockWebServer`/fake api enqueued with a
  fresh success body. Steps: collect `repo.stream(key)` with Turbine. Expected: first emission is
  the cached value (`Resource.Loading(cached)` / cached `Success`), second is `Resource.Success`
  with the fresh value, then complete; DAO now holds the fresh entity; `CacheHit` logged.
  Traces: AC-3 (FR-1).
- **TC-AND-119-02** — Type: unit. Target: JVM. Precondition: empty cache; fresh success enqueued.
  Steps: collect `repo.stream(key)`. Expected: a loading emission with NO data, then
  `Resource.Success(fresh)`; no spurious cached emission; DAO persists the fresh entity;
  `CacheMiss` logged. Traces: AC-3 (FR-2).
- **TC-AND-119-03** — Type: contract/MockWebServer. Target: JVM. Precondition: valid cache present;
  `MockWebServer` enqueues a transport failure (`setSocketPolicy(NO_RESPONSE)` with short
  `callTimeout`). Steps: collect the stream. Expected: cached value emitted first, then
  `Resource.Error(AppError.Timeout, data = cached)` (stale-served); DAO is NOT overwritten;
  `Stale` logged. Traces: AC-3, AC-5 (FR-3).
- **TC-AND-119-04** — Type: unit. Target: JVM. Precondition: empty cache; fetch fails (500). Steps:
  collect the stream. Expected: loading-with-no-data then `Resource.Error(error, data = null)`;
  DAO persists nothing. Traces: AC-3 (FR-4).
- **TC-AND-119-05** — Type: unit. Target: JVM. Precondition: cache entry written at t0 with
  `ttlMs = T`; `FakeClock` advanced by `T + 1`; fresh success enqueued. Steps: `clock.advanceBy(T+1)`
  then collect the stream. Expected: the expired entry is treated as stale-must-refetch (not served
  as authoritative without a refetch), a fetch occurs, and on success `updatedAtMs` is refreshed to
  the new clock value. Traces: AC-4 (FR-5).
- **TC-AND-119-06** — Type: integration. Target: emu35 (real Room in-memory DB). Precondition:
  Room `inMemoryDatabaseBuilder` cache; eviction cap configured (count cap N and/or byte budget B)
  passed explicitly; `bulkEntries` written to exceed the cap, with a known LRU access order. Steps:
  write entries beyond the cap, touch a subset to mark them recently used, trigger eviction.
  Expected: least-recently-used entries are evicted, recently-written/accessed survivors remain,
  count/byte budget is respected; `Evict` count logged equals the number removed. Note: real Room
  → run on emu35 (or JVM via Robolectric); no physical-device need. Traces: AC-4 (FR-6).
- **TC-AND-119-07** — Type: integration. Target: emu35 (real Room in-memory DB). Precondition: Room
  cache seeded with rows for `userScope = A` and `userScope = B`. Steps: invoke the per-user clear
  hook for user A (AND-032/AND-118). Expected: only user A's rows are deleted; all of user B's rows
  remain intact (cross-tenant isolation). Traces: AC-4 (FR-7).
- **TC-AND-119-08** — Type: contract/MockWebServer. Target: JVM. Precondition: real Retrofit/OkHttp
  stack against `MockWebServer`; retry interceptor configured GET-only, base backoff 10ms, max 3
  attempts; `FlakyDispatcher` seeded `Random(0xFLAKY)`; first two GET responses fail (503), third
  succeeds. Steps: issue the GET; advance virtual time over backoff. Expected:
  `MockWebServer.requestCount == 3`; final result is success; backoff advanced via virtual time
  (no `Thread.sleep`). Traces: AC-5 (FR-8).
- **TC-AND-119-09** — Type: contract/MockWebServer. Target: JVM. Precondition: same stack; a
  non-idempotent POST enqueued to fail (500). Steps: issue the POST. Expected:
  `MockWebServer.requestCount == 1` (no retry of non-idempotent method); error surfaced.
  Traces: AC-5 (FR-8).
- **TC-AND-119-10** — Type: contract/MockWebServer. Target: JVM. Precondition: valid cache present;
  `FlakyDispatcher` fault rate 1.0 (sustained failure), seeded. Steps: collect the stream under
  sustained failure. Expected: cached data emitted plus a non-fatal `Resource.Error` carrying the
  cached data; cache never overwritten with the failed result; `Stale` logged. Traces: AC-3, AC-5
  (FR-3, FR-8).
- **TC-AND-119-11** — Type: contract/MockWebServer. Target: JVM. Precondition: `MockWebServer`
  enqueues HTTP 200 with malformed/invalid JSON body; valid cache present. Steps: collect the
  stream. Expected: result maps to `AppError.Parse` (no crash/uncaught exception); existing cache
  is preserved. Traces: AC-5 (FR-8).
- **TC-AND-119-12** — Type: unit (parameterized). Target: JVM. Precondition: three `detail`
  fixtures from §5 — `"Service unavailable"` (string), the corrected validation array
  `[{type,loc,msg}]`, and `{code:"RATE_LIMITED", retry_after:5}`. Steps: run each through the
  Android error mapper. Expected: each maps to the correct `AppError` subtype without throwing —
  string → message verbatim; array → joined `msg` text; object/unknown-code → fallback message
  (mirrors `normalizeErrorDetail`, client.ts:66-102). Traces: AC-5 (FR-8).
- **TC-AND-119-13** — Type: unit (security). Target: JVM. Precondition: a response whose headers
  include `Set-Cookie` and whose body is a normal payload. Steps: run the SWR write path; spy the
  cache DAO. Expected: the DAO is asked to persist ONLY the response payload; it is never asked to
  persist any `Set-Cookie`/auth-header value (auth lives in the cookie jar, not the cache).
  Traces: AC-3, AC-6 (FR-1, §8 isolation).
- **TC-AND-119-14** — Type: instrumented/e2e. Target: A15 (physical device, arm64-v8a, API 34).
  Precondition: the suite assembled and run on the connected Samsung A15 via adb. Steps: run the
  `core-data` debug unit/instrumented tests on-device (real Room on arm64), repeat the
  `@Tag("flaky-sim")` suite 50x with seed `0xFLAKY`; run once more under randomized method order.
  Expected: all cases green on arm64/API-34, identical outcomes to the emulator x86_64/API-35 run
  (no ABI- or API-level divergence), 50/50 flaky-sim repetitions pass deterministically. Note: MUST
  run on the physical device to catch arm64-vs-x86 / API-34-vs-35 differences; CI emu35 covers the
  x86_64/API-35 baseline. Traces: AC-1, AC-2.
- **TC-AND-119-15** — Type: manual (static/review gate). Target: JVM (CI lint/grep). Precondition:
  full AND-119 source tree. Steps: run the CI grep/lint check. Expected: zero `Thread.sleep`, zero
  real-clock (`System.currentTimeMillis`/`Instant.now` outside injected `Clock`), and zero literal
  references to `18.222.237.167` anywhere in the suite. Traces: AC-6.

This ticket has no UI, so there are no Compose-UI or accessibility cases — accessibility of the
stale/reconnect affordances is owned by AND-117 (see §9). The offline/flaky path is covered by
TC-03, TC-08, TC-10, and TC-11; security/isolation by TC-07 and TC-13.

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
|---|---|
| AC-1 (suite passes, no skips) | TC-14 (and all of TC-01..TC-13 as the suite) |
| AC-2 (determinism: repeat + random order + 50x flaky) | TC-08, TC-10, TC-14 |
| AC-3 (SWR FR-1..FR-4) | TC-01, TC-02, TC-03, TC-04, TC-10, TC-13 |
| AC-4 (TTL/eviction FR-5..FR-7) | TC-05, TC-06, TC-07 |
| AC-5 (flaky host FR-8: retry/timeout/malformed/detail) | TC-03, TC-08, TC-09, TC-10, TC-11, TC-12 |
| AC-6 (no real I/O) | TC-13, TC-15 |
