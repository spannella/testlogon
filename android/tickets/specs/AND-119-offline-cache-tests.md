---
id: AND-119
title: Offline cache tests
milestone: M2
epic: E17
priority: P1
size: M
status: draft
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
- **Backend contract:** FastAPI + DynamoDB, OpenAPI at `/openapi.json`. Cookie-based auth with
  `ui_csrf` echoed as `X-CSRF-Token`; 401 → single `POST /ui/session/refresh` then retry.
  Error `detail` is `string | [{msg}] | {code,...}`. The dev host is plaintext HTTP and
  unreliable — tests simulate this rather than calling it.
- **Web reference:** `frontend/src/api/endpoints/*.ts`, `frontend/src/api/types.ts` for the
  shapes the cache stores (e.g. `GET /ui/me`, list endpoints feeding Paging).

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

`GET /ui/me` success body (cached domain object):

```json
{ "user_id": "u_123", "username": "alice", "display_name": "Alice", "factors": ["totp"] }
```

FastAPI error bodies the cache/error mapping must tolerate (each is a fixture):

```json
{ "detail": "Service unavailable" }
{ "detail": [ { "msg": "field required", "loc": ["body","x"] } ] }
{ "detail": { "code": "RATE_LIMITED", "retry_after": 5 } }
```

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
