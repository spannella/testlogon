---
id: AND-116
title: Cache repository pattern (SWR)
milestone: M2
epic: E17
priority: P0
size: M
status: draft
depends_on: [AND-115, AND-018]
blocks: []
---

# AND-116 — Cache repository pattern (SWR)

## 1. Overview & Goal

This ticket delivers the stale-while-revalidate (SWR) base repository that every
data-backed feature in the TestLogon Android app builds on. The unreliable
plaintext dev backend (`http://18.222.237.167:8000`, ~20s timeouts, frequent
flakiness) makes a cache-first contract mandatory: screens must render instantly
from the Room cache (AND-115) and then reconcile against a network fetch, rather
than blocking on a slow or failing request.

The goal is a single, reusable, well-tested coroutine/Flow primitive —
`networkBoundResource` plus a thin `SwrRepository` base — that:

1. Emits the locally cached value first (if present) as `Resource.Loading(data)`.
2. Triggers a network fetch in parallel.
3. On success, writes the fresh value to Room and emits `Resource.Success(fresh)`
   sourced from the database (single source of truth).
4. On failure, emits `Resource.Error(throwable, staleData)` while keeping the
   cached value visible.

The deliverable is library code in `core-data` (no UI, no feature wiring) plus a
deterministic test that proves the cached-then-fresh emission ordering. Feature
repositories (e.g. `/ui/me` profile, dashboards, paginated lists) consume this in
later tickets; they are explicitly out of scope here.

## 2. Context & References

- Module: `core-data` (`com.testlogon.android.core.data`). Layering: `app -> feature-* -> core-*`.
- Depends on **AND-115** (Room database + base DAOs in `core-data`) for the cache
  backing store and DAO conventions, and **AND-018** (`sealed ApiResult<T>` in
  `core-model`) for the network-result type produced by Retrofit call sites.
- Web reference: the React app uses TanStack Query's SWR semantics
  (`staleTime`/`gcTime`, `placeholderData`) in `frontend/src/api/`. This ticket is
  the Kotlin analogue of that cache-then-revalidate behavior.
- Stack: Kotlin 2.0.21, Coroutines/Flow, Hilt (KSP), Room 2.6, Moshi 1.15.
  minSdk 24, JDK 17.
- The classic reference pattern is Google's `NetworkBoundResource`; this ticket
  adapts it to Flow + `ApiResult` + Room and adds a freshness/TTL gate.

## 3. Functional Requirements

FR-1 Provide a generic `networkBoundResource` Flow builder parameterized over a
cache type and a network DTO type.

FR-2 Emit the cached value before any network work begins when a cached value
exists; emit a data-less loading state when it does not.

FR-3 Always attempt revalidation by default; allow callers to gate the fetch with
a `shouldFetch(cached)` predicate (e.g. TTL-based freshness check).

FR-4 On a successful fetch, persist via a caller-supplied `saveFetchResult` and
re-emit the freshly persisted value read back from the cache (DB is the single
source of truth — never emit the network DTO directly to consumers).

FR-5 On fetch failure, emit an error that carries the last known cached value so
the UI can show stale content with an error banner.

FR-6 Surface results as a `Resource<T>` sealed type with `Loading(data?)`,
`Success(data)`, `Error(throwable, data?)`. Map AND-018 `ApiResult.Failure`/
`NetworkError` into `Resource.Error`.

FR-7 Provide an abstract `SwrRepository` base offering a `stream(...)` helper so
feature repositories implement only `cacheFlow`, `fetch`, `persist`, and an
optional `isFresh`.

FR-8 Support a force-refresh entry point that bypasses `shouldFetch`.

FR-9 Be Flow-cold and lifecycle-safe: no work until collected; cancellation
propagates to the in-flight fetch.

## 4. Technical Design

Package: `com.testlogon.android.core.data.swr`.

### 4.1 Resource type

```kotlin
sealed interface Resource<out T> {
    val data: T?

    data class Loading<T>(override val data: T? = null) : Resource<T>
    data class Success<T>(override val data: T) : Resource<T>
    data class Error<T>(
        val throwable: Throwable,
        override val data: T? = null,
    ) : Resource<T>
}
```

### 4.2 The networkBoundResource builder

`DB` is the domain/cache type emitted to consumers; `NET` is the network DTO from
the Retrofit layer wrapped in `ApiResult<NET>` (AND-018).

```kotlin
fun <DB, NET> networkBoundResource(
    query: () -> Flow<DB?>,
    fetch: suspend () -> ApiResult<NET>,
    saveFetchResult: suspend (NET) -> Unit,
    shouldFetch: (DB?) -> Boolean = { true },
    onFetchFailed: (Throwable) -> Unit = {},
): Flow<Resource<DB>> = flow {
    val cached = query().first()
    if (shouldFetch(cached)) {
        emit(Resource.Loading(cached))
        when (val result = fetch()) {
            is ApiResult.Success -> {
                saveFetchResult(result.value)
                emitAll(query().filterNotNull().map { Resource.Success(it) })
            }
            is ApiResult.Failure -> {
                val t = result.error.asThrowable()
                onFetchFailed(t)
                emitAll(query().map { Resource.Error(t, it) })
            }
            is ApiResult.NetworkError -> {
                val t = result.cause
                onFetchFailed(t)
                emitAll(query().map { Resource.Error(t, it) })
            }
        }
    } else {
        emitAll(query().filterNotNull().map { Resource.Success(it) })
    }
}.flowOn(Dispatchers.Default)
```

Notes:
- `query()` is the Room `Flow` (DAO returns `Flow<DB?>`); it stays hot after the
  initial fetch so later DB writes from elsewhere re-emit downstream.
- `result.value` is never emitted directly; we re-read from `query()` so the DB is
  authoritative and Moshi→entity mapping is exercised exactly once.
- `flowOn(Dispatchers.Default)` keeps mapping off the main thread; Room/Retrofit
  switch their own dispatchers internally.

### 4.3 SwrRepository base

```kotlin
abstract class SwrRepository<Key, Domain, Dto> {
    protected abstract fun cacheFlow(key: Key): Flow<Domain?>
    protected abstract suspend fun fetch(key: Key): ApiResult<Dto>
    protected abstract suspend fun persist(key: Key, dto: Dto)
    protected open fun isFresh(cached: Domain?): Boolean = false

    fun stream(key: Key, forceRefresh: Boolean = false): Flow<Resource<Domain>> =
        networkBoundResource(
            query = { cacheFlow(key) },
            fetch = { fetch(key) },
            saveFetchResult = { dto -> persist(key, dto) },
            shouldFetch = { cached -> forceRefresh || !isFresh(cached) },
        )
}
```

### 4.4 TTL / freshness helper

Cache entities carry a `fetchedAt: Long` (epoch millis, written by `persist`). A
default freshness window is provided and overridable per repository:

```kotlin
object CachePolicy { const val DEFAULT_TTL_MS = 60_000L }

fun isFresh(fetchedAt: Long?, ttlMs: Long = CachePolicy.DEFAULT_TTL_MS): Boolean =
    fetchedAt != null && (nowMs() - fetchedAt) < ttlMs
```

`nowMs()` is injected via a `Clock`/time provider interface so tests are
deterministic.

### 4.5 Hilt

No new bindings are strictly required — `networkBoundResource` is a free function
and `SwrRepository` is an abstract base extended by `@Singleton`-scoped feature
repositories. A `TimeProvider` interface is bound in a `@Module` in `core-data` so
freshness checks are mockable. Concrete feature repositories declare
`@Inject constructor`.

## 5. API Contract

This ticket defines **no new HTTP endpoints**. It is a client-side abstraction
over endpoints owned by feature tickets. The shape of the network seam it depends
on is the AND-018 contract:

```kotlin
sealed interface ApiResult<out T> {
    data class Success<T>(val value: T) : ApiResult<T>
    data class Failure(val error: ApiError) : ApiResult<Nothing>
    data class NetworkError(val cause: Throwable) : ApiResult<Nothing>
}
```

The first concrete consumer (downstream, e.g. profile repo) will wrap
`GET /ui/me`, whose body is illustrative of a `Dto` persisted by `persist(...)`:

```json
{ "id": "u_123", "username": "spannella", "display_name": "Sean", "roles": ["user"] }
```

`networkBoundResource` is endpoint-agnostic: callers supply `fetch` returning
`ApiResult<Dto>`. FastAPI `detail` error mapping (`string | [{msg}] | {code,...}`)
is handled upstream in the AND-018 `ApiError` conversion and reaches this layer
only as `ApiResult.Failure`/`NetworkError`. Endpoint-specific contracts belong to
the consuming feature tickets, not here.

## 6. Data & State Management

- Source of truth: Room (AND-115). Repositories never expose network DTOs to
  ViewModels; only DB-read domain models flow out via `Resource<T>`.
- Cache write path: `saveFetchResult`/`persist` maps `Dto -> Entity`, stamps
  `fetchedAt = nowMs()`, and upserts through the AND-115 base DAO
  (`@Upsert`/`OnConflictStrategy.REPLACE`). Writes run in a single Room
  transaction so partial writes never surface a half-fresh state.
- Read path: DAO exposes `Flow<Entity?>` (or `Flow<List<Entity>>`); the repo maps
  entity→domain. Because the query Flow stays subscribed, any later write (force
  refresh, another feature touching the same row) re-emits automatically.
- ViewModels (downstream) collect `stream(key)` and reduce `Resource<T>` into
  their `StateFlow<UiState>`: `Loading(data=null)` → spinner; `Loading(data!=null)`
  → content + subtle refresh indicator; `Success` → content; `Error(_, data)` →
  content + error banner; `Error(_, null)` → full-screen error/retry.
- DataStore is not used here (prefs only); all SWR caching is Room-backed.

## 7. Error Handling & Resilience

- Network failures never clear cached data: `Error` always carries the last DB
  value via `query()`.
- Timeouts/retry/backoff are configured in the OkHttp/Retrofit layer (bounded
  backoff for idempotent GETs, ~20s timeouts) and arrive here as
  `ApiResult.NetworkError`; SWR does not implement its own retry to avoid double
  retry. A `forceRefresh` entry point lets the UI offer manual retry.
- `fetch` exceptions that escape AND-018 mapping are caught by a `.catch { }`
  appended in `stream` and converted to `Resource.Error(it, lastData)`; the Flow
  never crashes the collector.
- Empty cache + failed fetch yields `Resource.Error(t, null)` → callers show a
  retryable empty state.
- Cancellation: builder uses structured concurrency; collector cancellation
  cancels the in-flight `fetch`.

## 8. Security & Privacy

- No new auth surface. Cookie/CSRF session handling lives in the network layer;
  SWR only sees already-authenticated `ApiResult`s.
- Cached entities may contain user data (e.g. profile). This ticket mandates that
  cache writes go only to the app-private Room database (no external storage) and
  that the consuming feature ticket is responsible for clearing relevant tables on
  logout. A `clearAll()`/per-table clear contract is documented for AND-115 DAOs
  so logout (owned downstream) can purge SWR caches.
- No secrets, tokens, or passwords are ever persisted by SWR; only domain DTOs the
  caller chooses to cache. PII columns are not logged (see Section 10).

## 9. Accessibility & i18n

Not applicable directly — this is non-UI library code with no strings, no
Composables, and no user-facing surface. The `Resource` states it emits are the
inputs that downstream feature tickets map to accessible UI (loading
announcements, error banners with `contentDescription`, localized error copy).
No string resources are added by this ticket; error messages shown to users are
produced from `ApiError` by the consuming UI, which owns i18n.

## 10. Telemetry & Logging

- Lightweight debug logging behind a build-flavored `Timber`/logger tag
  `"swr"`: log fetch start, success (with cache key + duration), and failure
  (exception class only — never response bodies or PII). `Loading`/`Success`/
  `Error` transitions logged at `DEBUG`; release builds strip these.
- Emit a counter hook `onFetchFailed(throwable)` so a later analytics ticket can
  record cache-miss / revalidation-failure rates without modifying SWR core.
- No analytics SDK dependency is added here; only the extension point.

## 11. Testing Strategy

Tests live in `core-data` unit tests using `kotlinx-coroutines-test`
(`runTest`, `StandardTestDispatcher`) and Turbine for Flow assertions
(`core-testing`). No Android/instrumentation needed — DAOs are faked with an
in-memory `Flow` or Robolectric in-memory Room.

Required cases:

- **T-1 (acceptance) cached-then-fresh:** seed cache with value A; `fetch`
  returns B. Assert emission order: `Loading(A)` → `Success(B)`, and that
  `saveFetchResult(B)` was invoked exactly once. Proves the core acceptance
  bullet.
- **T-2 empty cache success:** no cached value; `fetch` returns B. Assert
  `Loading(null)` → `Success(B)`.
- **T-3 fetch failure with stale data:** cache A; `fetch` returns
  `ApiResult.NetworkError`. Assert `Loading(A)` → `Error(t, A)`; no save.
- **T-4 fetch failure empty cache:** `Loading(null)` → `Error(t, null)`.
- **T-5 shouldFetch=false (fresh):** cache A, `isFresh` true. Assert single
  `Success(A)`, `fetch` never called.
- **T-6 forceRefresh overrides freshness:** fresh cache but `forceRefresh=true`
  still fetches.
- **T-7 thrown exception in fetch** is caught → `Error`, not a crash.
- **T-8 TTL helper** `isFresh(fetchedAt, ttl)` boundary tests with injected clock.
- **T-9 cancellation:** collector cancels before fetch completes → fetch coroutine
  cancelled (asserted via a flag).

Coverage target: ≥90% lines for `networkBoundResource`, `Resource`, and the TTL
helper.

## 12. Dependencies & Sequencing

- **Blocked by AND-115** — needs Room + base DAO patterns to back the cache and to
  provide `Flow<Entity?>` query methods and upsert.
- **Blocked by AND-018** — needs `ApiResult<T>` as the network-result input.
- Both deps depend on AND-003 (project/module scaffolding).
- **Blocks:** every feature data-repository ticket that needs offline/stale
  behavior (profile, dashboard, lists). Those tickets extend `SwrRepository` or
  call `networkBoundResource`; they own their endpoints, entities, and UI mapping.
- Sequence: AND-003 → (AND-115, AND-018) → **AND-116** → feature repos.

## 13. Risks & Open Questions

- **R-1 Double-fetch / shared cache rows:** if two features cache the same row,
  concurrent writes could thrash. Mitigation: per-key cache flows; consider a
  request-dedup/`mutex` map in a follow-up if observed.
- **R-2 TTL default value:** 60s is a guess for the flaky dev host. Open question:
  per-resource TTLs likely needed; defaulted-and-overridable for now.
- **R-3 Paging interaction:** Paging 3 has its own `RemoteMediator` SWR-like flow;
  this base is for single-object/small-list resources, not paged lists. Open
  question whether to share the freshness helper with `RemoteMediator` (likely
  yes, in a later ticket).
- **R-4 Logout purge ownership:** SWR documents the clear contract but does not
  wire logout; confirm the logout/session ticket consumes it.
- **R-5 Time source:** must inject a clock; using `System.currentTimeMillis()`
  directly would make T-8 flaky.

## 14. Acceptance Criteria

- AC-1 `networkBoundResource` and `Resource<T>` exist in
  `com.testlogon.android.core.data.swr` and `core-data` compiles.
- AC-2 **Cached-then-fresh emission verified by an automated test** (T-1): given a
  seeded cache and a successful fetch, the Flow emits `Loading(cached)` then
  `Success(fresh)` in that order, and the fresh value is persisted to Room and
  read back as the source of truth.
- AC-3 On fetch failure the Flow emits `Error` carrying the last cached value
  (T-3) and never throws to the collector (T-7).
- AC-4 `shouldFetch=false` skips the network and emits cached `Success` only
  (T-5); `forceRefresh=true` always fetches (T-6).
- AC-5 `SwrRepository` base lets a feature repo be implemented by overriding only
  `cacheFlow`, `fetch`, `persist`, and optional `isFresh`.
- AC-6 No network DTO is emitted directly to consumers; all `Success` values are
  read from Room.
- AC-7 Unit-test suite (T-1..T-9) passes with ≥90% coverage on core SWR code.

## 15. Definition of Done

- Code merged to `android-port` under `android/core-data`, namespace
  `com.testlogon.android.core.data.swr`.
- All acceptance criteria met; T-1..T-9 green in CI; coverage gate satisfied.
- KDoc on `networkBoundResource`, `Resource`, and `SwrRepository` explaining the
  emission contract and DB-as-source-of-truth rule.
- `TimeProvider`/clock abstraction bound via Hilt in `core-data`; no direct
  `System.currentTimeMillis()` in testable paths.
- No new lint/detekt warnings; ktlint clean; builds on JDK 17 / AGP 8.7.3 /
  Gradle 8.9.
- No UI, no feature wiring, no new HTTP endpoints introduced (confirmed in review).
- Logout-purge clear contract documented for downstream session ticket.
- Reviewed and approved by an Android maintainer; merged with passing CI.
