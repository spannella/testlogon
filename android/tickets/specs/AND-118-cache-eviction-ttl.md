---
id: AND-118
title: Cache eviction / TTL
milestone: M2
epic: E17
priority: P2
size: M
status: draft
depends_on: [AND-115, AND-032]
blocks: []
---

# AND-118 — Cache eviction / TTL

## 1. Overview & Goal

The Room-backed offline cache introduced in AND-115 stores API responses (lists,
detail objects, paged feeds) so the app remains usable on the unreliable
PLAINTEXT dev backend (`http://18.222.237.167:8000`) and on flaky mobile
networks. Without a lifecycle policy that cache grows unbounded and serves stale
data indefinitely, and — critically — it leaks one user's cached content to the
next account that signs in on the same device.

This ticket adds a **cache lifecycle layer** in `core-data` with three
responsibilities:

1. **TTL (time-to-live):** every cached entry carries a `fetched_at` timestamp
   and a per-table TTL. Reads classify an entry as `FRESH`, `STALE`, or
   `EXPIRED`. Expired entries are treated as cache-miss and trigger a refetch;
   stale entries may be shown immediately while a background refresh runs
   (stale-while-revalidate).
2. **Size-based eviction:** a bounded LRU policy caps total cached rows (and an
   approximate byte budget) per table, evicting least-recently-accessed entries
   when limits are exceeded, so the on-device database stays bounded.
3. **Per-user cache clear on logout:** all user-scoped cached data is wiped when
   the active user changes, hooked into the AND-032 logout flow so account B
   never sees account A's cached content.

Goal: a single, testable `CachePolicy` + `CacheManager` abstraction that every
feature repository reuses, plus deterministic logout-time purge.

## 2. Context & References

- **Depends on AND-115** (`room-database-base-daos`): provides `TestLogonDatabase`,
  base entity/DAO patterns, and the migration strategy this ticket extends with
  metadata columns and a maintenance DAO.
- **Reuses AND-032** (`logout-flow`): logout already clears cookies + auth state;
  this ticket plugs the per-user cache purge into that flow's "clear caches"
  step rather than introducing a second logout path.
- **Web reference:** `frontend/` has no equivalent — the web app relies on
  HTTP caching and a short-lived in-memory store, so cache TTL/eviction is
  Android-specific. No `frontend/src/api/*` parity required.
- **Module:** all code lands in `core-data` (`com.testlogon.android.core.data.cache`).
  Feature repositories in `feature-*` consume it; no UI module is touched
  except indirectly via repository state.
- **Backend constraints:** GETs are idempotent and may be retried with bounded
  backoff; the host is slow (~20s timeouts). The cache exists to mask this, so
  TTLs are generous and stale data is preferred over a spinner.

## 3. Functional Requirements

FR-1. Each cacheable entity records `fetched_at` (epoch millis) and
`last_accessed_at` (epoch millis) and a logical `cache_key` plus an optional
`user_scope` (the owning user id, or `null` for global/anonymous data).

FR-2. A `CachePolicy` defines per-table `ttl` (fresh window), `staleAfter`
(optional separate stale threshold; defaults to `ttl`), `maxEntries`, and
`maxApproxBytes`. A `freshness(entry, now)` function returns
`FRESH | STALE | EXPIRED`.

FR-3. Reads return cached data with its freshness. Repositories:
- `EXPIRED` → ignore cache, perform network fetch; on success replace entry.
- `STALE` → emit cached value immediately, then refetch in background and
  re-emit (stale-while-revalidate).
- `FRESH` → serve from cache, no network call.

FR-4. On any successful network fetch, the entry's `fetched_at` and
`last_accessed_at` are set to `now`. On every cache read hit,
`last_accessed_at` is updated (used by LRU).

FR-5. Size eviction runs after writes: when a table exceeds `maxEntries` or
`maxApproxBytes`, delete least-recently-accessed rows until under both limits.
Eviction is bounded (deletes in a single transaction) and must not block UI.

FR-6. A periodic/opportunistic **sweep** deletes `EXPIRED` rows (TTL purge) to
reclaim space independent of reads. The sweep runs on app start (once) and on a
`WorkManager`-free coroutine trigger after writes; no new WorkManager dependency
is added by this ticket.

FR-7. **Logout / user-switch purge:** `clearUserCache(userId)` deletes all rows
where `user_scope = userId`, and `clearAllUserScopedCache()` deletes all rows
where `user_scope IS NOT NULL`. The AND-032 logout flow calls the latter.
Global/anonymous (`user_scope IS NULL`) rows survive logout.

FR-8. All operations are suspend functions running on the IO dispatcher and are
safe to call concurrently (single Room writer serializes them).

## 4. Technical Design

### 4.1 Metadata contract

All cacheable entities implement a Room-embeddable metadata block rather than
inheritance (Room entities cannot extend a base entity with columns cleanly):

```kotlin
package com.testlogon.android.core.data.cache

data class CacheMeta(
    @ColumnInfo(name = "cache_key") val cacheKey: String,
    @ColumnInfo(name = "user_scope") val userScope: String?,   // owning user id or null
    @ColumnInfo(name = "fetched_at") val fetchedAt: Long,      // epoch millis
    @ColumnInfo(name = "last_accessed_at") val lastAccessedAt: Long,
    @ColumnInfo(name = "approx_bytes") val approxBytes: Int = 0
)
```

Entities embed it: `@Embedded val meta: CacheMeta`. A marker interface exposes it
for generic maintenance:

```kotlin
interface Cacheable { val meta: CacheMeta }
```

### 4.2 Policy & freshness

```kotlin
enum class Freshness { FRESH, STALE, EXPIRED }

data class CachePolicy(
    val ttl: Duration,
    val staleAfter: Duration = ttl,
    val maxEntries: Int = 500,
    val maxApproxBytes: Long = 4 * 1024 * 1024 // 4 MiB
) {
    fun freshness(fetchedAt: Long, now: Long): Freshness {
        val age = now - fetchedAt
        return when {
            age < staleAfter.inWholeMilliseconds -> Freshness.FRESH
            age < ttl.inWholeMilliseconds        -> Freshness.STALE
            else                                 -> Freshness.EXPIRED
        }
    }
}
```

Note: when `staleAfter < ttl`, the `FRESH/STALE/EXPIRED` ordering holds; when
`staleAfter == ttl` (default) the `STALE` band is empty and entries flip
`FRESH → EXPIRED` directly. Per-table policies are provided via a registry:

```kotlin
object CachePolicies {
    val DEFAULT = CachePolicy(ttl = 15.minutes)
    val LISTS   = CachePolicy(ttl = 5.minutes, staleAfter = 1.minutes, maxEntries = 1000)
    val DETAIL  = CachePolicy(ttl = 30.minutes, staleAfter = 5.minutes, maxEntries = 300)
    fun forTable(table: String): CachePolicy = registry[table] ?: DEFAULT
    private val registry = mapOf(/* "feed_items" to LISTS, ... */)
}
```

### 4.3 CacheManager

```kotlin
@Singleton
class CacheManager @Inject constructor(
    private val maintenanceDao: CacheMaintenanceDao,
    private val clock: Clock,                              // injected for tests
    @IoDispatcher private val io: CoroutineDispatcher
) {
    suspend fun touch(table: String, cacheKey: String)
    suspend fun sweepExpired(table: String, policy: CachePolicy)
    suspend fun enforceLimits(table: String, policy: CachePolicy)
    suspend fun sweepAll()                                 // app-start TTL purge
    suspend fun clearUserCache(userId: String)
    suspend fun clearAllUserScopedCache()
}
```

`Clock` is a thin `interface Clock { fun now(): Long }` with a real
`SystemClock` binding and a `FakeClock` in `core-testing`, so TTL behavior is
deterministic in unit tests without `Thread.sleep`.

### 4.4 Maintenance DAO

Generic SQL keyed by table name (one DAO, parameterized via
`@RawQuery`/`SupportSQLiteQuery`) avoids per-entity boilerplate:

```kotlin
@Dao
abstract class CacheMaintenanceDao {
    @RawQuery suspend fun execDelete(q: SupportSQLiteQuery): Int
    @RawQuery suspend fun execCount(q: SupportSQLiteQuery): Long

    suspend fun deleteExpired(table: String, expiryCutoff: Long): Int =
        execDelete(SimpleSQLiteQuery(
            "DELETE FROM $table WHERE fetched_at < ?", arrayOf(expiryCutoff)))

    suspend fun deleteUserScoped(table: String, userId: String): Int =
        execDelete(SimpleSQLiteQuery(
            "DELETE FROM $table WHERE user_scope = ?", arrayOf(userId)))

    suspend fun deleteAllUserScoped(table: String): Int =
        execDelete(SimpleSQLiteQuery(
            "DELETE FROM $table WHERE user_scope IS NOT NULL"))

    // LRU eviction: keep newest-accessed N rows, delete the rest
    suspend fun evictOverLimit(table: String, keep: Int): Int =
        execDelete(SimpleSQLiteQuery(
            "DELETE FROM $table WHERE rowid NOT IN " +
            "(SELECT rowid FROM $table ORDER BY last_accessed_at DESC LIMIT ?)",
            arrayOf(keep)))
}
```

Table names come from a fixed allowlist (`CacheTables.ALL`) so no user input
ever reaches the interpolated `$table` — this prevents SQL injection through the
raw-query path (see §8).

### 4.5 Repository integration pattern

Repositories wrap reads via a helper so the policy is applied uniformly:

```kotlin
suspend fun <T : Cacheable> cachedFetch(
    table: String,
    read: suspend () -> T?,
    network: suspend () -> ApiResult<T>,
    write: suspend (T) -> Unit
): Flow<ApiResult<T>> = flow {
    val policy = CachePolicies.forTable(table)
    val now = clock.now()
    val cached = read()
    if (cached != null) {
        when (policy.freshness(cached.meta.fetchedAt, now)) {
            Freshness.FRESH -> { cacheManager.touch(table, cached.meta.cacheKey)
                                 emit(ApiResult.Success(cached)); return@flow }
            Freshness.STALE -> emit(ApiResult.Success(cached)) // then revalidate
            Freshness.EXPIRED -> { /* fall through to network */ }
        }
    }
    when (val res = network()) {
        is ApiResult.Success -> { write(res.data)
                                  cacheManager.enforceLimits(table, policy)
                                  emit(res) }
        is ApiResult.Error -> if (cached != null) emit(ApiResult.Success(cached))
                              else emit(res)
    }
}.flowOn(io)
```

This is additive to AND-115's DAOs; existing repositories opt in incrementally.

## 5. API Contract

This ticket introduces **no new backend endpoints**. It governs how responses
from existing idempotent GETs are persisted and aged. The only backend-facing
behavior is that an `EXPIRED` or cache-miss read triggers the same GET the
owning feature ticket already performs (e.g. `GET /ui/me`, list/detail
endpoints), subject to the standard ~20s timeout and bounded backoff for GETs.

The relevant request/response shape is the **on-device row**, not a wire
contract. Each cached row materializes the feature's DTO plus `CacheMeta`:

```json
{
  "...feature DTO fields...": "...",
  "cache_key": "feed:page=1",
  "user_scope": "usr_7c1f...",
  "fetched_at": 1749081600000,
  "last_accessed_at": 1749081930000,
  "approx_bytes": 2048
}
```

`user_scope` is populated from the authenticated user id obtained via the
session (`GET /ui/me` → `id`). Anonymous/global responses persist with
`user_scope = null`.

## 6. Data & State Management

**Schema migration (extends AND-115):** add `fetched_at`, `last_accessed_at`,
`user_scope`, `approx_bytes` columns to each cacheable table plus an index on
`(user_scope)` and `(last_accessed_at)`:

```kotlin
val MIGRATION_N_TO_N1 = object : Migration(N, N + 1) {
    override fun migrate(db: SupportSQLiteDatabase) {
        CacheTables.ALL.forEach { t ->
            db.execSQL("ALTER TABLE $t ADD COLUMN fetched_at INTEGER NOT NULL DEFAULT 0")
            db.execSQL("ALTER TABLE $t ADD COLUMN last_accessed_at INTEGER NOT NULL DEFAULT 0")
            db.execSQL("ALTER TABLE $t ADD COLUMN user_scope TEXT")
            db.execSQL("ALTER TABLE $t ADD COLUMN approx_bytes INTEGER NOT NULL DEFAULT 0")
            db.execSQL("CREATE INDEX IF NOT EXISTS idx_${t}_user ON $t(user_scope)")
            db.execSQL("CREATE INDEX IF NOT EXISTS idx_${t}_lru ON $t(last_accessed_at)")
        }
    }
}
```

Pre-existing rows get `fetched_at = 0`, making them immediately `EXPIRED` (safe:
they refetch on next read). DataStore (prefs) is **not** used for cached content;
it only stores a single `last_sweep_at` long to throttle the app-start sweep.

**Active-user binding:** the current user id is read from the session/auth state
(AND-032 owns it). `CacheManager` does not own auth; it receives the user id from
the caller for scoping writes and purges.

**State exposure:** freshness flows up to ViewModels through the existing
`ApiResult<T>` / `StateFlow<UiState>` channel; a `UiState` may carry an
`isStale: Boolean` flag so a feature can render a subtle "showing cached" hint.
This ticket adds the flag plumbing but leaves rendering to feature tickets.

## 7. Error Handling & Resilience

- **Network failure on EXPIRED with cached data present:** fall back to the
  expired-but-available cached value and surface `isStale = true` rather than
  an error (offline/stale UI state). Only emit `ApiResult.Error` when there is
  no cached fallback at all.
- **Eviction/sweep failures:** wrapped in try/catch; a failed maintenance op
  logs a warning and is retried on the next write — it never propagates to the
  UI or aborts the originating read/write.
- **Migration failure:** if the additive migration throws, fall back to a
  destructive recreate of cache tables only (data is reconstructable from the
  network), guarded so auth/session tables are untouched.
- **Concurrency:** all writes go through Room's single writer; eviction uses one
  transaction so a concurrent read never sees a half-evicted table.
- **Clock skew:** `fetched_at` uses device wall-clock; if the device clock moves
  backward, `age` may be negative → treated as `FRESH` (fail-safe, never
  serves something as more-expired than reality and never crashes).
- Bounded backoff retry stays in `core-network` for the GET itself; this layer
  does not add its own retry loop.

## 8. Security & Privacy

- **Cross-user data isolation is the primary security goal.** Logout (AND-032)
  MUST call `clearAllUserScopedCache()`; a unit + integration test asserts no
  `user_scope IS NOT NULL` rows remain after logout (FR-7).
- **No SQL injection via raw queries:** `$table` interpolation is restricted to
  the compile-time `CacheTables.ALL` allowlist; all variable inputs
  (`userId`, cutoffs, limits) are bound parameters, never string-concatenated.
- **No secrets cached:** session cookies and `ui_csrf` live in the OkHttp
  persistent cookie jar / encrypted store, never in Room. Cache rows hold only
  response payloads.
- **At-rest:** Room cache is app-private storage. If a payload contains PII, the
  per-user purge bounds exposure to the active session; full-disk encryption is
  the platform's responsibility (no SQLCipher added here).
- Package/namespace for all classes: `com.testlogon.android.core.data.cache`.

## 9. Accessibility & i18n

No direct UI surface in this ticket — it is a data-layer concern. The only
user-visible artifact is the optional "showing cached / stale" hint, which is
rendered by feature tickets; this spec mandates that the hint, when shown, use a
localized string resource (e.g. `R.string.cache_stale_banner`) and carry a
`contentDescription` so TalkBack announces stale state. No hard-coded strings,
no non-localizable timestamps surfaced to users. Sections otherwise N/A; UI
ownership belongs to the consuming `feature-*` tickets.

## 10. Telemetry & Logging

- Debug-level logs (stripped/no-op in release via the project logger) for:
  cache hit/miss/stale per table, eviction count, sweep deleted-count,
  per-user purge count.
- Lightweight in-memory counters exposed for tests/diagnostics:

```kotlin
data class CacheStats(
    val hits: Long, val misses: Long, val staleServes: Long,
    val evicted: Long, val expiredPurged: Long
)
fun snapshotStats(): CacheStats
```

- No PII in logs: log `cache_key` and `user_scope` only as hashed/truncated
  ids, never payload contents.
- No analytics SDK is introduced by this ticket; counters are local only.

## 11. Testing Strategy

Unit tests (`core-data` test source set, `core-testing` helpers, `FakeClock`):

1. `freshness()` boundary tests: age just below `staleAfter` → FRESH; between
   `staleAfter` and `ttl` → STALE; at/above `ttl` → EXPIRED; negative age (clock
   skew) → FRESH.
2. **Expired entries refetch** (acceptance): seed a row with old `fetched_at`,
   advance `FakeClock` past `ttl`, assert `cachedFetch` calls `network()` and
   replaces the row.
3. Stale-while-revalidate: STALE read emits cached value first, then refreshed
   value second (use Turbine on the returned `Flow`).
4. FRESH read does **not** call `network()`.
5. LRU eviction: insert `maxEntries + k` rows with ascending `last_accessed_at`,
   run `enforceLimits`, assert the `k` oldest-accessed rows are gone and newest
   `maxEntries` survive.
6. TTL sweep deletes only rows older than `ttl`.

Integration tests (Robolectric / in-memory Room):

7. Migration: build DB at version N, run `MIGRATION_N_TO_N1`, assert new columns
   + indices exist and old rows survive with `fetched_at = 0`.
8. **Logout clears user cache** (acceptance): seed user-A scoped rows + one
   global row, invoke the AND-032 logout path, assert all `user_scope = A` rows
   deleted, global row retained, and a subsequent protected fetch goes to
   network.
9. SQL-injection guard: assert a table name not in `CacheTables.ALL` is
   rejected before any SQL executes.

All async tests use `runTest` + injected `TestDispatcher`; no real sleeps.

## 12. Dependencies & Sequencing

- **Blocked by AND-115** (Room DB + base DAOs) — must merge first; this ticket
  adds columns/indices and the maintenance DAO on top of it.
- **Coupled with AND-032** (logout flow) — the per-user purge plugs into
  AND-032's existing "clear caches" step. If AND-032 ships before this ticket,
  it leaves a no-op hook that this ticket fills; sequencing either order works,
  but both must be merged for FR-7 to be end-to-end testable.
- **Blocks:** none formally, but every later cache-consuming `feature-*`
  repository should adopt `cachedFetch` once this lands; those are independent
  tickets.
- No new third-party libraries; uses existing Room 2.6, Coroutines/Flow, Hilt.

## 13. Risks & Open Questions

- **R1 — `approx_bytes` accuracy:** byte budget is approximate (estimated from
  serialized payload length at write time). Risk: under/over-estimation. Mitigation:
  treat `maxApproxBytes` as a soft cap; `maxEntries` is the hard cap.
- **R2 — Per-table TTL tuning:** default values (5/15/30 min) are guesses for an
  unreliable dev backend. Open question: do specific feeds (e.g. HLS/media
  metadata) need different windows? Defer concrete values to feature tickets via
  `CachePolicies.registry`.
- **R3 — Paging 3 interaction:** Paging's `RemoteMediator` has its own
  freshness concept; need to ensure `cachedFetch` and `RemoteMediator` don't
  double-evict. Open question: should paged tables use `RemoteMediator`'s
  `initialize()` TTL instead of this layer? Proposed: paged tables use
  `RemoteMediator` for freshness and only borrow `clearAllUserScopedCache()` +
  LRU eviction from this ticket.
- **R4 — Wall-clock dependency:** TTL uses device time; large clock changes can
  prematurely expire/freshen entries. Accepted (fail-safe behavior in §7).
- **R5 — Sweep trigger without WorkManager:** opportunistic + app-start sweeps
  may miss long-running sessions. Open question: is a future WorkManager
  periodic sweep warranted (separate ticket)?

## 14. Acceptance Criteria

AC-1 (source): **Expired entries refetch.** A cached entry whose age exceeds its
table TTL is treated as a miss; the repository performs the network GET and
replaces the entry. Covered by test §11.2.

AC-2 (source): **Logout clears user cache (tested).** After the AND-032 logout
flow runs, no rows with `user_scope IS NOT NULL` remain; global rows persist; a
subsequent protected read hits the network. Covered by test §11.8.

AC-3: Size-based LRU eviction keeps a table at or below `maxEntries`, deleting
least-recently-accessed rows first. Covered by §11.5.

AC-4: STALE entries are served immediately and revalidated in the background
(stale-while-revalidate), and FRESH entries make no network call. Covered by
§11.3–§11.4.

AC-5: The additive Room migration applies cleanly, preserves existing rows, and
adds the metadata columns/indices. Covered by §11.7.

AC-6: Raw-query table names are restricted to the `CacheTables.ALL` allowlist;
unknown tables are rejected before SQL executes. Covered by §11.9.

## 15. Definition of Done

- `CacheMeta`, `CachePolicy`, `Freshness`, `CacheManager`,
  `CacheMaintenanceDao`, `CacheTables`, and `Clock`/`SystemClock` implemented in
  `com.testlogon.android.core.data.cache` with Hilt bindings.
- Room migration added and registered; schema JSON regenerated and committed.
- `cachedFetch` helper available to repositories; at least one existing
  repository wired to it as a reference integration.
- AND-032 logout path invokes `clearAllUserScopedCache()`.
- All §11 unit + integration tests pass in CI; AC-1 and AC-2 (the source
  acceptance criteria) have explicit, named tests.
- No new lint/detekt violations; no new third-party dependencies; release build
  strips debug cache logging.
- KDoc on public `CacheManager`/`CachePolicy` APIs documenting TTL semantics and
  the user-scope isolation guarantee.
- Code reviewed and merged to `android-port`.
