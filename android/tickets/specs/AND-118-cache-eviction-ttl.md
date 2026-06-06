---
id: AND-118
title: Cache eviction / TTL
milestone: M2
epic: E17
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
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

> Verification note (§16): `GET /ui/me` is confirmed in the OpenAPI index
> (`GET /ui/me | op=ui_me_ui_me_get`). Its 200 response has **no schema in the
> OpenAPI spec** (`"schema": {}`); the web client types the body as `MeResp`.

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
session (`GET /ui/me` → `user_sub`). Anonymous/global responses persist with
`user_scope = null`.

> Correction (§16): the user identifier returned by `/ui/me` is **`user_sub`**,
> not `id`. The web client's `MeResp` shape is `{ user_sub: string;
> session_id: string; ip: string }` (`src/api/types.ts: MeResp`) — there is no
> `id` field. `user_scope` therefore stores the `user_sub` value.

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
- **No secrets cached:** session cookies and the `ui_csrf` token live in the
  OkHttp persistent cookie jar / encrypted store, never in Room. Cache rows hold
  only response payloads. (Verified against the web client: it sends requests
  with `credentials: "include"` for cookies, an `Authorization: Bearer <token>`
  header, and an `X-CSRF-Token` header sourced from the `ui_csrf` cookie —
  `src/api/client.ts`. The Android port likewise must keep the bearer access
  token out of the Room cache.)
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

## 16. Citations & Assumption Audit

Each key technical claim, its verification verdict, and the exact source pointer.

1. **Claim:** The user identifier for `user_scope` comes from `GET /ui/me`.
   **VERDICT: Verified** (endpoint exists).
   **Source:** OpenAPI `GET /ui/me` (`op=ui_me_ui_me_get`, line 1638 of
   `openapi.index.txt`); frontend `src/api/endpoints/auth.ts: getMe` →
   `api.get<MeResp>("/ui/me")`.

2. **Claim:** The id field returned by `/ui/me` is `id`.
   **VERDICT: Corrected.** The field is **`user_sub`**, not `id`. `MeResp` is
   `{ user_sub: string; session_id: string; ip: string }` — no `id` field.
   **Source:** `src/api/types.ts: MeResp`. §5 corrected accordingly.

3. **Claim (implicit):** `/ui/me` has a typed response body usable to derive the
   user id.
   **VERDICT: Verified with caveat.** The OpenAPI 200 response carries an
   **empty schema** (`"schema": {}`), so the field shape is only authoritative
   from the web client's `MeResp`, not the OpenAPI document.
   **Source:** `openapi.pretty.json` responses block for `ui_me_ui_me_get`
   (200 → `content.application/json.schema = {}`); `src/api/types.ts: MeResp`.

4. **Claim:** CSRF is carried by a `ui_csrf` cookie surfaced as a request
   header.
   **VERDICT: Verified.** The web client reads the `ui_csrf` cookie and sets it
   as the **`X-CSRF-Token`** request header.
   **Source:** `src/api/client.ts` (`getCookie("ui_csrf")` →
   `headers.set("X-CSRF-Token", csrf)`).

5. **Claim:** Session auth is cookie-based and CSRF/cookies must stay out of
   Room (§8).
   **VERDICT: Verified, with addition.** The web client uses cookies
   (`credentials: "include"`) **and** an `Authorization: Bearer <accessToken>`
   header **and** `X-CSRF-Token`. The §8 note was expanded to require keeping the
   bearer access token out of the cache as well.
   **Source:** `src/api/client.ts` (`api<T>` builds `Authorization`,
   `X-CSRF-Token`, and fetches with `credentials: "include"`).

6. **Claim:** Logout is a backend operation that this ticket hooks the cache
   purge into (FR-7, §12; endpoint owned by AND-032).
   **VERDICT: Verified.** Logout is `POST /ui/session/logout`, returning
   `StatusResp` (`{ status: string }`).
   **Source:** OpenAPI `POST /ui/session/logout`
   (`op=ui_session_logout_ui_session_logout_post`, line 1846 of
   `openapi.index.txt`); `src/api/endpoints/auth.ts: logout` →
   `api.post<StatusResp>("/ui/session/logout")`; `src/api/types.ts: StatusResp`.

7. **Claim:** GET endpoints return a 422 validation error on bad input
   (relevant to error-path tests for the GETs the cache replays).
   **VERDICT: Verified.** `/ui/me` (and the other `/ui/*` GETs) declare
   `422 → HTTPValidationError`. Shape: `{ detail: ValidationError[] }`, where
   `ValidationError = { loc: (string|int)[]; msg: string; type: string }`.
   **Source:** `openapi.index.txt` line 1638 (`resp=200:;422:HTTPValidationError`);
   `openapi.pretty.json` `components.schemas.HTTPValidationError` and
   `components.schemas.ValidationError`.

8. **Claim:** Session refresh on 401 is an existing transport concern handled
   below this layer (§7 says backoff/retry stays in `core-network`).
   **VERDICT: Verified.** The web client refreshes once via
   `POST /ui/session/refresh` on a 401 for an authenticated user, else logs out.
   The Android `core-network` layer owns the analogous behavior; this cache
   ticket adds no retry loop.
   **Source:** `src/api/client.ts` (`refreshSession()` →
   `POST /ui/session/refresh`; 401 handling in `api<T>`); OpenAPI
   `POST /ui/session/refresh` (line 1847).

9. **Claim:** The web app has no cache TTL/eviction equivalent, so this is
   Android-specific (§2).
   **VERDICT: Verified (negative finding).** The web client uses HTTP
   `credentials`/cookie transport and per-call typed fetches with no on-device
   persistent cache layer; freshness/eviction logic is absent from
   `src/api/client.ts` and `src/api/endpoints/*`.
   **Source:** `src/api/client.ts` (no persistence/TTL code path present).

10. **Claim:** Room 2.6, Coroutines/Flow, Hilt, `@RawQuery`/`SupportSQLiteQuery`,
    `Migration`, `runTest`/`TestDispatcher`, Turbine are the implementation
    primitives (§4, §11, §12).
    **VERDICT: Unverified-assumption (framework ref).** These are Android/Kotlin
    framework choices, not derivable from the backend or web sources; they are
    standard and correct per their docs.
    **Source (framework ref):**
    Room: https://developer.android.com/training/data-storage/room ;
    Room migrations / `RawQuery`:
    https://developer.android.com/reference/androidx/room/RawQuery ;
    Coroutines testing (`runTest`, `TestDispatcher`):
    https://developer.android.com/kotlin/coroutines/test ;
    Hilt: https://developer.android.com/training/dependency-injection/hilt-android ;
    Paging 3 `RemoteMediator` (R3):
    https://developer.android.com/topic/libraries/architecture/paging/v3-network-db .

11. **Claim:** The dev backend is plaintext HTTP at
    `http://18.222.237.167:8000` with ~20s timeouts (§1, §2).
    **VERDICT: Unverified-assumption.** The web client derives its base URL from
    `VITE_API_BASE_URL` (env) — `src/api/client.ts: API_BASE_URL` — so this
    concrete host/port and timeout are an Android-port deployment assumption not
    present in the reference sources.
    **Source:** `src/api/client.ts` (`API_BASE_URL` from
    `import.meta.env.VITE_API_BASE_URL`).

### Corrections made

- **§5 user-id field:** `GET /ui/me` returns **`user_sub`**, not `id`. Both the
  prose and the audit reflect this; `user_scope` stores `user_sub`. (Audit #2.)
- **§5 added verification note** that `/ui/me`'s OpenAPI 200 schema is empty and
  the field shape is authoritative only from the web client's `MeResp`.
  (Audit #3.)
- **§8 secrets-storage note expanded** to include the `Authorization: Bearer`
  access token (in addition to cookies + `ui_csrf`) as something that must not
  be cached in Room, matching the web client's transport. (Audit #5.)

### Open assumptions

- **Dev host/port + ~20s timeout** (`http://18.222.237.167:8000`): not in the
  reference sources (web base URL is env-driven). Treated as a deployment
  assumption for the Android port. (Audit #11.)
- **Android framework/library versions and APIs** (Room 2.6, Hilt, Coroutines
  test, Turbine, Paging 3): chosen by the Android port, not verifiable from
  backend/web sources; validated against framework docs only. (Audit #10.)
- **Per-table TTL values** (5/15/30 min) and `approx_bytes` estimation accuracy:
  acknowledged as tuning guesses in §13 (R1, R2); no authoritative source.
- **`/ui/me` 200 body fields beyond `MeResp`:** the OpenAPI document does not
  define them, so only `user_sub`/`session_id`/`ip` are confirmed.

## 17. Test Plan

Test target legend: **JVM** = local JVM/Robolectric unit (no device);
**MWS** = contract test via MockWebServer; **AVD test35** = headless emulator,
x86_64, Android 15 / API 35 (CI instrumented/Compose-UI); **Device A15** =
physical Samsung Galaxy A15 5G (SM-A156U, serial R5CX821TA9R), Android 14 /
API 34, arm64-v8a. This ticket is a pure data-layer concern with no direct UI
and no hardware sensors, so most cases run on JVM/Robolectric or the emulator;
the physical device is used only to confirm real-device SQLite/migration and
arm64-vs-x86 (API 34-vs-35) parity.

**TC-AND-118-01 — Expired entry triggers refetch (happy/acceptance)**
- **Type:** unit (JVM, `FakeClock`)
- **Target:** JVM
- **Preconditions:** A cacheable row seeded with `fetched_at` far in the past;
  `CachePolicies.forTable(table).ttl` known; fake `network()` returns a fresh
  value.
- **Steps:** Advance `FakeClock` past `ttl`; call `cachedFetch(...)`.
- **Expected:** `freshness == EXPIRED`; `network()` is invoked exactly once;
  the row is replaced; new `fetched_at`/`last_accessed_at == now`; emitted
  `ApiResult.Success` carries the network value.
- **Traces:** AC-1.

**TC-AND-118-02 — FRESH read serves cache, no network (happy)**
- **Type:** unit (JVM, `FakeClock`)
- **Target:** JVM
- **Preconditions:** Row with `fetched_at == now`; `staleAfter == ttl` (default)
  policy so the row is FRESH.
- **Steps:** Call `cachedFetch(...)` with `FakeClock` unchanged.
- **Expected:** `freshness == FRESH`; `network()` is **not** called; cached
  value emitted; `touch` updates `last_accessed_at`.
- **Traces:** AC-4.

**TC-AND-118-03 — Stale-while-revalidate emits cache then refreshed value**
- **Type:** unit (JVM, Turbine on the returned `Flow`, `FakeClock`)
- **Target:** JVM
- **Preconditions:** Policy with `staleAfter < ttl`; row aged into the STALE
  band; `network()` returns an updated value.
- **Steps:** Collect the `Flow`; assert first then second emission.
- **Expected:** First emission == cached value (immediate); second emission ==
  refreshed network value; `network()` called once; row updated after refresh.
- **Traces:** AC-4.

**TC-AND-118-04 — freshness() boundary + clock-skew classification**
- **Type:** unit (JVM, parameterized)
- **Target:** JVM
- **Preconditions:** `CachePolicy(ttl, staleAfter)` with `staleAfter < ttl`.
- **Steps:** Evaluate `freshness(fetchedAt, now)` at: age just below
  `staleAfter`; age between `staleAfter` and `ttl`; age == `ttl`; age > `ttl`;
  negative age (now < fetchedAt, simulating backward clock).
- **Expected:** FRESH; STALE; EXPIRED (at/above `ttl`); EXPIRED; negative age →
  **FRESH** (fail-safe per §7).
- **Traces:** AC-1, AC-4.

**TC-AND-118-05 — LRU size eviction keeps newest, drops oldest-accessed**
- **Type:** integration (Robolectric in-memory Room)
- **Target:** JVM (Robolectric)
- **Preconditions:** Insert `maxEntries + k` rows with strictly ascending
  `last_accessed_at`.
- **Steps:** Call `enforceLimits(table, policy)`.
- **Expected:** The `k` lowest-`last_accessed_at` rows are deleted; the newest
  `maxEntries` survive; total rows == `maxEntries`; runs in a single
  transaction.
- **Traces:** AC-3.

**TC-AND-118-06 — TTL sweep deletes only expired rows**
- **Type:** integration (Robolectric in-memory Room, `FakeClock`)
- **Target:** JVM (Robolectric)
- **Preconditions:** Seed rows with mixed `fetched_at` (some older than `ttl`,
  some within).
- **Steps:** Call `sweepExpired(table, policy)` (and `sweepAll()`).
- **Expected:** Only rows with `fetched_at < (now - ttl)` are deleted; fresh/
  stale rows remain; deleted-count reported in `CacheStats.expiredPurged`.
- **Traces:** AC-1.

**TC-AND-118-07 — Logout clears user-scoped cache, retains global (acceptance)**
- **Type:** integration (Robolectric in-memory Room)
- **Target:** JVM (Robolectric)
- **Preconditions:** Seed rows for `user_scope = "A"` (the `user_sub` value),
  rows for `user_scope = "B"`, and one row with `user_scope IS NULL` (global).
- **Steps:** Invoke the AND-032 logout path → `clearAllUserScopedCache()`.
- **Expected:** No rows with `user_scope IS NOT NULL` remain (A and B both
  gone); the global row persists; a subsequent protected read finds no cache and
  goes to network.
- **Traces:** AC-2.

**TC-AND-118-08 — Per-user clear scopes by user_sub only**
- **Type:** unit/integration (Robolectric in-memory Room)
- **Target:** JVM (Robolectric)
- **Preconditions:** Rows for `user_scope = "A"` and `user_scope = "B"`.
- **Steps:** Call `clearUserCache("A")`.
- **Expected:** Only `user_scope = "A"` rows deleted; B and global rows
  untouched. Confirms cross-user isolation by `user_sub` (§8).
- **Traces:** AC-2.

**TC-AND-118-09 — Additive migration applies and preserves rows**
- **Type:** integration (Room `MigrationTestHelper`, Robolectric)
- **Target:** JVM (Robolectric)
- **Preconditions:** Build DB at schema version N with pre-existing rows.
- **Steps:** Run `MIGRATION_N_TO_N1`; query schema.
- **Expected:** New columns (`fetched_at`, `last_accessed_at`, `user_scope`,
  `approx_bytes`) and indices (`idx_<t>_user`, `idx_<t>_lru`) exist; old rows
  survive with `fetched_at = 0` (→ classified EXPIRED on next read).
- **Traces:** AC-5.

**TC-AND-118-10 — SQL-injection / unknown-table guard (security)**
- **Type:** unit (JVM)
- **Target:** JVM
- **Preconditions:** A table name not in `CacheTables.ALL` (e.g.
  `"feed; DROP TABLE auth"`).
- **Steps:** Call a maintenance op (e.g. `sweepExpired`/`deleteUserScoped`) with
  the rogue table name.
- **Expected:** Rejected (throws / returns without executing) **before** any SQL
  runs; auth/session tables untouched; bound params (`userId`, cutoffs, limits)
  are never string-concatenated.
- **Traces:** AC-6.

**TC-AND-118-11 — Network failure on EXPIRED falls back to stale cache**
- **Type:** contract (MockWebServer) + unit
- **Target:** MWS (JVM)
- **Preconditions:** Expired cached row present; MockWebServer configured to
  return a network error or a 422 `HTTPValidationError`
  (`{ detail: [{ loc, msg, type }] }`) for the replayed GET.
- **Steps:** Trigger `cachedFetch` so it falls through to `network()`.
- **Expected:** On error with cached data present → emit
  `ApiResult.Success(cachedValue)` with `isStale = true` (no `ApiResult.Error`);
  on 422 the parsed error shape matches `HTTPValidationError`; with **no** cache
  present → emit `ApiResult.Error`.
- **Traces:** AC-1, AC-4.

**TC-AND-118-12 — Flaky/slow dev-host offline path (resilience)**
- **Type:** contract (MockWebServer)
- **Target:** MWS (JVM)
- **Preconditions:** Stale cached row; MockWebServer set to a delayed/timeout
  response (simulating the ~20s slow plaintext dev host) then a socket failure.
- **Steps:** Read a STALE entry; let background revalidation hit the
  timeout/failure.
- **Expected:** Cached value served immediately; background refresh failure is
  swallowed (logged, retried on next write per §7); UI never receives an error
  for a present-cache read; maintenance op failures never abort the read/write.
- **Traces:** AC-4.

**TC-AND-118-13 — Migration + maintenance parity on real device (arm64/API 34)**
- **Type:** instrumented/e2e
- **Target:** **Device A15 (physical, REQUIRED)** — runs on arm64-v8a / API 34
  to confirm real-device SQLite behavior vs the x86_64 / API 35 emulator.
- **Preconditions:** App installed on SM-A156U; seed a DB at version N via test
  hook.
- **Steps:** Launch app (triggers app-start `sweepAll()` + migration); seed
  user-A + global rows; perform logout; re-read.
- **Expected:** Migration succeeds on-device; `idx_*` indices created; LRU
  eviction and `clearAllUserScopedCache()` behave identically to JVM results
  (TC-07, TC-09); no arm64-vs-x86 / API 34-vs-35 divergence in SQLite
  `rowid`/ordering used by the LRU `ORDER BY last_accessed_at DESC` query.
- **Traces:** AC-2, AC-3, AC-5.

**TC-AND-118-14 — Stale-banner accessibility (a11y, when feature renders it)**
- **Type:** Compose-UI (instrumented)
- **Target:** AVD test35
- **Preconditions:** A reference feature screen wired to `cachedFetch` exposing
  `isStale = true`; localized `R.string.cache_stale_banner` present.
- **Steps:** Render with a STALE result; run Compose UI + accessibility
  assertions (TalkBack/semantics).
- **Expected:** The stale hint uses a localized string resource (no hard-coded
  text), exposes a non-empty `contentDescription`/semantics so TalkBack
  announces stale state; no raw timestamp string surfaced. (Plumbing owned by
  this ticket; rendering owned by feature tickets — assertion guards the
  contract.)
- **Traces:** AC-4.

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
| --- | --- |
| AC-1 Expired entries refetch | TC-01, TC-04, TC-06, TC-11 |
| AC-2 Logout clears user cache | TC-07, TC-08, TC-13 |
| AC-3 LRU size eviction | TC-05, TC-13 |
| AC-4 Stale-while-revalidate + FRESH no-network | TC-02, TC-03, TC-04, TC-11, TC-12, TC-14 |
| AC-5 Additive migration applies/preserves | TC-09, TC-13 |
| AC-6 Raw-query table allowlist | TC-10 |
