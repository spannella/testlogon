---
id: AND-115
title: Room database + base DAOs
milestone: M2
epic: E17
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-003]
blocks: [AND-116, AND-118]
---

# AND-115 — Room database + base DAOs

## 1. Overview & Goal

Establish the persistent on-device cache layer for the TestLogon native Android
app by introducing a Room 2.6 database, its singleton wiring through Hilt, a
migration strategy, and a reusable set of base entity/DAO patterns inside the
`core-data` module. This ticket delivers infrastructure only: it does **not**
implement feature-specific caching, stale-while-revalidate (SWR) repositories,
or TTL/eviction policy. Those are explicitly owned by downstream tickets
AND-116 (Cache repository pattern — SWR) and AND-118 (Cache eviction / TTL),
both of which depend on this work.

The dev backend (`http://18.222.237.167:8000`) is a plaintext, unreliable host
with ~20s timeouts. A durable local cache is therefore foundational: it lets the
app render last-known content while the network is slow, offline, or returning
errors. AND-115 lays the database substrate that makes those offline/stale UI
states possible.

**Definition of success:** the Room database compiles with the KSP annotation
processor, assembles a schema JSON artifact, and a sample entity inserted via a
base DAO round-trips (write → read → equality) under an instrumented test on an
Android device/emulator. No feature module is required to consume it yet.

## 2. Context & References

- **Module:** `core-data` (Android library), created in AND-003. Package root
  `com.testlogon.android.core.data`.
- **Layering:** `app -> feature-* -> core-*`. `core-data` may depend on
  `core-model` (for shared domain types) and `core-testing` (test scope only).
  It must **not** depend on `core-network` or any `feature-*` module.
- **Stack pins:** Room 2.6, KSP, Kotlin 2.0.21, Coroutines/Flow, JDK 17,
  minSdk 24, compileSdk/targetSdk 35, AGP 8.7.3, Gradle 8.9.
- **Prefs vs. cache split:** DataStore owns key/value preferences and auth/CSRF
  state; Room owns structured, queryable, relational cache. Do not store auth
  cookies or secrets in Room (see §8).
- **Downstream consumers:** AND-116 builds the SWR base repository on top of the
  DAOs defined here; AND-118 adds TTL columns/eviction and per-user cache clear
  (reusing logout teardown from AND-032).
- **Web reference:** *Correction (review):* the web app **does** have a
  structured client-side persistence/cache layer — an IndexedDB database
  (`app-offline-cache`) with `api_cache` / `api_cache_meta` object stores
  (PWA-003) plus a `sync_queue` store (PWA-004), driven by
  `src/lib/offlineCache.ts`, `src/lib/offlineCacheConfig.ts`,
  `src/lib/withOfflineCache.ts`, and `src/lib/syncQueueDb.ts`. This IndexedDB
  `api_cache` store is in fact the **conceptual 1:1 analog** of the Room cache
  introduced here: it keys rows by `cacheKey`/`endpoint`/`userId` with a
  `cachedAt` timestamp (the web analog of `CacheEntity.updatedAt`) and applies
  per-endpoint TTL + max-entries eviction (`CACHE_TTL_CONFIG`,
  `MAX_ENTRIES_PER_ENDPOINT`) — the exact policy AND-118 will mirror. The
  earlier "no persistence layer / no 1:1 web equivalent" claim was inaccurate
  and is corrected here. Entity shapes here still derive from `core-model`
  domain types, which in turn mirror `frontend/src/api/types.ts`; Room's row
  *shape* is Android-specific, but the *cache contract* has a direct web
  precedent the downstream SWR/TTL tickets should follow.

## 3. Functional Requirements

FR-1. `core-data` exposes a single Room database class
`TestLogonDatabase` (abstract, `@Database`) as the app-wide cache store, with
filename `testlogon-cache.db`.

FR-2. The database is provided as a process singleton via Hilt and is injectable
into any `core-*`/`feature-*` component requesting a DAO.

FR-3. A reusable base entity contract is defined that all cache entities will
implement, carrying common bookkeeping columns (primary key, `updated_at`
epoch-millis timestamp). This standardizes the rows AND-118 will later expire.

FR-4. A generic base DAO interface defines the common CRUD surface
(`upsert`, `upsertAll`, `getById` as `Flow`, `delete`, `clear`) so feature DAOs
inherit a consistent pattern rather than re-declaring it.

FR-5. A concrete **sample** entity + DAO (`CachedSampleEntity` /
`SampleDao`) demonstrates and verifies the pattern. This sample is internal
test/reference scaffolding, not a shipping feature surface, and may be removed
or kept as a canary once real entities land.

FR-6. A migration strategy is documented and wired: schemas are exported to
version control; `version = 1` is the baseline; the database builder registers
an explicit (initially empty) migration list and uses
`fallbackToDestructiveMigration` **only** in debug builds. Cache data is
non-authoritative, so destructive fallback is acceptable but must be controlled.

FR-7. All write DAO methods are `suspend`; all read methods return
`Flow<T>` (or `suspend` for one-shot reads) and run off the main thread via
Room's coroutine support.

## 4. Technical Design

### 4.1 Gradle / build wiring

In `core-data/build.gradle.kts`:

```kotlin
plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.ksp)
    alias(libs.plugins.hilt)
}

android {
    namespace = "com.testlogon.android.core.data"
    compileSdk = 35
    defaultConfig {
        minSdk = 24
        // Export Room schemas for migration diffing & CI.
        ksp { arg("room.schemaLocation", "$projectDir/schemas") }
    }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    implementation(project(":core-model"))
    implementation(libs.room.runtime)
    implementation(libs.room.ktx)            // Flow + suspend support
    ksp(libs.room.compiler)
    implementation(libs.hilt.android)
    ksp(libs.hilt.compiler)
    androidTestImplementation(project(":core-testing"))
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.room.testing)
}
```

The `schemas/` directory is committed to git; CI fails if a schema change is
uncommitted (see §11). KSP (not kapt) is used per stack pins.

### 4.2 Base contracts

```kotlin
package com.testlogon.android.core.data.db

/** Common columns every cache row carries. Implemented by all entities. */
interface CacheEntity {
    val id: String
    val updatedAt: Long   // epoch millis; written on every upsert; basis for AND-118 TTL
}

/**
 * Generic CRUD surface inherited by every feature DAO.
 * T must be a Room @Entity implementing CacheEntity.
 */
interface BaseDao<T> {
    @Upsert suspend fun upsert(item: T)
    @Upsert suspend fun upsertAll(items: List<T>)
    @Delete suspend fun delete(item: T)
}
```

`@Upsert` (Room 2.6) gives insert-or-update without per-DAO conflict strategy.
`getById`/`clear` are declared per-DAO because Room cannot generate `@Query`
against a generic table name; the sample DAO below shows the canonical shape
that feature DAOs copy.

### 4.3 Sample entity + DAO (verifies the pattern)

```kotlin
package com.testlogon.android.core.data.db.sample

import androidx.room.*
import com.testlogon.android.core.data.db.BaseDao
import com.testlogon.android.core.data.db.CacheEntity
import kotlinx.coroutines.flow.Flow

@Entity(tableName = "cached_sample")
data class CachedSampleEntity(
    @PrimaryKey override val id: String,
    @ColumnInfo(name = "payload") val payload: String,
    @ColumnInfo(name = "updated_at") override val updatedAt: Long,
) : CacheEntity

@Dao
interface SampleDao : BaseDao<CachedSampleEntity> {
    @Query("SELECT * FROM cached_sample WHERE id = :id LIMIT 1")
    fun getById(id: String): Flow<CachedSampleEntity?>

    @Query("SELECT * FROM cached_sample")
    fun observeAll(): Flow<List<CachedSampleEntity>>

    @Query("DELETE FROM cached_sample")
    suspend fun clear()
}
```

### 4.4 Database class

```kotlin
package com.testlogon.android.core.data.db

import androidx.room.Database
import androidx.room.RoomDatabase
import com.testlogon.android.core.data.db.sample.CachedSampleEntity
import com.testlogon.android.core.data.db.sample.SampleDao

@Database(
    entities = [CachedSampleEntity::class],
    version = 1,
    exportSchema = true,
)
abstract class TestLogonDatabase : RoomDatabase() {
    abstract fun sampleDao(): SampleDao

    companion object {
        const val NAME = "testlogon-cache.db"
        val ALL_MIGRATIONS: Array<Migration> = arrayOf() // grows as schema evolves
    }
}
```

### 4.5 Hilt module

```kotlin
package com.testlogon.android.core.data.di

import android.content.Context
import androidx.room.Room
import com.testlogon.android.core.data.BuildConfig
import com.testlogon.android.core.data.db.TestLogonDatabase
import com.testlogon.android.core.data.db.sample.SampleDao
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object DatabaseModule {

    @Provides @Singleton
    fun provideDatabase(@ApplicationContext ctx: Context): TestLogonDatabase =
        Room.databaseBuilder(ctx, TestLogonDatabase::class.java, TestLogonDatabase.NAME)
            .addMigrations(*TestLogonDatabase.ALL_MIGRATIONS)
            .apply { if (BuildConfig.DEBUG) fallbackToDestructiveMigration() }
            .build()

    @Provides fun provideSampleDao(db: TestLogonDatabase): SampleDao = db.sampleDao()
}
```

### 4.6 Migration strategy

- `exportSchema = true` writes `schemas/<db-class>/<version>.json`; baseline is
  `1.json`, committed in this ticket.
- Every schema-changing PR bumps `version`, adds a `Migration(from, to)` to
  `ALL_MIGRATIONS`, and commits the new schema JSON. A CI Gradle task
  (`./gradlew :core-data:compileDebugAndroidTestSources` plus a schema-dirty
  check) enforces this.
- Release builds **never** use destructive fallback. Debug builds may, so
  developers iterating on entities are not blocked.
- Because the database is a pure cache, an explicit destructive recovery path
  (drop + recreate) is acceptable as a last resort, but real migrations are
  preferred to avoid surprising data loss during dev.

## 5. API Contract

N/A for this ticket. AND-115 introduces no network calls and no REST endpoints;
it is a local persistence concern. The mapping between FastAPI/OpenAPI responses
and Room entities is owned by AND-116 (SWR repository), which wires
`core-network` `ApiResult<T>` results into the DAOs defined here. Entity fields
derive from `core-model` domain types rather than directly from any
`/openapi.json` schema in this ticket.

## 6. Data & State Management

- **Storage scope:** Room holds structured, queryable, non-authoritative cache
  rows only. Source of truth remains the FastAPI backend. DataStore (separate)
  holds preferences, auth/session, and the `ui_csrf` value — never Room.
- **Identity & timestamps:** every entity implements `CacheEntity` with a
  string `id` primary key and `updatedAt` epoch-millis. Callers must set
  `updatedAt = System.currentTimeMillis()` on each upsert; this is the column
  AND-118 reads for TTL expiry.
- **Reactivity:** reads return `Flow`; Room emits on any table change so
  repositories/ViewModels observe cache updates and re-render `StateFlow<UiState>`
  without manual invalidation. One-shot reads use `suspend` functions.
- **Threading:** all DAO I/O runs on Room's internal executor via
  coroutine support; no DAO is called from the main dispatcher. Database build
  uses default journal mode (WAL) for concurrent read/write.
- **No in-memory caching layer here:** memory caching/SWR sequencing is AND-116.
- **Lifecycle:** the database is an `@Singleton` bound to the application
  context; it is not closed during normal app lifetime.

## 7. Error Handling & Resilience

- **Migration failure:** in release, a failed/missing migration throws
  `IllegalStateException` at build time — surfaced in instrumentation/QA, never
  to users, because schema JSON + migration tests catch it pre-merge. In debug,
  destructive fallback recreates the DB.
- **Corruption:** Room's default `onCorruption` recreates the file; since data
  is non-authoritative cache, recreation is safe and self-healing. No user-facing
  error is shown; the next network fetch repopulates.
- **Disk full / write failure:** DAO `suspend` calls may throw `SQLiteException`.
  Repositories (AND-116) are responsible for catching these and degrading to
  network-only behavior; this ticket guarantees the exceptions propagate cleanly
  out of the suspend functions rather than crashing on the main thread.
- **Network independence:** the cache layer has no network dependency, so the
  unreliable dev host and ~20s timeouts do not affect AND-115. Resilience to the
  flaky backend is achieved *by* this cache (offline/stale reads), exercised in
  consuming tickets.

## 8. Security & Privacy

- **No secrets in Room.** Auth cookies, the persistent cookie jar, and the
  `ui_csrf` token live in OkHttp's cookie jar / DataStore, not the cache DB.
  Cache rows hold only already-fetched, user-visible content.
- **Per-user isolation:** entities that hold user-scoped data must include an
  owning-user discriminator column when introduced by feature tickets; AND-118
  implements per-user cache clear on logout (reusing AND-032 teardown). This
  ticket documents the requirement and ensures `clear()` exists as the teardown
  primitive.
- **At-rest:** default Room storage is unencrypted app-private storage
  (`/data/data/com.testlogon.android/databases/`), readable only by the app
  sandbox. SQLCipher is out of scope; flagged as an open question (§13) if
  sensitive PII is later cached.
- **Logging:** never log row payloads or PII (see §10). Schema/migration logs
  are safe to emit.

## 9. Accessibility & i18n

N/A — AND-115 has no UI surface. There are no Compose screens, strings, or
user-visible text in this ticket; accessibility and localization apply to the
feature tickets that render cached data. No user-facing strings are introduced
(the sample payload is opaque test data, not localized copy).

## 10. Telemetry & Logging

- **Build/migration events:** log database open, applied migration version
  transitions (`from -> to`), and destructive-fallback occurrences at `INFO`
  (debug) / `WARN` (destructive) via the app's logging facade. No PII.
- **No row-level telemetry:** do not log entity contents, ids that are PII, or
  query results. Cache hit/miss analytics are an AND-116 concern.
- **Strict-mode:** debug builds keep StrictMode disk-read/write detection on;
  DAO calls must not trip it on the main thread, providing a passive guard that
  threading is correct.

## 11. Testing Strategy

- **Instrumented round-trip (primary acceptance test),** `core-data`
  `androidTest`:

```kotlin
@RunWith(AndroidJUnit4::class)
class SampleDaoTest {
    private lateinit var db: TestLogonDatabase
    private lateinit var dao: SampleDao

    @Before fun setUp() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        db = Room.inMemoryDatabaseBuilder(ctx, TestLogonDatabase::class.java)
            .allowMainThreadQueries().build()
        dao = db.sampleDao()
    }
    @After fun tearDown() = db.close()

    @Test fun upsert_then_read_round_trips() = runTest {
        val row = CachedSampleEntity("k1", "hello", 42L)
        dao.upsert(row)
        assertEquals(row, dao.getById("k1").first())
    }

    @Test fun upsert_updates_existing_row() = runTest {
        dao.upsert(CachedSampleEntity("k1", "v1", 1L))
        dao.upsert(CachedSampleEntity("k1", "v2", 2L))
        val r = dao.getById("k1").first()!!
        assertEquals("v2", r.payload); assertEquals(2L, r.updatedAt)
    }

    @Test fun clear_empties_table() = runTest {
        dao.upsert(CachedSampleEntity("k1", "v", 1L))
        dao.clear()
        assertTrue(dao.observeAll().first().isEmpty())
    }
}
```

- **Migration test harness:** add `MigrationTestHelper` wired to the exported
  `schemas/` dir so the moment a real `Migration` is added it can be validated.
  Baseline (v1) has no migration to test yet; the harness is committed ready.
- **Schema-export CI check:** a CI step runs the androidTest build and asserts
  `git status schemas/` is clean — an uncommitted schema change fails the build.
- **Hilt provisioning smoke test:** an instrumented test using a Hilt test
  component asserts `TestLogonDatabase` and `SampleDao` inject as singletons.
- **No unit (JVM) DB tests** — Room requires Android; all DB tests are
  instrumented and run on emulator (API 24 + API 35 in CI matrix).

## 12. Dependencies & Sequencing

- **Depends on:** AND-003 (core module structure) — `core-data` module and its
  build file must exist. Hard blocker.
- **Blocks:** AND-116 (SWR cache repository — consumes `BaseDao`/DAOs and the
  database singleton) and AND-118 (TTL/eviction — extends `CacheEntity.updatedAt`
  and `clear()`).
- **Adjacent:** AND-018 is a co-dependency of AND-116, not of this ticket;
  AND-032 logout teardown is reused by AND-118, not implemented here.
- **Sequencing:** land Gradle/KSP wiring → base contracts → sample entity/DAO →
  database + Hilt module → schema export + tests, in one PR.

## 13. Risks & Open Questions

- **R1 — Destructive fallback in debug masking migration bugs.** Mitigation:
  schema export + `MigrationTestHelper` committed now so real migrations are
  always tested; destructive fallback never enabled in release.
- **R2 — Generic `BaseDao` limits.** Room cannot generate generic `@Query` by
  table; per-DAO `getById`/`clear` duplication is accepted as the documented
  pattern. Acceptable for the small DAO count expected.
- **OQ1 — At-rest encryption:** is SQLCipher required if PII (e.g., profile
  data) is cached later? Defer until a feature ticket caches PII; revisit in
  AND-118 security review.
- **OQ2 — Single DB vs. per-feature DBs:** current decision is one shared
  `TestLogonDatabase`. Revisit only if module-boundary coupling becomes painful.
- **OQ3 — WAL vs. TRUNCATE journal mode** on minSdk 24 emulators: default WAL
  assumed fine; confirm on the API 24 CI runner.

## 14. Acceptance Criteria

AC-1. `core-data` compiles with Room + KSP; `./gradlew :core-data:assemble`
and `:core-data:compileDebugAndroidTestSources` succeed on JDK 17 / AGP 8.7.3.

AC-2. `TestLogonDatabase` (version 1, `exportSchema = true`) exists with the
`CacheEntity` and `BaseDao<T>` base contracts and the `CachedSampleEntity` /
`SampleDao` sample, all under `com.testlogon.android.core.data`.

AC-3. The instrumented `upsert_then_read_round_trips` test passes on an
emulator: a sample entity written via the DAO is read back equal (the explicit
backlog acceptance — "a sample entity round-trips (tested)").

AC-4. `TestLogonDatabase` and `SampleDao` are injectable Hilt singletons via
`DatabaseModule`.

AC-5. Schema JSON `schemas/.../1.json` is committed; CI fails on an uncommitted
schema change.

AC-6. Release builds do not enable `fallbackToDestructiveMigration`; debug
builds do. Verified by build-variant inspection / a guarded `BuildConfig.DEBUG`
check.

AC-7. No auth/CSRF/secret data is written to Room (code review checklist item).

## 15. Definition of Done

- All §14 acceptance criteria met and green in CI (emulator API 24 + 35).
- Code merged to branch `android-port` under `android/core-data/`.
- Migration/test harness and committed baseline schema present; schema-dirty CI
  gate active.
- KDoc on `TestLogonDatabase`, `CacheEntity`, `BaseDao`, and `DatabaseModule`
  explaining the cache-not-source-of-truth contract and the
  set-`updatedAt`-on-upsert rule for downstream AND-116/AND-118.
- No new lint/detekt regressions; DAO threading verified by StrictMode in debug.
- Downstream owners (AND-116, AND-118) confirm the exposed surface
  (`BaseDao`, `CacheEntity.updatedAt`, `clear()`, database singleton) is
  sufficient to build SWR and TTL/eviction without changes to this layer.

## 16. Citations & Assumption Audit

This ticket is **infrastructure-only** (local Room persistence). It introduces
no REST endpoints, so there are no OpenAPI endpoint/method/field claims to
verify against `openapi.index.txt` / `openapi.pretty.json`. The §5 statement
"N/A — no network calls" is therefore **Verified** (a grep of the OpenAPI index
for `room`/`cache`/`database` returns only an unrelated `POST
/ui/geo/clear-cache` op, confirming no persistence endpoints exist for this
work). The audit below covers the spec's cross-cutting claims about web-app
behavior and the Android framework choices.

1. **Claim:** The web client sends CSRF as the `ui_csrf` cookie value in an
   `X-CSRF-Token` request header, and `ui_csrf` is the CSRF token (§6, §8).
   **VERDICT: Verified.**
   **Source:** frontend `src/api/client.ts` (`const csrf = getCookie("ui_csrf"); headers.set("X-CSRF-Token", csrf)`, lines ~167-170; `credentials: "include"`). Corroborated by `src/stores/offlineStore.ts: getCsrfFromCookie` and `src/api/endpoints/kycCompliance.ts`.

2. **Claim:** Auth/CSRF/session state belongs outside Room (in the OkHttp
   cookie jar / DataStore), and no secrets are written to Room (§6, §8, AC-7).
   **VERDICT: Verified (design decision, consistent with web contract).**
   **Source:** Web uses cookie-based session + `ui_csrf` cookie (`src/api/client.ts: credentials:"include"`); cookies are transport-layer auth, correctly mapped to OkHttp's cookie jar on Android rather than an app cache table. No source contradicts the no-secrets-in-Room rule.

3. **Claim (CORRECTED):** "The web app has no persistence layer beyond the
   browser; no 1:1 web equivalent exists" (§2, original draft).
   **VERDICT: Corrected.** The web app has a structured IndexedDB cache that is
   a direct conceptual analog of this Room cache.
   **Source:** `src/lib/syncQueueDb.ts` (IndexedDB DB `app-offline-cache`, stores `api_cache` with indexes `cachedAt`/`endpoint`/`userId`/`userId_endpoint`, plus `api_cache_meta` and `sync_queue`); `src/lib/offlineCacheConfig.ts` (`CACHE_TTL_CONFIG`, `MAX_ENTRIES_PER_ENDPOINT`, `DEFAULT_TTL`, `classifyEndpoint`); `src/lib/offlineCache.ts`, `src/lib/withOfflineCache.ts`, `src/components/shared/StalenessIndicator.tsx`.

4. **Claim:** `cachedAt`/`updatedAt`-style timestamps drive cache freshness;
   per-entity `updatedAt` is the column AND-118 reads for TTL (§3 FR-3, §6).
   **VERDICT: Verified by analogy to the web contract.**
   **Source:** `src/lib/offlineCacheConfig.ts: getTtlForEndpoint` + the `cachedAt` index in `src/lib/syncQueueDb.ts: openSyncDb`. The web TTL model (seconds-since-`cachedAt`) maps to Room `updatedAt` epoch-millis; the Android-side TTL/eviction implementation itself is AND-118 scope.

5. **Claim:** Room `@Upsert` provides insert-or-update without per-DAO conflict
   strategy (§4.2). **VERDICT: Verified (framework ref).**
   **Source:** framework ref — Android Room docs, `androidx.room.Upsert` (added in Room 2.5; available in pinned Room 2.6). https://developer.android.com/reference/androidx/room/Upsert

6. **Claim:** Room schemas are exported via the KSP arg
   `room.schemaLocation` and `exportSchema = true` writes
   `schemas/<db>/<version>.json` (§4.1, §4.6, AC-5).
   **VERDICT: Verified (framework ref).**
   **Source:** framework ref — "Migrating Room databases" / schema export. https://developer.android.com/training/data-storage/room/migrating-db-versions#export-schemas

7. **Claim:** `fallbackToDestructiveMigration()` exists on
   `RoomDatabase.Builder` and may be gated by `BuildConfig.DEBUG` (§4.5, §4.6,
   AC-6). **VERDICT: Verified (framework ref).** Note: the no-arg
   `fallbackToDestructiveMigration()` is valid in Room 2.6 (it is deprecated in
   favor of the `dropAllTables`-parameterized overload only in Room 2.7+, which
   is newer than the pinned 2.6 — no change needed for this ticket).
   **Source:** framework ref — `RoomDatabase.Builder.fallbackToDestructiveMigration`. https://developer.android.com/reference/androidx/room/RoomDatabase.Builder

8. **Claim:** Room read methods returning `Flow<T>` emit on table changes;
   `suspend` writes run off the main thread on Room's executor (§3 FR-7, §6).
   **VERDICT: Verified (framework ref).**
   **Source:** framework ref — "Write asynchronous DAO queries" (Flow + coroutines). https://developer.android.com/training/data-storage/room/async-queries

9. **Claim:** `MigrationTestHelper` + `Room.inMemoryDatabaseBuilder(...)
   .allowMainThreadQueries()` are the supported instrumented test primitives
   (§11). **VERDICT: Verified (framework ref).**
   **Source:** framework ref — "Test and debug your Room database". https://developer.android.com/training/data-storage/room/testing-db

10. **Claim:** Room's default journal mode is WAL and default `onCorruption`
    recreates the database file (§6, §7). **VERDICT: Verified (framework ref),
    with a residual open question.**
    **Source:** framework ref — `RoomDatabase.JournalMode.AUTOMATIC` resolves to WAL on API ≥ 16 with sufficient memory; Room installs a default corruption handler that deletes+recreates. https://developer.android.com/reference/androidx/room/RoomDatabase.JournalMode — the API-24-specific WAL behavior remains tracked as OQ3.

11. **Claim:** Stack pins — Room 2.6, KSP, Kotlin 2.0.21, JDK 17, minSdk 24,
    compile/targetSdk 35, AGP 8.7.3, Gradle 8.9 (§2). **VERDICT:
    Unverified-assumption (inherited from AND-003).** Not independently
    confirmable from the OpenAPI or frontend sources; treated as a project-wide
    pin owned by AND-003. Compatibility (AGP 8.7.3 ↔ KSP ↔ Kotlin 2.0.21) is a
    standard, plausible combination but should be confirmed against the actual
    `core-data/build.gradle.kts` / version catalog when AND-003 lands.

### Corrections made

- **§2 Web reference (Citation 3):** Replaced the inaccurate "the web app has
  no persistence layer beyond the browser / no 1:1 web equivalent exists" with
  the verified fact that the web client has a structured IndexedDB offline cache
  (`api_cache`/`api_cache_meta`/`sync_queue` in `app-offline-cache`) with per-
  endpoint TTL + max-entries eviction — the direct conceptual analog of this
  Room cache and the model AND-116 (SWR) / AND-118 (TTL/eviction) should mirror.
  No other concrete factual errors were found; the framework-level claims in
  §4/§6/§7/§11 verify correctly against Android Room/Hilt documentation.

### Open assumptions

- **OA-1 (Citation 11):** Exact version pins (Room 2.6, AGP 8.7.3, KSP, Kotlin
  2.0.21, Gradle 8.9) are inherited from AND-003 and cannot be verified from the
  provided OpenAPI/frontend sources; confirm against the version catalog once
  AND-003 lands.
- **OA-2 (Citation 10 / OQ3):** WAL journal-mode behavior on API 24 emulators
  is assumed fine but not verified on the API 24 CI runner; tracked as §13 OQ3
  and exercised by TC-AND-115-09.
- **OA-3:** SQLCipher at-rest encryption need (§13 OQ1) is deferred to a future
  feature ticket that caches PII; no source mandates encryption for the current
  non-PII sample cache.
- **OA-4:** The Hilt singleton/`@Singleton` scoping behavior (§4.5) is a
  standard Dagger-Hilt pattern; assumed correct and validated behaviorally by
  TC-AND-115-05 rather than against an external source.

## 17. Test Plan

Test target legend: **JVM** = JVM unit/Robolectric (local, no device);
**EMU** = headless emulator AVD `test35` (x86_64, Android 15 / API 35);
**EMU24** = emulator at API 24 (CI matrix low end, per §11); **DEVICE** =
physical Samsung Galaxy A15 5G (SM-A156U, API 34, arm64-v8a). Room DB code is
JVM-portable only via Robolectric; true DB behavior requires an Android runtime,
so most cases are instrumented on EMU. None of this ticket's behavior is
hardware-dependent (no camera/biometrics/WebRTC/FCM), so the **physical device
is used only for the arm64 / API-34 ABI-and-API differential check** (TC-10);
all other instrumented cases run fastest on the KVM-accelerated EMU.

- **TC-AND-115-01 — Sample entity round-trip (happy path).**
  Type: instrumented (androidTest). Target: EMU.
  Preconditions: `TestLogonDatabase` built via `Room.inMemoryDatabaseBuilder(...).allowMainThreadQueries()`; `SampleDao` obtained.
  Steps: 1) `dao.upsert(CachedSampleEntity("k1","hello",42L))`. 2) Collect first emission of `dao.getById("k1")`.
  Expected: emitted row `== CachedSampleEntity("k1","hello",42L)` (full structural equality, incl. `updatedAt`).
  Traces: AC-3, AC-2.

- **TC-AND-115-02 — Upsert updates existing row (no duplicate insert).**
  Type: instrumented. Target: EMU.
  Preconditions: in-memory DB + DAO as TC-01.
  Steps: 1) `upsert(("k1","v1",1L))`. 2) `upsert(("k1","v2",2L))`. 3) Read `getById("k1")`; also `observeAll().first()`.
  Expected: single row with `payload=="v2"`, `updatedAt==2L`; `observeAll()` size == 1 (proves `@Upsert` replaces, not duplicates, on same PK).
  Traces: AC-2, AC-3.

- **TC-AND-115-03 — `clear()` empties the table (teardown primitive).**
  Type: instrumented. Target: EMU.
  Preconditions: in-memory DB seeded with ≥1 row.
  Steps: 1) `upsert(("k1","v",1L))`. 2) `clear()`. 3) `observeAll().first()`.
  Expected: empty list. Confirms the `clear()` primitive AND-118 relies on for per-user cache wipe.
  Traces: AC-2 (`clear()` surface), supports DoD downstream-surface item.

- **TC-AND-115-04 — `Flow` reactivity on table change.**
  Type: instrumented. Target: EMU.
  Preconditions: in-memory DB + DAO; an active collector on `dao.observeAll()`.
  Steps: 1) Start collecting `observeAll()`. 2) `upsert(("k1","a",1L))`. 3) `upsert(("k2","b",2L))`. 4) `clear()`.
  Expected: collector receives successive emissions reflecting [], [k1], [k1,k2], [] (Room re-emits on every table mutation without manual invalidation).
  Traces: AC-2, AC-3 (validates FR-7 reactivity).

- **TC-AND-115-05 — Hilt provisions DB + DAO as singletons.**
  Type: instrumented (Hilt test, `@HiltAndroidTest`). Target: EMU.
  Preconditions: Hilt test component installs `DatabaseModule`; two injection points request `TestLogonDatabase` and `SampleDao`.
  Steps: 1) Inject `TestLogonDatabase` twice. 2) Inject `SampleDao` and `db.sampleDao()`.
  Expected: both `TestLogonDatabase` references are the *same* instance (singleton); `SampleDao` injects non-null and is backed by the same DB.
  Traces: AC-4.

- **TC-AND-115-06 — Schema JSON exported & committed (CI gate).**
  Type: integration (CI/Gradle). Target: JVM/CI host.
  Preconditions: `ksp { arg("room.schemaLocation", "$projectDir/schemas") }` configured; clean git tree.
  Steps: 1) Run `:core-data:compileDebugAndroidTestSources` (or assemble). 2) Run `git status --porcelain schemas/`.
  Expected: `schemas/<db>/1.json` exists after build; `git status` on `schemas/` is clean (no uncommitted diff). A deliberately-bumped uncommitted schema makes this step FAIL.
  Traces: AC-5, AC-1.

- **TC-AND-115-07 — Release build does NOT enable destructive fallback; debug does.**
  Type: instrumented + build-variant inspection. Target: EMU (run per variant).
  Preconditions: app/library built once as debug, once as release.
  Steps: 1) Inspect `DatabaseModule.provideDatabase` path under `BuildConfig.DEBUG==false`: confirm `fallbackToDestructiveMigration()` is NOT applied. 2) Behavioral check: open a v2 store file against the v1 schema with no migration registered — release build throws `IllegalStateException`; debug build recreates the DB instead.
  Expected: release → migration exception (no silent data loss); debug → destructive recreate succeeds.
  Traces: AC-6, plus §7 migration-failure behavior.

- **TC-AND-115-08 — Migration harness ready (baseline v1, forward-migration scaffold).**
  Type: instrumented (`MigrationTestHelper`). Target: EMU.
  Preconditions: `MigrationTestHelper` wired to the exported `schemas/` dir; v1 baseline present.
  Steps: 1) `helper.createDatabase(NAME, 1)`, insert a row via raw SQL, close. 2) (Scaffold) assert that `runMigrationsAndValidate` is callable for a future `(1→2)` migration; for v1-only, assert the DB opens and validates against `1.json`.
  Expected: v1 DB opens and validates against committed schema; harness is exercisable so the first real migration is testable without new wiring.
  Traces: AC-5, supports R1 mitigation (§13).

- **TC-AND-115-09 — Persistence + WAL across DB reopen on API 24 (low-end matrix).**
  Type: instrumented. Target: EMU24 (API 24 runner per §11).
  Preconditions: file-backed (NOT in-memory) `TestLogonDatabase` via `databaseBuilder` with default journal mode.
  Steps: 1) Open DB, `upsert(("k1","persist",1L))`, close. 2) Reopen DB, `getById("k1").first()`.
  Expected: row survives close/reopen; no WAL-related open failure on API 24. Resolves §13 OQ3 / OA-2.
  Traces: AC-3, AC-1 (CI matrix API 24).

- **TC-AND-115-10 — arm64 / API 34 differential round-trip (real hardware).**
  Type: instrumented/e2e. Target: **DEVICE (must run on physical SM-A156U)**.
  Rationale: confirms the Room/SQLite native layer round-trips identically on arm64-v8a / API 34 vs the x86_64 / API 35 emulator (ABI + API-level differential called out as device-only).
  Preconditions: app installed on device via adb (serial R5CX821TA9R).
  Steps: 1) Run the TC-01/TC-02/TC-09 suite as an on-device instrumented run. 2) Compare results to EMU/EMU24 runs.
  Expected: identical pass results and equal round-tripped values across arm64/API34 and x86_64/API35 — no ABI- or API-level divergence.
  Traces: AC-1, AC-3.

- **TC-AND-115-11 — No secrets/CSRF written to Room (security).**
  Type: unit/static (code-review-backed) + instrumented assertion. Target: JVM + EMU.
  Preconditions: schema `1.json`; entity set = `{CachedSampleEntity}`.
  Steps: 1) Static: assert no `@Entity`/`@ColumnInfo` field name matches `ui_csrf|csrf|cookie|token|password|secret` across `core-data`. 2) Behavioral: dump `cached_sample` columns and assert only `id`, `payload`, `updated_at` exist.
  Expected: no auth/CSRF/secret columns present; cache holds only `id/payload/updated_at`. Enforces the §8 / AC-7 no-secrets rule (web stores CSRF only in the `ui_csrf` cookie, never in `api_cache` — see Citation 1/3).
  Traces: AC-7.

- **TC-AND-115-12 — SQLiteException propagates cleanly (resilience, no main-thread crash).**
  Type: instrumented. Target: EMU.
  Preconditions: in-memory DB; a constraint or forced failure path (e.g. insert into a closed DB / simulated write failure).
  Steps: 1) Close DB. 2) Call a `suspend` DAO write and `runCatching` it.
  Expected: the call throws an `SQLiteException`/`IllegalStateException` that surfaces as a coroutine result (propagates to caller for AND-116 to catch) rather than crashing on the main thread.
  Traces: AC-3 (implicit), supports §7 disk-full/write-failure contract.

- **TC-AND-115-13 — Build compiles with Room + KSP on JDK 17 / AGP 8.7.3.**
  Type: integration (CI/Gradle). Target: JVM/CI host.
  Preconditions: pinned toolchain (JDK 17, AGP 8.7.3, KSP, Kotlin 2.0.21).
  Steps: 1) `:core-data:assemble`. 2) `:core-data:compileDebugAndroidTestSources`.
  Expected: both succeed; KSP (not kapt) generates Room + Hilt code; no annotation-processor errors.
  Traces: AC-1.

Accessibility note: AND-115 has **no UI surface** (§9). There is no Compose
screen, string, or user-visible text, so no Compose-UI / TalkBack / contrast
accessibility cases apply to this ticket; accessibility is owned by the feature
tickets that render cached data. (This absence is itself asserted by code review,
not a test case.)

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
| --- | --- |
| AC-1 (Room+KSP compiles; assemble + androidTest sources on JDK17/AGP8.7.3) | TC-13, TC-06, TC-09, TC-10 |
| AC-2 (`TestLogonDatabase` v1 + `CacheEntity`/`BaseDao`/sample contracts) | TC-01, TC-02, TC-03, TC-04 |
| AC-3 (instrumented `upsert_then_read_round_trips` passes) | TC-01, TC-02, TC-09, TC-10, TC-12 |
| AC-4 (DB + `SampleDao` injectable Hilt singletons) | TC-05 |
| AC-5 (schema `1.json` committed; CI fails on uncommitted schema) | TC-06, TC-08 |
| AC-6 (release no destructive fallback; debug yes) | TC-07 |
| AC-7 (no auth/CSRF/secret written to Room) | TC-11 |
