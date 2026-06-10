package com.testlogon.android.core.data.db

import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import com.testlogon.android.core.data.cache.CacheMaintenanceDao
import com.testlogon.android.core.data.cache.CacheTables
import com.testlogon.android.core.data.db.sample.CachedSampleEntity
import com.testlogon.android.core.data.db.sample.SampleDao
import com.testlogon.android.core.data.feed.BookmarkStateDao
import com.testlogon.android.core.data.feed.BookmarkStateEntity
import com.testlogon.android.core.data.feed.PostSuppressionDao
import com.testlogon.android.core.data.feed.PostSuppressionEntity
import com.testlogon.android.core.data.paywall.EntitlementDao
import com.testlogon.android.core.data.paywall.EntitlementEntity

/**
 * AND-115 — the app-wide on-device cache store.
 *
 * This database is a **non-authoritative** cache: the FastAPI backend is the source of truth.
 * Rows hold already-fetched, user-visible content so the app can render last-known data while the
 * unreliable dev host is slow/offline. Auth cookies, the bearer token, and `ui_csrf` are NEVER
 * stored here (they live in the OkHttp cookie jar / DataStore).
 *
 * Migration strategy (AND-115 / extended by AND-118):
 * - `exportSchema = true` writes schemas/<db-class>/<version>.json to version control.
 * - Every schema-changing change bumps [version], adds a [Migration] to [ALL_MIGRATIONS], and
 *   commits the new schema JSON.
 * - Release builds NEVER use destructive fallback; debug builds may (see DatabaseModule). Cache
 *   data is reconstructable from the network, so a destructive recovery path is acceptable as a
 *   last resort, but real migrations are preferred.
 *
 * Version history:
 * - v1 — AND-115 baseline: [CachedSampleEntity] with id/payload/updated_at.
 * - v2 — AND-118: adds fetched_at, last_accessed_at, user_scope, approx_bytes + LRU/user indices.
 * - v3 — AND-175: adds the post_suppression table (hide / not-interested durable set).
 * - v4 — AND-176/AND-177: adds the bookmark_state table (feed bookmark toggle) and the entitlement
 *        table (paywall unlock entitlements, keyed by user_sub+post_id).
 */
@Database(
    entities = [
        CachedSampleEntity::class,
        PostSuppressionEntity::class,
        BookmarkStateEntity::class,
        EntitlementEntity::class,
    ],
    version = 4,
    exportSchema = true,
)
abstract class TestLogonDatabase : RoomDatabase() {
    abstract fun sampleDao(): SampleDao

    /** AND-118 — generic, table-name-parameterized maintenance surface (sweep/evict/per-user clear). */
    abstract fun cacheMaintenanceDao(): CacheMaintenanceDao

    /** AND-175 — hide / not-interested durable suppression set. */
    abstract fun postSuppressionDao(): PostSuppressionDao

    /** AND-176 — feed bookmark toggle durable state. */
    abstract fun bookmarkStateDao(): BookmarkStateDao

    /** AND-177 — paywall unlock entitlements (per user_sub). */
    abstract fun entitlementDao(): EntitlementDao

    companion object {
        const val NAME = "testlogon-cache.db"

        /**
         * AND-118 — additive migration adding the cache-lifecycle metadata columns + indices to
         * every cacheable table in [CacheTables.ALL]. Pre-existing rows get fetched_at = 0 so they
         * classify as EXPIRED on next read (safe: they refetch).
         */
        val MIGRATION_1_2: Migration = object : Migration(1, 2) {
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

        /**
         * AND-175 — additive migration creating the post_suppression table. Purely additive (a new
         * table), so no existing rows are touched.
         */
        val MIGRATION_2_3: Migration = object : Migration(2, 3) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS post_suppression (" +
                        "post_id TEXT NOT NULL PRIMARY KEY, " +
                        "kind TEXT NOT NULL, " +
                        "created_at_epoch_ms INTEGER NOT NULL, " +
                        "pending INTEGER NOT NULL)",
                )
            }
        }

        /**
         * AND-176 / AND-177 — additive migration creating the bookmark_state and entitlement tables.
         * Purely additive (two new tables), so no existing rows are touched.
         */
        val MIGRATION_3_4: Migration = object : Migration(3, 4) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS bookmark_state (" +
                        "content_type TEXT NOT NULL, " +
                        "content_id TEXT NOT NULL, " +
                        "collection_id TEXT, " +
                        "created_at_epoch_ms INTEGER NOT NULL, " +
                        "pending INTEGER NOT NULL, " +
                        "PRIMARY KEY(content_type, content_id))",
                )
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS entitlement (" +
                        "user_sub TEXT NOT NULL, " +
                        "post_id TEXT NOT NULL, " +
                        "unlocked_at_epoch_ms INTEGER NOT NULL, " +
                        "source TEXT NOT NULL, " +
                        "PRIMARY KEY(user_sub, post_id))",
                )
            }
        }

        /** Registered migrations; grows as the schema evolves. */
        val ALL_MIGRATIONS: Array<Migration> = arrayOf(MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4)
    }
}
