package com.testlogon.android.core.data.cache

import androidx.room.Dao
import androidx.room.RawQuery
import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.sqlite.db.SupportSQLiteQuery

/**
 * AND-118 — generic cache maintenance keyed by table name.
 *
 * One DAO parameterized via `@RawQuery`/[SupportSQLiteQuery] avoids per-entity boilerplate. The
 * `$table` interpolation is restricted to the [CacheTables.ALL] allowlist (every public helper
 * calls [CacheTables.require] first); all variable inputs are BOUND parameters, never concatenated.
 */
@Dao
abstract class CacheMaintenanceDao {
    @RawQuery
    abstract suspend fun execDelete(query: SupportSQLiteQuery): Int

    @RawQuery
    abstract suspend fun execCount(query: SupportSQLiteQuery): Long

    /** Number of rows currently in [table]. */
    suspend fun count(table: String): Long {
        CacheTables.require(table)
        return execCount(SimpleSQLiteQuery("SELECT COUNT(*) FROM $table"))
    }

    /** Bumps `last_accessed_at` for an LRU read hit. */
    suspend fun touch(table: String, cacheKey: String, now: Long): Int {
        CacheTables.require(table)
        return execDelete(
            SimpleSQLiteQuery(
                "UPDATE $table SET last_accessed_at = ? WHERE cache_key = ?",
                arrayOf(now, cacheKey),
            ),
        )
    }

    /** Deletes rows whose `fetched_at` is older than [expiryCutoff] (TTL sweep). */
    suspend fun deleteExpired(table: String, expiryCutoff: Long): Int {
        CacheTables.require(table)
        return execDelete(
            SimpleSQLiteQuery(
                "DELETE FROM $table WHERE fetched_at < ?",
                arrayOf(expiryCutoff),
            ),
        )
    }

    /** Deletes all rows owned by [userId]. */
    suspend fun deleteUserScoped(table: String, userId: String): Int {
        CacheTables.require(table)
        return execDelete(
            SimpleSQLiteQuery(
                "DELETE FROM $table WHERE user_scope = ?",
                arrayOf(userId),
            ),
        )
    }

    /** Deletes every user-scoped row (keeps global `user_scope IS NULL` rows). */
    suspend fun deleteAllUserScoped(table: String): Int {
        CacheTables.require(table)
        return execDelete(SimpleSQLiteQuery("DELETE FROM $table WHERE user_scope IS NOT NULL"))
    }

    /** LRU eviction: keep the [keep] most-recently-accessed rows, delete the rest. */
    suspend fun evictOverLimit(table: String, keep: Int): Int {
        CacheTables.require(table)
        return execDelete(
            SimpleSQLiteQuery(
                "DELETE FROM $table WHERE rowid NOT IN " +
                    "(SELECT rowid FROM $table ORDER BY last_accessed_at DESC LIMIT ?)",
                arrayOf(keep),
            ),
        )
    }
}
