package com.testlogon.android.core.data.cache

/**
 * AND-118 — compile-time allowlist of cacheable table names.
 *
 * SECURITY: the maintenance DAO interpolates `$table` into raw SQL (Room cannot bind an identifier).
 * Only names in [ALL] are ever interpolated; all variable inputs (userId, cutoffs, limits) are
 * bound parameters. [require] rejects any table not in the allowlist BEFORE any SQL executes,
 * preventing SQL injection through the raw-query path.
 */
object CacheTables {
    const val SAMPLE = "cached_sample"

    /** Every table that carries the AND-118 metadata columns. New cache tables MUST be added here. */
    val ALL: List<String> = listOf(SAMPLE)

    /** Throws [IllegalArgumentException] if [table] is not an allowlisted cache table. */
    fun require(table: String): String {
        require(table in ALL) { "Unknown cache table: '$table' is not in CacheTables.ALL" }
        return table
    }
}
