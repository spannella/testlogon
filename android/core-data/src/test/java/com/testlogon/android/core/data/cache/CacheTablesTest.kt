package com.testlogon.android.core.data.cache

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * AND-118 / AND-119 — the raw-query table allowlist rejects unknown / injection table names BEFORE
 * any SQL runs (security guard for the @RawQuery maintenance path).
 */
class CacheTablesTest {

    @Test
    fun `allowlisted table passes`() {
        assertEquals("cached_sample", CacheTables.require(CacheTables.SAMPLE))
    }

    @Test
    fun `unknown table is rejected`() {
        assertThrows(IllegalArgumentException::class.java) {
            CacheTables.require("feed; DROP TABLE auth")
        }
    }

    @Test
    fun `empty table name is rejected`() {
        assertThrows(IllegalArgumentException::class.java) {
            CacheTables.require("")
        }
    }

    @Test
    fun `ALL contains the sample table`() {
        assert(CacheTables.SAMPLE in CacheTables.ALL)
    }
}
