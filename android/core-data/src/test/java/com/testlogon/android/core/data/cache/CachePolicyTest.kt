package com.testlogon.android.core.data.cache

import org.junit.Assert.assertEquals
import org.junit.Test
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes

/**
 * AND-118 / AND-119 — JVM unit tests for the pure TTL freshness policy. Time is supplied explicitly
 * (no real clock, no Thread.sleep), so the FRESH/STALE/EXPIRED decision is fully deterministic.
 */
class CachePolicyTest {

    private val policy = CachePolicy(ttl = 100.milliseconds, staleAfter = 50.milliseconds)

    @Test
    fun `age below staleAfter is FRESH`() {
        // age = 49 < staleAfter(50)
        assertEquals(Freshness.FRESH, policy.freshness(fetchedAt = 951, now = 1_000))
    }

    @Test
    fun `age at staleAfter is STALE`() {
        // age = 50 == staleAfter -> not < staleAfter, but < ttl -> STALE
        assertEquals(Freshness.STALE, policy.freshness(fetchedAt = 950, now = 1_000))
    }

    @Test
    fun `age between staleAfter and ttl is STALE`() {
        // age = 75
        assertEquals(Freshness.STALE, policy.freshness(fetchedAt = 925, now = 1_000))
    }

    @Test
    fun `age at ttl is EXPIRED`() {
        // age = 100 == ttl -> EXPIRED (exclusive upper bound of STALE)
        assertEquals(Freshness.EXPIRED, policy.freshness(fetchedAt = 900, now = 1_000))
    }

    @Test
    fun `age above ttl is EXPIRED`() {
        assertEquals(Freshness.EXPIRED, policy.freshness(fetchedAt = 500, now = 1_000))
    }

    @Test
    fun `negative age from backward clock is FRESH (fail-safe)`() {
        // now < fetchedAt -> negative age must not crash, classified FRESH.
        assertEquals(Freshness.FRESH, policy.freshness(fetchedAt = 2_000, now = 1_000))
    }

    @Test
    fun `default staleAfter equals ttl - empty STALE band`() {
        val p = CachePolicy(ttl = 100.milliseconds)
        assertEquals(Freshness.FRESH, p.freshness(fetchedAt = 950, now = 1_000)) // age 50 < 100
        assertEquals(Freshness.EXPIRED, p.freshness(fetchedAt = 900, now = 1_000)) // age 100 == ttl
    }

    @Test
    fun `policy registry falls back to DEFAULT for unknown table`() {
        assertEquals(CachePolicies.DEFAULT, CachePolicies.forTable("does_not_exist"))
        assertEquals(15.minutes, CachePolicies.DEFAULT.ttl)
    }

    @Test
    fun `registry returns a policy for the sample table`() {
        // cached_sample is allowlisted; must resolve to a non-null policy.
        assertEquals(CachePolicies.DEFAULT, CachePolicies.forTable(CacheTables.SAMPLE))
    }
}
