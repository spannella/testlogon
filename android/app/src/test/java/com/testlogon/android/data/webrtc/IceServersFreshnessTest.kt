package com.testlogon.android.data.webrtc

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-294 — pure [IceServers.isFreshAt] TTL/skew freshness logic, filling a gap left by
 * [IceServersMappingTest] (DTO->domain) and [IceServersRepositoryTest] (cache/network). No network, no SDK.
 */
class IceServersFreshnessTest {

    private fun servers(expiresAtMs: Long) = IceServers(
        servers = listOf(IceServer(urls = listOf("stun:stun.example:3478"))),
        ttlSeconds = 600,
        expiresAtEpochMs = expiresAtMs,
        fetchedAtEpochMs = 0,
    )

    @Test
    fun fresh_whenMoreThanSkewRemains() {
        val expires = 1_000_000L
        // now is well before expiry minus 60s skew.
        assertTrue(servers(expires).isFreshAt(nowMs = expires - 120_000L, skewSeconds = 60))
    }

    @Test
    fun stale_withinSkewWindow() {
        val expires = 1_000_000L
        // now is inside the 60s skew window before expiry -> not fresh.
        assertFalse(servers(expires).isFreshAt(nowMs = expires - 30_000L, skewSeconds = 60))
    }

    @Test
    fun stale_afterExpiry() {
        val expires = 1_000_000L
        assertFalse(servers(expires).isFreshAt(nowMs = expires + 1L, skewSeconds = 0))
    }
}
