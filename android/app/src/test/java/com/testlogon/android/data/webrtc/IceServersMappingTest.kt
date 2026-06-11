package com.testlogon.android.data.webrtc

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-291 — pure DTO->domain mapping + redaction-summary tests (no network). Asserts every transport URL
 * is preserved, ttl/expiry carry through, and the redacted summary never contains the username/credential.
 */
class IceServersMappingTest {

    private val dto = TurnCredentialsDto(
        iceServers = listOf(
            TurnIceServerDto(
                urls = listOf(
                    "turn:turn.testlogon.example:3478?transport=udp",
                    "turn:turn.testlogon.example:3478?transport=tcp",
                    "turns:turn.testlogon.example:5349?transport=tcp",
                ),
                username = "1717603200:tl-ephemeral",
                credential = "b64-hmac-secret==",
            ),
            TurnIceServerDto(
                urls = listOf("stun:stun.testlogon.example:3478"),
                username = "u2",
                credential = "c2",
            ),
        ),
        ttlSeconds = 600,
        expiresAtEpochSeconds = 1_717_603_800L,
    )

    @Test
    fun toDomain_preservesUrlsTtlExpiry() {
        val now = 1_700_000_000_000L
        val domain = dto.toDomain(nowMs = now, defaultTtlSec = 300)
        assertEquals(600L, domain.ttlSeconds)
        assertEquals(1_717_603_800L * 1_000L, domain.expiresAtEpochMs)
        assertEquals(now, domain.fetchedAtEpochMs)
        assertEquals(2, domain.servers.size)
        assertEquals(3, domain.servers.first().urls.size)
        assertEquals("b64-hmac-secret==", domain.servers.first().credential)
    }

    @Test
    fun toDomain_usesDefaultTtl_whenBackendOmits() {
        val now = 1_700_000_000_000L
        val bare = dto.copy(ttlSeconds = 0, expiresAtEpochSeconds = 0)
        val domain = bare.toDomain(nowMs = now, defaultTtlSec = 300)
        assertEquals(300L, domain.ttlSeconds)
        assertEquals(now + 300L * 1_000L, domain.expiresAtEpochMs)
    }

    @Test
    fun redactedSummary_neverLeaksCredentials() {
        val domain = dto.toDomain(nowMs = 0, defaultTtlSec = 300)
        val summary = domain.redactedSummary()
        assertFalse(summary.contains("b64-hmac-secret=="))
        assertFalse(summary.contains("1717603200:tl-ephemeral"))
        // It still reports useful, non-secret info.
        assertTrue(summary.contains("ttl=600s"))
        assertTrue(summary.contains("turn"))
        assertTrue(summary.contains("stun"))
    }
}
