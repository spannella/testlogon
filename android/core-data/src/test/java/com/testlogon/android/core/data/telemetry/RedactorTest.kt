package com.testlogon.android.core.data.telemetry

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RedactorTest {

    private val redactor = Redactor("test-salt".toByteArray())

    @Test
    fun deniedKeys_areDropped() {
        val line = redactor.line(
            listOf(
                "stage" to "LOGIN",
                "password" to "hunter2",
                "totp_code" to "123456",
                "authorization" to "Bearer abc",
            ),
        )
        assertTrue(line.contains("stage=LOGIN"))
        assertFalse(line.contains("hunter2"))
        assertFalse(line.contains("123456"))
        assertFalse(line.contains("Bearer"))
    }

    @Test
    fun secretShapedValues_areMasked() {
        // A 6-digit code that slips into an allowed key is still masked by the value scrubber.
        val scrubbed = redactor.scrub("otp is 482913 ok")
        assertFalse(scrubbed.contains("482913"))
        assertTrue(scrubbed.contains(Redactor.MASK))
    }

    @Test
    fun jwtLikeValue_isMasked() {
        val jwt = "eyJhbGciOi.eyJzdWIiOiAx.SflKxwRJSMeKKF2"
        assertFalse(redactor.scrub(jwt).contains("SflKxwRJSMeKKF2"))
    }

    @Test
    fun shortHash_isDeterministicWithinSalt_andNotRaw() {
        val id = "challenge-abc-123"
        assertEquals(redactor.shortHash(id), redactor.shortHash(id))
        assertNotEquals(id, redactor.shortHash(id))
        assertEquals(4, redactor.shortHash(id).length)
    }

    @Test
    fun differentSalts_produceDifferentHashes() {
        val other = Redactor("other-salt".toByteArray())
        assertNotEquals(redactor.shortHash("x"), other.shortHash("x"))
    }
}
