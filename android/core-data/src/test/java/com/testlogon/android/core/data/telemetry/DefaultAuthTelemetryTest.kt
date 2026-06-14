package com.testlogon.android.core.data.telemetry

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DefaultAuthTelemetryTest {

    private fun telemetry(): DefaultAuthTelemetry =
        // debug=false avoids the Android Log class entirely in JVM unit tests.
        DefaultAuthTelemetry(
            redactor = Redactor("salt".toByteArray()),
            debug = false,
            clock = { 0L },
        )

    @Test
    fun secretsCanary_neverLeakIntoRecords() {
        val t = telemetry()
        t.log(AuthEvent.LoginAttempt(userPresent = true))
        t.log(AuthEvent.MfaVerifyAttempt(AuthFactor.TOTP, challengeId = "secret-challenge-id-9999"))
        t.log(AuthEvent.MfaFailure(AuthFactor.SMS, AuthFailureReason.MFA_REJECTED, remainingFactors = 1, httpStatus = 401))

        val joined = t.snapshot().joinToString("\n") { it.line }
        // No raw challenge id, no codes; correlation token + presence flag are present.
        assertFalse(joined.contains("secret-challenge-id-9999"))
        assertTrue(joined.contains("cref="))
        assertTrue(joined.contains("userPresent=true"))
    }

    @Test
    fun ringBuffer_capsAtCapacity_oldestEvicted() {
        val t = telemetry()
        repeat(DefaultAuthTelemetry.RING_CAPACITY + 50) {
            t.log(AuthEvent.LoginAttempt(userPresent = false))
        }
        assertEquals(DefaultAuthTelemetry.RING_CAPACITY, t.snapshot().size)
    }

    @Test
    fun snapshot_isImmutableCopy() {
        val t = telemetry()
        t.log(AuthEvent.LoginAttempt(userPresent = true))
        val first = t.snapshot()
        t.log(AuthEvent.LoginAttempt(userPresent = false))
        // The earlier snapshot is not mutated by later logging.
        assertEquals(1, first.size)
    }

    @Test
    fun log_neverThrows_evenWhenSinkThrows() {
        val throwingSink = TelemetryLogSink { _, _, _ -> error("boom") }
        val t = DefaultAuthTelemetry(
            redactor = Redactor("salt".toByteArray()),
            debug = true,
            clock = { 0L },
            logSink = throwingSink,
        )
        // Must not propagate; record still lands in the ring buffer.
        t.log(AuthEvent.LoginSuccess(requiredFactors = emptyList()))
        assertEquals(1, t.snapshot().size)
    }
}
