package com.testlogon.android.data.auth

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Coverage for [RegisterConfirmResp.toMfaSetupHandoff] (AND-056). */
class RegisterDomainTest {

    private fun resp(mfa: List<String>?, smsPhone: String? = null) =
        RegisterConfirmResp(status = "confirmed", sessionId = "s1", mfaSetup = mfa, smsPhone = smsPhone)

    @Test
    fun nullOrEmptyMfa_isNotRequired() {
        assertFalse(resp(null).toMfaSetupHandoff("u@x.com").isRequired)
        assertFalse(resp(emptyList()).toMfaSetupHandoff("u@x.com").isRequired)
    }

    @Test
    fun totp_mapsToTotpFactor() {
        val h = resp(listOf("totp")).toMfaSetupHandoff("u@x.com")
        assertEquals(listOf(MfaSetupFactor.Totp), h.factors)
        assertTrue(h.isRequired)
    }

    @Test
    fun sms_withPhone_carriesPhone_blankNormalisedToNull() {
        val withPhone = resp(listOf("sms"), smsPhone = "+15551234567").toMfaSetupHandoff("u@x.com")
        assertEquals(listOf(MfaSetupFactor.Sms), withPhone.factors)
        assertEquals("+15551234567", withPhone.smsPhone)

        val blank = resp(listOf("sms"), smsPhone = "   ").toMfaSetupHandoff("u@x.com")
        assertNull(blank.smsPhone)
    }

    @Test
    fun mixedCase_orderPreserved_andDeduped() {
        val h = resp(listOf("TOTP", "Sms", "email")).toMfaSetupHandoff("u@x.com")
        assertEquals(listOf(MfaSetupFactor.Totp, MfaSetupFactor.Sms, MfaSetupFactor.Email), h.factors)

        val deduped = resp(listOf("totp", "totp", "sms")).toMfaSetupHandoff("u@x.com")
        assertEquals(listOf(MfaSetupFactor.Totp, MfaSetupFactor.Sms), deduped.factors)
    }

    @Test
    fun unknownFactors_dropped_allUnknownIsEmpty() {
        assertEquals(
            listOf(MfaSetupFactor.Totp),
            resp(listOf("totp", "webauthn")).toMfaSetupHandoff("u@x.com").factors,
        )
        assertFalse(resp(listOf("webauthn")).toMfaSetupHandoff("u@x.com").isRequired)
    }

    @Test
    fun email_sourcedFromParameter_blankToNull() {
        assertEquals("u@x.com", resp(listOf("email")).toMfaSetupHandoff("u@x.com").email)
        assertNull(resp(listOf("email")).toMfaSetupHandoff(null).email)
        assertNull(resp(listOf("email")).toMfaSetupHandoff("  ").email)
    }
}
