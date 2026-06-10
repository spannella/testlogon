package com.testlogon.android.feature.messaging.helpdesk

import com.testlogon.android.core.model.ApiError
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-162 — ClaimErrorMapper mapping table (verified reply-side codes + defensive HTTP-status branches). */
class ClaimErrorMapperTest {

    private fun map(status: Int, code: String? = null) =
        ClaimErrorMapper.map(ApiError(status = status, message = "x", code = code))

    @Test
    fun networkIsRetryable() {
        val (e, retry) = ClaimErrorMapper.map(ApiError(status = ApiError.STATUS_NETWORK, message = "off"))
        assertEquals(ClaimError.NETWORK, e)
        assertTrue(retry)
    }

    @Test
    fun notAvailableCode() {
        val (e, retry) = map(403, "helpdesk_claim_not_available")
        assertEquals(ClaimError.NOT_AVAILABLE, e)
        assertFalse(retry)
    }

    @Test
    fun roleRequiredCodesAreForbidden() {
        assertEquals(ClaimError.FORBIDDEN, map(403, "role_required").first)
        assertEquals(ClaimError.FORBIDDEN, map(403, "role_required_scope").first)
        assertEquals(ClaimError.FORBIDDEN, map(403, "role_required_admin_profile_type").first)
        assertEquals(ClaimError.FORBIDDEN, map(403).first) // bare 403
    }

    @Test
    fun conflictIsAlreadyClaimed() {
        assertEquals(ClaimError.ALREADY_CLAIMED, map(409).first)
    }

    @Test
    fun notFound() {
        assertEquals(ClaimError.NOT_FOUND, map(404).first)
    }

    @Test
    fun serverIsNetworkRetryable() {
        val (e, retry) = map(500)
        assertEquals(ClaimError.NETWORK, e)
        assertTrue(retry)
    }

    @Test
    fun validation422IsUnknownNonRetryable() {
        val (e, retry) = map(422)
        assertEquals(ClaimError.UNKNOWN, e)
        assertFalse(retry)
    }
}
