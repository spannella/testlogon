package com.testlogon.android.feature.billing.error

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.i18n.UiText
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.net.SocketTimeoutException

/**
 * AND-232 — [BillingErrorMapper] cases: decline-code dictionary -> recoverability + resource message,
 * transient/5xx -> RETRYABLE, validation/auth -> FATAL (server message passed through), and the
 * NetworkError/timeout split. Reuses the central ErrorDetailMapper output via [ApiError.message].
 */
class BillingErrorMapperTest {

    private val mapper = BillingErrorMapper()

    @Test
    fun networkError_offline_isRetryable() {
        val e = mapper.map(ApiResult.NetworkError(IOException("x"), isTimeout = false))
        assertEquals(Recoverability.RETRYABLE, e.recoverability)
        assertTrue(e.retryable)
        assertEquals(ApiError.STATUS_NETWORK, e.httpStatus)
    }

    @Test
    fun networkError_timeout_isRetryable_timeoutMessage() {
        val e = mapper.map(ApiResult.NetworkError(SocketTimeoutException(), isTimeout = true))
        assertEquals(Recoverability.RETRYABLE, e.recoverability)
    }

    @Test
    fun cardDeclined_requiresNewMethod() {
        val e = mapper.map(ApiError(status = 402, message = "Card declined.", code = "card_declined"))
        assertEquals(Recoverability.REQUIRES_NEW_METHOD, e.recoverability)
        assertEquals(DeclineCode.CARD_DECLINED, e.declineCode)
        assertEquals("card_declined", e.rawDetailCode)
        assertTrue(e.message is UiText.Res)
    }

    @Test
    fun insufficientFunds_expiredCard_incorrectCvc_allRequireNewMethod() {
        listOf("insufficient_funds", "expired_card", "incorrect_cvc").forEach { code ->
            val e = mapper.map(ApiError(status = 402, message = "x", code = code))
            assertEquals("$code -> REQUIRES_NEW_METHOD", Recoverability.REQUIRES_NEW_METHOD, e.recoverability)
        }
    }

    @Test
    fun processingError_isRetryable() {
        val e = mapper.map(ApiError(status = 402, message = "x", code = "processing_error"))
        assertEquals(Recoverability.RETRYABLE, e.recoverability)
        assertTrue(e.retryable)
    }

    @Test
    fun authenticationRequired_requiresAction() {
        val e = mapper.map(ApiError(status = 402, message = "x", code = "authentication_required"))
        assertEquals(Recoverability.REQUIRES_ACTION, e.recoverability)
    }

    @Test
    fun serverError_isRetryable_stableMessage() {
        val e = mapper.map(ApiError(status = 503, message = "Service Unavailable"))
        assertEquals(Recoverability.RETRYABLE, e.recoverability)
        assertTrue(e.message is UiText.Res) // stable resource, not the raw 503 body
    }

    @Test
    fun validation422_isFatal_passesServerMessageThrough() {
        val e = mapper.map(ApiError(status = 422, message = "field required"))
        assertEquals(Recoverability.FATAL, e.recoverability)
        assertEquals(UiText.Raw("field required"), e.message)
    }

    @Test
    fun geoBlocked_isFatal() {
        val e = mapper.map(
            ApiError(status = 403, message = "This content is not available in your region.", code = "geo_blocked"),
        )
        assertEquals(Recoverability.FATAL, e.recoverability)
    }

    @Test
    fun unknownCode_fallsBackToFatal_noCrash() {
        val e = mapper.map(ApiError(status = 400, message = "weird", code = "totally_unknown_code"))
        assertEquals(Recoverability.FATAL, e.recoverability)
        assertNull(e.declineCode)
    }

    @Test
    fun parseSentinel_isFatalGeneric() {
        val e = mapper.map(ApiError(status = ApiError.STATUS_PARSE, message = "x"))
        assertEquals(Recoverability.FATAL, e.recoverability)
        assertTrue(e.message is UiText.Res)
    }
}
