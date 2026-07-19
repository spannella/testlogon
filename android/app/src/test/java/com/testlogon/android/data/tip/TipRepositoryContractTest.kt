package com.testlogon.android.data.tip

import com.squareup.moshi.Moshi
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.messaging.BillingAuthorizer
import com.testlogon.android.data.messaging.BillingResult
import com.testlogon.android.data.messaging.StubBillingAuthorizer
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

private class FakeAuthorizedBilling(private val pmId: String = "pm_1") : BillingAuthorizer {
    override suspend fun authorize(amountMinorUnits: Long, currency: String, memo: String?): BillingResult =
        BillingResult.Authorized(pmId, amountMinorUnits)
}

/**
 * AND-178 — contract tests for [TipRepositoryImpl]. Covers the STOP-AND-FLAG stubbed-billing path,
 * the happy tip (POST body shape — amount_cents + payment_method_id, NO message), empty-body 200,
 * server-reported tip_total_cents, and error mapping.
 */
class TipRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(billing: BillingAuthorizer): TipRepositoryImpl {
        val api = backend.retrofit(moshi).create(TipApi::class.java)
        return TipRepositoryImpl(api, billing, ApiErrorParser(moshi))
    }

    @Test
    fun tip_withStubBilling_debugBypass_authorizesBlankPm_andReachesServer() = runTest {
        // The StubBillingAuthorizer now ships a DEV/DEMO bypass: in DEBUG builds (unit tests run debug) it
        // authorizes with a BLANK payment_method_id so on-device tips work without a real vendor. So the
        // tip is NO LONGER short-circuited to PaymentsUnavailable — it authorizes and POSTs to the server
        // (the backend dev path mock-completes a blank-pm charge). Release builds still return NotConfigured.
        backend.enqueue(Fixtures.okBody("""{"ok":true,"tip_total_cents":1000}"""))
        val outcome = repo(StubBillingAuthorizer()).tip("post_1", 1000)
        assertTrue(outcome is TipOutcome.Success)
        assertEquals(1, backend.requestCount)
        val body = backend.takeRequest().bodyJson()
        assertEquals("", body["payment_method_id"]) // blank pm = the debug-bypass marker
    }

    @Test
    fun tip_happyPath_sendsAmountCents_andPaymentMethod_noMessage() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true,"tip_total_cents":12345}"""))
        val outcome = repo(FakeAuthorizedBilling()).tip("post_123", 1000)

        assertTrue(outcome is TipOutcome.Success)
        val receipt = (outcome as TipOutcome.Success).receipt
        assertEquals(1000, receipt.amountCents) // submitted amount echoed locally
        assertEquals(12345, receipt.tipTotalCents)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/posts/post_123/tip", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals(1000.0, body["amount_cents"]) // Moshi numbers decode to Double in the map
        assertEquals("pm_1", body["payment_method_id"])
        assertFalse(body.containsKey("message")) // no message field on the backend schema (OQ-5)
    }

    @Test
    fun tip_emptyBody200_stillSucceeds_withNullTotal() = runTest {
        backend.enqueue(Fixtures.okBody("""{}"""))
        val outcome = repo(FakeAuthorizedBilling()).tip("post_1", 500)
        assertTrue(outcome is TipOutcome.Success)
        assertNull((outcome as TipOutcome.Success).receipt.tipTotalCents)
        assertEquals(500, outcome.receipt.amountCents)
    }

    @Test
    fun tip_422_isFailure() = runTest {
        backend.enqueue(Fixtures.error("""[{"msg":"ensure this value is greater than or equal to 1"}]""", 422))
        val outcome = repo(FakeAuthorizedBilling()).tip("post_1", 1000)
        assertTrue(outcome is TipOutcome.Failure)
    }

    @Test
    fun tip_invalidAmount_failsFast_noHttp() = runTest {
        val outcome = repo(FakeAuthorizedBilling()).tip("post_1", 0)
        assertTrue(outcome is TipOutcome.Failure)
        assertEquals(0, backend.requestCount)
    }
}
