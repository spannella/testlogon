package com.testlogon.android.data.payments

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import com.testlogon.android.data.billing.BillingApi
import com.testlogon.android.data.messaging.BillingAuthorizer
import com.testlogon.android.data.messaging.BillingResult
import com.testlogon.android.data.messaging.StubBillingAuthorizer
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-227..230 — repository contract tests against MockWebServer + the BillingAuthorizer gate.
 *
 * The headline assertion (PAYMENTS FLAG / AND-031): with the bound [StubBillingAuthorizer]
 * (NotConfigured), createRedirectSession returns NotConfigured and issues ZERO network requests — no
 * live provider session is created and no charge URL is produced. The verified capture + verify
 * round-trips are exercised with a fake-authorized authorizer / direct calls.
 */
class PaymentRedirectRepositoryTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(authorizer: BillingAuthorizer): PaymentRedirectRepositoryImpl {
        val retrofit = backend.retrofit(moshi)
        return PaymentRedirectRepositoryImpl(
            api = retrofit.create(PaymentRedirectApi::class.java),
            billingApi = retrofit.create(BillingApi::class.java),
            authorizer = authorizer,
            errorParser = ApiErrorParser(moshi),
        )
    }

    @Test
    fun createRedirectSession_withStub_debugBypass_authorizesBlankPm_andReachesServer() = runTest {
        // The StubBillingAuthorizer now ships a DEV/DEMO bypass: in DEBUG builds (unit tests run debug) it
        // authorizes with a BLANK payment_method_id so on-device redirect checkouts work without a real
        // vendor. So createRedirectSession is NO LONGER short-circuited to NotConfigured — it authorizes
        // and POSTs to the backend (which mints the hosted session). Release builds keep NotConfigured.
        backend.enqueue(
            Fixtures.okBody("""{"session_id":"cs_test_1","url":"https://checkout.example/c/pay/cs_test_1"}"""),
        )
        val result = repo(StubBillingAuthorizer()).createRedirectSession(
            provider = RedirectProvider.CHECKOUT,
            amountCents = 500,
            currency = "usd",
            description = "demo",
        )
        assertTrue(result is RedirectSessionResult.Created)
        assertEquals(1, backend.requestCount)
    }

    @Test
    fun createRedirectSession_authorizedHostedCheckout_createsSessionFromUrl() = runTest {
        backend.enqueue(
            Fixtures.okBody("""{"session_id":"cs_test_1","url":"https://checkout.example/c/pay/cs_test_1"}"""),
        )
        val result = repo(FakeAuthorizer(BillingResult.Authorized("pm_1", 500L)))
            .createRedirectSession(RedirectProvider.CHECKOUT, 500, "usd", "demo")
        assertTrue(result is RedirectSessionResult.Created)
        val session = (result as RedirectSessionResult.Created).session
        assertEquals("cs_test_1", session.sessionId)
        assertEquals("https://checkout.example/c/pay/cs_test_1", session.hostedUrl)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/billing/checkout_session", req.requestUrl?.encodedPath)
        assertTrue(req.body.readUtf8().contains("\"amount_cents\":500"))
    }

    @Test
    fun capturePayPalOrder_postsBodyOrderIdAndIdempotencyKey() = runTest {
        backend.enqueue(
            Fixtures.okBody("""{"order_id":"PP-1","capture_id":"PP-CAP-1","status":"COMPLETED"}"""),
        )
        val result = repo(StubBillingAuthorizer()).capturePayPalOrder("PP-1", "and228-key")
        assertTrue(result is ApiResult.Success)
        val capture = (result as ApiResult.Success).data
        assertEquals("PP-CAP-1", capture.captureId)
        assertEquals("COMPLETED", capture.status)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/api/billing/paypal/capture-order", req.requestUrl?.encodedPath)
        val body = req.body.readUtf8()
        assertTrue(body.contains("\"order_id\":\"PP-1\""))
        assertTrue(body.contains("\"idempotency_key\":\"and228-key\""))
    }

    @Test
    fun verifyMicrodeposits_postsSetupIntentAndAmounts_mapsVerified() = runTest {
        backend.enqueue(Fixtures.okBody("""{"status":"verified"}"""))
        val result = repo(StubBillingAuthorizer()).verifyMicrodeposits("seti_1", listOf(32, 45))
        assertTrue(result is ApiResult.Success)
        val data = (result as ApiResult.Success).data
        assertEquals(UsBankVerificationState.VERIFIED, data.state)
        assertEquals("seti_1", data.setupIntentId)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/billing/us-bank/verify-microdeposits", req.requestUrl?.encodedPath)
        val body = req.body.readUtf8()
        assertTrue(body.contains("\"setup_intent_id\":\"seti_1\""))
        assertTrue(body.contains("\"amounts\":[32,45]"))
    }

    @Test
    fun verifyMicrodeposits_unknownStatus_mapsUnknown() = runTest {
        backend.enqueue(Fixtures.okBody("""{"status":"weird"}"""))
        val result = repo(StubBillingAuthorizer()).verifyMicrodeposits("seti_1", listOf(1, 2))
        assertTrue(result is ApiResult.Success)
        assertEquals(UsBankVerificationState.UNKNOWN, (result as ApiResult.Success).data.state)
    }

    @Test
    fun verifyMicrodeposits_422_mapsFailure() = runTest {
        backend.enqueue(
            Fixtures.error("""[{"loc":["body","amounts"],"msg":"field required","type":"x"}]""", 422),
        )
        val result = repo(StubBillingAuthorizer()).verifyMicrodeposits("seti_1", listOf(1, 2))
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }
}

private class FakeAuthorizer(private val result: BillingResult) : BillingAuthorizer {
    override suspend fun authorize(amountMinorUnits: Long, currency: String, memo: String?): BillingResult =
        result
}
