package com.testlogon.android.data.billing

import com.squareup.moshi.Moshi
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.MockResponse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import retrofit2.HttpException

/**
 * AND-233 — billing checkout-session create contract (gap not covered by BillingRepositoryContractTest,
 * which exercises only the GET surfaces). Asserts the VERIFIED contract:
 *  - request: POST ui/billing/checkout_session with BillingCheckoutReq {amount_cents, currency?,
 *    description?} (no provider/price_id/return_url/idempotency_key);
 *  - response: {session_id, url} only (no client_secret/publishable_key/status);
 *  - non-2xx surfaces as retrofit2.HttpException (not swallowed); no Idempotency-Key header is sent.
 *
 * Source: reference/src/api/endpoints/billing.ts createCheckoutSession; openapi BillingCheckoutReq.
 */
class BillingCheckoutSessionContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun api(): BillingApi = backend.retrofit(moshi).create(BillingApi::class.java)

    @Test
    fun createCheckoutSession_postsBillingCheckoutReq_andParsesSessionUrl() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"session_id":"cs_test_abc","url":"https://checkout.stripe.com/c/pay/cs_test_abc"}""",
            ),
        )
        val result = api().createCheckoutSession(
            CheckoutSessionRequestDto(amountCents = 1999, currency = "usd", description = "TestLogon order"),
        )
        assertEquals("cs_test_abc", result.sessionId)
        assertEquals("https://checkout.stripe.com/c/pay/cs_test_abc", result.url)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/billing/checkout_session", req.requestUrl?.encodedPath)
        val body = req.body.readUtf8()
        assertTrue(body.contains("\"amount_cents\":1999"))
        assertTrue(body.contains("\"currency\":\"usd\""))
        // No Idempotency-Key header is sent (none in the verified contract).
        assertEquals(null, req.getHeader("Idempotency-Key"))
    }

    @Test
    fun createCheckoutSession_minimalBody_onlyAmountCents() = runTest {
        backend.enqueue(Fixtures.okBody("""{"session_id":"cs_1","url":"https://x/cs_1"}"""))
        api().createCheckoutSession(CheckoutSessionRequestDto(amountCents = 500))
        val body = backend.takeRequest().body.readUtf8()
        assertTrue(body.contains("\"amount_cents\":500"))
        // Optional fields omitted when null (Moshi non-serializeNulls by default).
        assertTrue(!body.contains("\"description\""))
    }

    @Test
    fun createCheckoutSession_402_throwsHttpException_notSwallowed() = runTest {
        backend.enqueue(Fixtures.error("\"Card declined.\"", 402))
        val ex = runCatching { api().createCheckoutSession(CheckoutSessionRequestDto(amountCents = 100)) }
            .exceptionOrNull()
        assertTrue(ex is HttpException)
        assertEquals(402, (ex as HttpException).code())
    }

    @Test
    fun createCheckoutSession_nonAsciiDetail_roundTripsForCaller() = runTest {
        // i18n: a localized backend detail must be retrievable verbatim from the error body.
        backend.enqueue(
            MockResponse()
                .setResponseCode(402)
                .setHeader("Content-Type", "application/json")
                .setBody("""{"detail":"Carte refusée — solde insuffisant"}"""),
        )
        val ex = runCatching { api().createCheckoutSession(CheckoutSessionRequestDto(amountCents = 100)) }
            .exceptionOrNull() as HttpException
        val raw = ex.response()?.errorBody()?.string().orEmpty()
        assertTrue(raw.contains("Carte refusée — solde insuffisant"))
    }
}
