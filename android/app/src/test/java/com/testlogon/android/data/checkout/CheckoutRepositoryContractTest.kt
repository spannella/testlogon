package com.testlogon.android.data.checkout

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-213 — contract tests for [CheckoutRepositoryImpl.createSession]: POST ui/checkout/session with
 * source="cart" + cart_id, the best-effort X-Idempotency-Key header, success mapping (id from
 * checkout_session_id), unknown status -> UNKNOWN, and 422 validation mapping.
 */
class CheckoutRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): CheckoutRepositoryImpl {
        val api = backend.retrofit(moshi).create(CheckoutApi::class.java)
        return CheckoutRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    private fun request() = CheckoutSessionRequest(
        cartId = "cart_1",
        idempotencyKey = "idem-123",
        totalCents = 4498,
        currency = "USD",
    )

    private val sessionOut = """
        {"checkout_session_id":"cs_1","order_id":"ord_1","source":"cart","status":"pending_payment",
         "line_items":[{"sku":"SKU-1","name":"Widget","quantity":2},{"sku":"SKU-2","quantity":1}]}
    """.trimIndent()

    @Test
    fun createSession_postsCorrectPathBodyAndHeader() = runTest {
        backend.enqueue(Fixtures.okBody(sessionOut))
        val result = repo().createSession(request())
        assertTrue(result is ApiResult.Success)
        val session = (result as ApiResult.Success).data
        assertEquals("cs_1", session.id)
        assertEquals("ord_1", session.orderId)
        assertEquals(CheckoutStatus.PENDING_PAYMENT, session.status)
        assertEquals(2, session.lineItems.size)
        assertEquals("Widget", session.lineItems[0].name)
        assertEquals("SKU-2", session.lineItems[1].sku) // name falls back to sku when absent
        assertEquals("SKU-2", session.lineItems[1].name)
        assertEquals(4498L, session.totalCents)         // seeded from the cart total

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/checkout/session", req.requestUrl?.encodedPath)
        assertEquals("idem-123", req.getHeader("X-Idempotency-Key"))
        val body = req.body.readUtf8()
        assertTrue(body.contains("\"source\":\"cart\""))
        assertTrue(body.contains("\"cart_id\":\"cart_1\""))
    }

    @Test
    fun createSession_unknownStatus_mapsToUnknown() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"checkout_session_id":"cs_1","order_id":"ord_1","source":"cart","status":"weird_value"}""",
            ),
        )
        val result = repo().createSession(request())
        assertTrue(result is ApiResult.Success)
        assertEquals(CheckoutStatus.UNKNOWN, (result as ApiResult.Success).data.status)
    }

    @Test
    fun createSession_422_validationMapped() = runTest {
        backend.enqueue(
            Fixtures.error("""[{"loc":["body","source"],"msg":"field required","type":"value_error"}]""", 422),
        )
        val result = repo().createSession(request())
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }
}
