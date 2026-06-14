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
 * AND-217 — checkout-repo resilience + error-shape wiring (the slice-specific assertions on top of the
 * core-network interceptor tests). Confirms the non-idempotent POST is hit exactly once on a 503 (no
 * client retry) and that the three FastAPI `detail` shapes fold to a typed ApiResult.Failure via the
 * repository's ApiErrorParser.
 */
class CheckoutResilienceContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): CheckoutRepositoryImpl {
        val api = backend.retrofit(moshi).create(CheckoutApi::class.java)
        return CheckoutRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    private fun request() = CheckoutSessionRequest(
        cartId = "cart_1", idempotencyKey = "idem", totalCents = 1000, currency = "USD",
    )

    @Test
    fun createSession_503_notRetried_singleRequest() = runTest {
        backend.enqueue(Fixtures.error("\"service unavailable\"", 503))
        val result = repo().createSession(request())
        assertTrue(result is ApiResult.Failure)
        assertEquals(503, (result as ApiResult.Failure).error.status)
        // Non-idempotent POST: exactly one attempt (no client-side retry).
        assertEquals(1, backend.requestCount)
    }

    @Test
    fun detailString_mapsToMessage() = runTest {
        backend.enqueue(Fixtures.error("\"Cart is empty\"", 400))
        val result = repo().createSession(request())
        assertTrue(result is ApiResult.Failure)
        assertEquals("Cart is empty", (result as ApiResult.Failure).error.message)
    }

    @Test
    fun detailList_mapsToValidationMessage() = runTest {
        backend.enqueue(
            Fixtures.error("""[{"loc":["body","source"],"msg":"field required"}]""", 422),
        )
        val result = repo().createSession(request())
        assertTrue(result is ApiResult.Failure)
        assertEquals("field required", (result as ApiResult.Failure).error.message)
    }

    @Test
    fun detailObject_withCode_mapsCode() = runTest {
        backend.enqueue(
            Fixtures.error("""{"code":"role_required","message":"nope"}""", 403),
        )
        val result = repo().createSession(request())
        assertTrue(result is ApiResult.Failure)
        assertEquals("role_required", (result as ApiResult.Failure).error.code)
    }
}
