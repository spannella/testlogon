package com.testlogon.android.data.refunds

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
 * AND-244 — contract tests for [RefundsRepositoryImpl] against MockWebServer using the production
 * Moshi/Retrofit config. Covers submit (path + body, no amount when full refund), list ({items} +
 * newest-first sort), detail (path param), 422 error mapping, and no-auto-retry on the submit POST.
 */
class RefundsRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): RefundsRepositoryImpl {
        val api = backend.retrofit(moshi).create(RefundsApi::class.java)
        return RefundsRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun submitRefund_postsBody_andMapsResult() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"refund_request_id":"rfnd_1","status":"pending","amount_cents":1299,
                   "currency":"usd","reason":"Charged twice for the same item","created_at":1749124800}""",
                code = 201,
            ),
        )
        val result = repo().submitRefund(
            SubmitRefundInput("entry_1", "Charged twice for the same item", 1299L),
        )
        assertTrue(result is ApiResult.Success)
        val refund = (result as ApiResult.Success).data
        assertEquals("rfnd_1", refund.id)
        assertEquals(RefundStatus.PENDING, refund.status)
        assertEquals(1299L, refund.amount.cents)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/billing/refund-requests", req.requestUrl?.encodedPath)
        val body = req.body.readUtf8()
        assertTrue(body.contains("\"transaction_entry_id\":\"entry_1\""))
        assertTrue(body.contains("\"amount_cents\":1299"))
    }

    @Test
    fun submitRefund_fullRefund_omitsAmount() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"refund_request_id":"rfnd_2","status":"pending","amount_cents":0,
                   "currency":"usd","reason":"full refund please","created_at":1}""",
                code = 201,
            ),
        )
        repo().submitRefund(SubmitRefundInput("entry_2", "full refund please", null))
        val body = backend.takeRequest().body.readUtf8()
        assertTrue(body.contains("transaction_entry_id"))
        assertTrue("full refund body should omit amount_cents", !body.contains("amount_cents"))
    }

    @Test
    fun listRefunds_mapsItems_andSortsNewestFirst() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"items":[
                   {"refund_request_id":"old","status":"completed","amount_cents":100,"currency":"usd","reason":"a","created_at":1000},
                   {"refund_request_id":"new","status":"pending","amount_cents":200,"currency":"usd","reason":"b","created_at":2000}
                ]}""",
            ),
        )
        val result = repo().listRefunds()
        assertTrue(result is ApiResult.Success)
        val list = (result as ApiResult.Success).data
        assertEquals(2, list.size)
        assertEquals("new", list[0].id) // newest first
        assertEquals("old", list[1].id)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/billing/refund-requests", req.requestUrl?.encodedPath)
        assertEquals("100", req.requestUrl?.queryParameter("limit"))
    }

    @Test
    fun getRefund_usesPathParam() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"refund_request_id":"rfnd_9","status":"approved","amount_cents":500,
                   "currency":"usd","reason":"x","created_at":5,"admin_notes":"ok"}""",
            ),
        )
        val result = repo().getRefund("rfnd_9")
        assertTrue(result is ApiResult.Success)
        assertEquals(RefundStatus.APPROVED, (result as ApiResult.Success).data.status)
        assertEquals("/ui/billing/refund-requests/rfnd_9", backend.takeRequest().requestUrl?.encodedPath)
    }

    @Test
    fun submitRefund_422_isFailure_andNotRetried() = runTest {
        backend.enqueue(
            Fixtures.error(
                """[{"loc":["body","reason"],"msg":"String should have at least 10 characters","type":"string_too_short"}]""",
                422,
            ),
        )
        val result = repo().submitRefund(SubmitRefundInput("entry_1", "short", null))
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
        assertEquals(1, backend.requestCount) // no auto-retry on the POST
        backend.takeRequest()
    }
}
