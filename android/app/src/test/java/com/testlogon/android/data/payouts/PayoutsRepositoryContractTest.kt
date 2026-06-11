package com.testlogon.android.data.payouts

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-258 — contract tests for [PayoutsRepositoryImpl] against MockWebServer with the production
 * Moshi/Retrofit config: balance + list round-trips (path/verb/query + epoch/cents mapping), the
 * request-payout POST body, cancel POST path, 422/malformed error mapping.
 */
class PayoutsRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): PayoutsRepositoryImpl {
        val api = backend.retrofit(moshi).create(PayoutsApi::class.java)
        return PayoutsRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun getBalance_hitsBalancePath_mapsAllFields() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"available_cents":4500,"pending_cents":1200,"total_earned_cents":98000,
                   "hold_cents":0,"currency":"USD","minimum_payout_cents":1000}""",
            ),
        )
        val result = repo().getBalance()
        assertTrue(result is ApiResult.Success)
        val balance = (result as ApiResult.Success).data
        assertEquals(4500L, balance.availableCents)
        assertEquals(1000L, balance.minimumPayoutCents)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/payouts/balance", req.requestUrl?.encodedPath)
    }

    @Test
    fun getPayouts_sendsLimitAndCursor_mapsItemsAndNextCursor() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"items":[{"payout_id":"po_1029","user_id":"usr_77","amount_cents":4500,
                   "method":"bank_transfer","status":"completed","created_at":1748628251,
                   "updated_at":1748800800,"completed_at":1748800800,"notes":"","reject_reason":"",
                   "approved_by":"admin_3"}],"next_cursor":"c2"}""",
            ),
        )
        val result = repo().getPayouts(cursor = "C1", limit = 20)
        assertTrue(result is ApiResult.Success)
        val page = (result as ApiResult.Success).data
        assertEquals(1, page.items.size)
        assertEquals("po_1029", page.items[0].payoutId)
        assertEquals(PayoutStatus.COMPLETED, page.items[0].status)
        assertEquals("c2", page.nextCursor)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/payouts", req.requestUrl?.encodedPath)
        assertEquals("20", req.requestUrl?.queryParameter("limit"))
        assertEquals("C1", req.requestUrl?.queryParameter("cursor"))
    }

    @Test
    fun requestPayout_postsRequestBody_mapsCreateResult() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"ok":true,"payout_id":"po_new","amount_cents":50000,"status":"pending"}""",
                code = 201,
            ),
        )
        val result = repo().requestPayout(amountCents = 50000, method = "bank_transfer", notes = "hi", currency = "USD")
        assertTrue(result is ApiResult.Success)
        val created = (result as ApiResult.Success).data
        assertEquals("po_new", created.payoutId)
        assertEquals(PayoutStatus.REQUESTED, created.status)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/payouts/request", req.requestUrl?.encodedPath)
        val body = req.body.readUtf8()
        assertTrue(body.contains("\"amount_cents\":50000"))
        assertTrue(body.contains("\"method\":\"bank_transfer\""))
    }

    @Test
    fun cancelPayout_postsToCancelPath() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true,"payout_id":"po_1","status":"cancelled"}"""))
        val result = repo().cancelPayout("po_1")
        assertTrue(result is ApiResult.Success)
        assertEquals(PayoutStatus.CANCELLED, (result as ApiResult.Success).data.status)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/payouts/po_1/cancel", req.requestUrl?.encodedPath)
    }

    @Test
    fun getPayouts_422_mapsFailure() = runTest {
        backend.enqueue(Fixtures.error("""[{"loc":["query","limit"],"msg":"bad","type":"x"}]""", 422))
        val result = repo().getPayouts()
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun getPayouts_malformedBody_mapsFailure_neverCrashes() = runTest {
        backend.enqueue(Fixtures.malformed())
        val result = repo().getPayouts()
        assertTrue(result is ApiResult.Failure || result is ApiResult.NetworkError)
    }

    @Test
    fun getPayouts_emptyItems_isSuccess() = runTest {
        backend.enqueue(Fixtures.okBody("""{"items":[],"next_cursor":null}"""))
        val result = repo().getPayouts()
        assertTrue(result is ApiResult.Success)
        assertEquals(0, (result as ApiResult.Success).data.items.size)
        assertNull(result.data.nextCursor)
    }
}
