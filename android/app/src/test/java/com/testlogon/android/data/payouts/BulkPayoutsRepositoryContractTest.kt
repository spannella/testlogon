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
 * AND-261/263 — contract tests for [BulkPayoutsRepositoryImpl] against MockWebServer with the
 * production Moshi/Retrofit config: bare-array list round-trip (path/verb + NO query params), single
 * detail GET with embedded items (no second request), empty-array success, 422 + generic non-2xx
 * mapping. READ-ONLY: every recorded request is a GET under /ui/admin/bulk-payouts/batches.
 */
class BulkPayoutsRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): BulkPayoutsRepositoryImpl {
        val api = backend.retrofit(moshi).create(BulkPayoutsApi::class.java)
        return BulkPayoutsRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun getBatches_hitsBarePath_noQueryParams_mapsArray() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """[
                   {"batch_id":"bat_77","kind":"payout","status":"completed","item_count":128,
                    "total_cents":5764500,"success_count":124,"failure_count":4,"created_at":1748729400,
                    "created_by":"admin_42","items":[]},
                   {"batch_id":"bat_78","kind":"refund","status":"processing","item_count":2,
                    "total_cents":900,"created_at":1748729500,"items":[]}
                   ]""",
            ),
        )
        val result = repo().getBatches()
        assertTrue(result is ApiResult.Success)
        val batches = (result as ApiResult.Success).data
        assertEquals(2, batches.size)
        assertEquals(listOf("bat_77", "bat_78"), batches.map { it.id })
        assertEquals(PayoutBatchStatus.COMPLETED, batches[0].status)
        assertEquals(5_764_500L, batches[0].total.cents)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/admin/bulk-payouts/batches", req.requestUrl?.encodedPath)
        assertNull("no query string expected", req.requestUrl?.query)
    }

    @Test
    fun getBatch_hitsIdPath_embeddedItems_singleRequest() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"batch_id":"bat_77","kind":"payout","status":"completed","item_count":1,
                   "total_cents":4500,"success_count":1,"failure_count":0,"created_at":1748729400,
                   "created_by":"admin_42","items":[
                     {"ref_id":"po_5501","amount_cents":4500,"status":"paid","recipient":"creator_88","reason":""}
                   ]}""",
            ),
        )
        val result = repo().getBatch("bat_77")
        assertTrue(result is ApiResult.Success)
        val batch = (result as ApiResult.Success).data
        assertEquals(1, batch.items.size)
        assertEquals("po_5501", batch.items[0].refId)
        assertEquals(PayoutStatus.PAID, batch.items[0].status) // "paid" -> PAID (payout program split PAID/COMPLETED)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/admin/bulk-payouts/batches/bat_77", req.requestUrl?.encodedPath)
        // Exactly one request was made (no second /items call).
        assertEquals(1, backend.requestCount)
    }

    @Test
    fun getBatches_emptyArray_isEmptySuccess() = runTest {
        backend.enqueue(Fixtures.okBody("[]"))
        val result = repo().getBatches()
        assertTrue(result is ApiResult.Success)
        assertEquals(0, (result as ApiResult.Success).data.size)
    }

    @Test
    fun getBatch_422_mapsFailure() = runTest {
        backend.enqueue(Fixtures.error("""[{"loc":["path","batch_id"],"msg":"bad","type":"x"}]""", 422))
        val result = repo().getBatch("bat_missing")
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun getBatch_generic404_mapsFailure_withoutAssumingFixedBody() = runTest {
        backend.enqueue(Fixtures.okBody("not found", code = 404))
        val result = repo().getBatch("bat_missing")
        assertTrue(result is ApiResult.Failure || result is ApiResult.NetworkError)
    }

    @Test
    fun getBatches_malformedBody_mapsFailure_neverCrashes() = runTest {
        backend.enqueue(Fixtures.malformed())
        val result = repo().getBatches()
        assertTrue(result is ApiResult.Failure || result is ApiResult.NetworkError)
    }
}
