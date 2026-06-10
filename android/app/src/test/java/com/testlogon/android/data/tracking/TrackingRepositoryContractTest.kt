package com.testlogon.android.data.tracking

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
 * AND-215 / AND-217 — contract tests for [TrackingRepositoryImpl]: GET path/method, 200 with shipment ->
 * Success(shipment), 200 not-shipped -> Success(null shipment), 404 -> Failure, and a transport failure
 * retried once (idempotent GET) then succeeding.
 */
class TrackingRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): TrackingRepositoryImpl {
        val api = backend.retrofit(moshi).create(TrackingApi::class.java)
        return TrackingRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun tracking_200_withShipment_mapsAndHitsCorrectPath() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """
                {"txn_id":"txn_1","carrier":"ups","tracking_number":"1Z999",
                 "tracking_url":"https://ups.com/track","status":"in_transit",
                 "carrier_events":[{"timestamp":"2026-06-06T14:22:00Z","description":"Departed"}]}
                """.trimIndent(),
            ),
        )
        val result = repo().tracking("txn_1")
        assertTrue(result is ApiResult.Success)
        val tracking = (result as ApiResult.Success).data
        assertEquals(ShipmentStatus.IN_TRANSIT, tracking.shipment?.status)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/purchase-history/transactions/txn_1/tracking", req.requestUrl?.encodedPath)
    }

    @Test
    fun tracking_200_notShipped_mapsToNullShipment() = runTest {
        backend.enqueue(Fixtures.okBody("""{"txn_id":"txn_2","carrier":null,"tracking_number":null}"""))
        val result = repo().tracking("txn_2")
        assertTrue(result is ApiResult.Success)
        assertNull((result as ApiResult.Success).data.shipment)
    }

    @Test
    fun tracking_404_isFailure() = runTest {
        backend.enqueue(Fixtures.error("\"Order not found\"", 404))
        val result = repo().tracking("txn_x")
        assertTrue(result is ApiResult.Failure)
        assertEquals(404, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun tracking_transportFailureThenSuccess_retriesOnce() = runTest {
        // NO_RESPONSE -> read timeout (SocketTimeoutException) -> NetworkError. OkHttp does not auto-retry
        // a read timeout, so the repo's own single bounded retry is what consumes the second response.
        backend.enqueue(Fixtures.timeout())
        backend.enqueue(Fixtures.okBody("""{"txn_id":"txn_3","carrier":"usps","status":"delivered"}"""))
        val result = repo().tracking("txn_3")
        assertTrue(result is ApiResult.Success)
        assertEquals(ShipmentStatus.DELIVERED, (result as ApiResult.Success).data.shipment?.status)
        // One retry: two requests recorded.
        assertEquals(2, backend.requestCount)
    }
}
