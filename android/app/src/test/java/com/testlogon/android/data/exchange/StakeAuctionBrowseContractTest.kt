package com.testlogon.android.data.exchange

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import com.testlogon.android.testutil.testMoshi
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * Contract tests for the STUB discovery-browse data layer (GET me/stake_requests, me/auctions). The
 * stub returns an empty list + stub:true + a human note; real rows must also map. A 404 (undeployed)
 * degrades to an unavailable empty state.
 */
class StakeAuctionBrowseContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi = testMoshi()

    private fun repo(): TradingRepository {
        val api = backend.retrofit(moshi).create(TradingApi::class.java)
        return TradingRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun stakeRequests_stub_emptyWithNote() = runTest {
        backend.enqueue(Fixtures.okBody("""{"stake_requests":[],"count":0,"stub":true,"note":"Open stake requests browsing is not available yet."}"""))
        val r = repo().stakeRequestsBrowse()
        assertTrue(r is ApiResult.Success)
        val d = (r as ApiResult.Success).data
        assertTrue(d.isEmpty)
        assertTrue(d.stub)
        assertFalse(d.unavailable)
        assertEquals(0, d.count)
        assertEquals("Open stake requests browsing is not available yet.", d.note)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/me/stake_requests", req.requestUrl?.encodedPath)
    }

    @Test
    fun stakeRequests_realRows_map() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"stake_requests":[
                    {"request_id":"42","symbolid":3,"symbol":"BTC","min_collateral":"1000","max_stake_pct":"50","status":"open","owner":"alice"}
                ],"count":1,"stub":false}""",
            ),
        )
        val d = (repo().stakeRequestsBrowse() as ApiResult.Success).data
        assertFalse(d.isEmpty)
        assertEquals(1, d.items.size)
        val item = d.items.first()
        assertEquals(42L, item.requestId)
        assertEquals("Request #42", item.idLabel)
        assertEquals("BTC", item.symbolLabel)
        assertEquals("1000", item.minCollateral)
        assertEquals("open", item.status)
    }

    @Test
    fun stakeRequests_404_unavailable() = runTest {
        backend.enqueue(Fixtures.error("\"not found\"", 404))
        val d = (repo().stakeRequestsBrowse() as ApiResult.Success).data
        assertTrue(d.unavailable)
        assertTrue(d.isEmpty)
    }

    @Test
    fun auctions_stub_emptyWithNote() = runTest {
        backend.enqueue(Fixtures.okBody("""{"auctions":[],"count":0,"stub":true,"note":"Open auctions browsing is not available yet."}"""))
        val d = (repo().auctionsBrowse() as ApiResult.Success).data
        assertTrue(d.isEmpty)
        assertTrue(d.stub)
        assertEquals("Open auctions browsing is not available yet.", d.note)

        val req = backend.takeRequest()
        assertEquals("/me/auctions", req.requestUrl?.encodedPath)
    }

    @Test
    fun auctions_realRows_map() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"auctions":[
                    {"auction_id":7,"symbol":"ETH","qty":"5","reserve_price":"250","status":"open"}
                ],"count":1}""",
            ),
        )
        val d = (repo().auctionsBrowse() as ApiResult.Success).data
        assertEquals(1, d.items.size)
        val item = d.items.first()
        assertEquals(7L, item.auctionId)
        assertEquals("Auction #7", item.idLabel)
        assertEquals("ETH", item.symbolLabel)
        assertEquals("5", item.qty)
        assertEquals("250", item.reservePrice)
    }

    @Test
    fun auctions_404_unavailable() = runTest {
        backend.enqueue(Fixtures.error("\"not found\"", 404))
        val d = (repo().auctionsBrowse() as ApiResult.Success).data
        assertTrue(d.unavailable)
    }
}