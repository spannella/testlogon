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
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * Contract tests for the trader staking + auctions data layer (peer mechanisms). Verifies the shared
 * [StakeAuctionAckDto] -> [StakeAuctionAck] mapping (per-kind created id + accepted/rejected/message +
 * the id label) and that an undeployed route (404) degrades to an un-applied ack instead of failing.
 */
class StakeAuctionContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi = testMoshi()

    private fun repo(): TradingRepository {
        val api = backend.retrofit(moshi).create(TradingApi::class.java)
        return TradingRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun stakeRequest_ack_surfacesRequestId() = runTest {
        backend.enqueue(Fixtures.okBody("""{"status":"ack","type":"stake_request","request_id":42}"""))
        val r = repo().stakeRequest(3, 1000L, 50L, 3600, 86400)
        assertTrue(r is ApiResult.Success)
        val ack = (r as ApiResult.Success).data
        assertTrue(ack.accepted)
        assertEquals(StakeAuctionKind.STAKE_REQUEST, ack.kind)
        assertEquals(42L, ack.createdId)
        assertEquals("Request #42", ack.idLabel)
    }

    @Test
    fun stakeRequest_stringifiedId_isLenient() = runTest {
        // The edge may stringify numeric ids -> the @LenientLong adapter must still parse it.
        backend.enqueue(Fixtures.okBody("""{"status":"ok","request_id":"77"}"""))
        val r = repo().stakeRequest(null, 500L, 10L, 60, 120)
        val ack = (r as ApiResult.Success).data
        assertTrue(ack.accepted)
        assertEquals(77L, ack.createdId)
    }

    @Test
    fun auctionRequest_ack_surfacesAuctionId() = runTest {
        backend.enqueue(Fixtures.okBody("""{"status":"created","type":"auction_request","auction_id":7}"""))
        val r = repo().auctionRequest(3, 5, 250L, 3600)
        val ack = (r as ApiResult.Success).data
        assertTrue(ack.accepted)
        assertEquals(StakeAuctionKind.AUCTION_REQUEST, ack.kind)
        assertEquals(7L, ack.createdId)
        assertEquals("Auction #7", ack.idLabel)
    }

    @Test
    fun stakeOffer_ack_prefersOfferId_elseFallsBackToRequestId() = runTest {
        backend.enqueue(Fixtures.okBody("""{"status":"ack","offer_id":9,"request_id":42}"""))
        val withOffer = (repo().stakeOffer(42L, 1000L, 25L) as ApiResult.Success).data
        assertEquals(9L, withOffer.createdId)
        assertEquals("Offer #9", withOffer.idLabel)

        backend.enqueue(Fixtures.okBody("""{"status":"ack","request_id":42}"""))
        val withoutOffer = (repo().stakeOffer(42L, 1000L, 25L) as ApiResult.Success).data
        assertEquals(42L, withoutOffer.createdId)
    }

    @Test
    fun auctionBid_ack_prefersBidId_elseFallsBackToAuctionId() = runTest {
        backend.enqueue(Fixtures.okBody("""{"status":"ack","bid_id":3,"auction_id":7}"""))
        val withBid = (repo().auctionBid(7L, 300L, 2) as ApiResult.Success).data
        assertEquals(3L, withBid.createdId)
        assertEquals("Bid #3", withBid.idLabel)
    }

    @Test
    fun rejected_nonZeroResult_isNotAccepted_withMessage() = runTest {
        backend.enqueue(Fixtures.okBody("""{"status":"rejected","type":"auction_bid","result":5,"error":"below reserve"}"""))
        val ack = (repo().auctionBid(7L, 1L, 1) as ApiResult.Success).data
        assertFalse(ack.accepted)
        assertEquals("below reserve", ack.message)
        assertNull(ack.idLabel)
    }

    @Test
    fun ackWithNonZeroResult_isNotAccepted() = runTest {
        // status ack but a non-zero result means the engine did not apply it.
        backend.enqueue(Fixtures.okBody("""{"status":"ack","result":3}"""))
        val ack = (repo().stakeRequest(1, 1L, 1L, 1, 1) as ApiResult.Success).data
        assertFalse(ack.accepted)
    }

    @Test
    fun undeployedRoute_404_degradesToUnappliedAck() = runTest {
        backend.enqueue(Fixtures.error("\"not found\"", 404))
        val r = repo().stakeRequest(3, 1000L, 50L, 3600, 86400)
        assertTrue(r is ApiResult.Success)
        val ack = (r as ApiResult.Success).data
        assertFalse(ack.accepted)
        assertNull(ack.createdId)
        assertEquals(StakeAuctionKind.STAKE_REQUEST, ack.kind)
    }
}
