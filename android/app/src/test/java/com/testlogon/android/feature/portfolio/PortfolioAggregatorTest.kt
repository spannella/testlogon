package com.testlogon.android.feature.portfolio

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.custody.CustodyAsset
import com.testlogon.android.data.custody.CustodyBalance
import com.testlogon.android.data.custody.CustodyBalances
import com.testlogon.android.data.custody.StakingDashboard
import com.testlogon.android.data.custody.StakingPosition
import com.testlogon.android.data.exchange.MarginAccount
import com.testlogon.android.data.exchange.PositionSnapshot
import com.testlogon.android.data.exchange.SpotAsset
import com.testlogon.android.data.exchange.SpotBalance
import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Aggregation logic for the read-only Portfolio: [PortfolioAggregator.aggregate] folds four
 * independent venue reads into one snapshot. Covers the cross-venue equity sum (readable sources
 * only), per-venue INDEPENDENT degradation (a 404/403/network venue becomes an "unavailable" card
 * without dropping the others), staking soft-unavailable, and open-position projection.
 */
class PortfolioAggregatorTest {

    private fun asset(sym: String) =
        CustodyAsset(sym, sym, 1, "Ethereum", "Ethereum Mainnet", "native", 18)

    private fun custody(vararg pairs: Pair<String, Double>): ApiResult<CustodyBalances> =
        ApiResult.Success(
            CustodyBalances(
                vault = "0xvault",
                tier = "T1",
                rows = pairs.map { CustodyBalance(asset(it.first), it.second, known = true) },
            ),
        )

    private fun spot(vararg pairs: Pair<String, Long>): ApiResult<SpotBalance> =
        ApiResult.Success(
            SpotBalance(
                assets = pairs.mapIndexed { i, p -> SpotAsset(i, p.first, p.second, p.second) },
                mpid = "MP1",
            ),
        )

    private fun margin(balance: Long, position: PositionSnapshot? = null): ApiResult<MarginAccount> =
        ApiResult.Success(
            MarginAccount(
                balance = balance,
                availableBalance = balance,
                reservedMargin = 0,
                numPositions = if (position != null) 1 else 0,
                position = position,
                distressLevel = 0,
                isLiquidating = false,
                mpid = "MP1",
            ),
        )

    private fun stakingWith(vararg totals: String): ApiResult<StakingDashboard> =
        ApiResult.Success(
            StakingDashboard(
                vault = "0xvault",
                providers = emptyList(),
                positions = totals.map {
                    StakingPosition("p", "0xvault", "prov", "eth", "ETH", "0", "0", it, "active")
                },
                unavailable = false,
            ),
        )

    private val stakingUnavailable: ApiResult<StakingDashboard> =
        ApiResult.Success(StakingDashboard.unavailable())

    private fun failure(status: Int): ApiResult<Nothing> =
        ApiResult.Failure(ApiError(status = status, message = "err"))

    private val networkErr: ApiResult<Nothing> =
        ApiResult.NetworkError(IOException("offline"))

    @Test
    fun aggregate_sumsReadableVenuesIntoTotalEquity() {
        val state = PortfolioAggregator.aggregate(
            custody = custody("ETH" to 2.0, "USDC" to 100.0),
            staking = stakingWith("5"),
            spot = spot("BTC" to 10L),
            margin = margin(balance = 50L),
        )
        // 102 (custody) + 10 (spot) + 50 (margin) + 5 (staking)
        assertEquals(167.0, state.totalEquity, 0.0001)
        assertFalse(state.anyLoading)
        assertFalse(state.allEmpty)
        assertEquals(4, state.cards.size)
    }

    @Test
    fun aggregate_custodyFiltersZeroBalances() {
        val state = PortfolioAggregator.aggregate(
            custody = custody("ETH" to 0.0, "USDC" to 3.0),
            staking = stakingUnavailable,
            spot = spot(),
            margin = margin(0L),
        )
        val card = state.card(PortfolioVenue.CUSTODY)!!
        assertEquals(1, card.lines.size)
        assertEquals("USDC", card.lines.first().label)
    }

    @Test
    fun aggregate_oneBrokenVenueDoesNotDropTheOthers() {
        val state = PortfolioAggregator.aggregate(
            custody = failure(404),
            staking = stakingUnavailable,
            spot = spot("BTC" to 7L),
            margin = failure(403),
        )
        assertTrue(state.card(PortfolioVenue.CUSTODY)!!.unavailable)
        assertTrue(state.card(PortfolioVenue.STAKING)!!.unavailable)
        assertTrue(state.card(PortfolioVenue.MARGIN)!!.unavailable)
        val spotCard = state.card(PortfolioVenue.SPOT)!!
        assertFalse(spotCard.unavailable)
        assertEquals(7.0, spotCard.equity, 0.0001)
        // total counts only the one readable venue
        assertEquals(7.0, state.totalEquity, 0.0001)
    }

    @Test
    fun aggregate_networkErrorDegradesThatVenueOnly() {
        val state = PortfolioAggregator.aggregate(
            custody = networkErr,
            staking = stakingWith("2"),
            spot = spot(),
            margin = margin(1L),
        )
        assertTrue(state.card(PortfolioVenue.CUSTODY)!!.unavailable)
        assertEquals(3.0, state.totalEquity, 0.0001) // 2 staking + 1 margin
    }

    @Test
    fun aggregate_liftsOpenPositionOutOfMargin() {
        val pos = PositionSnapshot(
            symbolId = 1,
            qty = -5,
            entryPrice = 30000,
            liquidationPrice = 33000,
            unrealizedPnl = -120,
        )
        val state = PortfolioAggregator.aggregate(
            custody = custody(),
            staking = stakingUnavailable,
            spot = spot(),
            margin = margin(balance = 500L, position = pos),
        )
        assertEquals(1, state.positions.size)
        val p = state.positions.first()
        assertEquals("BTCUSDC", p.symbol)
        assertFalse(p.isLong)
        assertFalse(p.isProfit)
        assertEquals(-120L, p.unrealizedPnl)
    }

    @Test
    fun aggregate_zeroQtyPositionIsNotShown() {
        val pos = PositionSnapshot(1, 0, 0, 0, 0)
        val state = PortfolioAggregator.aggregate(
            custody = custody(),
            staking = stakingUnavailable,
            spot = spot(),
            margin = margin(balance = 10L, position = pos),
        )
        assertTrue(state.positions.isEmpty())
    }

    @Test
    fun aggregate_allEmptyWhenNothingFunded() {
        val state = PortfolioAggregator.aggregate(
            custody = custody("ETH" to 0.0),
            staking = stakingUnavailable,
            spot = spot(),
            margin = failure(404),
        )
        // custody readable but empty, spot readable but empty, margin+staking unavailable, no positions
        assertTrue(state.allEmpty)
        assertEquals(0.0, state.totalEquity, 0.0001)
    }
}
