package com.testlogon.android.feature.portfolio

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.custody.CustodyBalances
import com.testlogon.android.data.custody.StakingDashboard
import com.testlogon.android.data.exchange.MarginAccount
import com.testlogon.android.data.exchange.SpotBalance

/**
 * Read-only Portfolio (cross-venue account overview). Aggregates four INDEPENDENT read sources
 * (custody vault balances, custody staking, exchange spot balance, exchange margin account) into a
 * single snapshot. Each source degrades on its own: a 404/403/undeployed venue renders its card as
 * "unavailable" while the others still show. Nothing here moves money - it is a consolidated view.
 */

/** Which venue a card represents, for labelling + iteration order. */
enum class PortfolioVenue(val label: String) {
    CUSTODY("Custody"),
    SPOT("Spot"),
    MARGIN("Margin"),
    STAKING("Staking"),
}

/**
 * One venue card. When [loading] is false, a readable venue carries an [equity] contribution (a coarse
 * cross-venue number) plus [lines] (per-asset / per-field detail); an unreadable venue carries a human
 * [unavailableReason] and [unavailable] = true.
 */
data class VenueCard(
    val venue: PortfolioVenue,
    val loading: Boolean = true,
    /** The venue's contribution to the cross-venue equity total (source-native units, unscaled). */
    val equity: Double = 0.0,
    /** True when this venue could NOT be read (404/403/undeployed/error) - render "unavailable". */
    val unavailable: Boolean = false,
    /** Human reason shown on an unavailable card. */
    val unavailableReason: String? = null,
    /** Per-row detail lines (asset + amount, or field + value). Empty on an unavailable/empty card. */
    val lines: List<PortfolioLine> = emptyList(),
) {
    val isEmpty: Boolean get() = !loading && !unavailable && lines.isEmpty()
    /** True once this venue's equity should count toward the header total. */
    val countsTowardTotal: Boolean get() = !loading && !unavailable
}

/** One labelled detail row inside a venue card. */
data class PortfolioLine(val label: String, val value: String)

/** One open margin position, projected for display (symbol, qty, entry, liq, uPnL). */
data class PortfolioPosition(
    val symbol: String,
    val qty: Long,
    val entryPrice: Long,
    val liquidationPrice: Long,
    val unrealizedPnl: Long,
) {
    val isLong: Boolean get() = qty > 0
    val isProfit: Boolean get() = unrealizedPnl >= 0
}

/**
 * The whole Portfolio screen state. [cards] is always the four venues in a stable order; positions are
 * lifted out of the margin read for the dedicated open-positions section.
 */
data class PortfolioUiState(
    val loading: Boolean = true,
    val cards: List<VenueCard> = PortfolioVenue.entries.map { VenueCard(venue = it) },
    val positions: List<PortfolioPosition> = emptyList(),
) {
    /** Sum of the readable venues' equity contributions - a coarse cross-venue snapshot, not a settled total. */
    val totalEquity: Double get() = cards.filter { it.countsTowardTotal }.sumOf { it.equity }
    /** True while at least one source is still loading. */
    val anyLoading: Boolean get() = cards.any { it.loading }
    /** True when every readable venue is empty AND nothing is loading (whole-screen empty state). */
    val allEmpty: Boolean get() = !anyLoading &&
        cards.none { it.countsTowardTotal && it.lines.isNotEmpty() } && positions.isEmpty()
    fun card(venue: PortfolioVenue): VenueCard? = cards.firstOrNull { it.venue == venue }
}

/**
 * Pure aggregator: folds the four already-fetched [ApiResult]s into a [PortfolioUiState]. Kept free of
 * Android/coroutine deps so it is unit-testable in isolation (the ViewModel just fetches + calls this).
 * A [ApiResult.Failure] whose status is 404/403 (or a soft-unavailable domain flag) degrades that venue
 * to an "unavailable" card; any other Failure/NetworkError likewise degrades (there is nothing the user
 * can act on in a read-only overview), so one broken venue never blanks the screen.
 */
object PortfolioAggregator {

    fun aggregate(
        custody: ApiResult<CustodyBalances>,
        staking: ApiResult<StakingDashboard>,
        spot: ApiResult<SpotBalance>,
        margin: ApiResult<MarginAccount>,
    ): PortfolioUiState {
        val custodyCard = custodyCard(custody)
        val stakingCard = stakingCard(staking)
        val spotCard = spotCard(spot)
        val marginCard = marginCard(margin)
        val positions = (margin as? ApiResult.Success)?.data?.position
            ?.takeIf { it.qty != 0L }
            ?.let {
                listOf(
                    PortfolioPosition(
                        symbol = symbolLabel(it.symbolId),
                        qty = it.qty,
                        entryPrice = it.entryPrice,
                        liquidationPrice = it.liquidationPrice,
                        unrealizedPnl = it.unrealizedPnl,
                    ),
                )
            }.orEmpty()
        return PortfolioUiState(
            loading = false,
            cards = listOf(custodyCard, spotCard, marginCard, stakingCard),
            positions = positions,
        )
    }

    private fun custodyCard(r: ApiResult<CustodyBalances>): VenueCard = when (r) {
        is ApiResult.Success -> {
            val funded = r.data.rows.filter { it.amount > 0.0 }
            VenueCard(
                venue = PortfolioVenue.CUSTODY,
                loading = false,
                equity = funded.sumOf { it.amount },
                lines = funded.map { PortfolioLine(it.symbol, it.amountText) },
            )
        }
        is ApiResult.Failure -> unavailableCard(PortfolioVenue.CUSTODY, r.error.status)
        is ApiResult.NetworkError -> networkCard(PortfolioVenue.CUSTODY)
    }

    private fun stakingCard(r: ApiResult<StakingDashboard>): VenueCard = when (r) {
        is ApiResult.Success -> {
            if (r.data.unavailable) {
                unavailableCard(PortfolioVenue.STAKING, 404)
            } else {
                val total = r.data.positions.sumOf { it.total.toDoubleOrNull() ?: 0.0 }
                VenueCard(
                    venue = PortfolioVenue.STAKING,
                    loading = false,
                    equity = total,
                    lines = r.data.positions.map {
                        PortfolioLine(it.asset + " (" + it.statusLabel + ")", it.total)
                    },
                )
            }
        }
        is ApiResult.Failure -> unavailableCard(PortfolioVenue.STAKING, r.error.status)
        is ApiResult.NetworkError -> networkCard(PortfolioVenue.STAKING)
    }

    private fun spotCard(r: ApiResult<SpotBalance>): VenueCard = when (r) {
        is ApiResult.Success -> {
            val funded = r.data.assets.filter { it.balance > 0L }
            VenueCard(
                venue = PortfolioVenue.SPOT,
                loading = false,
                equity = funded.sumOf { it.balance.toDouble() },
                lines = funded.map { PortfolioLine(it.symbol.ifBlank { "#" + it.asset }, it.balance.toString()) },
            )
        }
        is ApiResult.Failure -> unavailableCard(PortfolioVenue.SPOT, r.error.status)
        is ApiResult.NetworkError -> networkCard(PortfolioVenue.SPOT)
    }

    private fun marginCard(r: ApiResult<MarginAccount>): VenueCard = when (r) {
        is ApiResult.Success -> {
            val a = r.data
            VenueCard(
                venue = PortfolioVenue.MARGIN,
                loading = false,
                equity = a.balance.toDouble(),
                lines = listOf(
                    PortfolioLine("Balance", a.balance.toString()),
                    PortfolioLine("Available", a.availableBalance.toString()),
                    PortfolioLine("Reserved margin", a.reservedMargin.toString()),
                ),
            )
        }
        is ApiResult.Failure -> unavailableCard(PortfolioVenue.MARGIN, r.error.status)
        is ApiResult.NetworkError -> networkCard(PortfolioVenue.MARGIN)
    }

    private fun unavailableCard(venue: PortfolioVenue, status: Int): VenueCard = VenueCard(
        venue = venue,
        loading = false,
        unavailable = true,
        unavailableReason = when (status) {
            403 -> "Not available for this account."
            404 -> "Not available on this deployment."
            else -> "Unavailable right now."
        },
    )

    private fun networkCard(venue: PortfolioVenue): VenueCard = VenueCard(
        venue = venue,
        loading = false,
        unavailable = true,
        unavailableReason = "Network error. Pull to retry.",
    )

    /** Static market-symbol labels (mirror of the markets feature: 1=BTC, 2=ETH, 3=SOL). */
    private fun symbolLabel(symbolId: Int): String = when (symbolId) {
        1 -> "BTCUSDC"
        2 -> "ETHUSDC"
        3 -> "SOLUSDC"
        else -> "#" + symbolId
    }
}
