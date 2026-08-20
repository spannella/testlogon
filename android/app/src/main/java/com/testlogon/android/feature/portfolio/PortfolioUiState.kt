package com.testlogon.android.feature.portfolio

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.custody.CustodyBalances
import com.testlogon.android.data.custody.StakingDashboard
import com.testlogon.android.data.exchange.MarginAccount
import com.testlogon.android.data.exchange.PriceMap
import com.testlogon.android.data.exchange.SpotBalance

/**
 * Read-only Portfolio (cross-venue account overview). Aggregates four INDEPENDENT read sources
 * (custody vault balances, custody staking, exchange spot balance, exchange margin account) into a
 * single snapshot. Each source degrades on its own: a 404/403/undeployed venue renders its card as
 * "unavailable" while the others still show. Nothing here moves money - it is a consolidated view.
 *
 * A fifth, OPTIONAL read (GET /me/prices) provides indicative per-asset USD reference prices. When it
 * is readable, each priced balance is FX-normalized (amount * usdPrice) and summed into a real USD
 * [PortfolioUiState.totalEquityUsd]; the header shows that USD figure (labelled "indicative (stub
 * prices)" while the edge serves stub marks). On a 404 (undeployed) prices degrade to unavailable and
 * the header falls back to the coarse source-native [PortfolioUiState.totalEquity] with its caveat.
 */

/** Which venue a card represents, for labelling + iteration order. */
enum class PortfolioVenue(val label: String) {
    CUSTODY("Custody"),
    SPOT("Spot"),
    MARGIN("Margin"),
    STAKING("Staking"),
    /** The shared client-side PAPER account (only shown while paper mode is ON). */
    PAPER("Paper"),
}

/** The four real venues shown in live mode (PAPER is surfaced only while paper mode is ON). */
val LIVE_VENUES: List<PortfolioVenue> =
    listOf(PortfolioVenue.CUSTODY, PortfolioVenue.SPOT, PortfolioVenue.MARGIN, PortfolioVenue.STAKING)

/**
 * One venue card. When [loading] is false, a readable venue carries an [equity] contribution (a coarse
 * cross-venue number, source-native units) plus [lines] (per-asset / per-field detail); an unreadable
 * venue carries a human [unavailableReason] and [unavailable] = true. [equityUsd] is the venue's USD
 * contribution once its priced balances are FX-normalized (0.0 when no line on this venue is priced).
 */
data class VenueCard(
    val venue: PortfolioVenue,
    val loading: Boolean = true,
    /** The venue's contribution to the cross-venue equity total (source-native units, unscaled). */
    val equity: Double = 0.0,
    /** The venue's USD-normalized contribution (sum of amount*usdPrice over its PRICED lines). */
    val equityUsd: Double = 0.0,
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

/**
 * One labelled detail row inside a venue card. [usdValue] is the row's FX-normalized USD value when the
 * asset is priced (null when unpriced or on a non-asset field row), and [usdText] renders it compactly.
 */
data class PortfolioLine(
    val label: String,
    val value: String,
    val usdValue: Double? = null,
) {
    val isPriced: Boolean get() = usdValue != null
}

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
 *
 * [priced] is true when the USD price read succeeded AND at least one readable balance could be valued;
 * only then is [totalEquityUsd] meaningful and the header shows USD. [pricesStub] flags the indicative
 * caveat ("stub prices") when the edge reports source=="stub".
 */
data class PortfolioUiState(
    val loading: Boolean = true,
    val cards: List<VenueCard> = LIVE_VENUES.map { VenueCard(venue = it) },
    val positions: List<PortfolioPosition> = emptyList(),
    /** True when a usable USD price map valued at least one balance -> show USD equity. */
    val priced: Boolean = false,
    /** True when the priced marks are the edge STUB placeholders (indicative-only caveat). */
    val pricesStub: Boolean = false,
    /** True when the whole screen reflects the shared PAPER account (drives the PAPER badge). */
    val paper: Boolean = false,
) {
    /** Sum of the readable venues' equity contributions - a coarse cross-venue snapshot, not a settled total. */
    val totalEquity: Double get() = cards.filter { it.countsTowardTotal }.sumOf { it.equity }
    /** Real USD equity: sum of each readable venue's FX-normalized (amount*usdPrice) contribution. */
    val totalEquityUsd: Double get() = cards.filter { it.countsTowardTotal }.sumOf { it.equityUsd }
    /** True while at least one source is still loading. */
    val anyLoading: Boolean get() = cards.any { it.loading }
    /** True when every readable venue is empty AND nothing is loading (whole-screen empty state). */
    val allEmpty: Boolean get() = !anyLoading &&
        cards.none { it.countsTowardTotal && it.lines.isNotEmpty() } && positions.isEmpty()
    fun card(venue: PortfolioVenue): VenueCard? = cards.firstOrNull { it.venue == venue }
}

/**
 * Pure aggregator: folds the four already-fetched [ApiResult]s (plus an OPTIONAL [PriceMap]) into a
 * [PortfolioUiState]. Kept free of Android/coroutine deps so it is unit-testable in isolation (the
 * ViewModel just fetches + calls this). A [ApiResult.Failure] whose status is 404/403 (or a soft-
 * unavailable domain flag) degrades that venue to an "unavailable" card; any other Failure/NetworkError
 * likewise degrades (there is nothing the user can act on in a read-only overview), so one broken venue
 * never blanks the screen.
 *
 * When [prices] is a readable, non-empty [PriceMap], each readable balance line is FX-normalized to USD
 * (amount * usdPrice) and rolled into that venue's [VenueCard.equityUsd] + the header [totalEquityUsd].
 * If prices are unavailable (404) or value nothing, [PortfolioUiState.priced] stays false and the header
 * keeps its coarse source-native total.
 */
object PortfolioAggregator {

    fun aggregate(
        custody: ApiResult<CustodyBalances>,
        staking: ApiResult<StakingDashboard>,
        spot: ApiResult<SpotBalance>,
        margin: ApiResult<MarginAccount>,
        prices: PriceMap = PriceMap.unavailable(),
    ): PortfolioUiState {
        val pm = prices.takeIf { !it.unavailable && it.hasPrices }
        val custodyCard = custodyCard(custody, pm)
        val stakingCard = stakingCard(staking, pm)
        val spotCard = spotCard(spot, pm)
        val marginCard = marginCard(margin, pm)
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
        val cards = listOf(custodyCard, spotCard, marginCard, stakingCard)
        // priced only when we had a usable map AND it valued at least one readable line.
        val valuedSomething = pm != null && cards.any { it.countsTowardTotal && it.equityUsd > 0.0 }
        return PortfolioUiState(
            loading = false,
            cards = cards,
            positions = positions,
            priced = valuedSomething,
            pricesStub = valuedSomething && prices.stub,
        )
    }

    private fun custodyCard(r: ApiResult<CustodyBalances>, pm: PriceMap?): VenueCard = when (r) {
        is ApiResult.Success -> {
            val funded = r.data.rows.filter { it.amount > 0.0 }
            val lines = funded.map { row ->
                val usd = pm?.priceFor(row.symbol)?.let { it * row.amount }
                PortfolioLine(row.symbol, row.amountText, usdValue = usd)
            }
            VenueCard(
                venue = PortfolioVenue.CUSTODY,
                loading = false,
                equity = funded.sumOf { it.amount },
                equityUsd = lines.sumOf { it.usdValue ?: 0.0 },
                lines = lines,
            )
        }
        is ApiResult.Failure -> unavailableCard(PortfolioVenue.CUSTODY, r.error.status)
        is ApiResult.NetworkError -> networkCard(PortfolioVenue.CUSTODY)
    }

    private fun stakingCard(r: ApiResult<StakingDashboard>, pm: PriceMap?): VenueCard = when (r) {
        is ApiResult.Success -> {
            if (r.data.unavailable) {
                unavailableCard(PortfolioVenue.STAKING, 404)
            } else {
                val lines = r.data.positions.map { p ->
                    val amount = p.total.toDoubleOrNull()
                    val usd = if (amount != null) pm?.priceFor(p.asset)?.let { it * amount } else null
                    PortfolioLine(p.asset + " (" + p.statusLabel + ")", p.total, usdValue = usd)
                }
                VenueCard(
                    venue = PortfolioVenue.STAKING,
                    loading = false,
                    equity = r.data.positions.sumOf { it.total.toDoubleOrNull() ?: 0.0 },
                    equityUsd = lines.sumOf { it.usdValue ?: 0.0 },
                    lines = lines,
                )
            }
        }
        is ApiResult.Failure -> unavailableCard(PortfolioVenue.STAKING, r.error.status)
        is ApiResult.NetworkError -> networkCard(PortfolioVenue.STAKING)
    }

    private fun spotCard(r: ApiResult<SpotBalance>, pm: PriceMap?): VenueCard = when (r) {
        is ApiResult.Success -> {
            val funded = r.data.assets.filter { it.balance > 0L }
            val lines = funded.map { a ->
                val label = a.symbol.ifBlank { "#" + a.asset }
                val usd = a.symbol.takeIf { it.isNotBlank() }?.let { pm?.priceFor(it) }?.let { it * a.balance.toDouble() }
                PortfolioLine(label, a.balance.toString(), usdValue = usd)
            }
            VenueCard(
                venue = PortfolioVenue.SPOT,
                loading = false,
                equity = funded.sumOf { it.balance.toDouble() },
                equityUsd = lines.sumOf { it.usdValue ?: 0.0 },
                lines = lines,
            )
        }
        is ApiResult.Failure -> unavailableCard(PortfolioVenue.SPOT, r.error.status)
        is ApiResult.NetworkError -> networkCard(PortfolioVenue.SPOT)
    }

    private fun marginCard(r: ApiResult<MarginAccount>, pm: PriceMap?): VenueCard = when (r) {
        is ApiResult.Success -> {
            val a = r.data
            // Margin balance is a USDC-denominated cash figure; value it in USD via the quote asset.
            val usd = (pm?.priceFor("USDC") ?: pm?.priceFor("USD"))?.let { it * a.balance.toDouble() }
            VenueCard(
                venue = PortfolioVenue.MARGIN,
                loading = false,
                equity = a.balance.toDouble(),
                equityUsd = usd ?: 0.0,
                lines = listOf(
                    PortfolioLine("Balance", a.balance.toString(), usdValue = usd),
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
