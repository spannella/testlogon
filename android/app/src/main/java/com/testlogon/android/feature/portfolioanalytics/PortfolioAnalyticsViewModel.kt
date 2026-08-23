package com.testlogon.android.feature.portfolioanalytics

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.custody.CustodyReader
import com.testlogon.android.data.exchange.ExchangeRepository
import com.testlogon.android.data.exchange.Instrument
import com.testlogon.android.data.exchange.PriceMap
import com.testlogon.android.data.exchange.TradingRepository
import com.testlogon.android.data.strategies.StrategiesRepository
import com.testlogon.android.data.tokens.TokensRepository
import com.testlogon.android.feature.analysis.MarketStats
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject
import kotlin.math.abs
import kotlin.math.roundToLong

/**
 * Read-only Portfolio Analytics ViewModel. Fans out the SIX independent holding sources in parallel —
 * custody balances + staking ([CustodyReader]); spot + margin + indicative prices
 * ([TradingRepository]); creator tokens ([TokensRepository]); strategy funds ([StrategiesRepository])
 * — normalizes each into a [NormalizedPosition] in indicative USD cents, then folds everything through
 * the pure [PortfolioAnalyticsMath]. Per-asset return series for the risk math come from the exchange
 * [ExchangeRepository.getHistory] (degrade-on-404 handled inside the repo). Every source degrades
 * independently: an unreadable source contributes nothing and is noted in
 * [PortfolioAnalyticsUiState.sourceIssues] instead of blanking the screen. No writes.
 */
@HiltViewModel
class PortfolioAnalyticsViewModel @Inject constructor(
    private val custody: CustodyReader,
    private val trading: TradingRepository,
    private val exchange: ExchangeRepository,
    private val tokens: TokensRepository,
    private val strategies: StrategiesRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(PortfolioAnalyticsUiState())
    val uiState: StateFlow<PortfolioAnalyticsUiState> = _uiState.asStateFlow()

    init {
        refresh()
    }

    /** Change the allocation grouping without re-fetching (recompute from the held positions). */
    fun onSelectAllocationBy(by: AllocationBy) {
        val cur = _uiState.value
        if (cur.allocationBy == by) return
        _uiState.value = cur.copy(
            allocationBy = by,
            allocation = PortfolioAnalyticsMath.allocation(cur.positions, by),
        )
    }

    fun refresh() {
        _uiState.value = PortfolioAnalyticsUiState(loading = true, allocationBy = _uiState.value.allocationBy)
        viewModelScope.launch {
            val built = coroutineScope {
                val custodyDef = async { custody.getBalance() }
                val stakingDef = async { custody.getStaking() }
                val spotDef = async { trading.spotBalance() }
                val marginDef = async { trading.marginAccount() }
                val pricesDef = async { trading.getPrices() }
                val instrumentsDef = async { exchange.symbols() }
                val issuedDef = async { tokens.issued() }
                val tokenMarketDef = async { tokens.market() }
                val strategiesMineDef = async { strategies.mine() }

                val prices = (pricesDef.await() as? ApiResult.Success)?.data ?: PriceMap.unavailable()
                val instruments = (instrumentsDef.await() as? ApiResult.Success)?.data ?: emptyList()
                val instrumentBySymbol = instruments.associateBy { it.symbol.uppercase() }

                val positions = ArrayList<NormalizedPosition>()
                val issues = ArrayList<String>()

                normalizeCustody(custodyDef.await(), prices, positions, issues)
                normalizeStaking(stakingDef.await(), prices, positions, issues)
                normalizeSpot(spotDef.await(), instruments, prices, positions, issues)
                normalizeMargin(marginDef.await(), prices, positions, issues)
                normalizeTokens(issuedDef.await(), tokenMarketDef.await(), positions, issues)
                normalizeStrategies(strategiesMineDef.await(), positions, issues)

                // Risk math needs a per-asset return series for the priced EXCHANGE assets we hold.
                val riskKeys = positions.map { it.key.uppercase() }.toSet()
                    .mapNotNull { instrumentBySymbol[it] }
                    .distinctBy { it.symbolId }
                val risk = computeRisk(positions, riskKeys)

                buildState(positions, prices, issues, risk)
            }
            _uiState.value = built
        }
    }

    // ---------------- normalization per source ----------------

    private fun normalizeCustody(
        r: ApiResult<*>,
        prices: PriceMap,
        out: MutableList<NormalizedPosition>,
        issues: MutableList<String>,
    ) {
        when (r) {
            is ApiResult.Success -> {
                val balances = r.data as? com.testlogon.android.data.custody.CustodyBalances ?: return
                balances.rows.filter { it.amount > 0.0 }.forEach { row ->
                    val usd = prices.priceFor(row.symbol)?.let { it * row.amount }
                    if (usd != null) {
                        out.add(
                            NormalizedPosition(
                                key = row.symbol.uppercase(),
                                label = row.symbol,
                                group = "Custody",
                                assetClass = classOf(row.symbol),
                                valueCents = toCents(usd),
                                qty = row.amount,
                            ),
                        )
                    }
                }
            }
            is ApiResult.Failure -> issues.add("Custody: " + reason(r.error.status))
            is ApiResult.NetworkError -> issues.add("Custody: network error")
        }
    }

    private fun normalizeStaking(
        r: ApiResult<*>,
        prices: PriceMap,
        out: MutableList<NormalizedPosition>,
        issues: MutableList<String>,
    ) {
        when (r) {
            is ApiResult.Success -> {
                val dash = r.data as? com.testlogon.android.data.custody.StakingDashboard ?: return
                if (dash.unavailable) return
                dash.positions.forEach { p ->
                    val amount = p.total.toDoubleOrNull()
                    val usd = if (amount != null) prices.priceFor(p.asset)?.let { it * amount } else null
                    if (usd != null && amount != null) {
                        out.add(
                            NormalizedPosition(
                                key = p.asset.uppercase(),
                                label = p.asset + " (staked)",
                                group = "Staking",
                                assetClass = "Staking",
                                valueCents = toCents(usd),
                                qty = amount,
                            ),
                        )
                    }
                }
            }
            is ApiResult.Failure -> issues.add("Staking: " + reason(r.error.status))
            is ApiResult.NetworkError -> issues.add("Staking: network error")
        }
    }

    private fun normalizeSpot(
        r: ApiResult<*>,
        instruments: List<Instrument>,
        prices: PriceMap,
        out: MutableList<NormalizedPosition>,
        issues: MutableList<String>,
    ) {
        when (r) {
            is ApiResult.Success -> {
                val spot = r.data as? com.testlogon.android.data.exchange.SpotBalance ?: return
                spot.assets.filter { it.balance > 0L }.forEach { a ->
                    val sym = a.symbol.ifBlank {
                        instruments.firstOrNull { it.symbolId == a.asset }?.symbol.orEmpty()
                    }
                    val usd = sym.takeIf { it.isNotBlank() }?.let { prices.priceFor(it) }?.let { it * a.balance.toDouble() }
                    if (usd != null && sym.isNotBlank()) {
                        out.add(
                            NormalizedPosition(
                                key = sym.uppercase(),
                                label = sym,
                                group = "Spot",
                                assetClass = classOf(sym),
                                valueCents = toCents(usd),
                                qty = a.balance.toDouble(),
                            ),
                        )
                    }
                }
            }
            is ApiResult.Failure -> issues.add("Spot: " + reason(r.error.status))
            is ApiResult.NetworkError -> issues.add("Spot: network error")
        }
    }

    private fun normalizeMargin(
        r: ApiResult<*>,
        prices: PriceMap,
        out: MutableList<NormalizedPosition>,
        issues: MutableList<String>,
    ) {
        when (r) {
            is ApiResult.Success -> {
                val acct = r.data as? com.testlogon.android.data.exchange.MarginAccount ?: return
                // Free margin cash (USDC-denominated), valued via the quote asset.
                if (acct.balance > 0L) {
                    val usd = (prices.priceFor("USDC") ?: prices.priceFor("USD"))?.let { it * acct.balance.toDouble() }
                    if (usd != null) {
                        out.add(
                            NormalizedPosition(
                                key = "USDC",
                                label = "Margin cash",
                                group = "Margin",
                                assetClass = "Cash",
                                valueCents = toCents(usd),
                                qty = acct.balance.toDouble(),
                            ),
                        )
                    }
                }
                // The open position, valued as an indicative USD notional via the underlying's price.
                val pos = acct.position
                if (pos != null && pos.qty != 0L) {
                    val sym = marginSymbol(pos.symbolId)
                    val unitPrice = prices.priceFor(sym)
                    if (unitPrice != null && unitPrice > 0.0) {
                        val notionalUsd = abs(pos.qty).toDouble() * unitPrice
                        out.add(
                            NormalizedPosition(
                                key = sym.uppercase(),
                                label = sym + " position",
                                group = "Margin",
                                assetClass = classOf(sym),
                                valueCents = toCents(notionalUsd),
                                side = if (pos.qty >= 0) PositionSide.LONG else PositionSide.SHORT,
                                qty = pos.qty.toDouble(),
                            ),
                        )
                    }
                }
            }
            is ApiResult.Failure -> issues.add("Margin: " + reason(r.error.status))
            is ApiResult.NetworkError -> issues.add("Margin: network error")
        }
    }

    private fun normalizeTokens(
        issued: ApiResult<*>,
        market: ApiResult<*>,
        out: MutableList<NormalizedPosition>,
        issues: MutableList<String>,
    ) {
        val issuedFail = issued is ApiResult.Failure || issued is ApiResult.NetworkError
        val marketFail = market is ApiResult.Failure || market is ApiResult.NetworkError
        if (issuedFail && marketFail) {
            issues.add("Creator tokens: unavailable")
            return
        }
        @Suppress("UNCHECKED_CAST")
        val issuedList = (issued as? ApiResult.Success)?.data as? List<com.testlogon.android.data.tokens.Token> ?: emptyList()
        // Tokens I issued: I hold the un-sold supply; value it at the cleared IPO price when listed.
        issuedList.forEach { t ->
            val price = t.clearingPrice
            if (price != null && price > 0L && t.totalSupply > 0L) {
                // Indicative cents value of my creator holding (supply * price/token cents).
                val valueCents = t.totalSupply * price
                out.add(
                    NormalizedPosition(
                        key = "TOK:" + t.ticker.uppercase(),
                        label = t.ticker + " (my token)",
                        group = "Creator tokens",
                        assetClass = "Creator token",
                        valueCents = valueCents,
                        qty = t.totalSupply.toDouble(),
                    ),
                )
            }
        }
    }

    private fun normalizeStrategies(
        mine: ApiResult<*>,
        out: MutableList<NormalizedPosition>,
        issues: MutableList<String>,
    ) {
        when (mine) {
            is ApiResult.Success -> {
                @Suppress("UNCHECKED_CAST")
                val list = mine.data as? List<com.testlogon.android.data.strategies.Strategy> ?: emptyList()
                list.forEach { s ->
                    val aum = s.aumCents
                    if (aum != null && aum > 0L) {
                        out.add(
                            NormalizedPosition(
                                key = "FUND:" + s.strategyId,
                                label = s.name + " (fund)",
                                group = "Strategy funds",
                                assetClass = "Fund",
                                valueCents = aum,
                                qty = 0.0,
                            ),
                        )
                    }
                }
            }
            is ApiResult.Failure -> issues.add("Strategy funds: " + reason(mine.error.status))
            is ApiResult.NetworkError -> issues.add("Strategy funds: network error")
        }
    }

    // ---------------- risk math (per-asset return series -> vol/corr/VaR) ----------------

    private data class RiskInputs(
        val volBps: Int?,
        val parametric95: Long,
        val parametric99: Long,
        val historical95: Long,
        val diversification: Int,
        val covered: Int,
        val limitedHistory: Boolean,
        val unavailable: Boolean,
    )

    private suspend fun computeRisk(
        positions: List<NormalizedPosition>,
        riskInstruments: List<Instrument>,
    ): RiskInputs {
        val totalValue = PortfolioAnalyticsMath.totalValueCents(positions)
        if (riskInstruments.isEmpty() || totalValue <= 0L) {
            return RiskInputs(null, 0, 0, 0, 0, 0, false, unavailable = true)
        }
        // Per-asset gross value (cents) for the priced exchange assets, keyed by uppercase symbol.
        val valueByKey = HashMap<String, Long>()
        positions.forEach { valueByKey[it.key.uppercase()] = (valueByKey[it.key.uppercase()] ?: 0L) + abs(it.valueCents) }

        val seriesBySymbol = LinkedHashMap<String, List<Double>>()
        var limited = false
        for (inst in riskInstruments) {
            val bars = when (val h = exchange.getHistory(inst.symbolId, "1d")) {
                is ApiResult.Success -> {
                    if (h.data.stub) limited = true
                    h.data.bars.map { it.close.toDouble() }
                }
                else -> emptyList()
            }
            if (bars.size >= 2) seriesBySymbol[inst.symbol.uppercase()] = bars
        }
        if (seriesBySymbol.isEmpty()) {
            return RiskInputs(null, 0, 0, 0, 0, 0, limited, unavailable = true)
        }

        val keys = seriesBySymbol.keys.toList()
        // Sub-portfolio value covered by return series (only the priced exchange assets).
        val coveredValue = keys.sumOf { valueByKey[it] ?: 0L }
        if (coveredValue <= 0L) {
            return RiskInputs(null, 0, 0, 0, 0, 0, limited, unavailable = true)
        }
        val weightsBps = keys.map { k ->
            Math.round((valueByKey[k] ?: 0L).toDouble() / coveredValue.toDouble() * 10_000.0).toInt()
        }
        val volsBps = keys.map { k ->
            val v = MarketStats.annualizedVolatility(seriesBySymbol[k].orEmpty())
            ((v ?: 0.0) * 10_000.0).toInt().coerceAtLeast(0)
        }
        // Correlation matrix over aligned log-returns.
        val logReturns = keys.map { MarketStats.logReturns(seriesBySymbol[it].orEmpty()) }
        val corr = keys.indices.map { i ->
            keys.indices.map { j ->
                if (i == j) 1.0 else (MarketStats.correlation(logReturns[i], logReturns[j]) ?: 0.0)
            }
        }
        val portVolBps = PortfolioAnalyticsMath.portfolioVolatilityBps(weightsBps, volsBps, corr)
        val diversification = PortfolioAnalyticsMath.diversificationScore(weightsBps, corr)

        // Parametric VaR uses the DAILY vol (de-annualize) on the covered sub-portfolio value.
        val dailyVolBps = portVolBps?.let { (it / kotlin.math.sqrt(MarketStats.ANNUALIZATION_PERIODS)).toInt() } ?: 0
        val param95 = PortfolioAnalyticsMath.parametricVarCents(coveredValue, dailyVolBps, Z_95)
        val param99 = PortfolioAnalyticsMath.parametricVarCents(coveredValue, dailyVolBps, Z_99)

        // Historical VaR: blend per-asset daily log-returns by weight into a portfolio return series.
        val minLen = logReturns.filter { it.isNotEmpty() }.minOfOrNull { it.size } ?: 0
        val blended = ArrayList<Double>(minLen)
        for (t in 0 until minLen) {
            var r = 0.0
            for (i in keys.indices) {
                val w = weightsBps[i] / 10_000.0
                val series = logReturns[i]
                r += w * series[series.size - minLen + t]
            }
            blended.add(r)
        }
        val hist95 = PortfolioAnalyticsMath.historicalVarCents(coveredValue, blended, 0.95)

        return RiskInputs(
            volBps = portVolBps,
            parametric95 = param95,
            parametric99 = param99,
            historical95 = hist95,
            diversification = diversification,
            covered = keys.size,
            limitedHistory = limited,
            unavailable = false,
        )
    }

    // ---------------- fold into UI state ----------------

    private fun buildState(
        positions: List<NormalizedPosition>,
        prices: PriceMap,
        issues: List<String>,
        risk: RiskInputs,
    ): PortfolioAnalyticsUiState {
        val by = _uiState.value.allocationBy
        val allocation = PortfolioAnalyticsMath.allocation(positions, by)
        val assetSlices = PortfolioAnalyticsMath.allocation(positions, AllocationBy.ASSET)
        val concentration = PortfolioAnalyticsMath.concentration(assetSlices)
        val exposure = PortfolioAnalyticsMath.exposure(positions)
        return PortfolioAnalyticsUiState(
            loading = false,
            positions = positions,
            totalValueCents = PortfolioAnalyticsMath.totalValueCents(positions),
            allocationBy = by,
            allocation = allocation,
            concentration = if (positions.isEmpty()) null else concentration,
            exposure = if (positions.isEmpty()) null else exposure,
            portfolioVolBps = risk.volBps,
            parametricVar95Cents = risk.parametric95,
            parametricVar99Cents = risk.parametric99,
            historicalVar95Cents = risk.historical95,
            diversificationScore = risk.diversification,
            riskAssetsCovered = risk.covered,
            limitedHistory = risk.limitedHistory,
            riskUnavailable = risk.unavailable,
            sourceIssues = issues,
            pricesStub = !prices.unavailable && prices.stub && positions.isNotEmpty(),
            allEmpty = positions.isEmpty(),
        )
    }

    // ---------------- helpers ----------------

    private fun toCents(usd: Double): Long = (usd * 100.0).roundToLong().coerceAtLeast(0L)

    private fun reason(status: Int): String = when (status) {
        403 -> "not available for this account"
        404 -> "not available on this deployment"
        else -> "unavailable right now"
    }

    /** Coarse asset-class bucketing for the CLASS allocation view. */
    private fun classOf(symbol: String): String = when (symbol.trim().uppercase()) {
        "USD", "USDC", "USDT", "DAI" -> "Cash"
        else -> "Crypto"
    }

    private fun marginSymbol(symbolId: Int): String = when (symbolId) {
        1 -> "BTC"
        2 -> "ETH"
        3 -> "SOL"
        else -> "#$symbolId"
    }

    private companion object {
        const val Z_95 = 1.645
        const val Z_99 = 2.326
    }
}
