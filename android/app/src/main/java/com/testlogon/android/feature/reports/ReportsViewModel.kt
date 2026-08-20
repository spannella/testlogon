package com.testlogon.android.feature.reports

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.exchange.ExchangeRepository
import com.testlogon.android.data.exchange.FillsFees
import com.testlogon.android.data.exchange.FundingPayments
import com.testlogon.android.data.exchange.Instrument
import com.testlogon.android.data.exchange.Liquidations
import com.testlogon.android.data.exchange.MarginAccount
import com.testlogon.android.data.exchange.TradingRepository
import com.testlogon.android.feature.pnl.PnlAnalytics
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * ViewModel for the Export & Reporting screen. Fans the same exchange reads the PnL screen uses out in
 * parallel (fills-fees / liquidations / funding / margin + symbols for name resolution), caches the raw
 * reads, then projects a period-scoped [ReportsUiState] purely on the client. Changing the period only
 * re-derives (no re-fetch): the pure [filterFills]/[filterFunding]/[filterLiquidations] + [PnlAnalytics]
 * + [ReportCsv] path runs again against the cached reads.
 *
 * The unavailable / error degradation mirrors the PnL screen: a transient failure on the fills read is
 * a retryable error; when every input degraded (three feeds empty AND the margin read failed) the whole
 * surface is 'unavailable'. A 'now' reference tick is captured per refresh so windows are stable.
 */
@HiltViewModel
class ReportsViewModel @Inject constructor(
    private val trading: TradingRepository,
    private val exchange: ExchangeRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(ReportsUiState())
    val uiState: StateFlow<ReportsUiState> = _uiState.asStateFlow()

    // Cached raw reads from the last successful fetch, re-projected when the period changes.
    private var cachedFills: FillsFees? = null
    private var cachedLiq: Liquidations = Liquidations(emptyList(), 0)
    private var cachedFunding: FundingPayments = FundingPayments(emptyList(), 0)
    private var cachedMargin: MarginAccount? = null
    private var cachedNames: Map<Int, String> = emptyMap()
    private var nowNs: Long = nowTicksNs()

    init {
        refresh()
    }

    fun refresh() {
        val period = _uiState.value.period
        _uiState.value = ReportsUiState(loading = true, period = period)
        nowNs = nowTicksNs()
        viewModelScope.launch {
            _uiState.value = coroutineScope {
                val fillsDef = async { trading.fillsFees() }
                val liqDef = async { trading.liquidations() }
                val fundingDef = async { trading.fundingPayments() }
                val marginDef = async { trading.marginAccount() }
                val symbolsDef = async { exchange.symbols() }
                fetchAndProject(
                    fills = fillsDef.await(),
                    liquidations = liqDef.await(),
                    funding = fundingDef.await(),
                    marginResult = marginDef.await(),
                    symbolsResult = symbolsDef.await(),
                    period = period,
                )
            }
        }
    }

    /** Switch the reporting window; re-derives from the cached reads without a network round-trip. */
    fun setPeriod(period: ReportPeriod) {
        if (period == _uiState.value.period) return
        val fills = cachedFills
        if (fills == null) {
            _uiState.value = _uiState.value.copy(period = period)
            return
        }
        _uiState.value = project(fills, period)
    }

    private fun fetchAndProject(
        fills: ApiResult<FillsFees>,
        liquidations: ApiResult<Liquidations>,
        funding: ApiResult<FundingPayments>,
        marginResult: ApiResult<MarginAccount>,
        symbolsResult: ApiResult<List<Instrument>>,
        period: ReportPeriod,
    ): ReportsUiState {
        val fillsData = when (fills) {
            is ApiResult.Success -> fills.data
            is ApiResult.NetworkError -> return ReportsUiState(loading = false, period = period, error = "Network error. Pull to retry.")
            is ApiResult.Failure -> return ReportsUiState(loading = false, period = period, error = "Couldn't load trade data.")
        }
        val liqData = (liquidations as? ApiResult.Success)?.data ?: Liquidations(emptyList(), 0)
        val fundingData = (funding as? ApiResult.Success)?.data ?: FundingPayments(emptyList(), 0)
        val margin = (marginResult as? ApiResult.Success)?.data

        if (fillsData.isEmpty && liqData.isEmpty && fundingData.isEmpty && margin == null) {
            return ReportsUiState(loading = false, period = period, unavailable = true)
        }

        cachedFills = fillsData
        cachedLiq = liqData
        cachedFunding = fundingData
        cachedMargin = margin
        cachedNames = symbolNames(symbolsResult)
        return project(fillsData, period)
    }

    /** Pure re-projection from cached reads for the given [period]. */
    private fun project(fills: FillsFees, period: ReportPeriod): ReportsUiState {
        val scopedFills = filterFills(fills.fills, period, nowNs)
        val scopedLiq = filterLiquidations(cachedLiq.events, period, nowNs)
        val scopedFunding = filterFunding(cachedFunding.payments, period, nowNs)
        val unrealized = cachedMargin?.position?.unrealizedPnl ?: 0L

        val report = PnlAnalytics.analyze(
            FillsFees(scopedFills, scopedFills.size),
            Liquidations(scopedLiq, scopedLiq.size),
            FundingPayments(scopedFunding, scopedFunding.size),
            unrealized,
        )
        val names = cachedNames
        val stats = ReportStats(
            netRealized = report.netRealized,
            totalFees = report.totalFees,
            volume = report.volume,
            tradeCount = report.tradeCount,
            fillCount = scopedFills.size,
            winRate = report.winRate,
            closingTradeCount = report.closingTradeCount,
        )
        val exports = ReportExports(
            tradeHistoryCsv = ReportCsv.tradeHistory(scopedFills, names),
            pnlSummaryCsv = ReportCsv.pnlSummary(report, names),
            accountStatementCsv = ReportCsv.accountStatement(
                report = report,
                margin = cachedMargin,
                symbolNames = names,
                periodLabel = period.label,
                fromTsNs = period.cutoffNs(nowNs),
                toTsNs = nowNs,
            ),
            tradeHistoryName = "trade-history-" + period.label,
            pnlSummaryName = "pnl-summary-" + period.label,
            accountStatementName = "account-statement-" + period.label,
        )
        return ReportsUiState(loading = false, period = period, stats = stats, exports = exports)
    }

    private fun symbolNames(result: ApiResult<List<Instrument>>): Map<Int, String> =
        (result as? ApiResult.Success)?.data?.associate { it.symbolId to it.symbol } ?: emptyMap()
}
