package com.testlogon.android.feature.pnl

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.exchange.ExchangeRepository
import com.testlogon.android.data.exchange.FillsFees
import com.testlogon.android.data.exchange.FundingPayments
import com.testlogon.android.data.exchange.Instrument
import com.testlogon.android.data.exchange.Liquidations
import com.testlogon.android.data.exchange.TradingRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * ViewModel for the read-only PnL & performance screen. Fans four exchange reads out in parallel
 * (fills-fees, liquidations, funding payments, margin account) plus the symbols catalogue for name
 * resolution, then folds them through the pure [PnlAnalytics.analyze] and projects the result into a
 * render-ready [PnlUiState].
 *
 * fills-fees / liquidations / funding already fold a 404 (undeployed) into an EMPTY success in the
 * repository; the margin account read does NOT (it is a hard read). If EVERY analytics input degraded
 * — the three feeds empty AND the margin read failed — the screen shows an "unavailable" state rather
 * than a misleading all-zero report; a margin-only failure alongside real fills just drops uPnL to 0.
 */
@HiltViewModel
class PnlViewModel @Inject constructor(
    private val trading: TradingRepository,
    private val exchange: ExchangeRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(PnlUiState())
    val uiState: StateFlow<PnlUiState> = _uiState.asStateFlow()

    init {
        refresh()
    }

    fun refresh() {
        _uiState.value = PnlUiState(loading = true)
        viewModelScope.launch {
            _uiState.value = coroutineScope {
                val fillsDef = async { trading.fillsFees() }
                val liqDef = async { trading.liquidations() }
                val fundingDef = async { trading.fundingPayments() }
                val marginDef = async { trading.marginAccount() }
                val symbolsDef = async { exchange.symbols() }
                project(
                    fills = fillsDef.await(),
                    liquidations = liqDef.await(),
                    funding = fundingDef.await(),
                    marginResult = marginDef.await(),
                    symbolsResult = symbolsDef.await(),
                )
            }
        }
    }

    private fun project(
        fills: ApiResult<FillsFees>,
        liquidations: ApiResult<Liquidations>,
        funding: ApiResult<FundingPayments>,
        marginResult: ApiResult<com.testlogon.android.data.exchange.MarginAccount>,
        symbolsResult: ApiResult<List<Instrument>>,
    ): PnlUiState {
        // Each feed already folds an undeployed 404 into an empty success; surface a transient
        // network/failure on a feed as a retryable error rather than a silently-wrong report.
        val fillsData = when (fills) {
            is ApiResult.Success -> fills.data
            is ApiResult.NetworkError -> return PnlUiState(loading = false, error = "Network error. Pull to retry.")
            is ApiResult.Failure -> return PnlUiState(loading = false, error = "Couldn't load fills.")
        }
        val liqData = (liquidations as? ApiResult.Success)?.data ?: Liquidations(emptyList(), 0)
        val fundingData = (funding as? ApiResult.Success)?.data ?: FundingPayments(emptyList(), 0)
        val margin = (marginResult as? ApiResult.Success)?.data
        val unrealized = margin?.position?.unrealizedPnl ?: 0L

        // Whole-surface unavailable ONLY when there is nothing at all to show: no fills, no liq, no
        // funding, and the margin account itself couldn't be read (so uPnL is unknown too).
        if (fillsData.isEmpty && liqData.isEmpty && fundingData.isEmpty && margin == null) {
            return PnlUiState(loading = false, unavailable = true)
        }

        val report = PnlAnalytics.analyze(fillsData, liqData, fundingData, unrealized)
        val names = symbolNames(symbolsResult)

        val stats = PnlStats(
            netRealized = report.netRealized,
            unrealized = report.unrealized,
            totalFees = report.totalFees,
            winRate = report.winRate,
            closingTradeCount = report.closingTradeCount,
            tradeCount = report.tradeCount,
            volume = report.volume,
            fundingTotal = report.fundingTotal,
            liquidationPnl = report.liquidationPnl,
        )
        val rows = report.bySymbol.map { s ->
            SymbolRow(
                symbol = names[s.symbolId] ?: fallbackSymbol(s.symbolId),
                realized = s.realized,
                volume = s.volume,
                fees = s.fees,
                tradeCount = s.tradeCount,
            )
        }
        return PnlUiState(
            loading = false,
            stats = stats,
            bySymbol = rows,
            equityCurve = report.equityCurve.map { EquityCurvePoint(it.tsNs, it.cumulative) },
        )
    }

    private fun symbolNames(result: ApiResult<List<Instrument>>): Map<Int, String> =
        (result as? ApiResult.Success)?.data?.associate { it.symbolId to it.symbol } ?: emptyMap()

    /** Static fallback when the symbols read is unavailable (mirror of the markets catalogue). */
    private fun fallbackSymbol(symbolId: Int): String = when (symbolId) {
        1 -> "BTCUSDC"
        2 -> "ETHUSDC"
        3 -> "SOLUSDC"
        else -> "#" + symbolId
    }
}
