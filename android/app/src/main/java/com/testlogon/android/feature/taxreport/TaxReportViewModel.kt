package com.testlogon.android.feature.taxreport

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.exchange.ExchangeRepository
import com.testlogon.android.data.exchange.FillFee
import com.testlogon.android.data.exchange.FillsFees
import com.testlogon.android.data.exchange.Instrument
import com.testlogon.android.data.exchange.OrderSide
import com.testlogon.android.data.exchange.PriceMap
import com.testlogon.android.data.exchange.TradingRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.util.Calendar
import java.util.TimeZone
import javax.inject.Inject

/**
 * ViewModel for the Tax Lots & Realized-Gains screen. Assembles the account's fills from the live
 * exchange feed (GET me/fills/fees — the deployed fills-history feed; degrades to empty on 404), the
 * reference prices (GET me/prices; indicative marks), and the symbol catalogue (id -> name). It then
 * runs the pure [TaxLotMath] engine and projects a [TaxReportUiState]. Changing the cost-basis method
 * or the year re-derives from the cached reads with NO network round-trip.
 *
 * NOTE: the fills feed is a single-shot list on this deployment (there is no cursor page token in the
 * wire contract), so "assemble all fills" is one read; if a future contract adds a cursor, the loop
 * below is the single place to thread it. The report covers spot + margin fills (tokens / strategies
 * are future work).
 */
@HiltViewModel
class TaxReportViewModel @Inject constructor(
    private val trading: TradingRepository,
    private val exchange: ExchangeRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(TaxReportUiState())
    val uiState: StateFlow<TaxReportUiState> = _uiState.asStateFlow()

    // Cached raw reads from the last successful fetch, re-projected when method / year changes.
    private var cachedFills: List<FillFee> = emptyList()
    private var cachedNames: Map<Int, String> = emptyMap()
    private var cachedMarks: Map<String, Long> = emptyMap()
    private var marksAvailable: Boolean = false

    init {
        refresh()
    }

    fun refresh() {
        val method = _uiState.value.method
        val year = _uiState.value.year
        _uiState.value = TaxReportUiState(loading = true, method = method, year = year)
        viewModelScope.launch {
            _uiState.value = coroutineScope {
                val fillsDef = async { trading.fillsFees() }
                val pricesDef = async { trading.getPrices() }
                val symbolsDef = async { exchange.symbols() }
                fetchAndProject(
                    fillsResult = fillsDef.await(),
                    pricesResult = pricesDef.await(),
                    symbolsResult = symbolsDef.await(),
                    method = method,
                    year = year,
                )
            }
        }
    }

    fun setMethod(method: TaxLotMath.CostBasisMethod) {
        if (method == _uiState.value.method) return
        _uiState.value = project(method, _uiState.value.year)
    }

    fun setYear(year: TaxYear) {
        if (year == _uiState.value.year) return
        _uiState.value = project(_uiState.value.method, year)
    }

    private fun fetchAndProject(
        fillsResult: ApiResult<FillsFees>,
        pricesResult: ApiResult<PriceMap>,
        symbolsResult: ApiResult<List<Instrument>>,
        method: TaxLotMath.CostBasisMethod,
        year: TaxYear,
    ): TaxReportUiState {
        val fillsData = when (fillsResult) {
            is ApiResult.Success -> fillsResult.data
            is ApiResult.NetworkError -> return TaxReportUiState(loading = false, method = method, year = year, error = "Network error. Pull to retry.")
            is ApiResult.Failure -> return TaxReportUiState(loading = false, method = method, year = year, error = "Couldn't load trade history.")
        }

        cachedNames = (symbolsResult as? ApiResult.Success)?.data?.associate { it.symbolId to it.symbol } ?: emptyMap()
        cachedFills = fillsData.fills

        // Marks: reference USD prices (indicative). Keyed by resolved symbol name -> raw Long price.
        val priceMap = (pricesResult as? ApiResult.Success)?.data
        marksAvailable = priceMap != null && !priceMap.unavailable && priceMap.hasPrices
        cachedMarks = buildMarks(priceMap)

        if (cachedFills.isEmpty()) {
            // Fills history 404 / empty: degrade-on-404 (unavailable when nothing to show at all).
            return TaxReportUiState(
                loading = false,
                method = method,
                year = year,
                unavailable = true,
                degraded = true,
                availableYears = listOf(TaxYear.ALL),
            )
        }
        return project(method, year)
    }

    /**
     * Build the mark map the pure engine expects: symbol -> raw Long price. Reference prices are USD
     * doubles; the fills' prices are raw integer units (price scalers are identity today), so a
     * rounded Long is a faithful indicative mark. Only strictly-positive prices are kept.
     */
    private fun buildMarks(priceMap: PriceMap?): Map<String, Long> {
        if (priceMap == null || priceMap.unavailable) return emptyMap()
        return priceMap.prices.entries.mapNotNull { (sym, px) ->
            if (px > 0.0 && px.isFinite()) sym.uppercase() to Math.round(px) else null
        }.toMap()
    }

    /** Pure re-projection from the cached fills for the given [method] + [year]. */
    private fun project(method: TaxLotMath.CostBasisMethod, year: TaxYear): TaxReportUiState {
        val years = yearsPresent(cachedFills)
        val normalized = cachedFills
            .filter { year.isAll || yearOf(it.tsNs) == year.year }
            .map { it.toNormalized(cachedNames) }

        val result = TaxLotMath.computeLots(normalized, method)
        val summary = TaxLotMath.realizedSummary(result.realized)
        val unrealizedRows = TaxLotMath.unrealized(result.openLots, cachedMarks)

        return TaxReportUiState(
            loading = false,
            method = method,
            year = year,
            degraded = cachedFills.isEmpty(),
            availableYears = years,
            realizedLots = result.realized.sortedByDescending { it.closeTs },
            summary = summary,
            openLots = result.openLots.sortedBy { it.openTs },
            unrealized = unrealizedRows,
            marksUnavailable = !marksAvailable || (result.openLots.isNotEmpty() && unrealizedRows.isEmpty()),
            csv = TaxLotMath.lotsToCsv(result.realized.sortedByDescending { it.closeTs }),
            csvName = "tax-lots-" + method.name.lowercase() + "-" + year.label,
        )
    }

    /** Distinct calendar years (UTC) present in [fills], descending, prefixed with ALL. */
    private fun yearsPresent(fills: List<FillFee>): List<TaxYear> {
        val years = fills.mapNotNull { f -> yearOf(f.tsNs)?.let { TaxYear(it) } }
            .distinct()
            .sortedByDescending { it.year }
        return listOf(TaxYear.ALL) + years
    }

    private fun FillFee.toNormalized(names: Map<Int, String>): TaxLotMath.NormalizedFill =
        TaxLotMath.NormalizedFill(
            tsNs = tsNs,
            symbol = names[symbolId] ?: ("#" + symbolId),
            side = when (side) {
                OrderSide.BUY -> "buy"
                OrderSide.SELL -> "sell"
                null -> ""
            },
            qty = qty,
            priceCents = price,
            feeCents = fee,
        )

    private fun yearOf(tsNs: Long): Int? {
        if (tsNs <= 0L) return null
        val cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"))
        cal.timeInMillis = tsNs / 1_000_000L
        return cal.get(Calendar.YEAR)
    }
}
