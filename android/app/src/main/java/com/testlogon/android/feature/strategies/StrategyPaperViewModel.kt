package com.testlogon.android.feature.strategies

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.exchange.ExchangeRepository
import com.testlogon.android.data.strategies.StrategiesRepository
import com.testlogon.android.data.strategies.Strategy
import com.testlogon.android.data.strategies.StrategyLeg
import com.testlogon.android.feature.analysis.MarketStats
import com.testlogon.android.navigation.StrategyPaperDest
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** The interval label used for the client-side basket backtest history reads. */
private const val BACKTEST_INTERVAL = "1d"

/** The paper account's starting notional in cents ($10,000). */
private const val PAPER_START_CENTS = 1_000_000L

data class StrategyPaperUiState(
    val strategyId: String,
    val phase: Phase = Phase.Loading,
    val strategy: Strategy? = null,
    /** True when ANY leg's history was degraded from the recent-window candles read (md/history 404). */
    val degraded: Boolean = false,
    val equityCurve: List<Double> = emptyList(),
    val totalReturnPct: Double? = null,
    val annualizedVolPct: Double? = null,
    val maxDrawdownPct: Double? = null,
    /** The paper account NAV/value following the basket weights over the backtest window (cents). */
    val paperStartCents: Long = PAPER_START_CENTS,
    val paperEndCents: Long? = null,
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, Error, Empty }
}

/**
 * Drives the PAPER-RUN + BACKTEST screen for a strategy. Loads the strategy, then for each basket leg
 * pulls historical closes (reusing [ExchangeRepository.getHistory], which degrades to the recent
 * candles window on a 404 — surfaced via [StrategyPaperUiState.degraded]) and builds a client-side
 * weighted-basket EQUITY CURVE via the pure [StrategyMath.basketEquityCurve]. Stats come from
 * [MarketStats]. The "paper account" is a NAV-tracking simulation: it follows the basket weights and
 * marks a $10,000 notional along the same equity curve (no separate order simulation needed — the
 * basket IS the paper position).
 */
@HiltViewModel
class StrategyPaperViewModel @Inject constructor(
    private val repository: StrategiesRepository,
    private val exchange: ExchangeRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val strategyId: String = savedStateHandle.get<String>(StrategyPaperDest.ARG_STRATEGY_ID).orEmpty()

    private val _uiState = MutableStateFlow(StrategyPaperUiState(strategyId = strategyId))
    val uiState: StateFlow<StrategyPaperUiState> = _uiState.asStateFlow()

    init { load() }

    fun onRetry() = load()

    private fun load() {
        _uiState.update { it.copy(phase = StrategyPaperUiState.Phase.Loading, errorMessage = null) }
        viewModelScope.launch {
            when (val r = repository.strategy(strategyId)) {
                is ApiResult.Success -> {
                    val s = r.data
                    if (s == null || s.legs.isEmpty()) {
                        _uiState.update { it.copy(phase = StrategyPaperUiState.Phase.Empty, strategy = s) }
                        return@launch
                    }
                    _uiState.update { it.copy(strategy = s) }
                    runBacktest(s)
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(phase = StrategyPaperUiState.Phase.Error, errorMessage = r.error.message)
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(phase = StrategyPaperUiState.Phase.Error, errorMessage = "No connection. Check your network and retry.")
                }
            }
        }
    }

    private suspend fun runBacktest(strategy: Strategy) {
        var anyDegraded = false
        val backtestLegs = ArrayList<StrategyMath.BacktestLeg>()
        for (leg: StrategyLeg in strategy.legs) {
            when (val h = exchange.getHistory(leg.symbolId, BACKTEST_INTERVAL)) {
                is ApiResult.Success -> {
                    if (h.data.stub) anyDegraded = true
                    val closes = h.data.bars.map { it.close.toDouble() }
                    if (closes.size >= 2) backtestLegs.add(StrategyMath.BacktestLeg(leg.weightBps, closes))
                }
                is ApiResult.Failure -> anyDegraded = true
                is ApiResult.NetworkError -> {
                    _uiState.update {
                        it.copy(phase = StrategyPaperUiState.Phase.Error, errorMessage = "No connection. Check your network and retry.")
                    }
                    return
                }
            }
        }

        val curve = StrategyMath.basketEquityCurve(backtestLegs)
        val totalRet = StrategyMath.totalReturn(curve)
        val vol = MarketStats.annualizedVolatility(curve)
        val mdd = MarketStats.maxDrawdown(curve)
        val paperEnd = Math.round(PAPER_START_CENTS * (curve.lastOrNull() ?: 1.0))

        _uiState.update {
            it.copy(
                phase = StrategyPaperUiState.Phase.Content,
                degraded = anyDegraded,
                equityCurve = curve,
                totalReturnPct = totalRet * 100.0,
                annualizedVolPct = vol?.let { v -> v * 100.0 },
                maxDrawdownPct = mdd?.let { d -> d * 100.0 },
                paperEndCents = paperEnd,
                errorMessage = null,
            )
        }
    }
}
