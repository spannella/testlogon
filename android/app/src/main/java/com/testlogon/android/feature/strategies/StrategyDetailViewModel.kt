package com.testlogon.android.feature.strategies

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.strategies.InvestorPosition
import com.testlogon.android.data.strategies.StrategiesRepository
import com.testlogon.android.data.strategies.Strategy
import com.testlogon.android.data.strategies.StrategyFees
import com.testlogon.android.data.strategies.StrategyHolding
import com.testlogon.android.data.strategies.StrategyNav
import com.testlogon.android.data.exchange.watchlist.WatchKind
import com.testlogon.android.data.exchange.watchlist.WatchlistStore
import com.testlogon.android.data.exchange.watchlist.isWatched as isWatchedIn
import com.testlogon.android.navigation.StrategyDetailDest
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

data class StrategyDetailUiState(
    val strategyId: String,
    val phase: Phase = Phase.Loading,
    val strategy: Strategy? = null,
    val nav: StrategyNav? = null,
    val holdings: List<StrategyHolding> = emptyList(),
    val position: InvestorPosition? = null,
    val fees: StrategyFees? = null,
    /** True when the caller authored this strategy (drives creator-view fee accrual + edit/publish). */
    val isCreator: Boolean = false,
    val errorMessage: String? = null,
    val actionMessage: String? = null,
    val actionInFlight: Boolean = false,
) {
    enum class Phase { Loading, Content, Error }

    /** The NAV per unit to price a subscription/redemption at (cents); falls back to par. */
    val navPerUnitCents: Long
        get() = nav?.navPerUnit?.takeIf { it > 0 } ?: strategy?.navPerUnit?.takeIf { it > 0 } ?: StrategyMath.PAR_NAV_CENTS
}

/**
 * Drives the STRATEGY DETAIL surface: NAV, holdings, fee schedule + the pooled-NAV assumption note,
 * Invest (min-size + capacity validated + money-safety confirmed), the investor position, Redeem
 * (respecting the policy), and the creator-view fee accrual + edit/publish affordances. Every read
 * degrades to an honest empty/pending state on 404; every mutation surfaces a clear result message
 * (never a silent success), then refreshes the affected reads.
 */
@HiltViewModel
class StrategyDetailViewModel @Inject constructor(
    private val repository: StrategiesRepository,
    private val watchlist: WatchlistStore,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val strategyId: String = savedStateHandle.get<String>(StrategyDetailDest.ARG_STRATEGY_ID).orEmpty()

    private val _uiState = MutableStateFlow(StrategyDetailUiState(strategyId = strategyId))
    val uiState: StateFlow<StrategyDetailUiState> = _uiState.asStateFlow()

    /** Whether this strategy is on the unified watchlist (drives the detail star). */
    val isWatched: StateFlow<Boolean> = watchlist.items
        .map { items -> isWatchedIn(items, WatchKind.STRATEGY, strategyId) }
        .stateIn(
            viewModelScope,
            SharingStarted.WhileSubscribed(5_000),
            watchlist.isWatched(WatchKind.STRATEGY, strategyId),
        )

    /** Toggle this strategy on/off the unified watchlist. */
    fun toggleWatch() { watchlist.toggle(WatchKind.STRATEGY, strategyId) }

    init { load() }

    fun onRetry() = load()

    fun consumeActionMessage() = _uiState.update { it.copy(actionMessage = null) }

    private fun load() {
        _uiState.update { it.copy(phase = StrategyDetailUiState.Phase.Loading, errorMessage = null) }
        viewModelScope.launch {
            when (val r = repository.strategy(strategyId)) {
                is ApiResult.Success -> {
                    val s = r.data
                    if (s == null) {
                        _uiState.update {
                            it.copy(
                                phase = StrategyDetailUiState.Phase.Content,
                                strategy = null,
                                errorMessage = null,
                            )
                        }
                    } else {
                        _uiState.update { it.copy(phase = StrategyDetailUiState.Phase.Content, strategy = s) }
                    }
                    refreshReads()
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(phase = StrategyDetailUiState.Phase.Error, errorMessage = r.error.message)
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(phase = StrategyDetailUiState.Phase.Error, errorMessage = "No connection. Check your network and retry.")
                }
            }
        }
    }

    private suspend fun refreshReads() {
        val nav = (repository.nav(strategyId) as? ApiResult.Success)?.data
        val holdings = (repository.holdings(strategyId) as? ApiResult.Success)?.data.orEmpty()
        val position = (repository.position(strategyId) as? ApiResult.Success)?.data
        val fees = (repository.fees(strategyId) as? ApiResult.Success)?.data
        _uiState.update {
            it.copy(nav = nav, holdings = holdings, position = position, fees = fees)
        }
    }

    /** Whether an [amountCents] subscription is valid against the min-size + remaining-capacity checks. */
    fun investValidationError(amountCents: Long): String? {
        val s = _uiState.value.strategy ?: return "Strategy unavailable."
        if (!StrategyMath.meetsMinInvestment(amountCents, s.minInvestmentCents)) {
            return "Below the minimum investment of ${StrategyMath.formatCents(s.minInvestmentCents)}."
        }
        val currentAum = _uiState.value.nav?.aumCents ?: s.aumCents ?: 0L
        if (!StrategyMath.withinCapacity(amountCents, s.maxAumCents, currentAum)) {
            val remaining = StrategyMath.capacityRemaining(s.maxAumCents, currentAum)
            return "Exceeds remaining capacity" + (remaining?.let { " of ${StrategyMath.formatCents(it)}." } ?: ".")
        }
        return null
    }

    /** Estimated units issued for [amountCents] at the current NAV (for the confirm preview). */
    fun estimatedUnits(amountCents: Long): Double =
        StrategyMath.unitsForInvestment(amountCents, _uiState.value.navPerUnitCents) / 1_000_000.0

    /** Called AFTER the invest money-safety confirm is accepted. */
    fun confirmInvest(amountCents: Long) {
        val err = investValidationError(amountCents)
        if (err != null) {
            _uiState.update { it.copy(actionMessage = err) }
            return
        }
        _uiState.update { it.copy(actionInFlight = true) }
        viewModelScope.launch {
            when (val r = repository.invest(strategyId, amountCents)) {
                is ApiResult.Success -> {
                    _uiState.update {
                        it.copy(
                            actionInFlight = false,
                            actionMessage = if (r.data.accepted) "Invested ${StrategyMath.formatCents(amountCents)}." else (r.data.message ?: "The server did not confirm the investment."),
                        )
                    }
                    refreshReads()
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(actionInFlight = false, actionMessage = r.error.message.ifBlank { "Investing isn't available yet (backend pending). Nothing was charged." })
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(actionInFlight = false, actionMessage = "No connection. Nothing was charged.")
                }
            }
        }
    }

    /** Called AFTER the redeem confirm is accepted. [units] is whole units; converted to micro-units. */
    fun confirmRedeem(units: Long) {
        val microUnits = units * 1_000_000L
        val held = _uiState.value.position?.units ?: 0L
        if (microUnits <= 0L || microUnits > held) {
            _uiState.update { it.copy(actionMessage = "You can't redeem more units than you hold.") }
            return
        }
        _uiState.update { it.copy(actionInFlight = true) }
        viewModelScope.launch {
            when (val r = repository.redeem(strategyId, microUnits)) {
                is ApiResult.Success -> {
                    _uiState.update {
                        it.copy(
                            actionInFlight = false,
                            actionMessage = if (r.data.accepted) "Redemption submitted." else (r.data.message ?: "The server did not confirm the redemption."),
                        )
                    }
                    refreshReads()
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(actionInFlight = false, actionMessage = r.error.message.ifBlank { "Redemption isn't available yet (backend pending)." })
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(actionInFlight = false, actionMessage = "No connection. Your redemption was not submitted.")
                }
            }
        }
    }
}
