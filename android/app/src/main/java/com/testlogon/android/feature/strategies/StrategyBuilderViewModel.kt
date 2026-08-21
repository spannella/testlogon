package com.testlogon.android.feature.strategies

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.exchange.ExchangeRepository
import com.testlogon.android.data.exchange.Instrument
import com.testlogon.android.data.strategies.RebalanceRule
import com.testlogon.android.data.strategies.Redemption
import com.testlogon.android.data.strategies.RedemptionDto
import com.testlogon.android.data.strategies.RedemptionType
import com.testlogon.android.data.strategies.StrategiesRepository
import com.testlogon.android.data.strategies.StrategyKind
import com.testlogon.android.data.strategies.StrategyLeg
import com.testlogon.android.data.strategies.StrategyLegDto
import com.testlogon.android.data.strategies.UpsertStrategyRequestDto
import com.testlogon.android.navigation.StrategyBuilderDest
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** One editable leg row in the builder: a chosen symbol + a weight-percent text field. */
data class LegDraft(
    val symbolId: Int,
    val weightPctText: String = "",
) {
    /** Weight in bps parsed from the percent field (e.g. "40" -> 4000). Null when invalid. */
    val weightBps: Int?
        get() {
            val pct = weightPctText.trim().toDoubleOrNull() ?: return null
            if (pct < 0.0 || pct > 100.0) return null
            return (pct * 100.0).toInt()
        }
}

data class StrategyBuilderUiState(
    val editingId: String? = null,
    val loading: Boolean = false,
    val name: String = "",
    val description: String = "",
    val kind: StrategyKind = StrategyKind.BASKET,
    val availableSymbols: List<Instrument> = emptyList(),
    val legs: List<LegDraft> = emptyList(),
    val rebalance: RebalanceRule = RebalanceRule.NONE,
    val thresholdPctText: String = "5",
    val minInvestmentText: String = "100",
    val maxAumText: String = "1000000",
    val mgmtFeePctText: String = "2",
    val perfFeePctText: String = "20",
    val highWaterMark: Boolean = true,
    val redemptionType: RedemptionType = RedemptionType.INSTANT,
    val noticeDaysText: String = "7",
    val lockupDaysText: String = "0",
    val submitting: Boolean = false,
    val errorMessage: String? = null,
    val savedStrategyId: String? = null,
    val didPublish: Boolean = false,
) {
    val legModels: List<StrategyLeg>
        get() = legs.mapNotNull { d -> d.weightBps?.let { StrategyLeg(d.symbolId, it) } }

    val totalWeightBps: Int get() = StrategyMath.totalWeightBps(legModels)

    val weightsValid: Boolean get() = StrategyMath.weightsValid(legModels) && legModels.size == legs.size

    val minInvestmentCents: Long? get() = dollarsToCents(minInvestmentText)
    val maxAumCents: Long? get() = dollarsToCents(maxAumText)
    val mgmtFeeBps: Int? get() = pctToBps(mgmtFeePctText)
    val perfFeeBps: Int? get() = pctToBps(perfFeePctText)
    val thresholdBps: Int? get() = if (rebalance == RebalanceRule.THRESHOLD) pctToBps(thresholdPctText) else null

    val canSave: Boolean
        get() = name.isNotBlank() &&
            weightsValid &&
            minInvestmentCents != null &&
            maxAumCents != null &&
            mgmtFeeBps != null &&
            perfFeeBps != null &&
            (rebalance != RebalanceRule.THRESHOLD || thresholdBps != null) &&
            !submitting
}

private fun dollarsToCents(text: String): Long? {
    val v = text.trim().toDoubleOrNull() ?: return null
    if (v < 0.0) return null
    return Math.round(v * 100.0)
}

private fun pctToBps(text: String): Int? {
    val v = text.trim().toDoubleOrNull() ?: return null
    if (v < 0.0 || v > 100.0) return null
    return (v * 100.0).toInt()
}

/**
 * Drives the STRATEGY BUILDER: name/description/kind, the basket leg editor (symbol picker + weight,
 * with live 100% validation), rebalance cadence, and the fund params (min investment, max AUM, dual
 * fee + HWM toggle, redemption policy). Save persists a DRAFT; publishing is gated behind a
 * money-safety confirm and only offered once weights are a valid 100% basket. Loads the instrument
 * catalogue from [ExchangeRepository] for the leg picker (degrades to the known symbols on 404).
 *
 * When opened with a strategy id it loads that strategy for EDITING (creator-owned drafts).
 */
@HiltViewModel
class StrategyBuilderViewModel @Inject constructor(
    private val repository: StrategiesRepository,
    private val exchange: ExchangeRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val editId: String? = savedStateHandle.get<String>(StrategyBuilderDest.ARG_STRATEGY_ID)
        ?.takeIf { it.isNotBlank() && it != StrategyBuilderDest.NEW }

    private val _uiState = MutableStateFlow(StrategyBuilderUiState(editingId = editId, loading = true))
    val uiState: StateFlow<StrategyBuilderUiState> = _uiState.asStateFlow()

    init { bootstrap() }

    private fun bootstrap() {
        viewModelScope.launch {
            val symbols = (exchange.symbols() as? ApiResult.Success)?.data.orEmpty()
            _uiState.update { it.copy(availableSymbols = symbols, loading = editId != null) }
            if (editId != null) loadForEdit(editId, symbols)
        }
    }

    private suspend fun loadForEdit(id: String, symbols: List<Instrument>) {
        when (val r = repository.strategy(id)) {
            is ApiResult.Success -> {
                val s = r.data
                if (s == null) {
                    _uiState.update { it.copy(loading = false, errorMessage = "That strategy isn't available (backend pending).") }
                    return
                }
                _uiState.update {
                    it.copy(
                        loading = false,
                        name = s.name,
                        description = s.description,
                        kind = s.kind.takeIf { k -> k != StrategyKind.UNKNOWN } ?: StrategyKind.BASKET,
                        legs = s.legs.map { leg -> LegDraft(leg.symbolId, (leg.weightBps / 100.0).toString().trimEnd('0').trimEnd('.')) },
                        rebalance = s.rebalance.takeIf { rb -> rb != RebalanceRule.UNKNOWN } ?: RebalanceRule.NONE,
                        thresholdPctText = s.thresholdBps?.let { b -> (b / 100.0).toString() } ?: it.thresholdPctText,
                        minInvestmentText = (s.minInvestmentCents / 100.0).toString(),
                        maxAumText = (s.maxAumCents / 100.0).toString(),
                        mgmtFeePctText = (s.mgmtFeeBps / 100.0).toString(),
                        perfFeePctText = (s.perfFeeBps / 100.0).toString(),
                        highWaterMark = s.highWaterMark,
                        redemptionType = s.redemption.type.takeIf { t -> t != RedemptionType.UNKNOWN } ?: RedemptionType.INSTANT,
                        noticeDaysText = s.redemption.noticeDays?.toString() ?: it.noticeDaysText,
                        lockupDaysText = s.redemption.lockupDays?.toString() ?: it.lockupDaysText,
                    )
                }
            }
            is ApiResult.Failure -> _uiState.update { it.copy(loading = false, errorMessage = r.error.message) }
            is ApiResult.NetworkError -> _uiState.update { it.copy(loading = false, errorMessage = "No connection.") }
        }
    }

    // ---- field events ----
    fun onName(v: String) = _uiState.update { it.copy(name = v, errorMessage = null) }
    fun onDescription(v: String) = _uiState.update { it.copy(description = v, errorMessage = null) }
    fun onKind(k: StrategyKind) = _uiState.update { it.copy(kind = k, errorMessage = null) }
    fun onRebalance(r: RebalanceRule) = _uiState.update { it.copy(rebalance = r, errorMessage = null) }
    fun onThreshold(v: String) = _uiState.update { it.copy(thresholdPctText = v.numeric(), errorMessage = null) }
    fun onMinInvestment(v: String) = _uiState.update { it.copy(minInvestmentText = v.numeric(), errorMessage = null) }
    fun onMaxAum(v: String) = _uiState.update { it.copy(maxAumText = v.numeric(), errorMessage = null) }
    fun onMgmtFee(v: String) = _uiState.update { it.copy(mgmtFeePctText = v.numeric(), errorMessage = null) }
    fun onPerfFee(v: String) = _uiState.update { it.copy(perfFeePctText = v.numeric(), errorMessage = null) }
    fun onHighWaterMark(v: Boolean) = _uiState.update { it.copy(highWaterMark = v) }
    fun onRedemptionType(t: RedemptionType) = _uiState.update { it.copy(redemptionType = t) }
    fun onNoticeDays(v: String) = _uiState.update { it.copy(noticeDaysText = v.filter { c -> c.isDigit() }) }
    fun onLockupDays(v: String) = _uiState.update { it.copy(lockupDaysText = v.filter { c -> c.isDigit() }) }

    fun addLeg(symbolId: Int) = _uiState.update {
        if (it.legs.any { l -> l.symbolId == symbolId }) it
        else it.copy(legs = it.legs + LegDraft(symbolId), errorMessage = null)
    }

    fun removeLeg(symbolId: Int) = _uiState.update {
        it.copy(legs = it.legs.filterNot { l -> l.symbolId == symbolId }, errorMessage = null)
    }

    fun onLegWeight(symbolId: Int, v: String) = _uiState.update { st ->
        st.copy(legs = st.legs.map { if (it.symbolId == symbolId) it.copy(weightPctText = v.numeric()) else it }, errorMessage = null)
    }

    /** Evenly split 100% across the current legs (helper for the builder). */
    fun equalizeWeights() = _uiState.update { st ->
        val n = st.legs.size
        if (n == 0) return@update st
        val each = 10_000 / n
        val remainder = 10_000 - each * n
        st.copy(
            legs = st.legs.mapIndexed { i, l ->
                val bps = each + if (i == 0) remainder else 0
                l.copy(weightPctText = (bps / 100.0).toString().trimEnd('0').trimEnd('.'))
            },
            errorMessage = null,
        )
    }

    fun consumeSaved() = _uiState.update { it.copy(savedStrategyId = null, didPublish = false) }

    /** Save (create or update) the DRAFT. On success, optionally publish (money-safety confirmed). */
    fun save(thenPublish: Boolean) {
        val s = _uiState.value
        if (!s.canSave) {
            _uiState.update { it.copy(errorMessage = "Fix the fields: weights must total 100% and every value must be valid.") }
            return
        }
        val body = UpsertStrategyRequestDto(
            name = s.name.trim(),
            description = s.description.trim(),
            kind = when (s.kind) { StrategyKind.RULE -> "rule"; else -> "basket" },
            legs = s.legModels.map { StrategyLegDto(it.symbolId, it.weightBps) },
            rebalance = s.rebalance.name.lowercase(),
            thresholdBps = s.thresholdBps,
            minInvestmentCents = s.minInvestmentCents ?: 0L,
            maxAumCents = s.maxAumCents ?: 0L,
            mgmtFeeBps = s.mgmtFeeBps ?: 0,
            perfFeeBps = s.perfFeeBps ?: 0,
            highWaterMark = s.highWaterMark,
            redemption = RedemptionDto(
                type = s.redemptionType.name.lowercase(),
                noticeDays = if (s.redemptionType == RedemptionType.NOTICE) s.noticeDaysText.toIntOrNull() else null,
                lockupDays = s.lockupDaysText.toIntOrNull(),
            ),
        )
        _uiState.update { it.copy(submitting = true, errorMessage = null) }
        viewModelScope.launch {
            val saveResult = if (s.editingId != null) repository.update(s.editingId, body) else repository.create(body)
            when (saveResult) {
                is ApiResult.Success -> {
                    val id = saveResult.data.strategyId.ifBlank { s.editingId.orEmpty() }
                    if (thenPublish && id.isNotBlank()) {
                        when (val pub = repository.publish(id)) {
                            is ApiResult.Success -> _uiState.update { it.copy(submitting = false, savedStrategyId = id, didPublish = true) }
                            is ApiResult.Failure -> _uiState.update { it.copy(submitting = false, errorMessage = publishError(pub.error.message)) }
                            is ApiResult.NetworkError -> _uiState.update { it.copy(submitting = false, errorMessage = "No connection. Publish did not go through.") }
                        }
                    } else {
                        _uiState.update { it.copy(submitting = false, savedStrategyId = id.ifBlank { null }, didPublish = false) }
                    }
                }
                is ApiResult.Failure -> _uiState.update { it.copy(submitting = false, errorMessage = saveError(saveResult.error.message)) }
                is ApiResult.NetworkError -> _uiState.update { it.copy(submitting = false, errorMessage = "No connection. Your strategy was not saved.") }
            }
        }
    }

    private fun saveError(msg: String): String =
        msg.ifBlank { "Saving isn't available yet (backend pending). Your strategy was not saved." }

    private fun publishError(msg: String): String =
        msg.ifBlank { "Publishing isn't available yet (backend pending). The draft was saved but not published." }

    private fun String.numeric(): String = filter { it.isDigit() || it == '.' }
}
