package com.testlogon.android.feature.dca

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.cash.CashRepository
import com.testlogon.android.data.dca.CreateDcaPlanRequestDto
import com.testlogon.android.data.dca.DcaFrequency
import com.testlogon.android.data.dca.DcaPlan
import com.testlogon.android.data.dca.DcaRepository
import com.testlogon.android.data.dca.DcaTargetDto
import com.testlogon.android.data.dca.DcaTargetKind
import com.testlogon.android.data.exchange.ExchangeRepository
import com.testlogon.android.data.strategies.StrategiesRepository
import com.testlogon.android.data.tokens.TokensRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** A pickable buy target across the three markets (symbol / creator token / strategy fund). */
data class DcaTargetOption(
    val kind: DcaTargetKind,
    val id: String,
    val label: String,
    val sublabel: String? = null,
)

/** UI state for the create-plan flow. */
data class DcaCreateUiState(
    val loadingTargets: Boolean = true,
    val symbols: List<DcaTargetOption> = emptyList(),
    val tokens: List<DcaTargetOption> = emptyList(),
    val strategies: List<DcaTargetOption> = emptyList(),
    val selectedTarget: DcaTargetOption? = null,
    val amountText: String = "",
    val frequency: DcaFrequency = DcaFrequency.WEEKLY,
    val dayOfWeek: Int = 1,        // Mon..Sun, for WEEKLY
    val dayOfMonth: Int = 1,       // 1..28 (capped), for MONTHLY
    val startTs: Long = 0L,
    val endEnabled: Boolean = false,
    val endTs: Long? = null,
    val budgetEnabled: Boolean = false,
    val budgetText: String = "",
    // Funding: the USD cash wallet.
    val walletBalanceCents: Long = 0L,
    val walletAvailable: Boolean = false,
    val submitting: Boolean = false,
    val errorMessage: String? = null,
    val createdPlanId: String? = null,
) {
    val amountCents: Long? get() = DcaFormat.parseDollarsToCents(amountText)
    val budgetCents: Long? get() = if (budgetEnabled) DcaFormat.parseDollarsToCents(budgetText) else null

    /** Validate purely (schedule + money); target existence checked separately. */
    val validation: DcaSchedule.Validation
        get() {
            val amt = amountCents ?: return DcaSchedule.Validation.Invalid("Enter a buy amount.")
            return DcaSchedule.validatePlan(
                amountCents = amt,
                frequency = frequency,
                dayOfWeek = if (frequency == DcaFrequency.WEEKLY) dayOfWeek else null,
                dayOfMonth = if (frequency == DcaFrequency.MONTHLY) dayOfMonth else null,
                startTs = startTs,
                endTs = if (endEnabled) endTs else null,
                totalBudgetCents = budgetCents,
            )
        }

    val canPreview: Boolean get() = selectedTarget != null && validation is DcaSchedule.Validation.Ok

    /** Build a preview plan (planId placeholder) for the schedule preview + confirm. */
    fun toPreviewPlan(): DcaPlan? {
        val t = selectedTarget ?: return null
        val amt = amountCents ?: return null
        return DcaPlan(
            planId = "preview",
            target = com.testlogon.android.data.dca.DcaTarget(t.kind, t.id, t.label),
            amountCents = amt,
            frequency = frequency,
            dayOfWeek = if (frequency == DcaFrequency.WEEKLY) dayOfWeek else null,
            dayOfMonth = if (frequency == DcaFrequency.MONTHLY) dayOfMonth else null,
            startTs = startTs,
            endTs = if (endEnabled) endTs else null,
            totalBudgetCents = budgetCents,
            status = com.testlogon.android.data.dca.DcaStatus.ACTIVE,
        )
    }
}

/**
 * Drives the CREATE-plan flow. Loads pickable targets from the three shipped markets (exchange symbols +
 * creator tokens + strategy funds), each degrading independently on 404, and reads the USD cash-wallet
 * balance so the funding source can be shown + linked. The pure [DcaSchedule.validatePlan] gates submit,
 * and a schedule preview (next N runs) is shown behind the money-safety confirm. Submit surfaces a
 * rejection / undeployed 404 as a clear error, never a silent success.
 */
@HiltViewModel
class DcaCreateViewModel @Inject constructor(
    private val dcaRepository: DcaRepository,
    private val exchangeRepository: ExchangeRepository,
    private val tokensRepository: TokensRepository,
    private val strategiesRepository: StrategiesRepository,
    private val cashRepository: CashRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(DcaCreateUiState(startTs = todayUtcStartMs()))
    val uiState: StateFlow<DcaCreateUiState> = _uiState.asStateFlow()

    init {
        loadTargets()
        loadWallet()
    }

    private fun todayUtcStartMs(): Long {
        val now = System.currentTimeMillis()
        return (now / DcaSchedule.MS_PER_DAY) * DcaSchedule.MS_PER_DAY
    }

    private fun loadTargets() {
        _uiState.update { it.copy(loadingTargets = true) }
        viewModelScope.launch {
            val symbols = (exchangeRepository.symbols() as? ApiResult.Success)?.data.orEmpty().map {
                DcaTargetOption(DcaTargetKind.SYMBOL, it.symbolId.toString(), it.symbol, if (it.isPerpetual) "Perp" else "Spot")
            }
            val tokens = (tokensRepository.market() as? ApiResult.Success)?.data.orEmpty().map {
                DcaTargetOption(DcaTargetKind.TOKEN, it.tokenId, it.name, it.ticker)
            }
            val strategies = (strategiesRepository.market() as? ApiResult.Success)?.data.orEmpty().map {
                DcaTargetOption(DcaTargetKind.STRATEGY, it.strategyId, it.name, "Strategy fund")
            }
            _uiState.update { it.copy(loadingTargets = false, symbols = symbols, tokens = tokens, strategies = strategies) }
        }
    }

    private fun loadWallet() {
        viewModelScope.launch {
            when (val w = cashRepository.wallet()) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(walletBalanceCents = w.data.balanceCents, walletAvailable = w.data.available)
                }
                else -> Unit
            }
        }
    }

    fun onSelectTarget(option: DcaTargetOption) = _uiState.update { it.copy(selectedTarget = option, errorMessage = null) }
    fun onAmountText(v: String) = _uiState.update { it.copy(amountText = DcaFormat.sanitizeAmountInput(v), errorMessage = null) }
    fun onFrequency(f: DcaFrequency) = _uiState.update { it.copy(frequency = f, errorMessage = null) }
    fun onDayOfWeek(d: Int) = _uiState.update { it.copy(dayOfWeek = d.coerceIn(1, 7)) }
    fun onDayOfMonth(d: Int) = _uiState.update { it.copy(dayOfMonth = d.coerceIn(1, 28)) }
    fun onStartTs(ms: Long) = _uiState.update { it.copy(startTs = (ms / DcaSchedule.MS_PER_DAY) * DcaSchedule.MS_PER_DAY, errorMessage = null) }
    fun onEndEnabled(on: Boolean) = _uiState.update {
        it.copy(endEnabled = on, endTs = if (on) (it.endTs ?: it.startTs + 30 * DcaSchedule.MS_PER_DAY) else it.endTs, errorMessage = null)
    }
    fun onEndTs(ms: Long) = _uiState.update { it.copy(endTs = (ms / DcaSchedule.MS_PER_DAY) * DcaSchedule.MS_PER_DAY, errorMessage = null) }
    fun onBudgetEnabled(on: Boolean) = _uiState.update { it.copy(budgetEnabled = on, errorMessage = null) }
    fun onBudgetText(v: String) = _uiState.update { it.copy(budgetText = DcaFormat.sanitizeAmountInput(v), errorMessage = null) }
    fun consumeError() = _uiState.update { it.copy(errorMessage = null) }

    /** Called AFTER the money-safety confirm is accepted. */
    fun confirmCreate() {
        val s = _uiState.value
        val target = s.selectedTarget
        val amt = s.amountCents
        val v = s.validation
        if (target == null) {
            _uiState.update { it.copy(errorMessage = "Pick something to buy.") }
            return
        }
        if (amt == null || v is DcaSchedule.Validation.Invalid) {
            _uiState.update { it.copy(errorMessage = (v as? DcaSchedule.Validation.Invalid)?.reason ?: "Check the plan details.") }
            return
        }
        val body = CreateDcaPlanRequestDto(
            target = DcaTargetDto(kind = target.kind.wire, id = target.id, label = target.label),
            amountCents = amt,
            frequency = s.frequency.wire,
            dayOfWeek = if (s.frequency == DcaFrequency.WEEKLY) s.dayOfWeek else null,
            dayOfMonth = if (s.frequency == DcaFrequency.MONTHLY) s.dayOfMonth else null,
            startTs = s.startTs / 1_000L, // wire is epoch SECONDS
            endTs = if (s.endEnabled) s.endTs?.let { it / 1_000L } else null,
            totalBudgetCents = s.budgetCents,
            funding = "usd_wallet",
        )
        _uiState.update { it.copy(submitting = true, errorMessage = null) }
        viewModelScope.launch {
            when (val r = dcaRepository.createPlan(body)) {
                is ApiResult.Success -> _uiState.update { it.copy(submitting = false, createdPlanId = r.data.planId) }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(submitting = false, errorMessage = r.error.message.ifBlank { "Recurring buys aren't available yet. No plan was created." })
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(submitting = false, errorMessage = "No connection. No plan was created.")
                }
            }
        }
    }
}
