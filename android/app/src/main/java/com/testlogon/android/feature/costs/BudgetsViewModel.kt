package com.testlogon.android.feature.costs

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.costs.CostBudgetInDto
import com.testlogon.android.data.costs.CostBudgetUpdateInDto
import com.testlogon.android.data.costs.CostsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject
import kotlin.math.roundToLong

/** Drives [BudgetsUiState]. Mirrors the web BudgetManagerPage (list + create + delete + auto-pause toggle). */
@HiltViewModel
class BudgetsViewModel @Inject constructor(
    private val repository: CostsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(BudgetsUiState())
    val uiState: StateFlow<BudgetsUiState> = _uiState.asStateFlow()

    private val _effects = Channel<CostsEffect>(Channel.BUFFERED)
    val effects: Flow<CostsEffect> = _effects.receiveAsFlow()

    init {
        load(fromUser = false)
    }

    fun onRefresh() = load(fromUser = true)
    fun onRetry() = load(fromUser = true)

    // ---- Create form ----
    fun onOpenForm() = _uiState.update { it.copy(form = BudgetFormState(isOpen = true)) }
    fun onDismissForm() {
        if (_uiState.value.form.isSubmitting) return
        _uiState.update { it.copy(form = BudgetFormState(isOpen = false)) }
    }
    fun onNameChange(v: String) = _uiState.update { it.copy(form = it.form.copy(name = v)) }
    fun onScopeChange(v: String) = _uiState.update { it.copy(form = it.form.copy(scope = v)) }
    fun onScopeRefChange(v: String) = _uiState.update { it.copy(form = it.form.copy(scopeRef = v)) }
    fun onPeriodChange(v: String) = _uiState.update { it.copy(form = it.form.copy(period = v)) }
    fun onLimitChange(v: String) = _uiState.update { it.copy(form = it.form.copy(limitDollars = v)) }
    fun onThresholdChange(v: String) = _uiState.update { it.copy(form = it.form.copy(thresholdPct = v)) }

    fun onSubmitForm() {
        val form = _uiState.value.form
        if (!form.canSubmit) return
        _uiState.update { it.copy(form = it.form.copy(isSubmitting = true)) }
        val body = CostBudgetInDto(
            name = form.name.trim(),
            scope = form.scope,
            scopeRef = if (form.scope == "overall") null else form.scopeRef.trim().takeIf { it.isNotEmpty() },
            period = form.period,
            limitCents = ((form.limitDollars.toDoubleOrNull() ?: 0.0) * 100).roundToLong(),
            alertThresholdPct = form.thresholdPct.toIntOrNull() ?: 80,
        )
        viewModelScope.launch {
            when (repository.createBudget(body)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(form = BudgetFormState(isOpen = false)) }
                    _effects.send(CostsEffect.ShowMessage(R.string.costs_budget_created))
                    load(fromUser = true)
                }
                else -> {
                    _uiState.update { it.copy(form = it.form.copy(isSubmitting = false)) }
                    _effects.send(CostsEffect.ShowMessage(R.string.costs_action_failed))
                }
            }
        }
    }

    // ---- Row actions ----
    fun onDelete(budgetId: String) = viewModelScope.launch {
        when (repository.deleteBudget(budgetId)) {
            is ApiResult.Success -> {
                _effects.send(CostsEffect.ShowMessage(R.string.costs_budget_deleted))
                load(fromUser = true)
            }
            else -> _effects.send(CostsEffect.ShowMessage(R.string.costs_action_failed))
        }
    }

    fun onToggleAutoPause(budgetId: String, next: Boolean) = viewModelScope.launch {
        when (repository.updateBudget(budgetId, CostBudgetUpdateInDto(autoPauseOnExceed = next))) {
            is ApiResult.Success -> load(fromUser = true)
            else -> _effects.send(CostsEffect.ShowMessage(R.string.costs_action_failed))
        }
    }

    private fun load(fromUser: Boolean) {
        val state = _uiState.value
        if (state.isRefreshing) return
        val hasContent = state.phase == CostsPhase.Content || state.phase == CostsPhase.Empty
        _uiState.update {
            it.copy(
                phase = if (hasContent) it.phase else CostsPhase.Loading,
                isRefreshing = fromUser && hasContent,
            )
        }
        viewModelScope.launch {
            when (val result = repository.loadBudgets()) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(
                        phase = if (result.data.isEmpty()) CostsPhase.Empty else CostsPhase.Content,
                        budgets = result.data,
                        isRefreshing = false,
                        errorMessage = null,
                    )
                }
                is ApiResult.Failure ->
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _uiState.update { it.copy(phase = CostsPhase.SessionExpired, isRefreshing = false) }
                    } else {
                        _uiState.update {
                            it.copy(phase = CostsPhase.Error, isRefreshing = false, errorMessage = result.error.message)
                        }
                    }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(phase = CostsPhase.Offline, isRefreshing = false, errorMessage = OFFLINE_FALLBACK)
                }
            }
        }
    }

    private companion object {
        private const val HTTP_UNAUTHORIZED = 401
        private const val OFFLINE_FALLBACK = "Could not reach the server. Pull down to retry."
    }
}
