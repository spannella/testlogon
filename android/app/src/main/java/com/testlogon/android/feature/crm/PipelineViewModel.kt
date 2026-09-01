package com.testlogon.android.feature.crm

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.crm.CrmSalesMath
import com.testlogon.android.data.crm.Opportunity
import com.testlogon.android.data.crm.OpportunityCreateInDto
import com.testlogon.android.data.crm.SalesRepository
import com.testlogon.android.data.crm.StageConfigItem
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** One stage column on the pipeline board with its opportunities and roll-ups. */
data class PipelineColumn(
    val stageKey: String,
    val label: String,
    val opportunities: List<Opportunity>,
    val totalAmountCents: Long,
    val weightedAmountCents: Long,
)

data class PipelineUiState(
    val phase: Phase = Phase.Loading,
    val columns: List<PipelineColumn> = emptyList(),
    val stages: List<StageConfigItem> = emptyList(),
    val openWeightedCents: Long = 0,
    val openAmountCents: Long = 0,
    val wonAmountCents: Long = 0,
    val winRatePct: Int = 0,
    val moduleDisabled: Boolean = false,
    val isRefreshing: Boolean = false,
    val isOffline: Boolean = false,
    val errorMessage: String? = null,
    // create-opportunity sheet
    val createSubmitting: Boolean = false,
    val createError: String? = null,
    // per-card stage-move progress
    val movingOppId: String? = null,
    val actionMessage: String? = null,
) {
    enum class Phase { Loading, Content, Error }
}

/**
 * CRM-AND-1 — drives the opportunities pipeline board (stage columns + weighted-forecast header) and the
 * create / stage-move actions.
 *
 * A load pulls the combined pipeline snapshot; a 404/503 (module disabled) degrades to an empty,
 * non-error board with a banner. Roll-ups are computed purely via [CrmSalesMath].
 */
@HiltViewModel
class PipelineViewModel @Inject constructor(
    private val repository: SalesRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(PipelineUiState())
    val uiState: StateFlow<PipelineUiState> = _uiState.asStateFlow()

    init {
        load(fromUser = false)
    }

    fun onRefresh() = load(fromUser = true)
    fun onRetry() = load(fromUser = true)

    private fun load(fromUser: Boolean) {
        val hasContent = _uiState.value.columns.isNotEmpty()
        _uiState.update {
            it.copy(
                phase = if (hasContent) it.phase else PipelineUiState.Phase.Loading,
                isRefreshing = fromUser && hasContent,
            )
        }
        viewModelScope.launch {
            when (val r = repository.pipeline()) {
                is ApiResult.Success -> {
                    val opps = r.data.opportunities
                    val columns = buildColumns(r.data.stages, opps)
                    _uiState.update {
                        it.copy(
                            phase = PipelineUiState.Phase.Content,
                            columns = columns,
                            stages = r.data.stages,
                            openWeightedCents = CrmSalesMath.openPipelineWeightedCents(opps),
                            openAmountCents = CrmSalesMath.openPipelineAmountCents(opps),
                            wonAmountCents = CrmSalesMath.wonAmountCents(opps),
                            winRatePct = CrmSalesMath.winRatePct(opps),
                            moduleDisabled = r.data.moduleDisabled,
                            isRefreshing = false,
                            isOffline = false,
                            errorMessage = null,
                        )
                    }
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(
                        phase = if (it.columns.isNotEmpty()) PipelineUiState.Phase.Content else PipelineUiState.Phase.Error,
                        isRefreshing = false,
                        isOffline = false,
                        errorMessage = r.error.message,
                    )
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(
                        phase = if (it.columns.isNotEmpty()) PipelineUiState.Phase.Content else PipelineUiState.Phase.Error,
                        isRefreshing = false,
                        isOffline = true,
                        errorMessage = "You're offline. Try again.",
                    )
                }
            }
        }
    }

    private fun buildColumns(
        stages: List<StageConfigItem>,
        opps: List<Opportunity>,
    ): List<PipelineColumn> {
        val order = if (stages.isNotEmpty()) stages.map { it.stageKey } else CrmSalesMath.STAGE_ORDER
        val labels = stages.associate { it.stageKey to it.label }
        val byStage = opps.groupBy { it.stage }
        val extras = byStage.keys.filter { it !in order }
        return (order + extras).map { key ->
            val items = byStage[key].orEmpty().sortedByDescending { it.amountCents }
            PipelineColumn(
                stageKey = key,
                label = labels[key] ?: CrmSalesMath.stageLabel(key),
                opportunities = items,
                totalAmountCents = items.sumOf { maxOf(0L, it.amountCents) },
                weightedAmountCents = items.sumOf {
                    CrmSalesMath.weightedAmountCents(it.amountCents, it.probability, it.stage)
                },
            )
        }
    }

    fun moveStage(oppId: String, newStage: String) {
        _uiState.update { it.copy(movingOppId = oppId, actionMessage = null) }
        viewModelScope.launch {
            val message = when (val r = repository.moveStage(oppId, newStage)) {
                is ApiResult.Success -> "Moved to ${CrmSalesMath.stageLabel(newStage)}."
                is ApiResult.Failure -> r.error.message
                is ApiResult.NetworkError -> "You're offline. Try again."
            }
            _uiState.update { it.copy(movingOppId = null, actionMessage = message) }
            load(fromUser = false)
        }
    }

    fun createOpportunity(
        name: String,
        stage: String,
        amountDollars: String,
        closeDateEpochSeconds: Long,
        onCreated: () -> Unit,
    ) {
        if (name.isBlank()) {
            _uiState.update { it.copy(createError = "Name is required.") }
            return
        }
        val cents = parseDollarsToCents(amountDollars)
        if (cents == null) {
            _uiState.update { it.copy(createError = "Enter a valid amount.") }
            return
        }
        _uiState.update { it.copy(createSubmitting = true, createError = null) }
        viewModelScope.launch {
            val body = OpportunityCreateInDto(
                name = name.trim(),
                stage = stage,
                amountCents = cents,
                closeDate = closeDateEpochSeconds,
                probability = CrmSalesMath.defaultProbabilityFor(stage),
            )
            when (val r = repository.create(body)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(createSubmitting = false, createError = null) }
                    onCreated()
                    load(fromUser = false)
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(createSubmitting = false, createError = r.error.message)
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(createSubmitting = false, createError = "You're offline. Try again.")
                }
            }
        }
    }

    fun clearCreateError() = _uiState.update { it.copy(createError = null) }
    fun clearActionMessage() = _uiState.update { it.copy(actionMessage = null) }

    /** "1,234.56" / "1234" -> cents; null on garbage. Pure enough for the create sheet gate. */
    private fun parseDollarsToCents(raw: String): Long? {
        val cleaned = raw.trim().replace(",", "").removePrefix("$")
        if (cleaned.isBlank()) return null
        val value = cleaned.toDoubleOrNull() ?: return null
        if (value < 0) return null
        return Math.round(value * 100.0)
    }
}
