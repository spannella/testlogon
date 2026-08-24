package com.testlogon.android.feature.dca

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.dca.DcaPlan
import com.testlogon.android.data.dca.DcaRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** UI state for the DCA plans list. */
data class DcaPlansUiState(
    val loading: Boolean = true,
    val plans: List<DcaPlan> = emptyList(),
    val actingPlanId: String? = null,
    val errorMessage: String? = null,
    val successMessage: String? = null,
    /** True when the last load succeeded but returned no plans (runner may be pending backend-side). */
    val emptyPendingBackend: Boolean = false,
) {
    val isEmpty: Boolean get() = !loading && plans.isEmpty()
}

/**
 * Drives the DCA / recurring-buys PLANS list. Loading DEGRADES on 404 to an honest empty state that names
 * the pending backend runner; the per-plan pause / resume / cancel mutations surface a rejection (or a 404
 * from an undeployed runner) as a clear error, never a silent success, and refresh the list on success.
 */
@HiltViewModel
class DcaPlansViewModel @Inject constructor(
    private val repository: DcaRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(DcaPlansUiState())
    val uiState: StateFlow<DcaPlansUiState> = _uiState.asStateFlow()

    init {
        refresh()
    }

    fun refresh() {
        _uiState.update { it.copy(loading = true, errorMessage = null) }
        viewModelScope.launch {
            when (val r = repository.plans()) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(
                        loading = false,
                        plans = r.data.sortedWith(compareBy({ p -> p.status.ordinal }, { p -> p.nextRunTs ?: Long.MAX_VALUE })),
                        emptyPendingBackend = r.data.isEmpty(),
                    )
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(loading = false, errorMessage = r.error.message.ifBlank { "Couldn't load your recurring buys." })
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(loading = false, errorMessage = "No connection. Pull to retry.")
                }
            }
        }
    }

    fun consumeMessages() = _uiState.update { it.copy(errorMessage = null, successMessage = null) }

    fun pause(planId: String) = mutate(planId, "Plan paused.") { repository.pause(planId) }
    fun resume(planId: String) = mutate(planId, "Plan resumed.") { repository.resume(planId) }
    fun cancel(planId: String) = mutate(planId, "Plan cancelled.") { repository.cancel(planId) }

    private fun mutate(planId: String, okMessage: String, block: suspend () -> ApiResult<DcaPlan>) {
        _uiState.update { it.copy(actingPlanId = planId, errorMessage = null, successMessage = null) }
        viewModelScope.launch {
            when (val r = block()) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(actingPlanId = null, successMessage = okMessage) }
                    refresh()
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(actingPlanId = null, errorMessage = r.error.message.ifBlank { "That action isn't available right now." })
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(actingPlanId = null, errorMessage = "No connection. Nothing changed.")
                }
            }
        }
    }
}
