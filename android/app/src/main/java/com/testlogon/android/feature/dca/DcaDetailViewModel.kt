package com.testlogon.android.feature.dca

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.dca.DcaPlan
import com.testlogon.android.data.dca.DcaRepository
import com.testlogon.android.data.dca.DcaRun
import com.testlogon.android.navigation.DcaDetailDest
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/** UI state for a single plan's detail (plan + run history). */
data class DcaDetailUiState(
    val loading: Boolean = true,
    val plan: DcaPlan? = null,
    val runs: List<DcaRun> = emptyList(),
    val historyPendingBackend: Boolean = false,
    val acting: Boolean = false,
    val errorMessage: String? = null,
    val successMessage: String? = null,
    /** The plan id was not found in the plans list (e.g. runner pending / bad deep-link). */
    val notFound: Boolean = false,
)

/**
 * Drives the DCA plan DETAIL: resolves the plan from the plans list (the runner has no per-plan GET in the
 * contract), loads its run history (degrades on 404 to an honest "pending backend runner" empty state),
 * and exposes pause / resume / cancel + run-now. run-now is best-effort and runner-owned: on a 404 it
 * reports an honest "the server runner will execute this" message rather than faking a fill.
 */
@HiltViewModel
class DcaDetailViewModel @Inject constructor(
    private val repository: DcaRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val planId: String = savedStateHandle.get<String>(DcaDetailDest.ARG_PLAN_ID).orEmpty()

    private val _uiState = MutableStateFlow(DcaDetailUiState())
    val uiState: StateFlow<DcaDetailUiState> = _uiState.asStateFlow()

    init {
        refresh()
    }

    fun refresh() {
        _uiState.update { it.copy(loading = true, errorMessage = null) }
        viewModelScope.launch {
            val plan = when (val r = repository.plans()) {
                is ApiResult.Success -> r.data.firstOrNull { it.planId == planId }
                is ApiResult.Failure -> {
                    _uiState.update { it.copy(loading = false, errorMessage = r.error.message.ifBlank { "Couldn't load this plan." }) }
                    return@launch
                }
                is ApiResult.NetworkError -> {
                    _uiState.update { it.copy(loading = false, errorMessage = "No connection. Pull to retry.") }
                    return@launch
                }
            }
            if (plan == null) {
                _uiState.update { it.copy(loading = false, notFound = true) }
                return@launch
            }
            _uiState.update { it.copy(loading = false, plan = plan, notFound = false) }

            when (val h = repository.history(planId)) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(runs = h.data.sortedByDescending { r -> r.ts }, historyPendingBackend = h.data.isEmpty())
                }
                else -> Unit // history is optional; leave the pending state.
            }
        }
    }

    fun consumeMessages() = _uiState.update { it.copy(errorMessage = null, successMessage = null) }

    fun pause() = mutate("Plan paused.") { repository.pause(planId) }
    fun resume() = mutate("Plan resumed.") { repository.resume(planId) }
    fun cancel() = mutate("Plan cancelled.") { repository.cancel(planId) }

    fun runNow() {
        _uiState.update { it.copy(acting = true, errorMessage = null, successMessage = null) }
        viewModelScope.launch {
            when (val r = repository.runNow(planId)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(acting = false, successMessage = "Run requested. The server runner executes recurring buys.") }
                    refresh()
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(acting = false, errorMessage = r.error.message.ifBlank { "Run-now isn't available yet — the server runner will execute this plan on schedule." })
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(acting = false, errorMessage = "No connection. Nothing changed.")
                }
            }
        }
    }

    private fun mutate(okMessage: String, block: suspend () -> ApiResult<DcaPlan>) {
        _uiState.update { it.copy(acting = true, errorMessage = null, successMessage = null) }
        viewModelScope.launch {
            when (val r = block()) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(acting = false, plan = r.data, successMessage = okMessage) }
                    refresh()
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(acting = false, errorMessage = r.error.message.ifBlank { "That action isn't available right now." })
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(acting = false, errorMessage = "No connection. Nothing changed.")
                }
            }
        }
    }
}
