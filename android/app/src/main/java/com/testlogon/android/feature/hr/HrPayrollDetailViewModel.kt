package com.testlogon.android.feature.hr

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.hr.PayrollLine
import com.testlogon.android.core.model.hr.PayrollRun
import com.testlogon.android.data.hr.HrRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/** HRM-009 — payroll-run detail screen state. */
sealed interface HrPayrollDetailUiState {
    data object Loading : HrPayrollDetailUiState
    data class Content(val run: PayrollRun, val lines: List<PayrollLine>) : HrPayrollDetailUiState
    data object Unavailable : HrPayrollDetailUiState
    data class Error(val message: String, val canRetry: Boolean) : HrPayrollDetailUiState
}

/**
 * HRM-009 — payroll-run detail presentation logic. Loads the run header (`/ui/hr/payroll/{id}`) and its
 * line breakdown (`/ui/hr/payroll/{id}/lines`). The run embeds lines too; the dedicated lines call is
 * authoritative, falling back to the embedded lines when it fails. Degrade-on-404 -> Unavailable.
 */
@HiltViewModel
class HrPayrollDetailViewModel @Inject constructor(
    private val repository: HrRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val payrollRunId: String = checkNotNull(savedStateHandle[ARG_PAYROLL_RUN_ID]) {
        "HrPayrollDetailViewModel requires an '$ARG_PAYROLL_RUN_ID' nav argument"
    }

    private val _state = MutableStateFlow<HrPayrollDetailUiState>(HrPayrollDetailUiState.Loading)
    val state: StateFlow<HrPayrollDetailUiState> = _state.asStateFlow()

    init {
        load()
    }

    fun retry() = load()

    private fun load() {
        _state.value = HrPayrollDetailUiState.Loading
        viewModelScope.launch {
            _state.value = when (val r = repository.getPayrollRun(payrollRunId)) {
                is ApiResult.Success -> {
                    val lines = (repository.getPayrollRunLines(payrollRunId) as? ApiResult.Success)?.data
                        ?: r.data.lines
                    HrPayrollDetailUiState.Content(r.data, lines)
                }
                is ApiResult.Failure -> when (r.error.status) {
                    404 -> HrPayrollDetailUiState.Unavailable
                    403 -> HrPayrollDetailUiState.Error("You do not have access to HR.", canRetry = false)
                    else -> HrPayrollDetailUiState.Error(
                        r.error.message.ifBlank { "Could not load payroll run." },
                        canRetry = true,
                    )
                }
                is ApiResult.NetworkError ->
                    HrPayrollDetailUiState.Error("Network error. Check your connection.", canRetry = true)
            }
        }
    }

    companion object {
        const val ARG_PAYROLL_RUN_ID = "payroll_run_id"
    }
}
