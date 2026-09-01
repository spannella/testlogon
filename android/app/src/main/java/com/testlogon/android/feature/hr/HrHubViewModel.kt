package com.testlogon.android.feature.hr

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.hr.Employment
import com.testlogon.android.core.model.hr.PayrollRun
import com.testlogon.android.core.model.hr.Position
import com.testlogon.android.data.hr.HrRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/** HRM-009 — the three tabs of the HR hub. */
enum class HrTab { POSITIONS, EMPLOYMENTS, PAYROLL }

/**
 * HRM-009 — generic per-tab list state.
 *
 *  - [Loading]     — first fetch in flight.
 *  - [Content]     — items (possibly empty) fetched OK.
 *  - [Unavailable] — degrade-on-404 (the hr_enabled / hr_payroll_enabled flag is off): NOT an error, the
 *                    surface is simply not enabled for this deployment/account. Shown as a calm empty note.
 *  - [Error]       — 403 (not admin) or any other failure; retryable except for 403.
 */
sealed interface HrListUiState<out T> {
    data object Loading : HrListUiState<Nothing>
    data class Content<T>(val items: List<T>) : HrListUiState<T>
    data object Unavailable : HrListUiState<Nothing>
    data class Error(val message: String, val canRetry: Boolean) : HrListUiState<Nothing>
}

/**
 * HRM-009 — HR hub presentation logic (admin/root only; the More entry is operatorOnly and the backend
 * 403/404 remains authoritative). Loads all three read surfaces (positions, employments, payroll runs)
 * on construction; each maps its own [HrListUiState]. A 404 degrades to [Unavailable] (feature-flag off);
 * a 403 maps to a non-retryable [Error]; transport/5xx map to a retryable [Error].
 *
 * The ViewModel imports no Retrofit/Moshi/Compose; it consumes [ApiResult] only.
 */
@HiltViewModel
class HrHubViewModel @Inject constructor(
    private val repository: HrRepository,
) : ViewModel() {

    private val _positions = MutableStateFlow<HrListUiState<Position>>(HrListUiState.Loading)
    val positions: StateFlow<HrListUiState<Position>> = _positions.asStateFlow()

    private val _employments = MutableStateFlow<HrListUiState<Employment>>(HrListUiState.Loading)
    val employments: StateFlow<HrListUiState<Employment>> = _employments.asStateFlow()

    private val _payroll = MutableStateFlow<HrListUiState<PayrollRun>>(HrListUiState.Loading)
    val payroll: StateFlow<HrListUiState<PayrollRun>> = _payroll.asStateFlow()

    init {
        loadPositions()
        loadEmployments()
        loadPayroll()
    }

    fun retry(tab: HrTab) = when (tab) {
        HrTab.POSITIONS -> loadPositions()
        HrTab.EMPLOYMENTS -> loadEmployments()
        HrTab.PAYROLL -> loadPayroll()
    }

    private fun loadPositions() {
        _positions.value = HrListUiState.Loading
        viewModelScope.launch {
            _positions.value = reduce(repository.listPositions(status = null, cursor = null, limit = LIMIT)) {
                it.items
            }
        }
    }

    private fun loadEmployments() {
        _employments.value = HrListUiState.Loading
        viewModelScope.launch {
            _employments.value = reduce(
                repository.listEmployments(partyId = null, status = null, cursor = null, limit = LIMIT),
            ) { it.items }
        }
    }

    private fun loadPayroll() {
        _payroll.value = HrListUiState.Loading
        viewModelScope.launch {
            _payroll.value = reduce(repository.listPayrollRuns(status = null, cursor = null, limit = LIMIT)) {
                it.items
            }
        }
    }

    private fun <R, T> reduce(result: ApiResult<R>, items: (R) -> List<T>): HrListUiState<T> = when (result) {
        is ApiResult.Success -> HrListUiState.Content(items(result.data))
        is ApiResult.Failure -> when (result.error.status) {
            404 -> HrListUiState.Unavailable
            403 -> HrListUiState.Error("You do not have access to HR.", canRetry = false)
            else -> HrListUiState.Error(
                result.error.message.ifBlank { "Could not load HR data." },
                canRetry = true,
            )
        }
        is ApiResult.NetworkError -> HrListUiState.Error("Network error. Check your connection.", canRetry = true)
    }

    private companion object {
        const val LIMIT = 50
    }
}
