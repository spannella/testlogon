package com.testlogon.android.feature.hr

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.hr.Employment
import com.testlogon.android.core.model.hr.Position
import com.testlogon.android.data.hr.HrRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/** HRM-009 — employment detail screen state. */
sealed interface HrEmploymentDetailUiState {
    data object Loading : HrEmploymentDetailUiState

    /** [position] is a best-effort enrichment (the position title); null when it could not be loaded. */
    data class Content(val employment: Employment, val position: Position?) : HrEmploymentDetailUiState
    data object Unavailable : HrEmploymentDetailUiState
    data class Error(val message: String, val canRetry: Boolean) : HrEmploymentDetailUiState
}

/**
 * HRM-009 — employment detail presentation logic. Loads `/ui/hr/employments/{id}` once, then makes a
 * best-effort follow-up fetch of the linked position (for its title); a failed position fetch does NOT
 * fail the screen. Degrade-on-404 -> Unavailable; 403 -> non-retryable Error.
 */
@HiltViewModel
class HrEmploymentDetailViewModel @Inject constructor(
    private val repository: HrRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val employmentId: String = checkNotNull(savedStateHandle[ARG_EMPLOYMENT_ID]) {
        "HrEmploymentDetailViewModel requires an '$ARG_EMPLOYMENT_ID' nav argument"
    }

    private val _state = MutableStateFlow<HrEmploymentDetailUiState>(HrEmploymentDetailUiState.Loading)
    val state: StateFlow<HrEmploymentDetailUiState> = _state.asStateFlow()

    init {
        load()
    }

    fun retry() = load()

    private fun load() {
        _state.value = HrEmploymentDetailUiState.Loading
        viewModelScope.launch {
            _state.value = when (val r = repository.getEmployment(employmentId)) {
                is ApiResult.Success -> {
                    val position = (repository.getPosition(r.data.positionId) as? ApiResult.Success)?.data
                    HrEmploymentDetailUiState.Content(r.data, position)
                }
                is ApiResult.Failure -> when (r.error.status) {
                    404 -> HrEmploymentDetailUiState.Unavailable
                    403 -> HrEmploymentDetailUiState.Error("You do not have access to HR.", canRetry = false)
                    else -> HrEmploymentDetailUiState.Error(
                        r.error.message.ifBlank { "Could not load employment." },
                        canRetry = true,
                    )
                }
                is ApiResult.NetworkError ->
                    HrEmploymentDetailUiState.Error("Network error. Check your connection.", canRetry = true)
            }
        }
    }

    companion object {
        const val ARG_EMPLOYMENT_ID = "employment_id"
    }
}
