package com.testlogon.android.feature.adminops

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.adminops.FinancialDashboardData
import com.testlogon.android.data.adminops.FinancialsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.time.LocalDate
import java.time.format.DateTimeFormatter
import javax.inject.Inject

/** Selectable look-back ranges for the financial dashboard (mirrors the web date-range presets). */
enum class FinancialsRange(val label: String, val days: Long) {
    D7("7 days", 7),
    D30("30 days", 30),
    D90("90 days", 90),
}

sealed interface FinancialsUiState {
    data object Loading : FinancialsUiState
    data class Content(
        val data: FinancialDashboardData,
        val range: FinancialsRange,
        val startDate: String,
        val endDate: String,
        val isRefreshing: Boolean = false,
        val transientError: AdminOpsErrorType? = null,
    ) : FinancialsUiState
    data object Forbidden : FinancialsUiState
    data class Error(val type: AdminOpsErrorType) : FinancialsUiState
}

@HiltViewModel
class FinancialsViewModel @Inject constructor(
    private val repo: FinancialsRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<FinancialsUiState>(FinancialsUiState.Loading)
    val state: StateFlow<FinancialsUiState> = _state.asStateFlow()

    private var range: FinancialsRange = FinancialsRange.D30

    init {
        load(range, isRefresh = false, resetLoading = true)
    }

    fun retry() = load(range, isRefresh = false, resetLoading = true)

    fun setRange(r: FinancialsRange) {
        range = r
        load(r, isRefresh = false, resetLoading = true)
    }

    fun refresh() {
        val cur = _state.value
        if (cur is FinancialsUiState.Content) {
            _state.value = cur.copy(isRefreshing = true, transientError = null)
        }
        load(range, isRefresh = true, resetLoading = false)
    }

    private fun load(r: FinancialsRange, isRefresh: Boolean, resetLoading: Boolean) {
        if (resetLoading) _state.value = FinancialsUiState.Loading
        val end = LocalDate.now()
        val start = end.minusDays(r.days - 1)
        val fmt = DateTimeFormatter.ISO_LOCAL_DATE
        val startStr = start.format(fmt)
        val endStr = end.format(fmt)
        viewModelScope.launch {
            when (val res = repo.load(startStr, endStr)) {
                is ApiResult.Success -> _state.value = FinancialsUiState.Content(
                    data = res.data,
                    range = r,
                    startDate = startStr,
                    endDate = endStr,
                )
                is ApiResult.Failure -> reduceFailure(isRefresh, res.error.status)
                is ApiResult.NetworkError -> reduceError(isRefresh, AdminOpsErrorType.NETWORK)
            }
        }
    }

    private fun reduceFailure(isRefresh: Boolean, status: Int) {
        if (status == 403) {
            _state.value = FinancialsUiState.Forbidden
        } else {
            reduceError(isRefresh, adminOpsErrorFor(status))
        }
    }

    private fun reduceError(isRefresh: Boolean, type: AdminOpsErrorType) {
        val prior = _state.value as? FinancialsUiState.Content
        _state.value = if (isRefresh && prior != null) {
            prior.copy(isRefreshing = false, transientError = type)
        } else {
            FinancialsUiState.Error(type)
        }
    }
}
