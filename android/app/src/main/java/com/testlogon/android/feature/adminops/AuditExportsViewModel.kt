package com.testlogon.android.feature.adminops

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.adminops.AuditExportDto
import com.testlogon.android.data.adminops.AuditExportsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.time.LocalDate
import java.time.ZoneOffset
import javax.inject.Inject

sealed interface AuditExportsUiState {
    data object Loading : AuditExportsUiState
    data class Content(
        val exports: List<AuditExportDto>,
        val isRefreshing: Boolean = false,
        val creating: Boolean = false,
        val transientError: AdminOpsErrorType? = null,
        val actionMessage: String? = null,
    ) : AuditExportsUiState
    data object Forbidden : AuditExportsUiState
    data class Error(val type: AdminOpsErrorType) : AuditExportsUiState
}

@HiltViewModel
class AuditExportsViewModel @Inject constructor(
    private val repo: AuditExportsRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<AuditExportsUiState>(AuditExportsUiState.Loading)
    val state: StateFlow<AuditExportsUiState> = _state.asStateFlow()

    init { load(resetLoading = true, isRefresh = false) }

    fun retry() = load(resetLoading = true, isRefresh = false)

    fun refresh() {
        (_state.value as? AuditExportsUiState.Content)?.let {
            _state.value = it.copy(isRefreshing = true, transientError = null)
        }
        load(resetLoading = false, isRefresh = true)
    }

    /** Create an export over the last [days] days. Categories default to all if empty. */
    fun create(categories: List<String>, format: String, days: Long) {
        val cur = _state.value as? AuditExportsUiState.Content ?: return
        if (cur.creating || categories.isEmpty()) return
        _state.value = cur.copy(creating = true, transientError = null, actionMessage = null)
        val end = LocalDate.now()
        val start = end.minusDays(days - 1)
        val fromTs = start.atStartOfDay().toEpochSecond(ZoneOffset.UTC)
        val toTs = end.plusDays(1).atStartOfDay().toEpochSecond(ZoneOffset.UTC) - 1
        viewModelScope.launch {
            when (val r = repo.create(categories, format, fromTs, toTs)) {
                is ApiResult.Success -> {
                    _state.value = (_state.value as? AuditExportsUiState.Content ?: cur)
                        .copy(creating = false, actionMessage = "Export ${r.data.exportId} queued")
                    load(resetLoading = false, isRefresh = true)
                }
                is ApiResult.Failure -> reduceActionError(
                    if (r.error.status == 403) AdminOpsErrorType.AUTH else adminOpsErrorFor(r.error.status),
                )
                is ApiResult.NetworkError -> reduceActionError(AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun clearActionMessage() {
        (_state.value as? AuditExportsUiState.Content)?.let {
            _state.value = it.copy(actionMessage = null, transientError = null)
        }
    }

    private fun reduceActionError(type: AdminOpsErrorType) {
        (_state.value as? AuditExportsUiState.Content)?.let {
            _state.value = it.copy(creating = false, transientError = type)
        }
    }

    private fun load(resetLoading: Boolean, isRefresh: Boolean) {
        if (resetLoading) _state.value = AuditExportsUiState.Loading
        viewModelScope.launch {
            when (val r = repo.list()) {
                is ApiResult.Success -> _state.value = AuditExportsUiState.Content(r.data.exports)
                is ApiResult.Failure ->
                    if (r.error.status == 403) _state.value = AuditExportsUiState.Forbidden
                    else reduceError(isRefresh, adminOpsErrorFor(r.error.status))
                is ApiResult.NetworkError -> reduceError(isRefresh, AdminOpsErrorType.NETWORK)
            }
        }
    }

    private fun reduceError(isRefresh: Boolean, type: AdminOpsErrorType) {
        val prior = _state.value as? AuditExportsUiState.Content
        _state.value = if (isRefresh && prior != null) prior.copy(isRefreshing = false, transientError = type)
        else AuditExportsUiState.Error(type)
    }
}
