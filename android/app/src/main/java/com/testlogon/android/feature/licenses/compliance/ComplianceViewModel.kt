package com.testlogon.android.feature.licenses.compliance

import androidx.annotation.StringRes
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.licenses.CompliancePage
import com.testlogon.android.data.licenses.ComplianceDetail
import com.testlogon.android.data.licenses.ComplianceItem
import com.testlogon.android.data.licenses.ComplianceSummary
import com.testlogon.android.data.licenses.LicensesSubRepository
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

/** Render-ready state for the My-Compliance sub-screen. */
data class ComplianceUiState(
    val phase: Phase = Phase.Loading,
    val items: List<ComplianceItem> = emptyList(),
    val summary: ComplianceSummary = ComplianceSummary(0, 0, 0, 0, 0),
    val statusFilter: String = "all",
    val isRefreshing: Boolean = false,
    val errorMessage: String? = null,
    // detail bottom sheet
    val detailContentId: String? = null,
    val detail: ComplianceDetail? = null,
    val detailLoading: Boolean = false,
    val isChecking: Boolean = false,
    // flag dialog
    val flagOpen: Boolean = false,
    val isFlagging: Boolean = false,
) {
    enum class Phase { Loading, Content, Empty, Error }
}

@HiltViewModel
class ComplianceViewModel @Inject constructor(
    private val repository: LicensesSubRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(ComplianceUiState())
    val uiState: StateFlow<ComplianceUiState> = _uiState.asStateFlow()

    private val _effects = Channel<Int>(Channel.BUFFERED)
    val effects: Flow<Int> = _effects.receiveAsFlow()

    init {
        load(fromUser = false)
    }

    fun refresh() = load(fromUser = true)

    fun selectStatus(status: String) {
        if (status == _uiState.value.statusFilter) return
        _uiState.update { it.copy(statusFilter = status) }
        load(fromUser = true)
    }

    private fun load(fromUser: Boolean) {
        if (_uiState.value.isRefreshing) return
        val hasContent = _uiState.value.items.isNotEmpty()
        _uiState.update {
            it.copy(
                phase = if (hasContent) it.phase else ComplianceUiState.Phase.Loading,
                isRefreshing = fromUser,
                errorMessage = null,
            )
        }
        val status = _uiState.value.statusFilter.takeIf { it != "all" }
        viewModelScope.launch {
            when (val r = repository.loadCompliance(status)) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(
                        phase = if (r.data.isEmpty) ComplianceUiState.Phase.Empty else ComplianceUiState.Phase.Content,
                        items = r.data.items,
                        summary = r.data.summary,
                        isRefreshing = false,
                        errorMessage = null,
                    )
                }
                is ApiResult.Failure -> fail(r.error.message)
                is ApiResult.NetworkError -> fail(OFFLINE)
            }
        }
    }

    private fun fail(message: String) {
        _uiState.update {
            if (it.items.isNotEmpty()) {
                it.copy(isRefreshing = false)
            } else {
                it.copy(phase = ComplianceUiState.Phase.Error, isRefreshing = false, errorMessage = message)
            }
        }
    }

    // ---- detail sheet ----

    fun openDetail(contentId: String) {
        _uiState.update { it.copy(detailContentId = contentId, detail = null, detailLoading = true) }
        viewModelScope.launch {
            when (val r = repository.loadComplianceDetail(contentId)) {
                is ApiResult.Success -> _uiState.update { it.copy(detail = r.data, detailLoading = false) }
                is ApiResult.Failure -> {
                    _uiState.update { it.copy(detailLoading = false) }
                    _effects.send(R.string.licenses_action_failed)
                }
                is ApiResult.NetworkError -> {
                    _uiState.update { it.copy(detailLoading = false) }
                    _effects.send(R.string.licenses_action_failed)
                }
            }
        }
    }

    fun closeDetail() {
        _uiState.update { it.copy(detailContentId = null, detail = null, detailLoading = false) }
    }

    fun checkNow(contentId: String) {
        if (_uiState.value.isChecking) return
        _uiState.update { it.copy(isChecking = true) }
        viewModelScope.launch {
            val result = repository.checkCompliance(contentId)
            _uiState.update { it.copy(isChecking = false) }
            if (result is ApiResult.Success) {
                _effects.send(R.string.licenses_compliance_rechecked)
                // refresh detail + list so the new status shows
                openDetail(contentId)
                load(fromUser = false)
            } else {
                _effects.send(R.string.licenses_action_failed)
            }
        }
    }

    // ---- flag dialog ----

    fun openFlag() = _uiState.update { it.copy(flagOpen = true) }

    fun closeFlag() = _uiState.update { it.copy(flagOpen = false) }

    fun submitFlag(contentId: String, reason: String, evidence: String) {
        if (_uiState.value.isFlagging || contentId.isBlank()) return
        _uiState.update { it.copy(isFlagging = true) }
        viewModelScope.launch {
            val result = repository.flagContent(contentId.trim(), reason, evidence.trim())
            _uiState.update { it.copy(isFlagging = false) }
            if (result is ApiResult.Success) {
                _uiState.update { it.copy(flagOpen = false) }
                _effects.send(R.string.licenses_report_submitted)
                load(fromUser = false)
            } else {
                _effects.send(R.string.licenses_action_failed)
            }
        }
    }

    private companion object {
        private const val OFFLINE = "Could not reach the server. Pull down to retry."
    }
}
