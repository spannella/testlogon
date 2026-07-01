package com.testlogon.android.feature.compliance

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.compliance.ComplianceRepository
import com.testlogon.android.data.compliance.FindingStatus
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

/**
 * Drives [ComplianceUiState] from [ComplianceRepository]. Serves both the web /agents/compliance and
 * /agents/security surfaces (the web reuses one component). Loads the summary + findings on init;
 * switching tabs lazily loads that tab's data.
 */
@HiltViewModel
class ComplianceViewModel @Inject constructor(
    private val repository: ComplianceRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(ComplianceUiState())
    val uiState: StateFlow<ComplianceUiState> = _uiState.asStateFlow()

    private val _effects = Channel<ComplianceEffect>(Channel.BUFFERED)
    val effects: Flow<ComplianceEffect> = _effects.receiveAsFlow()

    init {
        load(fromUser = false)
    }

    fun onRefresh() = load(fromUser = true)
    fun onRetry() = load(fromUser = true)

    fun onSelectTab(tab: ComplianceTab) {
        if (tab == _uiState.value.tab) return
        _uiState.update { it.copy(tab = tab) }
        ensureTabLoaded(tab)
    }

    fun onSeverityFilter(value: String) {
        _uiState.update { it.copy(severityFilter = value) }
        loadFindings()
    }

    fun onStatusFilter(value: String) {
        _uiState.update { it.copy(statusFilter = value) }
        loadFindings()
    }

    fun onToggleExpanded(findingId: String) {
        _uiState.update {
            it.copy(expandedFindingId = if (it.expandedFindingId == findingId) null else findingId)
        }
    }

    fun onTransitionFinding(findingId: String, status: FindingStatus) = viewModelScope.launch {
        when (repository.updateFindingStatus(findingId, status)) {
            is ApiResult.Success -> {
                _effects.send(ComplianceEffect.ShowMessage(R.string.compliance_finding_updated))
                loadFindings()
                loadSummary()
            }
            else -> _effects.send(ComplianceEffect.ShowMessage(R.string.compliance_action_failed))
        }
    }

    fun onTriggerAudit() {
        if (_uiState.value.isTriggeringAudit) return
        _uiState.update { it.copy(isTriggeringAudit = true) }
        viewModelScope.launch {
            val result = repository.triggerAudit()
            _uiState.update { it.copy(isTriggeringAudit = false) }
            when (result) {
                is ApiResult.Success -> {
                    _effects.send(ComplianceEffect.ShowMessage(R.string.compliance_audit_triggered))
                    loadAudits()
                }
                else -> _effects.send(ComplianceEffect.ShowMessage(R.string.compliance_action_failed))
            }
        }
    }

    private fun load(fromUser: Boolean) {
        val hasContent = _uiState.value.summary != null
        _uiState.update {
            it.copy(
                phase = if (hasContent) it.phase else CompliancePhase.Loading,
                isRefreshing = fromUser && hasContent,
            )
        }
        loadSummary()
        loadFindings(driveTopPhase = true)
        // reset lazy tabs so they refetch when reopened
        _uiState.update { it.copy(audits = null, frameworks = null, trends = null) }
        ensureTabLoaded(_uiState.value.tab)
    }

    private fun loadSummary() = viewModelScope.launch {
        when (val r = repository.loadSummary()) {
            is ApiResult.Success -> _uiState.update { it.copy(summary = r.data) }
            else -> Unit // summary is a best-effort header; findings drive the top-level phase
        }
    }

    private fun loadFindings(driveTopPhase: Boolean = false) {
        val sev = _uiState.value.severityFilter.takeIf { it != "all" }
        val st = _uiState.value.statusFilter.takeIf { it != "all" }
        viewModelScope.launch {
            when (val r = repository.loadFindings(sev, st)) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(
                        phase = CompliancePhase.Content,
                        findings = r.data.findings,
                        isRefreshing = false,
                        errorMessage = null,
                    )
                }
                is ApiResult.Failure ->
                    if (r.error.status == HTTP_UNAUTHORIZED) {
                        _uiState.update { it.copy(phase = CompliancePhase.SessionExpired, isRefreshing = false) }
                    } else if (driveTopPhase && _uiState.value.summary == null) {
                        _uiState.update { it.copy(phase = CompliancePhase.Error, isRefreshing = false, errorMessage = r.error.message) }
                    } else {
                        _uiState.update { it.copy(isRefreshing = false) }
                    }
                is ApiResult.NetworkError ->
                    if (driveTopPhase && _uiState.value.summary == null) {
                        _uiState.update { it.copy(phase = CompliancePhase.Offline, isRefreshing = false, errorMessage = OFFLINE_FALLBACK) }
                    } else {
                        _uiState.update { it.copy(isRefreshing = false) }
                    }
            }
        }
    }

    private fun ensureTabLoaded(tab: ComplianceTab) {
        when (tab) {
            ComplianceTab.FINDINGS -> Unit
            ComplianceTab.AUDITS -> if (_uiState.value.audits == null) loadAudits()
            ComplianceTab.COMPLIANCE -> if (_uiState.value.frameworks == null) loadFrameworks()
            ComplianceTab.TRENDS -> if (_uiState.value.trends == null) loadTrends()
        }
    }

    private fun loadAudits() = viewModelScope.launch {
        when (val r = repository.loadAudits()) {
            is ApiResult.Success -> _uiState.update { it.copy(audits = r.data) }
            else -> _uiState.update { it.copy(audits = emptyList()) }
        }
    }

    private fun loadFrameworks() = viewModelScope.launch {
        when (val r = repository.loadFrameworks()) {
            is ApiResult.Success -> _uiState.update { it.copy(frameworks = r.data) }
            else -> _uiState.update { it.copy(frameworks = emptyList()) }
        }
    }

    private fun loadTrends() = viewModelScope.launch {
        when (val r = repository.loadTrends()) {
            is ApiResult.Success -> _uiState.update { it.copy(trends = r.data) }
            else -> _uiState.update { it.copy(trends = com.testlogon.android.data.compliance.Trends(emptyList(), 90, 0)) }
        }
    }

    private companion object {
        private const val HTTP_UNAUTHORIZED = 401
        private const val OFFLINE_FALLBACK = "Could not reach the server. Pull down to retry."
    }
}
