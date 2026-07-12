@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.kycadmin

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.kycadmin.KycMetricsAdminRepository
import com.testlogon.android.data.kycadmin.KycMetricsDto
import com.testlogon.android.feature.adminops.AdminOpsBranch
import com.testlogon.android.feature.adminops.AdminOpsDashboardScaffold
import com.testlogon.android.feature.adminops.AdminOpsErrorType
import com.testlogon.android.feature.adminops.CardSection
import com.testlogon.android.feature.adminops.KpiGrid
import com.testlogon.android.feature.adminops.SectionHeader
import com.testlogon.android.feature.adminops.StatRow
import com.testlogon.android.feature.adminops.adminOpsErrorFor
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

sealed interface KycMetricsUiState {
    data object Loading : KycMetricsUiState
    data class Content(val data: KycMetricsDto, val isRefreshing: Boolean = false) : KycMetricsUiState
    data object Forbidden : KycMetricsUiState
    data class Error(val type: AdminOpsErrorType) : KycMetricsUiState
}

@HiltViewModel
class KycMetricsAdminViewModel @Inject constructor(
    private val repo: KycMetricsAdminRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<KycMetricsUiState>(KycMetricsUiState.Loading)
    val state: StateFlow<KycMetricsUiState> = _state.asStateFlow()

    init { load(reset = true, refresh = false) }
    fun retry() = load(reset = true, refresh = false)
    fun refresh() {
        (_state.value as? KycMetricsUiState.Content)?.let { _state.value = it.copy(isRefreshing = true) }
        load(reset = false, refresh = true)
    }

    private fun load(reset: Boolean, refresh: Boolean) {
        if (reset) _state.value = KycMetricsUiState.Loading
        viewModelScope.launch {
            when (val r = repo.load()) {
                is ApiResult.Success -> _state.value = KycMetricsUiState.Content(r.data)
                is ApiResult.Failure ->
                    _state.value = if (r.error.status == 403) KycMetricsUiState.Forbidden
                    else KycMetricsUiState.Error(adminOpsErrorFor(r.error.status))
                is ApiResult.NetworkError -> _state.value = KycMetricsUiState.Error(AdminOpsErrorType.NETWORK)
            }
        }
    }
}

object KycMetricsTestTags {
    const val SCREEN = "kyc_metrics_screen"
    const val CONTENT = "kyc_metrics_content"
    const val FORBIDDEN = "kyc_metrics_forbidden"
    const val RETRY = "kyc_metrics_retry"
}

@Composable
fun KycMetricsAdminRoute(
    onBack: () -> Unit,
    viewModel: KycMetricsAdminViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val branch = when (state) {
        is KycMetricsUiState.Loading -> AdminOpsBranch.Loading
        is KycMetricsUiState.Forbidden -> AdminOpsBranch.Forbidden
        is KycMetricsUiState.Error -> AdminOpsBranch.Error((state as KycMetricsUiState.Error).type)
        is KycMetricsUiState.Content -> AdminOpsBranch.Content((state as KycMetricsUiState.Content).isRefreshing)
    }
    AdminOpsDashboardScaffold(
        title = "KYC metrics",
        branch = branch,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        screenTag = KycMetricsTestTags.SCREEN,
        forbiddenTag = KycMetricsTestTags.FORBIDDEN,
        retryTag = KycMetricsTestTags.RETRY,
        forbiddenBody = "You need admin access to view KYC metrics.",
    ) {
        (state as? KycMetricsUiState.Content)?.let { KycMetricsContent(it.data) }
    }
}

@Composable
private fun KycMetricsContent(m: KycMetricsDto) {
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)
            .testTag(KycMetricsTestTags.CONTENT),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        KpiGrid(
            tiles = listOf(
                "Stale queue" to m.staleQueueCount.toString(),
                "Ticket DLQ" to m.ticketSyncDeadletterCount.toString(),
            ),
        )

        if (m.funnelCounts.isNotEmpty()) {
            CardSection("Funnel counts") {
                m.funnelCounts.forEach { (k, v) -> StatRow(k.replace('_', ' ').replaceFirstChar { it.uppercase() }, v.toString()) }
            }
        }

        if (m.reviewLatencySeconds.isNotEmpty()) {
            CardSection("Review latency (seconds)") {
                m.reviewLatencySeconds.forEach { (k, v) ->
                    StatRow(k.replace('_', ' ').replaceFirstChar { it.uppercase() }, v?.let { "%.0f".format(it) } ?: "-")
                }
            }
        }

        if (m.submitGuardFailures.isNotEmpty()) {
            SectionHeader("Submit-guard failures")
            CardSection("By reason") {
                m.submitGuardFailures.forEach { (k, v) -> StatRow(k.replace('_', ' '), v.toString()) }
            }
        }

        if (m.ticketSyncCounters.isNotEmpty()) {
            CardSection("Ticket sync counters") {
                m.ticketSyncCounters.forEach { (k, v) -> StatRow(k.replace('_', ' '), v.toString()) }
            }
        }
    }
}
