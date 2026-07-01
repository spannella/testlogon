@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.kycadmin

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.kycadmin.KycMonitoringAdminRepository
import com.testlogon.android.data.kycadmin.KycMonitoringDashboardDto
import com.testlogon.android.feature.adminops.AdminOpsBranch
import com.testlogon.android.feature.adminops.AdminOpsDashboardScaffold
import com.testlogon.android.feature.adminops.AdminOpsErrorType
import com.testlogon.android.feature.adminops.CardSection
import com.testlogon.android.feature.adminops.KpiGrid
import com.testlogon.android.feature.adminops.SectionHeader
import com.testlogon.android.feature.adminops.StatRow
import com.testlogon.android.feature.adminops.adminOpsErrorFor
import com.testlogon.android.feature.adminops.adminOpsErrorMessage
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

sealed interface KycMonitoringUiState {
    data object Loading : KycMonitoringUiState
    data class Content(val data: KycMonitoringDashboardDto, val isRefreshing: Boolean = false) : KycMonitoringUiState
    data object Forbidden : KycMonitoringUiState
    data class Error(val type: AdminOpsErrorType) : KycMonitoringUiState
}

@HiltViewModel
class KycMonitoringAdminViewModel @Inject constructor(
    private val repo: KycMonitoringAdminRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<KycMonitoringUiState>(KycMonitoringUiState.Loading)
    val state: StateFlow<KycMonitoringUiState> = _state.asStateFlow()

    private val _message = MutableStateFlow<String?>(null)
    val message: StateFlow<String?> = _message.asStateFlow()

    private val _actionInFlight = MutableStateFlow(false)
    val actionInFlight: StateFlow<Boolean> = _actionInFlight.asStateFlow()

    init { load(reset = true) }
    fun retry() = load(reset = true)
    fun refresh() {
        (_state.value as? KycMonitoringUiState.Content)?.let { _state.value = it.copy(isRefreshing = true) }
        load(reset = false)
    }

    fun clearMessage() { _message.value = null }

    fun runReviewCheck(dryRun: Boolean) = runJob {
        when (val r = repo.reviewCheck(dryRun)) {
            is ApiResult.Success -> "Review check${if (dryRun) " (dry run)" else ""}: grace ${r.data.enteredGracePeriod}, downgraded ${r.data.autoDowngraded}"
            is ApiResult.Failure -> failMsg(r.error.status)
            is ApiResult.NetworkError -> adminOpsErrorMessage(AdminOpsErrorType.NETWORK)
        }
    }

    fun runRescreening(dryRun: Boolean) = runJob {
        when (val r = repo.rescreening(dryRun)) {
            is ApiResult.Success -> "Rescreening${if (dryRun) " (dry run)" else ""}: screened ${r.data.totalScreened}, matches ${r.data.matchesFound}, triggers ${r.data.triggersCreated}"
            is ApiResult.Failure -> failMsg(r.error.status)
            is ApiResult.NetworkError -> adminOpsErrorMessage(AdminOpsErrorType.NETWORK)
        }
    }

    private fun failMsg(status: Int): String =
        if (status == 403) "Not authorised." else adminOpsErrorMessage(adminOpsErrorFor(status))

    private fun runJob(block: suspend () -> String) {
        if (_actionInFlight.value) return
        _actionInFlight.value = true
        viewModelScope.launch {
            _message.value = block()
            _actionInFlight.value = false
            refresh()
        }
    }

    private fun load(reset: Boolean) {
        if (reset) _state.value = KycMonitoringUiState.Loading
        viewModelScope.launch {
            when (val r = repo.load()) {
                is ApiResult.Success -> _state.value = KycMonitoringUiState.Content(r.data)
                is ApiResult.Failure ->
                    _state.value = if (r.error.status == 403) KycMonitoringUiState.Forbidden
                    else KycMonitoringUiState.Error(adminOpsErrorFor(r.error.status))
                is ApiResult.NetworkError -> _state.value = KycMonitoringUiState.Error(AdminOpsErrorType.NETWORK)
            }
        }
    }
}

object KycMonitoringTestTags {
    const val SCREEN = "kyc_monitoring_screen"
    const val CONTENT = "kyc_monitoring_content"
    const val FORBIDDEN = "kyc_monitoring_forbidden"
    const val RETRY = "kyc_monitoring_retry"
    const val REVIEW_CHECK = "kyc_monitoring_review_check"
    const val RESCREEN = "kyc_monitoring_rescreen"
}

@Composable
fun KycMonitoringAdminRoute(
    onBack: () -> Unit,
    viewModel: KycMonitoringAdminViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val message by viewModel.message.collectAsStateWithLifecycle()
    val actionInFlight by viewModel.actionInFlight.collectAsStateWithLifecycle()
    val snackbar = remember { SnackbarHostState() }

    LaunchedEffect(message) {
        message?.let { snackbar.showSnackbar(it); viewModel.clearMessage() }
    }

    val branch = when (state) {
        is KycMonitoringUiState.Loading -> AdminOpsBranch.Loading
        is KycMonitoringUiState.Forbidden -> AdminOpsBranch.Forbidden
        is KycMonitoringUiState.Error -> AdminOpsBranch.Error((state as KycMonitoringUiState.Error).type)
        is KycMonitoringUiState.Content -> AdminOpsBranch.Content((state as KycMonitoringUiState.Content).isRefreshing)
    }

    androidx.compose.material3.Scaffold(
        modifier = Modifier.testTag(KycMonitoringTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        Column(modifier = Modifier.padding(padding)) {
            AdminOpsDashboardScaffold(
                title = "KYC monitoring",
                branch = branch,
                onBack = onBack,
                onRefresh = viewModel::refresh,
                onRetry = viewModel::retry,
                forbiddenTag = KycMonitoringTestTags.FORBIDDEN,
                retryTag = KycMonitoringTestTags.RETRY,
                forbiddenBody = "You need admin access to view ongoing monitoring.",
            ) {
                (state as? KycMonitoringUiState.Content)?.let {
                    KycMonitoringContent(
                        data = it.data,
                        actionInFlight = actionInFlight,
                        onReviewCheck = { viewModel.runReviewCheck(dryRun = true) },
                        onRescreen = { viewModel.runRescreening(dryRun = true) },
                    )
                }
            }
        }
    }
}

@Composable
private fun KycMonitoringContent(
    data: KycMonitoringDashboardDto,
    actionInFlight: Boolean,
    onReviewCheck: () -> Unit,
    onRescreen: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)
            .testTag(KycMonitoringTestTags.CONTENT),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        KpiGrid(
            tiles = listOf(
                "Needs review" to data.needsReviewCount.toString(),
                "Upcoming" to data.upcomingReviews.size.toString(),
                "Overdue" to data.overdueReviews.size.toString(),
            ),
        )

        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            OutlinedButton(
                onClick = onReviewCheck,
                enabled = !actionInFlight,
                modifier = Modifier.testTag(KycMonitoringTestTags.REVIEW_CHECK),
            ) { Text("Review check") }
            Button(
                onClick = onRescreen,
                enabled = !actionInFlight,
                modifier = Modifier.testTag(KycMonitoringTestTags.RESCREEN),
            ) { Text("Rescreen") }
        }
        Text(
            "Batch jobs run as a dry run (no writes).",
            style = androidx.compose.material3.MaterialTheme.typography.labelSmall,
            color = androidx.compose.material3.MaterialTheme.colorScheme.onSurfaceVariant,
        )

        if (data.overdueReviews.isNotEmpty()) {
            SectionHeader("Overdue reviews")
            data.overdueReviews.take(20).forEach { r ->
                CardSection(r.userSub.ifBlank { "unknown" }) {
                    StatRow("Tier", r.riskTier.ifBlank { "-" })
                    StatRow("Status", r.status.ifBlank { "-" })
                    StatRow("Days overdue", r.daysOverdue.toString())
                }
            }
        }

        if (data.upcomingReviews.isNotEmpty()) {
            SectionHeader("Upcoming reviews")
            data.upcomingReviews.take(20).forEach { r ->
                CardSection(r.userSub.ifBlank { "unknown" }) {
                    StatRow("Tier", r.riskTier.ifBlank { "-" })
                    StatRow("Days until due", r.daysUntilDue.toString())
                }
            }
        }
    }
}
