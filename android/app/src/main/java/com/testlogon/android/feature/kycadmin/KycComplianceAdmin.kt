@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.kycadmin

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.kycadmin.KycComplianceAdminRepository
import com.testlogon.android.data.kycadmin.KycComplianceData
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
import java.util.Locale
import javax.inject.Inject

sealed interface KycComplianceUiState {
    data object Loading : KycComplianceUiState
    data class Content(val data: KycComplianceData, val isRefreshing: Boolean = false) : KycComplianceUiState
    data object Forbidden : KycComplianceUiState
    data class Error(val type: AdminOpsErrorType) : KycComplianceUiState
}

@HiltViewModel
class KycComplianceAdminViewModel @Inject constructor(
    private val repo: KycComplianceAdminRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<KycComplianceUiState>(KycComplianceUiState.Loading)
    val state: StateFlow<KycComplianceUiState> = _state.asStateFlow()

    private val _message = MutableStateFlow<String?>(null)
    val message: StateFlow<String?> = _message.asStateFlow()

    private val _actionInFlight = MutableStateFlow(false)
    val actionInFlight: StateFlow<Boolean> = _actionInFlight.asStateFlow()

    init { load(reset = true) }
    fun retry() = load(reset = true)
    fun refresh() {
        (_state.value as? KycComplianceUiState.Content)?.let { _state.value = it.copy(isRefreshing = true) }
        load(reset = false)
    }

    fun clearMessage() { _message.value = null }

    fun generateSar(userSub: String, reason: String) {
        if (_actionInFlight.value || userSub.isBlank() || reason.isBlank()) return
        _actionInFlight.value = true
        viewModelScope.launch {
            _message.value = when (val r = repo.generateSar(userSub, reason)) {
                is ApiResult.Success -> "SAR generated: ${r.data.sarId}"
                is ApiResult.Failure -> if (r.error.status == 403) "Not authorised."
                else adminOpsErrorMessage(adminOpsErrorFor(r.error.status))
                is ApiResult.NetworkError -> adminOpsErrorMessage(AdminOpsErrorType.NETWORK)
            }
            _actionInFlight.value = false
        }
    }

    private fun load(reset: Boolean) {
        if (reset) _state.value = KycComplianceUiState.Loading
        viewModelScope.launch {
            when (val r = repo.load()) {
                is ApiResult.Success -> _state.value = KycComplianceUiState.Content(r.data)
                is ApiResult.Failure ->
                    _state.value = if (r.error.status == 403) KycComplianceUiState.Forbidden
                    else KycComplianceUiState.Error(adminOpsErrorFor(r.error.status))
                is ApiResult.NetworkError -> _state.value = KycComplianceUiState.Error(AdminOpsErrorType.NETWORK)
            }
        }
    }
}

object KycComplianceTestTags {
    const val SCREEN = "kyc_compliance_screen"
    const val CONTENT = "kyc_compliance_content"
    const val FORBIDDEN = "kyc_compliance_forbidden"
    const val RETRY = "kyc_compliance_retry"
    const val SAR_BTN = "kyc_compliance_sar_btn"
    const val SAR_CONFIRM = "kyc_compliance_sar_confirm"
}

private fun p1(v: Double): String = String.format(Locale.US, "%.1f%%", v)

@Composable
fun KycComplianceAdminRoute(
    onBack: () -> Unit,
    viewModel: KycComplianceAdminViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val message by viewModel.message.collectAsStateWithLifecycle()
    val snackbar = remember { SnackbarHostState() }
    var sarDialog by remember { mutableStateOf(false) }

    LaunchedEffect(message) {
        message?.let { snackbar.showSnackbar(it); viewModel.clearMessage() }
    }

    val branch = when (state) {
        is KycComplianceUiState.Loading -> AdminOpsBranch.Loading
        is KycComplianceUiState.Forbidden -> AdminOpsBranch.Forbidden
        is KycComplianceUiState.Error -> AdminOpsBranch.Error((state as KycComplianceUiState.Error).type)
        is KycComplianceUiState.Content -> AdminOpsBranch.Content((state as KycComplianceUiState.Content).isRefreshing)
    }

    androidx.compose.material3.Scaffold(
        modifier = Modifier.testTag(KycComplianceTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        Column(modifier = Modifier.padding(padding)) {
            AdminOpsDashboardScaffold(
                title = "KYC compliance",
                branch = branch,
                onBack = onBack,
                onRefresh = viewModel::refresh,
                onRetry = viewModel::retry,
                forbiddenTag = KycComplianceTestTags.FORBIDDEN,
                retryTag = KycComplianceTestTags.RETRY,
                forbiddenBody = "You need admin access to view compliance reports.",
            ) {
                (state as? KycComplianceUiState.Content)?.let {
                    KycComplianceContent(it.data, onOpenSar = { sarDialog = true })
                }
            }
        }
    }

    if (sarDialog) {
        SarDialog(
            onDismiss = { sarDialog = false },
            onConfirm = { user, reason -> viewModel.generateSar(user, reason); sarDialog = false },
        )
    }
}

@Composable
private fun KycComplianceContent(d: KycComplianceData, onOpenSar: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)
            .testTag(KycComplianceTestTags.CONTENT),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        SectionHeader("Volume")
        KpiGrid(
            tiles = listOf(
                "Total cases" to d.volume.totalCases.toString(),
                "Approval" to p1(d.volume.approvalRate),
                "Rejection" to p1(d.volume.rejectionRate),
            ),
        )
        if (d.volume.countsByStatus.isNotEmpty()) {
            CardSection("Cases by status") {
                d.volume.countsByStatus.forEach { (k, v) -> StatRow(k.replace('_', ' '), v.toString()) }
            }
        }

        SectionHeader("Screening")
        KpiGrid(
            tiles = listOf(
                "Screenings" to d.screening.totalScreenings.toString(),
                "Hits" to d.screening.totalHits.toString(),
                "Hit rate" to p1(d.screening.hitRatePct),
                "Confirmed" to d.screening.confirmedCount.toString(),
            ),
        )

        SectionHeader("Processing time")
        CardSection("Latency (seconds)") {
            StatRow("Decided", d.processingTime.totalDecided.toString())
            StatRow("Average", "%.0f".format(d.processingTime.avgSeconds))
            d.processingTime.p50Seconds?.let { StatRow("p50", "%.0f".format(it)) }
            d.processingTime.p90Seconds?.let { StatRow("p90", "%.0f".format(it)) }
            d.processingTime.p95Seconds?.let { StatRow("p95", "%.0f".format(it)) }
        }

        SectionHeader("Deadlines")
        KpiGrid(
            tiles = listOf(
                "Overdue" to d.deadlines.totalOverdue.toString(),
                "Critical" to d.deadlines.criticalCount.toString(),
                "Warning" to d.deadlines.warningCount.toString(),
            ),
        )
        if (d.deadlines.cases.isNotEmpty()) {
            CardSection("Overdue cases") {
                d.deadlines.cases.take(15).forEach { c ->
                    StatRow("${c.caseId} (${c.severity})", "%.0f h".format(c.ageHours))
                }
            }
        }

        SectionHeader("Retention")
        KpiGrid(
            tiles = listOf(
                "Records" to d.retention.totalRecords.toString(),
                "Purge overdue" to d.retention.overduePurgeCount.toString(),
                "Purged" to d.retention.alreadyPurgedCount.toString(),
            ),
        )

        Button(
            onClick = onOpenSar,
            modifier = Modifier.fillMaxWidth().testTag(KycComplianceTestTags.SAR_BTN),
        ) { Text("Generate SAR") }
    }
}

@Composable
private fun SarDialog(onDismiss: () -> Unit, onConfirm: (String, String) -> Unit) {
    var userSub by remember { mutableStateOf("") }
    var reason by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Suspicious Activity Report") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(value = userSub, onValueChange = { userSub = it }, label = { Text("Subject user sub") }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = reason, onValueChange = { reason = it }, label = { Text("Reason") }, modifier = Modifier.fillMaxWidth())
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(userSub, reason) },
                enabled = userSub.isNotBlank() && reason.isNotBlank(),
                modifier = Modifier.testTag(KycComplianceTestTags.SAR_CONFIRM),
            ) { Text("Generate") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
