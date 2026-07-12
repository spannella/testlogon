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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.OutlinedButton
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
import com.testlogon.android.data.kycadmin.KycWorkloadAdminRepository
import com.testlogon.android.data.kycadmin.KycWorkloadData
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

sealed interface KycWorkloadUiState {
    data object Loading : KycWorkloadUiState
    data class Content(val data: KycWorkloadData, val isRefreshing: Boolean = false) : KycWorkloadUiState
    data object Forbidden : KycWorkloadUiState
    data class Error(val type: AdminOpsErrorType) : KycWorkloadUiState
}

@HiltViewModel
class KycWorkloadAdminViewModel @Inject constructor(
    private val repo: KycWorkloadAdminRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<KycWorkloadUiState>(KycWorkloadUiState.Loading)
    val state: StateFlow<KycWorkloadUiState> = _state.asStateFlow()

    private val _message = MutableStateFlow<String?>(null)
    val message: StateFlow<String?> = _message.asStateFlow()

    private val _actionInFlight = MutableStateFlow(false)
    val actionInFlight: StateFlow<Boolean> = _actionInFlight.asStateFlow()

    init { load(reset = true) }
    fun retry() = load(reset = true)
    fun refresh() {
        (_state.value as? KycWorkloadUiState.Content)?.let { _state.value = it.copy(isRefreshing = true) }
        load(reset = false)
    }

    fun clearMessage() { _message.value = null }

    fun claim(caseId: String) = act("Claimed") { repo.claim(caseId) }
    fun unclaim(caseId: String) = act("Unclaimed") { repo.unclaim(caseId) }
    fun escalate(caseId: String) = act("Escalated") { repo.escalate(caseId) }
    fun autoAssign(caseId: String) = act("Auto-assigned") { repo.autoAssign(caseId) }
    fun reassign(caseId: String, target: String, reason: String) =
        act("Reassigned") { repo.reassign(caseId, target, reason) }

    private fun act(okLabel: String, block: suspend () -> ApiResult<Unit>) {
        if (_actionInFlight.value) return
        _actionInFlight.value = true
        viewModelScope.launch {
            _message.value = when (val r = block()) {
                is ApiResult.Success -> okLabel
                is ApiResult.Failure -> if (r.error.status == 403) "Not authorised." else adminOpsErrorMessage(adminOpsErrorFor(r.error.status))
                is ApiResult.NetworkError -> adminOpsErrorMessage(AdminOpsErrorType.NETWORK)
            }
            _actionInFlight.value = false
            refresh()
        }
    }

    private fun load(reset: Boolean) {
        if (reset) _state.value = KycWorkloadUiState.Loading
        viewModelScope.launch {
            when (val r = repo.load()) {
                is ApiResult.Success -> _state.value = KycWorkloadUiState.Content(r.data)
                is ApiResult.Failure ->
                    _state.value = if (r.error.status == 403) KycWorkloadUiState.Forbidden
                    else KycWorkloadUiState.Error(adminOpsErrorFor(r.error.status))
                is ApiResult.NetworkError -> _state.value = KycWorkloadUiState.Error(AdminOpsErrorType.NETWORK)
            }
        }
    }
}

object KycWorkloadTestTags {
    const val SCREEN = "kyc_workload_screen"
    const val CONTENT = "kyc_workload_content"
    const val FORBIDDEN = "kyc_workload_forbidden"
    const val RETRY = "kyc_workload_retry"
    fun caseRow(id: String) = "kyc_workload_case_$id"
}

@Composable
fun KycWorkloadAdminRoute(
    onBack: () -> Unit,
    viewModel: KycWorkloadAdminViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val message by viewModel.message.collectAsStateWithLifecycle()
    val actionInFlight by viewModel.actionInFlight.collectAsStateWithLifecycle()
    val snackbar = remember { SnackbarHostState() }
    var reassignTarget by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(message) { message?.let { snackbar.showSnackbar(it); viewModel.clearMessage() } }

    val branch = when (state) {
        is KycWorkloadUiState.Loading -> AdminOpsBranch.Loading
        is KycWorkloadUiState.Forbidden -> AdminOpsBranch.Forbidden
        is KycWorkloadUiState.Error -> AdminOpsBranch.Error((state as KycWorkloadUiState.Error).type)
        is KycWorkloadUiState.Content -> AdminOpsBranch.Content((state as KycWorkloadUiState.Content).isRefreshing)
    }

    androidx.compose.material3.Scaffold(
        modifier = Modifier.testTag(KycWorkloadTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        Column(modifier = Modifier.padding(padding)) {
            AdminOpsDashboardScaffold(
                title = "KYC workload",
                branch = branch,
                onBack = onBack,
                onRefresh = viewModel::refresh,
                onRetry = viewModel::retry,
                forbiddenTag = KycWorkloadTestTags.FORBIDDEN,
                retryTag = KycWorkloadTestTags.RETRY,
                forbiddenBody = "You need admin access to view the KYC workload dashboard.",
            ) {
                (state as? KycWorkloadUiState.Content)?.let {
                    KycWorkloadContent(
                        data = it.data,
                        actionInFlight = actionInFlight,
                        onClaim = viewModel::claim,
                        onUnclaim = viewModel::unclaim,
                        onEscalate = viewModel::escalate,
                        onAutoAssign = viewModel::autoAssign,
                        onReassign = { reassignTarget = it },
                    )
                }
            }
        }
    }

    reassignTarget?.let { caseId ->
        ReassignDialog(
            onDismiss = { reassignTarget = null },
            onConfirm = { target, reason -> viewModel.reassign(caseId, target, reason); reassignTarget = null },
        )
    }
}

@Composable
private fun KycWorkloadContent(
    data: KycWorkloadData,
    actionInFlight: Boolean,
    onClaim: (String) -> Unit,
    onUnclaim: (String) -> Unit,
    onEscalate: (String) -> Unit,
    onAutoAssign: (String) -> Unit,
    onReassign: (String) -> Unit,
) {
    val d = data.dashboard
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)
            .testTag(KycWorkloadTestTags.CONTENT),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        KpiGrid(
            tiles = listOf(
                "Active cases" to d.totalActiveCases.toString(),
                "On-duty admins" to d.totalOnDutyAdmins.toString(),
                "SLA breaches" to data.breaches.size.toString(),
            ),
        )

        if (d.admins.isNotEmpty()) {
            SectionHeader("Admins")
            d.admins.forEach { a ->
                CardSection(a.adminSub.ifBlank { "unknown" }) {
                    StatRow("On duty", if (a.onDuty) "Yes" else "No")
                    StatRow("Cases", "${a.currentCaseCount} / ${a.maxCases}")
                    StatRow("Avg hours", "%.1f".format(a.avgProcessingHours))
                    if (a.languages.isNotEmpty()) StatRow("Languages", a.languages.joinToString(", "))
                }
            }
        }

        if (data.breaches.isNotEmpty()) {
            SectionHeader("SLA breaches")
            data.breaches.forEach { b ->
                CardSection(b.kycCaseId) {
                    StatRow("Tier", b.tier.ifBlank { "-" })
                    StatRow("Hours overdue", "%.1f".format(b.hoursOverdue))
                    StatRow("Escalation level", b.escalationLevel.toString())
                }
            }
        }

        SectionHeader("My queue")
        if (data.myQueue.isEmpty()) {
            Text("No cases assigned to you.", style = androidx.compose.material3.MaterialTheme.typography.bodyMedium)
        }
        data.myQueue.forEach { c ->
            CardSection(c.kycCaseId) {
                StatRow("Status", c.status.replace('_', ' '))
                StatRow("Tier", c.tier.ifBlank { "-" })
                StatRow("Overdue", if (c.overdue) "Yes" else "No")
                Row(
                    Modifier.fillMaxWidth().padding(top = 8.dp).testTag(KycWorkloadTestTags.caseRow(c.kycCaseId)),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    OutlinedButton(onClick = { onUnclaim(c.kycCaseId) }, enabled = !actionInFlight) { Text("Unclaim") }
                    OutlinedButton(onClick = { onEscalate(c.kycCaseId) }, enabled = !actionInFlight) { Text("Escalate") }
                    OutlinedButton(onClick = { onReassign(c.kycCaseId) }, enabled = !actionInFlight) { Text("Reassign") }
                }
            }
        }
    }
}

@Composable
private fun ReassignDialog(onDismiss: () -> Unit, onConfirm: (String, String) -> Unit) {
    var target by remember { mutableStateOf("") }
    var reason by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Reassign case") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(value = target, onValueChange = { target = it }, label = { Text("Target admin sub") }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = reason, onValueChange = { reason = it }, label = { Text("Reason (optional)") }, modifier = Modifier.fillMaxWidth())
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(target, reason) }, enabled = target.isNotBlank()) { Text("Reassign") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
