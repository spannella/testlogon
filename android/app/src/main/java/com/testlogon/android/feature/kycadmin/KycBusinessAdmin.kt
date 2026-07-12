@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.kycadmin

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Apartment
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.kycadmin.KybCaseDto
import com.testlogon.android.data.kycadmin.KycBusinessAdminRepository
import com.testlogon.android.feature.adminmod.AdminOpsErrorType
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/** A8 — business (KYB) case review queue (queue + detail + screen/approve/reject). */

val KYB_STATUSES = listOf("submitted", "under_review", "needs_more_info", "approved", "rejected")
val KYB_REASON_CODES = listOf("registration_verified", "ubo_verified", "documents_valid", "screening_hit", "incomplete_ownership", "suspected_fraud")

sealed interface KybListState {
    data object Loading : KybListState
    data class Data(val cases: List<KybCaseDto>, val isRefreshing: Boolean = false) : KybListState
    data object Empty : KybListState
    data object Forbidden : KybListState
    data class Error(val type: AdminOpsErrorType) : KybListState
}

sealed interface KybDetailState {
    data object Loading : KybDetailState
    data class Data(val case: KybCaseDto) : KybDetailState
    data object Forbidden : KybDetailState
    data class Error(val type: AdminOpsErrorType) : KybDetailState
}

data class KycBusinessAdminUiState(
    val statusFilter: String = "submitted",
    val list: KybListState = KybListState.Loading,
    val detail: KybDetailState? = null,
    val actionInFlight: Boolean = false,
    val message: String? = null,
    val transientError: AdminOpsErrorType? = null,
)

@HiltViewModel
class KycBusinessAdminViewModel @Inject constructor(
    private val repo: KycBusinessAdminRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(KycBusinessAdminUiState())
    val state: StateFlow<KycBusinessAdminUiState> = _state.asStateFlow()

    init { fetch(false) }

    fun retry() = fetch(false)

    fun setStatus(status: String) {
        if (_state.value.statusFilter == status) return
        _state.value = _state.value.copy(statusFilter = status, list = KybListState.Loading)
        fetch(false)
    }

    fun refresh() {
        val cur = _state.value.list
        _state.value = _state.value.copy(list = if (cur is KybListState.Data) cur.copy(isRefreshing = true) else cur, transientError = null)
        fetch(true)
    }

    private fun fetch(isRefresh: Boolean) {
        viewModelScope.launch {
            val status = _state.value.statusFilter.ifBlank { null }
            when (val r = repo.queue(status)) {
                is ApiResult.Success -> {
                    val cases = r.data
                    _state.value = _state.value.copy(list = if (cases.isEmpty()) KybListState.Empty else KybListState.Data(cases))
                }
                is ApiResult.Failure -> _state.value = _state.value.copy(
                    list = when (r.error.status) {
                        403 -> KybListState.Forbidden
                        else -> (_state.value.list as? KybListState.Data)?.takeIf { isRefresh }?.copy(isRefreshing = false)
                            ?: KybListState.Error(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                    },
                    transientError = if (isRefresh && _state.value.list is KybListState.Data) (if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER) else null,
                )
                is ApiResult.NetworkError -> _state.value = _state.value.copy(
                    list = (_state.value.list as? KybListState.Data)?.takeIf { isRefresh }?.copy(isRefreshing = false)
                        ?: KybListState.Error(AdminOpsErrorType.NETWORK),
                    transientError = if (isRefresh && _state.value.list is KybListState.Data) AdminOpsErrorType.NETWORK else null,
                )
            }
        }
    }

    fun openDetail(caseId: String) {
        _state.value = _state.value.copy(detail = KybDetailState.Loading)
        viewModelScope.launch {
            _state.value = _state.value.copy(
                detail = when (val r = repo.detail(caseId)) {
                    is ApiResult.Success -> KybDetailState.Data(r.data)
                    is ApiResult.Failure -> if (r.error.status == 403) KybDetailState.Forbidden
                    else KybDetailState.Error(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                    is ApiResult.NetworkError -> KybDetailState.Error(AdminOpsErrorType.NETWORK)
                },
            )
        }
    }

    fun screen(caseId: String) {
        if (_state.value.actionInFlight) return
        _state.value = _state.value.copy(actionInFlight = true, transientError = null, message = null)
        viewModelScope.launch {
            when (val r = repo.screen(caseId)) {
                is ApiResult.Success -> { _state.value = _state.value.copy(actionInFlight = false, message = "Screening triggered"); openDetail(caseId) }
                is ApiResult.Failure -> _state.value = _state.value.copy(actionInFlight = false, transientError = if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                is ApiResult.NetworkError -> _state.value = _state.value.copy(actionInFlight = false, transientError = AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun decide(caseId: String, decision: String, reasonCodes: List<String>, note: String) {
        val d = _state.value.detail as? KybDetailState.Data ?: return
        if (_state.value.actionInFlight) return
        _state.value = _state.value.copy(actionInFlight = true, transientError = null, message = null)
        viewModelScope.launch {
            val v = d.case.version
            val r = if (decision == "approve") repo.approve(caseId, v, reasonCodes, note) else repo.reject(caseId, v, reasonCodes, note)
            when (r) {
                is ApiResult.Success -> { _state.value = _state.value.copy(actionInFlight = false, message = "Case $decision submitted", detail = KybDetailState.Data(r.data)); fetch(true) }
                is ApiResult.Failure -> _state.value = _state.value.copy(actionInFlight = false, transientError = if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                is ApiResult.NetworkError -> _state.value = _state.value.copy(actionInFlight = false, transientError = AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun closeDetail() { _state.value = _state.value.copy(detail = null) }
    fun clearMessage() { _state.value = _state.value.copy(message = null, transientError = null) }
}

object KycBusinessAdminTestTags {
    const val SCREEN = "kyc_business_screen"
    const val LIST = "kyc_business_list"
    const val EMPTY = "kyc_business_empty"
    const val FORBIDDEN = "kyc_business_forbidden"
    const val RETRY = "kyc_business_retry"
    const val DETAIL = "kyc_business_detail"
    const val SCREEN_BTN = "kyc_business_screen_btn"
    const val APPROVE = "kyc_business_approve"
    const val REJECT = "kyc_business_reject"
    const val DECISION_CONFIRM = "kyc_business_decision_confirm"
    fun row(id: String) = "kyc_business_row_$id"
    fun statusChip(s: String) = "kyc_business_status_$s"
}

@Composable
fun KycBusinessAdminRoute(onBack: () -> Unit, viewModel: KycBusinessAdminViewModel = hiltViewModel()) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val snackbar = remember { SnackbarHostState() }
    LaunchedEffect(state.message, state.transientError) {
        val msg = state.message ?: state.transientError?.let { kycAdminErrorMessage(it) }
        if (msg != null) { snackbar.showSnackbar(msg); viewModel.clearMessage() }
    }

    val detail = state.detail
    if (detail != null) {
        BackHandler(onBack = viewModel::closeDetail)
        KybDetail(detail, state.actionInFlight, snackbar, viewModel::closeDetail, viewModel::screen, viewModel::decide)
        return
    }

    Scaffold(
        modifier = Modifier.testTag(KycBusinessAdminTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("Business KYC review") },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") } },
            )
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            Row(
                Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(horizontal = 12.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                KYB_STATUSES.forEach { s ->
                    FilterChip(
                        selected = state.statusFilter == s,
                        onClick = { viewModel.setStatus(s) },
                        label = { Text(s.replace('_', ' ')) },
                        modifier = Modifier.testTag(KycBusinessAdminTestTags.statusChip(s)),
                    )
                }
            }
            val isRefreshing = (state.list as? KybListState.Data)?.isRefreshing == true
            PullToRefreshBox(isRefreshing = isRefreshing, onRefresh = viewModel::refresh, modifier = Modifier.fillMaxSize()) {
                when (val l = state.list) {
                    is KybListState.Loading -> LoadingState()
                    is KybListState.Empty -> EmptyState(
                        modifier = Modifier.testTag(KycBusinessAdminTestTags.EMPTY),
                        title = "No cases", body = "There are no ${state.statusFilter.replace('_', ' ')} business cases.",
                        imageVector = Icons.Outlined.Apartment,
                    )
                    is KybListState.Forbidden -> EmptyState(
                        modifier = Modifier.testTag(KycBusinessAdminTestTags.FORBIDDEN),
                        title = "Not authorised", body = "You need admin access to review business KYC.",
                        imageVector = Icons.Outlined.Lock, actionLabel = "Back", onAction = onBack,
                    )
                    is KybListState.Error -> ErrorState(
                        modifier = Modifier.testTag(KycBusinessAdminTestTags.RETRY),
                        message = kycAdminErrorMessage(l.type), onRetry = viewModel::retry,
                    )
                    is KybListState.Data -> LazyColumn(
                        modifier = Modifier.fillMaxSize().testTag(KycBusinessAdminTestTags.LIST),
                        contentPadding = PaddingValues(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        items(items = l.cases, key = { it.kybCaseId }) { c ->
                            Card(modifier = Modifier.fillMaxWidth().testTag(KycBusinessAdminTestTags.row(c.kybCaseId)), onClick = { viewModel.openDetail(c.kybCaseId) }) {
                                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                    Text(c.company.legalName.ifBlank { c.kybCaseId }, style = MaterialTheme.typography.titleSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        Text(c.status.replace('_', ' '), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                                        Text(c.company.jurisdiction, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                        Text("${c.uboSummary.totalUbos} UBOs", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun KybDetail(
    detail: KybDetailState,
    actionInFlight: Boolean,
    snackbar: SnackbarHostState,
    onBack: () -> Unit,
    onScreen: (String) -> Unit,
    onDecide: (String, String, List<String>, String) -> Unit,
) {
    var decision by remember { mutableStateOf<String?>(null) }
    Scaffold(
        modifier = Modifier.testTag(KycBusinessAdminTestTags.DETAIL),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("Business case") },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") } },
            )
        },
    ) { padding ->
        when (detail) {
            is KybDetailState.Loading -> LoadingState(modifier = Modifier.padding(padding))
            is KybDetailState.Forbidden -> EmptyState(
                modifier = Modifier.padding(padding).testTag(KycBusinessAdminTestTags.FORBIDDEN),
                title = "Not authorised", body = "Admin access required.", imageVector = Icons.Outlined.Lock,
                actionLabel = "Back", onAction = onBack,
            )
            is KybDetailState.Error -> ErrorState(modifier = Modifier.padding(padding), message = kycAdminErrorMessage(detail.type), onRetry = onBack)
            is KybDetailState.Data -> {
                val c = detail.case
                LazyColumn(
                    modifier = Modifier.fillMaxSize().padding(padding),
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    item {
                        Card(Modifier.fillMaxWidth()) {
                            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                Text(c.company.legalName.ifBlank { c.kybCaseId }, style = MaterialTheme.typography.titleMedium)
                                c.company.tradingName?.takeIf { it.isNotBlank() }?.let { Text("Trading as $it", style = MaterialTheme.typography.bodySmall) }
                                Text("Status: ${c.status.replace('_', ' ')} (v${c.version})", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.primary)
                                Text("Reg: ${c.company.registrationNumber} - ${c.company.jurisdiction}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                c.company.companyType.takeIf { it.isNotBlank() }?.let { Text("Type: ${it.replace('_', ' ')}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                                c.company.industry?.takeIf { it.isNotBlank() }?.let { Text("Industry: $it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                            }
                        }
                    }
                    item {
                        Card(Modifier.fillMaxWidth()) {
                            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Text("Ownership & structure", style = MaterialTheme.typography.titleSmall)
                                Text("UBOs: ${c.uboSummary.totalUbos} (${c.uboSummary.totalOwnershipPct}% covered, ${if (c.uboSummary.allKycApproved) "all KYC approved" else "KYC pending"})", style = MaterialTheme.typography.bodySmall)
                                Text("Directors: ${c.directorCount}", style = MaterialTheme.typography.bodySmall)
                                Text("Documents: ${c.documentCount}", style = MaterialTheme.typography.bodySmall)
                            }
                        }
                    }
                    item {
                        if (actionInFlight) {
                            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) { CircularProgressIndicator() }
                        } else {
                            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                OutlinedButton(onClick = { onScreen(c.kybCaseId) }, modifier = Modifier.fillMaxWidth().testTag(KycBusinessAdminTestTags.SCREEN_BTN)) { Text("Run screening") }
                                Button(onClick = { decision = "approve" }, modifier = Modifier.fillMaxWidth().testTag(KycBusinessAdminTestTags.APPROVE)) { Text("Approve") }
                                OutlinedButton(onClick = { decision = "reject" }, modifier = Modifier.fillMaxWidth().testTag(KycBusinessAdminTestTags.REJECT)) { Text("Reject") }
                            }
                        }
                    }
                }

                decision?.let { dec ->
                    val selected = remember { mutableStateListOf<String>() }
                    var note by remember { mutableStateOf("") }
                    AlertDialog(
                        onDismissRequest = { decision = null },
                        title = { Text(if (dec == "approve") "Approve case" else "Reject case") },
                        text = {
                            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Text("Reason codes", style = MaterialTheme.typography.labelMedium)
                                KYB_REASON_CODES.forEach { code ->
                                    Row(Modifier.fillMaxWidth().toggleable(value = selected.contains(code), onValueChange = { if (it) selected.add(code) else selected.remove(code) }), verticalAlignment = Alignment.CenterVertically) {
                                        Checkbox(checked = selected.contains(code), onCheckedChange = null)
                                        Text(code.replace('_', ' '))
                                    }
                                }
                                OutlinedTextField(value = note, onValueChange = { note = it }, label = { Text("Note") }, modifier = Modifier.fillMaxWidth())
                            }
                        },
                        confirmButton = { TextButton(onClick = { onDecide(c.kybCaseId, dec, selected.toList(), note); decision = null }, modifier = Modifier.testTag(KycBusinessAdminTestTags.DECISION_CONFIRM)) { Text("Confirm") } },
                        dismissButton = { TextButton(onClick = { decision = null }) { Text("Cancel") } },
                    )
                }
            }
        }
    }
}
