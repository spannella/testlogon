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
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.VerifiedUser
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
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.kycadmin.KycQueueItemDto

object KycCaseAdminTestTags {
    const val SCREEN = "kyc_case_admin_screen"
    const val LIST = "kyc_case_admin_list"
    const val EMPTY = "kyc_case_admin_empty"
    const val FORBIDDEN = "kyc_case_admin_forbidden"
    const val ERROR_RETRY = "kyc_case_admin_error_retry"
    const val DETAIL = "kyc_case_admin_detail"
    const val APPROVE = "kyc_case_approve"
    const val REJECT = "kyc_case_reject"
    const val REQUEST_INFO = "kyc_case_request_info"
    const val DECISION_CONFIRM = "kyc_case_decision_confirm"
    fun row(id: String) = "kyc_case_row_$id"
    fun statusChip(s: String) = "kyc_case_status_$s"
}

@Composable
fun KycCaseAdminRoute(
    onBack: () -> Unit,
    viewModel: KycCaseAdminViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    KycCaseAdminScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        onSetStatus = viewModel::setStatusFilter,
        onOpenDetail = viewModel::openDetail,
        onReloadDetail = viewModel::reloadDetail,
        onDecide = viewModel::decide,
        onCloseDetail = viewModel::closeDetail,
        onMessageShown = viewModel::clearMessage,
    )
}

@Composable
fun KycCaseAdminScreen(
    state: KycCaseAdminUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onSetStatus: (String) -> Unit,
    onOpenDetail: (String) -> Unit,
    onReloadDetail: (String) -> Unit,
    onDecide: (String, String, List<String>, String) -> Unit,
    onCloseDetail: () -> Unit,
    onMessageShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbar = remember { SnackbarHostState() }
    LaunchedEffect(state.message, state.transientError) {
        val msg = state.message ?: state.transientError?.let { kycAdminErrorMessage(it) }
        if (msg != null) { snackbar.showSnackbar(msg); onMessageShown() }
    }

    if (state.detail != null) {
        BackHandler(onBack = onCloseDetail)
        KycCaseDetailScreen(
            detail = state.detail,
            actionInFlight = state.actionInFlight,
            snackbar = snackbar,
            onBack = onCloseDetail,
            onReload = onReloadDetail,
            onDecide = onDecide,
            modifier = modifier,
        )
        return
    }

    Scaffold(
        modifier = modifier.testTag(KycCaseAdminTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("KYC review queue") },
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") }
                },
            )
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            Row(
                Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(horizontal = 12.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                KYC_CASE_STATUSES.forEach { s ->
                    FilterChip(
                        selected = state.statusFilter == s,
                        onClick = { onSetStatus(s) },
                        label = { Text(s.replace('_', ' ')) },
                        modifier = Modifier.testTag(KycCaseAdminTestTags.statusChip(s)),
                    )
                }
            }
            val isRefreshing = (state.list as? KycCaseListState.Data)?.isRefreshing == true
            PullToRefreshBox(isRefreshing = isRefreshing, onRefresh = onRefresh, modifier = Modifier.fillMaxSize()) {
                when (val l = state.list) {
                    is KycCaseListState.Loading -> LoadingState()
                    is KycCaseListState.Empty -> EmptyState(
                        modifier = Modifier.testTag(KycCaseAdminTestTags.EMPTY),
                        title = "No cases",
                        body = "There are no ${state.statusFilter.replace('_', ' ')} cases.",
                        imageVector = Icons.Outlined.VerifiedUser,
                    )
                    is KycCaseListState.Forbidden -> EmptyState(
                        modifier = Modifier.testTag(KycCaseAdminTestTags.FORBIDDEN),
                        title = "Not authorised",
                        body = "You need admin access to review KYC cases.",
                        imageVector = Icons.Outlined.Lock,
                        actionLabel = "Back", onAction = onBack,
                    )
                    is KycCaseListState.Error -> ErrorState(
                        modifier = Modifier.testTag(KycCaseAdminTestTags.ERROR_RETRY),
                        message = kycAdminErrorMessage(l.type), onRetry = onRetry,
                    )
                    is KycCaseListState.Data -> LazyColumn(
                        modifier = Modifier.fillMaxSize().testTag(KycCaseAdminTestTags.LIST),
                        contentPadding = PaddingValues(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        items(items = l.items, key = { it.kycCaseId }) { item ->
                            KycCaseRow(item = item, onClick = { onOpenDetail(item.kycCaseId) })
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun KycCaseRow(item: KycQueueItemDto, onClick: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth().testTag(KycCaseAdminTestTags.row(item.kycCaseId)),
        onClick = onClick,
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(item.userSub.ifBlank { item.kycCaseId }, style = MaterialTheme.typography.titleSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(item.status.ifBlank { "-" }.replace('_', ' '), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                item.riskTier?.takeIf { it.isNotBlank() }?.let {
                    Text("Risk: $it", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.error)
                }
                item.waitingSeconds?.let {
                    Text("Waiting ${it / 3600}h", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            item.assignedAdminSub?.takeIf { it.isNotBlank() }?.let {
                Text("Assigned: $it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
    }
}

@Composable
private fun KycCaseDetailScreen(
    detail: KycCaseDetailState,
    actionInFlight: Boolean,
    snackbar: SnackbarHostState,
    onBack: () -> Unit,
    onReload: (String) -> Unit,
    onDecide: (String, String, List<String>, String) -> Unit,
    modifier: Modifier = Modifier,
) {
    var decisionDialog by remember { mutableStateOf<String?>(null) }

    Scaffold(
        modifier = modifier.testTag(KycCaseAdminTestTags.DETAIL),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("Case detail") },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") } },
            )
        },
    ) { padding ->
        when (detail) {
            is KycCaseDetailState.Loading -> LoadingState(modifier = Modifier.padding(padding))
            is KycCaseDetailState.Forbidden -> EmptyState(
                modifier = Modifier.padding(padding).testTag(KycCaseAdminTestTags.FORBIDDEN),
                title = "Not authorised", body = "Admin access required.", imageVector = Icons.Outlined.Lock,
                actionLabel = "Back", onAction = onBack,
            )
            is KycCaseDetailState.Error -> ErrorState(
                modifier = Modifier.padding(padding),
                message = kycAdminErrorMessage(detail.type),
                onRetry = onBack,
            )
            is KycCaseDetailState.Data -> {
                val c = detail.case
                LazyColumn(
                    modifier = Modifier.fillMaxSize().padding(padding),
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    item {
                        Card(Modifier.fillMaxWidth()) {
                            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                Text(c.userSub.ifBlank { c.kycCaseId }, style = MaterialTheme.typography.titleMedium)
                                Text("Status: ${c.status.replace('_', ' ')}", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.primary)
                                Text("Version: ${c.version}", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                c.decisionState?.decision?.let {
                                    Text("Decision: $it", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.tertiary)
                                }
                            }
                        }
                    }
                    if (c.filesRef.isNotEmpty()) {
                        item { Text("Files", style = MaterialTheme.typography.titleSmall) }
                        items(items = c.filesRef, key = { it.path }) { f ->
                            Card(Modifier.fillMaxWidth()) {
                                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                    Text(f.type.ifBlank { "file" }.replace('_', ' '), style = MaterialTheme.typography.bodyMedium)
                                    Text(f.verificationState.ifBlank { "-" }, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                    KycAdminDocImage(imageUrl = f.path, contentDescription = "Submitted ${f.type}")
                                }
                            }
                        }
                    }
                    item {
                        if (actionInFlight) {
                            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) { CircularProgressIndicator() }
                        } else {
                            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                Button(onClick = { decisionDialog = "approve" }, enabled = true, modifier = Modifier.fillMaxWidth().testTag(KycCaseAdminTestTags.APPROVE)) { Text("Approve") }
                                OutlinedButton(onClick = { decisionDialog = "reject" }, modifier = Modifier.fillMaxWidth().testTag(KycCaseAdminTestTags.REJECT)) { Text("Reject") }
                                OutlinedButton(onClick = { decisionDialog = "request_info" }, modifier = Modifier.fillMaxWidth().testTag(KycCaseAdminTestTags.REQUEST_INFO)) { Text("Request more info") }
                            }
                        }
                    }
                }

                decisionDialog?.let { decision ->
                    DecisionDialog(
                        decision = decision,
                        onDismiss = { decisionDialog = null },
                        onConfirm = { codes, note ->
                            onDecide(c.kycCaseId, decision, codes, note)
                            decisionDialog = null
                        },
                    )
                }
            }
        }
    }
}

@Composable
private fun DecisionDialog(
    decision: String,
    onDismiss: () -> Unit,
    onConfirm: (List<String>, String) -> Unit,
) {
    val selected = remember { mutableStateListOf<String>() }
    var note by remember { mutableStateOf("") }
    val title = when (decision) {
        "approve" -> "Approve case"
        "reject" -> "Reject case"
        else -> "Request more info"
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(if (decision == "request_info") "Requested items" else "Reason codes", style = MaterialTheme.typography.labelMedium)
                KYC_DECISION_REASON_CODES.forEach { code ->
                    Row(
                        Modifier.fillMaxWidth().toggleable(
                            value = selected.contains(code),
                            onValueChange = { if (it) selected.add(code) else selected.remove(code) },
                        ),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Checkbox(checked = selected.contains(code), onCheckedChange = null)
                        Text(code.replace('_', ' '))
                    }
                }
                OutlinedTextField(value = note, onValueChange = { note = it }, label = { Text("Note") }, modifier = Modifier.fillMaxWidth())
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(selected.toList(), note) }, modifier = Modifier.testTag(KycCaseAdminTestTags.DECISION_CONFIRM)) { Text("Confirm") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
