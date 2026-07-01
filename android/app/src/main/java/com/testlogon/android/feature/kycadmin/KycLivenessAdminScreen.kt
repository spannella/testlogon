@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.kycadmin

import android.content.Intent
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
import androidx.compose.foundation.selection.selectable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Videocam
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
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
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.net.toUri
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.kycadmin.KycLivenessDto

object KycLivenessAdminTestTags {
    const val SCREEN = "kyc_liveness_screen"
    const val LIST = "kyc_liveness_list"
    const val EMPTY = "kyc_liveness_empty"
    const val FORBIDDEN = "kyc_liveness_forbidden"
    const val RETRY = "kyc_liveness_retry"
    const val DETAIL = "kyc_liveness_detail"
    const val CONDUCT = "kyc_liveness_conduct"
    const val RESULT = "kyc_liveness_result"
    const val CANCEL = "kyc_liveness_cancel"
    const val JOIN = "kyc_liveness_join"
    const val RESULT_CONFIRM = "kyc_liveness_result_confirm"
    fun row(id: String) = "kyc_liveness_row_$id"
    fun statusChip(s: String) = "kyc_liveness_status_$s"
}

@Composable
fun KycLivenessAdminRoute(onBack: () -> Unit, viewModel: KycLivenessAdminViewModel = hiltViewModel()) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val context = LocalContext.current
    KycLivenessAdminScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        onSetStatus = viewModel::setStatus,
        onOpenDetail = viewModel::openDetail,
        onConduct = viewModel::conduct,
        onCancel = viewModel::cancel,
        onRecordResult = viewModel::recordResult,
        onJoin = { url ->
            runCatching {
                context.startActivity(Intent(Intent.ACTION_VIEW, url.toUri()).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            }
        },
        onCloseDetail = viewModel::closeDetail,
        onMessageShown = viewModel::clearMessage,
    )
}

@Composable
fun KycLivenessAdminScreen(
    state: KycLivenessAdminUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onSetStatus: (String) -> Unit,
    onOpenDetail: (String) -> Unit,
    onConduct: (String) -> Unit,
    onCancel: (String) -> Unit,
    onRecordResult: (String, String, String) -> Unit,
    onJoin: (String) -> Unit,
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
        LivenessDetail(
            detail = state.detail,
            actionInFlight = state.actionInFlight,
            snackbar = snackbar,
            onBack = onCloseDetail,
            onConduct = onConduct,
            onCancel = onCancel,
            onRecordResult = onRecordResult,
            onJoin = onJoin,
            modifier = modifier,
        )
        return
    }

    Scaffold(
        modifier = modifier.testTag(KycLivenessAdminTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("Liveness call verifier") },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") } },
            )
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            Row(
                Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(horizontal = 12.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                KYC_LIVENESS_STATUSES.forEach { s ->
                    FilterChip(
                        selected = state.statusFilter == s,
                        onClick = { onSetStatus(s) },
                        label = { Text(s.replace('_', ' ')) },
                        modifier = Modifier.testTag(KycLivenessAdminTestTags.statusChip(s)),
                    )
                }
            }
            val isRefreshing = (state.list as? LivenessListState.Data)?.isRefreshing == true
            PullToRefreshBox(isRefreshing = isRefreshing, onRefresh = onRefresh, modifier = Modifier.fillMaxSize()) {
                when (val l = state.list) {
                    is LivenessListState.Loading -> LoadingState()
                    is LivenessListState.Empty -> EmptyState(
                        modifier = Modifier.testTag(KycLivenessAdminTestTags.EMPTY),
                        title = "No calls", body = "There are no ${state.statusFilter.replace('_', ' ')} calls.",
                        imageVector = Icons.Outlined.Videocam,
                    )
                    is LivenessListState.Forbidden -> EmptyState(
                        modifier = Modifier.testTag(KycLivenessAdminTestTags.FORBIDDEN),
                        title = "Not authorised", body = "You need admin access to verify liveness calls.",
                        imageVector = Icons.Outlined.Lock, actionLabel = "Back", onAction = onBack,
                    )
                    is LivenessListState.Error -> ErrorState(
                        modifier = Modifier.testTag(KycLivenessAdminTestTags.RETRY),
                        message = kycAdminErrorMessage(l.type), onRetry = onRetry,
                    )
                    is LivenessListState.Data -> LazyColumn(
                        modifier = Modifier.fillMaxSize().testTag(KycLivenessAdminTestTags.LIST),
                        contentPadding = PaddingValues(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        items(items = l.calls, key = { it.callId }) { call ->
                            Card(modifier = Modifier.fillMaxWidth().testTag(KycLivenessAdminTestTags.row(call.callId)), onClick = { onOpenDetail(call.callId) }) {
                                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                    Text(call.userSub ?: call.caseId.ifBlank { call.callId }, style = MaterialTheme.typography.titleSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        Text(call.status.replace('_', ' '), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                                        Text("${call.durationMinutes} min", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
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
private fun LivenessDetail(
    detail: LivenessDetailState,
    actionInFlight: Boolean,
    snackbar: SnackbarHostState,
    onBack: () -> Unit,
    onConduct: (String) -> Unit,
    onCancel: (String) -> Unit,
    onRecordResult: (String, String, String) -> Unit,
    onJoin: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    var resultDialog by remember { mutableStateOf(false) }

    Scaffold(
        modifier = modifier.testTag(KycLivenessAdminTestTags.DETAIL),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("Liveness call") },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") } },
            )
        },
    ) { padding ->
        when (detail) {
            is LivenessDetailState.Loading -> LoadingState(modifier = Modifier.padding(padding))
            is LivenessDetailState.Forbidden -> EmptyState(
                modifier = Modifier.padding(padding).testTag(KycLivenessAdminTestTags.FORBIDDEN),
                title = "Not authorised", body = "Admin access required.", imageVector = Icons.Outlined.Lock,
                actionLabel = "Back", onAction = onBack,
            )
            is LivenessDetailState.Error -> ErrorState(modifier = Modifier.padding(padding), message = kycAdminErrorMessage(detail.type), onRetry = onBack)
            is LivenessDetailState.Data -> {
                val c: KycLivenessDto = detail.call
                LazyColumn(
                    modifier = Modifier.fillMaxSize().padding(padding),
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    item {
                        Card(Modifier.fillMaxWidth()) {
                            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                Text(c.userSub ?: c.caseId.ifBlank { c.callId }, style = MaterialTheme.typography.titleMedium)
                                Text("Status: ${c.status.replace('_', ' ')}", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.primary)
                                Text("Duration: ${c.durationMinutes} min", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                c.verifierSub?.let { Text("Verifier: $it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                                c.result?.let { Text("Result: $it", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.tertiary) }
                                c.resultNotes?.takeIf { it.isNotBlank() }?.let { Text("Notes: $it", style = MaterialTheme.typography.bodySmall) }
                                c.note?.takeIf { it.isNotBlank() }?.let { Text("Applicant note: $it", style = MaterialTheme.typography.bodySmall) }
                            }
                        }
                    }
                    item {
                        if (actionInFlight) {
                            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) { CircularProgressIndicator() }
                        } else {
                            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                c.joinUrl?.takeIf { it.isNotBlank() }?.let { url ->
                                    Button(onClick = { onJoin(url) }, modifier = Modifier.fillMaxWidth().testTag(KycLivenessAdminTestTags.JOIN)) { Text("Join call") }
                                }
                                val active = c.status.equals("scheduled", true) || c.status.equals("in_progress", true)
                                if (active) {
                                    OutlinedButton(onClick = { onConduct(c.callId) }, modifier = Modifier.fillMaxWidth().testTag(KycLivenessAdminTestTags.CONDUCT)) { Text("Mark in progress") }
                                    Button(onClick = { resultDialog = true }, modifier = Modifier.fillMaxWidth().testTag(KycLivenessAdminTestTags.RESULT)) { Text("Record result") }
                                    OutlinedButton(onClick = { onCancel(c.callId) }, modifier = Modifier.fillMaxWidth().testTag(KycLivenessAdminTestTags.CANCEL)) { Text("Cancel call") }
                                }
                            }
                        }
                    }
                }

                if (resultDialog) {
                    ResultDialog(
                        onDismiss = { resultDialog = false },
                        onConfirm = { result, notes -> onRecordResult(c.callId, result, notes); resultDialog = false },
                    )
                }
            }
        }
    }
}

@Composable
private fun ResultDialog(onDismiss: () -> Unit, onConfirm: (String, String) -> Unit) {
    val options = listOf("passed", "failed")
    var selected by remember { mutableStateOf(options.first()) }
    var notes by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Record result") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                options.forEach { o ->
                    Row(Modifier.fillMaxWidth().selectable(selected = selected == o, onClick = { selected = o }), verticalAlignment = Alignment.CenterVertically) {
                        RadioButton(selected = selected == o, onClick = { selected = o })
                        Text(o.replaceFirstChar { it.uppercase() })
                    }
                }
                OutlinedTextField(value = notes, onValueChange = { notes = it }, label = { Text("Notes") }, modifier = Modifier.fillMaxWidth())
            }
        },
        confirmButton = { TextButton(onClick = { onConfirm(selected, notes) }, modifier = Modifier.testTag(KycLivenessAdminTestTags.RESULT_CONFIRM)) { Text("Confirm") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
