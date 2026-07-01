@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.admindisputes

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
import androidx.compose.material.icons.outlined.Gavel
import androidx.compose.material.icons.outlined.Lock
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
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.admindisputes.DisputeDto
import com.testlogon.android.feature.adminmod.AdminOpsErrorType

object DisputeAdminTestTags {
    const val SCREEN = "dispute_admin_screen"
    const val LIST = "dispute_admin_list"
    const val EMPTY = "dispute_admin_empty"
    const val FORBIDDEN = "dispute_admin_forbidden"
    const val ERROR_RETRY = "dispute_admin_error_retry"
    fun filter(s: String) = "dispute_filter_$s"
    fun row(id: String) = "dispute_row_$id"
    fun respond(id: String) = "dispute_respond_$id"
    fun resolve(id: String) = "dispute_resolve_$id"
    const val RESPOND_CONFIRM = "dispute_respond_confirm"
    const val RESOLVE_CONFIRM = "dispute_resolve_confirm"
    fun resolutionOption(r: String) = "dispute_resolution_$r"
}

@Composable
fun DisputeAdminRoute(
    onBack: () -> Unit,
    viewModel: DisputeAdminViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    DisputeAdminScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        onSetFilter = viewModel::setFilter,
        onRespond = viewModel::respond,
        onResolve = viewModel::resolve,
        onMessageShown = viewModel::clearMessage,
    )
}

@Composable
fun DisputeAdminScreen(
    state: DisputeAdminUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onSetFilter: (String) -> Unit,
    onRespond: (String, String) -> Unit,
    onResolve: (String, String, String?) -> Unit,
    onMessageShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbar = remember { SnackbarHostState() }
    var respondTarget by remember { mutableStateOf<String?>(null) }
    var resolveTarget by remember { mutableStateOf<String?>(null) }
    val content = state as? DisputeAdminUiState.Content

    LaunchedEffect(content?.message, content?.transientError) {
        val msg = content?.message ?: content?.transientError?.let { disputeErrorMessage(it) }
        if (msg != null) {
            snackbar.showSnackbar(msg)
            onMessageShown()
        }
    }

    val activeFilter = when (state) {
        is DisputeAdminUiState.Content -> state.statusFilter
        is DisputeAdminUiState.Empty -> state.statusFilter
        else -> DISPUTE_STATUS_FILTERS.first()
    }

    Scaffold(
        modifier = modifier.testTag(DisputeAdminTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("Disputes") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            FilterRow(active = activeFilter, onSelect = onSetFilter)
            val isRefreshing = content?.isRefreshing == true
            PullToRefreshBox(
                isRefreshing = isRefreshing,
                onRefresh = onRefresh,
                modifier = Modifier.fillMaxSize(),
            ) {
                when (state) {
                    is DisputeAdminUiState.Loading -> LoadingState()
                    is DisputeAdminUiState.Empty -> EmptyState(
                        modifier = Modifier.testTag(DisputeAdminTestTags.EMPTY),
                        title = "No disputes",
                        body = "There are no ${state.statusFilter.replace('_', ' ')} disputes.",
                        imageVector = Icons.Outlined.Gavel,
                    )
                    is DisputeAdminUiState.Forbidden -> EmptyState(
                        modifier = Modifier.testTag(DisputeAdminTestTags.FORBIDDEN),
                        title = "Not authorised",
                        body = "You need billing-admin access to review disputes.",
                        imageVector = Icons.Outlined.Lock,
                        actionLabel = "Back",
                        onAction = onBack,
                    )
                    is DisputeAdminUiState.Error -> ErrorState(
                        modifier = Modifier.testTag(DisputeAdminTestTags.ERROR_RETRY),
                        message = disputeErrorMessage(state.type),
                        onRetry = onRetry,
                    )
                    is DisputeAdminUiState.Content -> LazyColumn(
                        modifier = Modifier.fillMaxSize().testTag(DisputeAdminTestTags.LIST),
                        contentPadding = PaddingValues(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        items(items = state.disputes, key = { it.disputeId }) { d ->
                            DisputeRow(
                                dispute = d,
                                inFlight = state.actionInFlightId == d.disputeId,
                                actionsEnabled = state.actionInFlightId == null,
                                onRespond = { respondTarget = d.disputeId },
                                onResolve = { resolveTarget = d.disputeId },
                            )
                        }
                    }
                }
            }
        }
    }

    respondTarget?.let { targetId ->
        RespondDialog(
            onDismiss = { respondTarget = null },
            onConfirm = { evidence ->
                onRespond(targetId, evidence)
                respondTarget = null
            },
        )
    }
    resolveTarget?.let { targetId ->
        ResolveDialog(
            onDismiss = { resolveTarget = null },
            onConfirm = { resolution, notes ->
                onResolve(targetId, resolution, notes)
                resolveTarget = null
            },
        )
    }
}

@Composable
private fun FilterRow(active: String, onSelect: (String) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        DISPUTE_STATUS_FILTERS.forEach { s ->
            FilterChip(
                selected = active == s,
                onClick = { onSelect(s) },
                label = { Text(s.replace('_', ' ').replaceFirstChar { it.uppercase() }) },
                modifier = Modifier.testTag(DisputeAdminTestTags.filter(s)),
            )
        }
    }
}

@Composable
private fun DisputeRow(
    dispute: DisputeDto,
    inFlight: Boolean,
    actionsEnabled: Boolean,
    onRespond: () -> Unit,
    onResolve: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(DisputeAdminTestTags.row(dispute.disputeId))) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(formatCents(dispute.amountCents, dispute.currency), style = MaterialTheme.typography.titleMedium)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(dispute.status.ifBlank { "-" }.replace('_', ' '), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                Text(dispute.provider, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                if (dispute.evidenceSubmitted) {
                    Text("Evidence sent", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.tertiary)
                }
            }
            dispute.userId?.takeIf { it.isNotBlank() }?.let {
                Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            if (dispute.reason.isNotBlank()) {
                Text(dispute.reason, style = MaterialTheme.typography.bodySmall, maxLines = 3, overflow = TextOverflow.Ellipsis)
            }
            dispute.resolution?.takeIf { it.isNotBlank() }?.let {
                Text("Resolution: $it", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.tertiary)
            }
            if (inFlight) {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) { CircularProgressIndicator() }
            } else if (dispute.resolution.isNullOrBlank()) {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(
                        onClick = onRespond,
                        enabled = actionsEnabled,
                        modifier = Modifier.weight(1f).testTag(DisputeAdminTestTags.respond(dispute.disputeId)),
                    ) { Text("Respond") }
                    Button(
                        onClick = onResolve,
                        enabled = actionsEnabled,
                        modifier = Modifier.weight(1f).testTag(DisputeAdminTestTags.resolve(dispute.disputeId)),
                    ) { Text("Resolve") }
                }
            }
        }
    }
}

@Composable
private fun RespondDialog(onDismiss: () -> Unit, onConfirm: (String) -> Unit) {
    var evidence by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Submit evidence") },
        text = {
            OutlinedTextField(
                value = evidence,
                onValueChange = { evidence = it },
                label = { Text("Evidence (required)") },
                modifier = Modifier.fillMaxWidth(),
            )
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(evidence) },
                enabled = evidence.isNotBlank(),
                modifier = Modifier.testTag(DisputeAdminTestTags.RESPOND_CONFIRM),
            ) { Text("Submit") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun ResolveDialog(onDismiss: () -> Unit, onConfirm: (String, String?) -> Unit) {
    var selected by remember { mutableStateOf(DISPUTE_RESOLUTIONS.first()) }
    var notes by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Resolve dispute") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                DISPUTE_RESOLUTIONS.forEach { r ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .selectable(selected = selected == r, onClick = { selected = r })
                            .testTag(DisputeAdminTestTags.resolutionOption(r)),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(selected = selected == r, onClick = { selected = r })
                        Text(r.replaceFirstChar { it.uppercase() })
                    }
                }
                OutlinedTextField(
                    value = notes,
                    onValueChange = { notes = it },
                    label = { Text("Notes (optional)") },
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(selected, notes.ifBlank { null }) },
                modifier = Modifier.testTag(DisputeAdminTestTags.RESOLVE_CONFIRM),
            ) { Text("Confirm") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

private fun formatCents(cents: Long, currency: String): String {
    val amount = cents / 100.0
    val sym = when (currency.uppercase()) {
        "USD" -> "$"; "EUR" -> "€"; "GBP" -> "£"; else -> "$currency "
    }
    return "%s%,.2f".format(sym, amount)
}

internal fun disputeErrorMessage(type: AdminOpsErrorType): String = when (type) {
    AdminOpsErrorType.AUTH -> "Your session expired. Please sign in again."
    AdminOpsErrorType.SERVER -> "Something went wrong on the server. Try again."
    AdminOpsErrorType.NETWORK -> "You appear to be offline. Check your connection."
}
