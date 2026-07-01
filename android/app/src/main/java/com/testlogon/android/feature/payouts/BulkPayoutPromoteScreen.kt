@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.payouts

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Payments
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Divider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.payouts.BulkEligibleItem
import com.testlogon.android.data.payouts.PayoutBatch
import com.testlogon.android.data.payouts.PayoutMoney
import com.testlogon.android.feature.adminops.adminOpsErrorMessage

object BulkPromoteTestTags {
    const val SCREEN = "bulk_promote_screen"
    const val LIST = "bulk_promote_list"
    const val EMPTY = "bulk_promote_empty"
    const val FORBIDDEN = "bulk_promote_forbidden"
    const val ERROR_RETRY = "bulk_promote_error_retry"
    const val PREVIEW = "bulk_promote_preview"
    const val EXECUTE = "bulk_promote_execute"
    const val CONFIRM_EXECUTE = "bulk_promote_confirm_execute"
    fun row(id: String) = "bulk_promote_row_$id"
}

@Composable
fun BulkPayoutPromoteRoute(
    onBack: () -> Unit,
    viewModel: BulkPayoutPromoteViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    BulkPayoutPromoteScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        onToggle = viewModel::toggle,
        onSelectAll = viewModel::selectAll,
        onClearSelection = viewModel::clearSelection,
        onPreview = viewModel::preview,
        onExecute = viewModel::execute,
        onMessageShown = viewModel::clearActionMessage,
    )
}

@Composable
fun BulkPayoutPromoteScreen(
    state: BulkPromoteUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onToggle: (String) -> Unit,
    onSelectAll: () -> Unit,
    onClearSelection: () -> Unit,
    onPreview: () -> Unit,
    onExecute: () -> Unit,
    onMessageShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbar = remember { SnackbarHostState() }
    var showConfirm by remember { mutableStateOf(false) }

    val message = (state as? BulkPromoteUiState.Content)?.actionMessage
    val transient = (state as? BulkPromoteUiState.Content)?.transientError
    LaunchedEffect(message, transient) {
        val text = message ?: transient?.let { adminOpsErrorMessage(it) }
        if (text != null) {
            snackbar.showSnackbar(text)
            onMessageShown()
        }
    }
    LaunchedEffect(message) { if (message != null) showConfirm = false }

    Scaffold(
        modifier = modifier.testTag(BulkPromoteTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Bulk payout console") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
        bottomBar = {
            if (state is BulkPromoteUiState.Content) {
                PromoteBottomBar(
                    state = state,
                    onPreview = onPreview,
                    onExecuteClick = { showConfirm = true },
                )
            }
        },
    ) { padding ->
        val isRefreshing = (state as? BulkPromoteUiState.Content)?.isRefreshing == true
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            when (state) {
                is BulkPromoteUiState.Loading -> LoadingState()
                is BulkPromoteUiState.Forbidden -> EmptyState(
                    modifier = Modifier.testTag(BulkPromoteTestTags.FORBIDDEN),
                    title = "Not authorised",
                    body = "You need platform-admin access to run bulk payouts.",
                    imageVector = Icons.Outlined.Lock,
                    actionLabel = "Back",
                    onAction = onBack,
                )
                is BulkPromoteUiState.Error -> ErrorState(
                    modifier = Modifier.testTag(BulkPromoteTestTags.ERROR_RETRY),
                    message = adminOpsErrorMessage(state.type),
                    onRetry = onRetry,
                )
                is BulkPromoteUiState.Content -> {
                    if (state.eligible.isEmpty()) {
                        EmptyState(
                            modifier = Modifier.testTag(BulkPromoteTestTags.EMPTY),
                            title = "Nothing eligible",
                            body = "There are no pending payouts to promote.",
                            imageVector = Icons.Outlined.Payments,
                        )
                    } else {
                        EligibleList(state, onToggle, onSelectAll, onClearSelection)
                    }
                }
            }
        }
    }

    if (showConfirm && state is BulkPromoteUiState.Content && state.preview != null) {
        ExecuteConfirmDialog(
            preview = state.preview,
            actionInFlight = state.actionInFlight,
            onDismiss = { if (!state.actionInFlight) showConfirm = false },
            onConfirm = onExecute,
        )
    }
}

@Composable
private fun EligibleList(
    state: BulkPromoteUiState.Content,
    onToggle: (String) -> Unit,
    onSelectAll: () -> Unit,
    onClearSelection: () -> Unit,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag(BulkPromoteTestTags.LIST),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = "${state.selected.size} of ${state.eligible.size} selected",
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.weight(1f),
                )
                TextButton(onClick = onSelectAll, enabled = !state.actionInFlight) { Text("All") }
                TextButton(onClick = onClearSelection, enabled = !state.actionInFlight) { Text("None") }
            }
        }
        items(items = state.eligible, key = { it.refId }) { item ->
            EligibleRow(
                item = item,
                checked = item.refId in state.selected,
                enabled = !state.actionInFlight,
                onToggle = { onToggle(item.refId) },
            )
        }
        if (state.preview != null) {
            item { PreviewCard(state.preview) }
        }
    }
}

@Composable
private fun EligibleRow(
    item: BulkEligibleItem,
    checked: Boolean,
    enabled: Boolean,
    onToggle: () -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(BulkPromoteTestTags.row(item.refId))
            .clickable(enabled = enabled, onClick = onToggle),
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Checkbox(checked = checked, onCheckedChange = { if (enabled) onToggle() }, enabled = enabled)
            Column(modifier = Modifier.weight(1f).padding(start = 4.dp)) {
                Text(formatPayoutMoney(item.amount), style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Medium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(
                    text = "${item.recipient.ifBlank { item.refId }} · ${item.status}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1, overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }
}

@Composable
private fun PreviewCard(preview: PayoutBatch) {
    Card(
        modifier = Modifier.fillMaxWidth().testTag(BulkPromoteTestTags.PREVIEW),
        colors = androidx.compose.material3.CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.secondaryContainer,
        ),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text("Preview (not executed)", style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold)
            Text("${preview.itemCount} items · ${formatPayoutMoney(preview.total)}",
                style = MaterialTheme.typography.bodyMedium)
            Text("Review the totals, then Execute to move funds.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSecondaryContainer)
        }
    }
}

@Composable
private fun PromoteBottomBar(
    state: BulkPromoteUiState.Content,
    onPreview: () -> Unit,
    onExecuteClick: () -> Unit,
) {
    Surface(tonalElevation = 3.dp) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(12.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            OutlinedButton(
                onClick = onPreview,
                enabled = !state.actionInFlight && state.selected.isNotEmpty(),
                modifier = Modifier.weight(1f).testTag(BulkPromoteTestTags.PREVIEW + "_btn"),
            ) { Text("Preview") }
            Button(
                onClick = onExecuteClick,
                enabled = !state.actionInFlight && state.preview != null,
                modifier = Modifier.weight(1f).testTag(BulkPromoteTestTags.EXECUTE),
            ) { Text("Execute") }
        }
    }
}

@Composable
private fun ExecuteConfirmDialog(
    preview: PayoutBatch,
    actionInFlight: Boolean,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
) {
    Dialog(onDismissRequest = onDismiss) {
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("Confirm payout execution", style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold)
                Divider()
                Text(
                    text = "You are about to move real funds for ${preview.itemCount} payout(s) " +
                        "totalling ${formatPayoutMoney(preview.total)}. This cannot be undone from here.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End),
                ) {
                    TextButton(onClick = onDismiss, enabled = !actionInFlight) { Text("Cancel") }
                    Button(
                        onClick = onConfirm,
                        enabled = !actionInFlight,
                        colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error),
                        modifier = Modifier.testTag(BulkPromoteTestTags.CONFIRM_EXECUTE),
                    ) { Text("Execute payouts") }
                }
            }
        }
    }
}
