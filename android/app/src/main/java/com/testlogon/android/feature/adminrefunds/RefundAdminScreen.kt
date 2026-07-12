@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.adminrefunds

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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.ReceiptLong
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
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.adminrefunds.RefundRequestDto
import com.testlogon.android.feature.adminmod.AdminOpsErrorType

object RefundAdminTestTags {
    const val SCREEN = "refund_admin_screen"
    const val LIST = "refund_admin_list"
    const val EMPTY = "refund_admin_empty"
    const val FORBIDDEN = "refund_admin_forbidden"
    const val ERROR_RETRY = "refund_admin_error_retry"
    fun filter(s: String) = "refund_filter_$s"
    fun row(id: String) = "refund_row_$id"
    fun approve(id: String) = "refund_approve_$id"
    fun reject(id: String) = "refund_reject_$id"
    const val REJECT_CONFIRM = "refund_reject_confirm"
}

@Composable
fun RefundAdminRoute(
    onBack: () -> Unit,
    viewModel: RefundAdminViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    RefundAdminScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        onSetFilter = viewModel::setFilter,
        onApprove = { id -> viewModel.approve(id, null, null) },
        onReject = { id, notes -> viewModel.reject(id, notes) },
        onMessageShown = viewModel::clearMessage,
    )
}

@Composable
fun RefundAdminScreen(
    state: RefundAdminUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onSetFilter: (String) -> Unit,
    onApprove: (String) -> Unit,
    onReject: (String, String) -> Unit,
    onMessageShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbar = remember { SnackbarHostState() }
    var rejectTarget by remember { mutableStateOf<String?>(null) }
    val content = state as? RefundAdminUiState.Content

    LaunchedEffect(content?.message, content?.transientError) {
        val msg = content?.message ?: content?.transientError?.let { adminOpsErrorMessage(it) }
        if (msg != null) {
            snackbar.showSnackbar(msg)
            onMessageShown()
        }
    }

    val activeFilter = when (state) {
        is RefundAdminUiState.Content -> state.statusFilter
        is RefundAdminUiState.Empty -> state.statusFilter
        else -> REFUND_STATUS_FILTERS.first()
    }

    Scaffold(
        modifier = modifier.testTag(RefundAdminTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("Refund requests") },
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
                    is RefundAdminUiState.Loading -> LoadingState()
                    is RefundAdminUiState.Empty -> EmptyState(
                        modifier = Modifier.testTag(RefundAdminTestTags.EMPTY),
                        title = "No refund requests",
                        body = "There are no ${state.statusFilter} refund requests.",
                        imageVector = Icons.Outlined.ReceiptLong,
                    )
                    is RefundAdminUiState.Forbidden -> EmptyState(
                        modifier = Modifier.testTag(RefundAdminTestTags.FORBIDDEN),
                        title = "Not authorised",
                        body = "You need billing-admin access to review refund requests.",
                        imageVector = Icons.Outlined.Lock,
                        actionLabel = "Back",
                        onAction = onBack,
                    )
                    is RefundAdminUiState.Error -> ErrorState(
                        modifier = Modifier.testTag(RefundAdminTestTags.ERROR_RETRY),
                        message = adminOpsErrorMessage(state.type),
                        onRetry = onRetry,
                    )
                    is RefundAdminUiState.Content -> LazyColumn(
                        modifier = Modifier.fillMaxSize().testTag(RefundAdminTestTags.LIST),
                        contentPadding = PaddingValues(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        items(items = state.requests, key = { it.refundRequestId }) { r ->
                            RefundRow(
                                request = r,
                                inFlight = state.actionInFlightId == r.refundRequestId,
                                actionsEnabled = state.actionInFlightId == null,
                                onApprove = { onApprove(r.refundRequestId) },
                                onReject = { rejectTarget = r.refundRequestId },
                            )
                        }
                    }
                }
            }
        }
    }

    rejectTarget?.let { targetId ->
        RejectDialog(
            onDismiss = { rejectTarget = null },
            onConfirm = { notes ->
                onReject(targetId, notes)
                rejectTarget = null
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
        REFUND_STATUS_FILTERS.forEach { s ->
            FilterChip(
                selected = active == s,
                onClick = { onSelect(s) },
                label = { Text(s.replaceFirstChar { it.uppercase() }) },
                modifier = Modifier.testTag(RefundAdminTestTags.filter(s)),
            )
        }
    }
}

@Composable
private fun RefundRow(
    request: RefundRequestDto,
    inFlight: Boolean,
    actionsEnabled: Boolean,
    onApprove: () -> Unit,
    onReject: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(RefundAdminTestTags.row(request.refundRequestId))) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(formatCents(request.amountCents, request.currency), style = MaterialTheme.typography.titleMedium)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(request.status.ifBlank { "-" }.replace('_', ' '), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                request.transactionType?.takeIf { it.isNotBlank() }?.let {
                    Text(it.replace('_', ' '), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            request.requesterUserId?.takeIf { it.isNotBlank() }?.let {
                Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            if (request.reason.isNotBlank()) {
                Text(request.reason, style = MaterialTheme.typography.bodySmall, maxLines = 3, overflow = TextOverflow.Ellipsis)
            }
            request.adminNotes?.takeIf { it.isNotBlank() }?.let {
                Text("Notes: $it", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.tertiary)
            }
            if (inFlight) {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) { CircularProgressIndicator() }
            } else if (request.status.equals("pending", ignoreCase = true)) {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = onApprove,
                        enabled = actionsEnabled,
                        modifier = Modifier.weight(1f).testTag(RefundAdminTestTags.approve(request.refundRequestId)),
                    ) { Text("Approve") }
                    OutlinedButton(
                        onClick = onReject,
                        enabled = actionsEnabled,
                        modifier = Modifier.weight(1f).testTag(RefundAdminTestTags.reject(request.refundRequestId)),
                    ) { Text("Reject") }
                }
            }
        }
    }
}

@Composable
private fun RejectDialog(onDismiss: () -> Unit, onConfirm: (String) -> Unit) {
    var notes by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Reject refund") },
        text = {
            OutlinedTextField(
                value = notes,
                onValueChange = { notes = it },
                label = { Text("Reason (required)") },
                modifier = Modifier.fillMaxWidth(),
            )
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(notes) },
                enabled = notes.isNotBlank(),
                modifier = Modifier.testTag(RefundAdminTestTags.REJECT_CONFIRM),
            ) { Text("Reject") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

internal fun formatCents(cents: Long, currency: String): String {
    val amount = cents / 100.0
    return "%s%,.2f".format(currencySymbol(currency), amount)
}

private fun currencySymbol(currency: String): String = when (currency.uppercase()) {
    "USD" -> "$"
    "EUR" -> "€"
    "GBP" -> "£"
    else -> "$currency "
}

internal fun adminOpsErrorMessage(type: AdminOpsErrorType): String = when (type) {
    AdminOpsErrorType.AUTH -> "Your session expired. Please sign in again."
    AdminOpsErrorType.SERVER -> "Something went wrong on the server. Try again."
    AdminOpsErrorType.NETWORK -> "You appear to be offline. Check your connection."
}
