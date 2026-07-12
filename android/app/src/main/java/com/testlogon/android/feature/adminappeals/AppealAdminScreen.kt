@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.adminappeals

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
import androidx.compose.material.icons.outlined.Balance
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
import com.testlogon.android.data.adminappeals.AppealDto
import com.testlogon.android.feature.adminmod.AdminOpsErrorType

object AppealAdminTestTags {
    const val SCREEN = "appeal_admin_screen"
    const val LIST = "appeal_admin_list"
    const val EMPTY = "appeal_admin_empty"
    const val FORBIDDEN = "appeal_admin_forbidden"
    const val ERROR_RETRY = "appeal_admin_error_retry"
    fun filter(s: String) = "appeal_filter_$s"
    fun row(id: String) = "appeal_row_$id"
    fun claim(id: String) = "appeal_claim_$id"
    fun decide(id: String) = "appeal_decide_$id"
    const val DECIDE_CONFIRM = "appeal_decide_confirm"
    fun decisionOption(d: String) = "appeal_decision_$d"
}

private const val FILTER_ALL = "all"

@Composable
fun AppealAdminRoute(
    onBack: () -> Unit,
    viewModel: AppealAdminViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    AppealAdminScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        onSetFilter = viewModel::setFilter,
        onClaim = viewModel::claim,
        onDecide = viewModel::decide,
        onMessageShown = viewModel::clearMessage,
    )
}

@Composable
fun AppealAdminScreen(
    state: AppealAdminUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onSetFilter: (String?) -> Unit,
    onClaim: (String) -> Unit,
    onDecide: (String, String, String?) -> Unit,
    onMessageShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbar = remember { SnackbarHostState() }
    var decideTarget by remember { mutableStateOf<String?>(null) }
    val content = state as? AppealAdminUiState.Content

    LaunchedEffect(content?.message, content?.transientError) {
        val msg = content?.message ?: content?.transientError?.let { appealErrorMessage(it) }
        if (msg != null) {
            snackbar.showSnackbar(msg)
            onMessageShown()
        }
    }

    val activeFilter = when (state) {
        is AppealAdminUiState.Content -> state.statusFilter
        is AppealAdminUiState.Empty -> state.statusFilter
        else -> null
    }

    Scaffold(
        modifier = modifier.testTag(AppealAdminTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("Appeals") },
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
                    is AppealAdminUiState.Loading -> LoadingState()
                    is AppealAdminUiState.Empty -> EmptyState(
                        modifier = Modifier.testTag(AppealAdminTestTags.EMPTY),
                        title = "No appeals",
                        body = "There are no appeals to review.",
                        imageVector = Icons.Outlined.Balance,
                    )
                    is AppealAdminUiState.Forbidden -> EmptyState(
                        modifier = Modifier.testTag(AppealAdminTestTags.FORBIDDEN),
                        title = "Not authorised",
                        body = "You need content-moderation admin access to review appeals.",
                        imageVector = Icons.Outlined.Lock,
                        actionLabel = "Back",
                        onAction = onBack,
                    )
                    is AppealAdminUiState.Error -> ErrorState(
                        modifier = Modifier.testTag(AppealAdminTestTags.ERROR_RETRY),
                        message = appealErrorMessage(state.type),
                        onRetry = onRetry,
                    )
                    is AppealAdminUiState.Content -> LazyColumn(
                        modifier = Modifier.fillMaxSize().testTag(AppealAdminTestTags.LIST),
                        contentPadding = PaddingValues(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        items(items = state.appeals, key = { it.appealId }) { a ->
                            AppealRow(
                                appeal = a,
                                inFlight = state.actionInFlightId == a.appealId,
                                actionsEnabled = state.actionInFlightId == null,
                                onClaim = { onClaim(a.appealId) },
                                onDecide = { decideTarget = a.appealId },
                            )
                        }
                    }
                }
            }
        }
    }

    decideTarget?.let { targetId ->
        DecideDialog(
            onDismiss = { decideTarget = null },
            onConfirm = { decision, note ->
                onDecide(targetId, decision, note)
                decideTarget = null
            },
        )
    }
}

@Composable
private fun FilterRow(active: String?, onSelect: (String?) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        APPEAL_STATUS_FILTERS.forEach { s ->
            val label = s?.replace('_', ' ')?.replaceFirstChar { it.uppercase() } ?: "All"
            FilterChip(
                selected = active == s,
                onClick = { onSelect(s) },
                label = { Text(label) },
                modifier = Modifier.testTag(AppealAdminTestTags.filter(s ?: FILTER_ALL)),
            )
        }
    }
}

@Composable
private fun AppealRow(
    appeal: AppealDto,
    inFlight: Boolean,
    actionsEnabled: Boolean,
    onClaim: () -> Unit,
    onDecide: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(AppealAdminTestTags.row(appeal.appealId))) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(appeal.enforcementType.ifBlank { "Appeal" }.replace('_', ' '), style = MaterialTheme.typography.titleSmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(appeal.status.ifBlank { "-" }.replace('_', ' '), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                if (appeal.userId.isNotBlank()) {
                    Text(appeal.userId, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
            }
            if (appeal.appealText.isNotBlank()) {
                Text(appeal.appealText, style = MaterialTheme.typography.bodySmall, maxLines = 4, overflow = TextOverflow.Ellipsis)
            }
            appeal.decisionNote?.takeIf { it.isNotBlank() }?.let {
                Text("Decision note: $it", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.tertiary)
            }
            if (inFlight) {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) { CircularProgressIndicator() }
            } else if (appeal.decidedAt == null || appeal.decidedAt == 0L) {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(
                        onClick = onClaim,
                        enabled = actionsEnabled,
                        modifier = Modifier.weight(1f).testTag(AppealAdminTestTags.claim(appeal.appealId)),
                    ) { Text("Claim") }
                    Button(
                        onClick = onDecide,
                        enabled = actionsEnabled,
                        modifier = Modifier.weight(1f).testTag(AppealAdminTestTags.decide(appeal.appealId)),
                    ) { Text("Decide") }
                }
            }
        }
    }
}

@Composable
private fun DecideDialog(onDismiss: () -> Unit, onConfirm: (String, String?) -> Unit) {
    var selected by remember { mutableStateOf(APPEAL_DECISIONS.first()) }
    var note by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Decide appeal") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                APPEAL_DECISIONS.forEach { d ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .selectable(selected = selected == d, onClick = { selected = d })
                            .testTag(AppealAdminTestTags.decisionOption(d)),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(selected = selected == d, onClick = { selected = d })
                        Text(d.replaceFirstChar { it.uppercase() })
                    }
                }
                OutlinedTextField(
                    value = note,
                    onValueChange = { note = it },
                    label = { Text("Decision note (optional)") },
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(selected, note.ifBlank { null }) },
                modifier = Modifier.testTag(AppealAdminTestTags.DECIDE_CONFIRM),
            ) { Text("Confirm") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

internal fun appealErrorMessage(type: AdminOpsErrorType): String = when (type) {
    AdminOpsErrorType.AUTH -> "Your session expired. Please sign in again."
    AdminOpsErrorType.SERVER -> "Something went wrong on the server. Try again."
    AdminOpsErrorType.NETWORK -> "You appear to be offline. Check your connection."
}
