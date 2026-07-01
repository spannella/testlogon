@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.adminfraud

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.selection.selectable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
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
import com.testlogon.android.data.adminfraud.FraudCaseDto
import com.testlogon.android.data.adminfraud.FraudFlagDto
import com.testlogon.android.feature.adminmod.AdminOpsErrorType

object FraudAdminTestTags {
    const val SCREEN = "fraud_admin_screen"
    const val LIST = "fraud_admin_list"
    const val EMPTY = "fraud_admin_empty"
    const val FORBIDDEN = "fraud_admin_forbidden"
    const val ERROR_RETRY = "fraud_admin_error_retry"
    const val TAB_FLAGS = "fraud_tab_flags"
    const val TAB_CASES = "fraud_tab_cases"
    fun flagRow(id: String) = "fraud_flag_$id"
    fun caseRow(id: String) = "fraud_case_$id"
    fun review(id: String) = "fraud_review_$id"
    fun resolve(id: String) = "fraud_resolve_$id"
    const val REVIEW_CONFIRM = "fraud_review_confirm"
    const val RESOLVE_CONFIRM = "fraud_resolve_confirm"
    fun option(v: String) = "fraud_option_$v"
}

@Composable
fun FraudAdminRoute(
    onBack: () -> Unit,
    viewModel: FraudAdminViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    FraudAdminScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        onSelectTab = viewModel::selectTab,
        onReview = viewModel::reviewFlag,
        onResolveCase = viewModel::resolveCase,
        onMessageShown = viewModel::clearMessage,
    )
}

@Composable
fun FraudAdminScreen(
    state: FraudAdminUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onSelectTab: (FraudTab) -> Unit,
    onReview: (String, String, String) -> Unit,
    onResolveCase: (String, String, String) -> Unit,
    onMessageShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbar = remember { SnackbarHostState() }
    var reviewTarget by remember { mutableStateOf<String?>(null) }
    var resolveTarget by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(state.message, state.transientError) {
        val msg = state.message ?: state.transientError?.let { fraudErrorMessage(it) }
        if (msg != null) {
            snackbar.showSnackbar(msg)
            onMessageShown()
        }
    }

    Scaffold(
        modifier = modifier.testTag(FraudAdminTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("Fraud review") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            TabRow(selectedTabIndex = if (state.tab == FraudTab.FLAGS) 0 else 1) {
                Tab(
                    selected = state.tab == FraudTab.FLAGS,
                    onClick = { onSelectTab(FraudTab.FLAGS) },
                    text = { Text("Flags") },
                    modifier = Modifier.testTag(FraudAdminTestTags.TAB_FLAGS),
                )
                Tab(
                    selected = state.tab == FraudTab.CASES,
                    onClick = { onSelectTab(FraudTab.CASES) },
                    text = { Text("Cases") },
                    modifier = Modifier.testTag(FraudAdminTestTags.TAB_CASES),
                )
            }
            val isRefreshing = when (val d = state.data) {
                is FraudDataState.Flags -> d.isRefreshing
                is FraudDataState.Cases -> d.isRefreshing
                else -> false
            }
            PullToRefreshBox(
                isRefreshing = isRefreshing,
                onRefresh = onRefresh,
                modifier = Modifier.fillMaxSize(),
            ) {
                when (val d = state.data) {
                    is FraudDataState.Loading -> LoadingState()
                    is FraudDataState.Empty -> EmptyState(
                        modifier = Modifier.testTag(FraudAdminTestTags.EMPTY),
                        title = "Nothing to review",
                        body = "There are no ${if (state.tab == FraudTab.FLAGS) "flags" else "cases"} here.",
                        imageVector = Icons.Outlined.Shield,
                    )
                    is FraudDataState.Forbidden -> EmptyState(
                        modifier = Modifier.testTag(FraudAdminTestTags.FORBIDDEN),
                        title = "Not authorised",
                        body = "You need admin access to review fraud.",
                        imageVector = Icons.Outlined.Lock,
                        actionLabel = "Back",
                        onAction = onBack,
                    )
                    is FraudDataState.Error -> ErrorState(
                        modifier = Modifier.testTag(FraudAdminTestTags.ERROR_RETRY),
                        message = fraudErrorMessage(d.type),
                        onRetry = onRetry,
                    )
                    is FraudDataState.Flags -> LazyColumn(
                        modifier = Modifier.fillMaxSize().testTag(FraudAdminTestTags.LIST),
                        contentPadding = PaddingValues(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        items(items = d.flags, key = { it.flagId }) { f ->
                            FlagRow(
                                flag = f,
                                inFlight = state.actionInFlightId == f.flagId,
                                actionsEnabled = state.actionInFlightId == null,
                                onReview = { reviewTarget = f.flagId },
                            )
                        }
                    }
                    is FraudDataState.Cases -> LazyColumn(
                        modifier = Modifier.fillMaxSize().testTag(FraudAdminTestTags.LIST),
                        contentPadding = PaddingValues(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        items(items = d.cases, key = { it.caseId }) { c ->
                            CaseRow(
                                fraudCase = c,
                                inFlight = state.actionInFlightId == c.caseId,
                                actionsEnabled = state.actionInFlightId == null,
                                onResolve = { resolveTarget = c.caseId },
                            )
                        }
                    }
                }
            }
        }
    }

    reviewTarget?.let { targetId ->
        OptionDialog(
            title = "Review flag",
            options = FRAUD_FLAG_ACTIONS,
            confirmTag = FraudAdminTestTags.REVIEW_CONFIRM,
            onDismiss = { reviewTarget = null },
            onConfirm = { action, notes ->
                onReview(targetId, action, notes)
                reviewTarget = null
            },
        )
    }
    resolveTarget?.let { targetId ->
        OptionDialog(
            title = "Resolve case",
            options = FRAUD_CASE_RESOLUTIONS,
            confirmTag = FraudAdminTestTags.RESOLVE_CONFIRM,
            onDismiss = { resolveTarget = null },
            onConfirm = { resolution, notes ->
                onResolveCase(targetId, resolution, notes)
                resolveTarget = null
            },
        )
    }
}

@Composable
private fun FlagRow(
    flag: FraudFlagDto,
    inFlight: Boolean,
    actionsEnabled: Boolean,
    onReview: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(FraudAdminTestTags.flagRow(flag.flagId))) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(flag.ruleTriggered.ifBlank { "Flag" }.replace('_', ' '), style = MaterialTheme.typography.titleSmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(flag.status.ifBlank { "-" }.replace('_', ' '), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                Text("Risk ${flag.riskScore}", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.error)
                Text(centsUsd(flag.amountCents), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            if (flag.userId.isNotBlank()) {
                Text(flag.userId, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            flag.resolution?.takeIf { it.isNotBlank() }?.let {
                Text("Resolution: $it", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.tertiary)
            }
            if (inFlight) {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) { CircularProgressIndicator() }
            } else if (flag.status.equals("pending", ignoreCase = true)) {
                Button(
                    onClick = onReview,
                    enabled = actionsEnabled,
                    modifier = Modifier.fillMaxWidth().testTag(FraudAdminTestTags.review(flag.flagId)),
                ) { Text("Review") }
            }
        }
    }
}

@Composable
private fun CaseRow(
    fraudCase: FraudCaseDto,
    inFlight: Boolean,
    actionsEnabled: Boolean,
    onResolve: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(FraudAdminTestTags.caseRow(fraudCase.caseId))) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(fraudCase.userId.ifBlank { "Case" }, style = MaterialTheme.typography.titleSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(fraudCase.status.ifBlank { "-" }.replace('_', ' '), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                Text("${fraudCase.flags.size} flags", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            fraudCase.resolution?.takeIf { it.isNotBlank() }?.let {
                Text("Resolution: $it", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.tertiary)
            }
            if (inFlight) {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) { CircularProgressIndicator() }
            } else if (fraudCase.resolvedAt == null || fraudCase.resolvedAt == 0L) {
                Button(
                    onClick = onResolve,
                    enabled = actionsEnabled,
                    modifier = Modifier.fillMaxWidth().testTag(FraudAdminTestTags.resolve(fraudCase.caseId)),
                ) { Text("Resolve") }
            }
        }
    }
}

@Composable
private fun OptionDialog(
    title: String,
    options: List<String>,
    confirmTag: String,
    onDismiss: () -> Unit,
    onConfirm: (String, String) -> Unit,
) {
    var selected by remember { mutableStateOf(options.first()) }
    var notes by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                options.forEach { o ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .selectable(selected = selected == o, onClick = { selected = o })
                            .testTag(FraudAdminTestTags.option(o)),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(selected = selected == o, onClick = { selected = o })
                        Text(o.replace('_', ' ').replaceFirstChar { it.uppercase() })
                    }
                }
                androidx.compose.material3.OutlinedTextField(
                    value = notes,
                    onValueChange = { notes = it },
                    label = { Text("Notes (optional)") },
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(selected, notes) },
                modifier = Modifier.testTag(confirmTag),
            ) { Text("Confirm") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

private fun centsUsd(cents: Long): String = "$%,.2f".format(cents / 100.0)

internal fun fraudErrorMessage(type: AdminOpsErrorType): String = when (type) {
    AdminOpsErrorType.AUTH -> "Your session expired. Please sign in again."
    AdminOpsErrorType.SERVER -> "Something went wrong on the server. Try again."
    AdminOpsErrorType.NETWORK -> "You appear to be offline. Check your connection."
}
