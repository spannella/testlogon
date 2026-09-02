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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.ManageSearch
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
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
import com.testlogon.android.data.adminfraud.FraudMath
import com.testlogon.android.data.adminfraud.UserRiskProfileDto
import com.testlogon.android.feature.adminmod.AdminOpsErrorType

object FraudAdminTestTags {
    const val SCREEN = "fraud_admin_screen"
    const val LIST = "fraud_admin_list"
    const val EMPTY = "fraud_admin_empty"
    const val FORBIDDEN = "fraud_admin_forbidden"
    const val ERROR_RETRY = "fraud_admin_error_retry"
    const val TAB_FLAGS = "fraud_tab_flags"
    const val TAB_CASES = "fraud_tab_cases"
    const val TAB_USER = "fraud_tab_user"
    fun flagRow(id: String) = "fraud_flag_$id"
    fun caseRow(id: String) = "fraud_case_$id"
    fun review(id: String) = "fraud_review_$id"
    fun resolve(id: String) = "fraud_resolve_$id"
    const val REVIEW_CONFIRM = "fraud_review_confirm"
    const val RESOLVE_CONFIRM = "fraud_resolve_confirm"
    fun option(v: String) = "fraud_option_$v"
    const val USER_QUERY = "fraud_user_query"
    const val USER_LOOKUP = "fraud_user_lookup"
    const val USER_PROFILE = "fraud_user_profile"
    const val USER_FREEZE = "fraud_user_freeze"
    const val USER_UNFREEZE = "fraud_user_unfreeze"
    const val FREEZE_CONFIRM = "fraud_freeze_confirm"
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
        onUserQueryChange = viewModel::updateUserQuery,
        onUserLookup = viewModel::lookupUser,
        onFreeze = viewModel::freezeUser,
        onUnfreeze = viewModel::unfreezeUser,
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
    onUserQueryChange: (String) -> Unit,
    onUserLookup: () -> Unit,
    onFreeze: (String) -> Unit,
    onUnfreeze: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbar = remember { SnackbarHostState() }
    var reviewTarget by remember { mutableStateOf<String?>(null) }
    var resolveTarget by remember { mutableStateOf<String?>(null) }
    var freezeDialog by remember { mutableStateOf(false) }

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
            TabRow(selectedTabIndex = state.tab.ordinal) {
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
                Tab(
                    selected = state.tab == FraudTab.USER,
                    onClick = { onSelectTab(FraudTab.USER) },
                    text = { Text("User") },
                    modifier = Modifier.testTag(FraudAdminTestTags.TAB_USER),
                )
            }

            if (state.tab == FraudTab.USER) {
                UserRiskTab(
                    state = state,
                    onUserQueryChange = onUserQueryChange,
                    onUserLookup = onUserLookup,
                    onFreezeClick = { freezeDialog = true },
                    onUnfreeze = onUnfreeze,
                )
            } else {
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
    if (freezeDialog) {
        FreezeDialog(
            onDismiss = { freezeDialog = false },
            onConfirm = { reason ->
                onFreeze(reason)
                freezeDialog = false
            },
        )
    }
}

@Composable
private fun UserRiskTab(
    state: FraudAdminUiState,
    onUserQueryChange: (String) -> Unit,
    onUserLookup: () -> Unit,
    onFreezeClick: () -> Unit,
    onUnfreeze: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        OutlinedTextField(
            value = state.userQuery,
            onValueChange = onUserQueryChange,
            label = { Text("User ID") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth().testTag(FraudAdminTestTags.USER_QUERY),
        )
        Button(
            onClick = onUserLookup,
            enabled = state.userQuery.isNotBlank() && state.userRisk !is UserRiskState.Loading,
            modifier = Modifier.fillMaxWidth().testTag(FraudAdminTestTags.USER_LOOKUP),
        ) { Text("Look up risk") }

        when (val u = state.userRisk) {
            is UserRiskState.Idle -> EmptyState(
                title = "Look up a user",
                body = "Enter a user ID to see their risk profile and freeze status.",
                imageVector = Icons.Outlined.ManageSearch,
            )
            is UserRiskState.Loading -> Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Center,
            ) { CircularProgressIndicator() }
            is UserRiskState.NotFound -> EmptyState(
                title = "No profile",
                body = "No risk profile found for that user.",
                imageVector = Icons.Outlined.ManageSearch,
            )
            is UserRiskState.Forbidden -> EmptyState(
                modifier = Modifier.testTag(FraudAdminTestTags.FORBIDDEN),
                title = "Not authorised",
                body = "You need admin access to view risk.",
                imageVector = Icons.Outlined.Lock,
            )
            is UserRiskState.Error -> Text(
                fraudErrorMessage(u.type),
                color = MaterialTheme.colorScheme.error,
            )
            is UserRiskState.Loaded -> UserRiskCard(
                profile = u.profile,
                freezeInFlight = state.freezeInFlight,
                onFreezeClick = onFreezeClick,
                onUnfreeze = onUnfreeze,
            )
        }
    }
}

@Composable
private fun UserRiskCard(
    profile: UserRiskProfileDto,
    freezeInFlight: Boolean,
    onFreezeClick: () -> Unit,
    onUnfreeze: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(FraudAdminTestTags.USER_PROFILE)) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(profile.userId.ifBlank { "User" }, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Risk ${profile.score}", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.error)
                Text(FraudMath.scoreLabel(profile.score), style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
            }
            if (profile.flagged) {
                Text("Flagged for review", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.tertiary)
            }
            Text(
                if (profile.frozen) "Financial operations FROZEN" else "Not frozen",
                style = MaterialTheme.typography.bodyMedium,
                color = if (profile.frozen) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text("24h: ${profile.txCount24h} tx, ${centsUsd(profile.txTotal24h)}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text("Chargebacks: ${profile.chargebackCount}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)

            if (freezeInFlight) {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) { CircularProgressIndicator() }
            } else if (FraudMath.canUnfreeze(profile.frozen)) {
                OutlinedButton(
                    onClick = onUnfreeze,
                    modifier = Modifier.fillMaxWidth().testTag(FraudAdminTestTags.USER_UNFREEZE),
                ) { Text("Unfreeze user") }
            } else if (FraudMath.canFreeze(profile.frozen)) {
                Button(
                    onClick = onFreezeClick,
                    modifier = Modifier.fillMaxWidth().testTag(FraudAdminTestTags.USER_FREEZE),
                ) { Text("Freeze user") }
            }
        }
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
            } else if (FraudMath.isFlagReviewable(flag.status)) {
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
            } else if (FraudMath.isCaseResolvable(fraudCase.status, fraudCase.resolvedAt)) {
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
                onClick = { onConfirm(selected, notes) },
                modifier = Modifier.testTag(confirmTag),
            ) { Text("Confirm") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun FreezeDialog(
    onDismiss: () -> Unit,
    onConfirm: (String) -> Unit,
) {
    var reason by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Freeze user") },
        text = {
            OutlinedTextField(
                value = reason,
                onValueChange = { reason = it },
                label = { Text("Reason") },
                modifier = Modifier.fillMaxWidth(),
            )
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(reason) },
                enabled = reason.isNotBlank(),
                modifier = Modifier.testTag(FraudAdminTestTags.FREEZE_CONFIRM),
            ) { Text("Freeze") }
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
