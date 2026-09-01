@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.syndicates.management

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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.HorizontalDivider
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
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.model.syndicates.PlanField
import com.testlogon.android.core.model.syndicates.SyndicateMath
import com.testlogon.android.core.ui.input.TlButton
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** Stable testTags for the syndicate management screen. */
object SyndicateManagementTestTags {
    const val SCREEN = "syndicate_mgmt_screen"
    const val INVITE_FAB = "syndicate_mgmt_invite"
    const val PLAN_FAB = "syndicate_mgmt_add_plan"
    const val TRANSFER = "syndicate_mgmt_transfer"
    fun planRow(id: String) = "syndicate_mgmt_plan_$id"
    fun requestRow(id: String) = "syndicate_mgmt_request_$id"
    fun inviteRow(id: String) = "syndicate_mgmt_invite_$id"
}

@Composable
fun SyndicateManagementRoute(
    onBack: () -> Unit,
    viewModel: SyndicateManagementViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    SyndicateManagementScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::retry,
        onRefresh = viewModel::refresh,
        onOpenInvite = viewModel::openInviteForm,
        onDismissInvite = viewModel::dismissInviteForm,
        onInviteUserIdChange = viewModel::onInviteUserIdChange,
        onSubmitInvite = viewModel::submitInvite,
        onRespondInvite = viewModel::respondToInvite,
        onApprove = viewModel::approveRequest,
        onReject = viewModel::rejectRequest,
        onOpenTransfer = viewModel::openTransferForm,
        onDismissTransfer = viewModel::dismissTransferForm,
        onTransferUserIdChange = viewModel::onTransferUserIdChange,
        onSubmitTransfer = viewModel::submitTransfer,
        onOpenPlan = viewModel::openPlanForm,
        onDismissPlan = viewModel::dismissPlanForm,
        onPlanNameChange = viewModel::onPlanNameChange,
        onPlanDescriptionChange = viewModel::onPlanDescriptionChange,
        onPlanPriceChange = viewModel::onPlanPriceChange,
        onPlanIntervalChange = viewModel::onPlanIntervalChange,
        onSubmitPlan = viewModel::submitPlan,
        onSubscribe = viewModel::subscribe,
        onArchivePlan = viewModel::archivePlan,
        onActionMessageShown = viewModel::consumeActionMessage,
        onActionErrorShown = viewModel::clearActionError,
    )
}

@Composable
fun SyndicateManagementScreen(
    state: SyndicateManagementUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onRefresh: () -> Unit,
    onOpenInvite: () -> Unit,
    onDismissInvite: () -> Unit,
    onInviteUserIdChange: (String) -> Unit,
    onSubmitInvite: () -> Unit,
    onRespondInvite: (String, Boolean) -> Unit,
    onApprove: (String) -> Unit,
    onReject: (String) -> Unit,
    onOpenTransfer: () -> Unit,
    onDismissTransfer: () -> Unit,
    onTransferUserIdChange: (String) -> Unit,
    onSubmitTransfer: () -> Unit,
    onOpenPlan: () -> Unit,
    onDismissPlan: () -> Unit,
    onPlanNameChange: (String) -> Unit,
    onPlanDescriptionChange: (String) -> Unit,
    onPlanPriceChange: (String) -> Unit,
    onPlanIntervalChange: (String) -> Unit,
    onSubmitPlan: () -> Unit,
    onSubscribe: (String) -> Unit,
    onArchivePlan: (String) -> Unit,
    onActionMessageShown: () -> Unit,
    onActionErrorShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbarHostState = remember { SnackbarHostState() }
    val content = state as? SyndicateManagementUiState.Content

    LaunchedEffect(content?.actionMessage) {
        val msg = content?.actionMessage
        if (msg != null) {
            snackbarHostState.showSnackbar(msg)
            onActionMessageShown()
        }
    }
    LaunchedEffect(content?.actionError) {
        val err = content?.actionError
        if (err != null) {
            snackbarHostState.showSnackbar(err)
            onActionErrorShown()
        }
    }

    Scaffold(
        modifier = modifier.testTag(SyndicateManagementTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Manage syndicate") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        when (state) {
            is SyndicateManagementUiState.Loading -> LoadingState(modifier = Modifier.padding(padding))
            is SyndicateManagementUiState.Error ->
                ErrorState(message = state.message, onRetry = onRetry, modifier = Modifier.padding(padding))
            is SyndicateManagementUiState.Content ->
                ManagementBody(
                    state = state,
                    modifier = Modifier.padding(padding),
                    onRefresh = onRefresh,
                    onOpenInvite = onOpenInvite,
                    onRespondInvite = onRespondInvite,
                    onApprove = onApprove,
                    onReject = onReject,
                    onOpenTransfer = onOpenTransfer,
                    onOpenPlan = onOpenPlan,
                    onSubscribe = onSubscribe,
                    onArchivePlan = onArchivePlan,
                )
        }
    }

    if (content?.inviteForm?.visible == true) {
        InviteDialog(content.inviteForm, onDismissInvite, onInviteUserIdChange, onSubmitInvite)
    }
    if (content?.transferForm?.visible == true) {
        TransferDialog(content.transferForm, onDismissTransfer, onTransferUserIdChange, onSubmitTransfer)
    }
    if (content?.planForm?.visible == true) {
        PlanDialog(
            content.planForm,
            onDismissPlan,
            onPlanNameChange,
            onPlanDescriptionChange,
            onPlanPriceChange,
            onPlanIntervalChange,
            onSubmitPlan,
        )
    }
}

@Composable
private fun ManagementBody(
    state: SyndicateManagementUiState.Content,
    modifier: Modifier,
    onRefresh: () -> Unit,
    onOpenInvite: () -> Unit,
    onRespondInvite: (String, Boolean) -> Unit,
    onApprove: (String) -> Unit,
    onReject: (String) -> Unit,
    onOpenTransfer: () -> Unit,
    onOpenPlan: () -> Unit,
    onSubscribe: (String) -> Unit,
    onArchivePlan: (String) -> Unit,
) {
    PullToRefreshBox(
        isRefreshing = state.isRefreshing,
        onRefresh = onRefresh,
        modifier = modifier.fillMaxSize(),
    ) {
        LazyColumn(modifier = Modifier.fillMaxSize()) {
            item { SectionHeader("My invites") }
            if (state.invites.isEmpty()) {
                item { EmptyLine("No pending invites") }
            } else {
                items(state.invites, key = { "inv_${it.syndicateId}" }) { invite ->
                    InviteRow(invite, busy = state.busyId == invite.syndicateId, onRespondInvite)
                }
            }

            item { HorizontalDivider() }
            item {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    SectionHeader("Join requests")
                    TextButton(onClick = onOpenInvite, modifier = Modifier.testTag(SyndicateManagementTestTags.INVITE_FAB)) {
                        Text("Invite")
                    }
                }
            }
            if (state.requests.isEmpty()) {
                item { EmptyLine("No pending requests") }
            } else {
                items(state.requests, key = { "req_${it.userId}" }) { req ->
                    RequestRow(req, busy = state.busyId == req.userId, onApprove, onReject)
                }
            }

            item { HorizontalDivider() }
            item {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    SectionHeader("Bundle plans")
                    TextButton(onClick = onOpenPlan, modifier = Modifier.testTag(SyndicateManagementTestTags.PLAN_FAB)) {
                        Text("New plan")
                    }
                }
            }
            if (state.plans.isEmpty()) {
                item { EmptyLine("No bundle plans yet") }
            } else {
                items(state.plans, key = { "plan_${it.planId}" }) { plan ->
                    PlanRow(
                        plan = plan,
                        busy = state.busyId == plan.planId,
                        subscribed = plan.planId in state.subscribedPlanIds,
                        onSubscribe = onSubscribe,
                        onArchive = onArchivePlan,
                    )
                }
            }

            item { HorizontalDivider() }
            item { SectionHeader("Admin") }
            item {
                OutlinedButton(
                    onClick = onOpenTransfer,
                    modifier = Modifier
                        .padding(horizontal = 16.dp, vertical = 4.dp)
                        .testTag(SyndicateManagementTestTags.TRANSFER),
                ) { Text("Transfer admin") }
            }

            item { HorizontalDivider() }
            item { SectionHeader("Activity") }
            if (state.audit.isEmpty()) {
                item { EmptyLine("No recent activity") }
            } else {
                items(state.audit, key = { "audit_${it.eventId}" }) { entry -> AuditRow(entry) }
            }
        }
    }
}

@Composable
private fun SectionHeader(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.titleMedium,
        modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
    )
}

@Composable
private fun EmptyLine(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
    )
}

@Composable
private fun InviteRow(invite: SyndicateInvite, busy: Boolean, onRespond: (String, Boolean) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(SyndicateManagementTestTags.inviteRow(invite.syndicateId))
            .padding(horizontal = 16.dp, vertical = 12.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Column(modifier = Modifier.padding(end = 12.dp)) {
            Text(invite.syndicateName, style = MaterialTheme.typography.titleSmall)
            Text(
                "Invited by ${invite.invitedBy}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = { onRespond(invite.syndicateId, false) }, enabled = !busy) { Text("Decline") }
            TlButton(text = "Accept", onClick = { onRespond(invite.syndicateId, true) }, enabled = !busy, loading = busy)
        }
    }
}

@Composable
private fun RequestRow(req: JoinRequest, busy: Boolean, onApprove: (String) -> Unit, onReject: (String) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(SyndicateManagementTestTags.requestRow(req.userId))
            .padding(horizontal = 16.dp, vertical = 12.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Column(modifier = Modifier.padding(end = 12.dp)) {
            Text(req.displayName, style = MaterialTheme.typography.titleSmall)
            if (req.message.isNotBlank()) {
                Text(
                    req.message,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = { onReject(req.userId) }, enabled = !busy) { Text("Reject") }
            TlButton(text = "Approve", onClick = { onApprove(req.userId) }, enabled = !busy, loading = busy)
        }
    }
}

@Composable
private fun PlanRow(
    plan: BundlePlan,
    busy: Boolean,
    subscribed: Boolean,
    onSubscribe: (String) -> Unit,
    onArchive: (String) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(SyndicateManagementTestTags.planRow(plan.planId))
            .padding(horizontal = 16.dp, vertical = 12.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Column(modifier = Modifier.padding(end = 12.dp)) {
            Text(plan.name, style = MaterialTheme.typography.titleSmall)
            Text(
                SyndicateMath.priceLabel(plan.priceCents, plan.interval),
                style = MaterialTheme.typography.bodyMedium,
            )
            if (!plan.isActive) {
                Text(plan.status, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (plan.isActive) {
                OutlinedButton(onClick = { onArchive(plan.planId) }, enabled = !busy) { Text("Archive") }
            }
            if (subscribed) {
                AssistChip(onClick = {}, enabled = false, label = { Text("Subscribed") })
            } else {
                TlButton(
                    text = "Subscribe",
                    onClick = { onSubscribe(plan.planId) },
                    enabled = !busy && plan.isActive,
                    loading = busy,
                )
            }
        }
    }
}

@Composable
private fun AuditRow(entry: SyndicateAuditEntry) {
    Column(modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp)) {
        Text(SyndicateMath.auditActionLabel(entry.action), style = MaterialTheme.typography.bodyMedium)
        if (entry.actorId.isNotBlank()) {
            Text(
                "by ${entry.actorId}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

// ---- Dialogs ----

@Composable
private fun InviteDialog(
    form: InviteFormState,
    onDismiss: () -> Unit,
    onUserIdChange: (String) -> Unit,
    onSubmit: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Invite a member") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = form.userId,
                    onValueChange = onUserIdChange,
                    label = { Text("User ID") },
                    singleLine = true,
                    isError = form.error != null,
                    supportingText = form.error?.let { msg -> { Text(msg) } },
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            TlButton(text = "Send invite", onClick = onSubmit, enabled = form.isValid && !form.submitting, loading = form.submitting)
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun TransferDialog(
    form: TransferFormState,
    onDismiss: () -> Unit,
    onUserIdChange: (String) -> Unit,
    onSubmit: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Transfer admin") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("The new admin must be an existing member.", style = MaterialTheme.typography.bodySmall)
                OutlinedTextField(
                    value = form.newAdminUserId,
                    onValueChange = onUserIdChange,
                    label = { Text("New admin user ID") },
                    singleLine = true,
                    isError = form.error != null,
                    supportingText = form.error?.let { msg -> { Text(msg) } },
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            TlButton(text = "Transfer", onClick = onSubmit, enabled = form.isValid && !form.submitting, loading = form.submitting)
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun PlanDialog(
    form: PlanFormState,
    onDismiss: () -> Unit,
    onNameChange: (String) -> Unit,
    onDescriptionChange: (String) -> Unit,
    onPriceChange: (String) -> Unit,
    onIntervalChange: (String) -> Unit,
    onSubmit: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("New bundle plan") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = form.name,
                    onValueChange = onNameChange,
                    label = { Text("Name") },
                    singleLine = true,
                    isError = form.fieldErrors.containsKey(PlanField.NAME),
                    supportingText = form.fieldErrors[PlanField.NAME]?.let { msg -> { Text(msg) } },
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = form.description,
                    onValueChange = onDescriptionChange,
                    label = { Text("Description (optional)") },
                    isError = form.fieldErrors.containsKey(PlanField.DESCRIPTION),
                    supportingText = form.fieldErrors[PlanField.DESCRIPTION]?.let { msg -> { Text(msg) } },
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = form.priceInput,
                    onValueChange = onPriceChange,
                    label = { Text("Price (e.g. 9.99)") },
                    singleLine = true,
                    isError = form.fieldErrors.containsKey(PlanField.PRICE),
                    supportingText = form.fieldErrors[PlanField.PRICE]?.let { msg -> { Text(msg) } },
                    modifier = Modifier.fillMaxWidth(),
                )
                IntervalPicker(
                    selected = form.interval,
                    error = form.fieldErrors[PlanField.INTERVAL],
                    onSelect = onIntervalChange,
                )
                form.submitError?.let { msg ->
                    Text(msg, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
            }
        },
        confirmButton = {
            TlButton(text = "Create", onClick = onSubmit, enabled = !form.submitting, loading = form.submitting)
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun IntervalPicker(selected: String, error: String?, onSelect: (String) -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { expanded = it },
        modifier = Modifier.fillMaxWidth(),
    ) {
        OutlinedTextField(
            value = if (selected == "year") "Yearly" else "Monthly",
            onValueChange = {},
            readOnly = true,
            label = { Text("Billing interval") },
            isError = error != null,
            supportingText = error?.let { msg -> { Text(msg) } },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier.fillMaxWidth().menuAnchor(),
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            SyndicateMath.VALID_INTERVALS.forEach { option ->
                DropdownMenuItem(
                    text = { Text(if (option == "year") "Yearly" else "Monthly") },
                    onClick = {
                        expanded = false
                        onSelect(option)
                    },
                )
            }
        }
    }
}
