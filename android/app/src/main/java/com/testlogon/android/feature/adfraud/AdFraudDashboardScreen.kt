@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.adfraud

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.Button
import androidx.compose.material3.Card
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.adfraud.AdFraudAccountDto
import com.testlogon.android.data.adfraud.AdFraudDashboard
import com.testlogon.android.data.adfraud.AdFraudEventDto
import com.testlogon.android.feature.adminops.CardSection
import com.testlogon.android.feature.adminops.KpiGrid
import com.testlogon.android.feature.adminops.StatRow
import com.testlogon.android.feature.adminops.adminOpsErrorMessage
import com.testlogon.android.feature.adminops.bpsPct
import com.testlogon.android.feature.adminops.relativeSeconds

object AdFraudTestTags {
    const val SCREEN = "ad_fraud_screen"
    const val FORBIDDEN = "ad_fraud_forbidden"
    const val ERROR_RETRY = "ad_fraud_error_retry"
    fun event(id: String) = "ad_fraud_event_$id"
    fun account(id: String) = "ad_fraud_account_$id"
}

@Composable
fun AdFraudDashboardRoute(
    onBack: () -> Unit,
    viewModel: AdFraudDashboardViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    AdFraudDashboardScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        onConfirmEvent = viewModel::confirmEvent,
        onDismissEvent = viewModel::dismissEvent,
        onSuspend = viewModel::suspendAccount,
        onUnsuspend = viewModel::unsuspendAccount,
        onMessageShown = viewModel::clearActionMessage,
    )
}

@Composable
fun AdFraudDashboardScreen(
    state: AdFraudUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onConfirmEvent: (String) -> Unit,
    onDismissEvent: (String) -> Unit,
    onSuspend: (accountId: String, reason: String) -> Unit,
    onUnsuspend: (String) -> Unit,
    onMessageShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbar = remember { SnackbarHostState() }
    var suspendTarget by remember { mutableStateOf<AdFraudAccountDto?>(null) }

    val message = (state as? AdFraudUiState.Content)?.actionMessage
    val transient = (state as? AdFraudUiState.Content)?.transientError
    LaunchedEffect(message, transient) {
        val text = message ?: transient?.let { adminOpsErrorMessage(it) }
        if (text != null) {
            snackbar.showSnackbar(text)
            onMessageShown()
        }
    }
    LaunchedEffect(message) { if (message != null) suspendTarget = null }

    Scaffold(
        modifier = modifier.testTag(AdFraudTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Ad fraud") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        val isRefreshing = (state as? AdFraudUiState.Content)?.isRefreshing == true
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            when (state) {
                is AdFraudUiState.Loading -> LoadingState()
                is AdFraudUiState.Forbidden -> EmptyState(
                    modifier = Modifier.testTag(AdFraudTestTags.FORBIDDEN),
                    title = "Not authorised",
                    body = "You need platform-admin access to view ad-fraud data.",
                    imageVector = Icons.Outlined.Lock,
                    actionLabel = "Back",
                    onAction = onBack,
                )
                is AdFraudUiState.Error -> ErrorState(
                    modifier = Modifier.testTag(AdFraudTestTags.ERROR_RETRY),
                    message = adminOpsErrorMessage(state.type),
                    onRetry = onRetry,
                )
                is AdFraudUiState.Content -> DashboardBody(
                    data = state.data,
                    actionInFlight = state.actionInFlight,
                    onConfirmEvent = onConfirmEvent,
                    onDismissEvent = onDismissEvent,
                    onSuspendClick = { suspendTarget = it },
                    onUnsuspend = onUnsuspend,
                )
            }
        }
    }

    val target = suspendTarget
    if (target != null) {
        val inFlight = (state as? AdFraudUiState.Content)?.actionInFlight == true
        SuspendDialog(
            account = target,
            actionInFlight = inFlight,
            onDismiss = { if (!inFlight) suspendTarget = null },
            onConfirm = { reason -> onSuspend(target.accountId, reason) },
        )
    }
}

@Composable
private fun DashboardBody(
    data: AdFraudDashboard,
    actionInFlight: Boolean,
    onConfirmEvent: (String) -> Unit,
    onDismissEvent: (String) -> Unit,
    onSuspendClick: (AdFraudAccountDto) -> Unit,
    onUnsuspend: (String) -> Unit,
) {
    val s = data.summary
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        KpiGrid(
            tiles = listOf(
                "Flagged today" to s.flaggedEventsToday.toString(),
                "Fraud rate" to bpsPct(s.fraudRateBps),
                "Flagged events" to s.flaggedEvents.toString(),
                "Total events" to s.totalEvents.toString(),
                "Suspended" to s.suspendedAccounts.toString(),
                "Tracked accts" to s.trackedAccounts.toString(),
            ),
        )
        if (s.topFraudRules.isNotEmpty()) {
            CardSection(title = "Top fraud rules") {
                s.topFraudRules.entries.sortedByDescending { it.value }.forEach { (rule, count) ->
                    StatRow(label = rule.replace('_', ' '), value = count.toString())
                }
            }
        }

        Text("Flagged events", style = MaterialTheme.typography.titleMedium)
        if (data.events.isEmpty()) {
            Text("No flagged events.", style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        } else {
            data.events.forEach { ev ->
                EventCard(ev, actionInFlight, onConfirmEvent, onDismissEvent)
            }
        }

        Text("Account risk", style = MaterialTheme.typography.titleMedium)
        if (data.accounts.isEmpty()) {
            Text("No tracked accounts.", style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        } else {
            data.accounts.forEach { acct ->
                AccountCard(acct, actionInFlight, onSuspendClick, onUnsuspend)
            }
        }
    }
}

@Composable
private fun EventCard(
    ev: AdFraudEventDto,
    actionInFlight: Boolean,
    onConfirm: (String) -> Unit,
    onDismiss: (String) -> Unit,
) {
    val pending = ev.status.equals("flagged", true) || ev.status.equals("pending", true) || ev.status.isBlank()
    Card(modifier = Modifier.fillMaxWidth().testTag(AdFraudTestTags.event(ev.eventId))) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                text = ev.eventType.ifBlank { "event" }.replace('_', ' '),
                style = MaterialTheme.typography.titleSmall,
                maxLines = 1, overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = "Account: ${ev.accountId} · score ${String.format(java.util.Locale.US, "%.2f", ev.fraudScore)}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1, overflow = TextOverflow.Ellipsis,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(ev.status.ifBlank { "flagged" }, style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary)
                if (ev.createdAt > 0L) {
                    Text(relativeSeconds(ev.createdAt), style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            if (pending) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End),
                ) {
                    TextButton(onClick = { onDismiss(ev.eventId) }, enabled = !actionInFlight) { Text("Dismiss") }
                    Button(onClick = { onConfirm(ev.eventId) }, enabled = !actionInFlight) { Text("Confirm") }
                }
            }
        }
    }
}

@Composable
private fun AccountCard(
    acct: AdFraudAccountDto,
    actionInFlight: Boolean,
    onSuspendClick: (AdFraudAccountDto) -> Unit,
    onUnsuspend: (String) -> Unit,
) {
    val suspended = acct.status.equals("suspended", true)
    Card(modifier = Modifier.fillMaxWidth().testTag(AdFraudTestTags.account(acct.accountId))) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(acct.accountId, style = MaterialTheme.typography.titleSmall, maxLines = 1,
                overflow = TextOverflow.Ellipsis)
            Text(
                text = "Rate ${bpsPct(acct.fraudRateBps)} · ${acct.flaggedEvents}/${acct.totalEvents} flagged",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(acct.status.ifBlank { "active" }, style = MaterialTheme.typography.labelMedium,
                color = if (suspended) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary)
            Row(
                modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End),
            ) {
                if (suspended) {
                    OutlinedButton(onClick = { onUnsuspend(acct.accountId) }, enabled = !actionInFlight) {
                        Text("Reinstate")
                    }
                } else {
                    OutlinedButton(onClick = { onSuspendClick(acct) }, enabled = !actionInFlight) {
                        Text("Suspend")
                    }
                }
            }
        }
    }
}

@Composable
private fun SuspendDialog(
    account: AdFraudAccountDto,
    actionInFlight: Boolean,
    onDismiss: () -> Unit,
    onConfirm: (reason: String) -> Unit,
) {
    var reason by remember { mutableStateOf("") }
    Dialog(onDismissRequest = onDismiss) {
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("Suspend account", style = MaterialTheme.typography.titleMedium)
                Text(account.accountId, style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                OutlinedTextField(
                    value = reason,
                    onValueChange = { if (it.length <= 500) reason = it },
                    label = { Text("Reason (optional)") },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !actionInFlight,
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End),
                ) {
                    TextButton(onClick = onDismiss, enabled = !actionInFlight) { Text("Cancel") }
                    Button(onClick = { onConfirm(reason) }, enabled = !actionInFlight) { Text("Suspend") }
                }
            }
        }
    }
}
