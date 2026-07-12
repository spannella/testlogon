@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.adminincidents

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
import androidx.compose.material.icons.outlined.CreditCardOff
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
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
import com.testlogon.android.data.adminincidents.IncidentDto
import com.testlogon.android.feature.adminmod.AdminOpsErrorType

object IncidentAdminTestTags {
    const val SCREEN = "incident_admin_screen"
    const val LIST = "incident_admin_list"
    const val EMPTY = "incident_admin_empty"
    const val FORBIDDEN = "incident_admin_forbidden"
    const val ERROR_RETRY = "incident_admin_error_retry"
    fun filter(s: String) = "incident_filter_$s"
    fun row(id: String) = "incident_row_$id"
    fun respond(id: String) = "incident_respond_$id"
    const val RESPOND_CONFIRM = "incident_respond_confirm"
}

private const val FILTER_ALL = "all"
private const val TYPE_DISPUTE = "dispute"

@Composable
fun IncidentAdminRoute(
    onBack: () -> Unit,
    viewModel: IncidentAdminViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    IncidentAdminScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        onSetFilter = viewModel::setFilter,
        onSubmitResponse = viewModel::submitResponse,
        onMessageShown = viewModel::clearMessage,
    )
}

@Composable
fun IncidentAdminScreen(
    state: IncidentAdminUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onSetFilter: (String?) -> Unit,
    onSubmitResponse: (String, String, String?) -> Unit,
    onMessageShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbar = remember { SnackbarHostState() }
    var respondTarget by remember { mutableStateOf<String?>(null) }
    val content = state as? IncidentAdminUiState.Content

    LaunchedEffect(content?.message, content?.transientError) {
        val msg = content?.message ?: content?.transientError?.let { incidentErrorMessage(it) }
        if (msg != null) {
            snackbar.showSnackbar(msg)
            onMessageShown()
        }
    }

    val activeFilter = when (state) {
        is IncidentAdminUiState.Content -> state.statusFilter
        is IncidentAdminUiState.Empty -> state.statusFilter
        else -> null
    }

    Scaffold(
        modifier = modifier.testTag(IncidentAdminTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("Payment incidents") },
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
                    is IncidentAdminUiState.Loading -> LoadingState()
                    is IncidentAdminUiState.Empty -> EmptyState(
                        modifier = Modifier.testTag(IncidentAdminTestTags.EMPTY),
                        title = "No incidents",
                        body = "There are no payment incidents to review.",
                        imageVector = Icons.Outlined.CreditCardOff,
                    )
                    is IncidentAdminUiState.Forbidden -> EmptyState(
                        modifier = Modifier.testTag(IncidentAdminTestTags.FORBIDDEN),
                        title = "Not authorised",
                        body = "You need billing-support admin access to manage payment incidents.",
                        imageVector = Icons.Outlined.Lock,
                        actionLabel = "Back",
                        onAction = onBack,
                    )
                    is IncidentAdminUiState.Error -> ErrorState(
                        modifier = Modifier.testTag(IncidentAdminTestTags.ERROR_RETRY),
                        message = incidentErrorMessage(state.type),
                        onRetry = onRetry,
                    )
                    is IncidentAdminUiState.Content -> LazyColumn(
                        modifier = Modifier.fillMaxSize().testTag(IncidentAdminTestTags.LIST),
                        contentPadding = PaddingValues(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        items(items = state.incidents, key = { it.incidentId }) { i ->
                            IncidentRow(
                                incident = i,
                                inFlight = state.actionInFlightId == i.incidentId,
                                actionsEnabled = state.actionInFlightId == null,
                                onRespond = { respondTarget = i.incidentId },
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
            onConfirm = { summary, rationale ->
                onSubmitResponse(targetId, summary, rationale)
                respondTarget = null
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
        INCIDENT_STATUS_FILTERS.forEach { s ->
            val label = s?.replace('_', ' ')?.replaceFirstChar { it.uppercase() } ?: "All"
            FilterChip(
                selected = active == s,
                onClick = { onSelect(s) },
                label = { Text(label) },
                modifier = Modifier.testTag(IncidentAdminTestTags.filter(s ?: FILTER_ALL)),
            )
        }
    }
}

@Composable
private fun IncidentRow(
    incident: IncidentDto,
    inFlight: Boolean,
    actionsEnabled: Boolean,
    onRespond: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(IncidentAdminTestTags.row(incident.incidentId))) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(incident.incidentType.ifBlank { "Incident" }.replace('_', ' '), style = MaterialTheme.typography.titleSmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(incident.status.ifBlank { "-" }.replace('_', ' '), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                if (incident.provider.isNotBlank()) {
                    Text(incident.provider, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                formatAmount(incident)?.let {
                    Text(it, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            incident.customerId?.takeIf { it.isNotBlank() }?.let {
                Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            incident.reason?.takeIf { it.isNotBlank() }?.let {
                Text(it, style = MaterialTheme.typography.bodySmall, maxLines = 2, overflow = TextOverflow.Ellipsis)
            }
            if (inFlight) {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) { CircularProgressIndicator() }
            } else if (incident.incidentType.equals(TYPE_DISPUTE, ignoreCase = true)) {
                Button(
                    onClick = onRespond,
                    enabled = actionsEnabled,
                    modifier = Modifier.fillMaxWidth().testTag(IncidentAdminTestTags.respond(incident.incidentId)),
                ) { Text("Submit response") }
            }
        }
    }
}

@Composable
private fun RespondDialog(onDismiss: () -> Unit, onConfirm: (String, String?) -> Unit) {
    var summary by remember { mutableStateOf("") }
    var rationale by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Submit dispute response") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = summary,
                    onValueChange = { summary = it },
                    label = { Text("Response summary (required)") },
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = rationale,
                    onValueChange = { rationale = it },
                    label = { Text("Rationale (optional)") },
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(summary, rationale.ifBlank { null }) },
                enabled = summary.isNotBlank(),
                modifier = Modifier.testTag(IncidentAdminTestTags.RESPOND_CONFIRM),
            ) { Text("Submit") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

private fun formatAmount(incident: IncidentDto): String? {
    val sym = when (incident.currency?.uppercase()) {
        "USD", null -> "$"; "EUR" -> "€"; "GBP" -> "£"; else -> "${incident.currency} "
    }
    return when {
        incident.amountCents != null -> "%s%,.2f".format(sym, incident.amountCents / 100.0)
        incident.amount != null -> "%s%,.2f".format(sym, incident.amount)
        else -> null
    }
}

internal fun incidentErrorMessage(type: AdminOpsErrorType): String = when (type) {
    AdminOpsErrorType.AUTH -> "Your session expired. Please sign in again."
    AdminOpsErrorType.SERVER -> "Something went wrong on the server. Try again."
    AdminOpsErrorType.NETWORK -> "You appear to be offline. Check your connection."
}
