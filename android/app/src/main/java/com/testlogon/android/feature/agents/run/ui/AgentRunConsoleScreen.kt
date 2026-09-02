@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.agents.run.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
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
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.agentrun.AgentRunOutput
import com.testlogon.android.data.agentrun.AgentRunType
import com.testlogon.android.data.agentrun.PmOperation
import com.testlogon.android.data.agentrun.RunMetrics
import com.testlogon.android.data.agentrun.RunState

/**
 * AGENT-RUN (web-parity) - the generic agent-run CONSOLE. One screen drives eligible-tickets -> claim ->
 * execute -> output/report/metrics for any of the six agent types; DevOps additionally shows an
 * approve/reject deployment gate (mobile mirror of the web DeploymentApprovalPanel). Operator-gated in the
 * More catalog + backend-403 -> Forbidden notice.
 */
object AgentRunConsoleTestTags {
    const val SCREEN = "agent_run_console_screen"
    const val CLAIM = "agent_run_claim"
    const val EXECUTE = "agent_run_execute"
    const val APPROVE = "agent_run_approve"
    const val REJECT = "agent_run_reject"
    fun ticket(id: String) = "agent_run_ticket_$id"
}

@Composable
fun AgentRunConsoleRoute(
    onBack: () -> Unit,
    onNavigateToLogin: () -> Unit,
    viewModel: AgentRunConsoleViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                AgentRunEffect.NavigateToLogin -> onNavigateToLogin()
            }
        }
    }
    AgentRunConsoleScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onSelectTicket = viewModel::selectTicket,
        onSelectPmOperation = viewModel::selectPmOperation,
        onClaim = viewModel::claim,
        onExecute = viewModel::execute,
        onRefreshOutput = viewModel::refreshOutput,
        onLoadMetrics = viewModel::loadMetrics,
        onApprove = viewModel::approve,
        onReject = viewModel::reject,
        onDismissMessage = viewModel::dismissMessage,
    )
}

@Composable
fun AgentRunConsoleScreen(
    state: AgentRunUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onSelectTicket: (String) -> Unit,
    onSelectPmOperation: (PmOperation) -> Unit,
    onClaim: () -> Unit,
    onExecute: () -> Unit,
    onRefreshOutput: () -> Unit,
    onLoadMetrics: () -> Unit,
    onApprove: (String?) -> Unit,
    onReject: (String?) -> Unit,
    onDismissMessage: () -> Unit,
) {
    val snackbar = remember { SnackbarHostState() }
    val title = (state as? AgentRunUiState.Content)?.type?.title ?: "Agent run"

    if (state is AgentRunUiState.Content && state.message != null) {
        LaunchedEffect(state.message) {
            snackbar.showSnackbar(state.message)
            onDismissMessage()
        }
    }

    Scaffold(
        modifier = Modifier.testTag(AgentRunConsoleTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text(title) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        when (state) {
            AgentRunUiState.Loading -> LoadingState(Modifier.padding(padding))
            AgentRunUiState.Forbidden -> EmptyState(
                title = "Operator access required",
                body = "The agent-run console is available to admins/operators only.",
                modifier = Modifier.padding(padding),
            )
            is AgentRunUiState.Error -> ErrorState(
                message = state.message,
                onRetry = onRetry,
                modifier = Modifier.padding(padding),
            )
            is AgentRunUiState.Content -> ConsoleContent(
                state = state,
                modifier = Modifier.padding(padding),
                onSelectTicket = onSelectTicket,
                onSelectPmOperation = onSelectPmOperation,
                onClaim = onClaim,
                onExecute = onExecute,
                onRefreshOutput = onRefreshOutput,
                onLoadMetrics = onLoadMetrics,
                onApprove = onApprove,
                onReject = onReject,
            )
        }
    }
}

@Composable
private fun ConsoleContent(
    state: AgentRunUiState.Content,
    modifier: Modifier,
    onSelectTicket: (String) -> Unit,
    onSelectPmOperation: (PmOperation) -> Unit,
    onClaim: () -> Unit,
    onExecute: () -> Unit,
    onRefreshOutput: () -> Unit,
    onLoadMetrics: () -> Unit,
    onApprove: (String?) -> Unit,
    onReject: (String?) -> Unit,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        SectionCard("Agent") {
            Text("${state.type.title}  ·  type id: ${state.typeId}", style = MaterialTheme.typography.bodyMedium)
            Text("State: ${state.runState.name}", style = MaterialTheme.typography.labelMedium)
            state.runId?.let { Text("Run: $it", fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.labelSmall) }
        }

        if (state.type.operationDriven) {
            SectionCard("Operation") {
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    PmOperation.entries.forEach { op ->
                        FilterChip(
                            selected = state.pmOperation == op,
                            onClick = { onSelectPmOperation(op) },
                            label = { Text(op.label) },
                        )
                    }
                }
                Button(
                    onClick = onExecute,
                    enabled = !state.busy,
                    modifier = Modifier.fillMaxWidth().testTag(AgentRunConsoleTestTags.EXECUTE),
                ) { Text("Run operation") }
            }
        } else if (state.type != AgentRunType.DOCS) {
            SectionCard("Eligible tickets") {
                if (state.eligibleTickets.isEmpty()) {
                    Text("No eligible tickets for this agent.", style = MaterialTheme.typography.bodySmall)
                } else {
                    state.eligibleTickets.forEach { t ->
                        FilterChip(
                            selected = state.selectedTicketId == t.ticketId,
                            onClick = { onSelectTicket(t.ticketId) },
                            label = { Text("${t.ticketId} · ${t.subject.take(40)}") },
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag(AgentRunConsoleTestTags.ticket(t.ticketId)),
                        )
                    }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(
                        onClick = onClaim,
                        enabled = !state.busy && state.selectedTicketId != null,
                        modifier = Modifier.weight(1f).testTag(AgentRunConsoleTestTags.CLAIM),
                    ) { Text("Claim") }
                    Button(
                        onClick = onExecute,
                        enabled = !state.busy && state.runState == RunState.CLAIMED ||
                            !state.busy && state.runState == RunState.COMPLETED,
                        modifier = Modifier.weight(1f).testTag(AgentRunConsoleTestTags.EXECUTE),
                    ) { Text("Execute") }
                }
            }
        }

        state.output?.let { OutputCard(it, onRefreshOutput) }

        if (state.type.supportsApproval && state.runState == RunState.AWAITING_APPROVAL) {
            ApprovalCard(onApprove = onApprove, onReject = onReject, busy = state.busy)
        }
        state.decision?.let { d ->
            SectionCard("Deployment decision") {
                Text("Status: ${d.approvalStatus}", style = MaterialTheme.typography.bodyMedium)
                if (d.deploymentId.isNotBlank()) Text("Deployment: ${d.deploymentId}")
                d.notes?.let { Text("Notes: $it") }
            }
        }

        state.report?.let { r ->
            SectionCard("QA report (${r.verdict})") {
                Text(
                    text = r.markdown.ifBlank { "(empty report)" },
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                )
            }
        }

        MetricsCard(state.metrics, state.loadingMetrics, onLoadMetrics)
    }
}

@Composable
private fun OutputCard(output: AgentRunOutput, onRefresh: () -> Unit) {
    SectionCard("Output") {
        Text(output.headline, style = MaterialTheme.typography.titleSmall)
        AssistChip(onClick = {}, label = { Text(output.status) })
        output.prUrl?.let { Text(it, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall) }
        if (output.filesChanged.isNotEmpty()) {
            HorizontalDivider()
            Text("Files changed (+${output.insertions} / -${output.deletions})", style = MaterialTheme.typography.labelMedium)
            output.filesChanged.take(30).forEach {
                Text(it, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
            }
        }
        if (output.testResults.isNotEmpty()) {
            HorizontalDivider()
            output.testResults.forEach {
                Text(
                    "${if (it.passed) "PASS" else "FAIL"}  ${it.label}" + (it.durationSeconds?.let { d -> "  ${d}s" } ?: ""),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
        if (output.extras.isNotEmpty()) {
            HorizontalDivider()
            output.extras.forEach { (k, v) -> Text("$k: $v", style = MaterialTheme.typography.bodySmall) }
        }
        Text("Duration: ${output.totalDurationSeconds}s", style = MaterialTheme.typography.labelSmall)
        if (output.escalated) {
            Text("Escalated: ${output.escalationReason ?: "yes"}", style = MaterialTheme.typography.labelMedium)
        }
        OutlinedButton(onClick = onRefresh) { Text("Reload output") }
    }
}

@Composable
private fun ApprovalCard(onApprove: (String?) -> Unit, onReject: (String?) -> Unit, busy: Boolean) {
    var notes by remember { mutableStateOf("") }
    SectionCard("Deployment pending approval") {
        OutlinedTextField(
            value = notes,
            onValueChange = { notes = it },
            label = { Text("Approver notes") },
            modifier = Modifier.fillMaxWidth(),
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = { onApprove(notes) },
                enabled = !busy,
                modifier = Modifier.weight(1f).testTag(AgentRunConsoleTestTags.APPROVE),
            ) { Text("Approve") }
            OutlinedButton(
                onClick = { onReject(notes) },
                enabled = !busy,
                modifier = Modifier.weight(1f).testTag(AgentRunConsoleTestTags.REJECT),
            ) { Text("Reject") }
        }
    }
}

@Composable
private fun MetricsCard(metrics: RunMetrics?, loading: Boolean, onLoad: () -> Unit) {
    SectionCard("Metrics") {
        when {
            loading -> LoadingState(fullScreen = false)
            metrics == null || metrics.rows.isEmpty() ->
                OutlinedButton(onClick = onLoad) { Text("Load metrics") }
            else -> metrics.rows.forEach { (k, v) ->
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(k, style = MaterialTheme.typography.bodySmall)
                    Text(v, style = MaterialTheme.typography.bodyMedium)
                }
            }
        }
    }
}

@Composable
private fun SectionCard(title: String, content: @Composable () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp).fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            content()
        }
    }
}
