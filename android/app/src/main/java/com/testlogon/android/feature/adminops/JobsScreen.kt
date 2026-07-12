@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.adminops

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.data.adminops.JobTaskDto
import com.testlogon.android.data.adminops.JobsDashboardData

object JobsTestTags {
    const val SCREEN = "adminops_jobs_screen"
    const val CONTENT = "adminops_jobs_content"
    const val FORBIDDEN = "adminops_jobs_forbidden"
    const val RETRY = "adminops_jobs_retry"
    fun retryJob(id: String) = "adminops_jobs_retry_$id"
}

@Composable
fun JobsRoute(
    onBack: () -> Unit,
    viewModel: JobsViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val snackbar = remember { SnackbarHostState() }
    val content = state as? JobsUiState.Content
    LaunchedEffect(content?.actionMessage) {
        content?.actionMessage?.let {
            snackbar.showSnackbar(it)
            viewModel.clearActionMessage()
        }
    }
    val branch = when (state) {
        is JobsUiState.Loading -> AdminOpsBranch.Loading
        is JobsUiState.Forbidden -> AdminOpsBranch.Forbidden
        is JobsUiState.Error -> AdminOpsBranch.Error((state as JobsUiState.Error).type)
        is JobsUiState.Content -> AdminOpsBranch.Content((state as JobsUiState.Content).isRefreshing)
    }
    androidx.compose.material3.Scaffold(
        modifier = Modifier.testTag(JobsTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            androidx.compose.material3.TopAppBar(
                title = { Text("Background jobs") },
                navigationIcon = { AdminOpsBackIcon(onBack) },
            )
        },
    ) { padding ->
        androidx.compose.foundation.layout.Box(modifier = Modifier.fillMaxSize().padding(padding)) {
            androidx.compose.material3.pulltorefresh.PullToRefreshBox(
                isRefreshing = branch.isRefreshing,
                onRefresh = viewModel::refresh,
                modifier = Modifier.fillMaxSize(),
            ) {
                when (state) {
                    is JobsUiState.Loading -> com.testlogon.android.core.ui.state.LoadingState()
                    is JobsUiState.Forbidden -> com.testlogon.android.core.ui.state.EmptyState(
                        modifier = Modifier.testTag(JobsTestTags.FORBIDDEN),
                        title = "Not authorised",
                        body = "You need platform-admin access to view background jobs.",
                        imageVector = Icons.Outlined.Lock,
                        actionLabel = "Back",
                        onAction = onBack,
                    )
                    is JobsUiState.Error -> com.testlogon.android.core.ui.state.ErrorState(
                        modifier = Modifier.testTag(JobsTestTags.RETRY),
                        message = adminOpsErrorMessage((state as JobsUiState.Error).type),
                        onRetry = viewModel::retry,
                    )
                    is JobsUiState.Content -> JobsContent(
                        data = (state as JobsUiState.Content).data,
                        onRetryJob = viewModel::retryJob,
                    )
                }
            }
        }
    }
}

@Composable
private fun JobsContent(data: JobsDashboardData, onRetryJob: (String, String) -> Unit) {
    val q = data.status.queues
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
            .testTag(JobsTestTags.CONTENT),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        CardSection("Scheduled actions queue") {
            StatRow("Pending", q.scheduledActions.pending.toString())
            StatRow("Failed", q.scheduledActions.failed.toString())
        }
        CardSection("Webhook deliveries") {
            StatRow("Pending", q.webhookDeliveries.pending.toString())
            StatRow("Dead letter", q.webhookDeliveries.deadLetter.toString())
            StatRow("Success (24h)", q.webhookDeliveries.success24h.toString())
            StatRow("Endpoints", "${q.webhookDeliveries.enabledEndpoints}/${q.webhookDeliveries.totalEndpoints}")
        }

        SectionHeader("Tasks (${data.status.tasks.size})")
        data.status.tasks.values.sortedBy { it.name }.forEach { t -> TaskCard(t) }

        SectionHeader("Failed actions")
        if (data.failed.isEmpty()) {
            Text("No failed actions.", style = MaterialTheme.typography.bodyMedium)
        }
        data.failed.forEach { f ->
            CardSection("${f.actionType.ifBlank { "action" }} · retry ${f.retryCount}") {
                StatRow("User", f.userSub)
                StatRow("Action", f.actionId)
                if (f.lastError.isNotBlank()) StatRow("Error", f.lastError)
                TextButton(
                    onClick = { onRetryJob(f.actionId, f.userSub) },
                    modifier = Modifier.testTag(JobsTestTags.retryJob(f.actionId)),
                ) { Text("Retry now") }
            }
        }
    }
}

@Composable
private fun TaskCard(t: JobTaskDto) {
    val statusColor = when (t.status.lowercase()) {
        "running" -> Color(0xFF2E7D32)
        "stale", "disabled" -> Color(0xFFEF6C00)
        "unhealthy" -> MaterialTheme.colorScheme.error
        else -> MaterialTheme.colorScheme.onSurfaceVariant
    }
    CardSection(t.name.ifBlank { "task" }) {
        Text(
            text = t.status.ifBlank { "unknown" }.uppercase(),
            style = MaterialTheme.typography.labelLarge,
            color = statusColor,
            modifier = Modifier.padding(bottom = 4.dp),
        )
        if (t.description.isNotBlank()) StatRow("Description", t.description)
        StatRow("Processed / failed", "${t.itemsProcessed} / ${t.itemsFailed}")
        StatRow("Total polls", t.totalPolls.toString())
        if (t.consecutiveErrors > 0) StatRow("Consecutive errors", t.consecutiveErrors.toString())
        t.lastPollAt?.let { if (it > 0) StatRow("Last poll", relativeSeconds(it)) }
        t.lastError?.takeIf { it.isNotBlank() }?.let { StatRow("Last error", it) }
    }
}
