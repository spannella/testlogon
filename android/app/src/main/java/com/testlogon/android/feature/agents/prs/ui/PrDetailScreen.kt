@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.agents.prs.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.outlined.OpenInNew
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.core.net.toUri
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.feature.agents.prs.data.AgentCompletion
import com.testlogon.android.feature.agents.prs.data.PrsCompletionMath

/** AGENTS-BASICS - stable testTags for the agent-PR detail. */
object PrDetailTestTags {
    const val SCREEN = "agent_pr_detail_screen"
    const val OPEN_PR = "agent_pr_open_external"
    const val COMPLETE = "agent_pr_complete"
    const val COMPLETION = "agent_pr_completion_result"
}

@Composable
fun PrDetailRoute(
    onBack: () -> Unit,
    onNavigateToLogin: () -> Unit,
    viewModel: PrDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is PrsEffect.NavigateToLogin -> onNavigateToLogin()
            }
        }
    }
    PrDetailScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onComplete = viewModel::completeWork,
    )
}

@Composable
fun PrDetailScreen(
    state: PrDetailUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onComplete: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    Scaffold(
        modifier = modifier.testTag(PrDetailTestTags.SCREEN),
        topBar = {
            androidx.compose.material3.TopAppBar(
                title = { Text("Pull request") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    val pr = (state as? PrDetailUiState.Content)?.pr
                    if (pr != null && pr.prUrl.isNotBlank()) {
                        IconButton(
                            onClick = {
                                runCatching {
                                    context.startActivity(
                                        android.content.Intent(
                                            android.content.Intent.ACTION_VIEW,
                                            pr.prUrl.toUri(),
                                        ).addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK),
                                    )
                                }
                            },
                            modifier = Modifier.testTag(PrDetailTestTags.OPEN_PR),
                        ) {
                            Icon(Icons.AutoMirrored.Outlined.OpenInNew, contentDescription = "Open on the web")
                        }
                    }
                },
            )
        },
    ) { padding ->
        when (state) {
            is PrDetailUiState.Loading -> LoadingState(modifier = Modifier.padding(padding))
            is PrDetailUiState.Error ->
                ErrorState(modifier = Modifier.padding(padding), message = state.message, onRetry = onRetry)
            is PrDetailUiState.Content ->
                PrDetailContent(state = state, onComplete = onComplete, modifier = Modifier.padding(padding))
        }
    }
}

@Composable
private fun PrDetailContent(
    state: PrDetailUiState.Content,
    onComplete: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val pr = state.pr
    Column(
        modifier = modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = pr.title.ifBlank { if (pr.prNumber > 0) "PR #${pr.prNumber}" else pr.prId },
            style = MaterialTheme.typography.titleLarge,
        )
        AssistChip(onClick = {}, label = { Text(pr.statusWire.ifBlank { "open" }) })
        HorizontalDivider()
        DetailRow("Ticket", pr.ticketId)
        DetailRow("Branch", pr.branch)
        DetailRow("Repository", pr.repoUrl)
        DetailRow("PR URL", pr.prUrl)
        if (pr.commitCount > 0) DetailRow("Commits", pr.commitCount.toString())
        if (pr.description.isNotBlank()) {
            HorizontalDivider()
            Text("Description", style = MaterialTheme.typography.titleSmall)
            Text(pr.description, style = MaterialTheme.typography.bodyMedium)
        }
        if (pr.filesChanged.isNotEmpty()) {
            HorizontalDivider()
            Text("Files changed (${pr.filesChanged.size})", style = MaterialTheme.typography.titleSmall)
            pr.filesChanged.forEach { file ->
                Text(file, style = MaterialTheme.typography.bodySmall, modifier = Modifier.fillMaxWidth())
            }
        }
        HorizontalDivider()
        if (state.completion != null) {
            CompletionCard(state.completion)
        } else {
            Button(
                onClick = onComplete,
                enabled = !state.completing && pr.workerId.isNotBlank() && pr.ticketId.isNotBlank(),
                modifier = Modifier.fillMaxWidth().testTag(PrDetailTestTags.COMPLETE),
            ) {
                if (state.completing) {
                    CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(20.dp))
                } else {
                    Text("Complete work")
                }
            }
            if (state.completeError != null) {
                Text(
                    text = state.completeError,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
        }
    }
}

@Composable
private fun CompletionCard(completion: AgentCompletion) {
    Card(modifier = Modifier.fillMaxWidth().testTag(PrDetailTestTags.COMPLETION)) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text("Work completed", style = MaterialTheme.typography.titleSmall)
            Text(
                text = PrsCompletionMath.summaryLabel(completion.summary),
                style = MaterialTheme.typography.bodyMedium,
            )
            if (completion.summary.text.isNotBlank()) {
                Text(completion.summary.text, style = MaterialTheme.typography.bodySmall)
            }
            if (completion.newStatus.isNotBlank()) DetailRow("New status", completion.newStatus)
            if (completion.nextAgentType.isNotBlank()) DetailRow("Next agent", completion.nextAgentType)
            if (completion.summary.decisions.isNotEmpty()) {
                Text("Decisions", style = MaterialTheme.typography.labelMedium)
                completion.summary.decisions.forEach { Text("- $it", style = MaterialTheme.typography.bodySmall) }
            }
        }
    }
}

@Composable
private fun DetailRow(label: String, value: String) {
    if (value.isBlank()) return
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}
