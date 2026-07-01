@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.agents.prs.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.outlined.OpenInNew
import androidx.compose.material3.AssistChip
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
import com.testlogon.android.feature.agents.prs.data.AgentPr

/** AGENTS-BASICS - stable testTags for the agent-PR detail. */
object PrDetailTestTags {
    const val SCREEN = "agent_pr_detail_screen"
    const val OPEN_PR = "agent_pr_open_external"
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
    PrDetailScreen(state = state, onBack = onBack, onRetry = viewModel::onRetry)
}

@Composable
fun PrDetailScreen(
    state: PrDetailUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
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
            is PrDetailUiState.Content -> PrDetailContent(pr = state.pr, modifier = Modifier.padding(padding))
        }
    }
}

@Composable
private fun PrDetailContent(pr: AgentPr, modifier: Modifier = Modifier) {
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
