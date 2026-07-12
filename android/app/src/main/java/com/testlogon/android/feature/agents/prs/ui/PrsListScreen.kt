@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.agents.prs.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.MergeType
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
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
import com.testlogon.android.feature.agents.prs.data.AgentPr

/** AGENTS-BASICS - stable testTags for the agent-PR list. */
object PrsListTestTags {
    const val SCREEN = "agent_prs_screen"
    const val EMPTY = "agent_prs_empty"
    const val ERROR_RETRY = "agent_prs_error_retry"
    fun row(id: String) = "agent_pr_row_$id"
}

@Composable
fun PrsListRoute(
    onBack: () -> Unit,
    onOpenPr: (String) -> Unit,
    onNavigateToLogin: () -> Unit,
    viewModel: PrsListViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is PrsEffect.NavigateToLogin -> onNavigateToLogin()
            }
        }
    }
    PrsListScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::onRetry,
        onOpenPr = onOpenPr,
    )
}

@Composable
fun PrsListScreen(
    state: PrsListUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onOpenPr: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(PrsListTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Agent PRs") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        val isRefreshing = (state as? PrsListUiState.Content)?.isRefreshing == true
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            when (state) {
                is PrsListUiState.Loading -> LoadingState()
                is PrsListUiState.Empty ->
                    EmptyState(
                        modifier = Modifier.testTag(PrsListTestTags.EMPTY),
                        title = "No pull requests",
                        body = "Pull requests opened by your agent workers will appear here.",
                        imageVector = Icons.Outlined.MergeType,
                    )
                is PrsListUiState.Error ->
                    ErrorState(
                        modifier = Modifier.testTag(PrsListTestTags.ERROR_RETRY),
                        message = state.message,
                        onRetry = onRetry,
                    )
                is PrsListUiState.Content ->
                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        items(items = state.items, key = { it.prId }) { pr ->
                            PrRow(pr = pr, onOpen = { onOpenPr(pr.prId) })
                        }
                    }
            }
        }
    }
}

@Composable
private fun PrRow(pr: AgentPr, onOpen: () -> Unit) {
    Card(
        onClick = onOpen,
        modifier = Modifier.fillMaxWidth().testTag(PrsListTestTags.row(pr.prId)),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(
                    text = pr.title.ifBlank { if (pr.prNumber > 0) "PR #${pr.prNumber}" else pr.prId },
                    style = MaterialTheme.typography.titleSmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = listOf(
                        pr.ticketId.takeIf { it.isNotBlank() }?.let { "Ticket $it" },
                        pr.branch.takeIf { it.isNotBlank() },
                    ).filterNotNull().joinToString(" · "),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            AssistChip(onClick = onOpen, label = { Text(pr.statusWire.ifBlank { "open" }) })
        }
    }
}
