@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.agents.docs.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.feature.agents.docs.data.DocCoverage
import com.testlogon.android.feature.agents.docs.data.DocTypeCoverage
import kotlin.math.roundToInt

/** AGENTS-BASICS - stable testTags for the doc-coverage dashboard. */
object DocCoverageTestTags {
    const val SCREEN = "agent_docs_screen"
    const val ERROR_RETRY = "agent_docs_error_retry"
    const val FRESHNESS = "agent_docs_freshness"
    const val TEMPLATES = "agent_docs_templates"
}

private fun pct(value: Double): String = "${(value.coerceIn(0.0, 1.0) * 100).roundToInt()}%"

@Composable
fun DocCoverageRoute(
    onBack: () -> Unit,
    onOpenTemplates: () -> Unit,
    onNavigateToLogin: () -> Unit,
    viewModel: DocCoverageViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is DocsEffect.NavigateToLogin -> onNavigateToLogin()
            }
        }
    }
    DocCoverageScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::onRetry,
        onRunFreshness = viewModel::runFreshnessCheck,
        onOpenTemplates = onOpenTemplates,
    )
}

@Composable
fun DocCoverageScreen(
    state: DocCoverageUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onRunFreshness: () -> Unit,
    onOpenTemplates: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(DocCoverageTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Doc coverage") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    TextButton(onClick = onOpenTemplates, modifier = Modifier.testTag(DocCoverageTestTags.TEMPLATES)) {
                        Text("Templates")
                    }
                },
            )
        },
    ) { padding ->
        val isRefreshing = (state as? DocCoverageUiState.Content)?.isRefreshing == true
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            when (state) {
                is DocCoverageUiState.Loading -> LoadingState()
                is DocCoverageUiState.Error ->
                    ErrorState(
                        modifier = Modifier.testTag(DocCoverageTestTags.ERROR_RETRY),
                        message = state.message,
                        onRetry = onRetry,
                    )
                is DocCoverageUiState.Content ->
                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        item { SummaryCard(state, onRunFreshness) }
                        if (state.summary.byType.isNotEmpty()) {
                            item { Text("Coverage by type", style = MaterialTheme.typography.titleMedium) }
                            items(items = state.summary.byType, key = { it.docType }) { ByTypeRow(it) }
                        }
                        if (state.docs.isNotEmpty()) {
                            item { Text("Documents (${state.docs.size})", style = MaterialTheme.typography.titleMedium) }
                            items(items = state.docs, key = { it.docPath }) { DocRow(it) }
                        } else {
                            item {
                                Text(
                                    "No registered documents yet.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                    }
            }
        }
    }
}

@Composable
private fun SummaryCard(state: DocCoverageUiState.Content, onRunFreshness: () -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Overall coverage", style = MaterialTheme.typography.labelMedium)
            Text(pct(state.summary.overallCoverage), style = MaterialTheme.typography.headlineMedium)
            LinearProgressIndicator(
                progress = { state.summary.overallCoverage.coerceIn(0.0, 1.0).toFloat() },
                modifier = Modifier.fillMaxWidth(),
            )
            Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                Text("Total: ${state.summary.totalDocs}", style = MaterialTheme.typography.bodySmall)
                Text("Stale: ${state.summary.staleDocs}", style = MaterialTheme.typography.bodySmall)
            }
            if (state.actionMessage != null) {
                Text(state.actionMessage, style = MaterialTheme.typography.bodySmall)
            }
            OutlinedButton(
                onClick = onRunFreshness,
                enabled = !state.checkingFreshness,
                modifier = Modifier.testTag(DocCoverageTestTags.FRESHNESS),
            ) {
                if (state.checkingFreshness) {
                    CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(18.dp))
                } else {
                    Text("Run freshness check")
                }
            }
        }
    }
}

@Composable
private fun ByTypeRow(item: DocTypeCoverage) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(item.docType, style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
                Text(pct(item.avgCoverage), style = MaterialTheme.typography.bodyMedium)
            }
            LinearProgressIndicator(
                progress = { item.avgCoverage.coerceIn(0.0, 1.0).toFloat() },
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

@Composable
private fun DocRow(doc: DocCoverage) {
    Card(Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(
                    doc.docPath,
                    style = MaterialTheme.typography.bodyMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    listOf(doc.docType, pct(doc.coverageScore)).filter { it.isNotBlank() }.joinToString(" · "),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (doc.isStale) {
                AssistChip(onClick = {}, label = { Text("stale") })
            }
        }
    }
}
