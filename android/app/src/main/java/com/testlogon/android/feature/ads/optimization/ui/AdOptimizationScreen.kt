@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.ads.optimization.ui

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
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.model.syndicates.formatCents
import com.testlogon.android.core.network.ads.AdRecommendationDto
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** Stable testTags for the ad optimization panel. */
object AdOptimizationTestTags {
    const val SCREEN = "ad_optimization_screen"
    const val LIST = "ad_optimization_list"
    const val EMPTY = "ad_optimization_empty"
    const val ERROR_RETRY = "ad_optimization_error_retry"
    const val GENERATE = "ad_optimization_generate"
    const val AUTO_TOGGLE = "ad_optimization_auto_toggle"

    fun row(recId: String): String = "ad_rec_row_$recId"
    fun apply(recId: String): String = "ad_rec_apply_$recId"
    fun dismiss(recId: String): String = "ad_rec_dismiss_$recId"
}

@Composable
fun AdOptimizationRoute(
    onBack: () -> Unit,
    viewModel: AdOptimizationViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    AdOptimizationScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onGenerate = viewModel::generate,
        onApply = viewModel::applyRecommendation,
        onDismiss = viewModel::dismissRecommendation,
        onToggleAuto = viewModel::setAutoOptimize,
    )
}

@Composable
fun AdOptimizationScreen(
    state: AdOptimizationUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onGenerate: () -> Unit,
    onApply: (String) -> Unit,
    onDismiss: (String) -> Unit,
    onToggleAuto: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(AdOptimizationTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Ad optimization") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                is AdOptimizationUiState.Loading -> LoadingState()
                is AdOptimizationUiState.NoCampaign -> EmptyState(
                    title = "No campaign to optimize",
                    body = "Create an ad account and a campaign first, then run optimization.",
                    modifier = Modifier.testTag(AdOptimizationTestTags.EMPTY),
                )
                is AdOptimizationUiState.Error -> ErrorState(
                    message = state.error.message,
                    onRetry = onRetry,
                    modifier = Modifier.testTag(AdOptimizationTestTags.ERROR_RETRY),
                )
                is AdOptimizationUiState.Content -> OptimizationContent(
                    state, onGenerate, onApply, onDismiss, onToggleAuto,
                )
            }
        }
    }
}

@Composable
private fun OptimizationContent(
    state: AdOptimizationUiState.Content,
    onGenerate: () -> Unit,
    onApply: (String) -> Unit,
    onDismiss: (String) -> Unit,
    onToggleAuto: (Boolean) -> Unit,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag(AdOptimizationTestTags.LIST),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Text("Campaign: ${state.campaignName}", style = MaterialTheme.typography.titleMedium)
        }
        item { AutoOptimizeCard(state, onToggleAuto) }
        item { BidBudgetCard(state) }
        item {
            Button(
                onClick = onGenerate,
                enabled = !state.generating,
                modifier = Modifier.fillMaxWidth().testTag(AdOptimizationTestTags.GENERATE),
            ) {
                if (state.generating) {
                    CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(18.dp))
                } else {
                    Text("Generate recommendations")
                }
            }
        }
        if (state.actionError != null) {
            item {
                Text(
                    state.actionError,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
        if (state.recommendations.isEmpty()) {
            item {
                EmptyState(
                    title = "No recommendations yet",
                    body = "Run a pass to generate optimization recommendations for this campaign.",
                )
            }
        } else {
            items(state.recommendations, key = { it.recommendationId }) { rec ->
                RecommendationCard(
                    rec = rec,
                    busy = rec.recommendationId in state.busyRecIds,
                    onApply = { onApply(rec.recommendationId) },
                    onDismiss = { onDismiss(rec.recommendationId) },
                )
            }
        }
    }
}

@Composable
private fun AutoOptimizeCard(
    state: AdOptimizationUiState.Content,
    onToggleAuto: (Boolean) -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text("Auto-optimize", style = MaterialTheme.typography.titleSmall)
                Text(
                    "Automatically pause underperformers and reallocate budget.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (state.togglingAuto) {
                CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(20.dp))
            } else {
                Switch(
                    checked = state.autoOptimizeEnabled,
                    onCheckedChange = onToggleAuto,
                    modifier = Modifier.testTag(AdOptimizationTestTags.AUTO_TOGGLE),
                )
            }
        }
    }
}

@Composable
private fun BidBudgetCard(state: AdOptimizationUiState.Content) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            val bid = state.suggestedBid
            if (bid != null) {
                Text("Suggested bid (CPM)", style = MaterialTheme.typography.titleSmall)
                Text(
                    "${formatCents(bid.suggestedBidCpmCents)}  (${formatCents(bid.minBidCpmCents)} – ${formatCents(bid.maxBidCpmCents)})",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text(
                    "Competition: ${bid.competitionLevel} · fill ${(bid.estimatedFillRate * 100).toInt()}%",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            val budget = state.budgetRecommendation
            if (budget != null) {
                Text("Recommended daily budget", style = MaterialTheme.typography.titleSmall)
                Text(
                    "${formatCents(budget.recommendedDailyBudgetCents)} for ~${budget.estimatedDailyReach} reach/day",
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
            if (bid == null && budget == null) {
                Text(
                    "Bid & budget guidance unavailable.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun RecommendationCard(
    rec: AdRecommendationDto,
    busy: Boolean,
    onApply: () -> Unit,
    onDismiss: () -> Unit,
) {
    val open = rec.status == "open"
    Card(
        modifier = Modifier.fillMaxWidth().testTag(AdOptimizationTestTags.row(rec.recommendationId)),
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    rec.title.ifBlank { rec.action },
                    style = MaterialTheme.typography.titleSmall,
                    modifier = Modifier.weight(1f),
                )
                Text(
                    rec.status,
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (rec.description.isNotBlank()) {
                Text(rec.description, style = MaterialTheme.typography.bodyMedium)
            }
            if (rec.impact.isNotBlank()) {
                Text(
                    "Impact: ${rec.impact}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (open) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = onApply,
                        enabled = !busy,
                        modifier = Modifier.testTag(AdOptimizationTestTags.apply(rec.recommendationId)),
                    ) {
                        if (busy) {
                            CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(16.dp))
                        } else {
                            Text("Apply")
                        }
                    }
                    OutlinedButton(
                        onClick = onDismiss,
                        enabled = !busy,
                        modifier = Modifier.testTag(AdOptimizationTestTags.dismiss(rec.recommendationId)),
                    ) {
                        Text("Dismiss")
                    }
                }
            }
        }
    }
}
