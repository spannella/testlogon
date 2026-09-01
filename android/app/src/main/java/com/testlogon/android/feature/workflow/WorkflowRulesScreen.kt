@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.workflow

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle

/** WFL — stable testTags for the workflow-rules admin list screen. */
object WorkflowRulesTestTags {
    const val SCREEN = "workflow_rules_screen"
    const val RETRY = "workflow_rules_retry"

    fun row(ruleId: String): String = "workflow_rule_row_$ruleId"
}

@Composable
fun WorkflowRulesRoute(
    onBack: () -> Unit,
    viewModel: WorkflowRulesViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    WorkflowRulesScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::load,
    )
}

@Composable
fun WorkflowRulesScreen(
    state: WorkflowRulesUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
) {
    Scaffold(
        modifier = Modifier.testTag(WorkflowRulesTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Workflow rules") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Box(Modifier.padding(padding).fillMaxSize()) {
            when (state) {
                is WorkflowRulesUiState.Loading ->
                    CircularProgressIndicator(Modifier.align(Alignment.Center))

                is WorkflowRulesUiState.Unavailable ->
                    Text(
                        "Workflow automation isn't enabled for this account.",
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.align(Alignment.Center).padding(24.dp),
                    )

                is WorkflowRulesUiState.Empty ->
                    Text(
                        "No workflow rules configured.",
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.align(Alignment.Center).padding(24.dp),
                    )

                is WorkflowRulesUiState.Error -> Column(
                    modifier = Modifier.align(Alignment.Center),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(state.error.message, style = MaterialTheme.typography.bodyMedium)
                    Button(onClick = onRetry, modifier = Modifier.testTag(WorkflowRulesTestTags.RETRY)) {
                        Text("Retry")
                    }
                }

                is WorkflowRulesUiState.Content -> PullToRefreshBox(
                    isRefreshing = state.isRefreshing,
                    onRefresh = onRefresh,
                ) {
                    LazyColumn(
                        modifier = Modifier.fillMaxSize().padding(horizontal = 16.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        item(key = "header") {
                            Text(
                                text = "${state.rules.size} rules • ${state.enabledCount} enabled",
                                style = MaterialTheme.typography.titleSmall,
                                modifier = Modifier.padding(top = 12.dp, bottom = 4.dp),
                            )
                        }
                        items(state.rules, key = { it.ruleId }) { rule -> RuleRow(rule) }
                    }
                }
            }
        }
    }
}

@Composable
private fun RuleRow(rule: WorkflowRule) {
    Card(
        modifier = Modifier.fillMaxWidth().testTag(WorkflowRulesTestTags.row(rule.ruleId)),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(rule.name, style = MaterialTheme.typography.titleMedium)
            rule.description.takeIf { it.isNotBlank() }?.let {
                Text(it, style = MaterialTheme.typography.bodyMedium)
            }
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AssistChip(onClick = {}, label = { Text(if (rule.enabled) "Enabled" else "Disabled") })
                AssistChip(onClick = {}, label = { Text(moduleLabel(rule.targetModule)) })
                AssistChip(onClick = {}, label = { Text(triggerLabel(rule.triggerType)) })
            }
            Text(
                "${rule.conditionCount} conditions • ${rule.actionCount} actions",
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

private fun moduleLabel(m: WorkflowTargetModule): String = when (m) {
    WorkflowTargetModule.TICKET -> "Ticket"
    WorkflowTargetModule.CONTACT -> "Contact"
    WorkflowTargetModule.ORDER -> "Order"
    WorkflowTargetModule.SUBSCRIPTION -> "Subscription"
    WorkflowTargetModule.LEAD -> "Lead"
    WorkflowTargetModule.UNKNOWN -> "—"
}

private fun triggerLabel(t: WorkflowTriggerType): String = when (t) {
    WorkflowTriggerType.ON_SAVE -> "On save"
    WorkflowTriggerType.ON_SCHEDULE -> "On schedule"
    WorkflowTriggerType.ON_TIME_ELAPSED -> "On time elapsed"
    WorkflowTriggerType.UNKNOWN -> "—"
}
