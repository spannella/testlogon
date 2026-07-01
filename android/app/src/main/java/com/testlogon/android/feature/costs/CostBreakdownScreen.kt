@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.costs

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.data.costs.TicketCost
import com.testlogon.android.data.costs.WorkerCost
import com.testlogon.android.data.costs.formatCents

@Composable
fun CostBreakdownRoute(
    onBack: () -> Unit,
    onSessionExpired: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: CostBreakdownViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    androidx.compose.runtime.LaunchedEffect(state.phase) {
        if (state.phase == CostsPhase.SessionExpired) onSessionExpired()
    }
    var tab by remember { mutableIntStateOf(0) }

    Scaffold(
        modifier = modifier.testTag(CostsTestTags.BREAKDOWN_SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.costs_breakdown_title)) },
                navigationIcon = { CostsBackIcon(onBack, "costs_breakdown_back") },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.padding(padding).fillMaxSize()) {
            Text(
                text = stringResource(R.string.costs_date_label, state.date),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            )
            TabRow(selectedTabIndex = tab) {
                val titles = listOf(
                    R.string.costs_tab_agent_type,
                    R.string.costs_tab_worker,
                    R.string.costs_tab_ticket,
                )
                titles.forEachIndexed { i, res ->
                    Tab(
                        selected = tab == i,
                        onClick = { tab = i },
                        text = { Text(stringResource(res)) },
                        modifier = Modifier.testTag("breakdown_tab_$i"),
                    )
                }
            }
            CostsPhaseScaffold(state.phase, state.errorMessage, viewModel::onRetry) {
                PullToRefreshBox(
                    isRefreshing = state.isRefreshing,
                    onRefresh = viewModel::onRefresh,
                    modifier = Modifier.fillMaxSize(),
                ) {
                    val byType = state.summary?.byAgentType.orEmpty()
                    val workers = state.summary?.byWorker.orEmpty()
                    val tickets = state.tickets
                    when (tab) {
                        0 -> AgentTypeList(byType)
                        1 -> WorkerList(workers)
                        else -> TicketList(tickets)
                    }
                }
            }
        }
    }
}

@Composable
private fun AgentTypeList(byType: List<Pair<String, Long>>) {
    if (byType.isEmpty()) {
        EmptyState(title = stringResource(R.string.costs_no_spend_date), modifier = Modifier.testTag(CostsTestTags.EMPTY))
        return
    }
    LazyColumn(contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        items(byType, key = { it.first }) { (type, cents) ->
            Card(Modifier.fillMaxWidth()) {
                Row(Modifier.fillMaxWidth().padding(16.dp), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(type, style = MaterialTheme.typography.bodyMedium)
                    Text(formatCents(cents), style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
                }
            }
        }
    }
}

@Composable
private fun WorkerList(workers: List<WorkerCost>) {
    if (workers.isEmpty()) {
        EmptyState(title = stringResource(R.string.costs_no_worker_entries), modifier = Modifier.testTag(CostsTestTags.EMPTY))
        return
    }
    LazyColumn(contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        items(workers, key = { "${it.workerId}-${it.date}" }) { w ->
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(w.workerId, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                    Text(w.agentType, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text(stringResource(R.string.costs_llm_label, formatCents(w.llmCents)), style = MaterialTheme.typography.bodySmall)
                        Text(stringResource(R.string.costs_compute_label, formatCents(w.computeCents)), style = MaterialTheme.typography.bodySmall)
                        Text(formatCents(w.totalCents), style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Medium)
                    }
                }
            }
        }
    }
}

@Composable
private fun TicketList(tickets: List<TicketCost>) {
    if (tickets.isEmpty()) {
        EmptyState(title = stringResource(R.string.costs_no_ticket_data), modifier = Modifier.testTag(CostsTestTags.EMPTY))
        return
    }
    LazyColumn(contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        items(tickets, key = { it.ticketId }) { t ->
            Card(Modifier.fillMaxWidth().testTag(CostsTestTags.TICKET_ROW_PREFIX + t.ticketId)) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text(t.ticketId, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                        Text(formatCents(t.totalCents), style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
                    }
                    Text(
                        "${t.agentType} · ${t.status}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}
