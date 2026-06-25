@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.support.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.feature.support.data.SupportAdminSummary

/**
 * B-SUP (batch 7) - ADMIN helpdesk/moderation queue. Shows the full incoming-ticket queue + summary counts +
 * a client-side status filter; tapping a ticket opens the shared detail (with admin status/assign controls).
 * A non-admin reaching this surface gets a 403 -> the Forbidden state (defence in depth).
 */
@Composable
fun SupportAdminScreen(
    onBack: () -> Unit,
    onOpenTicket: (String) -> Unit,
    viewModel: SupportAdminViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    Scaffold(
        modifier = Modifier.testTag(SupportTestTags.ADMIN_SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Helpdesk queue") },
                navigationIcon = { BackButton(onBack) },
                actions = {
                    IconButton(onClick = viewModel::refresh) {
                        Icon(Icons.Outlined.Refresh, contentDescription = "Refresh")
                    }
                },
            )
        },
    ) { p ->
        PullToRefreshBox(
            isRefreshing = state.loading,
            onRefresh = viewModel::refresh,
            modifier = Modifier.fillMaxSize().padding(p),
        ) {
            when {
                state.forbidden ->
                    CenteredText(
                        "This is the support team queue. Your account doesn't have helpdesk access.",
                        SupportTestTags.ADMIN_FORBIDDEN,
                    )
                state.loading && state.tickets.isEmpty() ->
                    Box(Modifier.fillMaxSize(), Alignment.Center) { CircularProgressIndicator() }
                state.error != null && state.tickets.isEmpty() ->
                    CenteredText(state.error!!, "support_admin_error")
                else ->
                    LazyColumn(
                        Modifier.fillMaxSize(),
                        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        state.summary?.let { item { SummaryCard(it) } }
                        item {
                            Spacer(Modifier.height(4.dp))
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                FilterChip(
                                    selected = state.statusFilter == null,
                                    onClick = { viewModel.setStatusFilter(null) },
                                    label = { Text("All") },
                                )
                                viewModel.statusFilters.forEach { f ->
                                    FilterChip(
                                        selected = state.statusFilter == f,
                                        onClick = { viewModel.setStatusFilter(f) },
                                        label = { Text(statusLabelFromWire(f)) },
                                    )
                                }
                            }
                            Spacer(Modifier.height(4.dp))
                        }
                        val visible = state.visibleTickets
                        if (visible.isEmpty()) {
                            item {
                                Text(
                                    "No tickets in this view.",
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.testTag(SupportTestTags.EMPTY).padding(vertical = 8.dp),
                                )
                            }
                        } else {
                            items(visible, key = { it.ticketId }) { t ->
                                TicketRow(t, showOwner = true, onClick = { onOpenTicket(t.ticketId) })
                            }
                        }
                    }
            }
        }
    }
}

@Composable
private fun SummaryCard(summary: SupportAdminSummary) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Text("Queue overview", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(8.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Metric("Total", summary.totalCount)
                Metric("Unassigned", summary.unassignedCount)
                Metric("Stale", summary.staleCount)
                Metric("Open", summary.byStatus["open"] ?: 0)
            }
        }
    }
}

@Composable
private fun Metric(label: String, value: Int) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(value.toString(), style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
