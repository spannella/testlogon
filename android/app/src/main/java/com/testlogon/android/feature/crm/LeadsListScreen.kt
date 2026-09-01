@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.crm

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner
import com.testlogon.android.data.crm.CrmSalesMath
import com.testlogon.android.data.crm.Lead

object CrmLeadsTestTags {
    const val SCREEN = "crm_leads_screen"
    const val CONTENT = "crm_leads_content"
    const val LOADING = "crm_leads_loading"
    const val ERROR = "crm_leads_error"
    const val FAB = "crm_leads_fab"
}

/** CRM-AND-1 — route-level leads list entry (reachable from the More hub). */
@Composable
fun LeadsListRoute(
    onLeadClick: (String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: LeadsListViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    LeadsListScreen(
        state = state,
        onLeadClick = onLeadClick,
        onBack = onBack,
        onRefresh = viewModel::onRefresh,
        onRetry = viewModel::onRetry,
        onCreateLead = viewModel::createLead,
        onClearCreateError = viewModel::clearCreateError,
        modifier = modifier,
    )
}

@Composable
fun LeadsListScreen(
    state: LeadsListUiState,
    onLeadClick: (String) -> Unit,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onCreateLead: (String, String, String, String?, String?, (String) -> Unit) -> Unit,
    onClearCreateError: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var showCreate by remember { mutableStateOf(false) }

    Scaffold(
        modifier = modifier.testTag(CrmLeadsTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Leads") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = { showCreate = true },
                modifier = Modifier.testTag(CrmLeadsTestTags.FAB),
            ) { Icon(Icons.Filled.Add, contentDescription = "New lead") }
        },
    ) { padding ->
        when (state.phase) {
            LeadsListUiState.Phase.Loading -> LoadingState(
                modifier = Modifier.padding(padding).testTag(CrmLeadsTestTags.LOADING),
            )
            LeadsListUiState.Phase.Error -> ErrorState(
                message = state.errorMessage ?: "Couldn't load leads.",
                onRetry = onRetry,
                modifier = Modifier.padding(padding).testTag(CrmLeadsTestTags.ERROR),
            )
            LeadsListUiState.Phase.Content -> PullToRefreshBox(
                isRefreshing = state.isRefreshing,
                onRefresh = onRefresh,
                modifier = Modifier.padding(padding).fillMaxSize(),
            ) {
                Column(modifier = Modifier.fillMaxSize()) {
                    if (state.isOffline) OfflineBanner(onRetry = onRetry)
                    if (state.moduleDisabled) {
                        InfoBanner("The Leads module is not enabled for this account.")
                    }
                    if (state.leads.isEmpty()) {
                        EmptyState(
                            title = if (state.moduleDisabled) "Leads unavailable" else "No leads yet",
                            body = if (state.moduleDisabled) null else "Tap + to add your first lead.",
                            modifier = Modifier.fillMaxSize(),
                        )
                    } else {
                        LazyColumn(
                            modifier = Modifier.fillMaxSize().testTag(CrmLeadsTestTags.CONTENT),
                            contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            items(state.leads, key = { it.leadId }) { lead ->
                                LeadRow(lead = lead, onClick = { onLeadClick(lead.leadId) })
                            }
                        }
                    }
                }
            }
        }
    }

    if (showCreate) {
        CreateLeadSheet(
            submitting = state.createSubmitting,
            error = state.createError,
            onDismiss = {
                showCreate = false
                onClearCreateError()
            },
            onSubmit = { first, last, email, company, source ->
                onCreateLead(first, last, email, company, source) { _ ->
                    showCreate = false
                }
            },
        )
    }
}

@Composable
private fun LeadRow(lead: Lead, onClick: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth().clickable(onClick = onClick)) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(lead.fullName, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                val subtitle = listOfNotNull(lead.company?.ifBlank { null }, lead.email.ifBlank { null })
                    .joinToString(" · ")
                if (subtitle.isNotBlank()) {
                    Text(
                        subtitle,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Text(
                    "Status: ${lead.status.replace('_', ' ')}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            ScoreBadge(lead.score)
        }
    }
}

@Composable
private fun ScoreBadge(score: Int) {
    val band = CrmSalesMath.scoreBand(score)
    val (bg, label) = when (band) {
        CrmSalesMath.LeadScoreBand.HOT -> Color(0xFFB3261E) to "Hot"
        CrmSalesMath.LeadScoreBand.WARM -> Color(0xFFF9A825) to "Warm"
        CrmSalesMath.LeadScoreBand.COLD -> Color(0xFF5C6BC0) to "Cold"
    }
    Surface(color = bg, contentColor = Color.White, shape = MaterialTheme.shapes.small) {
        Column(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(score.toString(), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Text(label, style = MaterialTheme.typography.labelSmall)
        }
    }
}

@Composable
internal fun InfoBanner(message: String) {
    Surface(
        color = MaterialTheme.colorScheme.secondaryContainer,
        contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text(message, modifier = Modifier.padding(16.dp), style = MaterialTheme.typography.bodyMedium)
    }
}
