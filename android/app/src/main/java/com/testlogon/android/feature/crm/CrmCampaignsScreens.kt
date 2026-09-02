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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Person
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
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
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner
import com.testlogon.android.data.crm.CrmCampaign
import com.testlogon.android.data.crm.CrmPecMath

object CrmCampaignsTestTags {
    const val SCREEN = "crm_campaigns_screen"
    const val CONTENT = "crm_campaigns_content"
    const val LOADING = "crm_campaigns_loading"
    const val ERROR = "crm_campaigns_error"
    const val DETAIL = "crm_campaign_detail"
}

// ─── List ─────────────────────────────────────────────────────────────────────

@Composable
fun CrmCampaignsRoute(
    onCampaignClick: (String) -> Unit,
    onNewCampaign: () -> Unit,
    onOpenTemplates: () -> Unit,
    onOpenLeads: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: CrmCampaignsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    CrmCampaignsScreen(
        state = state,
        onCampaignClick = onCampaignClick,
        onNewCampaign = onNewCampaign,
        onOpenTemplates = onOpenTemplates,
        onOpenLeads = onOpenLeads,
        onBack = onBack,
        onRefresh = viewModel::onRefresh,
        onRetry = viewModel::onRetry,
        modifier = modifier,
    )
}

@Composable
fun CrmCampaignsScreen(
    state: CrmCampaignsUiState,
    onCampaignClick: (String) -> Unit,
    onNewCampaign: () -> Unit,
    onOpenTemplates: () -> Unit,
    onOpenLeads: () -> Unit,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(CrmCampaignsTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Campaigns") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(onClick = onOpenLeads) {
                        Icon(Icons.Filled.Person, contentDescription = "Web leads")
                    }
                    IconButton(onClick = onOpenTemplates) {
                        Icon(Icons.Filled.Edit, contentDescription = "Email templates")
                    }
                },
            )
        },
        floatingActionButton = {
            if (state.phase == CrmCampaignsUiState.Phase.Content && !state.moduleDisabled) {
                FloatingActionButton(onClick = onNewCampaign) {
                    Icon(Icons.Filled.Add, contentDescription = "New campaign")
                }
            }
        },
    ) { padding ->
        when (state.phase) {
            CrmCampaignsUiState.Phase.Loading -> LoadingState(
                modifier = Modifier.padding(padding).testTag(CrmCampaignsTestTags.LOADING),
            )
            CrmCampaignsUiState.Phase.Error -> ErrorState(
                message = state.errorMessage ?: "Couldn't load campaigns.",
                onRetry = onRetry,
                modifier = Modifier.padding(padding).testTag(CrmCampaignsTestTags.ERROR),
            )
            CrmCampaignsUiState.Phase.Content -> PullToRefreshBox(
                isRefreshing = state.isRefreshing,
                onRefresh = onRefresh,
                modifier = Modifier.padding(padding).fillMaxSize(),
            ) {
                Column(modifier = Modifier.fillMaxSize()) {
                    if (state.isOffline) OfflineBanner(onRetry = onRetry)
                    if (state.moduleDisabled) InfoBanner("The Marketing module is not enabled for this account.")
                    if (state.campaigns.isEmpty()) {
                        EmptyState(
                            title = if (state.moduleDisabled) "Campaigns unavailable" else "No campaigns yet",
                            body = if (state.moduleDisabled) null else "Create campaigns from the web console.",
                            modifier = Modifier.fillMaxSize(),
                        )
                    } else {
                        LazyColumn(
                            modifier = Modifier.fillMaxSize().testTag(CrmCampaignsTestTags.CONTENT),
                            contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            items(state.campaigns, key = { it.campaignId }) { c ->
                                CampaignRow(c, onClick = { onCampaignClick(c.campaignId) })
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun CampaignRow(campaign: CrmCampaign, onClick: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth().clickable(onClick = onClick)) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(campaign.name.ifBlank { "(untitled)" }, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Text(
                    "${CrmPecMath.campaignTypeLabel(campaign.campaignType)} · ${CrmPecMath.formatCents(campaign.budgetCents)}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            AssistChip(onClick = onClick, label = { Text(CrmPecMath.campaignStatusLabel(campaign.status)) })
        }
    }
}

// ─── Detail (read-only) ─────────────────────────────────────────────────────

@Composable
fun CrmCampaignDetailRoute(
    onBack: () -> Unit,
    onEdit: (String) -> Unit,
    modifier: Modifier = Modifier,
    viewModel: CrmCampaignDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    CrmCampaignDetailScreen(state = state, onBack = onBack, onEdit = onEdit, onRetry = viewModel::onRetry, modifier = modifier)
}

@Composable
fun CrmCampaignDetailScreen(
    state: CrmCampaignDetailUiState,
    onBack: () -> Unit,
    onEdit: (String) -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(CrmCampaignsTestTags.DETAIL),
        topBar = {
            TopAppBar(
                title = { Text(state.campaign?.name?.ifBlank { "Campaign" } ?: "Campaign") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    val id = state.campaign?.campaignId
                    if (id != null) {
                        IconButton(onClick = { onEdit(id) }) {
                            Icon(Icons.Filled.Edit, contentDescription = "Edit campaign")
                        }
                    }
                },
            )
        },
    ) { padding ->
        when (state.phase) {
            CrmCampaignDetailUiState.Phase.Loading -> LoadingState(modifier = Modifier.padding(padding))
            CrmCampaignDetailUiState.Phase.Error -> ErrorState(
                message = state.errorMessage ?: "Couldn't load this campaign.",
                onRetry = onRetry,
                modifier = Modifier.padding(padding),
            )
            CrmCampaignDetailUiState.Phase.Content -> {
                val campaign = state.campaign
                Column(
                    modifier = Modifier.padding(padding).fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    if (state.isOffline) OfflineBanner(onRetry = onRetry)
                    if (campaign != null) {
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            AssistChip(onClick = {}, label = { Text(CrmPecMath.campaignStatusLabel(campaign.status)) })
                            AssistChip(onClick = {}, label = { Text(CrmPecMath.campaignTypeLabel(campaign.campaignType)) })
                        }
                        LabeledValue("Budget", CrmPecMath.formatCents(campaign.budgetCents))
                        if (!campaign.objective.isNullOrBlank()) LabeledValue("Objective", campaign.objective)
                        if (!campaign.trackingCode.isNullOrBlank()) LabeledValue("Tracking code", campaign.trackingCode)
                    }
                    val attr = state.attribution
                    if (attr != null) {
                        Text("Performance", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                        LabeledValue("Sent", attr.totalSent.toString())
                        LabeledValue("Opens", "${attr.openCount} (${CrmPecMath.formatRate(attr.openRate)})")
                        LabeledValue("Clicks", "${attr.clickCount} (${CrmPecMath.formatRate(attr.clickRate)})")
                    }
                    val ab = state.abResults
                    if (ab != null) {
                        HorizontalDivider()
                        AbResultsSection(ab)
                    }
                    if (attr == null && ab == null) {
                        Text(
                            "Tap the edit action to configure audience, send, preview, or run an A/B test.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }
    }
}
