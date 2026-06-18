@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.ads.campaigns.ui

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
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.ads.AdCampaign
import com.testlogon.android.core.model.ads.AdCampaignStatusDomain
import com.testlogon.android.core.model.syndicates.formatCents
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.StaleBanner

/** AND-369 - stable testTags for the READ-ONLY ads-campaigns list. */
object AdsCampaignsTestTags {
    const val SCREEN = "ads_campaigns_screen"
    const val LIST = "ads_campaigns_list"
    const val EMPTY = "ads_campaigns_empty"
    const val ERROR_RETRY = "ads_campaigns_error_retry"

    /** Per-campaign row tag (suffix is the campaign id). */
    fun row(campaignId: String): String = "ads_campaign_row_$campaignId"
}

/**
 * AND-369 - route-level ads-campaigns entry (reached from the More hub / an ads-accounts list downstream).
 * The VM reads {accountId} from SavedStateHandle. READ-ONLY: a single list of the account's campaigns.
 */
@Composable
fun AdsCampaignsRoute(
    onBack: () -> Unit,
    viewModel: AdsCampaignsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    AdsCampaignsScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::onRetry,
    )
}

/** AND-369 - stateless ads-campaigns list. */
@Composable
fun AdsCampaignsScreen(
    state: AdsCampaignsUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(AdsCampaignsTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.ads_campaigns_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.ads_campaigns_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            when (state) {
                is AdsCampaignsUiState.Loading -> LoadingState()
                is AdsCampaignsUiState.Empty -> EmptyState(
                    title = stringResource(R.string.ads_campaigns_empty_title),
                    body = stringResource(R.string.ads_campaigns_empty_body),
                    modifier = Modifier.testTag(AdsCampaignsTestTags.EMPTY),
                )
                is AdsCampaignsUiState.Error -> ErrorState(
                    message = state.error.message,
                    onRetry = onRetry,
                    modifier = Modifier.testTag(AdsCampaignsTestTags.ERROR_RETRY),
                )
                is AdsCampaignsUiState.Content -> AdsCampaignsContent(
                    state = state,
                    onRefresh = onRefresh,
                    onRetry = onRetry,
                )
            }
        }
    }
}

@Composable
private fun AdsCampaignsContent(
    state: AdsCampaignsUiState.Content,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
) {
    PullToRefreshBox(
        isRefreshing = state.isRefreshing,
        onRefresh = onRefresh,
        modifier = Modifier.fillMaxSize(),
    ) {
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .testTag(AdsCampaignsTestTags.LIST),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item {
                StaleBanner(stale = state.isStale, refreshing = false, onRetry = onRetry)
            }
            items(state.campaigns, key = { it.campaignId }) { campaign ->
                CampaignRow(campaign = campaign)
            }
        }
    }
}

@Composable
private fun CampaignRow(campaign: AdCampaign) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(AdsCampaignsTestTags.row(campaign.campaignId)),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    text = campaign.name ?: stringResource(R.string.ads_campaigns_name_unknown),
                    style = MaterialTheme.typography.titleMedium,
                )
                Text(
                    text = campaign.statusLabel(),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            val budget = campaign.budgetCents ?: campaign.dailyBudgetCents
            if (budget != null) {
                Text(
                    text = stringResource(R.string.ads_campaigns_budget_label, formatCents(budget)),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }

            val spent = campaign.lifetimeSpentCents ?: campaign.spentTodayCents
            if (spent != null) {
                Text(
                    text = stringResource(R.string.ads_campaigns_spend_label, formatCents(spent)),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

/** The display status: the UNKNOWN-safe parsed enum when present, else the raw wire token. */
@Composable
private fun AdCampaign.statusLabel(): String = when (statusEnum) {
    AdCampaignStatusDomain.DRAFT -> stringResource(R.string.ads_campaigns_status_draft)
    AdCampaignStatusDomain.ACTIVE -> stringResource(R.string.ads_campaigns_status_active)
    AdCampaignStatusDomain.PAUSED -> stringResource(R.string.ads_campaigns_status_paused)
    AdCampaignStatusDomain.COMPLETED -> stringResource(R.string.ads_campaigns_status_completed)
    AdCampaignStatusDomain.ARCHIVED -> stringResource(R.string.ads_campaigns_status_archived)
    AdCampaignStatusDomain.UNKNOWN, null -> status
}
