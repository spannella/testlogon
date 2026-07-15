@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.ads.campaigns.detail

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.model.ads.AdCampaign
import com.testlogon.android.core.model.ads.AdCampaignStatusDomain
import com.testlogon.android.core.model.syndicates.formatCents
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** ADV3-4 (B2) - stable testTags for the campaign management (detail) screen. */
object AdCampaignDetailTestTags {
    const val SCREEN = "ad_campaign_detail_screen"
    const val PAUSE = "ad_campaign_detail_pause"
    const val RESUME = "ad_campaign_detail_resume"
    const val ARCHIVE = "ad_campaign_detail_archive"
    const val EDIT_BUDGET = "ad_campaign_detail_edit_budget"
    const val EDIT_BID = "ad_campaign_detail_edit_bid"
    const val ADD_FUNDS = "ad_campaign_detail_add_funds"
}

/**
 * ADV3-4 (B2) - route-level campaign MANAGEMENT entry. Reached from the campaigns list (a row tap). The VM
 * reads accountId + campaignId from SavedStateHandle. [onAddFunds] routes to the account's billing screen.
 */
@Composable
fun AdCampaignDetailRoute(
    onBack: () -> Unit,
    onAddFunds: (accountId: String) -> Unit,
    viewModel: AdCampaignDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    AdCampaignDetailScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onPause = viewModel::pause,
        onResume = viewModel::resume,
        onArchive = viewModel::archive,
        onEditBudget = viewModel::editBudget,
        onEditBid = viewModel::editBid,
        onAddFunds = { onAddFunds(viewModel.accountId) },
    )
}

@Composable
fun AdCampaignDetailScreen(
    state: AdCampaignDetailUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onPause: () -> Unit,
    onResume: () -> Unit,
    onArchive: () -> Unit,
    onEditBudget: (String) -> Unit,
    onEditBid: (String) -> Unit,
    onAddFunds: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(AdCampaignDetailTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Manage campaign") },
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
                is AdCampaignDetailUiState.Loading -> LoadingState()
                is AdCampaignDetailUiState.Error -> ErrorState(message = state.error.message, onRetry = onRetry)
                is AdCampaignDetailUiState.Content -> DetailContent(
                    content = state,
                    onPause = onPause,
                    onResume = onResume,
                    onArchive = onArchive,
                    onEditBudget = onEditBudget,
                    onEditBid = onEditBid,
                    onAddFunds = onAddFunds,
                )
            }
        }
    }
}

@Composable
private fun DetailContent(
    content: AdCampaignDetailUiState.Content,
    onPause: () -> Unit,
    onResume: () -> Unit,
    onArchive: () -> Unit,
    onEditBudget: (String) -> Unit,
    onEditBid: (String) -> Unit,
    onAddFunds: () -> Unit,
) {
    val campaign = content.campaign
    val busy = content.action is ActionState.Submitting
    var editBudget by remember { mutableStateOf(false) }
    var editBid by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Text(campaign.name ?: campaign.campaignId, style = MaterialTheme.typography.titleLarge)
                Text("Status: " + humanStatus(campaign), style = MaterialTheme.typography.bodyMedium)
                val budget = campaign.budgetCents ?: campaign.dailyBudgetCents
                if (budget != null) Text("Budget: " + formatCents(budget), style = MaterialTheme.typography.bodyMedium)
                val spent = campaign.lifetimeSpentCents ?: campaign.spentTodayCents
                if (spent != null) Text("Spent: " + formatCents(spent), style = MaterialTheme.typography.bodyMedium)
            }
        }

        (content.action as? ActionState.Error)?.let {
            Text(it.message, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
        }
        if (busy) CircularProgressIndicator()

        val status = campaign.statusEnum
        if (AdCampaignDetailViewModel.canPause(status)) {
            Button(
                onClick = onPause,
                enabled = !busy,
                modifier = Modifier.fillMaxWidth().testTag(AdCampaignDetailTestTags.PAUSE),
            ) { Text("Pause campaign") }
        }
        if (AdCampaignDetailViewModel.canResume(status)) {
            Button(
                onClick = onResume,
                enabled = !busy,
                modifier = Modifier.fillMaxWidth().testTag(AdCampaignDetailTestTags.RESUME),
            ) { Text("Resume campaign") }
        }

        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            OutlinedButton(
                onClick = { editBudget = true },
                enabled = !busy,
                modifier = Modifier.weight(1f).testTag(AdCampaignDetailTestTags.EDIT_BUDGET),
            ) { Text("Edit budget") }
            OutlinedButton(
                onClick = { editBid = true },
                enabled = !busy,
                modifier = Modifier.weight(1f).testTag(AdCampaignDetailTestTags.EDIT_BID),
            ) { Text("Edit bid") }
        }

        OutlinedButton(
            onClick = onAddFunds,
            modifier = Modifier.fillMaxWidth().testTag(AdCampaignDetailTestTags.ADD_FUNDS),
        ) { Text("Add funds to this account") }

        if (AdCampaignDetailViewModel.canArchive(status)) {
            TextButton(
                onClick = onArchive,
                enabled = !busy,
                modifier = Modifier.fillMaxWidth().testTag(AdCampaignDetailTestTags.ARCHIVE),
            ) { Text("Archive campaign") }
        }
    }

    if (editBudget) {
        AmountDialog(
            title = "Edit daily/lifetime budget",
            label = "New budget (USD)",
            onConfirm = { onEditBudget(it); editBudget = false },
            onDismiss = { editBudget = false },
        )
    }
    if (editBid) {
        AmountDialog(
            title = "Edit CPM bid",
            label = "New CPM bid (USD)",
            onConfirm = { onEditBid(it); editBid = false },
            onDismiss = { editBid = false },
        )
    }
}

@Composable
private fun AmountDialog(
    title: String,
    label: String,
    onConfirm: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    var text by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            OutlinedTextField(
                value = text,
                onValueChange = { text = it },
                label = { Text(label) },
                prefix = { Text("$") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
            )
        },
        confirmButton = { TextButton(onClick = { onConfirm(text) }, enabled = text.isNotBlank()) { Text("Save") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

/** ADV3-4 (B10) - a humanized, advertiser-facing status line. */
private fun humanStatus(c: AdCampaign): String = when (c.statusEnum) {
    AdCampaignStatusDomain.DRAFT -> "Draft - not yet submitted for review"
    AdCampaignStatusDomain.ACTIVE -> "Active - serving"
    AdCampaignStatusDomain.PAUSED -> "Paused - not serving"
    AdCampaignStatusDomain.COMPLETED -> "Completed"
    AdCampaignStatusDomain.ARCHIVED -> "Archived"
    AdCampaignStatusDomain.UNKNOWN, null -> when (c.status) {
        "pending_review" -> "In review - an admin is approving this campaign"
        "rejected" -> "Rejected - edit and resubmit"
        else -> c.status
    }
}
