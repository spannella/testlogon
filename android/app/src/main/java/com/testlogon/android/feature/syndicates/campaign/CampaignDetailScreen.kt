@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.syndicates.campaign

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Badge
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.text.KeyboardOptions
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.syndicates.formatCents
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner

/** Stable testTags for the campaign-detail screen. */
object CampaignDetailTestTags {
    const val SCREEN = "campaign_detail_screen"
    const val PAUSE = "campaign_pause"
    const val RESUME = "campaign_resume"
    const val CANCEL = "campaign_cancel"
    const val ADD_BUDGET_FIELD = "campaign_add_budget_field"
    const val ADD_BUDGET_SUBMIT = "campaign_add_budget_submit"
}

/** Route-level entry for the campaign-detail screen. */
@Composable
fun CampaignDetailRoute(
    onBack: () -> Unit,
    viewModel: CampaignDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    CampaignDetailScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::retry,
        onPause = viewModel::pause,
        onResume = viewModel::resume,
        onCancel = viewModel::cancel,
        onAddBudget = viewModel::addBudget,
    )
}

@Composable
fun CampaignDetailScreen(
    state: CampaignDetailUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onPause: () -> Unit,
    onResume: () -> Unit,
    onCancel: () -> Unit,
    onAddBudget: (Int) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(CampaignDetailTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.campaign_detail_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.campaign_back))
                    }
                },
            )
        },
    ) { padding ->
        Box(Modifier.padding(padding)) {
            when (state) {
                is CampaignDetailUiState.Loading -> LoadingState()
                is CampaignDetailUiState.Error -> ErrorState(message = state.message, onRetry = onRetry)
                is CampaignDetailUiState.Content -> ContentBody(
                    state = state,
                    onRetry = onRetry,
                    onPause = onPause,
                    onResume = onResume,
                    onCancel = onCancel,
                    onAddBudget = onAddBudget,
                )
            }
        }
    }
}

@Composable
private fun ContentBody(
    state: CampaignDetailUiState.Content,
    onRetry: () -> Unit,
    onPause: () -> Unit,
    onResume: () -> Unit,
    onCancel: () -> Unit,
    onAddBudget: (Int) -> Unit,
) {
    val campaign = state.campaign
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        if (state.isStale) OfflineBanner(onRetry = onRetry)

        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                text = campaign.name.ifBlank { campaign.campaignId },
                style = MaterialTheme.typography.headlineSmall,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f),
            )
            Badge { Text(campaign.status) }
        }
        if (campaign.description.isNotBlank()) {
            Text(campaign.description, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }

        // ---- KPI stat cards ----
        val a = state.analytics
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
            StatCard(label = stringResource(R.string.campaign_stat_impressions), value = (a?.impressions ?: 0).toString(), modifier = Modifier.weight(1f))
            StatCard(label = stringResource(R.string.campaign_stat_clicks), value = (a?.clicks ?: 0).toString(), modifier = Modifier.weight(1f))
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
            StatCard(label = stringResource(R.string.campaign_stat_ctr), value = "${a?.ctr ?: 0.0}%", modifier = Modifier.weight(1f))
            StatCard(label = stringResource(R.string.campaign_stat_spend), value = formatCents((a?.spendCents ?: 0).toLong()), modifier = Modifier.weight(1f))
        }

        // ---- Daily analytics ----
        SectionCard(title = stringResource(R.string.campaign_section_daily)) {
            if (a == null || a.daily.isEmpty()) {
                Text(stringResource(R.string.campaign_no_analytics), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            } else {
                a.daily.forEach { d ->
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Text(d.date, style = MaterialTheme.typography.bodyMedium)
                        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                            Text(stringResource(R.string.campaign_daily_impr, d.impressions), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            Text(stringResource(R.string.campaign_daily_clicks, d.clicks), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            Text(formatCents(d.spendCents.toLong()), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                }
            }
        }

        // ---- Creative ----
        SectionCard(title = stringResource(R.string.campaign_section_creative)) {
            Text(campaign.creativeHeadline.orEmpty(), style = MaterialTheme.typography.titleSmall)
            if (!campaign.creativeBody.isNullOrBlank()) {
                Text(campaign.creativeBody, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            if (!campaign.creativeCtaText.isNullOrBlank() || !campaign.creativeCtaUrl.isNullOrBlank()) {
                Text(
                    text = stringResource(R.string.campaign_cta, campaign.creativeCtaText.orEmpty(), campaign.creativeCtaUrl.orEmpty()),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }

        // ---- Budget + controls ----
        SectionCard(title = stringResource(R.string.campaign_section_budget)) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(
                    text = stringResource(
                        R.string.campaign_budget_spent_of,
                        formatCents(campaign.spentCents.toLong()),
                        formatCents(campaign.budgetCents.toLong()),
                    ),
                    style = MaterialTheme.typography.bodySmall,
                )
                Text(
                    text = stringResource(R.string.campaign_budget_remaining, formatCents(campaign.remainingCents.toLong())),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            LinearProgressIndicator(
                progress = { campaign.spendFraction },
                modifier = Modifier.fillMaxWidth().height(8.dp).padding(top = 4.dp),
            )

            if (state.actionError != null) {
                Text(state.actionError, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            }

            if (state.isAdmin && campaign.isMutable) {
                AddBudgetRow(enabled = !state.mutating, onAddBudget = onAddBudget)
            }
            if (state.isAdmin && (campaign.isActive || campaign.isPaused)) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (campaign.isActive) {
                        OutlinedButton(onClick = onPause, enabled = !state.mutating, modifier = Modifier.testTag(CampaignDetailTestTags.PAUSE)) {
                            Text(stringResource(R.string.campaign_pause))
                        }
                    }
                    if (campaign.isPaused) {
                        OutlinedButton(onClick = onResume, enabled = !state.mutating, modifier = Modifier.testTag(CampaignDetailTestTags.RESUME)) {
                            Text(stringResource(R.string.campaign_resume))
                        }
                    }
                    OutlinedButton(onClick = onCancel, enabled = !state.mutating, modifier = Modifier.testTag(CampaignDetailTestTags.CANCEL)) {
                        Text(stringResource(R.string.campaign_cancel), color = MaterialTheme.colorScheme.error)
                    }
                }
            }
            if (state.mutating) {
                CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(20.dp))
            }
        }
    }
}

@Composable
private fun AddBudgetRow(enabled: Boolean, onAddBudget: (Int) -> Unit) {
    var amount by remember { mutableStateOf("") }
    val dollars = amount.toDoubleOrNull()
    val valid = dollars != null && dollars >= 1.0
    Row(verticalAlignment = Alignment.Bottom, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedTextField(
            value = amount,
            onValueChange = { amount = it },
            singleLine = true,
            label = { Text(stringResource(R.string.campaign_add_budget_label)) },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
            modifier = Modifier.weight(1f).testTag(CampaignDetailTestTags.ADD_BUDGET_FIELD),
        )
        Button(
            onClick = {
                val cents = ((dollars ?: 0.0) * 100).toInt()
                onAddBudget(cents)
                amount = ""
            },
            enabled = enabled && valid,
            modifier = Modifier.testTag(CampaignDetailTestTags.ADD_BUDGET_SUBMIT),
        ) {
            Text(stringResource(R.string.campaign_add_budget))
        }
    }
}

@Composable
private fun StatCard(label: String, value: String, modifier: Modifier = Modifier) {
    Card(modifier = modifier) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(value, style = MaterialTheme.typography.titleLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
    }
}

@Composable
private fun SectionCard(title: String, content: @Composable () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            content()
        }
    }
}
