@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.groups

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
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.groups.GroupCampaign
import com.testlogon.android.core.model.groups.GroupCampaignStats
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** AND-355 (sub-pages) - stable testTags for the group ads screen. */
object GroupAdsTestTags {
    const val SCREEN = "group_ads_screen"
    const val CREATE = "group_ads_create"
    const val ROW_PREFIX = "group_ads_row_"
}

@Composable
fun GroupAdsRoute(
    onBack: () -> Unit,
    viewModel: GroupAdsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    GroupAdsScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onCreate = viewModel::create,
        onNoticeShown = viewModel::consumeNotice,
    )
}

@Composable
fun GroupAdsScreen(
    state: GroupAdsUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onCreate: (name: String, dailyBudgetCents: Long, lifetimeBudgetCents: Long, creativeText: String) -> Unit,
    onNoticeShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbarHostState = remember { SnackbarHostState() }
    (state as? GroupAdsUiState.Content)?.notice?.let { notice ->
        LaunchedEffect(notice) {
            snackbarHostState.showSnackbar(notice)
            onNoticeShown()
        }
    }
    Scaffold(
        modifier = modifier.testTag(GroupAdsTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.group_ads_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.groups_back),
                        )
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        when (state) {
            is GroupAdsUiState.Loading ->
                LoadingState(modifier = Modifier.padding(padding))

            is GroupAdsUiState.Error ->
                ErrorState(
                    message = state.error.message,
                    onRetry = onRetry,
                    modifier = Modifier.padding(padding),
                )

            is GroupAdsUiState.Content ->
                GroupAdsContent(state = state, onCreate = onCreate, modifier = Modifier.padding(padding))
        }
    }
}

@Composable
private fun GroupAdsContent(
    state: GroupAdsUiState.Content,
    onCreate: (name: String, dailyBudgetCents: Long, lifetimeBudgetCents: Long, creativeText: String) -> Unit,
    modifier: Modifier = Modifier,
) {
    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item { CreateCampaignCard(enabled = !state.isCreating, onCreate = onCreate) }

        item {
            Text(
                text = stringResource(R.string.group_ads_list_section),
                style = MaterialTheme.typography.titleMedium,
            )
        }
        if (state.campaigns.isEmpty()) {
            item {
                Text(
                    text = stringResource(R.string.group_ads_empty),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        } else {
            items(state.campaigns, key = { it.campaignId }) { c ->
                CampaignCard(c, state.stats[c.campaignId])
            }
        }
    }
}

@Composable
private fun CreateCampaignCard(
    enabled: Boolean,
    onCreate: (name: String, dailyBudgetCents: Long, lifetimeBudgetCents: Long, creativeText: String) -> Unit,
) {
    var name by remember { mutableStateOf("") }
    var daily by remember { mutableStateOf("") }
    var lifetime by remember { mutableStateOf("") }
    var creative by remember { mutableStateOf("") }
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = stringResource(R.string.group_ads_create_section),
                style = MaterialTheme.typography.titleSmall,
            )
            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = { Text(stringResource(R.string.group_ads_name_label)) },
                singleLine = true,
                enabled = enabled,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = daily,
                onValueChange = { v -> daily = v.filter { it.isDigit() } },
                label = { Text(stringResource(R.string.group_ads_daily_budget_label)) },
                singleLine = true,
                enabled = enabled,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = lifetime,
                onValueChange = { v -> lifetime = v.filter { it.isDigit() } },
                label = { Text(stringResource(R.string.group_ads_lifetime_budget_label)) },
                singleLine = true,
                enabled = enabled,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = creative,
                onValueChange = { creative = it },
                label = { Text(stringResource(R.string.group_ads_creative_label)) },
                enabled = enabled,
                modifier = Modifier.fillMaxWidth(),
            )
            Button(
                onClick = {
                    val d = (daily.toLongOrNull() ?: 0L) * 100
                    val l = (lifetime.toLongOrNull() ?: 0L) * 100
                    onCreate(name.trim(), d, l, creative.trim())
                    name = ""
                    daily = ""
                    lifetime = ""
                    creative = ""
                },
                enabled = enabled && name.isNotBlank(),
                modifier = Modifier.testTag(GroupAdsTestTags.CREATE),
            ) {
                if (!enabled) {
                    CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(20.dp))
                } else {
                    Text(stringResource(R.string.group_ads_create_action))
                }
            }
        }
    }
}

@Composable
private fun CampaignCard(c: GroupCampaign, stats: GroupCampaignStats?) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(GroupAdsTestTags.ROW_PREFIX + c.campaignId),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = c.name,
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.weight(1f),
                )
                Text(text = c.status, style = MaterialTheme.typography.labelMedium)
            }
            if (!c.creativeText.isNullOrBlank()) {
                Text(
                    text = c.creativeText!!,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Text(
                text = stringResource(
                    R.string.group_ads_budget,
                    formatMoney(c.dailyBudgetCents, null),
                    formatMoney(c.lifetimeBudgetCents, null),
                ),
                style = MaterialTheme.typography.bodySmall,
            )
            val impressions = stats?.impressions ?: c.impressions
            val clicks = stats?.clicks ?: c.clicks
            val spent = stats?.spentCents ?: c.spentCents
            Text(
                text = stringResource(
                    R.string.group_ads_stats,
                    impressions,
                    clicks,
                    formatMoney(spent, null),
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
