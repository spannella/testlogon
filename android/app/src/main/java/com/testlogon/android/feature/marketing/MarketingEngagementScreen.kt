@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.marketing

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.marketing.EngagementSummary

object MarketingEngagementTestTags {
    const val SCREEN = "marketing_engagement_screen"
    const val CONTENT = "marketing_engagement_content"
    const val LOADING = "marketing_engagement_loading"
    const val ERROR = "marketing_engagement_error"
    const val OFFLINE = "marketing_engagement_offline"
    const val SESSION_EXPIRED = "marketing_engagement_session_expired"
    const val TOP_PREFIX = "marketing_engagement_top_"
}

@Composable
fun MarketingEngagementRoute(
    onBack: () -> Unit,
    onSessionExpired: () -> Unit,
    onOpenContent: (String) -> Unit,
    modifier: Modifier = Modifier,
    viewModel: MarketingEngagementViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    LaunchedEffect(state.phase) {
        if (state.phase == MarketingEngagementUiState.Phase.SessionExpired) onSessionExpired()
    }
    MarketingEngagementScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onOpenContent = onOpenContent,
        modifier = modifier,
    )
}

@Composable
fun MarketingEngagementScreen(
    state: MarketingEngagementUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onOpenContent: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(MarketingEngagementTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.marketing_engagement_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Box(modifier = Modifier.padding(padding).fillMaxSize()) {
            when (state.phase) {
                MarketingEngagementUiState.Phase.Loading ->
                    LoadingState(modifier = Modifier.testTag(MarketingEngagementTestTags.LOADING))
                MarketingEngagementUiState.Phase.Error ->
                    ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.marketing_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(MarketingEngagementTestTags.ERROR),
                    )
                MarketingEngagementUiState.Phase.Offline ->
                    ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.marketing_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(MarketingEngagementTestTags.OFFLINE),
                    )
                MarketingEngagementUiState.Phase.SessionExpired ->
                    EmptyState(
                        title = stringResource(R.string.marketing_session_expired_title),
                        body = stringResource(R.string.marketing_session_expired_body),
                        modifier = Modifier.testTag(MarketingEngagementTestTags.SESSION_EXPIRED),
                    )
                MarketingEngagementUiState.Phase.Content -> {
                    val summary = state.summary ?: return@Box
                    EngagementBody(summary = summary, onOpenContent = onOpenContent)
                }
            }
        }
    }
}

@Composable
private fun EngagementBody(summary: EngagementSummary, onOpenContent: (String) -> Unit) {
    Column(
        modifier = Modifier
            .testTag(MarketingEngagementTestTags.CONTENT)
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            SummaryCard(stringResource(R.string.marketing_summary_content), summary.totalContent.toString(), Modifier.weight(1f))
            SummaryCard(stringResource(R.string.marketing_summary_views), summary.totalViews.toString(), Modifier.weight(1f))
        }
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            SummaryCard(stringResource(R.string.marketing_summary_clicks), summary.totalClicks.toString(), Modifier.weight(1f))
            SummaryCard(stringResource(R.string.marketing_summary_conversion), String.format("%.1f%%", summary.conversionPercent), Modifier.weight(1f))
        }
        Card(modifier = Modifier.fillMaxWidth(), elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)) {
            Column(modifier = Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.marketing_top_performing), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                if (summary.topPerforming.isEmpty()) {
                    Text(
                        stringResource(R.string.marketing_engagement_empty),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                } else {
                    summary.topPerforming.forEachIndexed { index, p ->
                        if (index > 0) HorizontalDivider()
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag(MarketingEngagementTestTags.TOP_PREFIX + p.contentId)
                                .clickable { onOpenContent(p.contentId) }
                                .padding(vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(
                                text = p.title,
                                style = MaterialTheme.typography.bodyMedium,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                                modifier = Modifier.weight(1f),
                            )
                            Text(
                                text = stringResource(R.string.marketing_clicks_count, p.clicks),
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.SemiBold,
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun SummaryCard(label: String, value: String, modifier: Modifier = Modifier) {
    Card(modifier = modifier, elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)) {
        Column(modifier = Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(value, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        }
    }
}
