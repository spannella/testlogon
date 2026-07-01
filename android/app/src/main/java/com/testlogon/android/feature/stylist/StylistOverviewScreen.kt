@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.stylist

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.material.icons.outlined.Palette
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material.icons.outlined.Rule
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
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
import com.testlogon.android.core.ui.state.OfflineBanner
import com.testlogon.android.data.stylist.OverallScore
import com.testlogon.android.data.stylist.PageScore

object StylistOverviewTestTags {
    const val SCREEN = "stylist_overview_screen"
    const val LIST = "stylist_overview_list"
    const val LOADING = "stylist_overview_loading"
    const val EMPTY = "stylist_overview_empty"
    const val ERROR = "stylist_overview_error"
    const val OFFLINE = "stylist_overview_offline"
    const val SESSION_EXPIRED = "stylist_overview_session_expired"
    const val RUN_REVIEW = "stylist_run_review"
    const val RULES = "stylist_open_rules"
    const val PAGE_ROW_PREFIX = "stylist_page_"
}

@Composable
fun StylistOverviewRoute(
    onBack: () -> Unit,
    onSessionExpired: () -> Unit,
    onOpenRules: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: StylistOverviewViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is StylistEffect.ShowMessage ->
                    snackbarHostState.showSnackbar(context.getString(effect.resId))
            }
        }
    }
    LaunchedEffect(state.phase) {
        if (state.phase == StylistOverviewUiState.Phase.SessionExpired) onSessionExpired()
    }

    StylistOverviewScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::onRefresh,
        onRetry = viewModel::onRetry,
        onRunReview = viewModel::onRunReview,
        onOpenRules = onOpenRules,
        snackbarHostState = snackbarHostState,
        modifier = modifier,
    )
}

@Composable
fun StylistOverviewScreen(
    state: StylistOverviewUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onRunReview: () -> Unit,
    onOpenRules: () -> Unit,
    modifier: Modifier = Modifier,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    Scaffold(
        modifier = modifier.testTag(StylistOverviewTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.stylist_overview_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
                actions = {
                    IconButton(onClick = onOpenRules, modifier = Modifier.testTag(StylistOverviewTestTags.RULES)) {
                        Icon(Icons.Outlined.Rule, contentDescription = stringResource(R.string.stylist_rules_title))
                    }
                    IconButton(
                        onClick = onRunReview,
                        enabled = !state.isTriggering,
                        modifier = Modifier.testTag(StylistOverviewTestTags.RUN_REVIEW),
                    ) {
                        if (state.isTriggering) {
                            CircularProgressIndicator(modifier = Modifier.padding(4.dp))
                        } else {
                            Icon(Icons.Outlined.Refresh, contentDescription = stringResource(R.string.stylist_run_review))
                        }
                    }
                },
            )
        },
    ) { padding ->
        Box(modifier = Modifier.padding(padding).fillMaxSize()) {
            when (state.phase) {
                StylistOverviewUiState.Phase.Loading ->
                    LoadingState(modifier = Modifier.testTag(StylistOverviewTestTags.LOADING))
                StylistOverviewUiState.Phase.Error ->
                    ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.stylist_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(StylistOverviewTestTags.ERROR),
                    )
                StylistOverviewUiState.Phase.Offline ->
                    ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.stylist_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(StylistOverviewTestTags.OFFLINE),
                    )
                StylistOverviewUiState.Phase.SessionExpired ->
                    EmptyState(
                        title = stringResource(R.string.stylist_session_expired_title),
                        body = stringResource(R.string.stylist_session_expired_body),
                        modifier = Modifier.testTag(StylistOverviewTestTags.SESSION_EXPIRED),
                    )
                StylistOverviewUiState.Phase.Empty ->
                    PullToRefreshBox(isRefreshing = state.isRefreshing, onRefresh = onRefresh, modifier = Modifier.fillMaxSize()) {
                        LazyColumn(
                            modifier = Modifier.testTag(StylistOverviewTestTags.EMPTY).fillMaxSize(),
                            contentPadding = PaddingValues(16.dp),
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            state.overview?.let { item { OverallCard(it.overall) } }
                            item {
                                EmptyState(
                                    title = stringResource(R.string.stylist_empty_title),
                                    body = stringResource(R.string.stylist_empty_body),
                                    imageVector = Icons.Outlined.Palette,
                                    actionLabel = stringResource(R.string.stylist_run_review),
                                    onAction = onRunReview,
                                )
                            }
                        }
                    }
                StylistOverviewUiState.Phase.Content -> {
                    val pages = state.overview?.pages.orEmpty()
                    PullToRefreshBox(isRefreshing = state.isRefreshing, onRefresh = onRefresh, modifier = Modifier.fillMaxSize()) {
                        LazyColumn(
                            modifier = Modifier.testTag(StylistOverviewTestTags.LIST).fillMaxSize(),
                            contentPadding = PaddingValues(16.dp),
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            if (state.isStale) item { OfflineBanner(onRetry = onRetry) }
                            state.overview?.let { item { OverallCard(it.overall) } }
                            item {
                                Text(
                                    text = stringResource(R.string.stylist_pages_heading),
                                    style = MaterialTheme.typography.titleMedium,
                                    fontWeight = FontWeight.SemiBold,
                                )
                            }
                            items(pages, key = { it.pageUrl }) { page -> PageScoreCard(page) }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun OverallCard(overall: OverallScore) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Row(horizontalArrangement = Arrangement.spacedBy(24.dp), modifier = Modifier.fillMaxWidth()) {
                Gauge(stringResource(R.string.stylist_gauge_design), overall.designScore, Modifier.weight(1f))
                Gauge(stringResource(R.string.stylist_gauge_a11y), overall.accessibilityScore, Modifier.weight(1f))
            }
            Text(
                text = stringResource(R.string.stylist_pages_summary, overall.pagesReviewed, overall.totalIssues),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun Gauge(label: String, value: Double, modifier: Modifier = Modifier) {
    Column(modifier = modifier, verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(
            text = String.format("%.1f", value),
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.Bold,
            color = scoreColor(value),
        )
        LinearProgressIndicator(
            progress = { (value / 100.0).coerceIn(0.0, 1.0).toFloat() },
            modifier = Modifier.fillMaxWidth(),
        )
    }
}

@Composable
private fun PageScoreCard(page: PageScore) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(StylistOverviewTestTags.PAGE_ROW_PREFIX + page.pageUrl)
            .clickable { },
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = page.pageName.ifBlank { page.pageUrl },
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                Text(
                    text = String.format("%.1f", page.designScore),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = scoreColor(page.designScore),
                )
            }
            LinearProgressIndicator(
                progress = { (page.designScore / 100.0).coerceIn(0.0, 1.0).toFloat() },
                modifier = Modifier.fillMaxWidth(),
            )
            Text(
                text = stringResource(R.string.stylist_issues_count, page.issuesFound),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            val reviewed = page.formattedLastReviewed()
            if (reviewed.isNotBlank()) {
                Text(
                    text = stringResource(R.string.stylist_last_reviewed, reviewed),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
internal fun scoreColor(value: Double) = when {
    value >= 85 -> MaterialTheme.colorScheme.primary
    value >= 70 -> MaterialTheme.colorScheme.tertiary
    else -> MaterialTheme.colorScheme.error
}
