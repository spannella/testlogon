package com.testlogon.android.feature.dashboard

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.scaffold.TlScaffold
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.feature.dashboard.states.DashboardEmptyState
import com.testlogon.android.feature.dashboard.states.DashboardErrorState
import com.testlogon.android.feature.dashboard.states.DashboardStaleBanner
import com.testlogon.android.feature.dashboard.widgets.HighlightsWidget
import com.testlogon.android.feature.dashboard.widgets.QuickLinksWidget
import com.testlogon.android.feature.dashboard.widgets.SummaryWidget

/**
 * AND-066 — route-level Dashboard entry wired into the Home tab. Collects state lifecycle-aware,
 * maps [QuickLink]s to hoisted nav callbacks, and shows one-shot effect messages in a Snackbar.
 */
@Composable
fun DashboardRoute(
    onOpenProfile: () -> Unit,
    onOpenSessions: () -> Unit,
    onOpenSettings: () -> Unit,
    onOpenMore: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: DashboardViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is DashboardEffect.ShowMessage ->
                    snackbarHostState.showSnackbar(context.getString(effect.resId))
            }
        }
    }

    DashboardScreen(
        state = state,
        onRefresh = viewModel::onRefresh,
        onRetry = viewModel::onRetry,
        onQuickLink = { link ->
            when (link) {
                QuickLink.Profile -> onOpenProfile()
                QuickLink.Sessions -> onOpenSessions()
                QuickLink.Settings -> onOpenSettings()
                QuickLink.More -> onOpenMore()
            }
        },
        snackbarHostState = snackbarHostState,
        modifier = modifier,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DashboardScreen(
    state: DashboardUiState,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onQuickLink: (QuickLink) -> Unit,
    modifier: Modifier = Modifier,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    TlScaffold(
        modifier = modifier.testTag("dashboard_screen"),
        topBar = { TopAppBar(title = { Text(stringResource(R.string.dashboard_title)) }) },
        snackbarHostState = snackbarHostState,
    ) {
        PullToRefreshBox(
            isRefreshing = state.isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize(),
        ) {
            when (state.phase) {
                DashboardUiState.Phase.Loading ->
                    LoadingState(modifier = Modifier.testTag(DashboardTestTags.LOADING))

                DashboardUiState.Phase.Error ->
                    DashboardErrorState(
                        message = state.errorMessage.orEmpty(),
                        onRetry = onRetry,
                    )

                DashboardUiState.Phase.Empty ->
                    DashboardEmptyState(onRefresh = onRetry)

                DashboardUiState.Phase.Content ->
                    DashboardContent(state = state, onRetry = onRetry, onQuickLink = onQuickLink)
            }
        }
    }
}

@Composable
private fun DashboardContent(
    state: DashboardUiState,
    onRetry: () -> Unit,
    onQuickLink: (QuickLink) -> Unit,
) {
    val data = state.dashboard ?: return
    LazyColumn(
        modifier = Modifier.fillMaxSize()
            .testTag(DashboardTestTags.LIST),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (state.isStale) {
            item { DashboardStaleBanner(onRetry = onRetry, refreshing = state.isRefreshing) }
        }
        if (data.warnings.isNotEmpty()) {
            items(data.warnings) { warning ->
                com.testlogon.android.core.ui.state.OfflineBanner(message = warning)
            }
        }
        item { SummaryWidget(data) }
        item {
            HighlightsWidget(dashboard = data, onSeeAll = { onQuickLink(QuickLink.More) })
        }
        item { QuickLinksWidget(onQuickLink = onQuickLink) }
    }
}
