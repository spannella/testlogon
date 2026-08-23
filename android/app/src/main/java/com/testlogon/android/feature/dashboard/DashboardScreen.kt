@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.dashboard

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.AccountBalanceWallet
import androidx.compose.material.icons.outlined.Diversity3
import androidx.compose.material.icons.outlined.Apps
import androidx.compose.material.icons.outlined.Edit
import androidx.compose.material.icons.outlined.Forum
import androidx.compose.material.icons.outlined.MovieCreation
import androidx.compose.material.icons.outlined.Person
import androidx.compose.material.icons.outlined.Storefront
import androidx.compose.material.icons.outlined.TrendingUp
import androidx.compose.material.icons.outlined.ShowChart
import androidx.compose.material.icons.outlined.CandlestickChart
import androidx.compose.material.icons.outlined.Insights
import androidx.compose.material.icons.outlined.Assessment
import androidx.compose.material.icons.outlined.PieChart
import androidx.compose.material.icons.outlined.Gavel
import androidx.compose.material.icons.outlined.Savings
import androidx.compose.material.icons.outlined.ReceiptLong
import androidx.compose.material.icons.outlined.AccountBalance
import androidx.compose.material.icons.outlined.Paid
import androidx.compose.material.icons.outlined.Videocam
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.scaffold.TlScaffold
import com.testlogon.android.core.ui.state.LoadingSkeleton
import com.testlogon.android.feature.dashboard.states.DashboardErrorState
import com.testlogon.android.feature.dashboard.states.DashboardStaleBanner
import com.testlogon.android.feature.dashboard.widgets.HighlightsWidget
import com.testlogon.android.feature.dashboard.widgets.SummaryWidget
import com.testlogon.android.feature.more.MoreHub
import com.testlogon.android.feature.onboarding.WelcomeTour
import com.testlogon.android.feature.more.accent
import com.testlogon.android.navigation.BroadcastBrowseDest
import com.testlogon.android.navigation.ComposePostDest
import com.testlogon.android.navigation.MoreRoutes

/**
 * AND-066 — route-level Dashboard entry wired into the Home tab. Collects state lifecycle-aware,
 * maps [QuickLink]s to hoisted nav callbacks, and shows one-shot effect messages in a Snackbar.
 *
 * Redesigned into a launchpad: quick actions + hub shortcuts always render so Home is useful even
 * with no dashboard data. [onOpenRoute] opens outer-graph routes; [onOpenInbox] jumps to the Inbox tab.
 */
@Composable
fun DashboardRoute(
    onOpenProfile: () -> Unit,
    onOpenSessions: () -> Unit,
    onOpenSettings: () -> Unit,
    onOpenMore: () -> Unit,
    onOpenRoute: (String) -> Unit,
    onOpenInbox: () -> Unit,
    onOpenHub: (MoreHub) -> Unit,
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

    // First-run guided tour of the new trading/investing surfaces (persisted show-once).
    WelcomeTour(onOpenRoute = onOpenRoute)

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
        onOpenProfile = onOpenProfile,
        onOpenMore = onOpenMore,
        onOpenRoute = onOpenRoute,
        onOpenInbox = onOpenInbox,
        onOpenHub = onOpenHub,
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
    onOpenProfile: () -> Unit = {},
    onOpenMore: () -> Unit = {},
    onOpenRoute: (String) -> Unit = {},
    onOpenInbox: () -> Unit = {},
    onOpenHub: (MoreHub) -> Unit = {},
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
                    LoadingSkeleton(modifier = Modifier.testTag(DashboardTestTags.LOADING))

                DashboardUiState.Phase.Error ->
                    DashboardErrorState(
                        message = state.errorMessage.orEmpty(),
                        onRetry = onRetry,
                    )

                DashboardUiState.Phase.Empty,
                DashboardUiState.Phase.Content ->
                    DashboardLaunchpad(
                        state = state,
                        onRetry = onRetry,
                        onQuickLink = onQuickLink,
                        onOpenProfile = onOpenProfile,
                        onOpenMore = onOpenMore,
                        onOpenRoute = onOpenRoute,
                        onOpenInbox = onOpenInbox,
                        onOpenHub = onOpenHub,
                    )
            }
        }
    }
}

/**
 * The Home launchpad. Header + quick actions + hub shortcuts always render (so Home is useful with
 * zero data); the activity area renders real content when present, else a slim inline note.
 */
@Composable
private fun DashboardLaunchpad(
    state: DashboardUiState,
    onRetry: () -> Unit,
    onQuickLink: (QuickLink) -> Unit,
    onOpenProfile: () -> Unit,
    onOpenMore: () -> Unit,
    onOpenRoute: (String) -> Unit,
    onOpenInbox: () -> Unit,
    onOpenHub: (MoreHub) -> Unit,
) {
    val data = state.dashboard
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag(DashboardTestTags.LIST),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        item { LaunchpadHeader(onOpenProfile = onOpenProfile, viewerName = state.viewerName, viewerPhotoUrl = state.viewerPhotoUrl) }

        if (state.isStale) {
            item { DashboardStaleBanner(onRetry = onRetry, refreshing = state.isRefreshing) }
        }
        if (data?.warnings?.isNotEmpty() == true) {
            items(data.warnings) { warning ->
                com.testlogon.android.core.ui.state.OfflineBanner(message = warning)
            }
        }

        item {
            QuickActionsRow(
                onOpenRoute = onOpenRoute,
                onOpenInbox = onOpenInbox,
                onOpenHub = onOpenHub,
            )
        }

        item { ShortcutsSection(onOpenHub = onOpenHub, onOpenMore = onOpenMore) }

        // Trading & Investing quick-access: links to already-shipped invest/markets surfaces.
        item { TradingSection(onOpenRoute = onOpenRoute) }

        // Activity / content: real widgets when present, else a slim inline note.
        if (data != null && !data.isEmpty) {
            item { SummaryWidget(data) }
            item {
                HighlightsWidget(dashboard = data, onSeeAll = { onQuickLink(QuickLink.More) })
            }
        } else {
            item { ActivityPlaceholder() }
        }
    }
}

@Composable
private fun LaunchpadHeader(
    onOpenProfile: () -> Unit,
    viewerName: String? = null,
    viewerPhotoUrl: String? = null,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = stringResource(R.string.dashboard_greeting),
                style = MaterialTheme.typography.headlineSmall,
                modifier = Modifier.semantics { heading() },
            )
            // ID15 - show the signed-in user's name under the greeting when known.
            viewerName?.takeIf { it.isNotBlank() }?.let { name ->
                Text(
                    text = name,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        // ID15 - greeting avatar: the user's profile photo when set, else a monogram; taps to profile.
        Box(
            modifier = Modifier
                .clip(CircleShape)
                .clickable(onClick = onOpenProfile)
                .testTag(DashboardTestTags.PROFILE_ACTION),
        ) {
            com.testlogon.android.feature.common.TlAvatar(
                name = viewerName,
                photoUrl = viewerPhotoUrl,
                size = 44.dp,
            )
        }
    }
}

@Composable
private fun QuickActionsRow(
    onOpenRoute: (String) -> Unit,
    onOpenInbox: () -> Unit,
    onOpenHub: (MoreHub) -> Unit,
) {
    val scheme = MaterialTheme.colorScheme
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        QuickActionItem(
            icon = Icons.Outlined.Edit,
            label = stringResource(R.string.dashboard_action_create_post),
            testTag = DashboardTestTags.ACTION_POST,
            circleColor = scheme.primaryContainer,
            iconTint = scheme.onPrimaryContainer,
            onClick = { onOpenRoute(ComposePostDest.build()) },
            modifier = Modifier.weight(1f),
        )
        QuickActionItem(
            icon = Icons.Outlined.Videocam,
            label = stringResource(R.string.dashboard_action_go_live),
            testTag = DashboardTestTags.ACTION_GO_LIVE,
            circleColor = scheme.tertiaryContainer,
            iconTint = scheme.onTertiaryContainer,
            onClick = { onOpenRoute(BroadcastBrowseDest.ROUTE) },
            modifier = Modifier.weight(1f),
        )
        QuickActionItem(
            icon = Icons.Outlined.Forum,
            label = stringResource(R.string.dashboard_action_messages),
            testTag = DashboardTestTags.ACTION_MESSAGES,
            circleColor = scheme.secondaryContainer,
            iconTint = scheme.onSecondaryContainer,
            onClick = onOpenInbox,
            modifier = Modifier.weight(1f),
        )
        QuickActionItem(
            icon = Icons.Outlined.AccountBalanceWallet,
            label = stringResource(R.string.dashboard_action_wallet),
            testTag = DashboardTestTags.ACTION_WALLET,
            circleColor = MoreHub.WALLET.accent().container,
            iconTint = MoreHub.WALLET.accent().onAccent,
            onClick = { onOpenHub(MoreHub.WALLET) },
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun QuickActionItem(
    icon: ImageVector,
    label: String,
    testTag: String,
    circleColor: Color,
    iconTint: Color,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Surface(
        onClick = onClick,
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surfaceVariant,
        modifier = modifier.testTag(testTag),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(vertical = 12.dp, horizontal = 4.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Box(
                modifier = Modifier.size(40.dp).clip(CircleShape).background(circleColor),
                contentAlignment = Alignment.Center,
            ) {
                Icon(icon, contentDescription = null, tint = iconTint, modifier = Modifier.size(22.dp))
            }
            Text(
                text = label,
                style = MaterialTheme.typography.labelMedium,
                textAlign = TextAlign.Center,
                maxLines = 1,
            )
        }
    }
}

@Composable
private fun ShortcutsSection(
    onOpenHub: (MoreHub) -> Unit,
    onOpenMore: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            text = stringResource(R.string.dashboard_shortcuts_title),
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.semantics { heading() },
        )
        // 2-col grid built from rows (nested LazyVerticalGrid in a LazyColumn is disallowed).
        ShortcutRow(
            left = {
                ShortcutCard(
                    icon = Icons.Outlined.MovieCreation,
                    label = stringResource(R.string.more_hub_studio),
                    testTag = DashboardTestTags.HUB_STUDIO,
                    circleColor = MoreHub.STUDIO.accent().container,
                    iconTint = MoreHub.STUDIO.accent().onAccent,
                    onClick = { onOpenHub(MoreHub.STUDIO) },
                    modifier = Modifier.weight(1f),
                )
            },
            right = {
                ShortcutCard(
                    icon = Icons.Outlined.TrendingUp,
                    label = stringResource(R.string.more_hub_growth),
                    testTag = DashboardTestTags.HUB_GROWTH,
                    circleColor = MoreHub.GROWTH.accent().container,
                    iconTint = MoreHub.GROWTH.accent().onAccent,
                    onClick = { onOpenHub(MoreHub.GROWTH) },
                    modifier = Modifier.weight(1f),
                )
            },
        )
        ShortcutRow(
            left = {
                ShortcutCard(
                    icon = Icons.Outlined.Diversity3,
                    label = stringResource(R.string.more_hub_community),
                    testTag = DashboardTestTags.HUB_COMMUNITY,
                    circleColor = MoreHub.COMMUNITY.accent().container,
                    iconTint = MoreHub.COMMUNITY.accent().onAccent,
                    onClick = { onOpenHub(MoreHub.COMMUNITY) },
                    modifier = Modifier.weight(1f),
                )
            },
            right = {
                ShortcutCard(
                    icon = Icons.Outlined.Storefront,
                    label = stringResource(R.string.more_hub_shop),
                    testTag = DashboardTestTags.HUB_SHOP,
                    circleColor = MoreHub.SHOP.accent().container,
                    iconTint = MoreHub.SHOP.accent().onAccent,
                    onClick = { onOpenHub(MoreHub.SHOP) },
                    modifier = Modifier.weight(1f),
                )
            },
        )
        ShortcutRow(
            left = {
                ShortcutCard(
                    icon = Icons.Outlined.Apps,
                    label = stringResource(R.string.dashboard_quick_link_more),
                    testTag = DashboardTestTags.HUB_ALL,
                    circleColor = MaterialTheme.colorScheme.secondaryContainer,
                    iconTint = MaterialTheme.colorScheme.onSecondaryContainer,
                    onClick = onOpenMore,
                    modifier = Modifier.weight(1f),
                )
            },
            right = { Box(modifier = Modifier.weight(1f)) {} },
        )
    }
}

@Composable
private fun TradingSection(
    onOpenRoute: (String) -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            text = stringResource(R.string.dashboard_trading_title),
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.semantics { heading() },
        )
        val scheme = MaterialTheme.colorScheme
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState())
                .testTag(DashboardTestTags.TRADING_SECTION),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            TradingCard(
                icon = Icons.Outlined.TrendingUp,
                label = stringResource(R.string.dashboard_trading_invest),
                testTag = DashboardTestTags.TRADING_INVEST,
                circleColor = scheme.primaryContainer,
                iconTint = scheme.onPrimaryContainer,
                onClick = { onOpenRoute(MoreRoutes.INVEST) },
            )
            TradingCard(
                icon = Icons.Outlined.CandlestickChart,
                label = stringResource(R.string.dashboard_trading_markets),
                testTag = DashboardTestTags.TRADING_MARKETS,
                circleColor = scheme.tertiaryContainer,
                iconTint = scheme.onTertiaryContainer,
                onClick = { onOpenRoute(MoreRoutes.MARKETS) },
            )
            TradingCard(
                icon = Icons.Outlined.Insights,
                label = stringResource(R.string.dashboard_trading_strategies),
                testTag = DashboardTestTags.TRADING_STRATEGIES,
                circleColor = scheme.secondaryContainer,
                iconTint = scheme.onSecondaryContainer,
                onClick = { onOpenRoute(MoreRoutes.STRATEGIES) },
            )
            TradingCard(
                icon = Icons.Outlined.PieChart,
                label = stringResource(R.string.dashboard_trading_portfolio_analytics),
                testTag = DashboardTestTags.TRADING_PORTFOLIO_ANALYTICS,
                circleColor = scheme.primaryContainer,
                iconTint = scheme.onPrimaryContainer,
                onClick = { onOpenRoute(MoreRoutes.PORTFOLIO_ANALYTICS) },
            )
            TradingCard(
                icon = Icons.Outlined.Assessment,
                label = stringResource(R.string.dashboard_trading_activity_center),
                testTag = DashboardTestTags.TRADING_ACTIVITY_CENTER,
                circleColor = scheme.tertiaryContainer,
                iconTint = scheme.onTertiaryContainer,
                onClick = { onOpenRoute(MoreRoutes.ACTIVITY_CENTER) },
            )
            TradingCard(
                icon = Icons.Outlined.ShowChart,
                label = stringResource(R.string.dashboard_trading_active_algos),
                testTag = DashboardTestTags.TRADING_ACTIVE_ALGOS,
                circleColor = scheme.secondaryContainer,
                iconTint = scheme.onSecondaryContainer,
                onClick = { onOpenRoute(MoreRoutes.ACTIVE_ALGOS) },
            )
            TradingCard(
                icon = Icons.Outlined.Paid,
                label = stringResource(R.string.dashboard_trading_tokens),
                testTag = DashboardTestTags.TRADING_TOKENS,
                circleColor = scheme.primaryContainer,
                iconTint = scheme.onPrimaryContainer,
                onClick = { onOpenRoute(MoreRoutes.TOKENS) },
            )
            TradingCard(
                icon = Icons.Outlined.Gavel,
                label = stringResource(R.string.dashboard_trading_bailouts),
                testTag = DashboardTestTags.TRADING_BAILOUTS,
                circleColor = scheme.tertiaryContainer,
                iconTint = scheme.onTertiaryContainer,
                onClick = { onOpenRoute(MoreRoutes.BAILOUTS) },
            )
            TradingCard(
                icon = Icons.Outlined.AccountBalance,
                label = stringResource(R.string.dashboard_trading_custody_providers),
                testTag = DashboardTestTags.TRADING_CUSTODY_PROVIDERS,
                circleColor = scheme.secondaryContainer,
                iconTint = scheme.onSecondaryContainer,
                onClick = { onOpenRoute(MoreRoutes.CUSTODY_PROVIDERS) },
            )
            TradingCard(
                icon = Icons.Outlined.ReceiptLong,
                label = stringResource(R.string.dashboard_trading_tax_gains),
                testTag = DashboardTestTags.TRADING_TAX_GAINS,
                circleColor = scheme.primaryContainer,
                iconTint = scheme.onPrimaryContainer,
                onClick = { onOpenRoute(MoreRoutes.TAX_REPORT) },
            )
        }
    }
}

@Composable
private fun TradingCard(
    icon: ImageVector,
    label: String,
    testTag: String,
    circleColor: Color,
    iconTint: Color,
    onClick: () -> Unit,
) {
    Card(onClick = onClick, modifier = Modifier.width(104.dp).testTag(testTag)) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(vertical = 12.dp, horizontal = 8.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Box(
                modifier = Modifier.size(40.dp).clip(CircleShape).background(circleColor),
                contentAlignment = Alignment.Center,
            ) {
                Icon(icon, contentDescription = null, tint = iconTint, modifier = Modifier.size(22.dp))
            }
            Text(
                text = label,
                style = MaterialTheme.typography.labelMedium,
                textAlign = TextAlign.Center,
                maxLines = 2,
            )
        }
    }
}

@Composable
private fun ShortcutRow(
    left: @Composable androidx.compose.foundation.layout.RowScope.() -> Unit,
    right: @Composable androidx.compose.foundation.layout.RowScope.() -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        left()
        right()
    }
}

@Composable
private fun ShortcutCard(
    icon: ImageVector,
    label: String,
    testTag: String,
    circleColor: Color,
    iconTint: Color,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Card(onClick = onClick, modifier = modifier.testTag(testTag)) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Box(
                modifier = Modifier.size(40.dp).clip(CircleShape).background(circleColor),
                contentAlignment = Alignment.Center,
            ) {
                Icon(icon, contentDescription = null, tint = iconTint, modifier = Modifier.size(22.dp))
            }
            Text(label, style = MaterialTheme.typography.bodyLarge, maxLines = 1)
        }
    }
}

/** Slim inline note shown in place of activity widgets when there is no dashboard content. */
@Composable
private fun ActivityPlaceholder() {
    Card(
        modifier = Modifier.fillMaxWidth().testTag(DashboardTestTags.EMPTY),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                text = stringResource(R.string.dashboard_activity_placeholder_title),
                style = MaterialTheme.typography.titleSmall,
            )
            Text(
                text = stringResource(R.string.dashboard_activity_placeholder_body),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
