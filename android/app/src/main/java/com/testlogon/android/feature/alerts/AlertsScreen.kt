@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.alerts

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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.DoneAll
import androidx.compose.material.icons.outlined.FilterList
import androidx.compose.material.icons.outlined.NotificationsActive
import androidx.compose.material3.AssistChip
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner
import com.testlogon.android.data.alerts.Alert
import com.testlogon.android.data.alerts.AlertPriority

/** Stable testTags for the alerts inbox. */
object AlertsTestTags {
    const val SCREEN = "alerts_screen"
    const val LIST = "alerts_list"
    const val LOADING = "alerts_loading"
    const val EMPTY = "alerts_empty"
    const val ERROR = "alerts_error"
    const val OFFLINE = "alerts_offline"
    const val SESSION_EXPIRED = "alerts_session_expired"
    const val MARK_ALL = "alerts_mark_all"
    const val FILTER = "alerts_filter_unread"
    const val ROW_PREFIX = "alerts_row_"
}

/** Route-level alerts-inbox entry (reachable from the More hub). */
@Composable
fun AlertsRoute(
    onBack: () -> Unit,
    onSessionExpired: () -> Unit,
    modifier: Modifier = Modifier,
    // MOD-D1: tapping a moderation alert opens the "My content under review" screen.
    onOpenModeration: () -> Unit = {},
    // ECOM-SELLER (G1): tapping a shop_item_sold alert opens that seller sale (ship group).
    onOpenSale: (String) -> Unit = {},
    viewModel: AlertsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is AlertsEffect.ShowMessage ->
                    snackbarHostState.showSnackbar(context.getString(effect.resId))
            }
        }
    }

    LaunchedEffect(state.phase) {
        if (state.phase == AlertsUiState.Phase.SessionExpired) onSessionExpired()
    }

    AlertsScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::onRefresh,
        onRetry = viewModel::onRetry,
        onMarkAllRead = viewModel::onMarkAllRead,
        onToggleUnreadOnly = viewModel::onToggleUnreadOnly,
        onAlertClick = viewModel::onAlertClick,
        onOpenModeration = onOpenModeration,
        onOpenSale = onOpenSale,
        snackbarHostState = snackbarHostState,
        modifier = modifier,
    )
}

/**
 * MOD-D1 — moderation poster-alert event strings (backend `write_alert` events). Tapping one of these
 * rows deep-links to the "My content under review" screen so the poster can respond / close.
 */
private val MODERATION_ALERT_EVENTS: Set<String> = setOf(
    "moderation_content_hidden",
    "moderation_violation_confirmed",
    "moderation_content_reinstated",
    "moderation_content_deleted",
    "moderation_content_restored",
    "dmca_claim_filed",
)

internal fun isModerationAlert(event: String?): Boolean =
    event != null && event.trim().lowercase() in MODERATION_ALERT_EVENTS

/**
 * ECOM-SELLER (G1) — the seller "you sold it" alert event (backend write_alert event=shop_item_sold).
 * Its action_url is /seller/orders?sale={ship_group_id}; parse that ship-group id to deep-link to the
 * seller sale detail.
 */
internal fun isShopSoldAlert(event: String?): Boolean =
    event != null && event.trim().lowercase() == "shop_item_sold"

internal fun saleIdFromActionUrl(actionUrl: String?): String? {
    val url = actionUrl ?: return null
    val q = url.substringAfter('?', "")
    if (q.isEmpty()) return null
    return q.split('&')
        .mapNotNull { part ->
            val i = part.indexOf('=')
            if (i <= 0) null else part.substring(0, i) to part.substring(i + 1)
        }
        .firstOrNull { it.first == "sale" }
        ?.second
        ?.let { android.net.Uri.decode(it) }
        ?.takeIf { it.isNotBlank() }
}

@Composable
fun AlertsScreen(
    state: AlertsUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onMarkAllRead: () -> Unit,
    onToggleUnreadOnly: () -> Unit,
    onAlertClick: (String) -> Unit,
    onOpenModeration: () -> Unit = {},
    onOpenSale: (String) -> Unit = {},
    modifier: Modifier = Modifier,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    Scaffold(
        modifier = modifier.testTag(AlertsTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.alerts_inbox_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("alerts_back")) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
                actions = {
                    val filterCd = stringResource(R.string.alerts_inbox_filter_unread)
                    IconButton(onClick = onToggleUnreadOnly, modifier = Modifier.testTag(AlertsTestTags.FILTER)) {
                        Icon(
                            Icons.Outlined.FilterList,
                            contentDescription = filterCd,
                            tint = if (state.unreadOnly) {
                                MaterialTheme.colorScheme.primary
                            } else {
                                MaterialTheme.colorScheme.onSurfaceVariant
                            },
                        )
                    }
                    if (state.hasUnread) {
                        val markCd = stringResource(R.string.alerts_inbox_mark_all)
                        IconButton(onClick = onMarkAllRead, modifier = Modifier.testTag(AlertsTestTags.MARK_ALL)) {
                            Icon(Icons.Outlined.DoneAll, contentDescription = markCd)
                        }
                    }
                },
            )
        },
    ) { padding ->
        Box(modifier = Modifier.padding(padding).fillMaxSize()) {
            when (state.phase) {
                AlertsUiState.Phase.Loading ->
                    LoadingState(modifier = Modifier.testTag(AlertsTestTags.LOADING))

                AlertsUiState.Phase.Error ->
                    ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.alerts_inbox_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(AlertsTestTags.ERROR),
                    )

                AlertsUiState.Phase.Offline ->
                    ErrorState(
                        message = state.errorMessage ?: stringResource(R.string.alerts_inbox_error_generic),
                        onRetry = onRetry,
                        modifier = Modifier.testTag(AlertsTestTags.OFFLINE),
                    )

                AlertsUiState.Phase.SessionExpired ->
                    EmptyState(
                        title = stringResource(R.string.alerts_inbox_session_expired_title),
                        body = stringResource(R.string.alerts_inbox_session_expired_body),
                        modifier = Modifier.testTag(AlertsTestTags.SESSION_EXPIRED),
                    )

                AlertsUiState.Phase.Empty ->
                    PullToRefreshBox(
                        isRefreshing = state.isRefreshing,
                        onRefresh = onRefresh,
                        modifier = Modifier.fillMaxSize(),
                    ) {
                        EmptyState(
                            title = stringResource(R.string.alerts_inbox_empty_title),
                            body = stringResource(R.string.alerts_inbox_empty_body),
                            imageVector = Icons.Outlined.NotificationsActive,
                            modifier = Modifier.testTag(AlertsTestTags.EMPTY),
                        )
                    }

                AlertsUiState.Phase.Content -> {
                    val alerts = state.page?.alerts.orEmpty()
                    PullToRefreshBox(
                        isRefreshing = state.isRefreshing,
                        onRefresh = onRefresh,
                        modifier = Modifier.fillMaxSize(),
                    ) {
                        LazyColumn(
                            modifier = Modifier
                                .testTag(AlertsTestTags.LIST)
                                .fillMaxSize(),
                            contentPadding = PaddingValues(vertical = 8.dp),
                        ) {
                            if (state.isStale) {
                                item { OfflineBanner(onRetry = onRetry) }
                            }
                            items(alerts, key = { it.id }) { alert ->
                                AlertRow(
                                    alert = alert,
                                    onClick = {
                                        onAlertClick(alert.id)
                                        // MOD-D1: moderation alerts deep-link to My content under review.
                                        if (isModerationAlert(alert.event)) onOpenModeration()
                                        // ECOM-SELLER (G1): a sold-item alert opens the seller sale.
                                        if (isShopSoldAlert(alert.event)) {
                                            saleIdFromActionUrl(alert.actionUrl)?.let(onOpenSale)
                                        }
                                    },
                                )
                                HorizontalDivider()
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun AlertRow(alert: Alert, onClick: () -> Unit) {
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(AlertsTestTags.ROW_PREFIX + alert.id)
            .clickable(onClick = onClick),
        color = if (alert.isUnread) {
            MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f)
        } else {
            MaterialTheme.colorScheme.surface
        },
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 14.dp),
            verticalAlignment = Alignment.Top,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Box(
                modifier = Modifier
                    .padding(top = 6.dp)
                    .size(8.dp)
                    .clip(CircleShape),
                contentAlignment = Alignment.Center,
            ) {
                if (alert.isUnread) {
                    Surface(
                        color = MaterialTheme.colorScheme.primary,
                        shape = CircleShape,
                        modifier = Modifier.size(8.dp),
                    ) {}
                }
            }
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(2.dp),
            ) {
                Text(
                    text = alert.title.ifBlank { alert.event },
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = if (alert.isUnread) FontWeight.SemiBold else FontWeight.Normal,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                val meta = listOf(alert.category, alert.formattedTime())
                    .filter { it.isNotBlank() }
                    .joinToString("   -   ")
                if (meta.isNotBlank()) {
                    Text(
                        text = meta,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            if (alert.priority == AlertPriority.URGENT) {
                AssistChip(
                    onClick = {},
                    label = { Text(stringResource(R.string.alerts_inbox_priority_urgent)) },
                )
            }
        }
    }
}
