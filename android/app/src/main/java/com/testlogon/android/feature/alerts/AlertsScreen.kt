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
    onOpenAppeals: () -> Unit = {},
    // ECOM-SELLER (G1): tapping a shop_item_sold alert opens that seller sale (ship group).
    onOpenSale: (String) -> Unit = {},
    // D4: tapping a buyer shipment alert opens the buyer order-tracking view (by ship-group id).
    onOpenTracking: (String) -> Unit = {},
    onOpenSubscription: (String, String) -> Unit = { _, _ -> },  // SUB-E5 route(A1): (event, actionUrl)
    // PAY-51: tapping a payout alert opens that payout statement/detail (by payout_id from action_url).
    onOpenPayout: (String) -> Unit = {},
    // TIPX-E2: tapping a tip alert deep-links to the tipped content / tip history.
    onOpenPost: (String) -> Unit = {},
    onOpenThread: (String) -> Unit = {},
    onOpenVideo: (String) -> Unit = {},
    onOpenTips: () -> Unit = {},
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
        onOpenAppeals = onOpenAppeals,
        onOpenSale = onOpenSale,
        onOpenTracking = onOpenTracking,
        onOpenSubscription = onOpenSubscription,  // SUB-E5 route(A2)
        onOpenPayout = onOpenPayout,  // PAY-51
        onOpenPost = onOpenPost,        // TIPX-E2
        onOpenThread = onOpenThread,    // TIPX-E2
        onOpenVideo = onOpenVideo,      // TIPX-E2
        onOpenTips = onOpenTips,        // TIPX-E2
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
    "moderation_hold_escalated",
    "moderation_content_reinstated",
    "moderation_content_restored",
    "dmca_claim_filed",
)

// MODX-15 (C6): enforcement OUTCOMES (ban / removal) whose actionable next step is an appeal,
// NOT the (now-terminal, empty) content-review list.
private val MODERATION_ENFORCEMENT_EVENTS: Set<String> = setOf(
    "moderation_ban",
    "moderation_content_deleted",
    "moderation_content_removed",
    "dmca_repeat_infringer_ban",
)

internal fun isModerationAlert(event: String?): Boolean =
    event != null && event.trim().lowercase() in MODERATION_ALERT_EVENTS

internal fun isModerationEnforcementAlert(event: String?): Boolean =
    event != null && event.trim().lowercase() in MODERATION_ENFORCEMENT_EVENTS

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

/**
 * D4 - the BUYER shipment-tracking alert events (backend write_alert). Their action_url is
 * /orders?order=..&ship_group=..&track=1; tapping one deep-links to the buyer order-tracking view.
 */
private val ORDER_TRACKING_ALERT_EVENTS: Set<String> = setOf(
    "order_shipped", "order_out_for_delivery", "order_delivered",
)

internal fun isOrderTrackingAlert(event: String?): Boolean =
    event != null && event.trim().lowercase() in ORDER_TRACKING_ALERT_EVENTS

/**
 * SUB-E5 subscription lifecycle alert events (backend emit_social_alert). Tapping one deep-links
 * to manage-subscription (subscriber-facing) or the Subscribers screen (creator-facing); the
 * backend sets the per-recipient action_url so the app just routes on that path.
 */
private val SUBSCRIPTION_ALERT_EVENTS: Set<String> = setOf(
    "subscription_started", "subscription_new_subscriber", "subscription_renewed",
    "subscription_renewal_failed", "subscription_expiring", "subscription_expired",
    "subscription_canceled", "subscription_gifted",
    // SUBX-51: plan-change / creator-removal / trial-conversion lifecycle alerts.
    "subscription_changed", "subscription_removed", "subscription_converted",
)

internal fun isSubscriptionAlert(event: String?): Boolean =
    event != null && event.trim().lowercase() in SUBSCRIPTION_ALERT_EVENTS

/**
 * PAY-51 payout lifecycle alert events (backend PAY-D emit; default-ON). Tapping one deep-links to the
 * payout statement/detail via its action_url `/wallet/payouts/{payout_id}`.
 */
private val PAYOUT_ALERT_EVENTS: Set<String> = setOf(
    "payout_initiated", "payout_paid", "payout_failed", "payout_returned",
)

internal fun isPayoutAlert(event: String?): Boolean =
    event != null && event.trim().lowercase() in PAYOUT_ALERT_EVENTS

/** Parses the payout_id from a payout alert action_url path `/wallet/payouts/{payout_id}`. */
internal fun payoutIdFromActionUrl(actionUrl: String?): String? {
    val path = (actionUrl ?: return null).substringBefore('?')
    val marker = "/wallet/payouts/"
    val idx = path.indexOf(marker)
    if (idx < 0) return null
    return path.substring(idx + marker.length)
        .trim('/')
        .substringBefore('/')
        .let { android.net.Uri.decode(it) }
        .takeIf { it.isNotBlank() }
}

/**
 * TIPX-E2 (N1/N2/N3) — tip notification events. EVERY surface routes through the backend
 * `notify_tip` choke point, emitting a `tip_received` (recipient) / `tip_sent` (tipper) /
 * `tip_reversed` / `tip_refunded` alert plus the legacy `post_tip` / `message_tip` social types.
 * All of them carry a relative `action_url` to the tipped content; tapping the row deep-links there.
 */
private val TIP_ALERT_EVENTS: Set<String> = setOf(
    "tip_received", "tip_sent", "tip_reversed", "tip_refunded",
    "post_tip", "message_tip",
)

internal fun isTipAlert(event: String?): Boolean =
    event != null && event.trim().lowercase() in TIP_ALERT_EVENTS

/** A resolved deep-link target parsed from a tip alert's action_url. */
sealed interface TipNavTarget {
    data class Post(val postId: String) : TipNavTarget
    data class Thread(val conversationId: String) : TipNavTarget
    data class Video(val videoId: String) : TipNavTarget
    /** reversal / refund receipts (and any unrecognised path) -> the tip history screen. */
    data object Tips : TipNavTarget
}

/**
 * Maps a tip alert's relative action_url to a [TipNavTarget]:
 *   /feed/posts/{id}         -> Post
 *   /messaging/thread/{id}   -> Thread
 *   /videos/{id}             -> Video
 *   /wallet/tips (or other)  -> Tips
 */
internal fun tipTargetFromActionUrl(actionUrl: String?): TipNavTarget {
    val path = (actionUrl ?: "").substringBefore('?').trim()
    fun seg(marker: String): String? {
        val i = path.indexOf(marker)
        if (i < 0) return null
        return path.substring(i + marker.length).trim('/').substringBefore('/')
            .let { android.net.Uri.decode(it) }.takeIf { it.isNotBlank() }
    }
    seg("/feed/posts/")?.let { return TipNavTarget.Post(it) }
    seg("/messaging/thread/")?.let { return TipNavTarget.Thread(it) }
    seg("/videos/")?.let { return TipNavTarget.Video(it) }
    return TipNavTarget.Tips
}

/** Parses the ship_group id from a buyer shipment alert action_url query. */
internal fun shipGroupFromActionUrl(actionUrl: String?): String? {
    val url = actionUrl ?: return null
    val q = url.substringAfter('?', "")
    if (q.isEmpty()) return null
    return q.split('&')
        .mapNotNull { part ->
            val i = part.indexOf('=')
            if (i <= 0) null else part.substring(0, i) to part.substring(i + 1)
        }
        .firstOrNull { it.first == "ship_group" }
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
    onOpenAppeals: () -> Unit = {},
    onOpenSale: (String) -> Unit = {},
    onOpenTracking: (String) -> Unit = {},
    onOpenSubscription: (String, String) -> Unit = { _, _ -> },  // SUB-E5 route(A3): (event, actionUrl)
    onOpenPayout: (String) -> Unit = {},  // PAY-51: (payoutId)
    onOpenPost: (String) -> Unit = {},    // TIPX-E2: (postId)
    onOpenThread: (String) -> Unit = {},  // TIPX-E2: (conversationId)
    onOpenVideo: (String) -> Unit = {},   // TIPX-E2: (videoId)
    onOpenTips: () -> Unit = {},          // TIPX-E2: tip history
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
                                        // MODX-15 (C6): a ban/removal outcome opens Appeals (a real next
                                        // step); other moderation alerts open My content under review.
                                        if (isModerationEnforcementAlert(alert.event)) onOpenAppeals()
                                        else if (isModerationAlert(alert.event)) onOpenModeration()
                                        // ECOM-SELLER (G1): a sold-item alert opens the seller sale.
                                        if (isShopSoldAlert(alert.event)) {
                                            saleIdFromActionUrl(alert.actionUrl)?.let(onOpenSale)
                                        }
                                        // D4: a buyer shipment alert opens the order-tracking view.
                                        if (isOrderTrackingAlert(alert.event)) {
                                            shipGroupFromActionUrl(alert.actionUrl)?.let(onOpenTracking)
                                        }
                                        // SUB-E5: a subscription alert deep-links via its action_url;
                                        // the event disambiguates the bare "/subscriptions" path
                                        // (creator-new-subscriber vs gift-recipient).
                                        if (isSubscriptionAlert(alert.event)) {
                                            onOpenSubscription(alert.event ?: "", alert.actionUrl ?: "")
                                        }
                                        // PAY-51: a payout alert deep-links to that payout's statement.
                                        if (isPayoutAlert(alert.event)) {
                                            payoutIdFromActionUrl(alert.actionUrl)?.let(onOpenPayout)
                                        }
                                        // TIPX-E2 (N3): a tip alert deep-links to the tipped
                                        // post / thread / video (or tip history for reversals).
                                        if (isTipAlert(alert.event)) {
                                            when (val t = tipTargetFromActionUrl(alert.actionUrl)) {
                                                is TipNavTarget.Post -> onOpenPost(t.postId)
                                                is TipNavTarget.Thread -> onOpenThread(t.conversationId)
                                                is TipNavTarget.Video -> onOpenVideo(t.videoId)
                                                TipNavTarget.Tips -> onOpenTips()
                                            }
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
