package com.testlogon.android.feature.notifications

import android.text.format.DateUtils
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.DoneAll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.paging.LoadState
import androidx.paging.compose.LazyPagingItems
import androidx.paging.compose.collectAsLazyPagingItems
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** Stable testTags for the notification center (AND-085 / AND-090). */
object NotifTestTags {
    const val SCREEN = "notif_center_screen"
    const val LIST = "notif_list"
    const val ROW = "notif_row"
    const val UNREAD_DOT = "notif_unread_dot"
    const val MARK_ALL_READ = "notif_mark_all_read"
    const val UNREAD_BADGE = "notif_unread_badge"
    const val APPEND_FOOTER = "notif_append_footer"
    const val APPEND_RETRY = "notif_append_retry"
}

/** AND-085 — route-level Notification Center entry, reached from the More hub / shell. */
@Composable
fun NotificationCenterRoute(
    onNavigateTarget: (NotificationTarget) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: NotificationsViewModel = hiltViewModel(),
) {
    val badge by viewModel.badge.collectAsStateWithLifecycle()
    val items = viewModel.pagedNotifications.collectAsLazyPagingItems()
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is NotificationsEvent.Navigate -> onNavigateTarget(event.target)
                is NotificationsEvent.Error -> snackbarHostState.showSnackbar(event.message)
            }
        }
    }

    NotificationCenterScreen(
        badge = badge,
        items = items,
        snackbarHostState = snackbarHostState,
        onItemClick = viewModel::onItemClick,
        onMarkAllRead = viewModel::onMarkAllRead,
        onBack = onBack,
        modifier = modifier,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NotificationCenterScreen(
    badge: UnreadBadgeUiState,
    items: LazyPagingItems<NotificationUi>,
    snackbarHostState: SnackbarHostState,
    onItemClick: (NotificationUi) -> Unit,
    onMarkAllRead: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val listState = rememberLazyListState()
    Scaffold(
        modifier = modifier.testTag(NotifTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("Notifications")
                        if (badge.display.isNotEmpty()) {
                            Text(
                                text = badge.display,
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.error,
                                modifier = Modifier
                                    .padding(start = 8.dp)
                                    .testTag(NotifTestTags.UNREAD_BADGE),
                            )
                        }
                    }
                },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("notif_back")) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(
                        onClick = onMarkAllRead,
                        enabled = badge.markAllEnabled,
                        modifier = Modifier.testTag(NotifTestTags.MARK_ALL_READ),
                    ) {
                        Icon(Icons.Filled.DoneAll, contentDescription = "Mark all notifications as read")
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        val refreshState = items.loadState.refresh
        Box(Modifier.fillMaxSize().padding(padding)) {
            when {
                refreshState is LoadState.Loading && items.itemCount == 0 -> LoadingState()

                refreshState is LoadState.Error && items.itemCount == 0 -> {
                    val message = (refreshState.error as? NotificationLoadException)?.message
                        ?: "Couldn't load notifications."
                    ErrorState(message = message, onRetry = items::retry)
                }

                refreshState is LoadState.NotLoading && items.itemCount == 0 ->
                    EmptyState(
                        title = "No notifications yet",
                        body = "You're all caught up.",
                    )

                else -> NotificationList(
                    items = items,
                    listState = listState,
                    onItemClick = onItemClick,
                )
            }
        }
    }
}

@Composable
private fun NotificationList(
    items: LazyPagingItems<NotificationUi>,
    listState: androidx.compose.foundation.lazy.LazyListState,
    onItemClick: (NotificationUi) -> Unit,
) {
    LazyColumn(
        state = listState,
        modifier = Modifier.fillMaxSize().testTag(NotifTestTags.LIST),
    ) {
        items(count = items.itemCount, key = { index -> items.peek(index)?.id ?: index }) { index ->
            val item = items[index]
            if (item != null) {
                NotificationRow(item = item, onClick = { onItemClick(item) })
            }
        }

        when (val append = items.loadState.append) {
            is LoadState.Loading -> item {
                Box(
                    Modifier.fillMaxWidth().padding(16.dp).testTag(NotifTestTags.APPEND_FOOTER),
                    contentAlignment = Alignment.Center,
                ) {
                    CircularProgressIndicator(modifier = Modifier.size(24.dp))
                }
            }
            is LoadState.Error -> item {
                Row(
                    Modifier.fillMaxWidth().padding(16.dp).testTag(NotifTestTags.APPEND_FOOTER),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text("Couldn't load more.", style = MaterialTheme.typography.bodyMedium)
                    TextButton(
                        onClick = items::retry,
                        modifier = Modifier.testTag(NotifTestTags.APPEND_RETRY),
                    ) { Text("Retry") }
                }
            }
            else -> Unit
        }
    }
}

@Composable
private fun NotificationRow(
    item: NotificationUi,
    onClick: () -> Unit,
) {
    val relative = remember(item.createdAtEpochSeconds) { relativeTime(item.createdAtEpochSeconds) }
    val rowBackground = if (item.isRead) {
        Color.Transparent
    } else {
        MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f)
    }
    val readState = if (item.isRead) "read" else "unread"
    val cd = "$readState: ${item.title}, $relative"

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .background(rowBackground)
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .testTag(NotifTestTags.ROW)
            .clearAndSetSemantics {
                contentDescription = cd
                stateDescription = readState
            },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            modifier = Modifier.size(24.dp),
            contentAlignment = Alignment.Center,
        ) {
            if (!item.isRead) {
                Box(
                    modifier = Modifier
                        .size(8.dp)
                        .clip(CircleShape)
                        .background(MaterialTheme.colorScheme.primary)
                        .testTag(NotifTestTags.UNREAD_DOT),
                )
            }
        }
        Column(
            modifier = Modifier.padding(start = 8.dp).fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Text(
                text = item.title,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = if (item.isRead) FontWeight.Normal else FontWeight.SemiBold,
            )
            if (item.body.isNotBlank()) {
                Text(
                    text = item.body,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Text(
                text = relative,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/** Relative-time copy from an epoch-SECONDS value (minSdk24-safe; not used in JVM unit tests). */
private fun relativeTime(epochSeconds: Long): String {
    if (epochSeconds <= 0L) return ""
    val nowMs = System.currentTimeMillis()
    return DateUtils.getRelativeTimeSpanString(
        epochSeconds * 1000L,
        nowMs,
        DateUtils.MINUTE_IN_MILLIS,
    ).toString()
}
