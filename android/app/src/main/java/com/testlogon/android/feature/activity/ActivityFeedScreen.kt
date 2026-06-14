package com.testlogon.android.feature.activity

import android.text.format.DateUtils
import androidx.compose.foundation.background
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
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Login
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.paging.LoadState
import androidx.paging.compose.LazyPagingItems
import androidx.paging.compose.collectAsLazyPagingItems
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.activity.ActivityEvent
import com.testlogon.android.data.activity.ActivityEventType

/** Stable testTags for the activity feed (AND-091 / AND-096). */
object ActivityTestTags {
    const val SCREEN = "activity_screen"
    const val LIST = "activity_list"
    const val ROW = "activity_row"
    const val UNREAD_DOT = "activity_unread_dot"
    const val APPEND_FOOTER = "activity_append_footer"
    const val APPEND_RETRY = "activity_append_retry"
    const val EMPTY = "activity_empty"
    const val ERROR = "activity_error"
}

/** AND-091 — route-level Activity feed entry, reached from the More hub. */
@Composable
fun ActivityFeedRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: ActivityViewModel = hiltViewModel(),
) {
    val items = viewModel.items.collectAsLazyPagingItems()
    ActivityFeedScreen(
        items = items,
        onRefresh = { items.refresh() },
        onBack = onBack,
        modifier = modifier,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ActivityFeedScreen(
    items: LazyPagingItems<ActivityEvent>,
    onRefresh: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val listState = rememberLazyListState()
    Scaffold(
        modifier = modifier.testTag(ActivityTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Activity") },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("activity_back")) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        val refreshState = items.loadState.refresh
        val isRefreshing = refreshState is LoadState.Loading && items.itemCount > 0
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            Box(Modifier.fillMaxSize()) {
                when {
                    refreshState is LoadState.Loading && items.itemCount == 0 -> LoadingState()

                    refreshState is LoadState.Error && items.itemCount == 0 -> {
                        val message = (refreshState.error as? ActivityLoadException)?.message
                            ?: "Couldn't load your activity."
                        ErrorState(
                            message = message,
                            onRetry = items::retry,
                            modifier = Modifier.testTag(ActivityTestTags.ERROR),
                        )
                    }

                    refreshState is LoadState.NotLoading && items.itemCount == 0 ->
                        EmptyState(
                            title = "No activity yet",
                            body = "Account events will show up here.",
                            modifier = Modifier.testTag(ActivityTestTags.EMPTY),
                        )

                    else -> ActivityList(items = items, listState = listState)
                }
            }
        }
    }
}

@Composable
private fun ActivityList(
    items: LazyPagingItems<ActivityEvent>,
    listState: androidx.compose.foundation.lazy.LazyListState,
) {
    LazyColumn(
        state = listState,
        modifier = Modifier.fillMaxSize().testTag(ActivityTestTags.LIST),
    ) {
        items(count = items.itemCount, key = { index -> items.peek(index)?.id ?: index }) { index ->
            val item = items[index]
            if (item != null) {
                ActivityRow(item = item)
            }
        }

        when (items.loadState.append) {
            is LoadState.Loading -> item {
                Box(
                    Modifier.fillMaxWidth().padding(16.dp).testTag(ActivityTestTags.APPEND_FOOTER),
                    contentAlignment = Alignment.Center,
                ) {
                    CircularProgressIndicator(modifier = Modifier.size(24.dp))
                }
            }
            is LoadState.Error -> item {
                Row(
                    Modifier.fillMaxWidth().padding(16.dp).testTag(ActivityTestTags.APPEND_FOOTER),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text("Couldn't load more.", style = MaterialTheme.typography.bodyMedium)
                    TextButton(
                        onClick = items::retry,
                        modifier = Modifier.testTag(ActivityTestTags.APPEND_RETRY),
                    ) { Text("Retry") }
                }
            }
            else -> Unit
        }
    }
}

@Composable
private fun ActivityRow(item: ActivityEvent) {
    val relative = remember(item.createdAtEpochSeconds) { relativeTime(item.createdAtEpochSeconds) }
    val title = remember(item.type, item.rawType) { titleFor(item) }
    val rowBackground = if (item.read) {
        Color.Transparent
    } else {
        MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f)
    }
    val readState = if (item.read) "read" else "unread"
    val cd = buildString {
        append(readState).append(": ").append(title)
        item.detail?.let { append(", ").append(it) }
        if (relative.isNotEmpty()) append(", ").append(relative)
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .background(rowBackground)
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .testTag(ActivityTestTags.ROW)
            .clearAndSetSemantics {
                contentDescription = cd
                stateDescription = readState
            },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(modifier = Modifier.size(24.dp), contentAlignment = Alignment.Center) {
            Icon(
                imageVector = iconFor(item.type),
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(20.dp),
            )
            if (!item.read) {
                Box(
                    modifier = Modifier
                        .align(Alignment.TopEnd)
                        .size(8.dp)
                        .clip(CircleShape)
                        .background(MaterialTheme.colorScheme.primary)
                        .testTag(ActivityTestTags.UNREAD_DOT),
                )
            }
        }
        Column(
            modifier = Modifier.padding(start = 12.dp).fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = if (item.read) FontWeight.Normal else FontWeight.SemiBold,
            )
            item.detail?.let {
                Text(
                    text = it,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (relative.isNotEmpty()) {
                Text(
                    text = relative,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

private fun iconFor(type: ActivityEventType): ImageVector = when (type) {
    ActivityEventType.LOGIN_SUCCESS, ActivityEventType.LOGIN_FAILED -> Icons.Filled.Login
    ActivityEventType.MFA_CHALLENGE -> Icons.Filled.Shield
    ActivityEventType.SESSION_REVOKED -> Icons.Filled.Security
    ActivityEventType.PASSWORD_CHANGED -> Icons.Filled.Lock
    ActivityEventType.SECURITY_ALERT -> Icons.Filled.Shield
    ActivityEventType.PROFILE_UPDATED, ActivityEventType.UNKNOWN -> Icons.Filled.Notifications
}

private fun titleFor(item: ActivityEvent): String = when (item.type) {
    ActivityEventType.LOGIN_SUCCESS -> "Successful sign-in"
    ActivityEventType.LOGIN_FAILED -> "Failed sign-in attempt"
    ActivityEventType.MFA_CHALLENGE -> "Two-factor challenge"
    ActivityEventType.SESSION_REVOKED -> "Session revoked"
    ActivityEventType.PASSWORD_CHANGED -> "Password changed"
    ActivityEventType.PROFILE_UPDATED -> "Profile updated"
    ActivityEventType.SECURITY_ALERT -> "Security alert"
    ActivityEventType.UNKNOWN -> item.rawType.ifBlank { "Account activity" }
        .replace('_', ' ')
        .replaceFirstChar { it.uppercase() }
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
