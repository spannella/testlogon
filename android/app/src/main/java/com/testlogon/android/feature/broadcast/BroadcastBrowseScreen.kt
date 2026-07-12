@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.broadcast

import com.testlogon.android.feature.broadcast.audioroom.AudioRoomDiscoverySection
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.NotificationAdd
import androidx.compose.material.icons.outlined.NotificationsActive
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material.icons.outlined.Videocam
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.hilt.navigation.compose.hiltViewModel
import coil.compose.AsyncImage
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner
import com.testlogon.android.data.broadcast.BroadcastSessionStatus
import kotlinx.coroutines.flow.collectLatest
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle

/** AND-279 — stable testTags for the browse screen. */
object BroadcastBrowseTestTags {
    const val TAB_LIVE = "broadcast_tab_live"
    const val TAB_UPCOMING = "broadcast_tab_upcoming"
    const val TAB_PAST = "broadcast_tab_past"
    const val LIST = "broadcast_list"
    const val REMINDER_SWITCH = "broadcast_reminder_switch"
}

/** Stable testTag for the host "Go Live" (create -> ingest) FAB on the broadcast browse screen. */
const val BROADCAST_GO_LIVE_FAB = "broadcast_go_live_fab"

/**
 * AND-279 — browse entry point. Collects the ViewModel state, resolves transient reminder-failure
 * effects against [LocalContext], and forwards the session-tap callback to the host (the viewer route
 * is owned by AND-280).
 */
@Composable
fun BroadcastBrowseRoute(
    onBack: () -> Unit,
    onSessionClick: (sessionId: String, status: BroadcastSessionStatus) -> Unit,
    onGoLiveHost: () -> Unit = {},
    onOpenAudioRoom: (String) -> Unit = {},
    viewModel: BroadcastBrowseViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val reminderFailed = stringResource(R.string.broadcast_reminder_failed)
    androidx.compose.runtime.LaunchedEffect(viewModel) {
        viewModel.events.collectLatest { event ->
            when (event) {
                BroadcastBrowseEvent.ReminderFailed ->
                    android.widget.Toast.makeText(context, reminderFailed, android.widget.Toast.LENGTH_SHORT).show()
            }
        }
    }
    BroadcastBrowseScreen(
        state = state,
        onBack = onBack,
        onSelectBucket = viewModel::selectBucket,
        onSessionClick = onSessionClick,
        onToggleReminder = viewModel::toggleReminder,
        onRetry = viewModel::retry,
        onGoLiveHost = onGoLiveHost,
        onOpenAudioRoom = onOpenAudioRoom,
    )
}

@Composable
fun BroadcastBrowseScreen(
    state: BroadcastUiState,
    onBack: () -> Unit,
    onSelectBucket: (BroadcastBucket) -> Unit,
    onSessionClick: (String, BroadcastSessionStatus) -> Unit,
    onToggleReminder: (String, Boolean) -> Unit,
    onRetry: () -> Unit,
    onGoLiveHost: () -> Unit = {},
    onOpenAudioRoom: (String) -> Unit = {},
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.broadcast_browse_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.viewer_back_cd),
                        )
                    }
                },
            )
        },
        floatingActionButton = {
            // Host entry to the camera/mic publish flow (create session -> ingest). Previously the only
            // broadcast surface reachable from the dashboard "Go Live" was this viewer list, so the real
            // host go-live (camera publish) screen was unreachable. This FAB wires it up.
            ExtendedFloatingActionButton(
                onClick = onGoLiveHost,
                icon = { Icon(Icons.Outlined.Videocam, contentDescription = null) },
                text = { Text(stringResource(R.string.broadcast_go_live_title)) },
                modifier = Modifier.testTag(BROADCAST_GO_LIVE_FAB),
            )
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            // #104 AUDIO ROOM — audio-rooms strip (Start + live audio rooms), distinct from the video list.
            AudioRoomDiscoverySection(onOpenAudioRoom = onOpenAudioRoom)
            val content = state.contentOrCached()
            if (content != null) {
                BucketTabs(content = content, onSelectBucket = onSelectBucket)
            }
            when (state) {
                BroadcastUiState.Loading -> LoadingState()
                is BroadcastUiState.Content -> BucketBody(
                    content = state,
                    isStale = state.isStale,
                    offline = false,
                    onSessionClick = onSessionClick,
                    onToggleReminder = onToggleReminder,
                )
                is BroadcastUiState.Error -> {
                    val cached = state.cached
                    if (cached != null) {
                        if (state.cause is BroadcastError.Network) {
                            OfflineBanner(onRetry = onRetry)
                        }
                        BucketBody(
                            content = cached,
                            isStale = true,
                            offline = state.cause is BroadcastError.Network,
                            onSessionClick = onSessionClick,
                            onToggleReminder = onToggleReminder,
                        )
                    } else {
                        ErrorState(
                            message = state.cause.message(),
                            onRetry = onRetry,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun BucketTabs(
    content: BroadcastUiState.Content,
    onSelectBucket: (BroadcastBucket) -> Unit,
) {
    val selectedIndex = content.selected.ordinal
    TabRow(selectedTabIndex = selectedIndex) {
        Tab(
            selected = content.selected == BroadcastBucket.LIVE,
            onClick = { onSelectBucket(BroadcastBucket.LIVE) },
            modifier = Modifier.testTag(BroadcastBrowseTestTags.TAB_LIVE),
            text = {
                if (content.live.isNotEmpty()) {
                    BadgedBox(badge = { Badge { Text("${content.live.size}") } }) {
                        Text(stringResource(R.string.broadcast_bucket_live))
                    }
                } else {
                    Text(stringResource(R.string.broadcast_bucket_live))
                }
            },
        )
        Tab(
            selected = content.selected == BroadcastBucket.UPCOMING,
            onClick = { onSelectBucket(BroadcastBucket.UPCOMING) },
            modifier = Modifier.testTag(BroadcastBrowseTestTags.TAB_UPCOMING),
            text = { Text(stringResource(R.string.broadcast_bucket_upcoming)) },
        )
        Tab(
            selected = content.selected == BroadcastBucket.PAST,
            onClick = { onSelectBucket(BroadcastBucket.PAST) },
            modifier = Modifier.testTag(BroadcastBrowseTestTags.TAB_PAST),
            text = { Text(stringResource(R.string.broadcast_bucket_past)) },
        )
    }
}

@Composable
private fun BucketBody(
    content: BroadcastUiState.Content,
    isStale: Boolean,
    offline: Boolean,
    onSessionClick: (String, BroadcastSessionStatus) -> Unit,
    onToggleReminder: (String, Boolean) -> Unit,
) {
    val items = when (content.selected) {
        BroadcastBucket.LIVE -> content.live
        BroadcastBucket.UPCOMING -> content.upcoming
        BroadcastBucket.PAST -> content.past
    }
    if (items.isEmpty()) {
        EmptyState(
            title = stringResource(R.string.broadcast_empty_title),
            body = stringResource(content.selected.emptyBody()),
        )
        return
    }
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag(BroadcastBrowseTestTags.LIST),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        items(items, key = { it.sessionId }) { item ->
            BroadcastCard(
                item = item,
                bucket = content.selected,
                reminderEnabled = !offline,
                onClick = { onSessionClick(item.sessionId, item.status) },
                onToggleReminder = { enable -> onToggleReminder(item.sessionId, enable) },
            )
        }
    }
}

@Composable
private fun BroadcastCard(
    item: BroadcastItem,
    bucket: BroadcastBucket,
    reminderEnabled: Boolean,
    onClick: () -> Unit,
    onToggleReminder: (Boolean) -> Unit,
) {
    Surface(
        tonalElevation = 1.dp,
        shape = MaterialTheme.shapes.medium,
        onClick = onClick,
        modifier = Modifier
            .fillMaxWidth()
            .semantics(mergeDescendants = true) { role = Role.Button },
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            AsyncImage(
                model = item.thumbnailUrl,
                contentDescription = stringResource(R.string.broadcast_thumbnail_cd),
                modifier = Modifier.size(72.dp),
            )
            Column(
                modifier = Modifier
                    .padding(horizontal = 12.dp)
                    .weight(1f),
            ) {
                StatusPill(item.status)
                Text(
                    text = item.title,
                    style = MaterialTheme.typography.titleMedium,
                    maxLines = 2,
                )
                item.hostName?.let {
                    Text(
                        text = stringResource(R.string.broadcast_host, it),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Text(
                    text = item.timeLabel(),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                item.viewerCount?.let { count ->
                    Text(
                        text = pluralStringResource(R.plurals.broadcast_viewer_count, count, count),
                        style = MaterialTheme.typography.labelSmall,
                    )
                }
            }
            // Reminder toggle only on Upcoming-with-future-start (AND-279 FR-5/AC-5).
            if (bucket == BroadcastBucket.UPCOMING) {
                val cd = stringResource(R.string.broadcast_reminder_cd, item.title)
                Box(contentAlignment = Alignment.Center) {
                    if (item.reminderPending) {
                        CircularProgressIndicator(modifier = Modifier.size(24.dp))
                    } else {
                        Switch(
                            checked = item.reminderSet,
                            enabled = reminderEnabled,
                            onCheckedChange = onToggleReminder,
                            modifier = Modifier
                                .testTag(BroadcastBrowseTestTags.REMINDER_SWITCH)
                                .semantics { role = Role.Switch; contentDescription = cd },
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun StatusPill(status: BroadcastSessionStatus) {
    val (labelRes, icon) = when {
        status == BroadcastSessionStatus.LIVE ->
            R.string.broadcast_status_live to Icons.Outlined.NotificationsActive
        status == BroadcastSessionStatus.SCHEDULED ||
            status == BroadcastSessionStatus.PROVISIONING ||
            status == BroadcastSessionStatus.READY ||
            status == BroadcastSessionStatus.DRAFT ->
            R.string.broadcast_status_scheduled to Icons.Outlined.NotificationAdd
        else -> R.string.broadcast_status_ended to Icons.Outlined.NotificationAdd
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(icon, contentDescription = null, modifier = Modifier.size(14.dp))
        Text(
            text = stringResource(labelRes),
            style = MaterialTheme.typography.labelSmall,
            modifier = Modifier.padding(start = 4.dp),
        )
    }
}

@Composable
private fun BroadcastItem.timeLabel(): String {
    val fmt = remember { DateTimeFormatter.ofLocalizedDateTime(FormatStyle.SHORT).withZone(ZoneId.systemDefault()) }
    return when {
        actualStart != null && endedAt == null ->
            stringResource(R.string.broadcast_started_at, fmt.format(actualStart))
        endedAt != null -> stringResource(R.string.broadcast_ended_label)
        scheduledStart != null ->
            stringResource(R.string.broadcast_scheduled_at, fmt.format(scheduledStart))
        else -> stringResource(R.string.broadcast_ended_label)
    }
}

private fun BroadcastBucket.emptyBody(): Int = when (this) {
    BroadcastBucket.LIVE -> R.string.broadcast_empty_live
    BroadcastBucket.UPCOMING -> R.string.broadcast_empty_upcoming
    BroadcastBucket.PAST -> R.string.broadcast_empty_past
}

@Composable
private fun BroadcastError.message(): String = when (this) {
    is BroadcastError.Server -> message
    BroadcastError.Network -> stringResource(R.string.viewer_offline)
    BroadcastError.Auth -> stringResource(R.string.viewer_unavailable_not_authorized)
    BroadcastError.Unknown -> stringResource(R.string.broadcast_error_generic)
}

private fun BroadcastUiState.contentOrCached(): BroadcastUiState.Content? = when (this) {
    is BroadcastUiState.Content -> this
    is BroadcastUiState.Error -> cached
    BroadcastUiState.Loading -> null
}
