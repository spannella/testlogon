@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.messaging.helpdesk

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Refresh
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
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.data.messaging.helpdesk.HelpdeskQueueItem
import com.testlogon.android.data.messaging.helpdesk.HelpdeskRoutingState
import com.testlogon.android.feature.messaging.relativeTimeFromSeconds

/** AND-161 — stable testTags for the helpdesk queue screen. */
object HelpdeskQueueTestTags {
    const val SCREEN = "helpdesk_queue_screen"
    const val LIST = "helpdesk_queue_list"
    const val ROW = "helpdesk_queue_row"
    const val LOADING = "helpdesk_queue_loading"
    const val EMPTY = "helpdesk_queue_empty"
    const val ERROR = "helpdesk_queue_error"
    const val NOT_AUTHORIZED = "helpdesk_queue_not_authorized"
    const val REFRESH = "helpdesk_queue_refresh"
}

/**
 * AND-161 — route-level helpdesk queue screen. Single bounded fetch rendered in a LazyColumn under a
 * PullToRefreshBox + toolbar refresh. 403 -> Not authorized (no toast); 200 [] -> empty. Row tap calls
 * [onOpenConversation] with the conversation id (consumed by the AND-162 detail).
 */
@Composable
fun HelpdeskQueueRoute(
    onOpenConversation: (conversationId: String, claimState: com.testlogon.android.data.messaging.helpdesk.ClaimState) -> Unit,
    onBack: () -> Unit,
    viewModel: HelpdeskQueueViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val refreshing = (state as? HelpdeskQueueUiState.Ready)?.isRefreshing == true

    Scaffold(
        modifier = Modifier.testTag(HelpdeskQueueTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.helpdesk_queue_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
                actions = {
                    IconButton(
                        onClick = viewModel::refresh,
                        modifier = Modifier.testTag(HelpdeskQueueTestTags.REFRESH),
                    ) {
                        Icon(
                            Icons.Filled.Refresh,
                            contentDescription = stringResource(R.string.helpdesk_queue_refresh_cd),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (val s = state) {
                HelpdeskQueueUiState.Loading ->
                    Box(Modifier.fillMaxSize(), Alignment.Center) {
                        CircularProgressIndicator(Modifier.testTag(HelpdeskQueueTestTags.LOADING))
                    }
                HelpdeskQueueUiState.NotAuthorized ->
                    CenteredMessage(
                        text = stringResource(R.string.helpdesk_queue_not_authorized),
                        tag = HelpdeskQueueTestTags.NOT_AUTHORIZED,
                    )
                is HelpdeskQueueUiState.Error ->
                    Column(
                        Modifier.fillMaxSize().padding(24.dp).testTag(HelpdeskQueueTestTags.ERROR),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Center,
                    ) {
                        Text(s.message, style = MaterialTheme.typography.bodyLarge)
                        Spacer(Modifier.size(12.dp))
                        if (s.retryable) {
                            TextButton(onClick = viewModel::retry) {
                                Text(stringResource(R.string.action_retry))
                            }
                        }
                    }
                is HelpdeskQueueUiState.Ready ->
                    PullToRefreshBox(
                        isRefreshing = refreshing,
                        onRefresh = viewModel::refresh,
                        modifier = Modifier.fillMaxSize(),
                    ) {
                        if (s.items.isEmpty()) {
                            CenteredMessage(
                                text = stringResource(R.string.helpdesk_queue_empty),
                                tag = HelpdeskQueueTestTags.EMPTY,
                            )
                        } else {
                            LazyColumn(Modifier.fillMaxSize().testTag(HelpdeskQueueTestTags.LIST)) {
                                items(s.items, key = { it.conversationId }) { item ->
                                    HelpdeskQueueRow(
                                        item = item,
                                        onClick = { onOpenConversation(item.conversationId, item.claimState) },
                                    )
                                }
                            }
                        }
                    }
            }
        }
    }
}

@Composable
private fun HelpdeskQueueRow(item: HelpdeskQueueItem, onClick: () -> Unit) {
    Column(
        Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(16.dp)
            .testTag(HelpdeskQueueTestTags.ROW),
    ) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = item.title ?: stringResource(R.string.helpdesk_queue_untitled),
                style = MaterialTheme.typography.titleMedium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f),
            )
            Text(
                text = routingBadge(item.routingState),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.primary,
            )
        }
        item.preview?.let {
            Text(
                text = it,
                style = MaterialTheme.typography.bodyMedium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            item.activeAgentUserId?.takeIf { it.isNotBlank() }?.let {
                Text(
                    text = stringResource(R.string.helpdesk_queue_claimed),
                    style = MaterialTheme.typography.labelSmall,
                    modifier = Modifier.weight(1f),
                )
            } ?: Spacer(Modifier.weight(1f))
            if (item.unreadCount > 0) {
                Text(
                    text = stringResource(R.string.helpdesk_queue_unread, item.unreadCount),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.primary,
                )
                Spacer(Modifier.size(8.dp))
            }
            item.lastMessageAtEpochSeconds?.takeIf { it > 0L }?.let {
                Text(
                    text = relativeTimeFromSeconds(it),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun routingBadge(state: HelpdeskRoutingState): String = stringResource(
    when (state) {
        HelpdeskRoutingState.AWAITING_AGENT -> R.string.helpdesk_badge_waiting
        HelpdeskRoutingState.ASSIGNED -> R.string.helpdesk_badge_assigned
        HelpdeskRoutingState.PAUSED_NO_AGENTS_ONLINE -> R.string.helpdesk_badge_paused
        HelpdeskRoutingState.CLOSED -> R.string.helpdesk_badge_closed
        HelpdeskRoutingState.UNKNOWN -> R.string.helpdesk_badge_unknown
    },
)

@Composable
private fun CenteredMessage(text: String, tag: String) {
    Box(Modifier.fillMaxSize().testTag(tag), Alignment.Center) {
        Text(text, style = MaterialTheme.typography.bodyLarge)
    }
}
