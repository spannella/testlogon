package com.testlogon.android.feature.messaging.list

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
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.GroupAdd
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.outlined.ChatBubbleOutline
import androidx.compose.material3.Badge
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
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
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
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
import com.testlogon.android.feature.messaging.relativeTimeFromSeconds

/** Stable testTags for the conversation list (AND-121). */
object ConversationListTestTags {
    const val SCREEN = "conv_list_screen"
    const val LIST = "conv_list"
    const val ROW = "conv_row"
    const val UNREAD_BADGE = "conv_unread_badge"
    const val STALE_BANNER = "conv_stale_banner"

    /** AND-152 — global message-search entry icon. */
    const val SEARCH = "conv_list_search"

    /** AND-157 — new-group FAB. */
    const val NEW_GROUP = "conv_list_new_group"
}

/** AND-121 — route-level conversation list, reached from the Messages tab / More hub. */
@Composable
fun ConversationListRoute(
    onOpenConversation: (String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    onOpenSearch: () -> Unit = {},
    onNewGroup: () -> Unit = {},
    viewModel: ConversationListViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is ConversationListEvent.ShowSnackbar -> snackbarHostState.showSnackbar(event.message)
            }
        }
    }

    ConversationListScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        onOpenConversation = onOpenConversation,
        onOpenSearch = onOpenSearch,
        onNewGroup = onNewGroup,
        onBack = onBack,
        modifier = modifier,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConversationListScreen(
    state: ConversationListUiState,
    snackbarHostState: SnackbarHostState,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onOpenConversation: (String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    onOpenSearch: () -> Unit = {},
    onNewGroup: () -> Unit = {},
) {
    Scaffold(
        modifier = modifier.testTag(ConversationListTestTags.SCREEN),
        floatingActionButton = {
            FloatingActionButton(
                onClick = onNewGroup,
                modifier = Modifier.testTag(ConversationListTestTags.NEW_GROUP),
            ) {
                Icon(
                    Icons.Filled.GroupAdd,
                    contentDescription = stringResource(R.string.group_new_group_cd),
                )
            }
        },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.conv_list_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
                actions = {
                    // AND-152 — open global (cross-conversation) message search.
                    IconButton(
                        onClick = onOpenSearch,
                        modifier = Modifier.testTag(ConversationListTestTags.SEARCH),
                    ) {
                        Icon(
                            Icons.Filled.Search,
                            contentDescription = stringResource(R.string.search_messages),
                        )
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                is ConversationListUiState.Loading -> LoadingState()
                is ConversationListUiState.Empty ->
                    EmptyState(
                        title = stringResource(R.string.conv_list_empty_title),
                        body = stringResource(R.string.conv_list_empty_body),
                        imageVector = Icons.Outlined.ChatBubbleOutline,
                    )
                is ConversationListUiState.Error ->
                    ErrorState(message = state.message, onRetry = onRetry)
                is ConversationListUiState.Content ->
                    ConversationContent(
                        content = state,
                        onRefresh = onRefresh,
                        onOpenConversation = onOpenConversation,
                    )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ConversationContent(
    content: ConversationListUiState.Content,
    onRefresh: () -> Unit,
    onOpenConversation: (String) -> Unit,
) {
    PullToRefreshBox(
        isRefreshing = content.isRefreshing,
        onRefresh = onRefresh,
        modifier = Modifier.fillMaxSize(),
    ) {
        Column(Modifier.fillMaxSize()) {
            if (content.staleReason == StaleReason.OFFLINE) {
                OfflineBanner(
                    modifier = Modifier.testTag(ConversationListTestTags.STALE_BANNER),
                    onRetry = onRefresh,
                )
            } else if (content.staleReason == StaleReason.SERVER_ERROR) {
                Surface(
                    color = MaterialTheme.colorScheme.errorContainer,
                    contentColor = MaterialTheme.colorScheme.onErrorContainer,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag(ConversationListTestTags.STALE_BANNER),
                ) {
                    Text(
                        text = stringResource(R.string.conv_list_refresh_failed),
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
                    )
                }
            }
            LazyColumn(
                modifier = Modifier.fillMaxSize().testTag(ConversationListTestTags.LIST),
            ) {
                items(content.rows, key = { it.id }) { row ->
                    ConversationRowItem(row = row, onClick = { onOpenConversation(row.id) })
                }
            }
        }
    }
}

@Composable
internal fun ConversationRowItem(row: ConversationRow, onClick: () -> Unit) {
    val relative = remember(row.lastActivityEpochSeconds) {
        relativeTimeFromSeconds(row.lastActivityEpochSeconds)
    }
    val previewText = row.preview ?: stringResource(R.string.conv_list_no_messages)
    val unreadLabel = if (row.isUnread) "${row.unreadCount} unread, " else ""
    val cd = "${row.title}, $unreadLabel$relative, $previewText"

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .testTag(ConversationListTestTags.ROW)
            .clearAndSetSemantics {
                contentDescription = cd
                role = Role.Button
            },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Surface(
            color = MaterialTheme.colorScheme.surfaceVariant,
            modifier = Modifier.size(40.dp).clip(CircleShape),
        ) {
            Box(contentAlignment = Alignment.Center) {
                Text(
                    text = row.title.firstOrNull()?.uppercase() ?: "?",
                    style = MaterialTheme.typography.titleMedium,
                )
            }
        }
        Column(
            modifier = Modifier.weight(1f).padding(start = 12.dp),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Text(
                text = row.title,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = if (row.isUnread) FontWeight.SemiBold else FontWeight.Normal,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = previewText,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontWeight = if (row.isUnread) FontWeight.Medium else FontWeight.Normal,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        Column(
            horizontalAlignment = Alignment.End,
            verticalArrangement = Arrangement.spacedBy(4.dp),
            modifier = Modifier.padding(start = 8.dp),
        ) {
            if (relative.isNotEmpty()) {
                Text(
                    text = relative,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (row.isUnread) {
                Badge(modifier = Modifier.testTag(ConversationListTestTags.UNREAD_BADGE)) {
                    Text(if (row.unreadCount > 99) "99+" else row.unreadCount.toString())
                }
            }
        }
    }
}
