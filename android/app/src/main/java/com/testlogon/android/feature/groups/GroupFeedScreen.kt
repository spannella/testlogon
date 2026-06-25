@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.groups

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.paging.LoadState
import androidx.paging.compose.LazyPagingItems
import androidx.paging.compose.collectAsLazyPagingItems
import com.testlogon.android.R
import com.testlogon.android.core.model.groups.GroupFeedPost
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import kotlinx.coroutines.flow.collectLatest

/** Batch-8 (#11) - stable testTags for the group-feed screen. */
object GroupFeedTestTags {
    const val SCREEN = "group_feed_screen"
    const val COMPOSE_INPUT = "group_feed_compose_input"
    const val COMPOSE_SEND = "group_feed_compose_send"
    const val EMPTY = "group_feed_empty"
    const val ERROR_RETRY = "group_feed_error_retry"

    fun row(postId: String) = "group_feed_post_$postId"
}

/** Batch-8 (#11) - route-level group-feed entry (list + compose). */
@Composable
fun GroupFeedRoute(
    onBack: () -> Unit,
    viewModel: GroupFeedViewModel = hiltViewModel(),
) {
    val posts = viewModel.posts.collectAsLazyPagingItems()
    val composeState by viewModel.composeState.collectAsStateWithLifecycle()
    LaunchedEffect(viewModel) {
        viewModel.refreshSignal.collectLatest { posts.refresh() }
    }
    GroupFeedScreen(
        posts = posts,
        composeState = composeState,
        onBack = onBack,
        onTextChange = viewModel::onTextChange,
        onSubmit = viewModel::submit,
    )
}

@Composable
fun GroupFeedScreen(
    posts: LazyPagingItems<GroupFeedPost>,
    composeState: GroupComposeState,
    onBack: () -> Unit,
    onTextChange: (String) -> Unit,
    onSubmit: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(GroupFeedTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.group_feed_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.group_feed_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            ComposeBox(
                state = composeState,
                onTextChange = onTextChange,
                onSubmit = onSubmit,
            )
            HorizontalDivider()
            val refresh = posts.loadState.refresh
            PullToRefreshBox(
                isRefreshing = refresh is LoadState.Loading && posts.itemCount > 0,
                onRefresh = { posts.refresh() },
                modifier = Modifier.fillMaxSize(),
            ) {
                when {
                    refresh is LoadState.Loading && posts.itemCount == 0 ->
                        LoadingState()

                    refresh is LoadState.Error && posts.itemCount == 0 ->
                        ErrorState(
                            modifier = Modifier.testTag(GroupFeedTestTags.ERROR_RETRY),
                            message = stringResource(R.string.group_feed_error),
                            onRetry = { posts.retry() },
                        )

                    posts.itemCount == 0 ->
                        EmptyState(
                            modifier = Modifier.testTag(GroupFeedTestTags.EMPTY),
                            title = stringResource(R.string.group_feed_empty_title),
                            body = stringResource(R.string.group_feed_empty_body),
                        )

                    else -> LazyColumn(modifier = Modifier.fillMaxSize()) {
                        items(
                            count = posts.itemCount,
                            key = { index -> posts[index]?.postId ?: "post_$index" },
                        ) { index ->
                            val post = posts[index] ?: return@items
                            GroupPostRow(post)
                            HorizontalDivider()
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ComposeBox(
    state: GroupComposeState,
    onTextChange: (String) -> Unit,
    onSubmit: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxWidth().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        OutlinedTextField(
            value = state.text,
            onValueChange = onTextChange,
            enabled = !state.sending,
            label = { Text(stringResource(R.string.group_feed_compose_hint)) },
            modifier = Modifier.fillMaxWidth().testTag(GroupFeedTestTags.COMPOSE_INPUT),
        )
        val err = state.error
        if (err != null) {
            Text(text = err, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.End,
        ) {
            Button(
                onClick = onSubmit,
                enabled = state.text.isNotBlank() && !state.sending,
                modifier = Modifier.testTag(GroupFeedTestTags.COMPOSE_SEND),
            ) {
                if (state.sending) {
                    CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                } else {
                    Text(stringResource(R.string.group_feed_compose_send))
                }
            }
        }
    }
}

@Composable
private fun GroupPostRow(post: GroupFeedPost) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(GroupFeedTestTags.row(post.postId))
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                text = post.authorName,
                style = MaterialTheme.typography.titleSmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f, fill = false),
            )
            if (post.pinned) {
                Text(
                    text = stringResource(R.string.group_feed_pinned),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
        }
        val text = post.text
        if (post.locked) {
            Text(
                text = stringResource(R.string.group_feed_locked),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else if (!text.isNullOrBlank()) {
            Text(text = text, style = MaterialTheme.typography.bodyMedium)
        }
        if (post.commentCount > 0) {
            Text(
                text = "${post.commentCount}",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
