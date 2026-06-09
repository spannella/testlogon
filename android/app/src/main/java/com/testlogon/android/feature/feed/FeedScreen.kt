package com.testlogon.android.feature.feed

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.paging.LoadState
import androidx.paging.compose.LazyPagingItems
import androidx.paging.compose.collectAsLazyPagingItems
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.feed.FeedPost

/** Stable test tags for the feed surface (AND-098). */
object FeedTestTags {
    const val SCREEN = "feed_screen"
    const val LIST = "feed_list"
    const val APPEND_FOOTER = "feed_append_footer"
    const val APPEND_RETRY = "feed_append_retry"
    const val EMPTY = "feed_empty"
    const val ERROR = "feed_error"
}

/**
 * AND-098 / AND-102 — feed tab route. Hosts the Paging 3 stream, pull-to-refresh, and the
 * loading/empty/error/append-footer scaffolding; rows are [PostItem] (AND-099). [onPostClick] opens
 * the post-detail destination. The unlock CTA is a deferred stub routed through the ViewModel.
 */
@Composable
fun FeedRoute(
    onPostClick: (postId: String) -> Unit,
    modifier: Modifier = Modifier,
    onAuthorClick: (authorId: String) -> Unit = {},
    onLinkClick: (url: String) -> Unit = {},
    viewModel: FeedViewModel = hiltViewModel(),
) {
    // Drain one-shot events (e.g. unlock CTA) so they don't buffer; M2 has no UI effect yet.
    LaunchedEffect(viewModel) { viewModel.events.collect { /* TODO(AND-E24): purchase flow */ } }

    val items = viewModel.items.collectAsLazyPagingItems()
    FeedScreen(
        items = items,
        onRefresh = { items.refresh() },
        onPostClick = { post -> onPostClick(post.id) },
        onAuthorClick = onAuthorClick,
        onLinkClick = onLinkClick,
        onUnlockClick = viewModel::onUnlockClick,
        modifier = modifier,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FeedScreen(
    items: LazyPagingItems<FeedPost>,
    onRefresh: () -> Unit,
    onPostClick: (FeedPost) -> Unit,
    modifier: Modifier = Modifier,
    onAuthorClick: (authorId: String) -> Unit = {},
    onLinkClick: (url: String) -> Unit = {},
    onUnlockClick: (postId: String) -> Unit = {},
) {
    val listState = rememberLazyListState()
    Scaffold(
        modifier = modifier.testTag(FeedTestTags.SCREEN),
        topBar = { TopAppBar(title = { Text("Feed") }) },
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
                        val message = (refreshState.error as? FeedLoadException)?.message
                            ?: "Couldn't load your feed."
                        ErrorState(
                            message = message,
                            onRetry = items::retry,
                            modifier = Modifier.testTag(FeedTestTags.ERROR),
                        )
                    }

                    refreshState is LoadState.NotLoading && items.itemCount == 0 ->
                        EmptyState(
                            title = "Your feed is empty",
                            body = "New posts will show up here.",
                            modifier = Modifier.testTag(FeedTestTags.EMPTY),
                        )

                    else -> FeedList(
                        items = items,
                        listState = listState,
                        onPostClick = onPostClick,
                        onAuthorClick = onAuthorClick,
                        onLinkClick = onLinkClick,
                        onUnlockClick = onUnlockClick,
                    )
                }
            }
        }
    }
}

@Composable
private fun FeedList(
    items: LazyPagingItems<FeedPost>,
    listState: androidx.compose.foundation.lazy.LazyListState,
    onPostClick: (FeedPost) -> Unit,
    onAuthorClick: (authorId: String) -> Unit,
    onLinkClick: (url: String) -> Unit,
    onUnlockClick: (postId: String) -> Unit,
) {
    LazyColumn(
        state = listState,
        modifier = Modifier.fillMaxSize().testTag(FeedTestTags.LIST),
    ) {
        items(count = items.itemCount, key = { index -> items.peek(index)?.id ?: index }) { index ->
            val item = items[index]
            if (item != null) {
                PostItem(
                    post = item,
                    onPostClick = onPostClick,
                    onAuthorClick = onAuthorClick,
                    onMediaClick = { post, _ -> onPostClick(post) },
                    onLinkClick = onLinkClick,
                    onUnlockClick = onUnlockClick,
                )
            }
        }

        when (items.loadState.append) {
            is LoadState.Loading -> item {
                Box(
                    Modifier.fillMaxWidth().padding(16.dp).testTag(FeedTestTags.APPEND_FOOTER)
                        .semantics { contentDescription = "Loading more posts" },
                    contentAlignment = Alignment.Center,
                ) {
                    CircularProgressIndicator(modifier = Modifier.size(24.dp))
                }
            }
            is LoadState.Error -> item {
                androidx.compose.foundation.layout.Row(
                    Modifier.fillMaxWidth().padding(16.dp).testTag(FeedTestTags.APPEND_FOOTER),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text("Couldn't load more.", style = MaterialTheme.typography.bodyMedium)
                    TextButton(
                        onClick = items::retry,
                        modifier = Modifier.testTag(FeedTestTags.APPEND_RETRY),
                    ) { Text("Retry") }
                }
            }
            else -> Unit
        }
    }
}
