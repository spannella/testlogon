@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.discover

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
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
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.paging.LoadState
import androidx.paging.compose.LazyPagingItems
import androidx.paging.compose.collectAsLazyPagingItems
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.feed.FeedPost
import com.testlogon.android.data.report.ReportTarget
import com.testlogon.android.feature.feed.PostItem
import com.testlogon.android.feature.report.ContentReportSheetHost

/** AND-183 — stable test tags. */
object TagPageTestTags {
    const val SCREEN = "tag_page_screen"
    const val LIST = "tag_page_list"
    const val APPEND_FOOTER = "tag_page_append_footer"
    const val APPEND_RETRY = "tag_page_append_retry"
}

/**
 * AND-183 — route-level tag page. Collects the paged posts and renders [TagPageScreen]. Tapping a post
 * navigates to post detail (owned by AND-100). The post action bar is hidden — this is a read-only
 * discovery surface (engagement is owned by the feed).
 */
@Composable
fun TagPageRoute(
    onPostClick: (postId: String) -> Unit,
    onAuthorClick: (authorId: String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: TagPageViewModel = hiltViewModel(),
) {
    val items = viewModel.content.collectAsLazyPagingItems()
    TagPageScreen(
        title = viewModel.uiState.titleDisplay,
        tag = viewModel.uiState.tag,
        items = items,
        onRefresh = { items.refresh() },
        onPostClick = onPostClick,
        onAuthorClick = onAuthorClick,
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun TagPageScreen(
    title: String,
    tag: String,
    items: LazyPagingItems<FeedPost>,
    onRefresh: () -> Unit,
    onPostClick: (postId: String) -> Unit,
    onAuthorClick: (authorId: String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    // MOD-5 — these are OTHER users' posts (a public tag/discovery surface), so they must be reportable.
    // Same call-site pattern as the feed: hold the target, host the sheet once, open it from the post's
    // report overflow with a feed_post content ref.
    var reportTarget by remember { mutableStateOf<ReportTarget?>(null) }
    Scaffold(
        modifier = modifier.testTag(TagPageTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(title) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
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
                        val message = (refreshState.error as? TagLoadException)?.message
                            ?: stringResource(R.string.tag_page_error)
                        ErrorState(message = message, onRetry = items::retry)
                    }

                    refreshState is LoadState.NotLoading && items.itemCount == 0 ->
                        EmptyState(title = stringResource(R.string.tag_page_empty, tag))

                    else -> TagPostList(
                        items = items,
                        onPostClick = onPostClick,
                        onAuthorClick = onAuthorClick,
                        onReport = { post -> reportTarget = ReportTarget.Content(post.id, "feed_post") },
                    )
                }
            }
        }
        // MOD-5 — one host renders the six-category report sheet (+ licensing -> DMCA route) for this list.
        ContentReportSheetHost(target = reportTarget, onDismiss = { reportTarget = null })
    }
}

@Composable
private fun TagPostList(
    items: LazyPagingItems<FeedPost>,
    onPostClick: (postId: String) -> Unit,
    onAuthorClick: (authorId: String) -> Unit,
    onReport: (FeedPost) -> Unit,
) {
    LazyColumn(modifier = Modifier.fillMaxSize().testTag(TagPageTestTags.LIST)) {
        items(count = items.itemCount, key = { index -> items.peek(index)?.id ?: index }) { index ->
            val post = items[index]
            if (post != null) {
                PostItem(
                    post = post,
                    onPostClick = { onPostClick(post.id) },
                    onAuthorClick = onAuthorClick,
                    onMediaClick = { _, _ -> onPostClick(post.id) },
                    // Read-only discovery surface: no engagement action bar here.
                    showActionBar = false,
                    // MOD-5 — still allow reporting another user's post via the compact header overflow.
                    onReport = { onReport(post) },
                )
            }
        }

        when (items.loadState.append) {
            is LoadState.Loading -> item {
                Box(
                    Modifier.fillMaxWidth().padding(16.dp).testTag(TagPageTestTags.APPEND_FOOTER)
                        .semantics { contentDescription = "Loading more posts" },
                    contentAlignment = Alignment.Center,
                ) {
                    CircularProgressIndicator(modifier = Modifier.size(24.dp))
                }
            }
            is LoadState.Error -> item {
                androidx.compose.foundation.layout.Row(
                    Modifier.fillMaxWidth().padding(16.dp).testTag(TagPageTestTags.APPEND_FOOTER),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = stringResource(R.string.tag_page_append_error),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    TextButton(
                        onClick = { items.retry() },
                        modifier = Modifier.testTag(TagPageTestTags.APPEND_RETRY),
                    ) { Text(stringResource(R.string.action_retry)) }
                }
            }
            else -> Unit
        }
    }
}
