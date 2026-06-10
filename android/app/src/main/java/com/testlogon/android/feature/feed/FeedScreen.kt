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
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import kotlinx.coroutines.launch
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
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
    paywallViewModel: PaywallViewModel = hiltViewModel(),
    tipViewModel: TipViewModel = hiltViewModel(),
) {
    val items = viewModel.items.collectAsLazyPagingItems()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    val shareLauncher = remember { ShareLauncher() }
    val savedIds by viewModel.savedIds.collectAsState()
    val pollStates by viewModel.pollUiStates.collectAsState()
    val unlockStates by paywallViewModel.states.collectAsState()
    val tipState by tipViewModel.state.collectAsState()

    val hiddenLabel = stringResource(R.string.feed_hidden_snackbar)
    val notInterestedLabel = stringResource(R.string.feed_not_interested_snackbar)
    val undoLabel = stringResource(R.string.feed_action_undo)
    val retryLabel = stringResource(R.string.comments_retry)
    val bookmarkRetryLabel = stringResource(R.string.feed_bookmark_retry)
    val shareNoTargetLabel = stringResource(R.string.feed_share_no_target)

    // Drain feed one-shot effects: like errors, hide Undo/Retry, bookmark Retry.
    LaunchedEffect(viewModel) {
        viewModel.events.collect { event ->
            when (event) {
                is FeedEvent.UnlockRequested -> paywallViewModel.unlock(event.postId)
                is FeedEvent.ShowError ->
                    snackbarHostState.showSnackbar(event.message)
                is FeedEvent.Suppressed -> {
                    val msg = when (event.action) {
                        is FeedAction.Hide -> hiddenLabel
                        is FeedAction.NotInterested -> notInterestedLabel
                    }
                    val result = snackbarHostState.showSnackbar(
                        message = msg,
                        actionLabel = undoLabel,
                        duration = SnackbarDuration.Short,
                    )
                    if (result == SnackbarResult.ActionPerformed) viewModel.onUndo(event.action)
                }
                is FeedEvent.SuppressFailed -> {
                    val result = snackbarHostState.showSnackbar(
                        message = event.message,
                        actionLabel = retryLabel,
                        duration = SnackbarDuration.Short,
                    )
                    if (result == SnackbarResult.ActionPerformed) viewModel.onRetry(event.action)
                }
                is FeedEvent.BookmarkFailed -> {
                    val result = snackbarHostState.showSnackbar(
                        message = event.message,
                        actionLabel = bookmarkRetryLabel,
                        duration = SnackbarDuration.Short,
                    )
                    if (result == SnackbarResult.ActionPerformed) {
                        viewModel.onRetryBookmark(event.postId, event.desired)
                    }
                }
            }
        }
    }

    // Drain tip one-shot effects (host snackbar).
    LaunchedEffect(tipViewModel) {
        tipViewModel.effects.collect { effect ->
            when (effect) {
                is TipEffect.ShowSnackbar -> snackbarHostState.showSnackbar(effect.message)
            }
        }
    }

    // AND-177 — when a post becomes unlocked (entitlement confirmed + cached), re-fetch the feed so the
    // server returns the now-unlocked content. Content is NEVER revealed client-side before this (the
    // locked post was redacted at the mapper); the entitlement cache prevents a re-charge on refetch.
    val anyUnlocked = unlockStates.values.any { it is UnlockState.Unlocked }
    LaunchedEffect(anyUnlocked) {
        if (anyUnlocked) items.refresh()
    }

    FeedScreen(
        items = items,
        snackbarHostState = snackbarHostState,
        savedIds = savedIds,
        pollStates = pollStates,
        unlockStates = unlockStates,
        onRefresh = { items.refresh() },
        onPostClick = { post -> onPostClick(post.id) },
        onAuthorClick = onAuthorClick,
        onLinkClick = onLinkClick,
        onUnlockClick = viewModel::onUnlockClick,
        onLikeToggle = viewModel::onLikeToggle,
        onCommentClick = { post -> onPostClick(post.id) },
        onHide = { post, index -> viewModel.onHide(post.id, index) },
        onNotInterested = { post, index -> viewModel.onNotInterested(post.id, index) },
        onToggleBookmark = { post -> viewModel.onToggleBookmark(post.id, post.id in savedIds) },
        onShare = { post ->
            val ok = shareLauncher.share(context, ShareContent(PostShare.urlFor(post.id), PostShare.subjectFor(post.authorId)))
            if (!ok) coroutineScope.launch { snackbarHostState.showSnackbar(shareNoTargetLabel) }
        },
        onTip = { post -> tipViewModel.open(post.id) },
        onEnsurePoll = viewModel::ensurePollState,
        onPollOptionClick = viewModel::onPollOptionSelected,
        onPollRetry = viewModel::onPollRetry,
        modifier = modifier,
    )

    // AND-178 — the tip bottom sheet, host-scoped.
    TipSheet(
        state = tipState,
        onSelectPreset = tipViewModel::selectPreset,
        onCustomAmount = tipViewModel::setCustomAmount,
        onSend = tipViewModel::send,
        onDismiss = tipViewModel::dismiss,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FeedScreen(
    items: LazyPagingItems<FeedPost>,
    onRefresh: () -> Unit,
    onPostClick: (FeedPost) -> Unit,
    modifier: Modifier = Modifier,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
    savedIds: Set<String> = emptySet(),
    pollStates: Map<String, PollCardState> = emptyMap(),
    unlockStates: Map<String, UnlockState> = emptyMap(),
    onAuthorClick: (authorId: String) -> Unit = {},
    onLinkClick: (url: String) -> Unit = {},
    onUnlockClick: (postId: String) -> Unit = {},
    onLikeToggle: (FeedPost) -> Unit = {},
    onCommentClick: (FeedPost) -> Unit = {},
    onHide: (post: FeedPost, index: Int) -> Unit = { _, _ -> },
    onNotInterested: (post: FeedPost, index: Int) -> Unit = { _, _ -> },
    onToggleBookmark: (FeedPost) -> Unit = {},
    onShare: (FeedPost) -> Unit = {},
    onTip: (FeedPost) -> Unit = {},
    onEnsurePoll: (FeedPost) -> Unit = {},
    onPollOptionClick: (postId: String, questionId: String, optionId: String) -> Unit = { _, _, _ -> },
    onPollRetry: (postId: String, questionId: String, optionId: String) -> Unit = { _, _, _ -> },
) {
    val listState = rememberLazyListState()
    Scaffold(
        modifier = modifier.testTag(FeedTestTags.SCREEN),
        topBar = { TopAppBar(title = { Text("Feed") }) },
        snackbarHost = { SnackbarHost(snackbarHostState) },
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
                        savedIds = savedIds,
                        pollStates = pollStates,
                        unlockStates = unlockStates,
                        onPostClick = onPostClick,
                        onAuthorClick = onAuthorClick,
                        onLinkClick = onLinkClick,
                        onUnlockClick = onUnlockClick,
                        onLikeToggle = onLikeToggle,
                        onCommentClick = onCommentClick,
                        onHide = onHide,
                        onNotInterested = onNotInterested,
                        onToggleBookmark = onToggleBookmark,
                        onShare = onShare,
                        onTip = onTip,
                        onEnsurePoll = onEnsurePoll,
                        onPollOptionClick = onPollOptionClick,
                        onPollRetry = onPollRetry,
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
    savedIds: Set<String>,
    pollStates: Map<String, PollCardState>,
    unlockStates: Map<String, UnlockState>,
    onPostClick: (FeedPost) -> Unit,
    onAuthorClick: (authorId: String) -> Unit,
    onLinkClick: (url: String) -> Unit,
    onUnlockClick: (postId: String) -> Unit,
    onLikeToggle: (FeedPost) -> Unit,
    onCommentClick: (FeedPost) -> Unit,
    onHide: (post: FeedPost, index: Int) -> Unit,
    onNotInterested: (post: FeedPost, index: Int) -> Unit,
    onToggleBookmark: (FeedPost) -> Unit,
    onShare: (FeedPost) -> Unit,
    onTip: (FeedPost) -> Unit,
    onEnsurePoll: (FeedPost) -> Unit,
    onPollOptionClick: (postId: String, questionId: String, optionId: String) -> Unit,
    onPollRetry: (postId: String, questionId: String, optionId: String) -> Unit,
) {
    LazyColumn(
        state = listState,
        modifier = Modifier.fillMaxSize().testTag(FeedTestTags.LIST),
    ) {
        items(count = items.itemCount, key = { index -> items.peek(index)?.id ?: index }) { index ->
            val item = items[index]
            if (item != null) {
                // Seed per-post poll state once the post is composed (idempotent).
                LaunchedEffect(item.id) { if (item.poll != null) onEnsurePoll(item) }
                PostItem(
                    post = item,
                    onPostClick = onPostClick,
                    onAuthorClick = onAuthorClick,
                    onMediaClick = { post, _ -> onPostClick(post) },
                    onLinkClick = onLinkClick,
                    onUnlockClick = onUnlockClick,
                    onLikeToggle = onLikeToggle,
                    onCommentClick = onCommentClick,
                    onHide = { post -> onHide(post, index) },
                    onNotInterested = { post -> onNotInterested(post, index) },
                    isBookmarked = item.id in savedIds,
                    onToggleBookmark = onToggleBookmark,
                    onShare = onShare,
                    onTip = onTip,
                    unlockState = unlockStates[item.id] ?: UnlockState.Idle,
                    pollState = pollStates[item.id],
                    onPollOptionClick = onPollOptionClick,
                    onPollRetry = onPollRetry,
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
