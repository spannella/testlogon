package com.testlogon.android.feature.feed

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.runtime.remember
import com.testlogon.android.data.report.ReportTarget
import com.testlogon.android.feature.report.ContentReportSheetHost
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** Stable test tags for the post-detail surface (AND-100). */
object PostDetailTestTags {
    const val SCREEN = "post_detail_screen"
    const val CONTENT = "post_detail_content"
    const val NOT_FOUND = "post_detail_not_found"
    const val FORBIDDEN = "post_detail_forbidden"
    const val ERROR = "post_detail_error"
    const val BACK = "post_detail_back"
}

/** AND-100 — read-only post-detail route (reached by in-app nav or deep link). */
@Composable
fun PostDetailRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    onAuthorClick: (authorId: String) -> Unit = {},
    onLinkClick: (url: String) -> Unit = {},
    // SUB-E3-2 - open the subscribe flow for a subscriber-only post lock card.
    onSubscribeClick: (creatorId: String) -> Unit = {},
    // TIPX-B3 (F3) - navigate to add-card when an empty-wallet tipper wants to tip a comment.
    onAddCard: () -> Unit = {},
    viewModel: PostDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val authorNames by viewModel.authorNames.collectAsStateWithLifecycle()
    val isOwnPost by viewModel.isOwnPost.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            if (effect is PostDetailEffect.ShowError) snackbarHostState.showSnackbar(effect.message)
        }
    }
    val shownAuthorId = (state as? PostDetailUiState.Content)?.post?.authorId
    LaunchedEffect(shownAuthorId) { shownAuthorId?.let { viewModel.resolveAuthor(it) } }
    PostDetailScreen(
        state = state,
        authorName = shownAuthorId?.let { authorNames[it] },
        onBack = onBack,
        onRetry = viewModel::retry,
        onRefresh = viewModel::refresh,
        snackbarHostState = snackbarHostState,
        onAuthorClick = onAuthorClick,
        onLinkClick = onLinkClick,
        onSubscribeClick = onSubscribeClick,
        onLikeToggle = { viewModel.onLikeToggle() },
        onToggleReaction = { emoji -> viewModel.onToggleReaction(emoji) },
        onRepost = { viewModel.onRepost() },
        onQuoteRepost = { quote -> viewModel.onRepost(quote) },
        onUndoRepost = { viewModel.onUndoRepost() },
        onCommentCountChanged = viewModel::onCommentCountChanged,
        isOwnPost = isOwnPost,
        commentsContent = { onCount ->
            CommentsSection(onCommentCountChanged = onCount, isOwnPost = isOwnPost, onAddCard = onAddCard)
        },
        modifier = modifier,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PostDetailScreen(
    state: PostDetailUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onRefresh: () -> Unit,
    modifier: Modifier = Modifier,
    authorName: String? = null,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
    onAuthorClick: (authorId: String) -> Unit = {},
    onLinkClick: (url: String) -> Unit = {},
    onSubscribeClick: (creatorId: String) -> Unit = {},
    onLikeToggle: () -> Unit = {},
    onToggleReaction: (emoji: String) -> Unit = {},
    // SOCIAL-002 — repost / quote-repost / undo-repost of the detail post.
    onRepost: () -> Unit = {},
    onQuoteRepost: (quote: String) -> Unit = {},
    onUndoRepost: () -> Unit = {},
    onCommentCountChanged: (delta: Int) -> Unit = {},
    // #25 — viewer authored this post => hide tipping in the comments.
    isOwnPost: Boolean = false,
    commentsContent: (@Composable (onCommentCountChanged: (Int) -> Unit) -> Unit)? = {
        CommentsSection(onCommentCountChanged = it, isOwnPost = isOwnPost)
    },
) {
    // MOD-C1 - post-level report target for this detail screen (comments self-host their own report).
    var reportTarget by remember { mutableStateOf<ReportTarget?>(null) }
    Scaffold(
        modifier = modifier.testTag(PostDetailTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text("Post") },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag(PostDetailTestTags.BACK)) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                PostDetailUiState.Loading -> LoadingState()

                PostDetailUiState.NotFound -> EmptyState(
                    title = "This post is unavailable",
                    modifier = Modifier.testTag(PostDetailTestTags.NOT_FOUND),
                )

                PostDetailUiState.Forbidden -> EmptyState(
                    title = "Subscription required",
                    body = "You don't have access to view this post.",
                    modifier = Modifier.testTag(PostDetailTestTags.FORBIDDEN),
                )

                is PostDetailUiState.Error -> ErrorState(
                    message = state.message,
                    onRetry = onRetry,
                    modifier = Modifier.testTag(PostDetailTestTags.ERROR),
                )

                is PostDetailUiState.Content -> PullToRefreshBox(
                    isRefreshing = state.isRefreshing,
                    onRefresh = onRefresh,
                    modifier = Modifier.fillMaxSize(),
                ) {
                    Column(
                        Modifier
                            .fillMaxSize()
                            .verticalScroll(rememberScrollState())
                            .testTag(PostDetailTestTags.CONTENT),
                    ) {
                        // Detail reuses PostItem; like/comment/overflow wired here (AND-173/174/175).
                        PostItem(
                            post = state.post,
                            authorName = authorName,
                            onAuthorClick = onAuthorClick,
                            onLinkClick = onLinkClick,
                            onSubscribeClick = onSubscribeClick,
                            onLikeToggle = { onLikeToggle() },
                            onToggleReaction = { _, emoji -> onToggleReaction(emoji) },
                            onRepost = { onRepost() },
                            onQuoteRepost = { _, quote -> onQuoteRepost(quote) },
                            onUndoRepost = { onUndoRepost() },
                            // #25 — can't tip your own post.
                            showTip = !isOwnPost,
                            // #3 — author sees a priced "Locked · $X" badge on their own locked post.
                            isOwnPost = isOwnPost,
                            // Comment icon on detail is a no-op (the section is already below).
                            onCommentClick = {},
                            onReport = { post -> reportTarget = ReportTarget.Content(post.id, "feed_post") },
                        )
                        // AND-174 — embedded comments surface. Host count updates flow back up.
                        commentsContent?.invoke(onCommentCountChanged)
                    }
                }
            }
        }
        // MOD-C1/C3 - report sheet host (six categories + licensing/IP -> DMCA).
        ContentReportSheetHost(target = reportTarget, onDismiss = { reportTarget = null })
    }
}
