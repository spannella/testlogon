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
import androidx.compose.runtime.remember
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
    viewModel: PostDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            if (effect is PostDetailEffect.ShowError) snackbarHostState.showSnackbar(effect.message)
        }
    }
    PostDetailScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::retry,
        onRefresh = viewModel::refresh,
        snackbarHostState = snackbarHostState,
        onAuthorClick = onAuthorClick,
        onLinkClick = onLinkClick,
        onLikeToggle = { viewModel.onLikeToggle() },
        onCommentCountChanged = viewModel::onCommentCountChanged,
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
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
    onAuthorClick: (authorId: String) -> Unit = {},
    onLinkClick: (url: String) -> Unit = {},
    onLikeToggle: () -> Unit = {},
    onCommentCountChanged: (delta: Int) -> Unit = {},
    commentsContent: (@Composable (onCommentCountChanged: (Int) -> Unit) -> Unit)? = {
        CommentsSection(onCommentCountChanged = it)
    },
) {
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
                            onAuthorClick = onAuthorClick,
                            onLinkClick = onLinkClick,
                            onLikeToggle = { onLikeToggle() },
                            // Comment icon on detail is a no-op (the section is already below).
                            onCommentClick = {},
                        )
                        // AND-174 — embedded comments surface. Host count updates flow back up.
                        commentsContent?.invoke(onCommentCountChanged)
                    }
                }
            }
        }
    }
}
