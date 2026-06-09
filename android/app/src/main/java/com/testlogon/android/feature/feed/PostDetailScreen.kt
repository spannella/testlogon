package com.testlogon.android.feature.feed

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
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
    PostDetailScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::retry,
        onRefresh = viewModel::refresh,
        onAuthorClick = onAuthorClick,
        onLinkClick = onLinkClick,
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
    onAuthorClick: (authorId: String) -> Unit = {},
    onLinkClick: (url: String) -> Unit = {},
) {
    Scaffold(
        modifier = modifier.testTag(PostDetailTestTags.SCREEN),
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
                    Box(
                        Modifier
                            .fillMaxSize()
                            .verticalScroll(rememberScrollState())
                            .testTag(PostDetailTestTags.CONTENT),
                    ) {
                        // Detail reuses PostItem; body is un-clamped here (no truncation in M2 either way).
                        PostItem(
                            post = state.post,
                            onAuthorClick = onAuthorClick,
                            onLinkClick = onLinkClick,
                        )
                    }
                }
            }
        }
    }
}
