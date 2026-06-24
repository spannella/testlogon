package com.testlogon.android.feature.feed.own

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.paging.LoadState
import androidx.paging.compose.LazyPagingItems
import androidx.paging.compose.collectAsLazyPagingItems
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.feed.FeedPost
import com.testlogon.android.feature.feed.PostItem

object MyPostsTestTags {
    const val SCREEN = "my_posts_screen"
    const val LIST = "my_posts_list"
    const val EMPTY = "my_posts_empty"
    const val ERROR = "my_posts_error"
    const val COMPOSE_FAB = "my_posts_compose_fab"
    const val OVERFLOW = "my_posts_overflow"
    const val EDIT = "my_posts_edit"
    const val DELETE = "my_posts_delete"
}

/**
 * FD1 -- the "Your posts" surface: lists the signed-in user's own posts and lets them edit/delete each
 * one (wired to PATCH/DELETE /posts/{id}). Reuses [PostItem] for rendering with the engagement action
 * bar hidden (this is a management view, not a consumption feed); an overflow menu hosts Edit/Delete.
 */
@Composable
fun MyPostsRoute(
    onBack: () -> Unit,
    onComposePost: () -> Unit,
    onEditPost: (postId: String) -> Unit,
    onPostClick: (postId: String) -> Unit,
    viewModel: MyPostsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val items = viewModel.items.collectAsLazyPagingItems()
    val authorNames by viewModel.authorNames.collectAsState()
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is MyPostsEffect.ShowMessage -> snackbarHostState.showSnackbar(effect.message)
            }
        }
    }

    MyPostsScreen(
        state = state,
        items = items,
        authorNames = authorNames,
        snackbarHostState = snackbarHostState,
        onBack = onBack,
        onComposePost = onComposePost,
        onEditPost = onEditPost,
        onDeletePost = viewModel::deletePost,
        onPostClick = onPostClick,
        onResolveAuthor = viewModel::resolveAuthor,
        onRetryResolve = viewModel::resolve,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MyPostsScreen(
    state: MyPostsUiState,
    items: LazyPagingItems<FeedPost>,
    authorNames: Map<String, String>,
    snackbarHostState: SnackbarHostState,
    onBack: () -> Unit,
    onComposePost: () -> Unit,
    onEditPost: (postId: String) -> Unit,
    onDeletePost: (postId: String) -> Unit,
    onPostClick: (postId: String) -> Unit,
    onResolveAuthor: (authorId: String) -> Unit,
    onRetryResolve: () -> Unit,
) {
    var pendingDelete by remember { mutableStateOf<String?>(null) }
    val listState = rememberLazyListState()

    Scaffold(
        modifier = Modifier.testTag(MyPostsTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Your posts") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        floatingActionButton = {
            ExtendedFloatingActionButton(
                onClick = onComposePost,
                icon = { Icon(Icons.Filled.Add, contentDescription = null) },
                text = { Text("New post") },
                modifier = Modifier.testTag(MyPostsTestTags.COMPOSE_FAB),
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            val refresh = items.loadState.refresh
            when {
                state.resolving ->
                    LoadingState()

                state.loadError != null ->
                    ErrorState(
                        message = state.loadError,
                        onRetry = onRetryResolve,
                        modifier = Modifier.testTag(MyPostsTestTags.ERROR),
                    )

                refresh is LoadState.Loading && items.itemCount == 0 ->
                    LoadingState()

                refresh is LoadState.Error && items.itemCount == 0 ->
                    ErrorState(
                        message = "Couldn't load your posts.",
                        onRetry = items::retry,
                        modifier = Modifier.testTag(MyPostsTestTags.ERROR),
                    )

                refresh is LoadState.NotLoading && items.itemCount == 0 ->
                    EmptyState(
                        title = "You haven't posted yet",
                        body = "Tap New post to share something with your audience.",
                        actionLabel = "New post",
                        onAction = onComposePost,
                        modifier = Modifier.testTag(MyPostsTestTags.EMPTY),
                    )

                else -> LazyColumn(
                    state = listState,
                    modifier = Modifier.fillMaxSize().testTag(MyPostsTestTags.LIST),
                ) {
                    items(count = items.itemCount, key = { i -> items.peek(i)?.id ?: i }) { index ->
                        val item = items[index]
                        if (item != null) {
                            LaunchedEffect(item.authorId) { onResolveAuthor(item.authorId) }
                            MyPostRow(
                                post = item,
                                authorName = authorNames[item.authorId],
                                onPostClick = { onPostClick(item.id) },
                                onEdit = { onEditPost(item.id) },
                                onDelete = { pendingDelete = item.id },
                            )
                        }
                    }
                    if (items.loadState.append is LoadState.Loading) {
                        item {
                            Box(
                                Modifier.fillMaxWidth().padding(16.dp),
                                contentAlignment = Alignment.Center,
                            ) { CircularProgressIndicator(modifier = Modifier.size(24.dp)) }
                        }
                    }
                }
            }
        }
    }

    pendingDelete?.let { id ->
        AlertDialog(
            onDismissRequest = { pendingDelete = null },
            title = { Text("Delete this post?") },
            text = { Text("This can't be undone.") },
            confirmButton = {
                TextButton(
                    onClick = {
                        onDeletePost(id)
                        pendingDelete = null
                    },
                    modifier = Modifier.testTag("my_posts_delete_confirm"),
                ) { Text("Delete") }
            },
            dismissButton = {
                TextButton(onClick = { pendingDelete = null }) { Text("Cancel") }
            },
        )
    }
}

@Composable
private fun MyPostRow(
    post: FeedPost,
    authorName: String?,
    onPostClick: () -> Unit,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
) {
    var menuOpen by remember { mutableStateOf(false) }
    Box(Modifier.fillMaxWidth()) {
        PostItem(
            post = post,
            authorName = authorName,
            onPostClick = { onPostClick() },
            // Management view: hide the consumer engagement action bar.
            showActionBar = false,
        )
        Box(modifier = Modifier.align(Alignment.TopEnd).padding(top = 8.dp, end = 4.dp)) {
            IconButton(onClick = { menuOpen = true }, modifier = Modifier.testTag(MyPostsTestTags.OVERFLOW)) {
                Icon(Icons.Filled.MoreVert, contentDescription = "Post actions")
            }
            DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                DropdownMenuItem(
                    text = { Text("Edit") },
                    onClick = { menuOpen = false; onEdit() },
                    modifier = Modifier.testTag(MyPostsTestTags.EDIT),
                )
                DropdownMenuItem(
                    text = { Text("Delete") },
                    onClick = { menuOpen = false; onDelete() },
                    modifier = Modifier.testTag(MyPostsTestTags.DELETE),
                )
            }
        }
    }
}
