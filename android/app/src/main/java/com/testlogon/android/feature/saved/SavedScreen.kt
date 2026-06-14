package com.testlogon.android.feature.saved

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
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.BookmarkRemove
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.paging.LoadState
import androidx.paging.compose.LazyPagingItems
import androidx.paging.compose.collectAsLazyPagingItems
import coil.compose.AsyncImage
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.bookmarks.Bookmark
import androidx.compose.runtime.LaunchedEffect

/** Stable testTags for the Saved screen (AND-092 / AND-096). */
object SavedTestTags {
    const val SCREEN = "saved_screen"
    const val LIST = "saved_list"
    const val ROW = "saved_row"
    const val UNSAVE = "saved_unsave"
    const val APPEND_FOOTER = "saved_append_footer"
    const val APPEND_RETRY = "saved_append_retry"
    const val EMPTY = "saved_empty"
    const val ERROR = "saved_error"
}

/** AND-092 — route-level Saved entry, reached from the More hub. */
@Composable
fun SavedRoute(
    onBack: () -> Unit,
    onOpen: (contentType: String, contentId: String) -> Unit = { _, _ -> },
    modifier: Modifier = Modifier,
    viewModel: SavedViewModel = hiltViewModel(),
) {
    val items = viewModel.items.collectAsLazyPagingItems()
    val state by viewModel.state.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is SavedEvent.ShowError -> snackbarHostState.showSnackbar(event.message)
                is SavedEvent.ShowUndo -> {
                    val result = snackbarHostState.showSnackbar(
                        message = "Removed from saved",
                        actionLabel = "Undo",
                    )
                    if (result == SnackbarResult.ActionPerformed) viewModel.onUndo()
                }
            }
        }
    }

    SavedScreen(
        items = items,
        state = state,
        snackbarHostState = snackbarHostState,
        onUnsave = viewModel::onUnsave,
        onOpen = onOpen,
        onRefresh = { items.refresh() },
        onBack = onBack,
        modifier = modifier,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SavedScreen(
    items: LazyPagingItems<Bookmark>,
    state: SavedUiState,
    snackbarHostState: SnackbarHostState,
    onUnsave: (Bookmark) -> Unit,
    onOpen: (String, String) -> Unit,
    onRefresh: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val listState = rememberLazyListState()
    Scaffold(
        modifier = modifier.testTag(SavedTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Saved") },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("saved_back")) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        val refreshState = items.loadState.refresh
        // Count visible (non-optimistically-removed) items to drive the empty state.
        val visibleCount = (0 until items.itemCount).count { index ->
            items.peek(index)?.let { it.key !in state.removedKeys } ?: true
        }
        Box(Modifier.fillMaxSize().padding(padding)) {
            when {
                refreshState is LoadState.Loading && items.itemCount == 0 -> LoadingState()

                refreshState is LoadState.Error && items.itemCount == 0 -> {
                    val message = (refreshState.error as? com.testlogon.android.data.bookmarks.BookmarkLoadException)?.message
                        ?: "Couldn't load your saved items."
                    ErrorState(
                        message = message,
                        onRetry = items::retry,
                        modifier = Modifier.testTag(SavedTestTags.ERROR),
                    )
                }

                refreshState is LoadState.NotLoading && visibleCount == 0 ->
                    EmptyState(
                        title = "Nothing saved yet",
                        body = "Items you bookmark will show up here.",
                        modifier = Modifier.testTag(SavedTestTags.EMPTY),
                    )

                else -> SavedList(
                    items = items,
                    removedKeys = state.removedKeys,
                    listState = listState,
                    onUnsave = onUnsave,
                    onOpen = onOpen,
                )
            }
        }
    }
}

@Composable
private fun SavedList(
    items: LazyPagingItems<Bookmark>,
    removedKeys: Set<String>,
    listState: androidx.compose.foundation.lazy.LazyListState,
    onUnsave: (Bookmark) -> Unit,
    onOpen: (String, String) -> Unit,
) {
    LazyColumn(
        state = listState,
        modifier = Modifier.fillMaxSize().testTag(SavedTestTags.LIST),
    ) {
        items(count = items.itemCount, key = { index -> items.peek(index)?.key ?: index }) { index ->
            val item = items[index]
            if (item != null && item.key !in removedKeys) {
                SavedRow(item = item, onUnsave = { onUnsave(item) }, onOpen = { onOpen(item.contentType, item.contentId) })
            }
        }

        when (items.loadState.append) {
            is LoadState.Loading -> item {
                Box(
                    Modifier.fillMaxWidth().padding(16.dp).testTag(SavedTestTags.APPEND_FOOTER),
                    contentAlignment = Alignment.Center,
                ) {
                    CircularProgressIndicator(modifier = Modifier.size(24.dp))
                }
            }
            is LoadState.Error -> item {
                Row(
                    Modifier.fillMaxWidth().padding(16.dp).testTag(SavedTestTags.APPEND_FOOTER),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text("Couldn't load more.", style = MaterialTheme.typography.bodyMedium)
                    TextButton(
                        onClick = items::retry,
                        modifier = Modifier.testTag(SavedTestTags.APPEND_RETRY),
                    ) { Text("Retry") }
                }
            }
            else -> Unit
        }
    }
}

@Composable
private fun SavedRow(
    item: Bookmark,
    onUnsave: () -> Unit,
    onOpen: () -> Unit,
) {
    val title = item.title ?: item.contentId
    val typeLabel = item.contentType.replaceFirstChar { it.uppercase() }
    val rowCd = buildString {
        append(title)
        if (typeLabel.isNotBlank()) append(", ").append(typeLabel)
    }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .clickable(onClick = onOpen)
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .testTag(SavedTestTags.ROW),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Surface(
            color = MaterialTheme.colorScheme.surfaceVariant,
            modifier = Modifier
                .size(48.dp)
                .clip(RoundedCornerShape(8.dp)),
        ) {
            if (item.thumbnailUrl != null) {
                AsyncImage(
                    model = item.thumbnailUrl,
                    contentDescription = null,
                    contentScale = ContentScale.Crop,
                    modifier = Modifier.fillMaxSize(),
                )
            }
        }
        Column(
            modifier = Modifier
                .weight(1f)
                .padding(start = 12.dp)
                .clearAndSetSemantics { contentDescription = rowCd },
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleSmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            if (!item.subtitle.isNullOrBlank()) {
                Text(
                    text = item.subtitle,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Text(
                text = typeLabel,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        IconButton(
            onClick = onUnsave,
            modifier = Modifier.testTag(SavedTestTags.UNSAVE),
        ) {
            Icon(
                imageVector = Icons.Filled.BookmarkRemove,
                contentDescription = "Remove $title from saved",
            )
        }
    }
}
