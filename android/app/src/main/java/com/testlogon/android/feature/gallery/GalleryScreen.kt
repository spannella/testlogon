@file:OptIn(ExperimentalLayoutApi::class, ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.gallery

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.rememberLazyGridState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.paging.LoadState
import androidx.paging.compose.LazyPagingItems
import androidx.paging.compose.collectAsLazyPagingItems
import coil.compose.SubcomposeAsyncImage
import coil.request.ImageRequest
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.gallery.GalleryCategory
import com.testlogon.android.data.gallery.GalleryVideoItem

/** Stable test tags for the gallery (AND-201). */
object GalleryTestTags {
    const val SCREEN = "gallery_screen"
    const val GRID = "gallery_grid"
    const val CARD = "gallery_card"
    const val EMPTY = "gallery_empty"
    const val ERROR = "gallery_error"
    const val APPEND_FOOTER = "gallery_append_footer"
    const val APPEND_RETRY = "gallery_append_retry"
    const val CATEGORY_PILL = "gallery_category_pill"
}

/**
 * AND-201 — gallery browse route. Hosts the cursor-paged grid (Paging 3), category pills, pull-to-
 * refresh, and the loading/empty/error/append scaffolding. Tapping a card opens the existing video
 * detail destination (AND-190) — there is no duplicate detail screen.
 */
@Composable
fun GalleryRoute(
    onItemClick: (videoId: String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: GalleryViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val items = viewModel.items.collectAsLazyPagingItems()
    GalleryScreen(
        state = state,
        items = items,
        onItemClick = onItemClick,
        onBack = onBack,
        onCategorySelected = viewModel::onCategorySelected,
        onSearch = viewModel::onSearch,
        modifier = modifier,
    )
}

@Composable
fun GalleryScreen(
    state: GalleryUiState,
    items: LazyPagingItems<GalleryVideoItem>,
    onItemClick: (videoId: String) -> Unit,
    onBack: () -> Unit,
    onCategorySelected: (String?) -> Unit,
    onSearch: (String?) -> Unit = {},
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(GalleryTestTags.SCREEN),
        topBar = { TopAppBar(title = { Text(stringResource(R.string.gallery_title)) }) },
    ) { padding ->
        val refreshState = items.loadState.refresh
        val isRefreshing = refreshState is LoadState.Loading && items.itemCount > 0
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = { items.refresh() },
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            Column(Modifier.fillMaxSize()) {
                GallerySearchField(query = state.searchQuery.orEmpty(), onSearch = onSearch)
                if (state.categories.isNotEmpty()) {
                    CategoryPills(
                        categories = state.categories,
                        selected = state.selectedCategory,
                        onSelect = onCategorySelected,
                    )
                }
                Box(Modifier.fillMaxSize()) {
                    when {
                        refreshState is LoadState.Loading && items.itemCount == 0 -> LoadingState()

                        refreshState is LoadState.Error && items.itemCount == 0 -> {
                            val message = (refreshState.error as? GalleryLoadException)?.message
                                ?: stringResource(R.string.gallery_error_generic)
                            ErrorState(
                                message = message,
                                onRetry = items::retry,
                                modifier = Modifier.testTag(GalleryTestTags.ERROR),
                            )
                        }

                        refreshState is LoadState.NotLoading && items.itemCount == 0 ->
                            EmptyState(
                                title = stringResource(R.string.gallery_empty_title),
                                body = stringResource(
                                    if (state.searchQuery != null) {
                                        R.string.gallery_empty_search
                                    } else {
                                        R.string.gallery_empty_browse
                                    },
                                ),
                                modifier = Modifier.testTag(GalleryTestTags.EMPTY),
                            )

                        else -> GalleryGrid(
                            items = items,
                            columns = state.columns,
                            onItemClick = onItemClick,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun GallerySearchField(
    query: String,
    onSearch: (String?) -> Unit,
) {
    var text by androidx.compose.runtime.saveable.rememberSaveable(query) { androidx.compose.runtime.mutableStateOf(query) }
    androidx.compose.material3.OutlinedTextField(
        value = text,
        onValueChange = { text = it },
        placeholder = { Text(stringResource(R.string.gallery_search_hint)) },
        singleLine = true,
        modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp).testTag("gallery_search_field"),
        keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
            imeAction = androidx.compose.ui.text.input.ImeAction.Search,
        ),
        keyboardActions = androidx.compose.foundation.text.KeyboardActions(
            onSearch = { onSearch(text.takeIf { it.isNotBlank() }) },
        ),
    )
}

@Composable
private fun CategoryPills(
    categories: List<GalleryCategory>,
    selected: String?,
    onSelect: (String?) -> Unit,
) {
    FlowRow(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        FilterChip(
            selected = selected == null,
            onClick = { onSelect(null) },
            label = { Text(stringResource(R.string.gallery_all)) },
        )
        categories.forEach { cat ->
            FilterChip(
                selected = selected == cat.slug,
                onClick = { onSelect(cat.slug) },
                label = { Text(cat.label.ifBlank { cat.slug }) },
                modifier = Modifier.testTag(GalleryTestTags.CATEGORY_PILL),
            )
        }
    }
}

@Composable
private fun GalleryGrid(
    items: LazyPagingItems<GalleryVideoItem>,
    columns: Int,
    onItemClick: (videoId: String) -> Unit,
) {
    val gridState = rememberLazyGridState()
    LazyVerticalGrid(
        columns = GridCells.Fixed(columns),
        state = gridState,
        modifier = Modifier.fillMaxSize().testTag(GalleryTestTags.GRID),
        contentPadding = PaddingValues(12.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        items(count = items.itemCount, key = { index -> items.peek(index)?.videoId ?: index }) { index ->
            val item = items[index]
            if (item != null) {
                GalleryVideoCard(item = item, onClick = { onItemClick(item.videoId) })
            }
        }

        when (items.loadState.append) {
            is LoadState.Loading -> item(span = { androidx.compose.foundation.lazy.grid.GridItemSpan(maxLineSpan) }) {
                Box(
                    Modifier.fillMaxWidth().padding(16.dp).testTag(GalleryTestTags.APPEND_FOOTER),
                    contentAlignment = Alignment.Center,
                ) {
                    CircularProgressIndicator(modifier = Modifier.padding(8.dp))
                }
            }
            is LoadState.Error -> item(span = { androidx.compose.foundation.lazy.grid.GridItemSpan(maxLineSpan) }) {
                Row(
                    Modifier.fillMaxWidth().padding(16.dp).testTag(GalleryTestTags.APPEND_FOOTER),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(stringResource(R.string.gallery_append_error), style = MaterialTheme.typography.bodyMedium)
                    TextButton(
                        onClick = items::retry,
                        modifier = Modifier.testTag(GalleryTestTags.APPEND_RETRY),
                    ) { Text(stringResource(R.string.gallery_retry)) }
                }
            }
            else -> Unit
        }
    }
}

/** AND-201 — one gallery card: 16:9 poster + duration/PPV badges + title + counts (mirrors web). */
@Composable
private fun GalleryVideoCard(
    item: GalleryVideoItem,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val posterCd = item.title.ifBlank { stringResource(R.string.gallery_video_cd) }
    Column(
        modifier = modifier
            .fillMaxWidth()
            .testTag(GalleryTestTags.CARD)
            .clickable(onClick = onClick),
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .aspectRatio(16f / 9f)
                .clip(RoundedCornerShape(8.dp))
                .background(MaterialTheme.colorScheme.surfaceVariant),
        ) {
            if (item.thumbnailUrl != null) {
                SubcomposeAsyncImage(
                    model = ImageRequest.Builder(LocalContext.current).data(item.thumbnailUrl).crossfade(true).build(),
                    contentDescription = posterCd,
                    contentScale = ContentScale.Crop,
                    loading = { Box(Modifier.fillMaxSize()) },
                    modifier = Modifier.fillMaxSize().semantics { contentDescription = posterCd },
                )
            } else {
                Box(
                    Modifier.fillMaxSize().semantics { contentDescription = posterCd },
                    contentAlignment = Alignment.Center,
                ) {
                    Text(stringResource(R.string.gallery_no_thumbnail), style = MaterialTheme.typography.labelSmall)
                }
            }
            item.durationSeconds?.takeIf { it > 0 }?.let { secs ->
                Badge(
                    text = formatDuration(secs.toLong()),
                    modifier = Modifier.align(Alignment.BottomEnd).padding(6.dp),
                )
            }
            if (item.isPpv) {
                Badge(
                    text = stringResource(R.string.gallery_ppv),
                    modifier = Modifier.align(Alignment.TopEnd).padding(6.dp),
                )
            }
        }
        Text(
            text = item.title,
            style = MaterialTheme.typography.titleSmall,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.padding(top = 6.dp),
        )
        Text(
            text = stringResource(
                R.string.gallery_counts,
                formatCount(item.viewCount),
                formatCount(item.likeCount),
                formatCount(item.commentCount),
            ),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun Badge(text: String, modifier: Modifier = Modifier) {
    Text(
        text = text,
        color = Color.White,
        style = MaterialTheme.typography.labelSmall,
        modifier = modifier
            .clip(RoundedCornerShape(4.dp))
            .background(Color.Black.copy(alpha = 0.6f))
            .padding(horizontal = 6.dp, vertical = 2.dp),
    )
}
