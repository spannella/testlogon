@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.vod

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.GridItemSpan
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.paging.LoadState
import androidx.paging.compose.LazyPagingItems
import androidx.paging.compose.collectAsLazyPagingItems
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.vod.VodCategory
import com.testlogon.android.data.vod.VodSummary
import com.testlogon.android.feature.videos.VideoTile

/** AND-191 — stable test tags. */
object VodCatalogTestTags {
    const val SCREEN = "vod_catalog_screen"
    const val GRID = "vod_catalog_grid"
    const val CATEGORIES = "vod_catalog_categories"
    const val APPEND_FOOTER = "vod_catalog_append_footer"
    const val APPEND_RETRY = "vod_catalog_append_retry"
    fun chip(slug: String) = "vod_catalog_chip_$slug"
}

/**
 * AND-191 — route-level VOD catalog. Collects the paged catalog + categories and renders
 * [VodCatalogScreen]. Tapping a tile navigates to the (shared) video detail route via [onVodClick].
 */
@Composable
fun VodCatalogRoute(
    onVodClick: (vodId: String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: VodCatalogViewModel = hiltViewModel(),
) {
    val items = viewModel.catalog.collectAsLazyPagingItems()
    val categories by viewModel.categories.collectAsStateWithLifecycle()
    val activeCategory by viewModel.activeCategory.collectAsStateWithLifecycle()
    VodCatalogScreen(
        items = items,
        categories = categories,
        activeCategory = activeCategory,
        onSelectCategory = viewModel::selectCategory,
        onVodClick = onVodClick,
        onRefresh = { items.refresh() },
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun VodCatalogScreen(
    items: LazyPagingItems<VodSummary>,
    categories: List<VodCategory>,
    activeCategory: String?,
    onSelectCategory: (String?) -> Unit,
    onVodClick: (vodId: String) -> Unit,
    onRefresh: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(VodCatalogTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.vod_catalog_title)) },
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
        Column(Modifier.fillMaxSize().padding(padding)) {
            if (categories.isNotEmpty()) {
                CategoryChips(
                    categories = categories,
                    activeCategory = activeCategory,
                    onSelectCategory = onSelectCategory,
                )
            }
            val refreshState = items.loadState.refresh
            val isRefreshing = refreshState is LoadState.Loading && items.itemCount > 0
            PullToRefreshBox(
                isRefreshing = isRefreshing,
                onRefresh = onRefresh,
                modifier = Modifier.fillMaxSize(),
            ) {
                Box(Modifier.fillMaxSize()) {
                    when {
                        refreshState is LoadState.Loading && items.itemCount == 0 -> LoadingState()

                        refreshState is LoadState.Error && items.itemCount == 0 -> {
                            val message = (refreshState.error as? VodLoadException)?.message
                                ?: stringResource(R.string.vod_catalog_error)
                            ErrorState(message = message, onRetry = items::retry)
                        }

                        refreshState is LoadState.NotLoading && items.itemCount == 0 ->
                            EmptyState(title = stringResource(R.string.vod_catalog_empty))

                        else -> CatalogGrid(items = items, onVodClick = onVodClick)
                    }
                }
            }
        }
    }
}

@Composable
private fun CategoryChips(
    categories: List<VodCategory>,
    activeCategory: String?,
    onSelectCategory: (String?) -> Unit,
) {
    FlowRow(
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 4.dp)
            .testTag(VodCatalogTestTags.CATEGORIES),
    ) {
        FilterChip(
            selected = activeCategory == null,
            onClick = { onSelectCategory(null) },
            label = { Text(stringResource(R.string.vod_category_all)) },
        )
        categories.forEach { category ->
            FilterChip(
                selected = activeCategory == category.slug,
                onClick = { onSelectCategory(category.slug) },
                label = { Text(category.label.ifBlank { category.slug }) },
                modifier = Modifier.testTag(VodCatalogTestTags.chip(category.slug)),
            )
        }
    }
}

@Composable
private fun CatalogGrid(
    items: LazyPagingItems<VodSummary>,
    onVodClick: (vodId: String) -> Unit,
) {
    LazyVerticalGrid(
        columns = GridCells.Adaptive(minSize = 160.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
        contentPadding = PaddingValues(12.dp),
        modifier = Modifier.fillMaxSize().testTag(VodCatalogTestTags.GRID),
    ) {
        items(count = items.itemCount, key = { index -> items.peek(index)?.id ?: index }) { index ->
            val video = items[index]
            if (video != null) {
                VideoTile(
                    title = video.title,
                    thumbnailUrl = video.thumbnailUrl,
                    durationSec = video.durationSec,
                    onClick = { onVodClick(video.id) },
                )
            }
        }

        when (items.loadState.append) {
            is LoadState.Loading -> item(span = { GridItemSpan(maxLineSpan) }) {
                Box(
                    Modifier.fillMaxWidth().padding(16.dp).testTag(VodCatalogTestTags.APPEND_FOOTER)
                        .semantics { contentDescription = "Loading more titles" },
                    contentAlignment = Alignment.Center,
                ) {
                    CircularProgressIndicator(modifier = Modifier.size(24.dp))
                }
            }
            is LoadState.Error -> item(span = { GridItemSpan(maxLineSpan) }) {
                androidx.compose.foundation.layout.Row(
                    Modifier.fillMaxWidth().padding(16.dp).testTag(VodCatalogTestTags.APPEND_FOOTER),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = stringResource(R.string.vod_catalog_append_error),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    TextButton(
                        onClick = { items.retry() },
                        modifier = Modifier.testTag(VodCatalogTestTags.APPEND_RETRY),
                    ) { Text(stringResource(R.string.action_retry)) }
                }
            }
            else -> Unit
        }
    }
}
