@file:OptIn(ExperimentalLayoutApi::class, ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.catalog

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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.GridItemSpan
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.rememberLazyGridState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Favorite
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.outlined.FavoriteBorder
import androidx.compose.material.icons.outlined.ShoppingCart
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
import androidx.compose.ui.draw.clip
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
import com.testlogon.android.data.catalog.CatalogCategory
import com.testlogon.android.data.catalog.CatalogItem

/** AND-205 — stable test tags for the catalog browse screen. */
object CatalogTestTags {
    const val SCREEN = "catalog_screen"
    const val GRID = "catalog_grid"
    const val SEARCH = "catalog_search_action"
    const val CART = "catalog_cart_action"
    const val CATEGORIES = "catalog_categories"
    const val CARD = "catalog_card"
    const val EMPTY = "catalog_empty"
    const val ERROR = "catalog_error"
    const val ITEMS_EMPTY = "catalog_items_empty"
    const val APPEND_FOOTER = "catalog_append_footer"
    const val APPEND_RETRY = "catalog_append_retry"
    fun chip(categoryId: String) = "catalog_chip_$categoryId"
    fun wishlist(itemId: String) = "wishlist_toggle_$itemId"
}

/**
 * AND-205 — catalog browse route. Collects the category state + the cursor-paged item grid and renders
 * [CatalogScreen]. Tapping an item navigates to the product detail route (AND-206) with both ids.
 */
@Composable
fun CatalogRoute(
    onItemClick: (categoryId: String, itemId: String) -> Unit,
    onSearch: () -> Unit,
    onCart: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: CatalogViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val items = viewModel.items.collectAsLazyPagingItems()
    val savedKeys by viewModel.savedKeys.collectAsStateWithLifecycle()
    val sponsored by viewModel.sponsored.collectAsStateWithLifecycle()
    CatalogScreen(
        state = state,
        items = items,
        savedKeys = savedKeys,
        sponsored = sponsored,
        onSelectCategory = viewModel::selectCategory,
        onRetryCategories = viewModel::retryCategories,
        onItemClick = onItemClick,
        onToggleWishlist = viewModel::toggleWishlist,
        onSponsoredImpression = viewModel::onSponsoredImpression,
        onSponsoredClick = { product ->
            // ADV x ECOM (B2): CPC click + stash ad_click_id (CPA), then route to the real product.
            viewModel.onSponsoredClick(product)
            onItemClick(product.categoryId, product.productId)
        },
        onSearch = onSearch,
        onCart = onCart,
        onRefresh = { items.refresh() },
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun CatalogScreen(
    state: CatalogUiState,
    items: LazyPagingItems<CatalogItem>,
    savedKeys: Set<String>,
    sponsored: List<com.testlogon.android.data.shopads.SponsoredProduct> = emptyList(),
    onSelectCategory: (String) -> Unit,
    onRetryCategories: () -> Unit,
    onItemClick: (categoryId: String, itemId: String) -> Unit,
    onToggleWishlist: (CatalogItem) -> Unit,
    onSponsoredImpression: (com.testlogon.android.data.shopads.SponsoredProduct) -> Unit = {},
    onSponsoredClick: (com.testlogon.android.data.shopads.SponsoredProduct) -> Unit = {},
    onSearch: () -> Unit,
    onCart: () -> Unit,
    onRefresh: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(CatalogTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.catalog_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
                actions = {
                    IconButton(
                        onClick = onSearch,
                        modifier = Modifier.testTag(CatalogTestTags.SEARCH),
                    ) {
                        Icon(
                            Icons.Filled.Search,
                            contentDescription = stringResource(R.string.catalog_search_field_label),
                        )
                    }
                    IconButton(
                        onClick = onCart,
                        modifier = Modifier.testTag(CatalogTestTags.CART),
                    ) {
                        Icon(
                            Icons.Outlined.ShoppingCart,
                            contentDescription = stringResource(R.string.cart_title),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                is CatalogUiState.Loading -> LoadingState()

                is CatalogUiState.Empty ->
                    EmptyState(
                        title = stringResource(R.string.catalog_empty_categories),
                        modifier = Modifier.testTag(CatalogTestTags.EMPTY),
                    )

                is CatalogUiState.Error ->
                    ErrorState(
                        message = state.message,
                        onRetry = onRetryCategories,
                        modifier = Modifier.testTag(CatalogTestTags.ERROR),
                    )

                is CatalogUiState.Ready ->
                    CatalogContent(
                        state = state,
                        items = items,
                        savedKeys = savedKeys,
                        sponsored = sponsored,
                        onSelectCategory = onSelectCategory,
                        onItemClick = onItemClick,
                        onToggleWishlist = onToggleWishlist,
                        onSponsoredImpression = onSponsoredImpression,
                        onSponsoredClick = onSponsoredClick,
                        onRefresh = onRefresh,
                    )
            }
        }
    }
}

@Composable
private fun CatalogContent(
    state: CatalogUiState.Ready,
    items: LazyPagingItems<CatalogItem>,
    savedKeys: Set<String>,
    sponsored: List<com.testlogon.android.data.shopads.SponsoredProduct>,
    onSelectCategory: (String) -> Unit,
    onItemClick: (categoryId: String, itemId: String) -> Unit,
    onToggleWishlist: (CatalogItem) -> Unit,
    onSponsoredImpression: (com.testlogon.android.data.shopads.SponsoredProduct) -> Unit,
    onSponsoredClick: (com.testlogon.android.data.shopads.SponsoredProduct) -> Unit,
    onRefresh: () -> Unit,
) {
    Column(Modifier.fillMaxSize()) {
        CategoryChips(
            categories = state.categories,
            selectedId = state.selectedId,
            onSelect = onSelectCategory,
        )
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
                        val message = (refreshState.error as? CatalogLoadException)?.message
                            ?: stringResource(R.string.catalog_items_error)
                        ErrorState(message = message, onRetry = items::retry)
                    }

                    refreshState is LoadState.NotLoading && items.itemCount == 0 ->
                        EmptyState(
                            title = stringResource(R.string.catalog_empty_items),
                            modifier = Modifier.testTag(CatalogTestTags.ITEMS_EMPTY),
                        )

                    else -> CatalogGrid(
                        items = items,
                        savedKeys = savedKeys,
                        sponsored = sponsored,
                        onItemClick = onItemClick,
                        onToggleWishlist = onToggleWishlist,
                        onSponsoredImpression = onSponsoredImpression,
                        onSponsoredClick = onSponsoredClick,
                    )
                }
            }
        }
    }
}

@Composable
private fun CategoryChips(
    categories: List<CatalogCategory>,
    selectedId: String,
    onSelect: (String) -> Unit,
) {
    FlowRow(
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 4.dp)
            .testTag(CatalogTestTags.CATEGORIES),
    ) {
        categories.forEach { category ->
            FilterChip(
                selected = category.categoryId == selectedId,
                onClick = { onSelect(category.categoryId) },
                label = { Text(category.name.ifBlank { category.categoryId }) },
                modifier = Modifier.testTag(CatalogTestTags.chip(category.categoryId)),
            )
        }
    }
}

@Composable
private fun CatalogGrid(
    items: LazyPagingItems<CatalogItem>,
    savedKeys: Set<String>,
    sponsored: List<com.testlogon.android.data.shopads.SponsoredProduct>,
    onItemClick: (categoryId: String, itemId: String) -> Unit,
    onToggleWishlist: (CatalogItem) -> Unit,
    onSponsoredImpression: (com.testlogon.android.data.shopads.SponsoredProduct) -> Unit,
    onSponsoredClick: (com.testlogon.android.data.shopads.SponsoredProduct) -> Unit,
) {
    val gridState = rememberLazyGridState()
    LazyVerticalGrid(
        columns = GridCells.Adaptive(minSize = 160.dp),
        state = gridState,
        modifier = Modifier.fillMaxSize().testTag(CatalogTestTags.GRID),
        contentPadding = PaddingValues(12.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        // ADV x ECOM (B2): STANDALONE sponsored product units injected above the organic grid (full-span,
        // distinct label, no wishlist/tip). Impression fires on first composition; tap routes to product.
        items(
            count = sponsored.size,
            span = { GridItemSpan(maxLineSpan) },
            key = { i -> "sponsored_" + sponsored[i].unitId },
        ) { i ->
            val product = sponsored[i]
            androidx.compose.runtime.LaunchedEffect(product.unitId) { onSponsoredImpression(product) }
            SponsoredProductCard(
                product = product,
                onClick = { onSponsoredClick(product) },
            )
        }
        items(count = items.itemCount, key = { index -> items.peek(index)?.itemId ?: index }) { index ->
            val item = items[index]
            if (item != null) {
                CatalogItemCell(
                    item = item,
                    isSaved = savedKeys.contains("${item.categoryId}#${item.itemId}"),
                    onClick = { onItemClick(item.categoryId, item.itemId) },
                    onToggleWishlist = { onToggleWishlist(item) },
                )
            }
        }

        when (items.loadState.append) {
            is LoadState.Loading -> item(span = { GridItemSpan(maxLineSpan) }) {
                Box(
                    Modifier.fillMaxWidth().padding(16.dp).testTag(CatalogTestTags.APPEND_FOOTER)
                        .semantics { contentDescription = "Loading more items" },
                    contentAlignment = Alignment.Center,
                ) {
                    CircularProgressIndicator(modifier = Modifier.padding(8.dp))
                }
            }
            is LoadState.Error -> item(span = { GridItemSpan(maxLineSpan) }) {
                Row(
                    Modifier.fillMaxWidth().padding(16.dp).testTag(CatalogTestTags.APPEND_FOOTER),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = stringResource(R.string.catalog_append_error),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    TextButton(
                        onClick = items::retry,
                        modifier = Modifier.testTag(CatalogTestTags.APPEND_RETRY),
                    ) { Text(stringResource(R.string.action_retry)) }
                }
            }
            else -> Unit
        }
    }
}

/** AND-205 — one catalog cell: square thumbnail (image_urls.first) + name + locale-formatted price. */
@Composable
private fun CatalogItemCell(
    item: CatalogItem,
    isSaved: Boolean,
    onClick: () -> Unit,
    onToggleWishlist: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val thumbCd = item.name.ifBlank { stringResource(R.string.catalog_item_cd) }
    Column(
        modifier = modifier
            .fillMaxWidth()
            .testTag(CatalogTestTags.CARD)
            .clickable(onClick = onClick),
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .aspectRatio(1f)
                .clip(RoundedCornerShape(8.dp))
                .background(MaterialTheme.colorScheme.surfaceVariant),
        ) {
            val thumb = item.thumbnailUrl
            if (thumb != null) {
                SubcomposeAsyncImage(
                    model = ImageRequest.Builder(LocalContext.current).data(thumb).crossfade(true).build(),
                    contentDescription = thumbCd,
                    loading = { Box(Modifier.fillMaxSize()) },
                    modifier = Modifier.fillMaxSize().semantics { contentDescription = thumbCd },
                )
            } else {
                Box(
                    Modifier.fillMaxSize().semantics { contentDescription = thumbCd },
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        stringResource(R.string.catalog_no_image),
                        style = MaterialTheme.typography.labelSmall,
                    )
                }
            }
            // Wishlist heart overlay (top-right of the thumbnail).
            val heartCd = stringResource(if (isSaved) R.string.wishlist_remove else R.string.wishlist_add)
            IconButton(
                onClick = onToggleWishlist,
                modifier = Modifier
                    .align(Alignment.TopEnd)
                    .testTag(CatalogTestTags.wishlist(item.itemId))
                    .semantics { contentDescription = heartCd },
            ) {
                Box(
                    Modifier
                        .clip(CircleShape)
                        .background(MaterialTheme.colorScheme.surface.copy(alpha = 0.7f))
                        .padding(4.dp),
                ) {
                    Icon(
                        imageVector = if (isSaved) Icons.Filled.Favorite else Icons.Outlined.FavoriteBorder,
                        contentDescription = heartCd,
                        tint = if (isSaved) MaterialTheme.colorScheme.primary
                        else MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(18.dp),
                    )
                }
            }
        }
        Text(
            text = item.name,
            style = MaterialTheme.typography.titleSmall,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.padding(top = 6.dp),
        )
        Text(
            text = formatPrice(item.priceCents, item.currency),
            style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.primary,
        )
    }
}
