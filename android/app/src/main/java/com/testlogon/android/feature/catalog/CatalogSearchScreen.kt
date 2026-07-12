@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.catalog

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
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
import androidx.compose.ui.text.input.ImeAction
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
import com.testlogon.android.data.catalog.CatalogItem

/** AND-207 — stable test tags for the catalog search screen. */
object CatalogSearchTestTags {
    const val SCREEN = "catalog_search_screen"
    const val FIELD = "catalog_search_field"
    const val CLEAR = "catalog_search_clear"
    const val LIST = "catalog_search_list"
    const val ROW = "catalog_search_row"
    const val PROMPT = "catalog_search_prompt"
    const val EMPTY = "catalog_search_empty"
    const val ERROR = "catalog_search_error"
    const val APPEND_FOOTER = "catalog_search_append_footer"
    const val APPEND_RETRY = "catalog_search_append_retry"
}

/**
 * AND-207 — catalog search route. Collects the query + the debounced paged results and renders
 * [CatalogSearchScreen]. Tapping a row navigates to the product detail route with both ids.
 */
@Composable
fun CatalogSearchRoute(
    onItemClick: (categoryId: String, itemId: String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: CatalogSearchViewModel = hiltViewModel(),
) {
    val query by viewModel.query.collectAsStateWithLifecycle()
    val items = viewModel.results.collectAsLazyPagingItems()
    val sponsored by viewModel.sponsored.collectAsStateWithLifecycle()
    CatalogSearchScreen(
        query = query,
        items = items,
        sponsored = sponsored,
        onQueryChange = viewModel::onQueryChange,
        onClear = viewModel::onClear,
        onItemClick = onItemClick,
        onSponsoredImpression = viewModel::onSponsoredImpression,
        onSponsoredClick = { product ->
            viewModel.onSponsoredClick(product)
            onItemClick(product.categoryId, product.productId)
        },
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun CatalogSearchScreen(
    query: String,
    items: LazyPagingItems<CatalogItem>,
    sponsored: List<com.testlogon.android.data.shopads.SponsoredProduct> = emptyList(),
    onQueryChange: (String) -> Unit,
    onClear: () -> Unit,
    onItemClick: (categoryId: String, itemId: String) -> Unit,
    onSponsoredImpression: (com.testlogon.android.data.shopads.SponsoredProduct) -> Unit = {},
    onSponsoredClick: (com.testlogon.android.data.shopads.SponsoredProduct) -> Unit = {},
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val refresh = items.loadState.refresh
    val phase = searchUiState(
        query = query,
        refreshLoading = refresh is LoadState.Loading,
        refreshError = refresh is LoadState.Error,
        errorMessage = (refresh as? LoadState.Error)?.let {
            (it.error as? CatalogLoadException)?.message
        },
        retryable = true,
        itemCount = items.itemCount,
    )
    Scaffold(
        modifier = modifier.testTag(CatalogSearchTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.catalog_search_title)) },
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
            SearchField(query = query, onQueryChange = onQueryChange, onClear = onClear)
            Box(Modifier.fillMaxSize()) {
                when (phase) {
                    is CatalogSearchUiState.Idle ->
                        EmptyState(
                            title = stringResource(R.string.catalog_search_prompt),
                            imageVector = Icons.Filled.Search,
                            modifier = Modifier.testTag(CatalogSearchTestTags.PROMPT),
                        )

                    is CatalogSearchUiState.Loading -> LoadingState()

                    is CatalogSearchUiState.Empty ->
                        EmptyState(
                            title = stringResource(R.string.catalog_search_empty, phase.query),
                            modifier = Modifier.testTag(CatalogSearchTestTags.EMPTY),
                        )

                    is CatalogSearchUiState.Error ->
                        ErrorState(
                            message = phase.message.ifBlank { stringResource(R.string.catalog_search_error) },
                            onRetry = items::retry,
                            modifier = Modifier.testTag(CatalogSearchTestTags.ERROR),
                        )

                    is CatalogSearchUiState.Content ->
                        SearchResults(
                            items = items,
                            sponsored = sponsored,
                            onItemClick = onItemClick,
                            onSponsoredImpression = onSponsoredImpression,
                            onSponsoredClick = onSponsoredClick,
                        )
                }
            }
        }
    }
}

@Composable
private fun SearchField(
    query: String,
    onQueryChange: (String) -> Unit,
    onClear: () -> Unit,
) {
    val fieldLabel = stringResource(R.string.catalog_search_field_label)
    OutlinedTextField(
        value = query,
        onValueChange = onQueryChange,
        singleLine = true,
        label = { Text(fieldLabel) },
        leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
        trailingIcon = {
            if (query.isNotEmpty()) {
                IconButton(
                    onClick = onClear,
                    modifier = Modifier.testTag(CatalogSearchTestTags.CLEAR),
                ) {
                    Icon(
                        Icons.Filled.Clear,
                        contentDescription = stringResource(R.string.catalog_search_clear),
                    )
                }
            }
        },
        keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(imeAction = ImeAction.Search),
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 8.dp)
            .testTag(CatalogSearchTestTags.FIELD)
            .semantics { contentDescription = fieldLabel },
    )
}

@Composable
private fun SearchResults(
    items: LazyPagingItems<CatalogItem>,
    sponsored: List<com.testlogon.android.data.shopads.SponsoredProduct>,
    onItemClick: (categoryId: String, itemId: String) -> Unit,
    onSponsoredImpression: (com.testlogon.android.data.shopads.SponsoredProduct) -> Unit,
    onSponsoredClick: (com.testlogon.android.data.shopads.SponsoredProduct) -> Unit,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag(CatalogSearchTestTags.LIST),
        contentPadding = PaddingValues(12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        // ADV x ECOM (B2): STANDALONE sponsored product units atop the organic search results.
        items(count = sponsored.size, key = { i -> "sponsored_" + sponsored[i].unitId }) { i ->
            val product = sponsored[i]
            androidx.compose.runtime.LaunchedEffect(product.unitId) { onSponsoredImpression(product) }
            SponsoredProductCard(product = product, onClick = { onSponsoredClick(product) })
        }
        items(count = items.itemCount, key = { index -> items.peek(index)?.itemId ?: index }) { index ->
            val item = items[index]
            if (item != null) {
                SearchResultRow(item = item, onClick = { onItemClick(item.categoryId, item.itemId) })
            }
        }

        when (items.loadState.append) {
            is LoadState.Loading -> item {
                Box(
                    Modifier.fillMaxWidth().padding(16.dp).testTag(CatalogSearchTestTags.APPEND_FOOTER),
                    contentAlignment = Alignment.Center,
                ) { CircularProgressIndicator() }
            }
            is LoadState.Error -> item {
                Row(
                    Modifier.fillMaxWidth().padding(16.dp).testTag(CatalogSearchTestTags.APPEND_FOOTER),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(stringResource(R.string.catalog_append_error), style = MaterialTheme.typography.bodyMedium)
                    TextButton(
                        onClick = items::retry,
                        modifier = Modifier.testTag(CatalogSearchTestTags.APPEND_RETRY),
                    ) { Text(stringResource(R.string.action_retry)) }
                }
            }
            else -> Unit
        }
    }
}

/** AND-207 — one result row: thumbnail + name + short description snippet + locale-formatted price. */
@Composable
private fun SearchResultRow(
    item: CatalogItem,
    onClick: () -> Unit,
) {
    val thumbCd = item.name.ifBlank { stringResource(R.string.catalog_item_cd) }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(CatalogSearchTestTags.ROW)
            .clickable(onClick = onClick),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            Modifier
                .size(64.dp)
                .clip(RoundedCornerShape(8.dp))
                .background(MaterialTheme.colorScheme.surfaceVariant),
        ) {
            val thumb = item.thumbnailUrl
            if (thumb != null) {
                SubcomposeAsyncImage(
                    model = ImageRequest.Builder(LocalContext.current).data(thumb).crossfade(true).build(),
                    contentDescription = thumbCd,
                    loading = { Box(Modifier.fillMaxSize()) },
                    modifier = Modifier.fillMaxSize(),
                )
            } else {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text(stringResource(R.string.catalog_no_image), style = MaterialTheme.typography.labelSmall)
                }
            }
        }
        Column(Modifier.fillMaxWidth()) {
            Text(
                text = item.name,
                style = MaterialTheme.typography.titleSmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            val description = item.description
            if (!description.isNullOrBlank()) {
                Text(
                    text = description,
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Text(
                text = formatPrice(item.priceCents, item.currency),
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.primary,
            )
        }
    }
}
