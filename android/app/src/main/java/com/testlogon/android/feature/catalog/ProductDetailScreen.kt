@file:OptIn(ExperimentalLayoutApi::class, ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.catalog

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import coil.compose.SubcomposeAsyncImage
import coil.request.ImageRequest
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.catalog.CatalogItem

/** AND-206 — stable test tags for the product detail screen. */
object ProductDetailTestTags {
    const val SCREEN = "product_detail_screen"
    const val CAROUSEL = "product_detail_carousel"
    const val NAME = "product_detail_name"
    const val PRICE = "product_detail_price"
    const val DESCRIPTION = "product_detail_description"
    const val ATTRIBUTES = "product_detail_attributes"
    const val STOCK = "product_detail_stock"
    const val ADD_TO_CART = "product_detail_add_to_cart"
    const val NOT_FOUND = "product_detail_not_found"
    const val ERROR = "product_detail_error"
}

/**
 * AND-206 — product detail route. Resolves the item by id (list-then-find), renders the real screen,
 * and routes one-shot add-to-cart results to a snackbar. Replaces the AND-205 placeholder.
 */
@Composable
fun ProductDetailRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: ProductDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val addState by viewModel.addState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val addedLabel = stringResource(R.string.catalog_detail_added)

    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is ProductDetailEvent.AddedToCart -> snackbarHostState.showSnackbar(addedLabel)
                is ProductDetailEvent.AddToCartFailed -> snackbarHostState.showSnackbar(event.message)
            }
        }
    }

    ProductDetailScreen(
        state = state,
        addState = addState,
        snackbarHostState = snackbarHostState,
        onAddToCart = { viewModel.addToCart() },
        onRetry = viewModel::retry,
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun ProductDetailScreen(
    state: ProductDetailUiState,
    addState: AddToCartStatus,
    snackbarHostState: SnackbarHostState,
    onAddToCart: () -> Unit,
    onRetry: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val title = (state as? ProductDetailUiState.Ready)?.item?.name
        ?: stringResource(R.string.catalog_item_title)
    Scaffold(
        modifier = modifier.testTag(ProductDetailTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(title, maxLines = 1, overflow = TextOverflow.Ellipsis) },
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
        snackbarHost = { SnackbarHost(snackbarHostState) },
        bottomBar = {
            if (state is ProductDetailUiState.Ready) {
                AddToCartBar(item = state.item, addState = addState, onAddToCart = onAddToCart)
            }
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                is ProductDetailUiState.Loading -> LoadingState()

                is ProductDetailUiState.NotFound ->
                    EmptyState(
                        title = stringResource(R.string.catalog_detail_not_found_title),
                        body = stringResource(R.string.catalog_detail_not_found_body),
                        modifier = Modifier.testTag(ProductDetailTestTags.NOT_FOUND),
                    )

                is ProductDetailUiState.Error ->
                    ErrorState(
                        message = state.message,
                        onRetry = onRetry,
                        modifier = Modifier.testTag(ProductDetailTestTags.ERROR),
                    )

                is ProductDetailUiState.Ready -> ProductDetailContent(item = state.item)
            }
        }
    }
}

@Composable
private fun ProductDetailContent(item: CatalogItem) {
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(bottom = 16.dp),
    ) {
        MediaCarousel(item = item)
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(
                text = item.name,
                style = MaterialTheme.typography.headlineSmall,
                modifier = Modifier.testTag(ProductDetailTestTags.NAME),
            )
            Text(
                text = formatPrice(item.priceCents, item.currency),
                style = MaterialTheme.typography.titleLarge,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.testTag(ProductDetailTestTags.PRICE),
            )
            StockChip(item = item)
            Text(
                text = item.description?.takeIf { it.isNotBlank() }
                    ?: stringResource(R.string.catalog_detail_no_description),
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.testTag(ProductDetailTestTags.DESCRIPTION),
            )
            AttributeList(item = item)
        }
    }
}

@Composable
private fun MediaCarousel(item: CatalogItem) {
    val urls = item.imageUrls
    Box(
        Modifier
            .fillMaxWidth()
            .aspectRatio(1f)
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .testTag(ProductDetailTestTags.CAROUSEL),
    ) {
        if (urls.isEmpty()) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text(stringResource(R.string.catalog_no_image), style = MaterialTheme.typography.labelMedium)
            }
            return@Box
        }
        val pagerState = rememberPagerState(pageCount = { urls.size })
        HorizontalPager(state = pagerState, modifier = Modifier.fillMaxSize()) { page ->
            val cd = stringResource(R.string.catalog_detail_image_cd, item.name, page + 1, urls.size)
            SubcomposeAsyncImage(
                model = ImageRequest.Builder(LocalContext.current).data(urls[page]).crossfade(true).build(),
                contentDescription = cd,
                loading = { Box(Modifier.fillMaxSize()) },
                modifier = Modifier.fillMaxSize().semantics { contentDescription = cd },
            )
        }
        if (urls.size > 1) {
            Row(
                Modifier
                    .align(Alignment.BottomCenter)
                    .padding(12.dp)
                    .clearAndSetSemantics {},
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                repeat(urls.size) { index ->
                    val selected = index == pagerState.currentPage
                    Box(
                        Modifier
                            .size(8.dp)
                            .clip(CircleShape)
                            .background(
                                if (selected) MaterialTheme.colorScheme.primary else Color.White.copy(alpha = 0.6f),
                            ),
                    )
                }
            }
        }
    }
}

@Composable
private fun StockChip(item: CatalogItem) {
    val label = when {
        item.isOutOfStock -> stringResource(R.string.catalog_detail_out_of_stock)
        item.stockStatus == "low_stock" && item.stockCount != null ->
            stringResource(R.string.catalog_detail_low_stock, item.stockCount)
        else -> stringResource(R.string.catalog_detail_in_stock)
    }
    AssistChip(
        onClick = {},
        enabled = false,
        label = { Text(label) },
        colors = AssistChipDefaults.assistChipColors(),
        modifier = Modifier.testTag(ProductDetailTestTags.STOCK),
    )
}

@Composable
private fun AttributeList(item: CatalogItem) {
    val attributes = item.attributes
    if (attributes.isEmpty()) return
    Column(
        Modifier.testTag(ProductDetailTestTags.ATTRIBUTES),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text(
            stringResource(R.string.catalog_detail_attributes),
            style = MaterialTheme.typography.titleMedium,
        )
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            attributes.forEach { (key, value) ->
                Surface(
                    color = MaterialTheme.colorScheme.surfaceVariant,
                    shape = RoundedCornerShape(8.dp),
                ) {
                    Text(
                        text = "$key: $value",
                        style = MaterialTheme.typography.labelMedium,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                    )
                }
            }
        }
    }
}

@Composable
private fun AddToCartBar(
    item: CatalogItem,
    addState: AddToCartStatus,
    onAddToCart: () -> Unit,
) {
    val outOfStock = item.isOutOfStock
    val inFlight = addState == AddToCartStatus.InFlight
    val label = when {
        outOfStock -> stringResource(R.string.catalog_detail_out_of_stock)
        inFlight -> stringResource(R.string.catalog_detail_adding)
        else -> stringResource(R.string.catalog_detail_add_to_cart)
    }
    Surface(tonalElevation = 3.dp) {
        Box(Modifier.fillMaxWidth().padding(16.dp)) {
            Button(
                onClick = onAddToCart,
                enabled = !outOfStock && !inFlight,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(ProductDetailTestTags.ADD_TO_CART)
                    .semantics { contentDescription = label },
            ) {
                if (inFlight) {
                    CircularProgressIndicator(
                        strokeWidth = 2.dp,
                        modifier = Modifier.size(18.dp),
                        color = MaterialTheme.colorScheme.onPrimary,
                    )
                    Spacer(Modifier.width(8.dp))
                }
                Text(label)
            }
        }
    }
}
