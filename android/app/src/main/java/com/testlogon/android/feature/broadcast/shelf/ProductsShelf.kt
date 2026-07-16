package com.testlogon.android.feature.broadcast.shelf

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ShoppingBag
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import com.testlogon.android.data.report.ReportTarget
import com.testlogon.android.feature.report.ContentReportSheetHost
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import coil.compose.SubcomposeAsyncImage
import coil.request.ImageRequest
import com.testlogon.android.R
import com.testlogon.android.data.broadcast.shelf.ShelfProduct
import com.testlogon.android.feature.catalog.formatPrice

/** AND-283 — stable testTags for the products shelf. */
object ShelfTestTags {
    const val TOGGLE = "shelf_toggle"
    const val ROW = "shelf_row"
    const val CARD = "shelf_card"
    const val BUY = "shelf_buy"
    const val RETRY = "shelf_retry"
}

/**
 * AND-283 — host that owns the assisted-inject [ProductsShelfViewModel] keyed by [sessionId] and routes
 * Buy to the AND-206 product detail. [onBuy] receives (categoryId, itemId) so the host (AND-280 viewer)
 * can navigate to `shop/{categoryId}/{itemId}`.
 */
@Composable
fun ProductsShelfPanel(
    sessionId: String,
    onBuy: (categoryId: String, itemId: String) -> Unit,
    modifier: Modifier = Modifier,
    viewModel: ProductsShelfViewModel = hiltViewModel<ProductsShelfViewModel, ProductsShelfViewModel.Factory>(
        key = "products_shelf_$sessionId",
        creationCallback = { factory -> factory.create(sessionId) },
    ),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val expanded by viewModel.expanded.collectAsStateWithLifecycle()
    var reportTarget by remember { mutableStateOf<ReportTarget?>(null) }
    ProductsShelf(
        state = state,
        expanded = expanded,
        onToggle = viewModel::setExpanded,
        onBuy = { product -> onBuy(product.categoryId, product.itemId) },
        onReport = { product ->
            reportTarget = ReportTarget.Content(
                product.itemId,
                "catalog_item",
                categoryId = product.categoryId,
                itemId = product.itemId,
            )
        },
        onRetry = viewModel::retry,
        modifier = modifier,
    )
    // MODX-12 - report a catalog product from the live shelf.
    ContentReportSheetHost(target = reportTarget, onDismiss = { reportTarget = null })
}

/**
 * AND-283 — the products shelf overlay composed into the AND-280 viewer. A toggle on the player chrome
 * opens/closes a horizontal [LazyRow] of compact cards over the player. Buy navigates to the AND-206
 * product detail (`shop/{categoryId}/{itemId}`) via [onBuy]; the shelf performs no mutation. Tiles reuse
 * the AND-205 [formatPrice] money formatter for parity with the catalog.
 */
@Composable
fun ProductsShelf(
    state: ProductsShelfUiState,
    expanded: Boolean,
    onToggle: (Boolean) -> Unit,
    onBuy: (ShelfProduct) -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
    onReport: (ShelfProduct) -> Unit = {},
) {
    Column(modifier = modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            val toggleCd = stringResource(
                if (expanded) R.string.shelf_hide else R.string.shelf_show,
            )
            IconButton(
                onClick = { onToggle(!expanded) },
                modifier = Modifier.testTag(ShelfTestTags.TOGGLE).semantics { contentDescription = toggleCd },
            ) {
                Icon(Icons.Filled.ShoppingBag, contentDescription = toggleCd)
            }
            Text(stringResource(R.string.shelf_title), style = MaterialTheme.typography.labelLarge)
        }
        AnimatedVisibility(visible = expanded) {
            Box(modifier = Modifier.fillMaxWidth().padding(8.dp)) {
                when (state) {
                    ProductsShelfUiState.Idle, ProductsShelfUiState.Loading -> ShelfLoadingRow()
                    ProductsShelfUiState.Empty ->
                        ShelfMessage(stringResource(R.string.shelf_empty))
                    is ProductsShelfUiState.Error -> ShelfErrorRow(state.retryable, onRetry)
                    is ProductsShelfUiState.Ready -> ShelfRow(state.products, onBuy, onReport)
                }
            }
        }
    }
}

@Composable
private fun ShelfRow(products: List<ShelfProduct>, onBuy: (ShelfProduct) -> Unit, onReport: (ShelfProduct) -> Unit = {}) {
    LazyRow(
        modifier = Modifier.fillMaxWidth().testTag(ShelfTestTags.ROW),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        items(products, key = { it.itemId }) { product ->
            ProductShelfCard(product = product, onBuy = { onBuy(product) }, onReport = { onReport(product) })
        }
    }
}

@Composable
private fun ProductShelfCard(product: ShelfProduct, onBuy: () -> Unit, onReport: () -> Unit = {}) {
    val cardCd = stringResource(
        R.string.shelf_card_cd,
        product.name,
        formatPrice(product.priceCents, product.currency),
    )
    Column(
        modifier = Modifier
            .width(140.dp)
            .testTag(ShelfTestTags.CARD)
            .semantics { contentDescription = cardCd },
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .aspectRatio(1f)
                .clip(RoundedCornerShape(8.dp))
                .background(MaterialTheme.colorScheme.surfaceVariant),
        ) {
            val thumb = product.imageUrl
            if (thumb != null) {
                SubcomposeAsyncImage(
                    model = ImageRequest.Builder(LocalContext.current).data(thumb).crossfade(true).build(),
                    contentDescription = null,
                    loading = { Box(Modifier.size(24.dp)) },
                    modifier = Modifier.fillMaxWidth().aspectRatio(1f),
                )
            } else {
                Box(Modifier.fillMaxWidth().aspectRatio(1f), contentAlignment = Alignment.Center) {
                    Text(stringResource(R.string.catalog_no_image), style = MaterialTheme.typography.labelSmall)
                }
            }
        }
        Text(
            text = product.name,
            style = MaterialTheme.typography.titleSmall,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.padding(top = 4.dp),
        )
        Text(
            text = formatPrice(product.priceCents, product.currency),
            style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.primary,
        )
        val original = product.originalPriceCents
        if (original != null) {
            Text(
                text = formatPrice(original, product.currency),
                style = MaterialTheme.typography.labelSmall,
                textDecoration = TextDecoration.LineThrough,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Button(
            onClick = onBuy,
            modifier = Modifier.fillMaxWidth().testTag(ShelfTestTags.BUY),
        ) {
            Text(stringResource(R.string.shelf_buy))
        }
        TextButton(
            onClick = onReport,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(stringResource(R.string.msg_action_report))
        }
    }
}

@Composable
private fun ShelfLoadingRow() {
    Box(modifier = Modifier.fillMaxWidth().padding(16.dp), contentAlignment = Alignment.Center) {
        CircularProgressIndicator()
    }
}

@Composable
private fun ShelfMessage(message: String) {
    Box(modifier = Modifier.fillMaxWidth().padding(16.dp), contentAlignment = Alignment.Center) {
        Text(message, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun ShelfErrorRow(retryable: Boolean, onRetry: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(
            stringResource(R.string.shelf_error),
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.weight(1f),
        )
        if (retryable) {
            TextButton(onClick = onRetry, modifier = Modifier.testTag(ShelfTestTags.RETRY)) {
                Text(stringResource(R.string.shelf_retry))
            }
        }
    }
}
