@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.cart

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Remove
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
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
import com.testlogon.android.data.cart.CartItem
import com.testlogon.android.data.cart.FullCart
import com.testlogon.android.feature.catalog.formatPrice

/** AND-211 / AND-212 — stable test tags for the cart screen. */
object CartTestTags {
    const val SCREEN = "cart_screen"
    const val LIST = "cart_list"
    const val SEARCH_FIELD = "cart_search_field"
    const val SEARCH_CLEAR = "cart_search_clear"
    const val MATCHED_HEADER = "cart_matched_header"
    const val NO_RESULTS = "cart_no_results"
    const val EMPTY = "cart_empty"
    const val ERROR = "cart_error"
    const val TOTAL = "cart_total"
    const val CHECKOUT = "cart_checkout"

    fun row(sku: String) = "cart_row_$sku"
    fun qty(sku: String) = "cart_qty_$sku"
    fun inc(sku: String) = "cart_inc_$sku"
    fun dec(sku: String) = "cart_dec_$sku"
    fun remove(sku: String) = "cart_remove_$sku"
    fun lineTotal(sku: String) = "cart_line_total_$sku"
}

/**
 * AND-211 — cart route. Loads the cart, routes one-shot mutation failures to a snackbar, and navigates
 * to checkout / catalog as requested.
 */
@Composable
fun CartRoute(
    onCheckout: (cartId: String, totalCents: Long, currency: String) -> Unit,
    onBrowseCatalog: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: CartViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is CartEvent.MutationFailed -> snackbarHostState.showSnackbar(event.message)
            }
        }
    }

    CartScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onQueryChange = viewModel::onQueryChange,
        onClearQuery = viewModel::onClearQuery,
        onQuantityChange = viewModel::onQuantityChange,
        onRemove = viewModel::onRemove,
        onCheckout = {
            state.cart?.let { onCheckout(it.cartId, it.totalCents, it.currency) }
        },
        onBrowseCatalog = onBrowseCatalog,
        onRetry = viewModel::retry,
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun CartScreen(
    state: CartUiState,
    snackbarHostState: SnackbarHostState,
    onQueryChange: (String) -> Unit,
    onClearQuery: () -> Unit,
    onQuantityChange: (sku: String, qty: Int) -> Unit,
    onRemove: (sku: String) -> Unit,
    onCheckout: () -> Unit,
    onBrowseCatalog: () -> Unit,
    onRetry: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val cart = state.cart
    Scaffold(
        modifier = modifier.testTag(CartTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.cart_title)) },
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
            if (cart != null && !cart.isEmpty) {
                CartBottomBar(
                    cart = cart,
                    checkoutEnabled = !state.isMutating,
                    onCheckout = onCheckout,
                )
            }
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (val load = state.load) {
                is CartLoadState.Loading -> LoadingState()

                is CartLoadState.Error ->
                    ErrorState(
                        message = load.message,
                        onRetry = onRetry,
                        modifier = Modifier.testTag(CartTestTags.ERROR),
                    )

                is CartLoadState.Loaded ->
                    if (load.cart.isEmpty) {
                        EmptyState(
                            title = stringResource(R.string.cart_empty_title),
                            body = stringResource(R.string.cart_empty_body),
                            actionLabel = stringResource(R.string.cart_browse_catalog),
                            onAction = onBrowseCatalog,
                            modifier = Modifier.testTag(CartTestTags.EMPTY),
                        )
                    } else {
                        CartContent(
                            state = state,
                            onQueryChange = onQueryChange,
                            onClearQuery = onClearQuery,
                            onQuantityChange = onQuantityChange,
                            onRemove = onRemove,
                        )
                    }
            }
        }
    }
}

@Composable
private fun CartContent(
    state: CartUiState,
    onQueryChange: (String) -> Unit,
    onClearQuery: () -> Unit,
    onQuantityChange: (sku: String, qty: Int) -> Unit,
    onRemove: (sku: String) -> Unit,
) {
    val cart = state.cart ?: return
    val filtered = state.filtered
    Column(Modifier.fillMaxSize()) {
        CartSearchField(
            query = state.query,
            onQueryChange = onQueryChange,
            onClear = onClearQuery,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
        )
        if (filtered.isFiltering) {
            MatchedHeader(filtered = filtered, currency = cart.currency)
        }
        if (state.query.isNotBlank() && filtered.items.isEmpty()) {
            NoResults(query = state.query, onClear = onClearQuery)
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize().testTag(CartTestTags.LIST),
                contentPadding = androidx.compose.foundation.layout.PaddingValues(bottom = 16.dp),
            ) {
                items(filtered.items, key = { it.sku }) { item ->
                    CartLineRow(
                        item = item,
                        currency = cart.currency,
                        inFlight = state.mutatingSku == item.sku,
                        controlsEnabled = !state.isMutating,
                        onQuantityChange = onQuantityChange,
                        onRemove = onRemove,
                    )
                    HorizontalDivider()
                }
            }
        }
    }
}

@Composable
fun CartSearchField(
    query: String,
    onQueryChange: (String) -> Unit,
    onClear: () -> Unit,
    modifier: Modifier = Modifier,
) {
    OutlinedTextField(
        value = query,
        onValueChange = onQueryChange,
        singleLine = true,
        leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
        trailingIcon = {
            if (query.isNotEmpty()) {
                IconButton(onClick = onClear, modifier = Modifier.testTag(CartTestTags.SEARCH_CLEAR)) {
                    Icon(
                        Icons.Filled.Clear,
                        contentDescription = stringResource(R.string.cart_search_clear),
                    )
                }
            }
        },
        placeholder = { Text(stringResource(R.string.cart_search_hint)) },
        modifier = modifier
            .fillMaxWidth()
            .testTag(CartTestTags.SEARCH_FIELD)
            .semantics { contentDescription = "" },
    )
}

@Composable
private fun MatchedHeader(filtered: FilteredCart, currency: String) {
    val label = stringResource(
        R.string.cart_search_matched,
        filtered.matchedCount,
        filtered.totalCount,
        formatPrice(filtered.matchedSubtotalCents, currency),
    )
    Text(
        text = label,
        style = MaterialTheme.typography.labelLarge,
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 4.dp)
            .testTag(CartTestTags.MATCHED_HEADER)
            .semantics { liveRegion = LiveRegionMode.Polite },
    )
}

@Composable
private fun NoResults(query: String, onClear: () -> Unit) {
    EmptyState(
        title = stringResource(R.string.cart_search_no_results, query),
        actionLabel = stringResource(R.string.cart_search_clear_action),
        onAction = onClear,
        modifier = Modifier.testTag(CartTestTags.NO_RESULTS),
    )
}

@Composable
private fun CartLineRow(
    item: CartItem,
    currency: String,
    inFlight: Boolean,
    controlsEnabled: Boolean,
    onQuantityChange: (sku: String, qty: Int) -> Unit,
    onRemove: (sku: String) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(CartTestTags.row(item.sku))
            .padding(16.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Box(
            Modifier
                .size(56.dp)
                .clip(RoundedCornerShape(8.dp))
                .background(MaterialTheme.colorScheme.surfaceVariant),
        ) {
            val url = item.imageUrl
            if (url != null) {
                SubcomposeAsyncImage(
                    model = ImageRequest.Builder(LocalContext.current).data(url).crossfade(true).build(),
                    contentDescription = null,
                    loading = { Box(Modifier.fillMaxSize()) },
                    error = { Box(Modifier.fillMaxSize()) },
                    modifier = Modifier.fillMaxSize(),
                )
            }
        }
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                text = item.name,
                style = MaterialTheme.typography.titleSmall,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = stringResource(
                    R.string.cart_unit_price,
                    formatPrice(item.unitPriceCents, currency),
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            QuantityStepper(
                item = item,
                enabled = controlsEnabled,
                onQuantityChange = onQuantityChange,
            )
        }
        Column(horizontalAlignment = Alignment.End, verticalArrangement = Arrangement.spacedBy(8.dp)) {
            if (inFlight) {
                CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(18.dp))
            } else {
                IconButton(
                    onClick = { onRemove(item.sku) },
                    enabled = controlsEnabled,
                    modifier = Modifier
                        .testTag(CartTestTags.remove(item.sku))
                        .semantics {
                            contentDescription = "Remove ${item.name} from cart"
                        },
                ) {
                    Icon(Icons.Filled.Delete, contentDescription = null)
                }
            }
            Text(
                text = formatPrice(item.lineTotalCents, currency),
                style = MaterialTheme.typography.titleSmall,
                modifier = Modifier.testTag(CartTestTags.lineTotal(item.sku)),
            )
        }
    }
}

@Composable
private fun QuantityStepper(
    item: CartItem,
    enabled: Boolean,
    onQuantityChange: (sku: String, qty: Int) -> Unit,
) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        IconButton(
            onClick = { onQuantityChange(item.sku, item.quantity - 1) },
            enabled = enabled && item.quantity > 1,
            modifier = Modifier
                .testTag(CartTestTags.dec(item.sku))
                .semantics { contentDescription = "Decrease quantity of ${item.name}" },
        ) {
            Icon(Icons.Filled.Remove, contentDescription = null)
        }
        Text(
            text = item.quantity.toString(),
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.testTag(CartTestTags.qty(item.sku)),
        )
        IconButton(
            onClick = { onQuantityChange(item.sku, item.quantity + 1) },
            enabled = enabled,
            modifier = Modifier
                .testTag(CartTestTags.inc(item.sku))
                .semantics { contentDescription = "Increase quantity of ${item.name}" },
        ) {
            Icon(Icons.Filled.Add, contentDescription = null)
        }
    }
}

@Composable
private fun CartBottomBar(
    cart: FullCart,
    checkoutEnabled: Boolean,
    onCheckout: () -> Unit,
) {
    Surface(tonalElevation = 3.dp) {
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(stringResource(R.string.cart_total_label), style = MaterialTheme.typography.titleMedium)
                Text(
                    text = formatPrice(cart.totalCents, cart.currency),
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.testTag(CartTestTags.TOTAL),
                )
            }
            Button(
                onClick = onCheckout,
                enabled = checkoutEnabled,
                modifier = Modifier.fillMaxWidth().testTag(CartTestTags.CHECKOUT),
            ) {
                if (!checkoutEnabled) {
                    CircularProgressIndicator(
                        strokeWidth = 2.dp,
                        modifier = Modifier.size(18.dp),
                        color = MaterialTheme.colorScheme.onPrimary,
                    )
                    Spacer(Modifier.width(8.dp))
                }
                Text(stringResource(R.string.cart_checkout))
            }
        }
    }
}
