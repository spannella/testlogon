@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.wishlist

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
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Favorite
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
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
import com.testlogon.android.data.wishlist.WishlistItem
import com.testlogon.android.feature.catalog.formatPrice

/** ECOM — stable test tags for the Wishlist screen. */
object WishlistTestTags {
    const val SCREEN = "wishlist_screen"
    const val LIST = "wishlist_list"
    const val ROW = "wishlist_row"
    const val EMPTY = "wishlist_empty"
    const val ERROR = "wishlist_error"
    const val REMOVE = "wishlist_remove"
}

/**
 * ECOM — Wishlist route (SHOP hub entry). Lists the user's saved catalog items; a row taps through to
 * product detail, the heart removes it.
 */
@Composable
fun WishlistRoute(
    onOpenItem: (categoryId: String, itemId: String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: WishlistViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is WishlistEvent.RemoveFailed -> snackbarHostState.showSnackbar(event.message)
            }
        }
    }

    WishlistScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onOpenItem = onOpenItem,
        onRemove = viewModel::remove,
        onRetry = viewModel::refresh,
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun WishlistScreen(
    state: WishlistUiState,
    snackbarHostState: SnackbarHostState,
    onOpenItem: (categoryId: String, itemId: String) -> Unit,
    onRemove: (WishlistItem) -> Unit,
    onRetry: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(WishlistTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.wishlist_title)) },
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
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                is WishlistUiState.Loading -> LoadingState()

                is WishlistUiState.Error ->
                    ErrorState(
                        message = state.message,
                        onRetry = onRetry,
                        modifier = Modifier.testTag(WishlistTestTags.ERROR),
                    )

                is WishlistUiState.Content ->
                    if (state.items.isEmpty()) {
                        EmptyState(
                            title = stringResource(R.string.wishlist_empty_title),
                            body = stringResource(R.string.wishlist_empty_body),
                            modifier = Modifier.testTag(WishlistTestTags.EMPTY),
                        )
                    } else {
                        LazyColumn(
                            Modifier.fillMaxSize().testTag(WishlistTestTags.LIST),
                            contentPadding = PaddingValues(12.dp),
                            verticalArrangement = Arrangement.spacedBy(10.dp),
                        ) {
                            items(state.items, key = { it.key }) { item ->
                                WishlistRow(
                                    item = item,
                                    onClick = { onOpenItem(item.categoryId, item.itemId) },
                                    onRemove = { onRemove(item) },
                                )
                            }
                        }
                    }
            }
        }
    }
}

@Composable
private fun WishlistRow(
    item: WishlistItem,
    onClick: () -> Unit,
    onRemove: () -> Unit,
) {
    Row(
        Modifier
            .fillMaxWidth()
            .testTag(WishlistTestTags.ROW)
            .clickable(onClick = onClick)
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Box(
            Modifier
                .size(64.dp)
                .clip(RoundedCornerShape(8.dp))
                .background(MaterialTheme.colorScheme.surfaceVariant),
        ) {
            val thumb = item.thumbnailUrl
            val cd = item.name ?: stringResource(R.string.catalog_item_title)
            if (thumb != null) {
                SubcomposeAsyncImage(
                    model = ImageRequest.Builder(LocalContext.current).data(thumb).crossfade(true).build(),
                    contentDescription = cd,
                    loading = { Box(Modifier.fillMaxSize()) },
                    modifier = Modifier.fillMaxSize().semantics { contentDescription = cd },
                )
            }
        }
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(
                text = item.name ?: stringResource(R.string.catalog_item_title),
                style = MaterialTheme.typography.titleSmall,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
            item.priceCents?.let {
                Text(
                    text = formatPrice(it, item.currency),
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
            if (!item.available) {
                Text(
                    text = stringResource(R.string.wishlist_unavailable),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
        }
        val removeCd = stringResource(R.string.wishlist_remove)
        IconButton(
            onClick = onRemove,
            modifier = Modifier
                .testTag(WishlistTestTags.REMOVE)
                .semantics { contentDescription = removeCd },
        ) {
            Icon(
                Icons.Filled.Favorite,
                contentDescription = removeCd,
                tint = MaterialTheme.colorScheme.primary,
            )
        }
    }
}
