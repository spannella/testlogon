@file:OptIn(ExperimentalLayoutApi::class, ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.catalog

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Favorite
import androidx.compose.material.icons.filled.FavoriteBorder
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.outlined.StarBorder
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
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
import com.testlogon.android.data.catalog.CatalogReview
import androidx.compose.ui.text.input.ImeAction

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
    // ECOMX-44 (B7): quantity stepper.
    const val QTY_STEPPER = "product_detail_qty_stepper"
    const val QTY_DECREASE = "product_detail_qty_decrease"
    const val QTY_INCREASE = "product_detail_qty_increase"
    const val QTY_VALUE = "product_detail_qty_value"
    const val NOT_FOUND = "product_detail_not_found"
    const val ERROR = "product_detail_error"

    // ECOM — wishlist heart + reviews section.
    const val WISHLIST_TOGGLE = "wishlist_toggle"
    const val REVIEW_SECTION = "review_section"
    const val REVIEW_SUMMARY = "review_summary"
    const val REVIEW_LIST = "review_list"
    const val REVIEW_ROW = "review_row"
    const val REVIEW_EMPTY = "review_empty"
    const val REVIEW_TITLE_INPUT = "review_title_input"
    const val REVIEW_BODY_INPUT = "review_body_input"
    const val REVIEW_SUBMIT = "review_submit"
    const val REVIEW_RATING = "review_rating_input"
    const val REVIEW_DELETE = "review_delete"
    fun ratingStar(index: Int) = "review_rating_star_$index"
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
    val reviewsState by viewModel.reviewsState.collectAsStateWithLifecycle()
    val reviewSubmitState by viewModel.reviewSubmitState.collectAsStateWithLifecycle()
    val isSaved by viewModel.isSaved.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val addedLabel = stringResource(R.string.catalog_detail_added)
    val reviewSubmittedLabel = stringResource(R.string.review_submitted)
    val reviewDeletedLabel = stringResource(R.string.review_deleted)

    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is ProductDetailEvent.AddedToCart -> snackbarHostState.showSnackbar(addedLabel)
                is ProductDetailEvent.AddToCartFailed -> snackbarHostState.showSnackbar(event.message)
                is ProductDetailEvent.ReviewSubmitted -> snackbarHostState.showSnackbar(reviewSubmittedLabel)
                is ProductDetailEvent.ReviewDeleted -> snackbarHostState.showSnackbar(reviewDeletedLabel)
                is ProductDetailEvent.ReviewSubmitFailed -> snackbarHostState.showSnackbar(event.message)
                is ProductDetailEvent.WishlistFailed -> snackbarHostState.showSnackbar(event.message)
            }
        }
    }

    ProductDetailScreen(
        state = state,
        addState = addState,
        reviewsState = reviewsState,
        reviewSubmitState = reviewSubmitState,
        isSaved = isSaved,
        snackbarHostState = snackbarHostState,
        onAddToCart = { qty -> viewModel.addToCart(qty) },
        onToggleWishlist = viewModel::toggleWishlist,
        onSubmitReview = viewModel::submitReview,
        onDeleteReview = viewModel::deleteReview,
        onRetryReviews = viewModel::retryReviews,
        onRetry = viewModel::retry,
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun ProductDetailScreen(
    state: ProductDetailUiState,
    addState: AddToCartStatus,
    reviewsState: ReviewsUiState,
    reviewSubmitState: ReviewSubmitStatus,
    isSaved: Boolean,
    snackbarHostState: SnackbarHostState,
    onAddToCart: (quantity: Int) -> Unit,
    onToggleWishlist: () -> Unit,
    onSubmitReview: (rating: Int, title: String, body: String) -> Unit,
    onDeleteReview: (reviewId: String) -> Unit,
    onRetryReviews: () -> Unit,
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
                actions = {
                    if (state is ProductDetailUiState.Ready) {
                        val heartCd = stringResource(
                            if (isSaved) R.string.wishlist_remove else R.string.wishlist_add,
                        )
                        IconButton(
                            onClick = onToggleWishlist,
                            modifier = Modifier
                                .testTag(ProductDetailTestTags.WISHLIST_TOGGLE)
                                .semantics { contentDescription = heartCd },
                        ) {
                            Icon(
                                imageVector = if (isSaved) Icons.Filled.Favorite else Icons.Filled.FavoriteBorder,
                                contentDescription = heartCd,
                                tint = if (isSaved) MaterialTheme.colorScheme.primary
                                else MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
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

                is ProductDetailUiState.Ready -> ProductDetailContent(
                    item = state.item,
                    reviewsState = reviewsState,
                    reviewSubmitState = reviewSubmitState,
                    onSubmitReview = onSubmitReview,
                    onDeleteReview = onDeleteReview,
                    onRetryReviews = onRetryReviews,
                )
            }
        }
    }
}

@Composable
private fun ProductDetailContent(
    item: CatalogItem,
    reviewsState: ReviewsUiState,
    reviewSubmitState: ReviewSubmitStatus,
    onSubmitReview: (rating: Int, title: String, body: String) -> Unit,
    onDeleteReview: (reviewId: String) -> Unit,
    onRetryReviews: () -> Unit,
) {
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
            HorizontalDivider(Modifier.padding(vertical = 4.dp))
            ReviewsSection(
                state = reviewsState,
                submitState = reviewSubmitState,
                onSubmitReview = onSubmitReview,
                onDeleteReview = onDeleteReview,
                onRetryReviews = onRetryReviews,
            )
        }
    }
}

/** ECOM (reviews) — the reviews section: summary + list + compose row + delete-own. */
@Composable
private fun ReviewsSection(
    state: ReviewsUiState,
    submitState: ReviewSubmitStatus,
    onSubmitReview: (rating: Int, title: String, body: String) -> Unit,
    onDeleteReview: (reviewId: String) -> Unit,
    onRetryReviews: () -> Unit,
) {
    Column(
        Modifier
            .fillMaxWidth()
            .testTag(ProductDetailTestTags.REVIEW_SECTION),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = stringResource(R.string.review_section_title),
            style = MaterialTheme.typography.titleMedium,
        )
        when (state) {
            is ReviewsUiState.Loading ->
                CircularProgressIndicator(Modifier.size(24.dp))

            is ReviewsUiState.Error ->
                TextButton(onClick = onRetryReviews) {
                    Text(stringResource(R.string.review_load_error_retry))
                }

            is ReviewsUiState.Ready -> {
                ReviewSummary(state)
                if (state.reviews.isEmpty()) {
                    Text(
                        text = stringResource(R.string.review_empty),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.testTag(ProductDetailTestTags.REVIEW_EMPTY),
                    )
                } else {
                    Column(
                        Modifier.testTag(ProductDetailTestTags.REVIEW_LIST),
                        verticalArrangement = Arrangement.spacedBy(10.dp),
                    ) {
                        state.reviews.forEach { review ->
                            ReviewRow(
                                review = review,
                                isOwn = review.isOwnedBy(state.currentUserSub),
                                onDelete = { onDeleteReview(review.reviewId) },
                            )
                        }
                    }
                }
                HorizontalDivider(Modifier.padding(vertical = 4.dp))
                ReviewComposer(submitState = submitState, onSubmitReview = onSubmitReview)
            }
        }
    }
}

@Composable
private fun ReviewSummary(state: ReviewsUiState.Ready) {
    Row(
        Modifier.testTag(ProductDetailTestTags.REVIEW_SUMMARY),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        val avg = state.averageRating
        if (avg != null) {
            StarRow(rating = avg.toInt())
            Text(
                text = stringResource(R.string.review_summary, avg, state.count),
                style = MaterialTheme.typography.bodyMedium,
            )
        } else {
            Text(
                text = stringResource(R.string.review_no_ratings),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun ReviewRow(review: CatalogReview, isOwn: Boolean, onDelete: () -> Unit) {
    Column(
        Modifier
            .fillMaxWidth()
            .testTag(ProductDetailTestTags.REVIEW_ROW),
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            StarRow(rating = review.rating)
            Spacer(Modifier.width(8.dp))
            Text(
                text = review.reviewer?.takeIf { it.isNotBlank() }
                    ?: stringResource(R.string.review_anonymous),
                style = MaterialTheme.typography.labelLarge,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f, fill = false),
            )
            Spacer(Modifier.weight(1f))
            Text(
                text = review.createdAt.take(10),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (isOwn) {
                IconButton(
                    onClick = onDelete,
                    modifier = Modifier
                        .size(28.dp)
                        .testTag(ProductDetailTestTags.REVIEW_DELETE),
                ) {
                    Icon(
                        Icons.Filled.Delete,
                        contentDescription = stringResource(R.string.review_delete),
                        modifier = Modifier.size(18.dp),
                    )
                }
            }
        }
        review.title?.takeIf { it.isNotBlank() }?.let {
            Text(it, style = MaterialTheme.typography.titleSmall)
        }
        review.body?.takeIf { it.isNotBlank() }?.let {
            Text(it, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

/** A static row of 5 stars filled up to [rating]. */
@Composable
private fun StarRow(rating: Int) {
    Row(Modifier.clearAndSetSemantics {}) {
        repeat(5) { i ->
            Icon(
                imageVector = if (i < rating) Icons.Filled.Star else Icons.Outlined.StarBorder,
                contentDescription = null,
                tint = if (i < rating) MaterialTheme.colorScheme.primary
                else MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(16.dp),
            )
        }
    }
}

/** ECOM (reviews) — star-rating + title + body + submit. */
@Composable
private fun ReviewComposer(
    submitState: ReviewSubmitStatus,
    onSubmitReview: (rating: Int, title: String, body: String) -> Unit,
) {
    var rating by remember { mutableIntStateOf(0) }
    var title by remember { mutableStateOf("") }
    var body by remember { mutableStateOf("") }
    val inFlight = submitState == ReviewSubmitStatus.InFlight

    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            text = stringResource(R.string.review_write_title),
            style = MaterialTheme.typography.titleSmall,
        )
        // Interactive star picker.
        Row(Modifier.testTag(ProductDetailTestTags.REVIEW_RATING)) {
            repeat(5) { i ->
                val filled = i < rating
                val starCd = stringResource(R.string.review_rate_stars, i + 1)
                Icon(
                    imageVector = if (filled) Icons.Filled.Star else Icons.Outlined.StarBorder,
                    contentDescription = starCd,
                    tint = if (filled) MaterialTheme.colorScheme.primary
                    else MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier
                        .size(32.dp)
                        .testTag(ProductDetailTestTags.ratingStar(i + 1))
                        .clickable { rating = i + 1 }
                        .semantics { contentDescription = starCd },
                )
            }
        }
        OutlinedTextField(
            value = title,
            onValueChange = { title = it },
            label = { Text(stringResource(R.string.review_title_label)) },
            singleLine = true,
            modifier = Modifier
                .fillMaxWidth()
                .testTag(ProductDetailTestTags.REVIEW_TITLE_INPUT),
        )
        OutlinedTextField(
            value = body,
            onValueChange = { body = it },
            label = { Text(stringResource(R.string.review_body_label)) },
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Default),
            modifier = Modifier
                .fillMaxWidth()
                .height(96.dp)
                .testTag(ProductDetailTestTags.REVIEW_BODY_INPUT),
        )
        OutlinedButton(
            onClick = {
                onSubmitReview(rating, title, body)
                rating = 0
                title = ""
                body = ""
            },
            enabled = rating in 1..5 && !inFlight,
            modifier = Modifier
                .fillMaxWidth()
                .testTag(ProductDetailTestTags.REVIEW_SUBMIT),
        ) {
            if (inFlight) {
                CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(16.dp))
                Spacer(Modifier.width(8.dp))
            }
            Text(stringResource(R.string.review_submit))
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
    onAddToCart: (quantity: Int) -> Unit,
) {
    val outOfStock = item.isOutOfStock
    val inFlight = addState == AddToCartStatus.InFlight
    val label = when {
        outOfStock -> stringResource(R.string.catalog_detail_out_of_stock)
        inFlight -> stringResource(R.string.catalog_detail_adding)
        else -> stringResource(R.string.catalog_detail_add_to_cart)
    }
    // ECOMX-44 (B7): quantity stepper. Clamped to 1..maxQty (available stock when known).
    val maxQty = if (item.stockStatus == "unlimited" || item.stockCount == null) MAX_QTY
    else (item.stockCount ?: 1).coerceAtLeast(1).coerceAtMost(MAX_QTY)
    var qty by rememberSaveable(item.itemId) { mutableStateOf(1) }
    if (qty > maxQty) qty = maxQty

    Surface(tonalElevation = 3.dp) {
        Column(
            Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            if (!outOfStock) {
                Row(
                    Modifier.fillMaxWidth().testTag(ProductDetailTestTags.QTY_STEPPER),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
                ) {
                    Text(stringResource(R.string.pdp_qty_label), style = MaterialTheme.typography.titleSmall)
                    Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                        androidx.compose.material3.OutlinedIconButton(
                            onClick = { if (qty > 1) qty-- },
                            enabled = qty > 1 && !inFlight,
                            modifier = Modifier.testTag(ProductDetailTestTags.QTY_DECREASE)
                                .semantics { contentDescription = "Decrease quantity" },
                        ) { Text("−", style = MaterialTheme.typography.titleLarge) }
                        Text(
                            text = qty.toString(),
                            style = MaterialTheme.typography.titleMedium,
                            modifier = Modifier.padding(horizontal = 16.dp)
                                .testTag(ProductDetailTestTags.QTY_VALUE),
                        )
                        androidx.compose.material3.OutlinedIconButton(
                            onClick = { if (qty < maxQty) qty++ },
                            enabled = qty < maxQty && !inFlight,
                            modifier = Modifier.testTag(ProductDetailTestTags.QTY_INCREASE)
                                .semantics { contentDescription = "Increase quantity" },
                        ) { Text("+", style = MaterialTheme.typography.titleLarge) }
                    }
                }
            }
            Button(
                onClick = { onAddToCart(qty) },
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

private const val MAX_QTY = 99
