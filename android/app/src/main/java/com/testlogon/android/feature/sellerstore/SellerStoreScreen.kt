@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.sellerstore

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.outlined.Campaign
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.Edit
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.catalog.CatalogCategory
import com.testlogon.android.data.catalog.CatalogItem
import com.testlogon.android.feature.catalog.formatPrice

/** ECOM (seller store) — stable test tags. */
object SellerStoreTestTags {
    const val SCREEN = "seller_store_screen"
    const val NEW_CATEGORY = "seller_store_new_category"
    const val CATEGORY_CHIP = "seller_store_category_chip"
    const val DELETE_CATEGORY = "seller_store_delete_category"
    const val ADD_ITEM = "seller_store_add_item"
    const val ITEM_ROW = "seller_store_item_row"
    const val ITEM_EDIT = "seller_store_item_edit"
    const val ITEM_DELETE = "seller_store_item_delete"
    const val ITEM_BOOST = "seller_store_item_boost"
    const val BOOST_DIALOG = "seller_store_boost_dialog"
    const val BOOST_BUDGET = "seller_store_boost_budget"
    const val BOOST_BID = "seller_store_boost_bid"
    const val BOOST_SUBMIT = "seller_store_boost_submit"
    const val EMPTY = "seller_store_empty"
    const val ERROR = "seller_store_error"
}

@Composable
fun SellerStoreRoute(
    onEditItem: (categoryId: String, itemId: String) -> Unit,
    onCreateItem: (categoryId: String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: SellerStoreViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }

    // Reflect create/edit/delete performed on the listing editor when we return to this screen.
    LifecycleResumeEffect(Unit) {
        viewModel.reloadSelectedItems()
        onPauseOrDispose { }
    }

    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is SellerStoreEvent.Message -> snackbarHostState.showSnackbar(event.text)
            }
        }
    }

    SellerStoreScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onSelectCategory = viewModel::selectCategory,
        onCreateCategory = viewModel::createCategory,
        onDeleteCategory = viewModel::deleteCategory,
        onDeleteItem = viewModel::deleteItem,
        onEditItem = onEditItem,
        onCreateItem = onCreateItem,
        onBoost = viewModel::boostListing,
        onRetry = viewModel::refresh,
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun SellerStoreScreen(
    state: SellerStoreUiState,
    snackbarHostState: SnackbarHostState,
    onSelectCategory: (String) -> Unit,
    onCreateCategory: (String, String?) -> Unit,
    onDeleteCategory: (String) -> Unit,
    onDeleteItem: (categoryId: String, itemId: String) -> Unit,
    onEditItem: (categoryId: String, itemId: String) -> Unit,
    onCreateItem: (categoryId: String) -> Unit,
    onBoost: (categoryId: String, item: CatalogItem, budgetDollars: Int, bidCpcCents: Int) -> Unit = { _, _, _, _ -> },
    onRetry: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var showNewCategory by remember { mutableStateOf(false) }
    // ADV x ECOM (B4): the listing the seller is boosting (drives the boost dialog); null = hidden.
    var boostTarget by remember { mutableStateOf<CatalogItem?>(null) }

    Scaffold(
        modifier = modifier.testTag(SellerStoreTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.seller_store_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.action_back))
                    }
                },
            )
        },
        floatingActionButton = {
            state.selectedCategoryId?.let { categoryId ->
                FloatingActionButton(
                    onClick = { onCreateItem(categoryId) },
                    modifier = Modifier.testTag(SellerStoreTestTags.ADD_ITEM),
                ) { Icon(Icons.Filled.Add, contentDescription = stringResource(R.string.seller_store_add_item)) }
            }
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when {
                state.loading -> LoadingState()
                state.error != null && state.categories.isEmpty() ->
                    ErrorState(message = state.error, onRetry = onRetry, modifier = Modifier.testTag(SellerStoreTestTags.ERROR))
                else -> Column(Modifier.fillMaxSize()) {
                    CategoryBar(
                        categories = state.categories,
                        selectedId = state.selectedCategoryId,
                        onSelect = onSelectCategory,
                        onNewCategory = { showNewCategory = true },
                    )
                    HorizontalDivider()
                    ItemsSection(
                        state = state,
                        onEditItem = onEditItem,
                        onDeleteItem = onDeleteItem,
                        onDeleteCategory = onDeleteCategory,
                        onBoost = { boostTarget = it },
                    )
                }
            }
        }
    }

    if (showNewCategory) {
        NewCategoryDialog(
            onDismiss = { showNewCategory = false },
            onConfirm = { name, desc ->
                showNewCategory = false
                onCreateCategory(name, desc)
            },
        )
    }

    // ADV x ECOM (B4): the boost-this-product dialog (prefilled from the listing).
    val target = boostTarget
    if (target != null) {
        BoostProductDialog(
            item = target,
            busy = state.boosting,
            onDismiss = { boostTarget = null },
            onConfirm = { budgetDollars, bidCpcCents ->
                onBoost(target.categoryId, target, budgetDollars, bidCpcCents)
                boostTarget = null
            },
        )
    }
}

@Composable
private fun CategoryBar(
    categories: List<CatalogCategory>,
    selectedId: String?,
    onSelect: (String) -> Unit,
    onNewCategory: () -> Unit,
) {
    FlowRow(
        Modifier.fillMaxWidth().padding(12.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        categories.forEach { category ->
            FilterChip(
                selected = category.categoryId == selectedId,
                onClick = { onSelect(category.categoryId) },
                label = { Text(category.name, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                modifier = Modifier.testTag(SellerStoreTestTags.CATEGORY_CHIP),
            )
        }
        AssistChip(
            onClick = onNewCategory,
            label = { Text(stringResource(R.string.seller_store_new_category)) },
            leadingIcon = { Icon(Icons.Filled.Add, contentDescription = null) },
            modifier = Modifier.testTag(SellerStoreTestTags.NEW_CATEGORY),
        )
    }
}

@Composable
private fun ItemsSection(
    state: SellerStoreUiState,
    onEditItem: (String, String) -> Unit,
    onDeleteItem: (String, String) -> Unit,
    onDeleteCategory: (String) -> Unit,
    onBoost: (CatalogItem) -> Unit,
) {
    val categoryId = state.selectedCategoryId
    if (categoryId == null) {
        EmptyState(
            title = stringResource(R.string.seller_store_no_categories_title),
            body = stringResource(R.string.seller_store_no_categories_body),
            modifier = Modifier.testTag(SellerStoreTestTags.EMPTY),
        )
        return
    }
    when {
        state.itemsLoading -> LoadingState()
        state.items.isEmpty() -> EmptyState(
            title = stringResource(R.string.seller_store_no_items_title),
            body = stringResource(R.string.seller_store_no_items_body),
            modifier = Modifier.testTag(SellerStoreTestTags.EMPTY),
        )
        else -> LazyColumn(
            Modifier.fillMaxSize(),
            contentPadding = PaddingValues(12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            items(state.items, key = { it.itemId }) { item ->
                SellerItemRow(
                    item = item,
                    onEdit = { onEditItem(categoryId, item.itemId) },
                    onDelete = { onDeleteItem(categoryId, item.itemId) },
                    onBoost = { onBoost(item) },
                )
            }
            item {
                TextButton(
                    onClick = { onDeleteCategory(categoryId) },
                    modifier = Modifier.testTag(SellerStoreTestTags.DELETE_CATEGORY),
                ) {
                    Icon(Icons.Outlined.Delete, contentDescription = null)
                    Text("  " + stringResource(R.string.seller_store_delete_category))
                }
            }
        }
    }
}

@Composable
private fun SellerItemRow(
    item: CatalogItem,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
    onBoost: () -> Unit,
) {
    Row(
        Modifier.fillMaxWidth().testTag(SellerStoreTestTags.ITEM_ROW).padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Column(Modifier.weight(1f)) {
            Text(item.name, style = MaterialTheme.typography.titleSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(
                text = formatPrice(item.priceCents, item.currency) +
                    (item.stockCount?.let { "  ·  " + stringResource(R.string.seller_store_stock, it) } ?: ""),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        // ADV x ECOM (B4): promote this listing as a product ad in a couple taps.
        IconButton(onClick = onBoost, modifier = Modifier.testTag(SellerStoreTestTags.ITEM_BOOST)) {
            Icon(
                Icons.Outlined.Campaign,
                contentDescription = stringResource(R.string.seller_store_boost_listing),
                tint = MaterialTheme.colorScheme.primary,
            )
        }
        IconButton(onClick = onEdit, modifier = Modifier.testTag(SellerStoreTestTags.ITEM_EDIT)) {
            Icon(Icons.Outlined.Edit, contentDescription = stringResource(R.string.seller_store_edit_listing))
        }
        IconButton(onClick = onDelete, modifier = Modifier.testTag(SellerStoreTestTags.ITEM_DELETE)) {
            Icon(Icons.Outlined.Delete, contentDescription = stringResource(R.string.seller_store_delete_listing))
        }
    }
}

/**
 * ADV x ECOM (B4) — the boost-this-product dialog. The creative is prefilled server-side from the
 * listing (image / name / price + buy_product CTA); the seller only picks a lifetime BUDGET (dollars)
 * and a per-click BID (cents). Submit calls the owner-checked boost endpoint.
 */
@Composable
private fun BoostProductDialog(
    item: CatalogItem,
    busy: Boolean,
    onDismiss: () -> Unit,
    onConfirm: (budgetDollars: Int, bidCpcCents: Int) -> Unit,
) {
    var budget by remember { mutableStateOf("20") }
    var bid by remember { mutableStateOf("50") }
    val budgetInt = budget.trim().toIntOrNull()
    val bidInt = bid.trim().toIntOrNull()
    val valid = budgetInt != null && budgetInt >= 1 && bidInt != null && bidInt in 1..10_000
    AlertDialog(
        modifier = Modifier.testTag(SellerStoreTestTags.BOOST_DIALOG),
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.seller_store_boost_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    text = item.name + "  ·  " + formatPrice(item.priceCents, item.currency),
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text(
                    text = stringResource(R.string.seller_store_boost_body),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                OutlinedTextField(
                    value = budget,
                    onValueChange = { budget = it.filter(Char::isDigit).take(7) },
                    label = { Text(stringResource(R.string.seller_store_boost_budget)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag(SellerStoreTestTags.BOOST_BUDGET),
                )
                OutlinedTextField(
                    value = bid,
                    onValueChange = { bid = it.filter(Char::isDigit).take(5) },
                    label = { Text(stringResource(R.string.seller_store_boost_bid)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag(SellerStoreTestTags.BOOST_BID),
                )
            }
        },
        confirmButton = {
            Button(
                onClick = { if (valid) onConfirm(budgetInt!!, bidInt!!) },
                enabled = valid && !busy,
                modifier = Modifier.testTag(SellerStoreTestTags.BOOST_SUBMIT),
            ) { Text(stringResource(R.string.seller_store_boost_submit)) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_cancel)) } },
    )
}

@Composable
private fun NewCategoryDialog(
    onDismiss: () -> Unit,
    onConfirm: (name: String, description: String?) -> Unit,
) {
    var name by remember { mutableStateOf("") }
    var description by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.seller_store_new_category)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text(stringResource(R.string.seller_store_category_name)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag("seller_store_category_name_input"),
                )
                OutlinedTextField(
                    value = description,
                    onValueChange = { description = it },
                    label = { Text(stringResource(R.string.seller_store_category_desc)) },
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            Button(
                onClick = { onConfirm(name, description.ifBlank { null }) },
                enabled = name.isNotBlank(),
                modifier = Modifier.testTag("seller_store_category_create"),
            ) { Text(stringResource(R.string.seller_store_create)) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_cancel)) } },
    )
}
