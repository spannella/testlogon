@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.broadcasthost.manage

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
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
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import coil.compose.AsyncImage
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner
import com.testlogon.android.data.broadcast.shelf.ShelfProduct
import com.testlogon.android.data.broadcast.tips.Goal
import java.text.NumberFormat
import java.util.Currency
import java.util.Locale

/** AND-314 — stable testTags for the goals + products authoring surfaces. */
object ManageTestTags {
    const val SCREEN = "manage_screen"
    const val TAB_GOALS = "manage_tab_goals"
    const val TAB_PRODUCTS = "manage_tab_products"
    const val GOAL_CREATE = "goal_create"
    const val GOAL_DELETE = "goal_delete"
    const val GOAL_DELETE_CONFIRM = "goal_delete_confirm"
    const val PRODUCT_ADD = "product_add"
    const val PRODUCT_REMOVE = "product_remove"
    const val PRODUCT_REMOVE_CONFIRM = "product_remove_confirm"
    const val PRODUCT_REORDER_UP = "product_reorder_up"
    const val PRODUCT_REORDER_DOWN = "product_reorder_down"
    const val PRODUCT_SET_PRICE = "product_set_price"
    const val PRODUCT_CLEAR_PRICE = "product_clear_price"
    const val PRICE_DIALOG = "price_dialog"

    fun goalRow(id: String): String = "goal_row_$id"
    fun productRow(id: String): String = "product_row_$id"
}

/**
 * AND-314 — host authoring entry. Collects [GoalsProductsViewModel] state and delegates to the stateless
 * [ManageScreen]. Goals + products load on first composition via the VM init (a single non-looping refresh);
 * thereafter refresh is pull-to-refresh only. Reached from the host control surface (BroadcastManageDest).
 */
@Composable
fun ManageRoute(
    onBack: () -> Unit,
    viewModel: GoalsProductsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    ManageScreen(
        state = state,
        onBack = onBack,
        onSelectTab = viewModel::selectTab,
        onGoalFormChange = viewModel::updateGoalForm,
        onSubmitGoal = viewModel::submitGoal,
        onRequestDeleteGoal = viewModel::requestDeleteGoal,
        onConfirmDeleteGoal = viewModel::deleteGoal,
        onDismissConfirm = viewModel::dismissConfirm,
        onRefreshGoals = { viewModel.refreshGoals(pullToRefresh = true) },
        onRetryGoals = { viewModel.refreshGoals() },
        onAddProduct = viewModel::addProduct,
        onRequestRemoveProduct = viewModel::requestRemoveProduct,
        onConfirmRemoveProduct = viewModel::removeProduct,
        onMoveProduct = viewModel::moveProduct,
        onOpenPriceDialog = viewModel::openPriceDialog,
        onPriceFormChange = viewModel::updatePriceForm,
        onSubmitPrice = viewModel::submitPrice,
        onDismissPriceDialog = viewModel::dismissPriceDialog,
        onClearPrice = viewModel::clearPrice,
        onRefreshProducts = { viewModel.refreshProducts(pullToRefresh = true) },
        onRetryProducts = { viewModel.refreshProducts() },
        onConsumeEvent = viewModel::consumeEvent,
    )
}

/**
 * AND-314 — stateless authoring surface with two tabs (Goals | Products). Each tab reuses the AND-021 core-ui
 * Loading / Empty / Error / Offline composables + pull-to-refresh. One-shot events surface via a snackbar.
 */
@Composable
fun ManageScreen(
    state: ManageUiState,
    onBack: () -> Unit,
    onSelectTab: (ManageTab) -> Unit,
    onGoalFormChange: ((GoalForm) -> GoalForm) -> Unit,
    onSubmitGoal: () -> Unit,
    onRequestDeleteGoal: (String, String) -> Unit,
    onConfirmDeleteGoal: (String) -> Unit,
    onDismissConfirm: () -> Unit,
    onRefreshGoals: () -> Unit,
    onRetryGoals: () -> Unit,
    onAddProduct: (String, String, Int) -> Unit,
    onRequestRemoveProduct: (String, String) -> Unit,
    onConfirmRemoveProduct: (String) -> Unit,
    onMoveProduct: (Int, Int) -> Unit,
    onOpenPriceDialog: (ShelfProduct) -> Unit,
    onPriceFormChange: ((PriceForm) -> PriceForm) -> Unit,
    onSubmitPrice: () -> Unit,
    onDismissPriceDialog: () -> Unit,
    onClearPrice: (String) -> Unit,
    onRefreshProducts: () -> Unit,
    onRetryProducts: () -> Unit,
    onConsumeEvent: () -> Unit,
) {
    val snackbarHostState = remember { SnackbarHostState() }
    val eventMessage = state.event?.let { eventMessage(it) }
    LaunchedEffect(state.event) {
        if (eventMessage != null) {
            snackbarHostState.showSnackbar(eventMessage)
            onConsumeEvent()
        }
    }

    Scaffold(
        modifier = Modifier.testTag(ManageTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.manage_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.manage_back_cd),
                        )
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            TabRow(selectedTabIndex = state.selectedTab.ordinal) {
                Tab(
                    selected = state.selectedTab == ManageTab.GOALS,
                    onClick = { onSelectTab(ManageTab.GOALS) },
                    modifier = Modifier.testTag(ManageTestTags.TAB_GOALS),
                    text = { Text(stringResource(R.string.manage_tab_goals)) },
                )
                Tab(
                    selected = state.selectedTab == ManageTab.PRODUCTS,
                    onClick = { onSelectTab(ManageTab.PRODUCTS) },
                    modifier = Modifier.testTag(ManageTestTags.TAB_PRODUCTS),
                    text = { Text(stringResource(R.string.manage_tab_products)) },
                )
            }

            when (state.selectedTab) {
                ManageTab.GOALS -> GoalsTab(
                    state = state,
                    onGoalFormChange = onGoalFormChange,
                    onSubmitGoal = onSubmitGoal,
                    onRequestDeleteGoal = onRequestDeleteGoal,
                    onRefresh = onRefreshGoals,
                    onRetry = onRetryGoals,
                )
                ManageTab.PRODUCTS -> ProductsTab(
                    state = state,
                    onAddProduct = onAddProduct,
                    onRequestRemoveProduct = onRequestRemoveProduct,
                    onMoveProduct = onMoveProduct,
                    onOpenPriceDialog = onOpenPriceDialog,
                    onClearPrice = onClearPrice,
                    onRefresh = onRefreshProducts,
                    onRetry = onRetryProducts,
                )
            }
        }
    }

    when (val confirm = state.confirm) {
        is ConfirmTarget.DeleteGoal -> AlertDialog(
            onDismissRequest = onDismissConfirm,
            title = { Text(stringResource(R.string.goals_delete_confirm_title)) },
            text = { Text(stringResource(R.string.goals_delete_confirm_body, confirm.label)) },
            confirmButton = {
                TextButton(
                    onClick = { onConfirmDeleteGoal(confirm.goalId) },
                    modifier = Modifier.testTag(ManageTestTags.GOAL_DELETE_CONFIRM),
                ) { Text(stringResource(R.string.goals_delete_confirm)) }
            },
            dismissButton = {
                TextButton(onClick = onDismissConfirm) { Text(stringResource(R.string.manage_cancel)) }
            },
        )
        is ConfirmTarget.RemoveProduct -> AlertDialog(
            onDismissRequest = onDismissConfirm,
            title = { Text(stringResource(R.string.products_remove_confirm_title)) },
            text = { Text(stringResource(R.string.products_remove_confirm_body, confirm.name)) },
            confirmButton = {
                TextButton(
                    onClick = { onConfirmRemoveProduct(confirm.itemId) },
                    modifier = Modifier.testTag(ManageTestTags.PRODUCT_REMOVE_CONFIRM),
                ) { Text(stringResource(R.string.products_remove_confirm)) }
            },
            dismissButton = {
                TextButton(onClick = onDismissConfirm) { Text(stringResource(R.string.manage_cancel)) }
            },
        )
        null -> Unit
    }

    state.priceForm?.let { form ->
        PriceDialog(
            form = form,
            onChange = onPriceFormChange,
            onSubmit = onSubmitPrice,
            onDismiss = onDismissPriceDialog,
        )
    }
}

// ---- Goals tab ----

@Composable
private fun GoalsTab(
    state: ManageUiState,
    onGoalFormChange: ((GoalForm) -> GoalForm) -> Unit,
    onSubmitGoal: () -> Unit,
    onRequestDeleteGoal: (String, String) -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
) {
    when (val goals = state.goals) {
        GoalsState.Loading -> LoadingState()
        GoalsState.Empty -> Column(modifier = Modifier.fillMaxSize()) {
            GoalCreateForm(state, onGoalFormChange, onSubmitGoal)
            EmptyState(
                title = stringResource(R.string.goals_empty_title),
                body = stringResource(R.string.goals_empty_body),
            )
        }
        is GoalsState.Error ->
            if (goals.offline) {
                OfflineBanner(message = goals.message, onRetry = onRetry)
            } else {
                ErrorState(message = goals.message, onRetry = onRetry)
            }
        is GoalsState.Content -> PullToRefreshBox(
            isRefreshing = goals.isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize(),
        ) {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                item { GoalCreateForm(state, onGoalFormChange, onSubmitGoal) }
                itemsIndexed(goals.goals, key = { _, g -> g.goalId }) { _, goal ->
                    GoalRow(
                        goal = goal,
                        deleting = state.isInFlight(GoalsProductsViewModel.goalDeleteKey(goal.goalId)),
                        onDelete = { onRequestDeleteGoal(goal.goalId, goal.label) },
                    )
                }
            }
        }
    }
}

@Composable
private fun GoalCreateForm(
    state: ManageUiState,
    onChange: ((GoalForm) -> GoalForm) -> Unit,
    onSubmit: () -> Unit,
) {
    val form = state.goalForm
    val creating = state.isInFlight(GoalsProductsViewModel.GOAL_CREATE_KEY)
    Column(
        modifier = Modifier.fillMaxWidth().padding(8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        OutlinedTextField(
            value = form.label,
            onValueChange = { v -> onChange { it.copy(label = v) } },
            label = { Text(stringResource(R.string.goals_label_label)) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = form.targetDollars,
            onValueChange = { v -> onChange { it.copy(targetDollars = v) } },
            label = { Text(stringResource(R.string.goals_target_label)) },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
            modifier = Modifier.fillMaxWidth(),
        )
        Button(
            onClick = onSubmit,
            enabled = form.isValid && !creating,
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 48.dp)
                .testTag(ManageTestTags.GOAL_CREATE),
        ) {
            Text(stringResource(R.string.goals_create))
        }
    }
}

@Composable
private fun GoalRow(goal: Goal, deleting: Boolean, onDelete: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(ManageTestTags.goalRow(goal.goalId))
            .padding(vertical = 4.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(goal.label, style = MaterialTheme.typography.titleSmall)
            if (goal.isReached) {
                AssistChip(onClick = {}, label = { Text(stringResource(R.string.goals_reached_badge)) })
            }
        }
        Text(
            text = stringResource(
                R.string.goals_progress,
                formatCents(goal.currentCents),
                formatCents(goal.targetCents),
                goal.percent,
            ),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        LinearProgressIndicator(progress = { goal.fraction }, modifier = Modifier.fillMaxWidth())
        TextButton(
            onClick = onDelete,
            enabled = !deleting,
            modifier = Modifier.heightIn(min = 48.dp).testTag(ManageTestTags.GOAL_DELETE),
        ) {
            Text(stringResource(R.string.goals_delete))
        }
    }
}

// ---- Products tab ----

@Composable
private fun ProductsTab(
    state: ManageUiState,
    onAddProduct: (String, String, Int) -> Unit,
    onRequestRemoveProduct: (String, String) -> Unit,
    onMoveProduct: (Int, Int) -> Unit,
    onOpenPriceDialog: (ShelfProduct) -> Unit,
    onClearPrice: (String) -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
) {
    when (val products = state.products) {
        ProductsState.Loading -> LoadingState()
        ProductsState.Empty -> Column(modifier = Modifier.fillMaxSize()) {
            ProductAddForm(state, onAddProduct)
            EmptyState(
                title = stringResource(R.string.products_empty_title),
                body = stringResource(R.string.products_empty_body),
            )
        }
        is ProductsState.Error ->
            if (products.offline) {
                OfflineBanner(message = products.message, onRetry = onRetry)
            } else {
                ErrorState(message = products.message, onRetry = onRetry)
            }
        is ProductsState.Content -> PullToRefreshBox(
            isRefreshing = products.isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize(),
        ) {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                item { ProductAddForm(state, onAddProduct) }
                itemsIndexed(products.products, key = { _, p -> p.itemId }) { index, product ->
                    ProductRow(
                        product = product,
                        index = index,
                        count = products.products.size,
                        busy = state.isInFlight(GoalsProductsViewModel.productRemoveKey(product.itemId)) ||
                            state.isInFlight(GoalsProductsViewModel.priceKey(product.itemId)) ||
                            state.isInFlight(GoalsProductsViewModel.REORDER_KEY),
                        onRemove = { onRequestRemoveProduct(product.itemId, product.name) },
                        onMoveUp = { onMoveProduct(index, index - 1) },
                        onMoveDown = { onMoveProduct(index, index + 1) },
                        onSetPrice = { onOpenPriceDialog(product) },
                        onClearPrice = { onClearPrice(product.itemId) },
                    )
                }
            }
        }
    }
}

@Composable
private fun ProductAddForm(state: ManageUiState, onAddProduct: (String, String, Int) -> Unit) {
    var itemId by remember { mutableStateOf("") }
    var categoryId by remember { mutableStateOf("") }
    var displayOrder by remember { mutableStateOf("") }
    val adding = state.isInFlight(GoalsProductsViewModel.PRODUCT_ADD_KEY)
    Column(
        modifier = Modifier.fillMaxWidth().padding(8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        OutlinedTextField(
            value = itemId,
            onValueChange = { itemId = it },
            label = { Text(stringResource(R.string.products_item_id_label)) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = categoryId,
            onValueChange = { categoryId = it },
            label = { Text(stringResource(R.string.products_category_id_label)) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = displayOrder,
            onValueChange = { displayOrder = it.filter(Char::isDigit) },
            label = { Text(stringResource(R.string.products_display_order_label)) },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.fillMaxWidth(),
        )
        Button(
            onClick = { onAddProduct(itemId, categoryId, displayOrder.toIntOrNull() ?: 0) },
            enabled = itemId.isNotBlank() && categoryId.isNotBlank() && !adding,
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 48.dp)
                .testTag(ManageTestTags.PRODUCT_ADD),
        ) {
            Text(stringResource(R.string.products_add))
        }
    }
}

@Composable
private fun ProductRow(
    product: ShelfProduct,
    index: Int,
    count: Int,
    busy: Boolean,
    onRemove: () -> Unit,
    onMoveUp: () -> Unit,
    onMoveDown: () -> Unit,
    onSetPrice: () -> Unit,
    onClearPrice: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(ManageTestTags.productRow(product.itemId))
            .padding(vertical = 4.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            AsyncImage(
                model = product.imageUrl,
                contentDescription = null,
                modifier = Modifier.size(48.dp),
            )
            Column(modifier = Modifier.padding(start = 8.dp).fillMaxWidth()) {
                Text(product.name.ifBlank { product.itemId }, style = MaterialTheme.typography.titleSmall)
                if (product.isBroadcastPrice) {
                    Text(
                        text = stringResource(
                            R.string.products_broadcast_price,
                            formatCents(product.priceCents, product.currency),
                            product.discountPct,
                        ),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary,
                    )
                    product.broadcastPriceExpiresAtEpochSeconds?.let { expiry ->
                        Text(
                            text = stringResource(R.string.products_price_expiry, formatExpiry(expiry)),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                } else {
                    Text(
                        text = formatCents(product.priceCents, product.currency),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(
                onClick = onMoveUp,
                enabled = index > 0 && !busy,
                modifier = Modifier.size(48.dp).testTag(ManageTestTags.PRODUCT_REORDER_UP),
            ) {
                Icon(
                    Icons.Filled.KeyboardArrowUp,
                    contentDescription = stringResource(R.string.products_move_up_cd),
                )
            }
            IconButton(
                onClick = onMoveDown,
                enabled = index < count - 1 && !busy,
                modifier = Modifier.size(48.dp).testTag(ManageTestTags.PRODUCT_REORDER_DOWN),
            ) {
                Icon(
                    Icons.Filled.KeyboardArrowDown,
                    contentDescription = stringResource(R.string.products_move_down_cd),
                )
            }
            if (product.isBroadcastPrice) {
                TextButton(
                    onClick = onClearPrice,
                    enabled = !busy,
                    modifier = Modifier.heightIn(min = 48.dp).testTag(ManageTestTags.PRODUCT_CLEAR_PRICE),
                ) { Text(stringResource(R.string.products_clear_price)) }
            } else {
                TextButton(
                    onClick = onSetPrice,
                    enabled = !busy,
                    modifier = Modifier.heightIn(min = 48.dp).testTag(ManageTestTags.PRODUCT_SET_PRICE),
                ) { Text(stringResource(R.string.products_set_price)) }
            }
            TextButton(
                onClick = onRemove,
                enabled = !busy,
                modifier = Modifier.heightIn(min = 48.dp).testTag(ManageTestTags.PRODUCT_REMOVE),
            ) { Text(stringResource(R.string.products_remove)) }
        }
    }
}

@Composable
private fun PriceDialog(
    form: PriceForm,
    onChange: ((PriceForm) -> PriceForm) -> Unit,
    onSubmit: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        modifier = Modifier.testTag(ManageTestTags.PRICE_DIALOG),
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.products_set_price_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    stringResource(
                        R.string.products_catalog_price,
                        formatCents(form.catalogPriceCents, form.currency),
                    ),
                    style = MaterialTheme.typography.bodySmall,
                )
                OutlinedTextField(
                    value = form.priceDollars,
                    onValueChange = { v -> onChange { it.copy(priceDollars = v) } },
                    label = { Text(stringResource(R.string.products_price_label)) },
                    singleLine = true,
                    isError = form.priceDollars.isNotBlank() && !form.priceValid,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = form.expiresMinutes,
                    onValueChange = { v -> onChange { it.copy(expiresMinutes = v.filter(Char::isDigit)) } },
                    label = { Text(stringResource(R.string.products_expiry_label)) },
                    singleLine = true,
                    isError = !form.expiresValid,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            TextButton(onClick = onSubmit, enabled = form.isValid) {
                Text(stringResource(R.string.products_set_price_confirm))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.manage_cancel)) }
        },
    )
}

// ---- formatting helpers (locale-aware money + a coarse expiry countdown) ----

/** Locale-aware cents -> currency string; falls back to the raw amount on an unusable currency code. */
internal fun formatCents(
    cents: Long,
    currencyCode: String = "USD",
    locale: Locale = Locale.getDefault(),
): String = runCatching {
    val nf = NumberFormat.getCurrencyInstance(locale)
    nf.currency = Currency.getInstance(currencyCode)
    nf.format(cents / 100.0)
}.getOrElse { (cents / 100.0).toString() }

/** Coarse seconds-from-now countdown to [expiresAtEpochSeconds]; "expired" once past. */
internal fun formatExpiry(
    expiresAtEpochSeconds: Long,
    nowEpochSeconds: Long = System.currentTimeMillis() / 1000L,
): String {
    val remaining = expiresAtEpochSeconds - nowEpochSeconds
    if (remaining <= 0L) return "expired"
    val minutes = remaining / 60L
    val seconds = remaining % 60L
    return if (minutes > 0L) "${minutes}m ${seconds}s" else "${seconds}s"
}

@Composable
private fun eventMessage(event: ManageEvent): String = when (event) {
    is ManageEvent.GoalCreated -> stringResource(R.string.goals_created_snackbar, event.label)
    ManageEvent.GoalDeleted -> stringResource(R.string.goals_deleted_snackbar)
    is ManageEvent.ProductAdded -> stringResource(R.string.products_added_snackbar, event.itemId)
    ManageEvent.ProductRemoved -> stringResource(R.string.products_removed_snackbar)
    ManageEvent.Reordered -> stringResource(R.string.products_reordered_snackbar)
    ManageEvent.PriceSet -> stringResource(R.string.products_price_set_snackbar)
    ManageEvent.PriceCleared -> stringResource(R.string.products_price_cleared_snackbar)
    is ManageEvent.Failure -> event.message
}
