@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.financialproducts

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
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
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner
import com.testlogon.android.data.financialproducts.FinancialProduct
import com.testlogon.android.data.financialproducts.ProductCollection

object FinancialProductsTestTags {
    const val SCREEN = "finprod_screen"
    const val LOADING = "finprod_loading"
    const val EMPTY = "finprod_empty"
    const val ERROR = "finprod_error"
    const val OFFLINE = "finprod_offline"
    const val FORBIDDEN = "finprod_forbidden"
    const val FAB = "finprod_fab"
    const val TAB_PREFIX = "finprod_tab_"
    const val PRODUCT_PREFIX = "finprod_product_"
    const val COLLECTION_PREFIX = "finprod_collection_"
    const val CREATE_FORM = "finprod_create_form"
    const val CREATE_SUBMIT = "finprod_create_submit"
}

@Composable
fun FinancialProductsRoute(
    onBack: () -> Unit,
    onSessionExpired: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: FinancialProductsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val context = LocalContext.current

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is FinancialProductsEffect.ShowMessage ->
                    snackbarHostState.showSnackbar(context.getString(effect.resId))
                is FinancialProductsEffect.ShowText ->
                    snackbarHostState.showSnackbar(effect.text)
            }
        }
    }
    LaunchedEffect(state.phase) {
        if (state.phase == FinancialProductsUiState.Phase.SessionExpired) onSessionExpired()
    }

    FinancialProductsScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onBack = onBack,
        onRefresh = viewModel::onRefresh,
        onRetry = viewModel::onRetry,
        onSelectTab = viewModel::onSelectTab,
        onOpenCreateProduct = viewModel::onOpenCreateProduct,
        onDismissCreateProduct = viewModel::onDismissCreateProduct,
        onProductCodeChange = viewModel::onProductCodeChange,
        onProductNameChange = viewModel::onProductNameChange,
        onProductCategoryChange = viewModel::onProductCategoryChange,
        onProductDescriptionChange = viewModel::onProductDescriptionChange,
        onSubmitCreateProduct = viewModel::onSubmitCreateProduct,
        onOpenCreateCollection = viewModel::onOpenCreateCollection,
        onDismissCreateCollection = viewModel::onDismissCreateCollection,
        onCollectionCodeChange = viewModel::onCollectionCodeChange,
        onCollectionNameChange = viewModel::onCollectionNameChange,
        onSubmitCreateCollection = viewModel::onSubmitCreateCollection,
        modifier = modifier,
    )
}

@Composable
fun FinancialProductsScreen(
    state: FinancialProductsUiState,
    snackbarHostState: SnackbarHostState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onSelectTab: (FinancialProductsTab) -> Unit,
    onOpenCreateProduct: () -> Unit,
    onDismissCreateProduct: () -> Unit,
    onProductCodeChange: (String) -> Unit,
    onProductNameChange: (String) -> Unit,
    onProductCategoryChange: (String) -> Unit,
    onProductDescriptionChange: (String) -> Unit,
    onSubmitCreateProduct: () -> Unit,
    onOpenCreateCollection: () -> Unit,
    onDismissCreateCollection: () -> Unit,
    onCollectionCodeChange: (String) -> Unit,
    onCollectionNameChange: (String) -> Unit,
    onSubmitCreateCollection: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(FinancialProductsTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Financial products") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
        floatingActionButton = {
            if (state.phase == FinancialProductsUiState.Phase.Content) {
                Button(
                    onClick = {
                        if (state.tab == FinancialProductsTab.PRODUCTS) onOpenCreateProduct() else onOpenCreateCollection()
                    },
                    modifier = Modifier.testTag(FinancialProductsTestTags.FAB),
                ) {
                    Icon(Icons.Outlined.Add, contentDescription = null)
                    Text(if (state.tab == FinancialProductsTab.PRODUCTS) "New product" else "New collection")
                }
            }
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            if (state.phase == FinancialProductsUiState.Phase.Content) {
                TabRow(selectedTabIndex = state.tab.ordinal) {
                    FinancialProductsTab.entries.forEach { tab ->
                        Tab(
                            selected = state.tab == tab,
                            onClick = { onSelectTab(tab) },
                            text = { Text(tab.label) },
                            modifier = Modifier.testTag(FinancialProductsTestTags.TAB_PREFIX + tab.name),
                        )
                    }
                }
            }

            when (state.phase) {
                FinancialProductsUiState.Phase.Loading ->
                    LoadingState(modifier = Modifier.testTag(FinancialProductsTestTags.LOADING))
                FinancialProductsUiState.Phase.Forbidden ->
                    EmptyState(
                        title = "Admins only",
                        body = "You do not have access to financial-product administration.",
                        imageVector = Icons.Outlined.Lock,
                        modifier = Modifier.testTag(FinancialProductsTestTags.FORBIDDEN),
                    )
                FinancialProductsUiState.Phase.Error ->
                    ErrorState(
                        message = "Something went wrong.",
                        onRetry = onRetry,
                        modifier = Modifier.testTag(FinancialProductsTestTags.ERROR),
                    )
                FinancialProductsUiState.Phase.Offline ->
                    OfflineBanner(onRetry = onRetry, modifier = Modifier.testTag(FinancialProductsTestTags.OFFLINE))
                FinancialProductsUiState.Phase.SessionExpired -> Unit
                FinancialProductsUiState.Phase.Content ->
                    PullToRefreshBox(
                        isRefreshing = state.isRefreshing,
                        onRefresh = onRefresh,
                        modifier = Modifier.fillMaxSize(),
                    ) {
                        TabContent(state = state)
                    }
            }
        }
    }

    if (state.createProduct.isOpen) {
        CreateProductDialog(
            form = state.createProduct,
            onDismiss = onDismissCreateProduct,
            onCodeChange = onProductCodeChange,
            onNameChange = onProductNameChange,
            onCategoryChange = onProductCategoryChange,
            onDescriptionChange = onProductDescriptionChange,
            onSubmit = onSubmitCreateProduct,
        )
    }
    if (state.createCollection.isOpen) {
        CreateCollectionDialog(
            form = state.createCollection,
            onDismiss = onDismissCreateCollection,
            onCodeChange = onCollectionCodeChange,
            onNameChange = onCollectionNameChange,
            onSubmit = onSubmitCreateCollection,
        )
    }
}

@Composable
private fun TabContent(state: FinancialProductsUiState) {
    if (state.isEmptyForTab) {
        val (title, body) = when (state.tab) {
            FinancialProductsTab.PRODUCTS -> "No products yet" to "Create a financial product to get started."
            FinancialProductsTab.COLLECTIONS -> "No collections yet" to "Group products into a collection."
        }
        EmptyState(title = title, body = body, modifier = Modifier.testTag(FinancialProductsTestTags.EMPTY))
        return
    }
    LazyColumn(
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        modifier = Modifier.fillMaxSize(),
    ) {
        when (state.tab) {
            FinancialProductsTab.PRODUCTS -> items(state.products, key = { it.code }) { p -> ProductCard(p) }
            FinancialProductsTab.COLLECTIONS -> items(state.collections, key = { it.code }) { c -> CollectionCard(c) }
        }
    }
}

@Composable
private fun ProductCard(product: FinancialProduct) {
    Card(modifier = Modifier.fillMaxWidth().testTag(FinancialProductsTestTags.PRODUCT_PREFIX + product.code)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(product.name, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(product.code, style = MaterialTheme.typography.bodySmall)
            Text(product.familyLabel, style = MaterialTheme.typography.bodyMedium)
            product.description?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
            AssistChip(onClick = {}, label = { Text("v${product.version}") })
        }
    }
}

@Composable
private fun CollectionCard(collection: ProductCollection) {
    Card(modifier = Modifier.fillMaxWidth().testTag(FinancialProductsTestTags.COLLECTION_PREFIX + collection.code)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(collection.name, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(collection.code, style = MaterialTheme.typography.bodySmall)
            Text(collection.memberCountLabel, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
private fun CreateProductDialog(
    form: CreateProductFormState,
    onDismiss: () -> Unit,
    onCodeChange: (String) -> Unit,
    onNameChange: (String) -> Unit,
    onCategoryChange: (String) -> Unit,
    onDescriptionChange: (String) -> Unit,
    onSubmit: () -> Unit,
) {
    Dialog(onDismissRequest = onDismiss) {
        Card(modifier = Modifier.testTag(FinancialProductsTestTags.CREATE_FORM)) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("New product", style = MaterialTheme.typography.titleLarge)
                OutlinedTextField(
                    value = form.productCode,
                    onValueChange = onCodeChange,
                    label = { Text("Product code") },
                    singleLine = true,
                    enabled = !form.isSubmitting,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = form.name,
                    onValueChange = onNameChange,
                    label = { Text("Name") },
                    singleLine = true,
                    enabled = !form.isSubmitting,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = form.category,
                    onValueChange = onCategoryChange,
                    label = { Text("Category (optional)") },
                    singleLine = true,
                    enabled = !form.isSubmitting,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = form.description,
                    onValueChange = onDescriptionChange,
                    label = { Text("Description (optional)") },
                    enabled = !form.isSubmitting,
                    modifier = Modifier.fillMaxWidth(),
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.align(Alignment.End)) {
                    TextButton(onClick = onDismiss, enabled = !form.isSubmitting) { Text("Cancel") }
                    Button(
                        onClick = onSubmit,
                        enabled = form.canSubmit,
                        modifier = Modifier.testTag(FinancialProductsTestTags.CREATE_SUBMIT),
                    ) { Text("Create") }
                }
            }
        }
    }
}

@Composable
private fun CreateCollectionDialog(
    form: CreateCollectionFormState,
    onDismiss: () -> Unit,
    onCodeChange: (String) -> Unit,
    onNameChange: (String) -> Unit,
    onSubmit: () -> Unit,
) {
    Dialog(onDismissRequest = onDismiss) {
        Card(modifier = Modifier.testTag(FinancialProductsTestTags.CREATE_FORM)) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("New collection", style = MaterialTheme.typography.titleLarge)
                OutlinedTextField(
                    value = form.collectionCode,
                    onValueChange = onCodeChange,
                    label = { Text("Collection code") },
                    singleLine = true,
                    enabled = !form.isSubmitting,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = form.name,
                    onValueChange = onNameChange,
                    label = { Text("Name") },
                    singleLine = true,
                    enabled = !form.isSubmitting,
                    modifier = Modifier.fillMaxWidth(),
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.align(Alignment.End)) {
                    TextButton(onClick = onDismiss, enabled = !form.isSubmitting) { Text("Cancel") }
                    Button(
                        onClick = onSubmit,
                        enabled = form.canSubmit,
                        modifier = Modifier.testTag(FinancialProductsTestTags.CREATE_SUBMIT),
                    ) { Text("Create") }
                }
            }
        }
    }
}
