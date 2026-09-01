@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.sellerstore

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.sellerstore.CatalogSellerMath

/** ECOM (catalog depth) — stable test tags for the advanced product editor. */
object ProductDepthTestTags {
    const val SCREEN = "product_depth_screen"
    const val PRODUCT_TYPE_ROW = "product_depth_type_row"
    const val VARIANTS = "product_depth_variants"
    const val PRICE_COMPONENTS = "product_depth_price_components"
    const val BUNDLE = "product_depth_bundle"
    const val FEATURES = "product_depth_features"
    const val ADD_PRICE_COMPONENT = "product_depth_add_price_component"
    const val ADD_BUNDLE_COMPONENT = "product_depth_add_bundle_component"
    const val ADD_FEATURE_CATEGORY = "product_depth_add_feature_category"
}

@Composable
fun ProductDepthRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: ProductDepthViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(Unit) {
        viewModel.events.collect { e -> when (e) { is ProductDepthEvent.Message -> snackbarHostState.showSnackbar(e.text) } }
    }

    ProductDepthScreen(
        state = state,
        priceTypes = viewModel.priceTypes,
        productTypes = viewModel.productTypes,
        snackbarHostState = snackbarHostState,
        onBack = onBack,
        onSetProductType = viewModel::setProductType,
        onAddPriceComponent = viewModel::addPriceComponent,
        onCreateVariant = viewModel::createVariant,
        onDeleteVariant = viewModel::deleteVariant,
        onAddBundleComponent = viewModel::addBundleComponent,
        onRemoveBundleComponent = viewModel::removeBundleComponent,
        onCreateFeatureCategory = viewModel::createFeatureCategory,
        onAddFeatureValue = viewModel::addFeatureValue,
        onDeleteFeatureCategory = viewModel::deleteFeatureCategory,
        modifier = modifier,
    )
}

@Composable
fun ProductDepthScreen(
    state: ProductDepthUiState,
    priceTypes: List<String>,
    productTypes: List<String>,
    snackbarHostState: SnackbarHostState,
    onBack: () -> Unit,
    onSetProductType: (String) -> Unit,
    onAddPriceComponent: (priceType: String, amount: String, effectiveAt: Long, expiresAt: Long?) -> Unit,
    onCreateVariant: (Map<String, String>, String?) -> Unit,
    onDeleteVariant: (String) -> Unit,
    onAddBundleComponent: (componentItemId: String, quantity: String) -> Unit,
    onRemoveBundleComponent: (String) -> Unit,
    onCreateFeatureCategory: (String) -> Unit,
    onAddFeatureValue: (featureCategoryId: String, value: String, priceDelta: String) -> Unit,
    onDeleteFeatureCategory: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(ProductDepthTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(state.itemName.ifBlank { "Product depth" }) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        if (state.loading) {
            Box(Modifier.fillMaxSize().padding(padding)) { LoadingState() }
            return@Scaffold
        }
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            ProductTypeSection(state, productTypes, onSetProductType)
            FeaturesSection(state, onCreateFeatureCategory, onAddFeatureValue, onDeleteFeatureCategory)
            VariantsSection(state, onCreateVariant, onDeleteVariant)
            PriceComponentsSection(state, priceTypes, onAddPriceComponent)
            if (state.isBundle) {
                BundleSection(state, onAddBundleComponent, onRemoveBundleComponent)
            }
        }
    }
}

@Composable
private fun SectionCard(title: String, tag: String, content: @Composable ColumnScope.() -> Unit) {
    Card(Modifier.fillMaxWidth().testTag(tag)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            content()
        }
    }
}

@Composable
private fun ProductTypeSection(
    state: ProductDepthUiState,
    productTypes: List<String>,
    onSet: (String) -> Unit,
) {
    SectionCard("Product type", ProductDepthTestTags.PRODUCT_TYPE_ROW) {
        Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            productTypes.forEach { pt ->
                FilterChip(selected = state.productType == pt, onClick = { onSet(pt) }, label = { Text(pt) })
            }
        }
    }
}

@Composable
private fun FeaturesSection(
    state: ProductDepthUiState,
    onCreateCategory: (String) -> Unit,
    onAddValue: (String, String, String) -> Unit,
    onDeleteCategory: (String) -> Unit,
) {
    var newCategory by rememberSaveable { mutableStateOf("") }
    SectionCard("Features (options)", ProductDepthTestTags.FEATURES) {
        val features = state.features
        if (features == null || features.categories.isEmpty()) {
            Text("No feature options yet.", style = MaterialTheme.typography.bodySmall)
        } else {
            features.categories.sortedBy { it.position }.forEach { fc ->
                Row(Modifier.fillMaxWidth(), verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                    Text(fc.name, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium, modifier = Modifier.weight(1f))
                    IconButton(onClick = { onDeleteCategory(fc.featureCategoryId) }) {
                        Icon(Icons.Outlined.Delete, contentDescription = "Delete feature")
                    }
                }
                FeatureValuesRow(state, fc.featureCategoryId, onAddValue)
                HorizontalDivider()
            }
        }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
            OutlinedTextField(
                value = newCategory,
                onValueChange = { newCategory = it },
                label = { Text("New option (e.g. Color)") },
                singleLine = true,
                modifier = Modifier.weight(1f),
            )
            OutlinedButton(
                onClick = { if (newCategory.isNotBlank()) { onCreateCategory(newCategory); newCategory = "" } },
                modifier = Modifier.testTag(ProductDepthTestTags.ADD_FEATURE_CATEGORY),
            ) { Icon(Icons.Outlined.Add, contentDescription = "Add") }
        }
    }
}

@Composable
private fun FeatureValuesRow(
    state: ProductDepthUiState,
    featureCategoryId: String,
    onAddValue: (String, String, String) -> Unit,
) {
    var value by rememberSaveable(featureCategoryId) { mutableStateOf("") }
    var delta by rememberSaveable(featureCategoryId) { mutableStateOf("") }
    val values = state.features?.valuesFor(featureCategoryId).orEmpty()
    FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        values.forEach { v ->
            val label = if (v.priceDeltaCents != 0L) "${v.value} (${CatalogSellerMath.formatDeltaCents(v.priceDeltaCents)})" else v.value
            AssistChip(onClick = {}, label = { Text(label) })
        }
    }
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
        OutlinedTextField(value = value, onValueChange = { value = it }, label = { Text("Value") }, singleLine = true, modifier = Modifier.weight(1f))
        OutlinedTextField(
            value = delta,
            onValueChange = { delta = it },
            label = { Text("+/- \$") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.weight(1f),
        )
        OutlinedButton(onClick = { if (value.isNotBlank()) { onAddValue(featureCategoryId, value, delta); value = ""; delta = "" } }) {
            Icon(Icons.Outlined.Add, contentDescription = "Add value")
        }
    }
}

@Composable
private fun VariantsSection(
    state: ProductDepthUiState,
    onCreate: (Map<String, String>, String?) -> Unit,
    onDelete: (String) -> Unit,
) {
    var sku by rememberSaveable { mutableStateOf("") }
    SectionCard("Variants", ProductDepthTestTags.VARIANTS) {
        if (state.variants.isEmpty()) {
            Text("No variants yet.", style = MaterialTheme.typography.bodySmall)
        } else {
            state.variants.forEach { v ->
                Row(Modifier.fillMaxWidth(), verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(v.sku, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
                        Text(
                            "${CatalogSellerMath.formatCents(v.effectivePriceCents)} • ${CatalogSellerMath.formatDeltaCents(v.priceDeltaCents)}",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    IconButton(onClick = { onDelete(v.variantId) }) { Icon(Icons.Outlined.Delete, contentDescription = "Delete variant") }
                }
                HorizontalDivider()
            }
        }
        // Variant creation needs a feature-value map, built from the item's features.
        val features = state.features
        val selection = remember { mutableStateMapOf<String, String>() }
        features?.categories?.sortedBy { it.position }?.forEach { fc ->
            Text(fc.name, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Medium)
            FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                features.valuesFor(fc.featureCategoryId).forEach { v ->
                    FilterChip(
                        selected = selection[fc.featureCategoryId] == v.featureValueId,
                        onClick = { selection[fc.featureCategoryId] = v.featureValueId },
                        label = { Text(v.value) },
                    )
                }
            }
        }
        OutlinedTextField(value = sku, onValueChange = { sku = it }, label = { Text("SKU override (optional)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
        OutlinedButton(
            onClick = { onCreate(selection.toMap(), sku.takeIf { it.isNotBlank() }); selection.clear(); sku = "" },
            modifier = Modifier.fillMaxWidth(),
        ) { Icon(Icons.Outlined.Add, contentDescription = null); Text("  Add variant") }
    }
}

@Composable
private fun PriceComponentsSection(
    state: ProductDepthUiState,
    priceTypes: List<String>,
    onAdd: (String, String, Long, Long?) -> Unit,
) {
    var selectedType by rememberSaveable { mutableStateOf("DEFAULT") }
    var amount by rememberSaveable { mutableStateOf("") }
    SectionCard("Price components", ProductDepthTestTags.PRICE_COMPONENTS) {
        if (state.priceComponents.isEmpty()) {
            Text("No price components yet.", style = MaterialTheme.typography.bodySmall)
        } else {
            state.priceComponents.forEach { pc ->
                Text(
                    "${pc.priceType}: ${CatalogSellerMath.formatCents(pc.amountCents, pc.currency)}${if (pc.isActive) " • active" else ""}",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
        Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            priceTypes.forEach { t -> FilterChip(selected = selectedType == t, onClick = { selectedType = t }, label = { Text(t) }) }
        }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
            OutlinedTextField(
                value = amount,
                onValueChange = { amount = it },
                label = { Text("Amount \$") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                modifier = Modifier.weight(1f),
            )
            OutlinedButton(
                onClick = { onAdd(selectedType, amount, System.currentTimeMillis() / 1000L, null); amount = "" },
                modifier = Modifier.testTag(ProductDepthTestTags.ADD_PRICE_COMPONENT),
            ) { Icon(Icons.Outlined.Add, contentDescription = "Add price component") }
        }
    }
}

@Composable
private fun BundleSection(
    state: ProductDepthUiState,
    onAdd: (String, String) -> Unit,
    onRemove: (String) -> Unit,
) {
    var componentId by rememberSaveable { mutableStateOf("") }
    var qty by rememberSaveable { mutableStateOf("1") }
    SectionCard("Bundle components", ProductDepthTestTags.BUNDLE) {
        if (state.bundleComponents.isEmpty()) {
            Text("No components yet.", style = MaterialTheme.typography.bodySmall)
        } else {
            state.bundleComponents.forEach { bc ->
                Row(Modifier.fillMaxWidth(), verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(bc.componentName ?: bc.componentItemId, style = MaterialTheme.typography.bodyMedium)
                        Text(
                            "x${bc.quantity}${bc.componentPriceCents?.let { " • " + CatalogSellerMath.formatCents(it) } ?: ""}",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    IconButton(onClick = { onRemove(bc.componentItemId) }) { Icon(Icons.Outlined.Delete, contentDescription = "Remove component") }
                }
            }
            Text("Bundle total: ${CatalogSellerMath.formatCents(state.bundleTotalCents)}", style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
        }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
            OutlinedTextField(value = componentId, onValueChange = { componentId = it }, label = { Text("Component item id") }, singleLine = true, modifier = Modifier.weight(2f))
            OutlinedTextField(
                value = qty,
                onValueChange = { qty = it.filter { c -> c.isDigit() } },
                label = { Text("Qty") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.weight(1f),
            )
            OutlinedButton(
                onClick = { if (componentId.isNotBlank()) { onAdd(componentId, qty); componentId = ""; qty = "1" } },
                modifier = Modifier.testTag(ProductDepthTestTags.ADD_BUNDLE_COMPONENT),
            ) { Icon(Icons.Outlined.Add, contentDescription = "Add component") }
        }
    }
}
