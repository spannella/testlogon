package com.testlogon.android.feature.sellerstore

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.sellerstore.BundleComponent
import com.testlogon.android.data.sellerstore.CatalogSellerMath
import com.testlogon.android.data.sellerstore.PriceComponent
import com.testlogon.android.data.sellerstore.ProductDepthRepository
import com.testlogon.android.data.sellerstore.ProductFeatures
import com.testlogon.android.data.sellerstore.Variant
import com.testlogon.android.navigation.ProductDepthDest
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.math.BigDecimal
import java.math.RoundingMode
import javax.inject.Inject

/**
 * ECOM (catalog depth) — drives the advanced seller product editor: product type, variants, price
 * components, bundle components and per-item product features for one catalog item. Every list read is
 * degrade-on-flag-off (the repository maps 404/501 to empty), so with the depth flag disabled the screen
 * simply shows empty sections; mutations surface errors via a snackbar.
 */
data class ProductDepthUiState(
    val itemId: String,
    val itemName: String,
    val loading: Boolean = true,
    val productType: String = "standalone",
    val variants: List<Variant> = emptyList(),
    val priceComponents: List<PriceComponent> = emptyList(),
    val bundleComponents: List<BundleComponent> = emptyList(),
    val features: ProductFeatures? = null,
    val busy: Boolean = false,
) {
    val isBundle: Boolean get() = CatalogSellerMath.isBundleType(productType)
    val bundleTotalCents: Long
        get() = CatalogSellerMath.bundleTotalCents(
            bundleComponents.map {
                com.testlogon.android.data.sellerstore.BundleLineMath(it.quantity, it.componentPriceCents)
            },
        )
}

sealed interface ProductDepthEvent {
    data class Message(val text: String) : ProductDepthEvent
}

@HiltViewModel
class ProductDepthViewModel @Inject constructor(
    private val repo: ProductDepthRepository,
    savedState: SavedStateHandle,
) : ViewModel() {

    private val itemId: String = checkNotNull(savedState[ProductDepthDest.ARG_ITEM_ID])
    private val itemName: String = savedState.get<String>(ProductDepthDest.ARG_ITEM_NAME).orEmpty()

    private val _uiState = MutableStateFlow(ProductDepthUiState(itemId = itemId, itemName = itemName))
    val uiState: StateFlow<ProductDepthUiState> = _uiState.asStateFlow()

    private val _events = Channel<ProductDepthEvent>(Channel.BUFFERED)
    val events: Flow<ProductDepthEvent> = _events.receiveAsFlow()

    val priceTypes: List<String> = CatalogSellerMath.PRICE_TYPES
    val productTypes: List<String> = CatalogSellerMath.PRODUCT_TYPES

    init { refresh() }

    fun refresh() {
        _uiState.update { it.copy(loading = true) }
        viewModelScope.launch {
            (repo.getProductType(itemId) as? ApiResult.Success)?.let { r -> _uiState.update { s -> s.copy(productType = r.data) } }
            loadVariants()
            loadPriceComponents()
            loadBundle()
            loadFeatures()
            _uiState.update { it.copy(loading = false) }
        }
    }

    private suspend fun loadVariants() {
        (repo.listVariants(itemId) as? ApiResult.Success)?.let { r -> _uiState.update { it.copy(variants = r.data) } }
    }

    private suspend fun loadPriceComponents() {
        (repo.listPriceComponents(itemId, priceType = null) as? ApiResult.Success)?.let { r ->
            _uiState.update { it.copy(priceComponents = r.data) }
        }
    }

    private suspend fun loadBundle() {
        (repo.listBundleComponents(itemId) as? ApiResult.Success)?.let { r -> _uiState.update { it.copy(bundleComponents = r.data) } }
    }

    private suspend fun loadFeatures() {
        (repo.listProductFeatures(itemId) as? ApiResult.Success)?.let { r -> _uiState.update { it.copy(features = r.data) } }
    }

    // ── product type ──
    fun setProductType(type: String) = mutate {
        when (val r = repo.setProductType(itemId, type)) {
            is ApiResult.Success -> { _uiState.update { it.copy(productType = r.data) }; loadBundle() }
            is ApiResult.Failure -> emit(r.error.message)
            is ApiResult.NetworkError -> emit(OFFLINE)
        }
    }

    // ── price components ──
    /** amountText is a decimal-dollar string; effective/expires are epoch-second longs (expires nullable). */
    fun addPriceComponent(priceType: String, amountText: String, effectiveAt: Long, expiresAt: Long?) {
        val cents = parseCents(amountText)
        if (cents == null) { emit(BAD_AMOUNT); return }
        val reason = CatalogSellerMath.validatePriceComponent(priceType, cents, effectiveAt, expiresAt)
        if (reason != null) { emit(reason); return }
        mutate {
            when (val r = repo.addPriceComponent(itemId, priceType, cents, "USD", effectiveAt, expiresAt)) {
                is ApiResult.Success -> loadPriceComponents()
                is ApiResult.Failure -> emit(r.error.message)
                is ApiResult.NetworkError -> emit(OFFLINE)
            }
        }
    }

    // ── variants ──
    fun createVariant(featureValues: Map<String, String>, skuOverride: String?) {
        val reason = CatalogSellerMath.validateVariant(featureValues)
        if (reason != null) { emit(reason); return }
        mutate {
            when (val r = repo.createVariant(itemId, featureValues, skuOverride)) {
                is ApiResult.Success -> loadVariants()
                is ApiResult.Failure -> emit(r.error.message)
                is ApiResult.NetworkError -> emit(OFFLINE)
            }
        }
    }

    fun deleteVariant(variantId: String) = mutate {
        when (val r = repo.deleteVariant(itemId, variantId)) {
            is ApiResult.Success -> loadVariants()
            is ApiResult.Failure -> emit(r.error.message)
            is ApiResult.NetworkError -> emit(OFFLINE)
        }
    }

    // ── bundle components ──
    fun addBundleComponent(componentItemId: String, quantityText: String) {
        val qty = quantityText.trim().toIntOrNull() ?: 1
        val reason = CatalogSellerMath.validateBundleComponent(itemId, componentItemId.trim(), qty)
        if (reason != null) { emit(reason); return }
        mutate {
            when (val r = repo.addBundleComponent(itemId, componentItemId.trim(), qty)) {
                is ApiResult.Success -> loadBundle()
                is ApiResult.Failure -> emit(r.error.message)
                is ApiResult.NetworkError -> emit(OFFLINE)
            }
        }
    }

    fun removeBundleComponent(componentItemId: String) = mutate {
        when (val r = repo.removeBundleComponent(itemId, componentItemId)) {
            is ApiResult.Success -> loadBundle()
            is ApiResult.Failure -> emit(r.error.message)
            is ApiResult.NetworkError -> emit(OFFLINE)
        }
    }

    // ── per-item features ──
    fun createFeatureCategory(name: String) {
        if (name.isBlank()) { emit(NAME_REQUIRED); return }
        mutate {
            when (val r = repo.createFeatureCategory(itemId, name.trim(), position = 0)) {
                is ApiResult.Success -> loadFeatures()
                is ApiResult.Failure -> emit(r.error.message)
                is ApiResult.NetworkError -> emit(OFFLINE)
            }
        }
    }

    fun addFeatureValue(featureCategoryId: String, value: String, priceDeltaText: String) {
        if (value.isBlank()) { emit(VALUE_REQUIRED); return }
        val delta = parseSignedCents(priceDeltaText) ?: 0L
        mutate {
            when (val r = repo.addFeatureValue(itemId, featureCategoryId, value.trim(), delta, position = 0)) {
                is ApiResult.Success -> loadFeatures()
                is ApiResult.Failure -> emit(r.error.message)
                is ApiResult.NetworkError -> emit(OFFLINE)
            }
        }
    }

    fun deleteFeatureCategory(featureCategoryId: String) = mutate {
        when (val r = repo.deleteFeatureCategory(itemId, featureCategoryId)) {
            is ApiResult.Success -> loadFeatures()
            is ApiResult.Failure -> emit(r.error.message)
            is ApiResult.NetworkError -> emit(OFFLINE)
        }
    }

    // ── plumbing ──
    private fun mutate(block: suspend () -> Unit) {
        _uiState.update { it.copy(busy = true) }
        viewModelScope.launch {
            try { block() } finally { _uiState.update { it.copy(busy = false) } }
        }
    }

    private fun emit(text: String) { viewModelScope.launch { _events.send(ProductDepthEvent.Message(text)) } }

    /** Positive decimal-dollar string -> non-negative cents, or null if invalid. */
    private fun parseCents(text: String): Long? = try {
        BigDecimal(text.trim()).movePointRight(2).setScale(0, RoundingMode.HALF_UP).longValueExact().takeIf { it >= 0 }
    } catch (_: Exception) {
        null
    }

    /** Signed decimal-dollar string (delta may be negative) -> cents, or null if invalid. */
    private fun parseSignedCents(text: String): Long? = try {
        text.trim().takeIf { it.isNotBlank() }?.let {
            BigDecimal(it).movePointRight(2).setScale(0, RoundingMode.HALF_UP).longValueExact()
        }
    } catch (_: Exception) {
        null
    }

    companion object {
        private const val OFFLINE = "You're offline"
        private const val BAD_AMOUNT = "Enter a valid amount"
        private const val NAME_REQUIRED = "Enter a name"
        private const val VALUE_REQUIRED = "Enter a value"
    }
}
