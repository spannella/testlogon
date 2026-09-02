package com.testlogon.android.feature.financialproducts

import androidx.annotation.StringRes
import com.testlogon.android.data.financialproducts.FinancialProduct
import com.testlogon.android.data.financialproducts.FinancialProductsMath
import com.testlogon.android.data.financialproducts.ProductCollection

/** Top-level tabs of the financial-products hub (web CUS-004: products / collections). */
enum class FinancialProductsTab(val label: String) {
    PRODUCTS("Products"),
    COLLECTIONS("Collections"),
}

/** Render-ready state for the financial-products hub. */
data class FinancialProductsUiState(
    val phase: Phase = Phase.Loading,
    val tab: FinancialProductsTab = FinancialProductsTab.PRODUCTS,
    val products: List<FinancialProduct> = emptyList(),
    val collections: List<ProductCollection> = emptyList(),
    val isRefreshing: Boolean = false,
    val busyId: String? = null,
    val createProduct: CreateProductFormState = CreateProductFormState(),
    val createCollection: CreateCollectionFormState = CreateCollectionFormState(),
) {
    enum class Phase { Loading, Content, Forbidden, SessionExpired, Error, Offline }

    val isEmptyForTab: Boolean
        get() = when (tab) {
            FinancialProductsTab.PRODUCTS -> products.isEmpty()
            FinancialProductsTab.COLLECTIONS -> collections.isEmpty()
        }
}

/** Create-product form. Mirrors the backend `product_code` pattern + required name. */
data class CreateProductFormState(
    val isOpen: Boolean = false,
    val productCode: String = "",
    val name: String = "",
    val category: String = "",
    val description: String = "",
    val isSubmitting: Boolean = false,
) {
    val validationErrors: List<String>
        get() = FinancialProductsMath.productFormErrors(productCode, name)
    val canSubmit: Boolean get() = !isSubmitting && validationErrors.isEmpty()
}

/** Create-collection form. Code + name required; members are added later via the members endpoint. */
data class CreateCollectionFormState(
    val isOpen: Boolean = false,
    val collectionCode: String = "",
    val name: String = "",
    val isSubmitting: Boolean = false,
) {
    val validationErrors: List<String>
        get() = FinancialProductsMath.collectionFormErrors(collectionCode, name)
    val canSubmit: Boolean get() = !isSubmitting && validationErrors.isEmpty()
}

/** One-shot side effects. */
sealed interface FinancialProductsEffect {
    data class ShowMessage(@StringRes val resId: Int) : FinancialProductsEffect
    data class ShowText(val text: String) : FinancialProductsEffect
}
