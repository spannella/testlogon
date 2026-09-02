package com.testlogon.android.feature.financialproducts

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.R
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.financialproducts.FinancialProductsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Drives [FinancialProductsUiState] from [FinancialProductsRepository]. Loads products + collections on
 * first composition + pull-to-refresh. Products + collections support create. Gating: a verified
 * non-admin -> Forbidden with NO network calls; the backend 403 is authoritative. Degrade-on-404: reads
 * fold to honest-empty when the OBP/financial-products flags are off; mutations surface errors.
 */
@HiltViewModel
class FinancialProductsViewModel @Inject constructor(
    private val repository: FinancialProductsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(FinancialProductsUiState())
    val uiState: StateFlow<FinancialProductsUiState> = _uiState.asStateFlow()

    private val _effects = Channel<FinancialProductsEffect>(Channel.BUFFERED)
    val effects: Flow<FinancialProductsEffect> = _effects.receiveAsFlow()

    init {
        load(fromUser = false)
    }

    fun onResumed() = load(fromUser = false, force = true)
    fun onRefresh() = load(fromUser = true)
    fun onRetry() = load(fromUser = true)

    fun onSelectTab(tab: FinancialProductsTab) {
        if (_uiState.value.tab == tab) return
        _uiState.update { it.copy(tab = tab) }
    }

    // ---- create product ----
    fun onOpenCreateProduct() =
        _uiState.update { it.copy(createProduct = CreateProductFormState(isOpen = true)) }
    fun onDismissCreateProduct() {
        if (_uiState.value.createProduct.isSubmitting) return
        _uiState.update { it.copy(createProduct = CreateProductFormState(isOpen = false)) }
    }
    fun onProductCodeChange(v: String) =
        _uiState.update { it.copy(createProduct = it.createProduct.copy(productCode = v)) }
    fun onProductNameChange(v: String) =
        _uiState.update { it.copy(createProduct = it.createProduct.copy(name = v)) }
    fun onProductCategoryChange(v: String) =
        _uiState.update { it.copy(createProduct = it.createProduct.copy(category = v)) }
    fun onProductDescriptionChange(v: String) =
        _uiState.update { it.copy(createProduct = it.createProduct.copy(description = v)) }

    fun onSubmitCreateProduct() {
        val form = _uiState.value.createProduct
        if (!form.canSubmit) return
        _uiState.update { it.copy(createProduct = it.createProduct.copy(isSubmitting = true)) }
        viewModelScope.launch {
            when (val r = repository.createProduct(form.productCode, form.name, form.category, form.description)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(createProduct = CreateProductFormState(isOpen = false)) }
                    _effects.send(FinancialProductsEffect.ShowMessage(R.string.finprod_product_created))
                    load(fromUser = true)
                }
                is ApiResult.Failure -> {
                    _uiState.update { it.copy(createProduct = it.createProduct.copy(isSubmitting = false)) }
                    handleMutationFailure(r.error.status, r.error.message)
                }
                is ApiResult.NetworkError -> {
                    _uiState.update { it.copy(createProduct = it.createProduct.copy(isSubmitting = false)) }
                    _effects.send(FinancialProductsEffect.ShowMessage(R.string.finprod_action_failed))
                }
            }
        }
    }

    // ---- create collection ----
    fun onOpenCreateCollection() =
        _uiState.update { it.copy(createCollection = CreateCollectionFormState(isOpen = true)) }
    fun onDismissCreateCollection() {
        if (_uiState.value.createCollection.isSubmitting) return
        _uiState.update { it.copy(createCollection = CreateCollectionFormState(isOpen = false)) }
    }
    fun onCollectionCodeChange(v: String) =
        _uiState.update { it.copy(createCollection = it.createCollection.copy(collectionCode = v)) }
    fun onCollectionNameChange(v: String) =
        _uiState.update { it.copy(createCollection = it.createCollection.copy(name = v)) }

    fun onSubmitCreateCollection() {
        val form = _uiState.value.createCollection
        if (!form.canSubmit) return
        _uiState.update { it.copy(createCollection = it.createCollection.copy(isSubmitting = true)) }
        viewModelScope.launch {
            when (val r = repository.createCollection(form.collectionCode, form.name, emptyList())) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(createCollection = CreateCollectionFormState(isOpen = false)) }
                    _effects.send(FinancialProductsEffect.ShowMessage(R.string.finprod_collection_created))
                    load(fromUser = true)
                }
                is ApiResult.Failure -> {
                    _uiState.update { it.copy(createCollection = it.createCollection.copy(isSubmitting = false)) }
                    handleMutationFailure(r.error.status, r.error.message)
                }
                is ApiResult.NetworkError -> {
                    _uiState.update { it.copy(createCollection = it.createCollection.copy(isSubmitting = false)) }
                    _effects.send(FinancialProductsEffect.ShowMessage(R.string.finprod_action_failed))
                }
            }
        }
    }

    private suspend fun handleMutationFailure(status: Int, message: String) {
        when (status) {
            HTTP_UNAUTHORIZED -> _uiState.update { it.copy(phase = FinancialProductsUiState.Phase.SessionExpired) }
            HTTP_FORBIDDEN -> _uiState.update { it.copy(phase = FinancialProductsUiState.Phase.Forbidden) }
            else -> _effects.send(FinancialProductsEffect.ShowText(message))
        }
    }

    // ---- load ----
    private fun load(fromUser: Boolean, force: Boolean = false) {
        val hasContent = _uiState.value.phase == FinancialProductsUiState.Phase.Content
        if (_uiState.value.isRefreshing && !force) return
        _uiState.update {
            it.copy(
                phase = if (hasContent && !force) it.phase else FinancialProductsUiState.Phase.Loading,
                isRefreshing = fromUser && hasContent,
            )
        }
        viewModelScope.launch {
            if (!repository.isAdmin()) {
                _uiState.update { it.copy(phase = FinancialProductsUiState.Phase.Forbidden, isRefreshing = false) }
                return@launch
            }

            val productsR = repository.loadProducts()
            val collectionsR = repository.loadCollections()
            val results = listOf(productsR, collectionsR)

            if (results.any { it is ApiResult.Failure && it.error.status == HTTP_FORBIDDEN }) {
                _uiState.update { it.copy(phase = FinancialProductsUiState.Phase.Forbidden, isRefreshing = false) }
                return@launch
            }
            if (results.any { it is ApiResult.Failure && it.error.status == HTTP_UNAUTHORIZED }) {
                _uiState.update { it.copy(phase = FinancialProductsUiState.Phase.SessionExpired, isRefreshing = false) }
                return@launch
            }

            val anyNetworkError = results.any { it is ApiResult.NetworkError }
            val products = (productsR as? ApiResult.Success)?.data.orEmpty()
            val collections = (collectionsR as? ApiResult.Success)?.data.orEmpty()
            val allFailed = results.none { it is ApiResult.Success }
            val phase = when {
                allFailed && anyNetworkError -> FinancialProductsUiState.Phase.Offline
                allFailed -> FinancialProductsUiState.Phase.Error
                else -> FinancialProductsUiState.Phase.Content
            }

            _uiState.update {
                it.copy(
                    phase = phase,
                    products = products,
                    collections = collections,
                    isRefreshing = false,
                )
            }
        }
    }

    private companion object {
        private const val HTTP_UNAUTHORIZED = 401
        private const val HTTP_FORBIDDEN = 403
    }
}
