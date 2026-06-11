package com.testlogon.android.feature.broadcast.shelf

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.broadcast.shelf.ShelfProduct
import com.testlogon.android.data.broadcast.shelf.ShelfRepository
import dagger.assisted.Assisted
import dagger.assisted.AssistedFactory
import dagger.assisted.AssistedInject
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/** AND-283 — products shelf view-state. Starts Idle; the first open triggers exactly one load. */
sealed interface ProductsShelfUiState {
    data object Idle : ProductsShelfUiState
    data object Loading : ProductsShelfUiState
    data class Ready(val products: List<ShelfProduct>) : ProductsShelfUiState
    data object Empty : ProductsShelfUiState
    data class Error(val retryable: Boolean) : ProductsShelfUiState
}

/**
 * AND-283 — products shelf presentation logic for a single broadcast session.
 *
 * The shelf is hidden by default; [setExpanded] toggles it and lazily triggers [load] only on the first
 * open from [ProductsShelfUiState.Idle] (so the network call stays off the playback hot path). The Buy
 * action navigates to the AND-206 product detail (handled by the host); the VM only emits analytics-free
 * intent here. Built with AssistedInject so the sessionId is supplied at the call site.
 */
@HiltViewModel(assistedFactory = ProductsShelfViewModel.Factory::class)
class ProductsShelfViewModel @AssistedInject constructor(
    @Assisted private val sessionId: String,
    private val repo: ShelfRepository,
) : ViewModel() {

    @AssistedFactory
    interface Factory {
        fun create(sessionId: String): ProductsShelfViewModel
    }

    private val _uiState = MutableStateFlow<ProductsShelfUiState>(ProductsShelfUiState.Idle)
    val uiState: StateFlow<ProductsShelfUiState> = _uiState.asStateFlow()

    private val _expanded = MutableStateFlow(false)
    val expanded: StateFlow<Boolean> = _expanded.asStateFlow()

    fun setExpanded(open: Boolean) {
        _expanded.value = open
        if (open && _uiState.value is ProductsShelfUiState.Idle) load()
    }

    fun load() {
        _uiState.value = ProductsShelfUiState.Loading
        viewModelScope.launch {
            _uiState.value = when (val result = repo.getSessionProducts(sessionId)) {
                is ApiResult.Success ->
                    if (result.data.isEmpty()) {
                        ProductsShelfUiState.Empty
                    } else {
                        ProductsShelfUiState.Ready(result.data)
                    }
                is ApiResult.Failure -> ProductsShelfUiState.Error(retryable = !result.error.isAuth)
                is ApiResult.NetworkError -> ProductsShelfUiState.Error(retryable = true)
            }
        }
    }

    fun retry() = load()
}
