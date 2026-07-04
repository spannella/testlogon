package com.testlogon.android.feature.sellerstore

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.catalog.CatalogCategory
import com.testlogon.android.data.catalog.CatalogItem
import com.testlogon.android.data.catalog.CatalogRepository
import com.testlogon.android.data.feed.CurrentUserRepository
import com.testlogon.android.data.sellerstore.SellerCatalogRepository
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
 * ECOM (seller store) — "My store / Manage listings" state. Shows the categories the signed-in seller
 * owns (creator_id == my user_sub), the items in the selected category, and drives create-category /
 * delete-category / delete-item. Item create/edit is delegated to the listing editor screen.
 */
data class SellerStoreUiState(
    val loading: Boolean = true,
    val error: String? = null,
    val categories: List<CatalogCategory> = emptyList(),
    val selectedCategoryId: String? = null,
    val itemsLoading: Boolean = false,
    val items: List<CatalogItem> = emptyList(),
    val busy: Boolean = false,
) {
    val selectedCategory: CatalogCategory? get() = categories.firstOrNull { it.categoryId == selectedCategoryId }
}

sealed interface SellerStoreEvent {
    data class Message(val text: String) : SellerStoreEvent
}

@HiltViewModel
class SellerStoreViewModel @Inject constructor(
    private val catalogRepository: CatalogRepository,
    private val sellerRepository: SellerCatalogRepository,
    private val currentUserRepository: CurrentUserRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(SellerStoreUiState())
    val uiState: StateFlow<SellerStoreUiState> = _uiState.asStateFlow()

    private val _events = Channel<SellerStoreEvent>(Channel.BUFFERED)
    val events: Flow<SellerStoreEvent> = _events.receiveAsFlow()

    private var userSub: String? = null

    init {
        refresh()
    }

    /** Reloads the seller's own categories, preserving/repairing the selection, then its items. */
    fun refresh() {
        _uiState.update { it.copy(loading = it.categories.isEmpty(), error = null) }
        viewModelScope.launch {
            if (userSub == null) {
                (currentUserRepository.currentUserSub() as? ApiResult.Success)?.let { userSub = it.data }
            }
            when (val r = catalogRepository.categories()) {
                is ApiResult.Success -> {
                    val mine = r.data.categories.filter { c -> userSub != null && c.creatorId == userSub }
                    val selected = _uiState.value.selectedCategoryId
                        ?.takeIf { id -> mine.any { it.categoryId == id } }
                        ?: mine.firstOrNull()?.categoryId
                    _uiState.update { it.copy(loading = false, error = null, categories = mine, selectedCategoryId = selected) }
                    selected?.let { loadItems(it) }
                }
                is ApiResult.Failure ->
                    _uiState.update { it.copy(loading = false, error = r.error.message) }
                is ApiResult.NetworkError ->
                    _uiState.update { it.copy(loading = false, error = OFFLINE) }
            }
        }
    }

    fun selectCategory(categoryId: String) {
        if (categoryId == _uiState.value.selectedCategoryId) return
        _uiState.update { it.copy(selectedCategoryId = categoryId, items = emptyList()) }
        loadItems(categoryId)
    }

    /** Silently reloads the selected category's items — called on screen resume (after the editor). */
    fun reloadSelectedItems() {
        _uiState.value.selectedCategoryId?.let { loadItems(it, silent = true) }
    }

    private fun loadItems(categoryId: String, silent: Boolean = false) {
        if (!silent) _uiState.update { it.copy(itemsLoading = true) }
        viewModelScope.launch {
            when (val r = catalogRepository.categoryItems(categoryId, cursor = null)) {
                is ApiResult.Success ->
                    _uiState.update { if (it.selectedCategoryId == categoryId) it.copy(itemsLoading = false, items = r.data.items) else it }
                is ApiResult.Failure -> {
                    _uiState.update { it.copy(itemsLoading = false) }
                    if (!silent) _events.send(SellerStoreEvent.Message(r.error.message))
                }
                is ApiResult.NetworkError -> {
                    _uiState.update { it.copy(itemsLoading = false) }
                    if (!silent) _events.send(SellerStoreEvent.Message(OFFLINE))
                }
            }
        }
    }

    fun createCategory(name: String, description: String?) {
        if (name.isBlank() || _uiState.value.busy) return
        _uiState.update { it.copy(busy = true) }
        viewModelScope.launch {
            when (val r = sellerRepository.createCategory(name.trim(), description)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(busy = false, selectedCategoryId = r.data.categoryId) }
                    _events.send(SellerStoreEvent.Message(CATEGORY_CREATED))
                    refresh()
                }
                is ApiResult.Failure -> fail(r.error.message)
                is ApiResult.NetworkError -> fail(OFFLINE)
            }
        }
    }

    fun deleteCategory(categoryId: String) {
        if (_uiState.value.busy) return
        _uiState.update { it.copy(busy = true) }
        viewModelScope.launch {
            when (val r = sellerRepository.deleteCategory(categoryId)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(busy = false, selectedCategoryId = null, items = emptyList()) }
                    _events.send(SellerStoreEvent.Message(CATEGORY_DELETED))
                    refresh()
                }
                is ApiResult.Failure -> fail(r.error.message)
                is ApiResult.NetworkError -> fail(OFFLINE)
            }
        }
    }

    fun deleteItem(categoryId: String, itemId: String) {
        if (_uiState.value.busy) return
        _uiState.update { it.copy(busy = true) }
        viewModelScope.launch {
            when (val r = sellerRepository.deleteItem(categoryId, itemId)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(busy = false, items = it.items.filterNot { i -> i.itemId == itemId }) }
                    _events.send(SellerStoreEvent.Message(ITEM_DELETED))
                }
                is ApiResult.Failure -> fail(r.error.message)
                is ApiResult.NetworkError -> fail(OFFLINE)
            }
        }
    }

    private suspend fun fail(message: String) {
        _uiState.update { it.copy(busy = false) }
        _events.send(SellerStoreEvent.Message(message))
    }

    companion object {
        private const val OFFLINE = "You're offline"
        private const val CATEGORY_CREATED = "Category created"
        private const val CATEGORY_DELETED = "Category deleted"
        private const val ITEM_DELETED = "Listing deleted"
    }
}
