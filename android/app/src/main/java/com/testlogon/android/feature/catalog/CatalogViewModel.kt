package com.testlogon.android.feature.catalog

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import androidx.paging.cachedIn
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.catalog.CatalogApi
import com.testlogon.android.data.catalog.CatalogCategory
import com.testlogon.android.data.catalog.CatalogItem
import com.testlogon.android.data.catalog.CatalogRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-205 — category-layer state for the catalog browse screen. The item grid uses Paging's own
 * LoadState; this state only models the category strip + selection.
 */
sealed interface CatalogUiState {
    data object Loading : CatalogUiState
    data class Ready(
        val categories: List<CatalogCategory>,
        val selectedId: String,
    ) : CatalogUiState
    data object Empty : CatalogUiState
    data class Error(val message: String, val retryable: Boolean) : CatalogUiState
}

/**
 * AND-205 — catalog / category browse presentation logic.
 *
 * Loads all categories once on init, default-selects the first, and exposes a cursor-paged item stream
 * that switches when the selected category changes (re-anchors at page 1 via [flatMapLatest]). The
 * selected category id is persisted to [SavedStateHandle] so it survives process death. Mirrors the
 * AND-191 VodCatalogViewModel / AND-201 GalleryViewModel conventions.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@HiltViewModel
class CatalogViewModel @Inject constructor(
    private val repository: CatalogRepository,
    private val savedState: SavedStateHandle,
) : ViewModel() {

    private val selectedCategoryId = savedState.getStateFlow<String?>(KEY_SELECTED, null)

    private val _uiState = MutableStateFlow<CatalogUiState>(CatalogUiState.Loading)
    val uiState: StateFlow<CatalogUiState> = _uiState.asStateFlow()

    /** Paged item stream that re-creates the Pager when the selected category changes. */
    val items: Flow<PagingData<CatalogItem>> =
        selectedCategoryId
            .filterNotNull()
            .flatMapLatest { id ->
                Pager(
                    config = PagingConfig(
                        pageSize = CatalogApi.PAGE_SIZE,
                        initialLoadSize = CatalogApi.PAGE_SIZE,
                        prefetchDistance = PREFETCH_DISTANCE,
                        enablePlaceholders = false,
                    ),
                    pagingSourceFactory = { CatalogItemsPagingSource(repository, id) },
                ).flow
            }
            .cachedIn(viewModelScope)

    init {
        loadCategories()
    }

    fun loadCategories() {
        _uiState.update { CatalogUiState.Loading }
        viewModelScope.launch {
            when (val r = repository.categories()) {
                is ApiResult.Success -> {
                    val categories = r.data.categories
                    if (categories.isEmpty()) {
                        _uiState.update { CatalogUiState.Empty }
                    } else {
                        // Restore a persisted selection if it is still present, else default to the first.
                        val persisted = selectedCategoryId.value
                        val selected = categories.firstOrNull { it.categoryId == persisted }?.categoryId
                            ?: categories.first().categoryId
                        if (savedState.get<String?>(KEY_SELECTED) != selected) {
                            savedState[KEY_SELECTED] = selected
                        }
                        _uiState.update { CatalogUiState.Ready(categories = categories, selectedId = selected) }
                    }
                }
                is ApiResult.Failure ->
                    _uiState.update { CatalogUiState.Error(r.error.message, retryable = true) }
                is ApiResult.NetworkError ->
                    _uiState.update { CatalogUiState.Error(OFFLINE_MESSAGE, retryable = true) }
            }
        }
    }

    /** Selects a category: persists the id (drives the paging stream) and updates the Ready state. */
    fun selectCategory(categoryId: String) {
        if (savedState.get<String?>(KEY_SELECTED) == categoryId) return
        savedState[KEY_SELECTED] = categoryId
        _uiState.update { current ->
            if (current is CatalogUiState.Ready) current.copy(selectedId = categoryId) else current
        }
    }

    fun retryCategories() = loadCategories()

    companion object {
        const val KEY_SELECTED = "catalog_selected_category_id"
        private const val PREFETCH_DISTANCE = 6
        private const val OFFLINE_MESSAGE = "You're offline"
    }
}
