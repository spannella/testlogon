package com.testlogon.android.feature.gallery

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import androidx.paging.cachedIn
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.gallery.GalleryApi
import com.testlogon.android.data.gallery.GalleryCategory
import com.testlogon.android.data.gallery.GalleryRepository
import com.testlogon.android.data.gallery.GalleryVideoItem
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * AND-201 — header/banner/filter state for the gallery (the grid itself is driven by Paging LoadState).
 * [columns] is set by the screen from the window size class (2 portrait / 4 expanded).
 */
data class GalleryUiState(
    val columns: Int = 2,
    val selectedCategory: String? = null,
    val searchQuery: String? = null,
    val categories: List<GalleryCategory> = emptyList(),
)

/** Drives the active query for the pager: category browse vs. text search. */
private data class GalleryQuery(val category: String?, val query: String?)

/**
 * AND-201 — gallery presentation logic. The paged grid is a cursor-paged [GalleryPagingSource] wrapped
 * in a cached Pager that re-creates when the active category/search query changes (re-anchors at page
 * 1). Categories are fetched once on init. Selecting a category clears search and vice-versa (web
 * parity).
 */
@OptIn(ExperimentalCoroutinesApi::class)
@HiltViewModel
class GalleryViewModel @Inject constructor(
    private val repository: GalleryRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(GalleryUiState())
    val uiState: StateFlow<GalleryUiState> = _uiState.asStateFlow()

    private val query = MutableStateFlow(GalleryQuery(category = null, query = null))

    val items: Flow<PagingData<GalleryVideoItem>> =
        query
            .flatMapLatest { q ->
                Pager(
                    config = PagingConfig(
                        pageSize = GalleryApi.PAGE_SIZE,
                        initialLoadSize = GalleryApi.PAGE_SIZE,
                        prefetchDistance = PREFETCH_DISTANCE,
                        enablePlaceholders = false,
                    ),
                    pagingSourceFactory = { GalleryPagingSource(repository, q.category, q.query) },
                ).flow
            }
            .cachedIn(viewModelScope)

    init {
        loadCategories()
    }

    private fun loadCategories() {
        viewModelScope.launch {
            when (val r = repository.categories()) {
                is ApiResult.Success -> _uiState.update { it.copy(categories = r.data) }
                else -> Unit // category pills are non-critical; the grid still renders.
            }
        }
    }

    fun onCategorySelected(category: String?) {
        _uiState.update { it.copy(selectedCategory = category, searchQuery = null) }
        query.value = GalleryQuery(category = category, query = null)
    }

    fun onSearch(text: String?) {
        val trimmed = text?.trim()?.takeIf { it.isNotEmpty() }
        _uiState.update { it.copy(searchQuery = trimmed, selectedCategory = null) }
        query.value = GalleryQuery(category = null, query = trimmed)
    }

    fun setColumns(columns: Int) {
        if (columns != _uiState.value.columns) _uiState.update { it.copy(columns = columns) }
    }

    companion object {
        private const val PREFETCH_DISTANCE = 12
    }
}
