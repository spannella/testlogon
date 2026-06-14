package com.testlogon.android.feature.vod

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import androidx.paging.cachedIn
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.vod.VodApi
import com.testlogon.android.data.vod.VodCategory
import com.testlogon.android.data.vod.VodRepository
import com.testlogon.android.data.vod.VodSummary
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
 * AND-191 — VOD catalog presentation. The paged catalog stream is keyed by the selected category: no
 * category -> public catalog; a category slug -> gallery browse (the repository routes the endpoint).
 * Changing the category re-creates the Pager via [flatMapLatest]. Category chips load once on init.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@HiltViewModel
class VodCatalogViewModel @Inject constructor(
    private val repository: VodRepository,
) : ViewModel() {

    private val selectedCategory = MutableStateFlow<String?>(null)

    private val _categories = MutableStateFlow<List<VodCategory>>(emptyList())
    val categories: StateFlow<List<VodCategory>> = _categories.asStateFlow()

    val activeCategory: StateFlow<String?> = selectedCategory.asStateFlow()

    val catalog: Flow<PagingData<VodSummary>> =
        selectedCategory
            .flatMapLatest { category ->
                Pager(
                    config = PagingConfig(
                        pageSize = VodApi.CATALOG_PAGE_SIZE,
                        initialLoadSize = VodApi.CATALOG_PAGE_SIZE,
                        prefetchDistance = PREFETCH_DISTANCE,
                        enablePlaceholders = false,
                    ),
                    pagingSourceFactory = { VodCatalogPagingSource(repository, category = category) },
                ).flow
            }
            .cachedIn(viewModelScope)

    init {
        loadCategories()
    }

    fun selectCategory(slug: String?) {
        selectedCategory.update { current -> slug.takeIf { it != current } }
    }

    private fun loadCategories() {
        viewModelScope.launch {
            (repository.categories() as? ApiResult.Success)?.let { result ->
                _categories.update { result.data }
            }
        }
    }

    companion object {
        private const val PREFETCH_DISTANCE = 10
    }
}
