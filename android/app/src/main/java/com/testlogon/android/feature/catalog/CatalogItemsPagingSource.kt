package com.testlogon.android.feature.catalog

import androidx.paging.PagingSource
import androidx.paging.PagingState
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.catalog.CatalogItem
import com.testlogon.android.data.catalog.CatalogRepository

/**
 * AND-205 — cursor-keyed Paging 3 source over [CatalogRepository], mirroring the AND-191
 * VodCatalogPagingSource. The [categoryId] is fixed for the lifetime of one source (a category change
 * re-creates the source via the VM). Keys are the opaque next_token strings; the list is forward-only
 * (prevKey null) and a null/absent token terminates pagination. Repository failures become
 * [LoadResult.Error]; [getRefreshKey] returns null (opaque cursors are not reversible — refresh
 * re-anchors at page 1).
 */
class CatalogItemsPagingSource(
    private val repository: CatalogRepository,
    private val categoryId: String,
) : PagingSource<String, CatalogItem>() {

    override suspend fun load(params: LoadParams<String>): LoadResult<String, CatalogItem> =
        when (val result = repository.categoryItems(categoryId, cursor = params.key, limit = params.loadSize)) {
            is ApiResult.Success -> LoadResult.Page(
                data = result.data.items,
                prevKey = null,
                nextKey = result.data.nextToken,
            )
            is ApiResult.Failure -> LoadResult.Error(CatalogLoadException(result.error.message))
            is ApiResult.NetworkError -> LoadResult.Error(result.cause)
        }

    override fun getRefreshKey(state: PagingState<String, CatalogItem>): String? = null
}

/** Carries a mapped, human-readable message for a non-2xx catalog item-page load failure. */
class CatalogLoadException(message: String) : Exception(message)
