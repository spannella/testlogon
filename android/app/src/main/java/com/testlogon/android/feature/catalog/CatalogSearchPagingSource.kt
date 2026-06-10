package com.testlogon.android.feature.catalog

import androidx.paging.PagingSource
import androidx.paging.PagingState
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.catalog.CatalogItem
import com.testlogon.android.data.catalog.CatalogRepository

/**
 * AND-207 — cursor-keyed Paging 3 source over [CatalogRepository.search], mirroring
 * [CatalogItemsPagingSource]. The [query] is fixed for the lifetime of one source (a query change
 * re-creates the source via the VM's flatMapLatest). Keys are the opaque next_token strings; the list is
 * forward-only (prevKey null) and a null/absent token terminates pagination. Repository failures become
 * [LoadResult.Error] (reusing [CatalogLoadException] for mapped HTTP messages) so the screen's load-state
 * mapping is uniform with browse.
 */
class CatalogSearchPagingSource(
    private val repository: CatalogRepository,
    private val query: String,
) : PagingSource<String, CatalogItem>() {

    override suspend fun load(params: LoadParams<String>): LoadResult<String, CatalogItem> =
        when (val result = repository.search(query, cursor = params.key, limit = params.loadSize)) {
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
