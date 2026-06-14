package com.testlogon.android.feature.purchases

import androidx.paging.PagingConfig
import androidx.paging.PagingSource
import androidx.paging.testing.TestPager
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/**
 * AND-221 / AND-222 — [PurchasesPagingSource] via Paging's TestPager. The backend has NO pagination, so
 * the source is single-page: nextKey/prevKey are always null. A null query hits the list endpoint; a
 * non-null query hits the search endpoint with the exact term. Failures fold to LoadResult.Error.
 */
class PurchasesPagingSourceTest {

    private val config = PagingConfig(pageSize = 50, initialLoadSize = 50, enablePlaceholders = false)

    @Test
    fun list_singlePage_nextAndPrevNull() = runTest {
        val repo = FakePurchasesRepository(
            listResult = ApiResult.Success(listOf(FakePurchasesRepository.sampleItem("a"))),
        )
        val source = PurchasesPagingSource(repo, query = null)
        val page = TestPager(config, source).refresh() as PagingSource.LoadResult.Page
        assertEquals(listOf("a"), page.data.map { it.id })
        assertNull(page.nextKey)
        assertNull(page.prevKey)
        assertEquals(1, repo.listCalls)
        assertTrue(repo.searchQueries.isEmpty())
    }

    @Test
    fun search_usesSearchEndpoint_withExactQuery() = runTest {
        val repo = FakePurchasesRepository(
            searchResult = ApiResult.Success(listOf(FakePurchasesRepository.sampleItem("s"))),
        )
        val source = PurchasesPagingSource(repo, query = "tee")
        val page = TestPager(config, source).refresh() as PagingSource.LoadResult.Page
        assertEquals(listOf("s"), page.data.map { it.id })
        assertEquals(listOf("tee"), repo.searchQueries)
        assertEquals(0, repo.listCalls)
    }

    @Test
    fun emptyArray_yieldsEmptyPage() = runTest {
        val repo = FakePurchasesRepository(listResult = ApiResult.Success(emptyList()))
        val page = TestPager(config, PurchasesPagingSource(repo, null)).refresh()
            as PagingSource.LoadResult.Page
        assertTrue(page.data.isEmpty())
        assertNull(page.nextKey)
    }

    @Test
    fun httpFailure_yieldsPurchasesLoadException() = runTest {
        val repo = FakePurchasesRepository(listResult = ApiResult.Failure(ApiError(500, "boom")))
        val result = TestPager(config, PurchasesPagingSource(repo, null)).refresh()
        assertTrue(result is PagingSource.LoadResult.Error)
        assertTrue((result as PagingSource.LoadResult.Error).throwable is PurchasesLoadException)
    }

    @Test
    fun networkError_yieldsError() = runTest {
        val repo = FakePurchasesRepository(listResult = ApiResult.NetworkError(IOException("offline")))
        assertTrue(TestPager(config, PurchasesPagingSource(repo, null)).refresh() is PagingSource.LoadResult.Error)
    }
}
