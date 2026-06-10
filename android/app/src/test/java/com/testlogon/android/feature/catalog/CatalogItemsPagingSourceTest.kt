package com.testlogon.android.feature.catalog

import androidx.paging.PagingConfig
import androidx.paging.PagingSource
import androidx.paging.PagingState
import androidx.paging.testing.TestPager
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.catalog.CatalogCategoryPage
import com.testlogon.android.data.catalog.CatalogItem
import com.testlogon.android.data.catalog.CatalogItemPage
import com.testlogon.android.data.catalog.CatalogRepository
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/**
 * AND-205 — [CatalogItemsPagingSource] via Paging's TestPager: cursor follow (next_token), terminal on
 * null token, and error mapping.
 */
class CatalogItemsPagingSourceTest {

    private val config = PagingConfig(pageSize = 50, initialLoadSize = 50, enablePlaceholders = false)
    private val repo = FakeCatalogRepository()

    private fun item(id: String) = CatalogItem(
        itemId = id,
        categoryId = "c",
        name = "n-$id",
        priceCents = 100,
        currency = "USD",
    )

    private fun source() = CatalogItemsPagingSource(repo, categoryId = "c")

    @Test
    fun firstPage_followsToken_prevNull() = runTest {
        repo.itemPages[null] = ApiResult.Success(CatalogItemPage(listOf(item("i1")), nextToken = "t2"))
        val result = TestPager(config, source()).refresh() as PagingSource.LoadResult.Page
        assertEquals(listOf("i1"), result.data.map { it.itemId })
        assertEquals("t2", result.nextKey)
        assertNull(result.prevKey)
    }

    @Test
    fun append_followsToken_terminatesOnNull() = runTest {
        repo.itemPages[null] = ApiResult.Success(CatalogItemPage(listOf(item("i1")), nextToken = "t2"))
        repo.itemPages["t2"] = ApiResult.Success(CatalogItemPage(listOf(item("i2")), nextToken = null))
        val pager = TestPager(config, source())
        pager.refresh()
        val appended = pager.append() as PagingSource.LoadResult.Page
        assertEquals(listOf("i2"), appended.data.map { it.itemId })
        assertNull(appended.nextKey)
    }

    @Test
    fun singlePage_nullToken_noAppend() = runTest {
        repo.itemPages[null] = ApiResult.Success(CatalogItemPage(listOf(item("i1")), nextToken = null))
        val result = TestPager(config, source()).refresh() as PagingSource.LoadResult.Page
        assertNull(result.nextKey)
    }

    @Test
    fun httpFailure_yieldsCatalogLoadException() = runTest {
        repo.itemPages[null] = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        val result = TestPager(config, source()).refresh()
        assertTrue(result is PagingSource.LoadResult.Error)
        assertTrue((result as PagingSource.LoadResult.Error).throwable is CatalogLoadException)
    }

    @Test
    fun networkError_yieldsError() = runTest {
        repo.itemPages[null] = ApiResult.NetworkError(IOException("offline"))
        assertTrue(TestPager(config, source()).refresh() is PagingSource.LoadResult.Error)
    }

    @Test
    fun getRefreshKey_isNull() {
        assertNull(source().getRefreshKey(PagingState(emptyList(), null, config, 0)))
    }
}

/** Test double for [CatalogRepository] keyed by cursor. */
class FakeCatalogRepository : CatalogRepository {
    val itemPages = mutableMapOf<String?, ApiResult<CatalogItemPage>>()
    val searchPages = mutableMapOf<String?, ApiResult<CatalogItemPage>>()
    var categoriesResult: ApiResult<CatalogCategoryPage> =
        ApiResult.Success(CatalogCategoryPage(emptyList(), nextToken = null))

    override suspend fun categories(nextToken: String?, pageSize: Int): ApiResult<CatalogCategoryPage> =
        categoriesResult

    override suspend fun categoryItems(categoryId: String, cursor: String?, limit: Int): ApiResult<CatalogItemPage> =
        itemPages[cursor] ?: ApiResult.Success(CatalogItemPage(emptyList(), nextToken = null))

    override suspend fun search(query: String, cursor: String?, limit: Int): ApiResult<CatalogItemPage> =
        searchPages[cursor] ?: ApiResult.Success(CatalogItemPage(emptyList(), nextToken = null))
}
