package com.testlogon.android.feature.catalog

import androidx.paging.PagingConfig
import androidx.paging.PagingSource
import androidx.paging.testing.TestPager
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.catalog.CatalogItem
import com.testlogon.android.data.catalog.CatalogItemPage
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/**
 * AND-207 / AND-209 — [CatalogSearchPagingSource] via Paging's TestPager: cursor follow (next_token),
 * terminal on null token, and HTTP / transport error mapping (uniform with browse paging).
 */
class CatalogSearchPagingSourceTest {

    private val config = PagingConfig(pageSize = 50, initialLoadSize = 50, enablePlaceholders = false)
    private val repo = FakeCatalogRepository()

    private fun item(id: String) = CatalogItem(
        itemId = id, categoryId = "c", name = "n-$id", priceCents = 1, currency = "USD",
    )

    private fun source() = CatalogSearchPagingSource(repo, query = "hood")

    @Test
    fun firstPage_followsToken_prevNull() = runTest {
        repo.searchPages[null] = ApiResult.Success(CatalogItemPage(listOf(item("i1")), nextToken = "t2"))
        val result = TestPager(config, source()).refresh() as PagingSource.LoadResult.Page
        assertEquals(listOf("i1"), result.data.map { it.itemId })
        assertEquals("t2", result.nextKey)
        assertNull(result.prevKey)
    }

    @Test
    fun append_followsToken_terminatesOnNull() = runTest {
        repo.searchPages[null] = ApiResult.Success(CatalogItemPage(listOf(item("i1")), nextToken = "t2"))
        repo.searchPages["t2"] = ApiResult.Success(CatalogItemPage(listOf(item("i2")), nextToken = null))
        val pager = TestPager(config, source())
        pager.refresh()
        val appended = pager.append() as PagingSource.LoadResult.Page
        assertEquals(listOf("i2"), appended.data.map { it.itemId })
        assertNull(appended.nextKey)
    }

    @Test
    fun httpFailure_yieldsCatalogLoadException() = runTest {
        repo.searchPages[null] = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        val result = TestPager(config, source()).refresh()
        assertTrue(result is PagingSource.LoadResult.Error)
        assertTrue((result as PagingSource.LoadResult.Error).throwable is CatalogLoadException)
    }

    @Test
    fun networkError_yieldsError() = runTest {
        repo.searchPages[null] = ApiResult.NetworkError(IOException("offline"))
        assertTrue(TestPager(config, source()).refresh() is PagingSource.LoadResult.Error)
    }
}
